import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

from dataclasses import dataclass
from email.message import Message
from http.client import HTTPResponse
from typing import Protocol, override

from secrets_hunter._version import __version__
from secrets_hunter.scanning.cancellation import ScanCancellation
from secrets_hunter.scanning.read_result import (
    SourceBytes,
    SourceCancelled,
    SourceMissing,
    SourceReadFailure,
    SourceReadResult
)
from secrets_hunter.scanning.modes.domain.url import is_http_url, normalize_domain


class _BinaryResponse(Protocol):
    status: int
    headers: Message

    def read(self, size: int = -1) -> bytes:
        ...


@dataclass(frozen=True)
class _Redirect:
    location: str


@dataclass(frozen=True)
class FetchedHttpResponse:
    content: bytes
    effective_url: str


type DomainReadResult = (
    FetchedHttpResponse
    | SourceMissing
    | SourceCancelled
    | SourceReadFailure
)
type _RequestResult = SourceReadResult | _Redirect


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    @override
    def redirect_request(
        self,
        request: urllib.request.Request,
        response: HTTPResponse,
        code: int,
        message: str,
        headers: Message,
        new_url: str
    ) -> None:
        return None


class DomainClient:
    READ_CHUNK_BYTES = 64 * 1024
    MAX_REDIRECTS = 10
    REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

    def __init__(
        self,
        domain: str,
        max_source_bytes: int,
        source_timeout_seconds: float,
        cancellation: ScanCancellation,
        skip_tls_verify: bool = False
    ) -> None:
        self.base_url = normalize_domain(domain)
        self.max_source_bytes = max_source_bytes
        self.source_timeout_seconds = source_timeout_seconds
        self.cancellation = cancellation
        self.opener = self._build_opener(skip_tls_verify)

    def read_url(self, url: str) -> DomainReadResult:
        if self.cancellation.cancelled:
            return SourceCancelled()

        if not is_http_url(url):
            return SourceReadFailure(f"Unsupported URL: {url}")

        deadline = time.monotonic() + self.source_timeout_seconds
        current_url, _ = urllib.parse.urldefrag(url)
        visited_urls: set[str] = set()
        redirects_followed = 0

        while True:
            if self.cancellation.cancelled:
                return SourceCancelled()

            if current_url in visited_urls:
                return SourceReadFailure("HTTP redirect loop detected")

            if self._remaining_timeout(deadline) <= 0:
                return self._timeout_failure()

            visited_urls.add(current_url)
            result = self._request_once(current_url, deadline)

            if isinstance(result, SourceBytes):
                return FetchedHttpResponse(
                    content=result.content,
                    effective_url=current_url
                )

            if not isinstance(result, _Redirect):
                return result

            if redirects_followed >= self.MAX_REDIRECTS:
                return SourceReadFailure(
                    f"Too many HTTP redirects; maximum is "
                    f"{self.MAX_REDIRECTS}"
                )

            redirected_url = urllib.parse.urljoin(
                current_url,
                result.location
            )
            redirected_url, _ = urllib.parse.urldefrag(redirected_url)

            if not is_http_url(redirected_url):
                return SourceReadFailure(
                    f"Unsupported redirect URL: {redirected_url}"
                )

            current_url = redirected_url
            redirects_followed += 1

    def _request_once(
        self,
        url: str,
        deadline: float
    ) -> _RequestResult:
        remaining_timeout = self._remaining_timeout(deadline)
        if remaining_timeout <= 0:
            return self._timeout_failure()

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": f"fvlcn-secrets-hunter v{__version__}"
            },
            method="GET"
        )

        try:
            with self.opener.open(
                request,
                timeout=remaining_timeout
            ) as response:
                if self.cancellation.cancelled:
                    return SourceCancelled()

                status = response.status

                if status < 200 or status >= 300:
                    return SourceReadFailure(f"HTTP {status}")

                content_length = self._content_length(
                    response.headers.get("Content-Length")
                )
                if (
                    content_length is not None
                    and content_length > self.max_source_bytes
                ):
                    return SourceReadFailure(
                        self._size_failure_message(content_length)
                    )

                return self._read_body(response, deadline)
        except urllib.error.HTTPError as error:
            try:
                if error.code in self.REDIRECT_STATUSES:
                    location = error.headers.get("Location")
                    if location is None or not location.strip():
                        return SourceReadFailure(
                            f"HTTP {error.code} redirect has no Location header"
                        )

                    return _Redirect(location.strip())

                return self._http_error_result(error)
            finally:
                error.close()
        except TimeoutError:
            if self.cancellation.cancelled:
                return SourceCancelled()

            return self._timeout_failure()
        except urllib.error.URLError as error:
            if self.cancellation.cancelled:
                return SourceCancelled()

            if isinstance(error.reason, TimeoutError):
                return self._timeout_failure()

            return SourceReadFailure(f"Failed to fetch URL: {error}")
        except (OSError, ValueError) as error:
            if self.cancellation.cancelled:
                return SourceCancelled()

            return SourceReadFailure(f"Failed to fetch URL: {error}")

    def _http_error_result(
        self,
        error: urllib.error.HTTPError
    ) -> SourceReadResult:
        if self.cancellation.cancelled:
            return SourceCancelled()

        if error.code == 404:
            return SourceMissing()

        reason = (
            str(error.reason).strip()
            if error.reason is not None
            else ""
        )
        suffix = f" {reason}" if reason else ""
        return SourceReadFailure(f"HTTP {error.code}{suffix}")

    def _read_body(
        self,
        response: _BinaryResponse,
        deadline: float
    ) -> SourceReadResult:
        body = bytearray()

        while True:
            if self.cancellation.cancelled:
                return SourceCancelled()

            if self._remaining_timeout(deadline) <= 0:
                return self._timeout_failure()

            remaining = self.max_source_bytes + 1 - len(body)
            chunk = response.read(min(self.READ_CHUNK_BYTES, remaining))

            if self.cancellation.cancelled:
                return SourceCancelled()

            if self._remaining_timeout(deadline) <= 0:
                return self._timeout_failure()

            if not chunk:
                return SourceBytes(bytes(body))

            body.extend(chunk)
            if len(body) > self.max_source_bytes:
                return SourceReadFailure(
                    self._size_failure_message(len(body))
                )

    @staticmethod
    def _remaining_timeout(deadline: float) -> float:
        return deadline - time.monotonic()

    @staticmethod
    def _timeout_failure() -> SourceReadFailure:
        return SourceReadFailure("HTTP request timed out")

    @staticmethod
    def _content_length(value: str | None) -> int | None:
        if value is None:
            return None

        try:
            content_length = int(value)
        except (TypeError, ValueError):
            return None

        return content_length if content_length >= 0 else None

    def _size_failure_message(self, actual_bytes: int) -> str:
        return (
            f"Source body is {actual_bytes} bytes; maximum is "
            f"{self.max_source_bytes} bytes"
        )

    @classmethod
    def _build_opener(
        cls,
        skip_tls_verify: bool
    ) -> urllib.request.OpenerDirector:
        handlers: list[urllib.request.BaseHandler] = [
            _NoRedirectHandler()
        ]
        ssl_context = cls._build_ssl_context(skip_tls_verify)

        if ssl_context is not None:
            handlers.append(
                urllib.request.HTTPSHandler(context=ssl_context)
            )

        return urllib.request.build_opener(*handlers)

    @staticmethod
    def _build_ssl_context(skip_tls_verify: bool) -> ssl.SSLContext | None:
        if skip_tls_verify:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context

        return None
