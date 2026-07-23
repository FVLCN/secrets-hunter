import logging
import urllib.parse

from typing import assert_never, override

from secrets_hunter.config import DOMAIN_SCAN_PATHS
from secrets_hunter.models import (
    ScanFailure,
    ScanResult
)
from secrets_hunter.scanning.content_validator import TextContentValidator
from secrets_hunter.scanning.read_result import (
    SourceBytes,
    SourceCancelled,
    SourceMissing,
    SourceReadFailure
)
from secrets_hunter.scanning.scanner import BaseScanner
from secrets_hunter.scanning.session import ScanSession
from secrets_hunter.scanning.source_identity import SourcePathResolver
from secrets_hunter.scanning.text_reader import SourceTextReader
from secrets_hunter.scanning.work import ScanWorkItem, ScanWorkPlan
from secrets_hunter.scan_modes.domain.client import DomainClient

logger = logging.getLogger(__name__)


class DomainScanner(BaseScanner):
    def __init__(
        self,
        session: ScanSession,
        content_validator: TextContentValidator,
        source_text_reader: SourceTextReader,
        domain: str,
        *,
        skip_tls_verify: bool = False
    ) -> None:
        super().__init__(session)
        self.content_validator = content_validator
        self.source_text_reader = source_text_reader
        self.domain = domain
        self.skip_tls_verify = skip_tls_verify
        self.source_path_resolver = SourcePathResolver()

    @override
    def create_work_plan(self) -> ScanWorkPlan:
        domain_client = DomainClient(
            self.domain,
            self.session.options.max_source_bytes,
            self.session.options.source_timeout_seconds,
            self.session.control.cancellation,
            skip_tls_verify=self.skip_tls_verify
        )
        logger.info(f"Collecting likely sensitive URLs from {domain_client.base_url}...")
        urls = self.collect_urls_to_scan(domain_client)
        return ScanWorkPlan(
            label=domain_client.base_url,
            events=tuple(
                ScanWorkItem(
                    label=url,
                    run=lambda url=url: self.scan_url_response(domain_client, url)
                )
                for url in urls
            ),
            total_items=len(urls)
        )

    @staticmethod
    def collect_urls_to_scan(domain_client: DomainClient) -> list[str]:
        return [
            urllib.parse.urljoin(domain_client.base_url, path)
            for path in DOMAIN_SCAN_PATHS
        ]

    def scan_url_response(
        self,
        domain_client: DomainClient,
        url: str
    ) -> ScanResult:
        if self.session.control.cancellation.cancelled:
            return ScanResult(
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        read_result = domain_client.read_url(url)

        if self.session.control.cancellation.cancelled:
            return ScanResult(
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        if isinstance(read_result, SourceReadFailure):
            return ScanResult(
                total_items=1,
                attempted_items=1,
                failures=(
                    ScanFailure(
                        label=url,
                        message=read_result.message
                    ),
                )
            )

        if isinstance(read_result, SourceCancelled):
            return ScanResult(
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        if isinstance(read_result, SourceMissing):
            return ScanResult(
                total_items=1,
                attempted_items=1,
                successful_items=1
            )

        if not isinstance(read_result, SourceBytes):
            assert_never(read_result)

        response_body = read_result.content
        if not self.content_validator.is_text_content(response_body):
            return ScanResult(
                total_items=1,
                attempted_items=1,
                successful_items=1
            )

        result = self.session.source_scanner.scan(
            self.source_text_reader.bytes_to_lines(response_body),
            self.source_path_resolver.identify(url)
        )

        if not result.complete:
            return result

        return result.with_findings(
            finding.with_vulnerable_url(url)
            for finding in result.findings
        )
