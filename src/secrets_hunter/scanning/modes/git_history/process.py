import subprocess

from dataclasses import dataclass, field
from pathlib import Path
from threading import Event, Thread
from time import monotonic
from typing import BinaryIO

from secrets_hunter.scanning.cancellation import (
    ScanCancellation,
    ScanCancelledError
)
from secrets_hunter.scanning.failures import OperationalScanError


@dataclass
class _BoundedCapture:
    limit_bytes: int
    content: bytearray = field(default_factory=bytearray)
    overflowed: Event = field(default_factory=Event)
    failed: Event = field(default_factory=Event)
    error: OSError | ValueError | None = None

    def drain(self, stream: BinaryIO) -> None:
        try:
            while chunk := stream.read(GitProcessRunner.READ_CHUNK_BYTES):
                remaining = self.limit_bytes - len(self.content)
                if remaining > 0:
                    self.content.extend(chunk[:remaining])

                if len(chunk) > remaining:
                    self.overflowed.set()
        except (OSError, ValueError) as error:
            self.error = error
            self.failed.set()
        finally:
            stream.close()


class GitProcessRunner:
    READ_CHUNK_BYTES = 64 * 1024
    STDERR_LIMIT_BYTES = 64 * 1024
    PROCESS_POLL_SECONDS = 0.1
    TERMINATION_GRACE_SECONDS = 0.5

    def __init__(
        self,
        source_timeout_seconds: float,
        cancellation: ScanCancellation
    ) -> None:
        self.source_timeout_seconds = source_timeout_seconds
        self.cancellation = cancellation

    def run(
        self,
        args: list[str],
        cwd: Path,
        max_stdout_bytes: int
    ) -> bytes:
        if self.cancellation.cancelled:
            raise ScanCancelledError()

        command = ["git", *args]
        try:
            process = subprocess.Popen(
                command,
                cwd=cwd,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                shell=False
            )
        except OSError as error:
            raise OperationalScanError(
                f"Could not run git {' '.join(args)}: {error}"
            ) from error

        if process.stdout is None or process.stderr is None:
            self._stop_process(process)
            raise OperationalScanError("Could not capture git process output")

        stdout_capture = _BoundedCapture(max_stdout_bytes)
        stderr_capture = _BoundedCapture(self.STDERR_LIMIT_BYTES)
        stdout_thread = Thread(
            target=stdout_capture.drain,
            args=(process.stdout,),
            daemon=True,
            name="git-stdout-reader"
        )
        stderr_thread = Thread(
            target=stderr_capture.drain,
            args=(process.stderr,),
            daemon=True,
            name="git-stderr-reader"
        )
        stdout_thread.start()
        stderr_thread.start()
        deadline = monotonic() + self.source_timeout_seconds

        try:
            while process.poll() is None:
                if self.cancellation.cancelled:
                    raise ScanCancelledError()

                self._raise_capture_error(
                    args,
                    stdout_capture,
                    stderr_capture
                )

                remaining = deadline - monotonic()
                if remaining <= 0:
                    raise OperationalScanError(
                        f"git {' '.join(args)} timed out after "
                        f"{self.source_timeout_seconds:g} seconds"
                    )

                try:
                    process.wait(
                        timeout=min(self.PROCESS_POLL_SECONDS, remaining)
                    )
                except subprocess.TimeoutExpired:
                    continue
        except BaseException:
            self._stop_process(process)
            raise
        finally:
            self._join_readers(
                process,
                (stdout_thread, stderr_thread)
            )

        if stdout_thread.is_alive() or stderr_thread.is_alive():
            raise OperationalScanError("Git output readers did not stop")

        self._raise_capture_error(
            args,
            stdout_capture,
            stderr_capture
        )

        stderr = bytes(stderr_capture.content)
        if process.returncode != 0:
            stderr_text = stderr.decode("utf-8", errors="replace").strip()
            detail = stderr_text or f"exit code {process.returncode}"
            raise OperationalScanError(
                f"git {' '.join(args)} failed: {detail}"
            )

        return bytes(stdout_capture.content)

    @staticmethod
    def _raise_capture_error(
        args: list[str],
        stdout_capture: _BoundedCapture,
        stderr_capture: _BoundedCapture
    ) -> None:
        if stdout_capture.overflowed.is_set():
            raise OperationalScanError(
                f"git {' '.join(args)} stdout exceeds maximum of "
                f"{stdout_capture.limit_bytes} bytes"
            )

        if stderr_capture.overflowed.is_set():
            raise OperationalScanError(
                f"git {' '.join(args)} stderr exceeds maximum of "
                f"{stderr_capture.limit_bytes} bytes"
            )

        for capture in (stdout_capture, stderr_capture):
            if capture.failed.is_set():
                raise OperationalScanError(
                    f"Could not read git process output: {capture.error}"
                )

    def _stop_process(self, process: subprocess.Popen[bytes]) -> None:
        if process.poll() is not None:
            return

        try:
            process.terminate()
        except OSError:
            pass

        try:
            process.wait(timeout=self.TERMINATION_GRACE_SECONDS)
        except subprocess.TimeoutExpired:
            try:
                process.kill()
            except OSError:
                pass
            process.wait()

    def _join_readers(
        self,
        process: subprocess.Popen[bytes],
        readers: tuple[Thread, Thread]
    ) -> None:
        for reader in readers:
            reader.join(timeout=self.TERMINATION_GRACE_SECONDS)

        if not any(reader.is_alive() for reader in readers):
            return

        for stream in (process.stdout, process.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except (OSError, ValueError):
                pass

        for reader in readers:
            reader.join(timeout=self.TERMINATION_GRACE_SECONDS)
