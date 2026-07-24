import re

from pathlib import Path

from secrets_hunter.scanning.cancellation import (
    ScanCancellation,
    ScanCancelledError
)
from secrets_hunter.scanning.failures import OperationalScanError
from secrets_hunter.scanning.read_result import (
    SourceBytes,
    SourceCancelled,
    SourceReadFailure
)
from secrets_hunter.scanning.modes.git_history.process import GitProcessRunner


_DIFF_HUNK_RE = re.compile(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")
_COMMIT_SHA_RE = re.compile(r"\A(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")


class GitHistoryReader:
    """Read commit-selected file blobs from a git repository."""

    CONTROL_OUTPUT_BYTES = 64 * 1024

    def __init__(
        self,
        target: Path,
        max_source_bytes: int,
        source_timeout_seconds: float,
        cancellation: ScanCancellation
    ) -> None:
        self.target = Path(target).resolve()
        self.max_source_bytes = max_source_bytes
        self.process_runner = GitProcessRunner(
            source_timeout_seconds,
            cancellation
        )
        self._repo_root = self._find_repo_root(self._git_cwd())

    @property
    def repo_root(self) -> Path:
        return self._repo_root

    def list_commits(self, revset: str, max_count: int | None = None) -> list[str]:
        args = ["rev-list", "--reverse"]

        if max_count is not None:
            args.extend(["--max-count", str(max_count)])

        args.append("--end-of-options")
        args.append(revset)
        output = self._run_git_text(args)

        if not output:
            return []

        return [line for line in output.splitlines() if line]

    def list_changed_files(self, commit_sha: str) -> list[str]:
        self._validate_commit_sha(commit_sha)

        output = self._run_git_bytes([
            "diff-tree",
            "--root",
            "--no-commit-id",
            "--name-only",
            "-r",
            "-z",
            "--diff-filter=AM",
            "--end-of-options",
            commit_sha
        ])

        if not output:
            return []

        return [
            path.decode("utf-8", errors="replace")
            for path in output.split(b"\0")
            if path
        ]

    def read_blob(
        self,
        commit_sha: str,
        repo_rel_path: str
    ) -> SourceBytes | SourceCancelled | SourceReadFailure:
        self._validate_commit_sha(commit_sha)
        object_spec = f"{commit_sha}:{repo_rel_path}"

        try:
            blob_size = int(self._run_git_text([
                "cat-file",
                "-s",
                object_spec
            ], max_output_bytes=self.CONTROL_OUTPUT_BYTES))
        except ScanCancelledError:
            return SourceCancelled()
        except (OperationalScanError, ValueError) as error:
            return SourceReadFailure(f"Failed to inspect git blob: {error}")

        if blob_size > self.max_source_bytes:
            return SourceReadFailure(
                f"Git blob is {blob_size} bytes; maximum is "
                f"{self.max_source_bytes} bytes"
            )

        try:
            body = self._run_git_bytes([
                "show",
                "--end-of-options",
                object_spec
            ])
        except ScanCancelledError:
            return SourceCancelled()
        except OperationalScanError as error:
            return SourceReadFailure(f"Failed to read git blob: {error}")

        if len(body) > self.max_source_bytes:
            return SourceReadFailure(
                f"Git blob is {len(body)} bytes; maximum is "
                f"{self.max_source_bytes} bytes"
            )

        return SourceBytes(body)

    def list_added_lines(self, commit_sha: str, repo_rel_path: str) -> set[int]:
        self._validate_commit_sha(commit_sha)

        diff = self._run_git_text([
            "diff-tree",
            "--root",
            "--unified=0",
            "--no-ext-diff",
            "--no-renames",
            "-p",
            "--end-of-options",
            commit_sha,
            "--",
            repo_rel_path
        ])

        added_lines: set[int] = set()

        for line in diff.splitlines():
            match = _DIFF_HUNK_RE.match(line)

            if not match:
                continue

            start_line = int(match.group(1))
            line_count = int(match.group(2) or "1")

            for line_number in range(start_line, start_line + line_count):
                added_lines.add(line_number)

        return added_lines

    def target_matches(self, target_path: Path, repo_rel_path: str) -> bool:
        resolved_target = target_path.resolve()

        try:
            target_rel = resolved_target.relative_to(self.repo_root)
        except ValueError:
            return False

        if target_rel == Path("."):
            return True

        normalized_repo_rel_path = Path(repo_rel_path).as_posix()
        normalized_target = target_rel.as_posix()

        if resolved_target.is_dir():
            return (
                normalized_repo_rel_path == normalized_target
                or normalized_repo_rel_path.startswith(f"{normalized_target}/")
            )

        return normalized_repo_rel_path == normalized_target

    def _git_cwd(self) -> Path:
        return self.target if self.target.is_dir() else self.target.parent

    def _find_repo_root(self, cwd: Path) -> Path:
        output = self._run_git_text(
            ["rev-parse", "--show-toplevel"],
            cwd=cwd,
            max_output_bytes=self.CONTROL_OUTPUT_BYTES
        )
        return Path(output).resolve()

    def _run_git_text(
        self,
        args: list[str],
        cwd: Path | None = None,
        max_output_bytes: int | None = None
    ) -> str:
        return self._run_git_bytes(
            args,
            cwd=cwd,
            max_output_bytes=max_output_bytes
        ).decode("utf-8", errors="replace").strip()

    def _run_git_bytes(
        self,
        args: list[str],
        cwd: Path | None = None,
        max_output_bytes: int | None = None
    ) -> bytes:
        return self.process_runner.run(
            args,
            cwd or self.repo_root,
            max_output_bytes or self.max_source_bytes
        )

    @staticmethod
    def _validate_commit_sha(commit_sha: str) -> None:
        if not _COMMIT_SHA_RE.fullmatch(commit_sha):
            raise ValueError(f"invalid git commit sha: {commit_sha!r}")
