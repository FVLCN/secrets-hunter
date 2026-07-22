import logging

from collections.abc import Iterator
from dataclasses import dataclass
from functools import partial
from pathlib import Path
from typing import assert_never, override

from secrets_hunter.models import (
    ScanFailure,
    ScanResult
)
from secrets_hunter.scanning.cancellation import ScanCancelledError
from secrets_hunter.scanning.content_validator import TextContentValidator
from secrets_hunter.scanning.path_filter import PathFilter
from secrets_hunter.scanning.read_result import (
    SourceBytes,
    SourceCancelled,
    SourceReadFailure
)
from secrets_hunter.scanning.scanner import BaseScanner
from secrets_hunter.scanning.session import ScanSession
from secrets_hunter.scanning.source_identity import SourcePathResolver
from secrets_hunter.scanning.text_reader import SourceTextReader
from secrets_hunter.scanning.work import (
    ScanWorkEvent,
    ScanWorkItem,
    ScanWorkPlan
)
from secrets_hunter.scan_modes.git_history.reader import GitHistoryReader

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class GitBlobRef:
    commit_sha: str
    repo_rel_path: str


class GitHistoryScanner(BaseScanner):
    def __init__(
        self,
        session: ScanSession,
        path_filter: PathFilter,
        content_validator: TextContentValidator,
        source_text_reader: SourceTextReader,
        target: str,
        revset: str,
        max_count: int | None = None
    ) -> None:
        super().__init__(session)
        self.path_filter = path_filter
        self.content_validator = content_validator
        self.source_text_reader = source_text_reader
        self.target = target
        self.target_path = Path(target)
        self.revset = revset
        self.max_count = max_count

    @override
    def create_work_plan(self) -> ScanWorkPlan:
        git_reader = GitHistoryReader(
            self.target_path,
            self.session.options.max_source_bytes,
            self.session.options.source_timeout_seconds,
            self.session.control.cancellation
        )
        source_path_resolver = SourcePathResolver.for_target(
            git_reader.repo_root
        )

        logger.info(f"Collecting commits from git revset {self.revset!r}...")
        return ScanWorkPlan(
            label=str(self.target_path),
            events=self._work_events(git_reader, source_path_resolver)
        )

    def _work_events(
        self,
        git_reader: GitHistoryReader,
        source_path_resolver: SourcePathResolver
    ) -> Iterator[ScanWorkEvent]:
        for blob in self.iter_git_blobs(git_reader):
            yield ScanWorkItem(
                label=f"{blob.commit_sha[:12]}:{blob.repo_rel_path}",
                run=partial(
                    self.scan_git_blob,
                    git_reader,
                    source_path_resolver,
                    blob.commit_sha,
                    blob.repo_rel_path
                )
            )

    def iter_git_blobs(
        self,
        git_reader: GitHistoryReader
    ) -> Iterator[GitBlobRef]:
        commits = git_reader.list_commits(self.revset, max_count=self.max_count)

        if not commits:
            return

        for commit_sha in commits:
            for repo_rel_path in git_reader.list_changed_files(commit_sha):
                if not git_reader.target_matches(self.target_path, repo_rel_path):
                    continue

                if self.path_filter.is_ignored_path(Path(repo_rel_path)):
                    continue

                yield GitBlobRef(commit_sha, repo_rel_path)

    def scan_git_blob(
        self,
        git_reader: GitHistoryReader,
        source_path_resolver: SourcePathResolver,
        commit_sha: str,
        repo_rel_path: str
    ) -> ScanResult:
        if self.session.control.cancellation.cancelled:
            return ScanResult(
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        read_result = git_reader.read_blob(commit_sha, repo_rel_path)

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
                        label=f"{commit_sha[:12]}:{repo_rel_path}",
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

        if not isinstance(read_result, SourceBytes):
            assert_never(read_result)

        blob = read_result.content
        if not self.content_validator.is_text_content(blob):
            return ScanResult(
                total_items=1,
                attempted_items=1,
                successful_items=1
            )

        display_path = git_reader.repo_root / repo_rel_path
        result = self.session.source_scanner.scan(
            self.source_text_reader.bytes_to_lines(blob),
            source_path_resolver.identify(display_path)
        )

        if not result.complete:
            return result

        try:
            added_lines = git_reader.list_added_lines(
                commit_sha,
                repo_rel_path
            )
        except ScanCancelledError:
            return ScanResult(
                findings=result.findings,
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        if self.session.control.cancellation.cancelled:
            return ScanResult(
                findings=result.findings,
                total_items=1,
                attempted_items=1,
                aborted=True
            )

        if not added_lines:
            return result.with_findings(())

        introduced_findings = [
            finding.with_commit(commit_sha)
            for finding in result.findings
            if finding.line in added_lines
        ]

        return result.with_findings(introduced_findings)
