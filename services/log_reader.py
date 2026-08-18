"""Trusted structured-log reader for registered project log sources."""

from __future__ import annotations

import json
from pathlib import Path

from pydantic import ValidationError

from schemas.logging import ApplicationLogEvent, LogReadResult
from services.target_registry import TargetRegistry


class LogReaderError(RuntimeError):
    """Raised when a configured log source escapes the trusted project root."""


class LogReader:
    """Read and normalize application events from registry-approved log files."""

    def __init__(self, *, registry: TargetRegistry, project_root: Path) -> None:
        self.registry = registry
        self.project_root = project_root.resolve(strict=False)

    def read_run(self, *, target_id: str, run_id: str) -> LogReadResult:
        """Return de-duplicated validated application events for one exact run."""
        target = self.registry.get_target(target_id)
        seen_event_ids: set[str] = set()
        events: list[ApplicationLogEvent] = []
        ignored = 0
        malformed = 0
        duplicates = 0

        for relative_source in target.log_sources:
            source = self._resolve_source(relative_source)
            if not source.exists():
                continue

            for raw_line in source.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw_line.strip()
                if not line:
                    ignored += 1
                    continue
                try:
                    decoded = json.loads(line)
                except json.JSONDecodeError:
                    if line.startswith("{"):
                        malformed += 1
                    else:
                        ignored += 1
                    continue

                if not isinstance(decoded, dict) or "schema_version" not in decoded:
                    ignored += 1
                    continue

                try:
                    event = ApplicationLogEvent.model_validate(decoded)
                except ValidationError:
                    malformed += 1
                    continue

                if event.event_id in seen_event_ids:
                    duplicates += 1
                    continue
                seen_event_ids.add(event.event_id)

                if event.run_id == run_id:
                    events.append(event)

        return LogReadResult(
            target_id=target_id,
            run_id=run_id,
            events=tuple(events),
            ignored_line_count=ignored,
            malformed_line_count=malformed,
            duplicate_event_count=duplicates,
        )

    def _resolve_source(self, relative_source: str) -> Path:
        candidate = (self.project_root / relative_source).resolve(strict=False)
        try:
            candidate.relative_to(self.project_root)
        except ValueError as exc:
            raise LogReaderError("registered log source escapes project root") from exc
        return candidate
