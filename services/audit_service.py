"""Append-oriented trusted audit service for sensitive workflow operations."""

from __future__ import annotations

from datetime import UTC, datetime
import json
from pathlib import Path
from uuid import uuid4

from pydantic import ValidationError

from schemas.common import PolicyReasonCode
from schemas.logging import (
    AuditEvent,
    AuditExecutionStatus,
    AuditPolicyDecision,
)


_AUDIT_RELATIVE_PATH = Path("data/audit/audit.jsonl")


class AuditService:
    """Create and read typed audit records under one fixed project-local path."""

    def __init__(self, *, project_root: Path) -> None:
        self.project_root = project_root.resolve(strict=False)
        self.path = self.project_root / _AUDIT_RELATIVE_PATH

    def record(
        self,
        *,
        run_id: str,
        component: str,
        actor_type: str,
        operation: str,
        target: str,
        policy_decision: AuditPolicyDecision,
        execution_status: AuditExecutionStatus,
        policy_reason: PolicyReasonCode | None = None,
        duration_ms: int = 0,
        evidence_reference: str | None = None,
        error_code: str | None = None,
    ) -> AuditEvent:
        """Append one trusted event; structural ID/timestamp are service-generated."""
        event = AuditEvent(
            event_id=f"audit-{uuid4().hex[:24]}",
            timestamp=datetime.now(UTC),
            run_id=run_id,
            component=component,
            actor_type=actor_type,
            operation=operation,
            target=target,
            policy_decision=policy_decision,
            policy_reason=policy_reason,
            execution_status=execution_status,
            duration_ms=duration_ms,
            evidence_reference=evidence_reference,
            error_code=error_code,
        )
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(event.model_dump_json())
            handle.write("\n")
        return event

    def read_run(self, *, run_id: str) -> tuple[AuditEvent, ...]:
        """Return valid audit events for one run, ignoring malformed history lines."""
        if not self.path.exists():
            return ()

        events: list[AuditEvent] = []
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            try:
                decoded = json.loads(line)
                event = AuditEvent.model_validate(decoded)
            except (json.JSONDecodeError, ValidationError):
                continue
            if event.run_id == run_id:
                events.append(event)
        return tuple(events)
