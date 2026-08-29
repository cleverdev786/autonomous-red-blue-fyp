"""Observational experiment lifecycle recorder for Milestone 15.

This module intentionally imports no agents, Red/Blue flows, patch flows,
verification pipeline, experience selector, or retry implementation.
"""

from __future__ import annotations

from datetime import UTC, datetime

from schemas.common import RunStatus
from schemas.experiment_results import AgentCallRecord, RunProvenance, StageTimingRecord
from schemas.experiments import ExperimentConfiguration
from storage.repositories import ExperimentWriteRepository


class ExperimentRecorder:
    """Create run records and persist evidence supplied by later experiment executors."""

    def __init__(self, repository: ExperimentWriteRepository) -> None:
        self.repository = repository

    def register_configuration(self, config: ExperimentConfiguration) -> None:
        self.repository.create_configuration(config)

    def create_run(
        self,
        *,
        run_id: str,
        config: ExperimentConfiguration,
        repetition_index: int,
        baseline_commit: str,
        scenario_id: str | None = None,
        dataset_id: str | None = None,
        provenance: RunProvenance,
        started_at: datetime | None = None,
    ) -> None:
        """Create lifecycle/provenance records only; no experimental behavior is dispatched."""
        self.repository.create_run(
            run_id=run_id,
            config_id=config.config_id,
            repetition_index=repetition_index,
            baseline_commit=baseline_commit,
            scenario_id=scenario_id,
            dataset_id=dataset_id,
            started_at=started_at or datetime.now(UTC),
        )
        self.repository.record_provenance(run_id, provenance)
        self.repository.mark_running(run_id)

    def record_stage_timing(self, run_id: str, timing: StageTimingRecord) -> None:
        self.repository.record_stage_timing(run_id, timing)

    def record_agent_call(self, run_id: str, call: AgentCallRecord) -> None:
        self.repository.record_agent_call(run_id, call)

    def finish_run(
        self,
        run_id: str,
        *,
        status: RunStatus,
        system_error_code: str | None = None,
        system_error_summary: str | None = None,
        completed_at: datetime | None = None,
    ) -> None:
        self.repository.finalize_run(
            run_id,
            status=status,
            completed_at=completed_at,
            system_error_code=system_error_code,
            system_error_summary=system_error_summary,
        )
