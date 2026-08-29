"""Post-execution completeness and integrity checks for stored research evidence."""

from __future__ import annotations

import hashlib

from sqlalchemy import select

from schemas.common import RunType
from storage.models import (
    AgentCallRow,
    ExperimentConfigurationRow,
    ExperimentRunRow,
    ResultArtifactRow,
    RunProvenanceRow,
)
from storage.repositories import ResearchReadRepository


def validate_run_completeness(repository: ResearchReadRepository, run_id: str) -> dict:
    """Return deterministic completeness findings without changing stored data."""
    findings: list[str] = []
    with repository.session() as session:
        run = session.get(ExperimentRunRow, run_id)
        if run is None:
            return {"run_id": run_id, "complete": False, "findings": ["run_not_found"]}
        config = session.get(ExperimentConfigurationRow, run.config_id)
        provenance = session.get(RunProvenanceRow, run_id)
        if config is None:
            findings.append("configuration_missing")
        if provenance is None:
            findings.append("provenance_missing")
        else:
            if run.scenario_id is not None and provenance.scenario_version is None:
                findings.append("scenario_version_missing")
            if run.dataset_id is not None and provenance.dataset_version is None:
                findings.append("dataset_version_missing")
        for artifact in session.scalars(select(ResultArtifactRow).where(ResultArtifactRow.run_id == run_id)):
            actual = hashlib.sha256(artifact.payload_json.encode("utf-8")).hexdigest()
            if actual != artifact.payload_sha256:
                findings.append(f"artifact_hash_mismatch:{artifact.artifact_id}")
        for call in session.scalars(select(AgentCallRow).where(AgentCallRow.run_id == run_id)):
            if call.token_usage_status == "not_reported":
                findings.append(f"token_usage_not_reported:{call.call_id}")
            if call.cost_status == "not_reported":
                findings.append(f"cost_not_reported:{call.call_id}")
        if config and config.run_type == RunType.FINAL_EVALUATION.value and run.status in {"created", "running"}:
            findings.append("final_evaluation_incomplete")
    return {"run_id": run_id, "complete": not findings, "findings": findings}
