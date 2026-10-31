"""R4-A read-only loader for genuine R3 deterministic PREPARED artifacts.

Does not create patch branches, invoke LLMs, run Docker, commit, or mutate a DB.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select

from schemas.blue_team import BlueTeamAnalysisResult
from schemas.common import ResearchQuestion, RunStatus, RunType, WorkflowState
from schemas.experiment_results import ArtifactType
from schemas.patches import PatchGenerationResult
from schemas.trusted_compilation import TrustedCompilerStoredOutcome
from services.trusted_remediation_compiler import (
    TrustedCompilerOutcome, TrustedCompilerProvenance, SOURCE
)
from storage.models import (
    ExperimentConfigurationRow, ExperimentRunRow, PatchAttemptRow, ResultArtifactRow,
)
from storage.repositories import ResearchStorageError, canonical_sha256
from storage.trusted_compilation_repository import TrustedCompilationWriteRepository


class TrustedPreparedLoadBlocked(ResearchStorageError):
    pass


@dataclass(frozen=True, slots=True)
class LoadedTrustedPrepared:
    generation: PatchGenerationResult
    provenance: TrustedCompilerStoredOutcome
    generation_artifact_id: int
    provenance_artifact_id: int
    baseline_commit: str
    # NEVER inferred from PREPARED alone.
    accepted: bool = False


class TrustedPreparedReadRepository:
    def __init__(self, session_factory, *, project_root: Path):
        self._factory=session_factory
        self._root=project_root.resolve(strict=False)
        self._verifier=TrustedCompilationWriteRepository(
            session_factory,project_root=self._root)

    def load(self, *, run_id: str, attempt_number: int,
             expected_baseline_commit: str | None = None) -> LoadedTrustedPrepared:
        """Fail closed if ANY cross-record, hash, source, or baseline check fails."""
        if attempt_number < 1:
            raise TrustedPreparedLoadBlocked("invalid attempt number")
        with self._factory() as session:
            run=session.get(ExperimentRunRow,run_id)
            if run is None or run.status!=RunStatus.RUNNING.value:
                raise TrustedPreparedLoadBlocked("prepared load requires running development run")
            config=session.get(ExperimentConfigurationRow,run.config_id)
            if (config is None or config.run_type!=RunType.DEVELOPMENT.value
                    or config.research_question!=ResearchQuestion.RQ1.value):
                raise TrustedPreparedLoadBlocked("FINAL or non-RQ1 prepared load prohibited")
            if expected_baseline_commit is not None and run.baseline_commit!=expected_baseline_commit:
                raise TrustedPreparedLoadBlocked("recorded baseline SHA differs")
            if run.baseline_commit is None or len(run.baseline_commit)!=40:
                raise TrustedPreparedLoadBlocked("run lacks a recorded 40-hex baseline")
            rows=list(session.scalars(select(ResultArtifactRow).where(
                ResultArtifactRow.run_id==run_id,
                ResultArtifactRow.attempt_number==attempt_number,
                ResultArtifactRow.artifact_type.in_((
                    ArtifactType.PATCH_GENERATION_RESULT.value,
                    ArtifactType.TRUSTED_COMPILER_OUTCOME.value,
                )),
            )))
            gen_rows=[r for r in rows if r.artifact_type==ArtifactType.PATCH_GENERATION_RESULT.value]
            provenance_rows=[r for r in rows if r.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value]
            if len(gen_rows)!=1 or len(provenance_rows)!=1:
                raise TrustedPreparedLoadBlocked("exactly one generation and one compiler provenance required")
            gen_row=gen_rows[0]; prov_row=provenance_rows[0]
            if (gen_row.schema_name!="PatchGenerationResult" or gen_row.schema_version!="1.0"
                or prov_row.schema_name!="TrustedCompilerStoredOutcome"
                or prov_row.schema_version!="r3-deterministic-v1"):
                raise TrustedPreparedLoadBlocked("artifact schema label/version mismatch")
            for row in (gen_row,prov_row):
                if canonical_sha256(row.payload_json)!=row.payload_sha256:
                    raise TrustedPreparedLoadBlocked("stored payload hash mismatch")
            try:
                generation=PatchGenerationResult.model_validate_json(gen_row.payload_json)
                provenance=TrustedCompilerStoredOutcome.model_validate_json(prov_row.payload_json)
            except Exception as exc:
                raise TrustedPreparedLoadBlocked("invalid stored typed artifact") from exc
            if (provenance.status!="prepared" or
                provenance.generation_artifact_sha256!=gen_row.payload_sha256 or
                provenance.run_id!=run_id or
                provenance.attempt_number!=attempt_number or
                provenance.target_id!=generation.target_id or
                generation.final_state!=WorkflowState.PATCH_VALIDATING):
                raise TrustedPreparedLoadBlocked("stored prepared provenance/generation mismatch")
            attempt=session.scalars(select(PatchAttemptRow).where(
                PatchAttemptRow.run_id==run_id,
                PatchAttemptRow.attempt_number==attempt_number)).all()
            if len(attempt)!=1:
                raise TrustedPreparedLoadBlocked("one patch attempt required")
            a=attempt[0]
            pp=generation.prepared_patch
            if (a.prepared_patch_artifact_id!=gen_row.artifact_id or
                a.prepared_diff_sha256!=pp.diff_sha256 or
                a.files_changed!=1 or
                a.final_state!=WorkflowState.PATCH_VALIDATING.value or
                a.branch_artifact_id is not None or a.verification_artifact_id is not None or
                a.accepted_commit_sha is not None or a.patch_decision is not None or
                a.branch_name is not None or a.git_diff_sha256 is not None or
                a.changed_paths_json != json.dumps([SOURCE],separators=(",",":"))):
                raise TrustedPreparedLoadBlocked("patch attempt is not exactly an unverified prepared candidate")
            blues=list(session.scalars(select(ResultArtifactRow).where(
                ResultArtifactRow.run_id==run_id,
                ResultArtifactRow.artifact_type==ArtifactType.BLUE_TEAM_ANALYSIS_RESULT.value,
            )))
            if len(blues)!=1 or canonical_sha256(blues[0].payload_json)!=blues[0].payload_sha256:
                raise TrustedPreparedLoadBlocked("exactly one intact Blue analysis required")
            try:
                blue=BlueTeamAnalysisResult.model_validate_json(blues[0].payload_json)
                origin=TrustedCompilerProvenance.model_validate(
                    provenance.model_dump(mode="json",exclude={"generation_artifact_sha256"}))
                reconstructed=TrustedCompilerOutcome(provenance=origin,generation=generation)
                revalidated=self._verifier._verified_stored(outcome=reconstructed,analysis=blue)
            except Exception as exc:
                raise TrustedPreparedLoadBlocked("trusted reconstruction/hash/source validation failed") from exc
            if revalidated!=provenance:
                raise TrustedPreparedLoadBlocked("stored compiler outcome differs from trusted recomputation")
            if pp.files[0].file_path!=SOURCE:
                raise TrustedPreparedLoadBlocked("unregistered prepared source path")
            return LoadedTrustedPrepared(
                generation=generation,provenance=provenance,
                generation_artifact_id=gen_row.artifact_id,
                provenance_artifact_id=prov_row.artifact_id,
                baseline_commit=run.baseline_commit)
