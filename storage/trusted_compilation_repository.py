"""Atomic DEVELOPMENT-only persistence for trusted deterministic R3 preparation.

No provider, model decision, Git application, Docker, or FINAL_EVALUATION.
Kept separate from the existing legacy ExperimentWriteRepository methods.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from schemas.blue_team import BlueTeamAnalysisResult
from schemas.common import ResearchQuestion, RunStatus, RunType, WorkflowState
from schemas.experiment_results import ArtifactType
from schemas.patches import PatchGenerationResult
from schemas.trusted_compilation import TrustedCompilerStoredOutcome
from services.trusted_remediation_compiler import (
    EXPECTED_SOURCE_SHA256, SOURCE, TARGET, RULES,
    TrustedCompilerOutcome, _changes, _function_ast,
    _trusted_candidate_function, canon, sha,
)
from storage.models import (
    ExperimentConfigurationRow, ExperimentRunRow, PatchAttemptRow,
    ResultArtifactRow,
)
from storage.repositories import (
    ExperimentWriteRepository, ResearchStorageError,
    canonical_model_json, canonical_sha256,
)


@dataclass(frozen=True, slots=True)
class TrustedCompilationReceipt:
    run_id: str
    attempt_number: int
    status: str
    provenance_artifact_id: int
    provenance_payload_sha256: str
    generation_artifact_id: int | None
    generation_payload_sha256: str | None
    # No patch is accepted here. Only isolated verification can accept it.
    accepted: bool = False


class TrustedCompilationWriteRepository(ExperimentWriteRepository):
    """Additive repository facade: one database transaction per compiler outcome."""

    def __init__(self, session_factory, *, project_root: Path) -> None:
        super().__init__(session_factory)
        self.project_root=project_root.resolve(strict=False)

    def _before_commit(self, session: Session) -> None:
        """No-op failure-injection seam, called after flushing all rows."""
        return None

    def _lock_run(self, session: Session, run_id: str) -> ExperimentRunRow:
        # SQLite does not support SELECT FOR UPDATE. Acquire a writer lock
        # before checking duplicate artifacts; guard is process-independent.
        if session.get_bind().dialect.name=="sqlite":
            session.connection().exec_driver_sql("BEGIN IMMEDIATE")
        stmt=select(ExperimentRunRow).where(ExperimentRunRow.run_id==run_id)
        if session.get_bind().dialect.name!="sqlite":
            stmt=stmt.with_for_update()
        run=session.scalar(stmt)
        if run is None or run.status!=RunStatus.RUNNING.value:
            raise ResearchStorageError("trusted compilation requires a running run")
        cfg=session.get(ExperimentConfigurationRow,run.config_id)
        if cfg is None or cfg.run_type!=RunType.DEVELOPMENT.value or cfg.research_question!=ResearchQuestion.RQ1.value:
            raise ResearchStorageError("trusted compiler persistence is DEVELOPMENT RQ1 only")
        if run.scenario_id is None or run.dataset_id is not None:
            raise ResearchStorageError("trusted compiler persistence requires one RQ1 scenario")
        return run

    @staticmethod
    def _recorded_blue(session: Session, analysis: BlueTeamAnalysisResult) -> None:
        rows=session.scalars(select(ResultArtifactRow).where(
            ResultArtifactRow.run_id==analysis.run_id,
            ResultArtifactRow.artifact_type==ArtifactType.BLUE_TEAM_ANALYSIS_RESULT.value,
        )).all()
        if len(rows)!=1 or rows[0].payload_sha256!=canonical_sha256(canonical_model_json(analysis)):
            raise ResearchStorageError("recorded Blue analysis differs from provided analysis")

    @staticmethod
    def _unique_attempt(session: Session, run_id: str, attempt: int) -> None:
        rows=session.scalars(select(ResultArtifactRow).where(
            ResultArtifactRow.run_id==run_id,
            ResultArtifactRow.attempt_number==attempt,
            ResultArtifactRow.artifact_type==ArtifactType.TRUSTED_COMPILER_OUTCOME.value,
        )).all()
        if rows:
            raise ResearchStorageError("duplicate trusted compiler outcome for attempt")
        attempt_row=session.scalar(select(PatchAttemptRow).where(
            PatchAttemptRow.run_id==run_id,
            PatchAttemptRow.attempt_number==attempt,
        ))
        if attempt_row is not None:
            raise ResearchStorageError("patch attempt already recorded for this attempt")

    def _verified_stored(self, *, outcome: TrustedCompilerOutcome,
                         analysis: BlueTeamAnalysisResult) -> TrustedCompilerStoredOutcome:
        p=outcome.provenance
        if p.run_id!=analysis.run_id or p.target_id!=analysis.target_id or p.target_id!=TARGET:
            raise ResearchStorageError("compiler and Blue run/target mismatch")
        if p.blue_analysis_sha256!=sha(canon(analysis.model_dump(mode="json"))):
            raise ResearchStorageError("compiler Blue analysis digest mismatch")
        compiler_file=Path(__file__).resolve().parents[1]/"services/trusted_remediation_compiler.py"
        if p.compiler_sha256!=hashlib.sha256(compiler_file.read_bytes()).hexdigest():
            raise ResearchStorageError("compiler module identity mismatch")
        generation=outcome.generation
        if p.status=="prepared":
            if generation is None or p.reason_code!="prepared":
                raise ResearchStorageError("prepared outcome has no real generation")
            if analysis.code_finding is None:
                raise ResearchStorageError("prepared outcome has no Blue finding")
            try:
                rule=_trusted_candidate_function(analysis)
            except Exception as exc:
                raise ResearchStorageError("Blue source is not a supported registered rule") from exc
            if p.rule_id!=rule.rule_id or p.strategy!=rule.strategy or p.source_file!=SOURCE:
                raise ResearchStorageError("trusted strategy and registered rule mismatch")
            src_path=self.project_root/SOURCE
            if src_path.is_symlink() or not src_path.is_file():
                raise ResearchStorageError("trusted source is not a regular file")
            src_bytes=src_path.read_bytes()
            source_sha=sha(src_bytes)
            if source_sha!=EXPECTED_SOURCE_SHA256 or p.source_sha256!=source_sha:
                raise ResearchStorageError("source identity changed")
            text=src_bytes.decode("utf-8",errors="strict")
            try:
                ast_sha=_function_ast(text,rule)
            except Exception as exc:
                raise ResearchStorageError("source AST no longer matches registered rule") from exc
            if p.function_ast_sha256!=ast_sha:
                raise ResearchStorageError("compiled function AST mismatch")
            proposal=generation.proposal
            prepared=generation.prepared_patch
            if (generation.run_id,generation.target_id,generation.attempt_number)!=(
                    p.run_id,p.target_id,p.attempt_number):
                raise ResearchStorageError("generation identity mismatch")
            if generation.final_state!=WorkflowState.PATCH_VALIDATING:
                raise ResearchStorageError("unverified patch generation state")
            expected_changes=_changes(rule,text)
            if tuple(proposal.changes)!=expected_changes:
                raise ResearchStorageError("proposal does not match deterministic anchors")
            if (proposal.run_id,proposal.target_id,proposal.attempt_number)!=(
                    p.run_id,p.target_id,p.attempt_number):
                raise ResearchStorageError("proposal identity mismatch")
            if len(prepared.files)!=1 or prepared.files[0].file_path!=SOURCE:
                raise ResearchStorageError("trusted generator must change exactly one approved file")
            if (prepared.run_id,prepared.target_id,prepared.attempt_number)!=(
                    p.run_id,p.target_id,p.attempt_number):
                raise ResearchStorageError("prepared patch identity mismatch")
            if prepared.files[0].original_sha256!=source_sha:
                raise ResearchStorageError("prepared source hash mismatch")
            derived=text
            for change in expected_changes:
                if derived.count(change.original_content)!=1:
                    raise ResearchStorageError("grounded source anchor mismatch")
                derived=derived.replace(change.original_content,change.replacement_content,1)
            if prepared.files[0].replacement_content!=derived:
                raise ResearchStorageError("prepared replacement is not fixed trusted output")
            if sha(derived.encode())!=prepared.files[0].replacement_sha256:
                raise ResearchStorageError("prepared replacement hash mismatch")
            if (p.proposal_sha256!=sha(canon(proposal.model_dump(mode="json")))
                or p.prepared_diff_sha256!=prepared.diff_sha256
                or hashlib.sha256(prepared.unified_diff.encode()).hexdigest()!=prepared.diff_sha256):
                raise ResearchStorageError("proposal/diff digests disagree")
            gen_hash=canonical_sha256(canonical_model_json(generation))
        else:
            if generation is not None or p.proposal_sha256 is not None or p.prepared_diff_sha256 is not None:
                raise ResearchStorageError("rejected compiler claimed prepared patch")
            gen_hash=None
        return TrustedCompilerStoredOutcome.model_validate({
            **p.model_dump(mode="json"),
            "generation_artifact_sha256":gen_hash,
        })

    def persist(self, *, outcome: TrustedCompilerOutcome,
                analysis: BlueTeamAnalysisResult) -> TrustedCompilationReceipt:
        """Atomically persist true prepared+provenance, or terminal rejection.

        No second transaction is used by the public legacy generation writer.
        On failure, the context manager rolls back every new row and status.
        """
        stored=self._verified_stored(outcome=outcome,analysis=analysis)
        p=outcome.provenance
        with self._factory() as session:
            run=self._lock_run(session,p.run_id)
            self._recorded_blue(session,analysis)
            self._unique_attempt(session,p.run_id,p.attempt_number)
            gen_id=None
            if outcome.generation is not None:
                generation=outcome.generation
                legacy=self._artifact_row(p.run_id,ArtifactType.PATCH_GENERATION_RESULT,
                                          generation,p.attempt_number)
                if legacy.payload_sha256!=stored.generation_artifact_sha256:
                    raise ResearchStorageError("generation canonical payload mismatch")
                session.add(legacy)
                session.flush()
                prepared=generation.prepared_patch
                session.add(PatchAttemptRow(
                    run_id=p.run_id,
                    attempt_number=p.attempt_number,
                    prepared_patch_artifact_id=legacy.artifact_id,
                    prepared_diff_sha256=prepared.diff_sha256,
                    files_changed=prepared.files_changed,
                    inserted_lines=prepared.inserted_lines,
                    deleted_lines=prepared.deleted_lines,
                    total_diff_bytes=prepared.total_diff_bytes,
                    changed_paths_json='["'+SOURCE+'"]',
                    generated_test_path=prepared.generated_test_path,
                    final_state=generation.final_state.value,
                ))
                gen_id=legacy.artifact_id
            else:
                # Source not repaired. An ineligibility is a completed
                # DEVELOPMENT attempt, NOT an accepted patch.
                run.status=RunStatus.COMPLETED.value
                from datetime import UTC, datetime
                run.completed_at=datetime.now(UTC)
                run.system_error_code="trusted_compiler_rejected"
                run.system_error_summary=p.reason_code
            artifact=self._artifact_row(p.run_id,ArtifactType.TRUSTED_COMPILER_OUTCOME,
                                        stored,p.attempt_number)
            session.add(artifact)
            session.flush()
            self._before_commit(session)
            prov_id=artifact.artifact_id
            prov_hash=artifact.payload_sha256
            session.commit()
        return TrustedCompilationReceipt(
            run_id=p.run_id,attempt_number=p.attempt_number,status=p.status,
            provenance_artifact_id=prov_id,provenance_payload_sha256=prov_hash,
            generation_artifact_id=gen_id,
            generation_payload_sha256=stored.generation_artifact_sha256)
