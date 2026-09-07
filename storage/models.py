"""SQLAlchemy models for append-oriented Milestone 15 research evidence."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class ExperimentConfigurationRow(Base):
    __tablename__ = "experiment_configurations"

    config_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    run_type: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    research_question: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    scenario_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
    dataset_id: Mapped[str | None] = mapped_column(String(100))
    repetitions: Mapped[int] = mapped_column(Integer, nullable=False)
    blue_team_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    classification_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    retry_feedback_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    experience_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    model_provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    configuration_json: Mapped[str] = mapped_column(Text, nullable=False)
    configuration_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ExperimentRunRow(Base):
    __tablename__ = "experiment_runs"

    run_id: Mapped[str] = mapped_column(String(100), primary_key=True)
    config_id: Mapped[str] = mapped_column(ForeignKey("experiment_configurations.config_id"), nullable=False, index=True)
    repetition_index: Mapped[int] = mapped_column(Integer, nullable=False)
    scenario_id: Mapped[str | None] = mapped_column(String(100), index=True)
    dataset_id: Mapped[str | None] = mapped_column(String(100), index=True)
    status: Mapped[str] = mapped_column(String(40), nullable=False, index=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    baseline_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    system_error_code: Mapped[str | None] = mapped_column(String(100))
    system_error_summary: Mapped[str | None] = mapped_column(Text)


class RunProvenanceRow(Base):
    __tablename__ = "run_provenance"

    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), primary_key=True)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    framework_git_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    baseline_git_commit: Mapped[str] = mapped_column(String(40), nullable=False)
    prompt_set_version: Mapped[str] = mapped_column(String(100), nullable=False)
    schema_set_version: Mapped[str] = mapped_column(String(100), nullable=False)
    agent_configuration_version: Mapped[str] = mapped_column(String(100), nullable=False)
    context_policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    scenario_version: Mapped[str | None] = mapped_column(String(100))
    dataset_version: Mapped[str | None] = mapped_column(String(100))
    rule_version: Mapped[str] = mapped_column(String(100), nullable=False)
    test_suite_version: Mapped[str] = mapped_column(String(100), nullable=False)
    verification_policy_version: Mapped[str] = mapped_column(String(100), nullable=False)
    random_seed: Mapped[int | None] = mapped_column(Integer)


class ResultArtifactRow(Base):
    __tablename__ = "result_artifacts"

    artifact_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    attempt_number: Mapped[int | None] = mapped_column(Integer)
    artifact_type: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    schema_name: Mapped[str] = mapped_column(String(120), nullable=False)
    schema_version: Mapped[str] = mapped_column(String(40), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class ScenarioTruthRow(Base):
    __tablename__ = "scenario_truth_snapshots"

    truth_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scenario_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    scenario_version: Mapped[str] = mapped_column(String(100), nullable=False)
    vulnerability_class: Mapped[str] = mapped_column(String(40), nullable=False)
    source_file: Mapped[str] = mapped_column(Text, nullable=False)
    function_or_route: Mapped[str] = mapped_column(Text, nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    payload_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    __table_args__ = (UniqueConstraint("scenario_id", "scenario_version", name="uq_scenario_truth_version"),)


class RunClassificationRow(Base):
    __tablename__ = "run_classifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, unique=True, index=True)
    classification_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    predicted_label: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    supporting_event_ids_json: Mapped[str] = mapped_column(Text, nullable=False)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("result_artifacts.artifact_id"), nullable=False)


class DatasetItemRow(Base):
    __tablename__ = "classification_dataset_items"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dataset_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    dataset_version: Mapped[str] = mapped_column(String(100), nullable=False)
    event_id: Mapped[str] = mapped_column(String(100), nullable=False)
    normalized_input_json: Mapped[str] = mapped_column(Text, nullable=False)
    normalized_input_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    __table_args__ = (UniqueConstraint("dataset_id", "dataset_version", "event_id", name="uq_dataset_item"),)


class ClassificationTruthRow(Base):
    __tablename__ = "classification_ground_truth"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    dataset_item_id: Mapped[int] = mapped_column(ForeignKey("classification_dataset_items.id"), nullable=False, unique=True)
    ground_truth_label: Mapped[str] = mapped_column(String(40), nullable=False)
    source_notes: Mapped[str | None] = mapped_column(Text)


class EventClassificationRow(Base):
    __tablename__ = "event_classifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    dataset_item_id: Mapped[int] = mapped_column(ForeignKey("classification_dataset_items.id"), nullable=False, index=True)
    classification_mode: Mapped[str] = mapped_column(String(40), nullable=False)
    predicted_label: Mapped[str] = mapped_column(String(40), nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_id: Mapped[int | None] = mapped_column(ForeignKey("result_artifacts.artifact_id"))
    __table_args__ = (UniqueConstraint("run_id", "dataset_item_id", "classification_mode", name="uq_event_prediction"),)


class CodeFindingRow(Base):
    __tablename__ = "code_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, unique=True)
    file_path: Mapped[str] = mapped_column(Text, nullable=False)
    function_or_route: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(nullable=False)
    artifact_id: Mapped[int] = mapped_column(ForeignKey("result_artifacts.artifact_id"), nullable=False)


class StageTimingRow(Base):
    __tablename__ = "stage_timings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    attempt_number: Mapped[int | None] = mapped_column(Integer)
    stage_id: Mapped[str] = mapped_column(String(100), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("run_id", "sequence_number", name="uq_stage_sequence"),)


class SecurityTestExecutionRow(Base):
    __tablename__ = "security_test_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    purpose: Mapped[str] = mapped_column(String(50), nullable=False)
    red_attempt_number: Mapped[int | None] = mapped_column(Integer)
    patch_attempt_number: Mapped[int | None] = mapped_column(Integer)
    test_id: Mapped[str] = mapped_column(String(100), nullable=False)
    vulnerability_class: Mapped[str | None] = mapped_column(String(40))
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    completed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    timed_out: Mapped[bool] = mapped_column(Boolean, nullable=False)
    request_count: Mapped[int] = mapped_column(Integer, nullable=False)
    status_code: Mapped[int | None] = mapped_column(Integer)
    exploit_evidence_observed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    confirmed: Mapped[bool | None] = mapped_column(Boolean)
    error_code: Mapped[str | None] = mapped_column(String(100))
    artifact_id: Mapped[int | None] = mapped_column(ForeignKey("result_artifacts.artifact_id"))


class PatchAttemptRow(Base):
    __tablename__ = "patch_attempts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    prepared_patch_artifact_id: Mapped[int | None] = mapped_column(ForeignKey("result_artifacts.artifact_id"))
    branch_artifact_id: Mapped[int | None] = mapped_column(ForeignKey("result_artifacts.artifact_id"))
    verification_artifact_id: Mapped[int | None] = mapped_column(ForeignKey("result_artifacts.artifact_id"))
    branch_name: Mapped[str | None] = mapped_column(String(240))
    base_commit: Mapped[str | None] = mapped_column(String(40))
    prepared_diff_sha256: Mapped[str | None] = mapped_column(String(64))
    git_diff_sha256: Mapped[str | None] = mapped_column(String(64))
    files_changed: Mapped[int | None] = mapped_column(Integer)
    inserted_lines: Mapped[int | None] = mapped_column(Integer)
    deleted_lines: Mapped[int | None] = mapped_column(Integer)
    total_diff_bytes: Mapped[int | None] = mapped_column(Integer)
    changed_paths_json: Mapped[str | None] = mapped_column(Text)
    generated_test_path: Mapped[str | None] = mapped_column(Text)
    final_state: Mapped[str | None] = mapped_column(String(40), index=True)
    patch_decision: Mapped[str | None] = mapped_column(String(40))
    rejection_reason: Mapped[str | None] = mapped_column(Text)
    failure_reason: Mapped[str | None] = mapped_column(Text)
    accepted_commit_sha: Mapped[str | None] = mapped_column(String(40))
    patch_prepared_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    verification_decision_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    attempt_completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (UniqueConstraint("run_id", "attempt_number", name="uq_patch_attempt"),)


class PatchFeedbackRow(Base):
    __tablename__ = "patch_feedback_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    source_attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    receiving_attempt_number: Mapped[int] = mapped_column(Integer, nullable=False)
    feedback_artifact_id: Mapped[int] = mapped_column(ForeignKey("result_artifacts.artifact_id"), nullable=False)
    __table_args__ = (UniqueConstraint("run_id", "receiving_attempt_number", name="uq_patch_feedback_receiving_attempt"),)


class VerificationStageRow(Base):
    __tablename__ = "verification_stages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patch_attempt_id: Mapped[int] = mapped_column(ForeignKey("patch_attempts.id"), nullable=False, index=True)
    stage_id: Mapped[str] = mapped_column(String(100), nullable=False)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    required: Mapped[bool] = mapped_column(Boolean, nullable=False)
    passed: Mapped[bool] = mapped_column(Boolean, nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    __table_args__ = (UniqueConstraint("patch_attempt_id", "stage_id", name="uq_verification_stage"),)


class FunctionalCheckRow(Base):
    __tablename__ = "functional_checks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    patch_attempt_id: Mapped[int] = mapped_column(ForeignKey("patch_attempts.id"), nullable=False, index=True)
    check_id: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[str] = mapped_column(String(30), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    details: Mapped[str] = mapped_column(Text, nullable=False)
    __table_args__ = (UniqueConstraint("patch_attempt_id", "check_id", name="uq_functional_check"),)


class AgentCallRow(Base):
    __tablename__ = "agent_calls"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    call_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    sequence_number: Mapped[int] = mapped_column(Integer, nullable=False)
    agent_role: Mapped[str] = mapped_column(String(80), nullable=False)
    provider: Mapped[str] = mapped_column(String(100), nullable=False)
    model_name: Mapped[str] = mapped_column(String(100), nullable=False)
    duration_ms: Mapped[int] = mapped_column(Integer, nullable=False)
    result_status: Mapped[str] = mapped_column(String(40), nullable=False)
    classification_observation_id: Mapped[int | None] = mapped_column(ForeignKey("event_classifications.id"))
    patch_attempt_number: Mapped[int | None] = mapped_column(Integer)
    red_attempt_number: Mapped[int | None] = mapped_column(Integer)
    input_tokens: Mapped[int | None] = mapped_column(Integer)
    output_tokens: Mapped[int | None] = mapped_column(Integer)
    token_usage_status: Mapped[str] = mapped_column(String(30), nullable=False)
    estimated_cost: Mapped[Decimal | None] = mapped_column(Numeric(18, 8))
    cost_status: Mapped[str] = mapped_column(String(30), nullable=False)
    currency: Mapped[str | None] = mapped_column(String(3))
    pricing_version: Mapped[str | None] = mapped_column(String(100))
    source_audit_event_id: Mapped[str | None] = mapped_column(String(100))
    __table_args__ = (UniqueConstraint("run_id", "sequence_number", name="uq_agent_call_sequence"),)


class AuditRunManifestRow(Base):
    __tablename__ = "audit_run_manifests"

    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), primary_key=True)
    audit_source: Mapped[str] = mapped_column(Text, nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    blocked_count: Mapped[int] = mapped_column(Integer, nullable=False)
    failed_count: Mapped[int] = mapped_column(Integer, nullable=False)
    first_event_id: Mapped[str | None] = mapped_column(String(100))
    last_event_id: Mapped[str | None] = mapped_column(String(100))
    canonical_run_audit_sha256: Mapped[str] = mapped_column(String(64), nullable=False)


class PolicyEventReferenceRow(Base):
    __tablename__ = "policy_event_references"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    audit_event_id: Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    operation: Mapped[str] = mapped_column(String(100), nullable=False)
    policy_decision: Mapped[str] = mapped_column(String(30), nullable=False)
    policy_reason: Mapped[str | None] = mapped_column(String(100))
    execution_status: Mapped[str] = mapped_column(String(30), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(100))


class ScoreRecordRow(Base):
    __tablename__ = "score_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    run_id: Mapped[str] = mapped_column(ForeignKey("experiment_runs.run_id"), nullable=False, index=True)
    score_type: Mapped[str] = mapped_column(String(20), nullable=False)
    score_value: Mapped[Decimal] = mapped_column(Numeric(18, 8), nullable=False)
    scoring_version: Mapped[str] = mapped_column(String(100), nullable=False)
    evidence_reference: Mapped[str] = mapped_column(Text, nullable=False)
    __table_args__ = (
        UniqueConstraint("run_id", "score_type", "scoring_version", name="uq_score_run_type_version"),
    )
