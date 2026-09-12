"""Milestone 18 RQ2 frozen-dataset tooling tests using synthetic captures only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
import inspect
import json
from pathlib import Path

import pytest
from pydantic import ValidationError
from sqlalchemy import func, select

from experiments.rq2_dataset import (
    RQ2_DATASET_ID,
    RQ2_DATASET_VERSION,
    RQ2_EXPECTED_CLASS_COUNTS,
    RQ2_EXPECTED_ITEM_COUNT,
    RQ2_EXPECTED_TEST_IDS,
    RQ2_REPETITIONS_PER_TEST,
    RQ2DatasetError,
    build_candidate_dataset,
    capture_observations_from_execution,
    classifier_payload_sha256,
    load_classifier_dataset,
    load_evaluation_dataset,
    materialize_log_read_result,
    seed_evaluation_truth,
    semantic_input_sha256,
)
from schemas.common import ClassificationLabel
from schemas.experiments import ClassificationMode
from schemas.logging import ApplicationEventType, ApplicationLogEvent, LogReadResult
from schemas.red_team import HttpExchangeEvidence, TestExecutionResult as SecurityTestExecutionResult
from schemas.rq2_dataset import RQ2CapturedObservation, RQ2DatasetInputItem, RQ2GroundTruthItem, RQ2SourceKind
from security_tests.registry import SecurityTestRegistry
from services.target_registry import TargetRegistry
from storage.database import create_database_engine, initialize_database, make_session_factory
from storage.models import Base, ClassificationTruthRow, DatasetItemRow
from storage.repositories import EvaluationTruthRepository, ExperimentWriteRepository


ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 9, 12, 12, 0, tzinfo=UTC)


def _registries() -> tuple[TargetRegistry, SecurityTestRegistry]:
    targets = TargetRegistry.from_directories(
        targets_dir=ROOT / "config" / "targets",
        security_tests_dir=ROOT / "config" / "security_tests",
    )
    tests = SecurityTestRegistry.default()
    tests.validate_against_target_registry(targets)
    return targets, tests


def _semantics(test_id: str, step, kind: RQ2SourceKind):
    if test_id == "sqli-login-bypass-001":
        return (
            ApplicationEventType.DATABASE_EVENT,
            "login",
            {
                "operation": "login_lookup",
                "username": step.json_body["username"],
                "matched": kind == RQ2SourceKind.ATTACK,
                "authenticated": kind == RQ2SourceKind.ATTACK,
            },
        )
    if test_id == "xss-reflection-001":
        return (
            ApplicationEventType.VALIDATION_EVENT,
            "search",
            {"field": "q", "value": step.query_params["q"], "accepted": True},
        )
    if test_id == "path-traversal-private-file-001":
        return (
            ApplicationEventType.FILE_ACCESS_EVENT,
            "file_read",
            {"requested_path": step.query_params["path"], "outcome": "allowed"},
        )
    raise AssertionError(test_id)


def _synthetic_captures() -> tuple[RQ2CapturedObservation, ...]:
    targets, tests = _registries()
    captures: list[RQ2CapturedObservation] = []
    for test_position, test_id in enumerate(RQ2_EXPECTED_TEST_IDS, start=1):
        metadata = targets.get_security_test(test_id)
        steps = tests.get(test_id).build_steps()
        assert len(steps) == 2
        for repetition in range(1, RQ2_REPETITIONS_PER_TEST + 1):
            for step_position, (kind, step) in enumerate(
                zip((RQ2SourceKind.CONTROL, RQ2SourceKind.ATTACK), steps, strict=True),
                start=1,
            ):
                event_type, route_name, attributes = _semantics(test_id, step, kind)
                captures.append(
                    RQ2CapturedObservation(
                        source_test_id=test_id,
                        source_step_id=step.step_id,
                        source_repetition=repetition,
                        source_kind=kind,
                        event=ApplicationLogEvent(
                            schema_version="1.0",
                            event_id=f"evt-{test_position:02d}-{repetition:02d}-{step_position:02d}",
                            timestamp=START
                            + timedelta(minutes=test_position, seconds=repetition * 2 + step_position),
                            run_id=f"capture-run-{test_position:02d}-{repetition:02d}",
                            request_id=f"req-{test_position:02d}-{repetition:02d}-{step_position:02d}",
                            event_type=event_type,
                            component="vulnerable_store",
                            route_name=route_name,
                            method=step.method.value,
                            attributes=attributes,
                        ),
                    )
                )
    assert len(captures) == 60
    return tuple(captures)


def _build(tmp_path: Path):
    targets, tests = _registries()
    dataset_dir = tmp_path / "candidate"
    manifest = build_candidate_dataset(
        _synthetic_captures(),
        output_dir=dataset_dir,
        target_registry=targets,
        test_registry=tests,
    )
    return dataset_dir, manifest


def _rewrite_manifest_input_hash(dataset_dir: Path) -> None:
    from hashlib import sha256

    manifest_path = dataset_dir / "manifest.json"
    payload = json.loads(manifest_path.read_text())
    payload["inputs_sha256"] = sha256((dataset_dir / "inputs.jsonl").read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n")


def test_runtime_capture_adapter_selects_real_semantic_event_by_executor_request_id() -> None:
    targets, tests = _registries()
    test_id = "xss-reflection-001"
    steps = tests.get(test_id).build_steps()
    run_id = "runtime-capture-one"
    exchanges = tuple(
        HttpExchangeEvidence(
            exchange_id=f"exchange-{index:02d}",
            request_id=f"req-runtime-{index:02d}",
            step_id=step.step_id,
            endpoint_id=step.endpoint_id,
            method=step.method.value,
            status_code=200,
            duration_ms=1,
        )
        for index, step in enumerate(steps, start=1)
    )
    execution = SecurityTestExecutionResult(
        run_id=run_id,
        target_id="vulnerable-store",
        test_id=test_id,
        attempt_number=1,
        request_count=2,
        completed=True,
        status_code=200,
        exchanges=exchanges,
        duration_ms=2,
    )
    events = []
    for index, (step, exchange, kind) in enumerate(
        zip(steps, exchanges, (RQ2SourceKind.CONTROL, RQ2SourceKind.ATTACK), strict=True),
        start=1,
    ):
        event_type, route_name, attributes = _semantics(test_id, step, kind)
        events.extend(
            (
                ApplicationLogEvent(
                    schema_version="1.0",
                    event_id=f"semantic-{index}",
                    timestamp=START,
                    run_id=run_id,
                    request_id=exchange.request_id,
                    event_type=event_type,
                    component="vulnerable_store",
                    route_name=route_name,
                    method=step.method.value,
                    attributes=attributes,
                ),
                ApplicationLogEvent(
                    schema_version="1.0",
                    event_id=f"http-{index}",
                    timestamp=START,
                    run_id=run_id,
                    request_id=exchange.request_id,
                    event_type=ApplicationEventType.HTTP_REQUEST,
                    component="vulnerable_store",
                    route_name=route_name,
                    method=step.method.value,
                    status_code=200,
                ),
            )
        )
    logs = LogReadResult(target_id="vulnerable-store", run_id=run_id, events=tuple(events))

    control, attack = capture_observations_from_execution(
        execution=execution,
        logs=logs,
        source_repetition=1,
        target_registry=targets,
        test_registry=tests,
    )

    assert control.source_kind == RQ2SourceKind.CONTROL
    assert attack.source_kind == RQ2SourceKind.ATTACK
    assert control.event.event_id == "semantic-1"
    assert attack.event.event_id == "semantic-2"


def test_candidate_builder_freezes_exact_counts_hashes_and_duplication_audit(tmp_path: Path) -> None:
    dataset_dir, manifest = _build(tmp_path)
    loaded_manifest, inputs, truth = load_evaluation_dataset(dataset_dir)

    assert loaded_manifest == manifest
    assert manifest.dataset_id == RQ2_DATASET_ID
    assert manifest.dataset_version == RQ2_DATASET_VERSION
    assert manifest.item_count == RQ2_EXPECTED_ITEM_COUNT == 60
    assert manifest.expected_class_counts == RQ2_EXPECTED_CLASS_COUNTS
    assert len(inputs) == len(truth) == 60
    assert manifest.duplication_audit.total_events == 60
    assert manifest.duplication_audit.unique_event_ids == 60
    assert manifest.duplication_audit.unique_semantic_input_hashes < 60
    assert set(manifest.duplication_audit.repetition_group_sizes.values()) == {10}
    assert len(manifest.duplication_audit.repetition_group_sizes) == 6
    assert {item.ground_truth_label for item in truth} == {
        ClassificationLabel.SQL_INJECTION,
        ClassificationLabel.XSS,
        ClassificationLabel.PATH_TRAVERSAL,
        ClassificationLabel.BENIGN,
    }
    assert all(item.ground_truth_label != ClassificationLabel.UNKNOWN for item in truth)


def test_classifier_visible_projection_is_run_neutral_and_correlation_is_materialized_later(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    item = load_classifier_dataset(dataset_dir)[0]
    raw = item.model_dump(mode="json")
    rendered = json.dumps(raw, sort_keys=True)
    for forbidden in (
        "run_id",
        "request_id",
        "timestamp",
        "ground_truth_label",
        "source_test_id",
        "source_step_id",
        "source_notes",
        "source_file",
        "vulnerable_function",
    ):
        assert forbidden not in rendered

    first = materialize_log_read_result(
        item,
        target_id="vulnerable-store",
        run_id="runtime-a",
        request_id="req-runtime-a",
        timestamp=START,
    )
    second = materialize_log_read_result(
        item,
        target_id="vulnerable-store",
        run_id="runtime-b",
        request_id="req-runtime-b",
        timestamp=START + timedelta(seconds=1),
    )
    assert first.events[0].attributes == second.events[0].attributes
    assert first.events[0].route_name == second.events[0].route_name
    assert first.events[0].event_type == second.events[0].event_type
    assert first.run_id != second.run_id


def test_classifier_loader_never_requires_truth_and_has_no_mode_parameter(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    expected_hashes = tuple(item.classifier_input_sha256 for item in load_classifier_dataset(dataset_dir))
    (dataset_dir / "ground_truth.jsonl").unlink()

    signature = inspect.signature(load_classifier_dataset)
    assert "classification_mode" not in signature.parameters
    assert "mode" not in signature.parameters
    items = load_classifier_dataset(dataset_dir)
    assert tuple(item.classifier_input_sha256 for item in items) == expected_hashes

    # Future modes share this same frozen base sequence; mode is not an input to the loader.
    by_mode = {
        mode: tuple(item.classifier_input_sha256 for item in items)
        for mode in ClassificationMode
    }
    assert len(set(by_mode.values())) == 1


def test_legitimate_observable_xss_payload_is_not_mistaken_for_truth_leakage(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    _, inputs, truth = load_evaluation_dataset(dataset_dir)
    xss_truth_ids = {item.event_id for item in truth if item.ground_truth_label == ClassificationLabel.XSS}
    xss_inputs = [item for item in inputs if item.event_id in xss_truth_ids]
    assert xss_inputs
    assert any("fyp_xss_marker" in json.dumps(item.normalized_event.model_dump()) for item in xss_inputs)



def test_legitimate_observable_component_matching_target_id_is_allowed(tmp_path: Path) -> None:
    targets, tests = _registries()
    captures = list(_synthetic_captures())
    first = captures[0]
    captures[0] = first.model_copy(
        update={
            "event": first.event.model_copy(update={"component": "vulnerable-store"})
        }
    )
    dataset_dir = tmp_path / "candidate-target-component"
    build_candidate_dataset(
        tuple(captures),
        output_dir=dataset_dir,
        target_registry=targets,
        test_registry=tests,
    )
    _, inputs, _ = load_evaluation_dataset(dataset_dir)
    assert any(item.normalized_event.component == "vulnerable-store" for item in inputs)


def test_leakage_validator_rejects_forbidden_attribute_field_name(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    lines = (dataset_dir / "inputs.jsonl").read_text().splitlines()
    first = json.loads(lines[0])
    first["normalized_event"]["attributes"]["source_test_id"] = "hidden"
    normalized = first["normalized_event"]
    from hashlib import sha256

    semantic_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    first["semantic_input_sha256"] = sha256(semantic_json.encode()).hexdigest()
    classifier_payload = {"event_id": first["event_id"], "normalized_event": normalized}
    first["classifier_input_sha256"] = sha256(
        json.dumps(classifier_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    lines[0] = json.dumps(first, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    (dataset_dir / "inputs.jsonl").write_text("\n".join(lines) + "\n")
    _rewrite_manifest_input_hash(dataset_dir)

    with pytest.raises(RQ2DatasetError, match="field leaks"):
        load_classifier_dataset(dataset_dir)


def test_leakage_validator_rejects_evaluator_provenance_value(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    truth_lines = [json.loads(line) for line in (dataset_dir / "ground_truth.jsonl").read_text().splitlines()]
    truth_by_id = {item["event_id"]: item for item in truth_lines}
    input_lines = [json.loads(line) for line in (dataset_dir / "inputs.jsonl").read_text().splitlines()]
    first = input_lines[0]
    first_truth = truth_by_id[first["event_id"]]
    first["normalized_event"]["attributes"]["note"] = first_truth["source_test_id"]

    normalized = first["normalized_event"]
    from hashlib import sha256

    semantic_json = json.dumps(normalized, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    first["semantic_input_sha256"] = sha256(semantic_json.encode()).hexdigest()
    classifier_payload = {"event_id": first["event_id"], "normalized_event": normalized}
    first["classifier_input_sha256"] = sha256(
        json.dumps(classifier_payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()
    ).hexdigest()
    (dataset_dir / "inputs.jsonl").write_text(
        "\n".join(json.dumps(item, sort_keys=True, separators=(",", ":"), ensure_ascii=False) for item in input_lines)
        + "\n"
    )
    _rewrite_manifest_input_hash(dataset_dir)

    with pytest.raises(RQ2DatasetError, match="evaluator-only provenance"):
        load_evaluation_dataset(dataset_dir)


def test_manifest_hash_tampering_is_rejected(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    with (dataset_dir / "inputs.jsonl").open("a", encoding="utf-8") as handle:
        handle.write("{}\n")
    with pytest.raises(RQ2DatasetError, match="SHA-256"):
        load_classifier_dataset(dataset_dir)


def test_candidate_builder_refuses_incomplete_capture_set_and_overwrite(tmp_path: Path) -> None:
    targets, tests = _registries()
    captures = _synthetic_captures()
    with pytest.raises(RQ2DatasetError, match="exactly 60"):
        build_candidate_dataset(
            captures[:-1],
            output_dir=tmp_path / "short",
            target_registry=targets,
            test_registry=tests,
        )

    output = tmp_path / "full"
    build_candidate_dataset(captures, output_dir=output, target_registry=targets, test_registry=tests)
    with pytest.raises(RQ2DatasetError, match="refusing to overwrite"):
        build_candidate_dataset(captures, output_dir=output, target_registry=targets, test_registry=tests)


def test_unknown_is_prediction_only_not_valid_v1_ground_truth() -> None:
    with pytest.raises(ValidationError, match="does not permit unknown"):
        RQ2GroundTruthItem(
            event_id="rq2evt-deadbeef",
            ground_truth_label=ClassificationLabel.UNKNOWN,
            source_test_id="xss-reflection-001",
            source_step_id="unescaped-reflection",
            source_repetition=1,
            source_kind=RQ2SourceKind.ATTACK,
            source_target_id="vulnerable-store",
            source_endpoint_id="scenario-xss-search",
            source_run_id="run-one",
            source_request_id="req-one",
            source_event_id="evt-one",
            source_notes="fixture",
        )


def test_existing_evaluation_tables_seed_60_items_without_new_table(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    db = tmp_path / "rq2.db"
    engine = create_database_engine(f"sqlite:///{db}", project_root=tmp_path)
    initialize_database(engine)
    factory = make_session_factory(engine)
    truth_repo = EvaluationTruthRepository(factory)

    inserted = seed_evaluation_truth(truth_repo, dataset_dir=dataset_dir)
    assert len(inserted) == 60
    assert len(Base.metadata.tables) == 20
    assert not hasattr(ExperimentWriteRepository, "record_classification_truth")
    assert not hasattr(ExperimentWriteRepository, "record_dataset_item")

    with factory() as session:
        assert session.scalar(select(func.count()).select_from(DatasetItemRow)) == 60
        assert session.scalar(select(func.count()).select_from(ClassificationTruthRow)) == 60
        stored = tuple(session.scalars(select(DatasetItemRow).order_by(DatasetItemRow.event_id)))
    inputs = load_classifier_dataset(dataset_dir)
    expected = {item.event_id: item.classifier_input_sha256 for item in inputs}
    assert {row.event_id: row.normalized_input_sha256 for row in stored} == expected
    engine.dispose()


def test_hash_fields_revalidate_from_classifier_content(tmp_path: Path) -> None:
    dataset_dir, _ = _build(tmp_path)
    for item in load_classifier_dataset(dataset_dir):
        assert classifier_payload_sha256(item) == item.classifier_input_sha256
        assert semantic_input_sha256(item.normalized_event) == item.semantic_input_sha256
