"""Milestone 18 tooling for the frozen RQ2 classification dataset.

This module never executes attacks. It accepts already-captured observations
from the controlled runtime, removes volatile correlation from classifier-visible
content, validates evaluator separation, and writes/loads frozen dataset files.
"""

from __future__ import annotations

from collections import Counter
from datetime import datetime
from hashlib import sha256
import json
from pathlib import Path
from typing import Iterable

from schemas.common import ClassificationLabel, VulnerabilityClass
from schemas.logging import ApplicationEventType, ApplicationLogEvent, LogReadResult
from schemas.red_team import TestExecutionResult
from schemas.rq2_dataset import (
    RQ2CapturedObservation,
    RQ2ClassifierEvent,
    RQ2DatasetInputItem,
    RQ2DatasetManifest,
    RQ2DuplicationAudit,
    RQ2GroundTruthItem,
    RQ2SourceKind,
)
from security_tests.registry import SecurityTestRegistry
from services.target_registry import TargetRegistry
from storage.repositories import EvaluationTruthRepository


RQ2_DATASET_ID = "rq2-classification"
RQ2_DATASET_VERSION = "v1"
RQ2_SOURCE_FRAMEWORK_COMMIT = "25ebfdbee1c6ca310c073c21fca3b81603e366ab"
RQ2_REPETITIONS_PER_TEST = 10
RQ2_GENERATION_METHOD = "controlled-runtime-capture-v1"
RQ2_EXPECTED_TEST_IDS = (
    "path-traversal-private-file-001",
    "sqli-login-bypass-001",
    "xss-reflection-001",
)
RQ2_EXPECTED_CLASS_COUNTS = {
    ClassificationLabel.SQL_INJECTION: 10,
    ClassificationLabel.XSS: 10,
    ClassificationLabel.PATH_TRAVERSAL: 10,
    ClassificationLabel.BENIGN: 30,
    ClassificationLabel.UNKNOWN: 0,
}
RQ2_EXPECTED_ITEM_COUNT = 60

_SEMANTIC_EVENT_TYPES = {
    ApplicationEventType.DATABASE_EVENT,
    ApplicationEventType.VALIDATION_EVENT,
    ApplicationEventType.FILE_ACCESS_EVENT,
}

_FORBIDDEN_CLASSIFIER_KEY_FRAGMENTS = (
    "ground_truth",
    "vulnerability_class",
    "test_id",
    "step_id",
    "scenario_id",
    "source_notes",
    "source_file",
    "vulnerable_function",
    "endpoint_id",
    "target_id",
    "run_id",
    "request_id",
    "timestamp",
)


class RQ2DatasetError(RuntimeError):
    """Raised when candidate/frozen RQ2 dataset evidence violates M18 rules."""


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _sha256_text(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _sha256_bytes(value: bytes) -> str:
    return sha256(value).hexdigest()


def _model_json_line(model) -> str:
    return _canonical_json(model.model_dump(mode="json"))


def _file_bytes(lines: Iterable[str]) -> bytes:
    rendered = "\n".join(lines)
    if rendered:
        rendered += "\n"
    return rendered.encode("utf-8")


def _classifier_payload(item: RQ2DatasetInputItem) -> dict:
    """Return exactly the frozen content permitted to reach a classifier adapter."""
    return {
        "event_id": item.event_id,
        "normalized_event": item.normalized_event.model_dump(mode="json"),
    }


def classifier_payload_sha256(item: RQ2DatasetInputItem) -> str:
    """Canonical hash of the classifier-visible item, excluding integrity metadata."""
    return _sha256_text(_canonical_json(_classifier_payload(item)))


def semantic_input_sha256(event: RQ2ClassifierEvent) -> str:
    """Canonical hash used to audit repeated semantic observations."""
    return _sha256_text(_canonical_json(event.model_dump(mode="json")))


def _opaque_event_id(source_event_id: str) -> str:
    material = f"{RQ2_DATASET_ID}:{RQ2_DATASET_VERSION}:{source_event_id}"
    return f"rq2evt-{_sha256_text(material)[:24]}"


def _truth_label(metadata, source_kind: RQ2SourceKind) -> ClassificationLabel:
    if source_kind == RQ2SourceKind.CONTROL:
        return ClassificationLabel.BENIGN
    mapping = {
        VulnerabilityClass.SQL_INJECTION: ClassificationLabel.SQL_INJECTION,
        VulnerabilityClass.XSS: ClassificationLabel.XSS,
        VulnerabilityClass.PATH_TRAVERSAL: ClassificationLabel.PATH_TRAVERSAL,
    }
    return mapping[metadata.vulnerability_class]


def _registered_step_roles(
    *,
    test_id: str,
    test_registry: SecurityTestRegistry,
) -> dict[RQ2SourceKind, object]:
    steps = test_registry.get(test_id).build_steps()
    if len(steps) != 2:
        raise RQ2DatasetError(
            f"M18 v1 requires exactly control+attack steps for {test_id!r}; got {len(steps)}"
        )
    return {
        RQ2SourceKind.CONTROL: steps[0],
        RQ2SourceKind.ATTACK: steps[1],
    }


def capture_observations_from_execution(
    *,
    execution: TestExecutionResult,
    logs: LogReadResult,
    source_repetition: int,
    target_registry: TargetRegistry,
    test_registry: SecurityTestRegistry,
) -> tuple[RQ2CapturedObservation, RQ2CapturedObservation]:
    """Extract the real semantic control/attack events from one controlled execution.

    The caller performs the already-authorized registered test. This function
    performs no network action and invents no payload. It joins executor request
    IDs to existing normalized application logs and requires one semantic route
    event per registered request step.
    """
    if execution.test_id not in RQ2_EXPECTED_TEST_IDS:
        raise RQ2DatasetError(f"unexpected M18 source test: {execution.test_id}")
    if not execution.completed or execution.timed_out:
        raise RQ2DatasetError("dataset capture requires a completed non-timeout execution")
    if logs.run_id != execution.run_id:
        raise RQ2DatasetError("log run_id must match controlled execution run_id")

    metadata = target_registry.get_security_test(execution.test_id)
    test_registry.validate_against_target_registry(target_registry)
    roles = _registered_step_roles(test_id=execution.test_id, test_registry=test_registry)
    expected_steps = (roles[RQ2SourceKind.CONTROL], roles[RQ2SourceKind.ATTACK])

    if len(execution.exchanges) != 2:
        raise RQ2DatasetError("M18 v1 requires exactly two exchanges per registered test")

    captured: list[RQ2CapturedObservation] = []
    for source_kind, expected_step, exchange in zip(
        (RQ2SourceKind.CONTROL, RQ2SourceKind.ATTACK),
        expected_steps,
        execution.exchanges,
        strict=True,
    ):
        if exchange.step_id != expected_step.step_id:
            raise RQ2DatasetError("execution step_id does not match registered test implementation")
        if exchange.endpoint_id != metadata.endpoint_id:
            raise RQ2DatasetError("execution endpoint does not match registered security-test metadata")
        if exchange.method != expected_step.method.value:
            raise RQ2DatasetError("execution method does not match registered request step")

        candidates = tuple(
            event
            for event in logs.events
            if event.request_id == exchange.request_id
            and event.event_type in _SEMANTIC_EVENT_TYPES
        )
        if len(candidates) != 1:
            raise RQ2DatasetError(
                "each registered control/attack request must map to exactly one semantic event"
            )
        event = candidates[0]
        if event.run_id != execution.run_id:
            raise RQ2DatasetError("captured event run_id does not match execution")
        if event.method != expected_step.method.value:
            raise RQ2DatasetError("captured semantic event method does not match registered step")

        captured.append(
            RQ2CapturedObservation(
                source_test_id=execution.test_id,
                source_step_id=expected_step.step_id,
                source_repetition=source_repetition,
                source_kind=source_kind,
                event=event,
            )
        )

    return captured[0], captured[1]


def _walk_keys(value: object) -> Iterable[str]:
    if isinstance(value, dict):
        for key, child in value.items():
            yield str(key)
            yield from _walk_keys(child)
    elif isinstance(value, (list, tuple)):
        for child in value:
            yield from _walk_keys(child)


def _validate_no_field_name_leakage(item: RQ2DatasetInputItem) -> None:
    payload = _classifier_payload(item)
    for key in _walk_keys(payload):
        lowered = key.lower().replace("-", "_")
        if any(fragment in lowered for fragment in _FORBIDDEN_CLASSIFIER_KEY_FRAGMENTS):
            raise RQ2DatasetError(f"classifier-visible field leaks evaluator/correlation metadata: {key}")


def _validate_no_value_leakage(
    item: RQ2DatasetInputItem,
    truth: RQ2GroundTruthItem,
) -> None:
    payload = _canonical_json(_classifier_payload(item)).lower()
    # Ground-truth label text is intentionally not banned by value alone: an
    # observable payload may legitimately contain a token such as "xss". Label
    # leakage is prevented structurally by the classifier schema/field-name check.
    # source_target_id may legitimately equal an observable application component
    # name (for example, ``vulnerable-store``). Treating that shared value as
    # evaluator-only provenance would reject valid runtime observations. Keep
    # structural field-name leakage strict, but value-scan only provenance that
    # has no legitimate classifier-visible role.
    evaluator_values = (
        truth.source_test_id,
        truth.source_step_id,
        truth.source_kind.value,
        truth.source_endpoint_id,
        truth.source_run_id,
        truth.source_request_id,
        truth.source_event_id,
    )
    for raw in evaluator_values:
        token = str(raw).strip().lower()
        if token and token in payload:
            raise RQ2DatasetError(
                "classifier-visible value contains evaluator-only provenance: "
                f"{raw!r}"
            )


def _validate_registry_identity(
    *,
    target_registry: TargetRegistry,
    test_registry: SecurityTestRegistry,
) -> None:
    test_registry.validate_against_target_registry(target_registry)
    metadata_ids = tuple(item.test_id for item in target_registry.list_security_tests())
    implementation_ids = tuple(sorted(test.test_id for test in target_registry.list_security_tests()))
    if tuple(sorted(metadata_ids)) != RQ2_EXPECTED_TEST_IDS:
        raise RQ2DatasetError(
            "M18 v1 source-test registry does not match the permanent M17 three-test set"
        )
    if implementation_ids != RQ2_EXPECTED_TEST_IDS:
        raise RQ2DatasetError("unexpected security-test registry identity")


def _validate_capture_set(
    observations: tuple[RQ2CapturedObservation, ...],
    *,
    target_registry: TargetRegistry,
    test_registry: SecurityTestRegistry,
) -> None:
    _validate_registry_identity(target_registry=target_registry, test_registry=test_registry)
    if len(observations) != RQ2_EXPECTED_ITEM_COUNT:
        raise RQ2DatasetError(f"M18 v1 requires exactly {RQ2_EXPECTED_ITEM_COUNT} captures")

    source_event_ids = [item.event.event_id for item in observations]
    if len(source_event_ids) != len(set(source_event_ids)):
        raise RQ2DatasetError("runtime capture source event IDs must be unique")

    for test_id in RQ2_EXPECTED_TEST_IDS:
        metadata = target_registry.get_security_test(test_id)
        roles = _registered_step_roles(test_id=test_id, test_registry=test_registry)
        for kind in (RQ2SourceKind.CONTROL, RQ2SourceKind.ATTACK):
            subset = tuple(
                item
                for item in observations
                if item.source_test_id == test_id and item.source_kind == kind
            )
            if len(subset) != RQ2_REPETITIONS_PER_TEST:
                raise RQ2DatasetError(
                    f"{test_id}:{kind.value} requires exactly {RQ2_REPETITIONS_PER_TEST} observations"
                )
            if {item.source_repetition for item in subset} != set(
                range(1, RQ2_REPETITIONS_PER_TEST + 1)
            ):
                raise RQ2DatasetError(f"{test_id}:{kind.value} repetitions must be exactly 1..10")
            expected_step = roles[kind]
            for item in subset:
                if item.source_step_id != expected_step.step_id:
                    raise RQ2DatasetError("capture step_id does not match registered step role")
                if item.event.method != expected_step.method.value:
                    raise RQ2DatasetError("capture method does not match registered step")
                if item.event.event_type not in _SEMANTIC_EVENT_TYPES:
                    raise RQ2DatasetError("capture is not a supported semantic application event")
                if item.event.run_id == "" or item.event.request_id == "":
                    raise RQ2DatasetError("runtime capture must retain original correlation for provenance")
        if metadata.test_id != test_id:
            raise RQ2DatasetError("registered metadata identity changed unexpectedly")

    unexpected = {item.source_test_id for item in observations} - set(RQ2_EXPECTED_TEST_IDS)
    if unexpected:
        raise RQ2DatasetError(f"unexpected M18 source tests: {sorted(unexpected)}")


def _build_items(
    observations: tuple[RQ2CapturedObservation, ...],
    *,
    target_registry: TargetRegistry,
) -> tuple[tuple[RQ2DatasetInputItem, ...], tuple[RQ2GroundTruthItem, ...]]:
    inputs: list[RQ2DatasetInputItem] = []
    truth: list[RQ2GroundTruthItem] = []

    for capture in observations:
        metadata = target_registry.get_security_test(capture.source_test_id)
        event_id = _opaque_event_id(capture.event.event_id)
        normalized = RQ2ClassifierEvent.from_application_event(capture.event)
        semantic_hash = semantic_input_sha256(normalized)
        payload = {
            "event_id": event_id,
            "normalized_event": normalized.model_dump(mode="json"),
        }
        input_item = RQ2DatasetInputItem(
            event_id=event_id,
            classifier_input_sha256=_sha256_text(_canonical_json(payload)),
            semantic_input_sha256=semantic_hash,
            normalized_event=normalized,
        )
        truth_item = RQ2GroundTruthItem(
            event_id=event_id,
            ground_truth_label=_truth_label(metadata, capture.source_kind),
            source_test_id=capture.source_test_id,
            source_step_id=capture.source_step_id,
            source_repetition=capture.source_repetition,
            source_kind=capture.source_kind,
            source_target_id=metadata.target_id,
            source_endpoint_id=metadata.endpoint_id,
            source_run_id=capture.event.run_id,
            source_request_id=capture.event.request_id,
            source_event_id=capture.event.event_id,
            source_notes=(
                "Controlled development-laptop observation captured from the existing "
                "registered deterministic test and its registered request step."
            ),
        )
        _validate_no_field_name_leakage(input_item)
        _validate_no_value_leakage(input_item, truth_item)
        inputs.append(input_item)
        truth.append(truth_item)

    inputs.sort(key=lambda item: item.event_id)
    truth.sort(key=lambda item: item.event_id)
    return tuple(inputs), tuple(truth)


def _duplication_audit(
    inputs: tuple[RQ2DatasetInputItem, ...],
    truth: tuple[RQ2GroundTruthItem, ...],
) -> RQ2DuplicationAudit:
    groups = Counter(
        f"{item.source_test_id}:{item.source_step_id}"
        for item in truth
    )
    return RQ2DuplicationAudit(
        total_events=len(inputs),
        unique_event_ids=len({item.event_id for item in inputs}),
        unique_classifier_input_hashes=len({item.classifier_input_sha256 for item in inputs}),
        unique_semantic_input_hashes=len({item.semantic_input_sha256 for item in inputs}),
        repetition_group_sizes=dict(sorted(groups.items())),
    )


def _validate_expected_truth(truth: tuple[RQ2GroundTruthItem, ...]) -> None:
    counts = Counter(item.ground_truth_label for item in truth)
    actual = {label: counts.get(label, 0) for label in ClassificationLabel}
    if actual != RQ2_EXPECTED_CLASS_COUNTS:
        raise RQ2DatasetError(
            "M18 v1 ground-truth counts differ from 10/10/10/30 with zero unknown"
        )


def build_candidate_dataset(
    observations: Iterable[RQ2CapturedObservation],
    *,
    output_dir: Path,
    target_registry: TargetRegistry,
    test_registry: SecurityTestRegistry,
) -> RQ2DatasetManifest:
    """Write a candidate v1 dataset from exactly 60 real controlled captures.

    Existing candidate files are never overwritten. A caller must explicitly
    remove a disposable candidate directory before regenerating it.
    """
    captures = tuple(observations)
    _validate_capture_set(
        captures,
        target_registry=target_registry,
        test_registry=test_registry,
    )
    inputs, truth = _build_items(captures, target_registry=target_registry)
    _validate_expected_truth(truth)

    if {item.event_id for item in inputs} != {item.event_id for item in truth}:
        raise RQ2DatasetError("classifier input and truth IDs must match exactly")

    output_dir.mkdir(parents=True, exist_ok=True)
    inputs_path = output_dir / "inputs.jsonl"
    truth_path = output_dir / "ground_truth.jsonl"
    manifest_path = output_dir / "manifest.json"
    for path in (inputs_path, truth_path, manifest_path):
        if path.exists():
            raise RQ2DatasetError(f"refusing to overwrite existing frozen candidate file: {path}")

    input_bytes = _file_bytes(_model_json_line(item) for item in inputs)
    truth_bytes = _file_bytes(_model_json_line(item) for item in truth)
    audit = _duplication_audit(inputs, truth)
    generated_at = max(item.event.timestamp for item in captures)
    manifest = RQ2DatasetManifest(
        schema_version="1.0",
        dataset_id=RQ2_DATASET_ID,
        dataset_version=RQ2_DATASET_VERSION,
        source_framework_commit=RQ2_SOURCE_FRAMEWORK_COMMIT,
        generated_at=generated_at,
        generation_method=RQ2_GENERATION_METHOD,
        item_count=len(inputs),
        repetitions_per_test=RQ2_REPETITIONS_PER_TEST,
        source_test_ids=RQ2_EXPECTED_TEST_IDS,
        expected_class_counts=RQ2_EXPECTED_CLASS_COUNTS,
        inputs_sha256=_sha256_bytes(input_bytes),
        ground_truth_sha256=_sha256_bytes(truth_bytes),
        duplication_audit=audit,
    )

    inputs_path.write_bytes(input_bytes)
    truth_path.write_bytes(truth_bytes)
    manifest_path.write_text(
        json.dumps(manifest.model_dump(mode="json"), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return manifest


def _read_manifest(dataset_dir: Path) -> RQ2DatasetManifest:
    path = dataset_dir / "manifest.json"
    try:
        manifest = RQ2DatasetManifest.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise RQ2DatasetError(f"invalid RQ2 dataset manifest: {path}") from exc
    if manifest.dataset_id != RQ2_DATASET_ID or manifest.dataset_version != RQ2_DATASET_VERSION:
        raise RQ2DatasetError("unexpected RQ2 dataset identity/version")
    if manifest.source_framework_commit != RQ2_SOURCE_FRAMEWORK_COMMIT:
        raise RQ2DatasetError("RQ2 v1 source framework commit does not match permanent M17")
    if manifest.item_count != RQ2_EXPECTED_ITEM_COUNT:
        raise RQ2DatasetError("RQ2 v1 manifest item count must be exactly 60")
    if manifest.repetitions_per_test != RQ2_REPETITIONS_PER_TEST:
        raise RQ2DatasetError("RQ2 v1 manifest repetition count must be exactly 10")
    if manifest.source_test_ids != RQ2_EXPECTED_TEST_IDS:
        raise RQ2DatasetError("RQ2 v1 manifest contains unexpected source tests")
    if manifest.expected_class_counts != RQ2_EXPECTED_CLASS_COUNTS:
        raise RQ2DatasetError("RQ2 v1 manifest class counts are not frozen 10/10/10/30")
    return manifest


def _parse_jsonl(path: Path, model_type) -> tuple:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise RQ2DatasetError(f"could not read dataset file: {path}") from exc
    try:
        return tuple(model_type.model_validate_json(line) for line in lines if line.strip())
    except ValueError as exc:
        raise RQ2DatasetError(f"invalid dataset JSONL content: {path}") from exc


def load_classifier_dataset(dataset_dir: Path) -> tuple[RQ2DatasetInputItem, ...]:
    """Load only classifier-visible v1 content; ground_truth.jsonl is never opened."""
    manifest = _read_manifest(dataset_dir)
    inputs_path = dataset_dir / "inputs.jsonl"
    try:
        input_bytes = inputs_path.read_bytes()
    except OSError as exc:
        raise RQ2DatasetError(f"could not read classifier input file: {inputs_path}") from exc
    if _sha256_bytes(input_bytes) != manifest.inputs_sha256:
        raise RQ2DatasetError("classifier input SHA-256 does not match manifest")

    items = _parse_jsonl(inputs_path, RQ2DatasetInputItem)
    if len(items) != RQ2_EXPECTED_ITEM_COUNT:
        raise RQ2DatasetError("RQ2 v1 classifier input file must contain exactly 60 items")
    if tuple(item.event_id for item in items) != tuple(sorted(item.event_id for item in items)):
        raise RQ2DatasetError("RQ2 v1 classifier input order must be stable event_id order")
    if len({item.event_id for item in items}) != len(items):
        raise RQ2DatasetError("RQ2 v1 classifier event IDs must be unique")

    for item in items:
        if not item.event_id.startswith("rq2evt-"):
            raise RQ2DatasetError("RQ2 v1 event IDs must use opaque rq2evt identifiers")
        if classifier_payload_sha256(item) != item.classifier_input_sha256:
            raise RQ2DatasetError("classifier-visible item hash mismatch")
        if semantic_input_sha256(item.normalized_event) != item.semantic_input_sha256:
            raise RQ2DatasetError("semantic input hash mismatch")
        _validate_no_field_name_leakage(item)
    return items


def load_evaluation_dataset(
    dataset_dir: Path,
) -> tuple[RQ2DatasetManifest, tuple[RQ2DatasetInputItem, ...], tuple[RQ2GroundTruthItem, ...]]:
    """Load/validate classifier content plus evaluator-only truth and provenance."""
    manifest = _read_manifest(dataset_dir)
    inputs = load_classifier_dataset(dataset_dir)
    truth_path = dataset_dir / "ground_truth.jsonl"
    try:
        truth_bytes = truth_path.read_bytes()
    except OSError as exc:
        raise RQ2DatasetError(f"could not read evaluator truth file: {truth_path}") from exc
    if _sha256_bytes(truth_bytes) != manifest.ground_truth_sha256:
        raise RQ2DatasetError("ground-truth SHA-256 does not match manifest")
    truth = _parse_jsonl(truth_path, RQ2GroundTruthItem)
    if len(truth) != RQ2_EXPECTED_ITEM_COUNT:
        raise RQ2DatasetError("RQ2 v1 ground-truth file must contain exactly 60 items")
    if tuple(item.event_id for item in truth) != tuple(sorted(item.event_id for item in truth)):
        raise RQ2DatasetError("RQ2 v1 truth order must be stable event_id order")
    if {item.event_id for item in inputs} != {item.event_id for item in truth}:
        raise RQ2DatasetError("classifier input and evaluator truth IDs do not match")
    _validate_expected_truth(truth)

    by_id = {item.event_id: item for item in inputs}
    for truth_item in truth:
        _validate_no_value_leakage(by_id[truth_item.event_id], truth_item)

    audit = _duplication_audit(inputs, truth)
    if audit != manifest.duplication_audit:
        raise RQ2DatasetError("dataset duplication audit does not match manifest")
    return manifest, inputs, truth


def materialize_log_read_result(
    item: RQ2DatasetInputItem,
    *,
    target_id: str,
    run_id: str,
    request_id: str,
    timestamp: datetime,
) -> LogReadResult:
    """Add runtime correlation at an explicit adapter boundary for a classifier call."""
    event = ApplicationLogEvent(
        event_id=item.event_id,
        timestamp=timestamp,
        run_id=run_id,
        request_id=request_id,
        **item.normalized_event.model_dump(),
    )
    return LogReadResult(target_id=target_id, run_id=run_id, events=(event,))


def seed_evaluation_truth(
    repository: EvaluationTruthRepository,
    *,
    dataset_dir: Path,
) -> dict[str, int]:
    """Seed the existing M15 evaluation-only tables from a validated frozen dataset."""
    manifest, inputs, truth = load_evaluation_dataset(dataset_dir)
    truth_by_id = {item.event_id: item for item in truth}
    inserted: dict[str, int] = {}
    for item in inputs:
        dataset_item_id = repository.record_dataset_item(
            dataset_id=manifest.dataset_id,
            dataset_version=manifest.dataset_version,
            event_id=item.event_id,
            normalized_input=_classifier_payload(item),
        )
        truth_item = truth_by_id[item.event_id]
        repository.record_classification_truth(
            dataset_item_id=dataset_item_id,
            ground_truth_label=truth_item.ground_truth_label,
            source_notes=_canonical_json(
                {
                    "source_test_id": truth_item.source_test_id,
                    "source_step_id": truth_item.source_step_id,
                    "source_repetition": truth_item.source_repetition,
                    "source_kind": truth_item.source_kind.value,
                    "source_target_id": truth_item.source_target_id,
                    "source_endpoint_id": truth_item.source_endpoint_id,
                    "source_run_id": truth_item.source_run_id,
                    "source_request_id": truth_item.source_request_id,
                    "source_event_id": truth_item.source_event_id,
                }
            ),
        )
        inserted[item.event_id] = dataset_item_id
    return inserted
