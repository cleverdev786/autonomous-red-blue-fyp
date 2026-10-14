"""Read-only integration of externally pinned isolated Docker Red evidence.

A previously authorized executor wrote these bytes. This module does NOT run
Docker, authorize a dispatch, claim that an LLM authored Red, or establish
fresh/current Docker identity. It checks archived integrity and re-evaluates
registered exploit evidence against trusted implementations. The caller must
independently pin BOTH admission and receipt digests.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Literal

from schemas.registered_red_observation import (
    REGISTERED,
    DeterministicRedObservation,
    observe_registered_result,
)
from security_tests.registry import SecurityTestRegistry
from services.isolated_compose_executor import (
    CONTAINER_FILES,
    MAX_OUTPUT,
    IsolatedExecutionBlocked,
    RealExecutionReceipt,
    load_real_admission,
)
from services.isolated_compose_mock_adapter import ISOLATED_COMPOSE
from services.target_registry import TargetRegistry

SOURCE_IMPLEMENTATION = {
    "sqli-login-bypass-001": "security_tests/sql_injection/login_bypass.py",
    "xss-reflection-001": "security_tests/xss/reflection.py",
    "path-traversal-private-file-001": "security_tests/path_traversal/private_file.py",
}
SHA256_EMPTY = sha256(b"").hexdigest()
_MAX_INTENT = 15000
_MAX_OBSERVATION = 65536
_MAX_RECEIPT = 8192


class BoundRedEvidenceError(ValueError):
    """An archived development observation cannot be trusted for this context."""


@dataclass(frozen=True, slots=True)
class BoundRegisteredRedEvidence:
    """Output of complete read-only validation, not independent live attestation."""

    run_id: str
    target_id: Literal["vulnerable-store"]
    test_id: str
    endpoint_id: str
    vulnerability_class: str
    observation: DeterministicRedObservation
    admission_sha256: str
    receipt_sha256: str
    source_head: str
    source_tree: str
    case_id: str
    evidence_scope: Literal["archived_development_provenance"] = (
        "archived_development_provenance"
    )


def _strict_file(path: Path, *, max_bytes: int) -> bytes:
    if (
        not path.is_file()
        or path.is_symlink()
        or any(parent.is_symlink() for parent in path.parents)
    ):
        raise BoundRedEvidenceError("archived evidence path is not regular")
    if path.stat().st_size > max_bytes:
        raise BoundRedEvidenceError("archived evidence exceeds size bound")
    value = path.read_bytes()
    if len(value) > max_bytes:
        raise BoundRedEvidenceError("archived evidence exceeds read bound")
    return value


def _json_object(raw: bytes) -> dict:
    value = json.loads(raw)
    if type(value) is not dict:
        raise BoundRedEvidenceError("evidence JSON must be an object")
    return value


def _expected_command(*, dispatch_root: Path, context: str, test_id: str,
                      run_id: str) -> tuple[str, ...]:
    return (
        "docker", "--context", context, "compose",
        "-f", str(dispatch_root / ISOLATED_COMPOSE),
        "--project-directory", str(dispatch_root),
        "exec", "-T", "controlled-executor",
        "python", "-m", "infrastructure.executor.run_verification_test",
        "--test-id", test_id,
        "--attempt-number", "1",
        "--run-id", run_id,
    )


def verify_archived_registered_red(
    *,
    source_root: Path,
    dispatch_root: Path,
    evidence_dir: Path,
    admission_path: Path,
    admission_sha256: str,
    receipt_sha256: str,
    registry: TargetRegistry,
    implementations: SecurityTestRegistry,
) -> BoundRegisteredRedEvidence:
    """Bind raw bytes, admission, command, Docker snapshot and Red semantics.

    The admission/receipt hashes MUST be provided by a separately authorized
    evidence register, not learned from files inside evidence_dir. These checks
    cannot prove an archived Docker daemon still exists or has not changed.
    """
    if (
        len(receipt_sha256) != 64
        or any(c not in "0123456789abcdef" for c in receipt_sha256)
    ):
        raise BoundRedEvidenceError("externally pinned receipt hash required")
    try:
        if source_root.is_symlink() or not source_root.is_dir():
            raise BoundRedEvidenceError("source checkout is not a regular directory")
        root = source_root.resolve(strict=True)
        if dispatch_root.is_symlink() or not dispatch_root.is_dir():
            raise BoundRedEvidenceError("approved dispatch root does not exist")
        approved_dispatch = dispatch_root.resolve(strict=True)
        if (
            evidence_dir.is_symlink()
            or not evidence_dir.is_dir()
            or any(p.is_symlink() for p in evidence_dir.parents)
        ):
            raise BoundRedEvidenceError("archive directory invalid or symlinked")
        evidence = evidence_dir.resolve(strict=True)
        if root in evidence.parents or approved_dispatch in evidence.parents:
            raise BoundRedEvidenceError("archive must not be inside source repository")
        pin = load_real_admission(root, admission_path, admission_sha256)
        for relative, expected_digest in pin.source_hashes.items():
            source_file = root / relative
            if sha256(_strict_file(source_file, max_bytes=1024 * 1024)).hexdigest() != expected_digest:
                raise BoundRedEvidenceError("approved archived checkout source SHA changed")
        test_id, endpoint_id, vulnerability = REGISTERED[pin.scenario_id]
        receipt_raw = _strict_file(evidence / "receipt.json", max_bytes=_MAX_RECEIPT)
        if sha256(receipt_raw).hexdigest() != receipt_sha256:
            raise BoundRedEvidenceError("receipt does not match external digest")
        receipt = RealExecutionReceipt.model_validate_json(receipt_raw)
        if receipt_raw != (receipt.model_dump_json(indent=2) + "\n").encode():
            raise BoundRedEvidenceError("receipt is not canonical")
        if (
            receipt.case_id != pin.case_id
            or receipt.run_id != pin.run_id
            or receipt.scenario_id != pin.scenario_id
            or evidence.name != pin.case_id
            or receipt.source_head != pin.source_head
            or receipt.source_tree != pin.source_tree
            or receipt.daemon_id != pin.daemon_id
            or receipt.image_id != pin.image_id
            or receipt.app_container_id != pin.app_container_id
            or receipt.executor_container_id != pin.executor_container_id
            or receipt.admission_sha256 != admission_sha256
            or receipt.outcome != "baseline_exploit_confirmed"
            or receipt.returncode != 0
            or receipt.timed_out
            or receipt.observation_sha256 is None
        ):
            raise BoundRedEvidenceError("execution receipt is not an approved success")
        intended_command = _expected_command(
            dispatch_root=approved_dispatch,
            context=pin.context,
            test_id=test_id,
            run_id=pin.run_id,
        )
        if receipt.dispatch_argv != intended_command:
            raise BoundRedEvidenceError("recorded command exceeds trusted registry")
        intent_raw = _strict_file(
            evidence / "dispatch-intent.json", max_bytes=_MAX_INTENT
        )
        intent = _json_object(intent_raw)
        if intent_raw != (json.dumps(intent, sort_keys=True, indent=2) + "\n").encode():
            raise BoundRedEvidenceError("dispatch intent is not canonical")
        if (
            set(intent) != {
                "scope", "admission_sha256", "case_id", "run_id", "scenario_id",
                "test_id", "argv", "cwd", "source_head", "source_tree",
                "before", "attempt_number",
            }
            or intent["scope"] != receipt.scope
            or intent["admission_sha256"] != admission_sha256
            or intent["case_id"] != pin.case_id
            or intent["run_id"] != pin.run_id
            or intent["scenario_id"] != pin.scenario_id
            or intent["test_id"] != test_id
            or intent["argv"] != list(intended_command)
            or intent["cwd"] != str(approved_dispatch)
            or intent["source_head"] != pin.source_head
            or intent["source_tree"] != pin.source_tree
            or intent["attempt_number"] != 1
        ):
            raise BoundRedEvidenceError("registered intent identity mismatch")
        before = intent["before"]
        if not isinstance(before, dict):
            raise BoundRedEvidenceError("runtime identity is not a dict")
        if (
            before.get("context") != pin.context
            or before.get("daemon_id") != pin.daemon_id
            or before.get("image_id") != pin.image_id
            or before.get("source_hashes") != {
                k: pin.source_hashes[k] for k in CONTAINER_FILES
            }
        ):
            raise BoundRedEvidenceError("runtime source/daemon identity mismatch")
        for which, expected_id in (
            ("app_container", pin.app_container_id),
            ("executor_container", pin.executor_container_id),
        ):
            obj = before.get(which)
            if (
                not isinstance(obj, dict)
                or obj.get("id") != expected_id
                or obj.get("image") != pin.image_id
                or obj.get("healthy") is not True
            ):
                raise BoundRedEvidenceError("recorded container identity mismatch")
        raw_stdout = _strict_file(evidence / "stdout.raw", max_bytes=MAX_OUTPUT)
        raw_stderr = _strict_file(evidence / "stderr.raw", max_bytes=MAX_OUTPUT)
        if (
            sha256(raw_stdout).hexdigest() != receipt.stdout_sha256
            or sha256(raw_stderr).hexdigest() != receipt.stderr_sha256
        ):
            raise BoundRedEvidenceError("raw process output SHA mismatch")
        observation_raw = _strict_file(
            evidence / "observation.json", max_bytes=_MAX_OBSERVATION
        )
        if sha256(observation_raw).hexdigest() != receipt.observation_sha256:
            raise BoundRedEvidenceError("stored observation SHA mismatch")
        observed = DeterministicRedObservation.model_validate_json(observation_raw)
        if observation_raw != (observed.model_dump_json(indent=2) + "\n").encode():
            raise BoundRedEvidenceError("observation JSON not canonical")
        session_sha = sha256(intent_raw).hexdigest()
        recomputed = observe_registered_result(
            raw_result=raw_stdout,
            scenario_id=pin.scenario_id,
            phase="vulnerable_baseline",
            source_sha256=pin.source_hashes[CONTAINER_FILES[0]],
            policy_config_sha256=pin.source_hashes[
                "config/security_tests/" + test_id + ".json"
            ],
            test_implementation_sha256=pin.source_hashes[
                SOURCE_IMPLEMENTATION[test_id]
            ],
            evidence_scope="reported_controlled_executor",
            docker_session_evidence_sha256=session_sha,
            registry=registry, implementations=implementations,
        )
        if observed != recomputed or not recomputed.exploit_confirmed:
            raise BoundRedEvidenceError("deterministic registered exploit not confirmed")
        if (
            recomputed.execution.run_id != pin.run_id
            or recomputed.execution.attempt_number != 1
            or recomputed.registered_test_id != test_id
            or recomputed.registered_endpoint_id != endpoint_id
        ):
            raise BoundRedEvidenceError("registered executor identities disagree")
        return BoundRegisteredRedEvidence(
            run_id=pin.run_id,
            target_id="vulnerable-store",
            test_id=test_id,
            endpoint_id=endpoint_id,
            vulnerability_class=vulnerability,
            observation=recomputed,
            admission_sha256=admission_sha256,
            receipt_sha256=receipt_sha256,
            source_head=pin.source_head,
            source_tree=pin.source_tree,
            case_id=pin.case_id,
        )
    except BoundRedEvidenceError:
        raise
    except (OSError, ValueError, KeyError, TypeError, AttributeError,
        IsolatedExecutionBlocked) as exc:
        raise BoundRedEvidenceError("archived registered provenance rejected") from exc
