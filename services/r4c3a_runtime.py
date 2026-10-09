"""R4-C3A runtime-bound *contract simulation*. No live Docker/Git/subprocess.

All three dependencies are REQUIRED injected mock functions. Historical R4-C1
fixtures remain unchanged. This v2 never claims to attest a real container.
"""
from __future__ import annotations

from dataclasses import dataclass
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Callable, Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field

from schemas.r4c3a_admission import R4C3AAdmission, INITIAL_SCENARIO_SHA256
from schemas.r4a_red_observation import REGISTERED, observe_registered_result
from services.r4c1_executor_capture import TEST_POLICY, PINNED_REGISTERED_HASHES, SOURCE
from services.target_registry import TargetRegistry
from security_tests.registry import SecurityTestRegistry

MAX_BYTES = 65536
OPAQUE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,70}$")


class R4C3ABlocked(RuntimeError):
    pass


class MockGitState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observation_scope: Literal["mock_git_snapshot"] = "mock_git_snapshot"
    head: str
    tree: str
    branch: str
    clean: bool
    shallow: bool
    has_remotes: bool
    has_alternates: bool
    common_directory_is_private: bool
    source_sha256: str
    staged_diff_sha256: str | None = None


class MockRuntimeState(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    observation_scope: Literal["injected_mock_docker_snapshot"] = "injected_mock_docker_snapshot"
    context_id: str
    daemon_id: str
    ledger_id: str
    app_container_id: str
    executor_container_id: str
    image_id: str
    deployed_source_sha256: str


@dataclass(frozen=True)
class StreamedMockProcess:
    returncode: int | None
    stdout_chunks: Iterable[bytes]
    stderr_chunks: Iterable[bytes]
    timed_out: bool = False


class R4C3AMockReceipt(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    schema_version: Literal["r4c3a-mocked-runtime-identity-v2"] = "r4c3a-mocked-runtime-identity-v2"
    origin: Literal["injected_mock_runtime_observer"] = "injected_mock_runtime_observer"
    evidence_scope: Literal["offline_mock_only"] = "offline_mock_only"
    model_calls: Literal[0] = 0
    red_agent_plan_authored: Literal[False] = False
    final_research_result: Literal[False] = False
    ready_for_live: Literal[False] = False
    case_id: str
    scenario_id: str
    test_id: str
    phase: Literal["vulnerable_baseline", "patched_replay"]
    admission_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    admitted_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    admitted_tree: str = Field(pattern=r"^[0-9a-f]{40}$")
    requested_run_id: str
    observed_run_id: str
    source_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    staged_diff_sha256: str | None = None
    daemon_id: str
    app_container_id: str
    executor_container_id: str
    image_id: str
    stdout_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    stderr_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    subprocess_returncode: int | None
    timed_out: bool
    outcome: Literal[
        "baseline_exploit_confirmed","baseline_not_proven",
        "patched_exploit_not_observed","patched_exploit_still_present",
        "inconclusive","executor_failed","provenance_failed",
    ]
    observation_sha256: str | None = None
    reason: str


def _mock_git_valid(
    state: MockGitState, admission: R4C3AAdmission,
    *, phase: str, source_sha: str, staged_diff_sha: str | None,
) -> bool:
    if (state.head != admission.approved_commit or state.tree != admission.approved_tree
            or state.shallow or state.has_remotes or state.has_alternates
            or not state.common_directory_is_private or state.source_sha256 != source_sha):
        return False
    if phase == "vulnerable_baseline":
        return (state.branch == "main" and state.clean
                and state.staged_diff_sha256 is None and staged_diff_sha is None)
    return (state.branch.startswith("agent-patch/") and not state.clean
            and state.staged_diff_sha256 == staged_diff_sha
            and staged_diff_sha is not None)


def _mock_runtime_valid(snapshot: MockRuntimeState, source_sha: str) -> bool:
    return (snapshot.deployed_source_sha256 == source_sha
            and all([
                snapshot.context_id, snapshot.daemon_id, snapshot.ledger_id,
                snapshot.app_container_id, snapshot.executor_container_id,
                snapshot.image_id
            ])
            and snapshot.app_container_id != snapshot.executor_container_id)


def _chunks_to_bytes(chunks: Iterable[bytes]) -> bytes:
    buffer=bytearray()
    for item in chunks:
        if not isinstance(item, bytes):
            raise R4C3ABlocked("binary stream contains non-bytes chunk")
        if len(buffer)+len(item)>MAX_BYTES:
            raise R4C3ABlocked("stream exceeds 64-KiB hard cap")
        buffer.extend(item)
    return bytes(buffer)


class R4C3AMockedRuntimeCollector:
    def __init__(
        self, *, source_root: Path, evidence_root: Path,
        admission: R4C3AAdmission, admission_sha256: str,
        git_observer: Callable[[], MockGitState],
        runtime_observer: Callable[[], MockRuntimeState],
        expected_mock_owner: MockRuntimeState,
        process_runner: Callable[[tuple[str, ...], Path], StreamedMockProcess],
        registry: TargetRegistry, implementations: SecurityTestRegistry,
    ):
        self.source_root=source_root.resolve(strict=True)
        self.evidence_root=evidence_root.resolve(strict=True)
        if self.evidence_root == self.source_root or self.source_root in self.evidence_root.parents:
            raise R4C3ABlocked("evidence cannot be stored inside source tree")
        if self.evidence_root.is_symlink():
            raise R4C3ABlocked("external evidence root must not be symlink")
        if sha256(admission.canonical_bytes()).hexdigest()!=admission_sha256:
            raise R4C3ABlocked("admission digest mismatch")
        self.admission=admission
        self.admission_sha256=admission_sha256
        self.git_observer=git_observer
        self.runtime_observer=runtime_observer
        if not isinstance(expected_mock_owner, MockRuntimeState):
            raise R4C3ABlocked("missing independent mock ownership binding")
        self.expected_mock_owner=expected_mock_owner
        self.process_runner=process_runner
        self.registry=registry
        self.implementations=implementations

    @staticmethod
    def _save_new(path: Path, data: bytes):
        import os
        with path.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())

    def collect(self, *, case_id: str, scenario_id: str,
                phase: Literal["vulnerable_baseline","patched_replay"],
                staged_diff_sha256: str | None = None) -> R4C3AMockReceipt:
        if not OPAQUE_ID.fullmatch(case_id) or scenario_id not in self.admission.scenario_ids:
            raise R4C3ABlocked("case or scenario unregistered")
        if phase not in ("vulnerable_baseline","patched_replay"):
            raise R4C3ABlocked("invalid phase")
        original=self.source_root/SOURCE
        if not original.is_file() or original.is_symlink():
            raise R4C3ABlocked("target source not a regular file")
        actual_sha=sha256(original.read_bytes()).hexdigest()
        if phase=="vulnerable_baseline":
            if actual_sha != INITIAL_SCENARIO_SHA256 or staged_diff_sha256 is not None:
                raise R4C3ABlocked("baseline source/diff drift")
        elif (actual_sha==INITIAL_SCENARIO_SHA256 or not isinstance(staged_diff_sha256,str)
              or not re.fullmatch(r"[0-9a-f]{64}",staged_diff_sha256)):
            raise R4C3ABlocked("patched source/staged diff unverified")
        test_id=REGISTERED[scenario_id][0]
        pinned_policy,pinned_impl=PINNED_REGISTERED_HASHES[scenario_id]
        pol=self.source_root/"config/security_tests"/(test_id+".json")
        impl=self.source_root/TEST_POLICY[scenario_id][0]
        if (pol.is_symlink() or impl.is_symlink() or not pol.is_file() or not impl.is_file()
                or sha256(pol.read_bytes()).hexdigest()!=pinned_policy
                or sha256(impl.read_bytes()).hexdigest()!=pinned_impl):
            raise R4C3ABlocked("registered test definitions drift")
        before_git=self.git_observer()
        before_runtime=self.runtime_observer()
        if not isinstance(before_git,MockGitState) or not _mock_git_valid(
                before_git,self.admission,phase=phase,
                source_sha=actual_sha,staged_diff_sha=staged_diff_sha256):
            raise R4C3ABlocked("mock Git baseline identity mismatch")
        if (not isinstance(before_runtime,MockRuntimeState)
                or not _mock_runtime_valid(before_runtime,actual_sha)
                or before_runtime != self.expected_mock_owner):
            raise R4C3ABlocked("mock runtime/container ownership binding mismatch")
        argv=("docker","compose","exec","-T","controlled-executor",
              "python","-m","infrastructure.executor.run_verification_test",
              "--test-id",test_id,"--attempt-number","1",
              "--run-id",self.admission.observed_run_id)
        folder=self.evidence_root/case_id
        try:
            folder.mkdir(mode=0o700,exist_ok=False)
        except FileExistsError as exc:
            raise R4C3ABlocked("case already reserved; never redispatch") from exc
        intent={
            "schema_version":"r4c3a-mock-intent-v1",
            "scope":"offline_mock_only","case_id":case_id,
            "scenario_id":scenario_id,"phase":phase,"argv":argv,
            "requested_run_id":self.admission.run_id,
            "observed_run_id":self.admission.observed_run_id,
            "admitted_commit":self.admission.approved_commit,
            "admitted_tree":self.admission.approved_tree,
            "source_sha256":actual_sha,
            "staged_diff_sha256":staged_diff_sha256,
            "git_snapshot":before_git.model_dump(mode="json"),
            "runtime_snapshot":before_runtime.model_dump(mode="json"),
            "independent_mock_owner_binding":self.expected_mock_owner.model_dump(mode="json"),
        }
        self._save_new(folder/"dispatch-intent.json",
                       (json.dumps(intent,sort_keys=True,indent=2)+"\n").encode())
        try:
            process=self.process_runner(argv,self.source_root)
            if not isinstance(process,StreamedMockProcess):
                raise R4C3ABlocked("invalid process runner return")
            raw_out=_chunks_to_bytes(process.stdout_chunks)
            raw_err=_chunks_to_bytes(process.stderr_chunks)
        except Exception as exc:
            self._save_new(folder/"failure.json",
                           (json.dumps({"status":"mock_runner_or_capture_failed",
                                        "exception_type":type(exc).__name__})+"\n").encode())
            raise R4C3ABlocked("runner/capture failed; no retry") from exc
        self._save_new(folder/"stdout.raw",raw_out)
        self._save_new(folder/"stderr.raw",raw_err)
        observed_sha=None
        after_git=self.git_observer()
        after_runtime=self.runtime_observer()
        if not isinstance(after_git,MockGitState) or not isinstance(after_runtime,MockRuntimeState) or (
                after_git!=before_git or after_runtime!=before_runtime
                or sha256(original.read_bytes()).hexdigest()!=actual_sha):
            outcome="provenance_failed"
            reason="mock Git/daemon/container/source changed across dispatch"
        elif process.timed_out:
            outcome="inconclusive"
            reason="mock process timed out"
        elif process.returncode != 0:
            outcome="executor_failed"
            reason="mock registered executor returned nonzero/nonexistent process code"
        else:
            try:
                obs=observe_registered_result(
                    raw_result=raw_out,scenario_id=scenario_id,phase=phase,
                    source_sha256=INITIAL_SCENARIO_SHA256,
                    policy_config_sha256=pinned_policy,
                    test_implementation_sha256=pinned_impl,
                    evidence_scope="offline_fixture",
                    registry=self.registry,implementations=self.implementations)
                if (obs.execution.run_id!=self.admission.observed_run_id
                        or obs.execution.attempt_number!=1
                        or obs.execution.test_id!=test_id):
                    raise ValueError("registered result run/test/attempt mismatch")
                raw_obs=(obs.model_dump_json(indent=2)+"\n").encode()
                self._save_new(folder/"observation.json",raw_obs)
                observed_sha=sha256(raw_obs).hexdigest()
                if not obs.test_completed or obs.exploit_confirmed is None:
                    outcome="inconclusive"
                elif phase=="vulnerable_baseline":
                    outcome="baseline_exploit_confirmed" if obs.exploit_confirmed else "baseline_not_proven"
                else:
                    outcome="patched_exploit_still_present" if obs.exploit_confirmed else "patched_exploit_not_observed"
                reason="recomputed registered evaluator, MOCK evidence only"
            except Exception:
                outcome="provenance_failed"
                reason="registered JSON or event identity invalid"
        receipt=R4C3AMockReceipt(
            case_id=case_id,scenario_id=scenario_id,test_id=test_id,
            phase=phase,admission_sha256=self.admission_sha256,
            admitted_commit=self.admission.approved_commit,
            admitted_tree=self.admission.approved_tree,
            requested_run_id=self.admission.run_id,
            observed_run_id=self.admission.observed_run_id,
            source_sha256=actual_sha,staged_diff_sha256=staged_diff_sha256,
            daemon_id=before_runtime.daemon_id,
            app_container_id=before_runtime.app_container_id,
            executor_container_id=before_runtime.executor_container_id,
            image_id=before_runtime.image_id,
            stdout_sha256=sha256(raw_out).hexdigest(),
            stderr_sha256=sha256(raw_err).hexdigest(),
            subprocess_returncode=process.returncode,timed_out=process.timed_out,
            outcome=outcome,observation_sha256=observed_sha,reason=reason)
        self._save_new(folder/"receipt.json",(receipt.model_dump_json(indent=2)+"\n").encode())
        return receipt
