"""R4-C4F Option-B isolated Compose and mock-only command adapter.

NEVER calls Git, Docker, the network or subprocess. All observations come
exclusively from required injected mock callbacks. Not a live execution seam.
"""
from __future__ import annotations

from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Callable, Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator
import yaml

BASE_COMPOSE = "compose.yaml"
ISOLATED_COMPOSE = "compose.isolated.yaml"
BASE_COMPOSE_SHA256 = "be1271771fbc54b906b4d42e1dbff0f6525701108a41c2fb04a61f18466dd92f"
ORIGINAL_ROUTES_SHA256 = "f8675d5bed857138f49cdf717bd4c696aad7e4e42c5f14cd41b4623b140a6e5d"
ORIGINAL_IMAGE = "fyp-red-blue-lab:local"
PROJECT = "fyp-r4c4f-red-blue-lab"
IMAGE = "fyp-r4c4f-red-blue-lab:local"
APP_CONTAINER = "fyp-r4c4f-vulnerable-store"
EXECUTOR_CONTAINER = "fyp-r4c4f-controlled-executor"
NETWORK = "fyp-r4c4f-security-lab"
VOLUME = "fyp-r4c4f-store-runtime"
PUBLISHED_PORT = 18080
INTERNAL_PORT = 8000
APPROVED_TESTS = (
    "sqli-login-bypass-001",
    "xss-reflection-001",
    "path-traversal-private-file-001",
)
REQUIRED_HASHES = (
    BASE_COMPOSE,
    ISOLATED_COMPOSE,
    "config/git-policy.json",
    "config/verification-policy.json",
    "dummy_apps/vulnerable_store/app/scenario_routes.py",
)
OPERATIONS = (
    "config", "build", "start_app", "health_app", "start_executor",
    "health_executor", "registered_replay", "functional", "regression",
)
OLD_NAMES = {"fyp-vulnerable-store", "fyp-controlled-executor", "fyp-red-blue-lab"}
NEW_NAMES = {PROJECT, IMAGE, APP_CONTAINER, EXECUTOR_CONTAINER, NETWORK, VOLUME}
HEX40 = r"^[a-f0-9]{40}$"
HEX64 = r"^[a-f0-9]{64}$"


class R4C4FBlocked(RuntimeError):
    pass


class MockOptionBAdmission(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["r4c4f-option-b-isolation-v1"] = "r4c4f-option-b-isolation-v1"
    scope: Literal["offline_injected_mock_only"] = "offline_injected_mock_only"
    authorizes_real_docker: Literal[False] = False
    authorizes_cleanup: Literal[False] = False
    authorizes_final_research: Literal[False] = False
    source_commit: str = Field(pattern=HEX40)
    source_tree: str = Field(pattern=HEX40)
    source_parent: str = Field(pattern=HEX40)
    source_sha256: dict[str, str]
    context: Literal["default"] = "default"
    compose_path: Literal["compose.isolated.yaml"] = ISOLATED_COMPOSE
    project: Literal["fyp-r4c4f-red-blue-lab"] = PROJECT
    image: Literal["fyp-r4c4f-red-blue-lab:local"] = IMAGE
    app_container: Literal["fyp-r4c4f-vulnerable-store"] = APP_CONTAINER
    executor_container: Literal["fyp-r4c4f-controlled-executor"] = EXECUTOR_CONTAINER
    network: Literal["fyp-r4c4f-security-lab"] = NETWORK
    volume: Literal["fyp-r4c4f-store-runtime"] = VOLUME
    host_port: Literal[18080] = PUBLISHED_PORT
    protected_old_image: Literal["fyp-red-blue-lab:local"] = ORIGINAL_IMAGE
    run_id: str = Field(min_length=1, max_length=64)

    @model_validator(mode="after")
    def check_fixed_values(self):
        if set(self.source_sha256) != set(REQUIRED_HASHES):
            raise ValueError("exact source, policy and two Compose digest keys required")
        if any(not re.fullmatch(HEX64, x) for x in self.source_sha256.values()):
            raise ValueError("invalid SHA256 input")
        if self.source_sha256[BASE_COMPOSE] != BASE_COMPOSE_SHA256:
            raise ValueError("frozen original Compose changed")
        if self.source_sha256["dummy_apps/vulnerable_store/app/scenario_routes.py"] != ORIGINAL_ROUTES_SHA256:
            raise ValueError("frozen vulnerable source changed")
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", self.run_id):
            raise ValueError("unsafe run ID")
        if self.source_commit == self.source_parent:
            raise ValueError("approved source and parent must differ")
        return self

    def canonical_bytes(self) -> bytes:
        return (json.dumps(self.model_dump(mode="json"), sort_keys=True,
                           separators=(",", ":"), ensure_ascii=True) + "\n").encode()


def load_mock_option_b_admission(*, source_root: Path, manifest: Path,
                                 external_sha256: str) -> MockOptionBAdmission:
    if not re.fullmatch(HEX64, external_sha256):
        raise R4C4FBlocked("external manifest checksum unavailable")
    if not source_root.is_dir() or source_root.is_symlink():
        raise R4C4FBlocked("source root invalid")
    root = source_root.resolve(strict=True)
    if not manifest.is_absolute() or manifest.is_symlink() or not manifest.is_file():
        raise R4C4FBlocked("external manifest must be an absolute regular file")
    if root == manifest or root in manifest.parents:
        raise R4C4FBlocked("manifest cannot be held in source checkout")
    raw = manifest.read_bytes()
    if len(raw) > 8192 or sha256(raw).hexdigest() != external_sha256:
        raise R4C4FBlocked("external manifest SHA256 mismatch")
    try:
        item = MockOptionBAdmission.model_validate_json(raw)
        if item.canonical_bytes() != raw:
            raise ValueError("manifest not canonical")
    except Exception as ex:
        raise R4C4FBlocked("external manifest invalid") from ex
    for name, digest in item.source_sha256.items():
        f = root/name
        if not f.is_file() or f.is_symlink() or sha256(f.read_bytes()).hexdigest() != digest:
            raise R4C4FBlocked("source/config hash mismatch: "+name)
    verify_isolation_yaml(root)
    return item


def verify_isolation_yaml(root: Path) -> dict:
    """Enforce exact unchanged baseline behavior except reviewed isolation deltas."""
    orig = root/BASE_COMPOSE
    isolated = root/ISOLATED_COMPOSE
    for f in (orig, isolated):
        if not f.is_file() or f.is_symlink():
            raise R4C4FBlocked("Compose source missing or symlink")
    if sha256(orig.read_bytes()).hexdigest() != BASE_COMPOSE_SHA256:
        raise R4C4FBlocked("original Compose changed")
    try:
        base = yaml.safe_load(orig.read_bytes())
        actual = yaml.safe_load(isolated.read_bytes())
    except (yaml.YAMLError, UnicodeError) as ex:
        raise R4C4FBlocked("Compose YAML invalid") from ex
    if not isinstance(base, dict) or not isinstance(actual, dict):
        raise R4C4FBlocked("Compose documents must be maps")
    import copy
    expected = copy.deepcopy(base)
    expected["name"] = PROJECT
    for service, cname in (("vulnerable-store", APP_CONTAINER),
                           ("controlled-executor", EXECUTOR_CONTAINER)):
        expected["services"][service]["image"] = IMAGE
        expected["services"][service]["container_name"] = cname
    expected["x-lab-image"]["image"] = IMAGE
    expected["services"]["vulnerable-store"]["ports"] = ["127.0.0.1:18080:8000"]
    expected["networks"]["security-lab"]["name"] = NETWORK
    expected["volumes"]["store-runtime"] = {"name": VOLUME}
    if actual != expected:
        raise R4C4FBlocked("isolation YAML changed beyond approved isolation-only deltas")
    service = actual["services"]
    for item in service.values():
        if (item.get("privileged") is not False or item.get("read_only") is not True
            or item.get("cap_drop") != ["ALL"]
            or "no-new-privileges:true" not in item.get("security_opt", [])):
            raise R4C4FBlocked("container security hardening removed")
        if item["build"] != {"context": ".", "dockerfile": "dummy_apps/vulnerable_store/Dockerfile"}:
            raise R4C4FBlocked("container build source changed")
    if (actual["networks"]["security-lab"].get("internal") is not True
        or actual["networks"]["security-lab"].get("attachable") is not False):
        raise R4C4FBlocked("isolated internal network safety changed")
    if not NEW_NAMES.isdisjoint(OLD_NAMES):
        raise R4C4FBlocked("old and new resource identities collide")
    return actual


class MockInventory(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    origin: Literal["injected_mock_docker_inventory"] = "injected_mock_docker_inventory"
    context: str
    daemon_id: str
    existing_containers: tuple[str, ...] = ()
    existing_images: tuple[str, ...] = ()
    existing_networks: tuple[str, ...] = ()
    existing_volumes: tuple[str, ...] = ()
    occupied_host_ports: tuple[int, ...] = ()


class MockBinaryProcess(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    returncode: int
    stdout_chunks: tuple[bytes, ...]
    stderr_chunks: tuple[bytes, ...] = ()
    timed_out: bool = False


class MockAdapterReceipt(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")
    schema_version: Literal["r4c4f-isolated-argv-mock-v1"] = "r4c4f-isolated-argv-mock-v1"
    origin: Literal["injected_mock_runner_no_docker_invocation"] = "injected_mock_runner_no_docker_invocation"
    ready_for_live: Literal[False] = False
    real_docker_calls: Literal[0] = 0
    outcome: Literal["mock_success", "mock_failure", "mock_provenance_failure"]
    action: str
    case_id: str
    argv: tuple[str, ...]
    cwd: str
    manifest_sha256: str
    stdout_sha256: str
    stderr_sha256: str
    returncode: int
    timed_out: bool
    reasons: tuple[str, ...]


def _mock_inventory_valid(expected: MockInventory, observed: MockInventory,
                          admission: MockOptionBAdmission) -> bool:
    if observed != expected or expected.context != admission.context or not expected.daemon_id:
        return False
    if set(expected.existing_containers) & {APP_CONTAINER, EXECUTOR_CONTAINER}:
        return False
    if IMAGE in expected.existing_images or NETWORK in expected.existing_networks:
        return False
    if VOLUME in expected.existing_volumes or PUBLISHED_PORT in expected.occupied_host_ports:
        return False
    return True


def _check_normalized_config(raw: bytes) -> bool:
    """Mocked 'docker compose config', never a real Docker normalized output."""
    try:
        obj = json.loads(raw)
        services = obj["services"]
        x = services["vulnerable-store"]
        y = services["controlled-executor"]
        return (
            obj.get("name") == PROJECT
            and set(services) == {"vulnerable-store", "controlled-executor"}
            and x.get("image") == y.get("image") == IMAGE
            and x.get("container_name") == APP_CONTAINER
            and y.get("container_name") == EXECUTOR_CONTAINER
            and x.get("read_only") is True and y.get("read_only") is True
            and x.get("cap_drop") == ["ALL"] and y.get("cap_drop") == ["ALL"]
            and obj["networks"]["security-lab"]["name"] == NETWORK
            and obj["volumes"]["store-runtime"]["name"] == VOLUME
            and x.get("ports") == ["127.0.0.1:18080:8000"]
        )
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


class R4C4FMockComposeAdapter:
    """Runner must be injected; no built-in runner or subprocess fallback."""

    def __init__(self, *, source_root: Path, evidence_root: Path,
                 manifest_path: Path, manifest_sha256: str,
                 expected_inventory: MockInventory,
                 inventory_observer: Callable[[], MockInventory],
                 binary_runner: Callable[[tuple[str, ...], Path], MockBinaryProcess]):
        self.root = source_root.resolve(strict=True)
        self.evidence = evidence_root
        self.sha = manifest_sha256
        self.manifest_path = manifest_path
        self.admission = load_mock_option_b_admission(
            source_root=self.root, manifest=manifest_path, external_sha256=manifest_sha256)
        if not isinstance(expected_inventory, MockInventory):
            raise R4C4FBlocked("missing independently frozen mock inventory")
        self.expected_inventory = expected_inventory
        self.inventory_observer = inventory_observer
        self.binary_runner = binary_runner
        self.seen = set()

    def command(self, operation: str, *, test_id: str | None = None,
                attempt_number: int = 1) -> tuple[str, ...]:
        if operation not in OPERATIONS:
            raise R4C4FBlocked("operation not in mock adapter allowlist")
        prefix = ("docker", "--context", self.admission.context,
                  "compose", "-f", str(self.root/ISOLATED_COMPOSE),
                  "--project-directory", str(self.root))
        commands = {
          "config": ("config", "--format", "json"),
          "build": ("build",),
          "start_app": ("up", "-d", "--no-build", "vulnerable-store"),
          "start_executor": ("up", "-d", "--no-build", "controlled-executor"),
          "functional": ("exec", "-T", "controlled-executor", "python", "-m", "verification.functional"),
          "regression": ("exec", "-T", "controlled-executor", "python", "-m", "pytest",
                         "-q", "-p", "no:cacheprovider", "tests/test_vulnerable_store.py"),
        }
        if operation in commands:
            if test_id is not None:
                raise R4C4FBlocked("unused test id in non-registered action")
            return prefix + commands[operation]
        if operation in ("health_app", "health_executor"):
            if test_id is not None:
                raise R4C4FBlocked("test ID not allowed for health probe")
            target = APP_CONTAINER if operation == "health_app" else EXECUTOR_CONTAINER
            return ("docker", "--context", self.admission.context, "inspect",
                    "--format={{.State.Health.Status}}", target)
        if test_id not in APPROVED_TESTS or attempt_number != 1:
            raise R4C4FBlocked("test identifier or number not in frozen registered allowlist")
        return prefix + (
           "exec", "-T", "controlled-executor",
           "python", "-m", "infrastructure.executor.run_verification_test",
           "--test-id", test_id, "--attempt-number", "1",
           "--run-id", self.admission.run_id[:70]+"-security_replay",
        )

    def collect_mock(self, *, operation: str, case_id: str,
                     test_id: str | None = None, attempt_number: int = 1) -> MockAdapterReceipt:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{0,63}", case_id):
            raise R4C4FBlocked("invalid case ID")
        argv = self.command(operation, test_id=test_id, attempt_number=attempt_number)
        if case_id in self.seen or (self.evidence/case_id).exists():
            raise R4C4FBlocked("duplicate case denied; never redispatch")
        self.seen.add(case_id)
        load_mock_option_b_admission(
            source_root=self.root, manifest=self.manifest_path, external_sha256=self.sha)
        before = self.inventory_observer()
        if not isinstance(before, MockInventory) or not _mock_inventory_valid(
            self.expected_inventory, before, self.admission
        ):
            raise R4C4FBlocked("simulated pre-dispatch daemon or resource collision")
        if not self.evidence.is_dir() or self.evidence.is_symlink():
            raise R4C4FBlocked("missing independent evidence parent")
        case = self.evidence/case_id
        case.mkdir(mode=0o700)
        def save(name: str, data: bytes):
            with (case/name).open("xb") as f:
                f.write(data)
        save("dispatch-intent.json", (json.dumps({
            "operation":operation, "argv":argv,"scope":"offline_mock_only",
            "case_id":case_id,"manifest_sha256":self.sha,
        }, sort_keys=True)+"\n").encode())
        try:
            result = self.binary_runner(argv, self.root)
            if not isinstance(result, MockBinaryProcess):
                raise ValueError("mock binary runner returned invalid type")
            def raw_chunks(chunks):
                if any(not isinstance(part, bytes) for part in chunks):
                    raise ValueError("non-binary process chunk")
                data = b"".join(chunks)
                if len(data)>65536:
                    raise ValueError("process raw stream exceeds 64KiB")
                return data
            stdout = raw_chunks(result.stdout_chunks)
            stderr = raw_chunks(result.stderr_chunks)
            save("stdout.raw", stdout)
            save("stderr.raw", stderr)
            after = self.inventory_observer()
            reasons=[]
            if not isinstance(after, MockInventory) or not _mock_inventory_valid(
                self.expected_inventory, after, self.admission):
                reasons.append("simulated daemon/resource drift after dispatch")
            try:
                load_mock_option_b_admission(
                    source_root=self.root,manifest=self.manifest_path,external_sha256=self.sha)
            except R4C4FBlocked:
                reasons.append("source or admission drift after dispatch")
            if operation == "config" and not _check_normalized_config(stdout):
                reasons.append("mock normalized Compose config does not match isolated identities")
            if result.timed_out or result.returncode != 0:
                reasons.append("mock command timed out or returned nonzero")
            outcome = ("mock_provenance_failure" if any(
                "drift" in x or "does not match" in x for x in reasons)
                else "mock_failure" if reasons else "mock_success")
            receipt = MockAdapterReceipt(
                outcome=outcome,action=operation,case_id=case_id,
                argv=argv,cwd=str(self.root),manifest_sha256=self.sha,
                stdout_sha256=sha256(stdout).hexdigest(),
                stderr_sha256=sha256(stderr).hexdigest(),
                returncode=result.returncode,timed_out=result.timed_out,
                reasons=tuple(reasons))
            save("receipt.json",(json.dumps(receipt.model_dump(mode="json"),
                sort_keys=True,indent=2)+"\n").encode())
            return receipt
        except Exception as exc:
            save("failure.json",(json.dumps({
                "status":"offline_dispatch_failed_no_retry",
                "error_type":type(exc).__name__
            },sort_keys=True)+"\n").encode())
            raise R4C4FBlocked("mock dispatch failed; no retry") from exc
