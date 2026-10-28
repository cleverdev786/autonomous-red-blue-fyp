"""Offline Gate 2/3 tests: injected Git/Docker and benign local pipe limits."""
from __future__ import annotations

import json
import shutil
import sys
from hashlib import sha256
from pathlib import Path

import pytest
from test_security_preflight import _R4B1_CASES, _r4b1_actual_executor_result

from security_tests.registry import SecurityTestRegistry
from services.isolated_compose_executor import (
    HOST_FILES,
    BinaryResult,
    IsolatedDockerExecutor,
    IsolatedExecutionBlocked,
    RealExecutionAdmission,
    load_real_admission,
    run_local_binary,
)
from services.isolated_compose_mock_adapter import (
    APP_CONTAINER,
    EXECUTOR_CONTAINER,
    IMAGE,
    NETWORK,
    PROJECT,
    VOLUME,
)
from services.target_registry import TargetRegistry

REPO = Path(__file__).resolve().parents[1]
HEAD = "1" * 40
TREE = "2" * 40
DAEMON = "synthetic-offline-daemon"
IMAGE_ID = "sha256:" + "a" * 64
APP_ID, EXEC_ID = "b" * 64, "c" * 64


@pytest.fixture
def environment(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    for rel in HOST_FILES:
        dst = root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(REPO / rel, dst)
    external = tmp_path / "external"
    external.mkdir()
    (external / "evidence").mkdir()
    pin = RealExecutionAdmission(
        source_head=HEAD, source_tree=TREE,
        source_hashes={rel: sha256((root / rel).read_bytes()).hexdigest()
                       for rel in HOST_FILES},
        daemon_id=DAEMON, image_id=IMAGE_ID,
        app_container_id=APP_ID, executor_container_id=EXEC_ID,
        run_id="gate2-run-1", case_id="gate2-case-1",
        scenario_id="sqli-login-001",
    )
    manifest = external / "admission.json"
    manifest.write_bytes(pin.canonical_bytes())
    registry = TargetRegistry.from_directories(
        targets_dir=REPO / "config/targets",
        security_tests_dir=REPO / "config/security_tests")
    return root, external, manifest, pin, registry


def compose_config():
    return {
        "name": PROJECT,
        "services": {
            "vulnerable-store": {"image": IMAGE, "container_name": APP_CONTAINER,
                "ports": []},
            "controlled-executor": {"image": IMAGE, "container_name": EXECUTOR_CONTAINER},
        },
        "networks": {"security-lab": {"name": NETWORK}},
        "volumes": {"store-runtime": {"name": VOLUME}},
    }


def container_config(name):
    app = name == APP_CONTAINER
    return {
        "Id": APP_ID if app else EXEC_ID,
        "Image": IMAGE_ID,
        "Config": {"Image": IMAGE, "User": "10001:10001", "Labels": {
            "com.docker.compose.project": PROJECT,
            "com.docker.compose.service": "vulnerable-store" if app else "controlled-executor"}},
        "State": {"Running": True, "Health": {"Status": "healthy"}},
        "Mounts": [{"Type": "volume", "Name": VOLUME, "Destination": "/runtime"}] if app else [],
        "HostConfig": {
            "ReadonlyRootfs": True, "Privileged": False, "CapDrop": ["ALL"],
            "NanoCpus": 500000000 if app else 250000000,
            "Memory": 268435456 if app else 134217728,
            "PidsLimit": 128 if app else 64,
            "SecurityOpt": ["no-new-privileges:true"],
            "PortBindings": {}},
        "NetworkSettings": {"Networks": {NETWORK: {"NetworkID": "net123"}},
                            "Ports": {"8000/tcp": None} if app else {}},
    }



def configured(
    environment, *, scenario="sqli-login-001", fault=None, process=None,
    command_hook=None,
):
    root, external, manifest, pin, registry = environment
    if scenario != pin.scenario_id:
        pin = pin.model_copy(update={"scenario_id": scenario})
        manifest.write_bytes(pin.canonical_bytes())
    baseline = next(replies for name, replies, _ in _R4B1_CASES if name == scenario)
    result, _ = _r4b1_actual_executor_result(scenario, baseline)
    result = result.model_copy(update={"run_id": pin.run_id})
    payload = result.model_dump_json().encode() + b"\r\n"
    calls, dispatches = [], []

    def runner(argv, cwd):
        assert cwd == root
        calls.append(argv)
        if command_hook is not None:
            hooked = command_hook(argv)
            if hooked is not None:
                return BinaryResult(0, hooked, b"")
        if argv[0] == "git":
            if "symbolic-ref" in argv:
                answer = pin.source_branch
            elif "status" in argv:
                answer = "?? stray.py" if fault == "dirty" else ""
            elif argv[-1] == "HEAD^{tree}":
                answer = pin.source_tree
            else:
                answer = "f" * 40 if fault == "head" else pin.source_head
            return BinaryResult(0, (answer + "\n").encode(), b"")
        if argv == ("docker", "context", "show"):
            return BinaryResult(0, b"foreign" if fault == "context" else b"default\n", b"")
        assert argv[:3] == ("docker", "--context", "default")
        if "infrastructure.executor.run_verification_test" in argv:
            dispatches.append(argv)
            return process if process is not None else BinaryResult(0, payload, b"")
        if "sha256sum" in argv:
            files = argv[argv.index("sha256sum") + 1:]
            data = "".join(
                f"{pin.source_hashes[rel.removeprefix('/workspace/')]}  {rel}\n"
                for rel in files)
            if fault == "source_inside":
                data = "0" * 64 + data[64:]
            return BinaryResult(0, data.encode(), b"")
        if argv[-3:] == ("info", "--format", "{{json .}}"):
            item = {"ID": "foreign" if fault == "daemon" else DAEMON}
        elif argv[-3:] == ("config", "--format", "json"):
            item = compose_config()
            if fault == "config":
                item["services"]["vulnerable-store"]["ports"] = [
                    {"host_ip": "127.0.0.1", "mode": "ingress",
                     "protocol": "tcp", "published": "18080", "target": 8000}]
            if fault == "config_executor_port":
                item["services"]["controlled-executor"]["ports"] = [
                    {"host_ip": "0.0.0.0", "mode": "ingress",
                     "protocol": "tcp", "published": "18081", "target": 8000}]
        elif argv[3] == "network":
            item = {
                "Name": NETWORK, "Id": "net123", "Driver": "bridge",
                "Internal": True, "Attachable": False,
                "Labels": {"com.docker.compose.project": PROJECT},
                "Options": {"com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"},
                "Containers": {APP_ID: {}, EXEC_ID: {}},
            }
            if fault == "network_owner":
                item["Labels"]["com.docker.compose.project"] = "unowned"
            if fault == "third_party":
                item["Containers"]["d" * 64] = {}
            if fault == "network_binding":
                item["Options"]["com.docker.network.bridge.host_binding_ipv4"] = "0.0.0.0"
        elif argv[3] == "image":
            item = {
                "Id": "sha256:" + "f" * 64 if fault == "image" else IMAGE_ID,
                "Config": {"Labels": {"com.docker.compose.project":
                                     "another-project" if fault == "image_owner" else PROJECT}},
            }
        elif argv[3] == "volume":
            item = {
                "Name": VOLUME, "Driver": "local", "Mountpoint": "/var/lib/docker/volumes/isolated",
                "CreatedAt": "2026-10-10T00:00:00Z",
                "Labels": {"com.docker.compose.project":
                           "unowned" if fault == "volume_owner" else PROJECT},
            }
        elif argv[3] == "container":
            item = container_config(argv[-1])
            if fault == "container_id":
                item["Id"] = "d" * 64
            if fault == "privileged":
                item["HostConfig"]["Privileged"] = True
            if fault == "extra_mount":
                item["Mounts"].append({"Type": "bind", "Source": "/var/run/docker.sock",
                                       "Destination": "/var/run/docker.sock"})
            if fault == "cpu":
                item["HostConfig"]["NanoCpus"] = 0
            if fault == "labels":
                item["Config"]["Labels"]["com.docker.compose.project"] = "wrong"
            if fault == "requested_ports_missing" and argv[-1] == APP_CONTAINER:
                del item["HostConfig"]["PortBindings"]
            if fault == "requested_port_app" and argv[-1] == APP_CONTAINER:
                item["HostConfig"]["PortBindings"] = {
                    "8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]}
            if fault == "requested_port_executor" and argv[-1] == EXECUTOR_CONTAINER:
                item["HostConfig"]["PortBindings"] = {
                    "8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]}
            if fault == "effective_port_app" and argv[-1] == APP_CONTAINER:
                item["NetworkSettings"]["Ports"] = {
                    "8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": "18080"}]}
            if fault == "effective_port_executor" and argv[-1] == EXECUTOR_CONTAINER:
                item["NetworkSettings"]["Ports"] = {
                    "8000/tcp": [{"HostIp": "0.0.0.0", "HostPort": "18080"}]}
            if fault == "effective_port_unrelated" and argv[-1] == APP_CONTAINER:
                item["NetworkSettings"]["Ports"]["9999/tcp"] = [
                    {"HostIp": "0.0.0.0", "HostPort": "19999"}]
            if fault == "effective_ports_missing" and argv[-1] == APP_CONTAINER:
                del item["NetworkSettings"]["Ports"]
            if fault == "effective_ports_empty_list" and argv[-1] == APP_CONTAINER:
                item["NetworkSettings"]["Ports"]["8000/tcp"] = []
            if fault == "effective_ports_null_object" and argv[-1] == APP_CONTAINER:
                item["NetworkSettings"]["Ports"] = None
        else:
            raise AssertionError("unexpected command " + str(argv))
        return BinaryResult(0, json.dumps(item).encode(), b"")

    seam = IsolatedDockerExecutor(
        source_root=root, evidence_root=external / "evidence",
        admission_path=manifest, admission_sha256=sha256(pin.canonical_bytes()).hexdigest(),
        registry=registry, implementations=SecurityTestRegistry.default(), runner=runner)
    return seam, calls, dispatches, payload



def test_admission_requires_independent_immutable_sha(environment):
    root, _ext, path, pin, _registry = environment
    assert load_real_admission(root, path, sha256(pin.canonical_bytes()).hexdigest()) == pin
    path.write_bytes(pin.canonical_bytes() + b" ")
    with pytest.raises(IsolatedExecutionBlocked, match="digest mismatch"):
        load_real_admission(root, path, sha256(pin.canonical_bytes()).hexdigest())


@pytest.mark.parametrize("scenario", [
    "sqli-login-001", "xss-search-001", "path-traversal-read-001",
])
def test_bounded_registered_flow_from_actual_executor_fixture(environment, scenario, monkeypatch):
    import subprocess
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("real subprocess called"))
    seam, _calls, dispatches, payload = configured(environment, scenario=scenario)
    receipt = seam.run_registered()
    assert receipt.outcome == "baseline_exploit_confirmed"
    assert receipt.observation_sha256 is not None
    assert receipt.model_calls == 0 and receipt.scope == "development_only_not_final_research"
    assert len(dispatches) == 1
    assert dispatches[0][-2:] == ("--run-id", "gate2-run-1")
    assert "compose.isolated.yaml" in " ".join(dispatches[0])
    assert receipt.stdout_sha256 == sha256(payload).hexdigest()
    directory = seam.evidence / receipt.case_id
    assert (directory / "stdout.raw").read_bytes() == payload
    assert (directory / "observation.json").is_file()
    with pytest.raises(IsolatedExecutionBlocked, match="case already exists"):
        seam.run_registered()
    assert len(dispatches) == 1


@pytest.mark.parametrize("fault", [
    "head", "dirty", "context", "daemon", "config", "source_inside",
    "image", "container_id", "privileged", "labels",
    "extra_mount", "cpu", "network_owner", "third_party",
    "volume_owner", "image_owner", "network_binding",
    "config_executor_port", "requested_ports_missing",
    "requested_port_app", "requested_port_executor",
    "effective_port_app", "effective_port_executor", "effective_port_unrelated",
    "effective_ports_missing", "effective_ports_empty_list",
    "effective_ports_null_object",
])
def test_preflight_fail_closed_before_registered_execution(environment, fault):
    seam, _calls, dispatches, _ = configured(environment, fault=fault)
    with pytest.raises(IsolatedExecutionBlocked):
        seam.run_registered()
    assert dispatches == []
    assert not list(seam.evidence.iterdir())


def test_host_source_tamper_rejected_without_execution(environment):
    seam, _calls, dispatches, _ = configured(environment)
    (seam.root / "services/controlled_executor.py").write_text("tampered")
    with pytest.raises(IsolatedExecutionBlocked, match="source hash drift"):
        seam.run_registered()
    assert dispatches == []


@pytest.mark.parametrize("response,expected", [
    (BinaryResult(5, b"not JSON", b"docker failed"), "executor_failed"),
    (BinaryResult(-1, b"partial", b"", True), "inconclusive"),
    (BinaryResult(0, b"x" * 65537, b""), "executor_failed"),
    (BinaryResult(0, b'{"run_id":"wrong"}', b""), "provenance_failed"),
])
def test_failed_incomplete_oversized_and_forged_outputs_never_pass(
    environment, response, expected,
):
    seam, _calls, dispatches, _ = configured(environment, process=response)
    receipt = seam.run_registered()
    assert receipt.outcome == expected
    assert receipt.observation_sha256 is None
    assert len(dispatches) == 1


def test_no_evidence_inside_source_and_no_missing_pin(environment):
    root, external, path, pin, registry = environment
    with pytest.raises(IsolatedExecutionBlocked):
        IsolatedDockerExecutor(
            source_root=root, evidence_root=root, admission_path=path,
            admission_sha256=sha256(pin.canonical_bytes()).hexdigest(),
            registry=registry, implementations=SecurityTestRegistry.default())
    with pytest.raises(IsolatedExecutionBlocked):
        IsolatedDockerExecutor(
            source_root=root, evidence_root=external / "evidence", admission_path=path,
            admission_sha256="0" * 64,
            registry=registry, implementations=SecurityTestRegistry.default())



def test_post_dispatch_daemon_drift_invalidates_semantics_and_preserves_bytes(environment):
    seam, _calls, dispatches, payload = configured(environment)
    original = seam.runner
    dispatched = False

    def injected(argv, cwd):
        nonlocal dispatched
        if "infrastructure.executor.run_verification_test" in argv:
            dispatched = True
        if dispatched and argv[-3:] == ("info", "--format", "{{json .}}"):
            return BinaryResult(0, b'{"ID":"different-after-dispatch"}', b"")
        return original(argv, cwd)

    seam.runner = injected
    receipt = seam.run_registered()
    assert receipt.outcome == "provenance_failed"
    assert receipt.observation_sha256 is None
    assert len(dispatches) == 1
    assert (seam.evidence / receipt.case_id / "stdout.raw").read_bytes() == payload
    with pytest.raises(IsolatedExecutionBlocked):
        seam.run_registered()
    assert len(dispatches) == 1



def test_bounded_local_binary_exact_raw_bytes_and_no_shell(tmp_path):
    # Harmless Python-only local subprocess. Never a Docker or registered test.
    payload = run_local_binary(
        (sys.executable, "-c",
         ("import sys; sys.stdout.buffer.write(b'\\r\\nabc'); "
          "sys.stderr.buffer.write(b'\\x00z')")), tmp_path,
    )
    assert payload == BinaryResult(0, bytes([13, 10]) + b"abc", bytes([0]) + b"z")


def test_bounded_local_binary_rejects_unlimited_pipe_output(tmp_path):
    # stdout alone cannot grow past the live read cap before being rejected.
    with pytest.raises(IsolatedExecutionBlocked, match="hard limit"):
        run_local_binary(
            (sys.executable, "-c",
             ("import sys; sys.stdout.buffer.write(b'X' * 200000); "
              "sys.stdout.buffer.flush()")), tmp_path,
        )


def test_evidence_directory_replacement_fails_without_dispatch(environment):
    seam, _calls, dispatches, _ = configured(environment)
    outside = seam.evidence.parent / "relocated"
    seam.evidence.rename(outside)
    seam.evidence.symlink_to(outside, target_is_directory=True)
    with pytest.raises(IsolatedExecutionBlocked, match="evidence parent changed"):
        seam.run_registered()
    assert dispatches == []


@pytest.mark.parametrize("value", [
    {"schema_version": "isolated-registered-live-admission-v1"},
    {"allow_single_registered_execution": False},
    {"final_evaluation": True},
    {"attempt_number": 2},
    {"app_container_id": EXEC_ID},
])
def test_real_admission_does_not_expand_authorization(environment, value):
    from pydantic import ValidationError

    pin = environment[3]
    with pytest.raises(ValidationError):
        RealExecutionAdmission.model_validate({**pin.model_dump(), **value})
