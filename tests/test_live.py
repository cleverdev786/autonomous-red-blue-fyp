"""Injected patched-Docker replay tests. Never call the Docker daemon."""
import json
from hashlib import sha256
from pathlib import Path

import pytest
from test_branch import localized  # noqa: F401
from test_classify import environment  # noqa: F401
from test_preview import reviewed_archive  # noqa: F401
from test_replay import staged  # noqa: F401

from schemas.red_team import HttpExchangeEvidence
from schemas.red_team import TestExecutionResult as ExecutionResult
from services.blue_live import BlueLiveAdmission, BlueLiveBlocked, run_patched_replay
from services.isolated_compose_executor import BinaryResult


@pytest.fixture
def admitted(staged):  # noqa: F811
    from services.blue_docker import prepare_docker_candidate
    from services.blue_replay import verify_blue_replay
    info, parent, pins, _ = staged
    offline = verify_blue_replay(staged=info, output_parent=parent, source_root=pins["source_root"])
    built = prepare_docker_candidate(
        staged=info, output_parent=parent, source_root=pins["source_root"],
        replay_sha256=offline["report_sha256"],
    )
    build_record = {
        "schema_version": "reviewed-image-build-v1",
        "candidate_sha256": built["candidate_sha256"],
        "daemon_id": "approved-daemon",
        "image_id": "sha256:" + "a"*64,
        "patched_source_sha256": built["patched_source_sha256"],
        "build_log_sha256": "e"*64,
        "independent_review_complete": True,
    }
    attestation = parent / "image-attestation.json"
    attestation.write_text(
        json.dumps(build_record, sort_keys=True, separators=(",", ":")) + "\n"
    )
    approved = BlueLiveAdmission(
        job_id=info["job_id"], candidate_sha256=built["candidate_sha256"],
        build_attestation_sha256=sha256(attestation.read_bytes()).hexdigest(),
        build_attestation_path=str(attestation),
        daemon_id="approved-daemon", image_id="sha256:" + "a"*64,
        app_container_id="b"*64, executor_container_id="c"*64,
        network_id="approved-network-id",
        run_id="patched-replay-1",
    )
    location = parent / "reviewed-admission.json"
    location.write_bytes(approved.canonical_bytes())
    return info, parent, pins, built, approved, location


def fake_runner(approved, built, *, attack=401, unhealthy=False, drift=False, wrong_executor=False):
    from security_tests.registry import SecurityTestRegistry
    from services.isolated_compose_executor import CONTAINER_FILES
    calls = []
    context = Path(built["build_context"])
    name = built["image"].split(":")[0]
    network = name + "-network"
    responses = [401, attack]
    steps = SecurityTestRegistry.default().get("sqli-login-bypass-001").build_steps()
    exchanges = tuple(HttpExchangeEvidence(
        exchange_id=f"live-{i}", request_id=f"live-{i}",
        step_id=step.step_id, endpoint_id=step.endpoint_id, method="POST",
        status_code=responses[i], body_excerpt=(
            '{"authenticated":true}' if responses[i] == 200 else
            '{"detail":"Invalid username or password"}'
        ), duration_ms=1,
    ) for i,step in enumerate(steps))
    payload = ExecutionResult(
        run_id=approved.run_id, target_id="vulnerable-store",
        test_id="sqli-login-bypass-001", attempt_number=1, request_count=2,
        completed=True, exchanges=exchanges, duration_ms=2,
        evidence=SecurityTestRegistry.default().get("sqli-login-bypass-001").evaluate(exchanges),
    ).model_dump_json().encode()
    def response(args, root):
        cmd = tuple(args)
        calls.append(cmd)
        assert root == context
        if cmd == ("docker", "context", "show"):
            return BinaryResult(0,b"default\n",b"")
        if cmd[3:4] == ("info",):
            return BinaryResult(0,json.dumps({"ID":approved.daemon_id}).encode(),b"")
        if cmd[3:5] == ("image", "inspect"):
            return BinaryResult(0,json.dumps({"Id":approved.image_id}).encode(),b"")
        if "network" in cmd and "inspect" in cmd:
            return BinaryResult(0,json.dumps({
                "Id":approved.network_id,"Name":network,"Internal":True,"Attachable":False,
                "Containers":{approved.app_container_id:{},approved.executor_container_id:{}}
            }).encode(),b"")
        if "container" in cmd and "inspect" in cmd:
            app = cmd[-1] == name+"-vulnerable-store"
            service="vulnerable-store" if app else "controlled-executor"
            obj = {
                "Id": approved.app_container_id if app else approved.executor_container_id,
                "Image": approved.image_id,
                "Config": {"Image": built["image"], "User":"10001:10001",
                           "Labels":{"com.docker.compose.project":name,
                                     "com.docker.compose.service":service}},
                "State":{"Running":True,"Health":{"Status":"unhealthy" if unhealthy else "healthy"}},
                "HostConfig":{"ReadonlyRootfs":True,"Privileged":False,"CapDrop":["ALL"],
                              "SecurityOpt":["no-new-privileges:true"],"PortBindings":{},
                              "NanoCpus":500000000 if app else 250000000,
                              "Memory":268435456 if app else 134217728,
                              "PidsLimit":128 if app else 64},
                "NetworkSettings":{"Networks":{network:{"NetworkID":approved.network_id}},
                                   "Ports":{"8000/tcp":None} if app else {}},
                "Mounts":[{"Type":"volume","Name":name+"-volume","Destination":"/runtime"}] if app else [],
            }
            if wrong_executor and not app:
                obj["Config"]["User"] = "0:0"
            return BinaryResult(0,json.dumps(obj).encode(),b"")
        if "sha256sum" in cmd:
            stdout="".join(
                f"{sha256((context / rel).read_bytes()).hexdigest()}  /workspace/{rel}\n"
                for rel in CONTAINER_FILES
            ).encode()
            if drift:
                stdout=stdout.replace(b"f",b"0",1)
            return BinaryResult(0,stdout,b"")
        if any("run_verification_test" in part for part in cmd):
            return BinaryResult(0,payload,b"")
        raise AssertionError("unexpected Docker command "+repr(cmd))
    return response,calls


def execute(admitted, runner):
    _, _parent, _, built, _approved, location = admitted
    return run_patched_replay(
        candidate_dir=Path(built["build_context"]),
        admission_path=location,
        admission_sha256=sha256(location.read_bytes()).hexdigest(),
        candidate_sha256=built["candidate_sha256"], runner=runner,
    )


def test_patched_registered_test_is_bound_to_approved_containers(admitted):
    _,_,_,built,approved,_=admitted
    runner,calls=fake_runner(approved,built)
    receipt=execute(admitted,runner)
    assert receipt["status"]=="passed"
    assert receipt["test_id"]=="sqli-login-bypass-001"
    assert receipt["control_status"]==receipt["injection_status"]==401
    assert receipt["docker_replayed"] is False
    assert receipt["evidence_scope"]=="injected_offline_runner"
    saved_raw=Path(built["build_context"]).parent/"docker-stdout.raw"
    assert saved_raw.is_file()
    assert sha256(saved_raw.read_bytes()).hexdigest()==receipt["stdout_sha256"]
    assert receipt["final_repair_accepted"] is False
    assert sum(("infrastructure.executor.run_verification_test" in a) for a in calls)==1
    assert all("build" not in a and "up" not in a and "down" not in a for a in calls)
    with pytest.raises(BlueLiveBlocked,match="already"):
        execute(admitted,runner)


@pytest.mark.parametrize("case",["wrong_hash","invalid_schema","changed_candidate","unhealthy","drift","exploit"])
def test_invalid_runtime_or_candidate_is_not_accepted(admitted,case):
    _,_,_,built,approved,location=admitted
    runner,calls=fake_runner(approved,built,
                             attack=200 if case=="exploit" else 401,
                             unhealthy=case=="unhealthy",drift=case=="drift")
    if case=="wrong_hash":
        with pytest.raises(BlueLiveBlocked):
            run_patched_replay(
                candidate_dir=Path(built["build_context"]),admission_path=location,
                admission_sha256="0"*64,candidate_sha256=built["candidate_sha256"],runner=runner)
    elif case=="invalid_schema":
        location.write_text("{}")
        with pytest.raises(BlueLiveBlocked):
            execute(admitted,runner)
    elif case=="changed_candidate":
        (Path(built["build_context"])/"compose.blue.yaml").write_text("changed")
        with pytest.raises(BlueLiveBlocked):
            execute(admitted,runner)
    else:
        if case in ("unhealthy","drift"):
            with pytest.raises(BlueLiveBlocked):
                execute(admitted,runner)
        else:
            result=execute(admitted,runner)
            assert result["status"]=="failed"
            assert result["final_repair_accepted"] is False
    if case not in ("exploit",):
        assert not any(("infrastructure.executor.run_verification_test" in a) for a in calls)



@pytest.mark.parametrize("which", ["missing_attestation", "tampered_attestation"])
def test_unverified_image_build_is_blocked_before_docker(admitted, which):
    _, _parent, _, built, approved, _location = admitted
    runner, calls = fake_runner(approved, built)
    attestation = Path(approved.build_attestation_path)
    if which == "missing_attestation":
        attestation.unlink()
    else:
        attestation.write_text("{}")
    with pytest.raises(BlueLiveBlocked):
        execute(admitted, runner)
    assert not calls



def test_unprivileged_executor_identity_cannot_be_skipped(admitted):
    _,_,_,built,approved,_=admitted
    runner,calls=fake_runner(approved,built,wrong_executor=True)
    with pytest.raises(BlueLiveBlocked):
        execute(admitted,runner)
    assert not any("infrastructure.executor.run_verification_test" in a for a in calls)
