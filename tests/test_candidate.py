"""Offline packaging for a reviewed, independently admissible patched Docker target.

No Docker invocation or runtime approval is produced by these tests.
"""
import json
from hashlib import sha256
from pathlib import Path

import pytest
import yaml
from test_branch import localized  # noqa: F401
from test_classify import environment  # noqa: F401
from test_preview import reviewed_archive  # noqa: F401
from test_replay import staged  # noqa: F401

from services.trusted_remediation_compiler import SOURCE


def test_buildable_review_candidate_is_outside_repo_and_hardened(staged):  # noqa: F811
    from services.blue_docker import prepare_docker_candidate
    from services.blue_replay import verify_blue_replay
    info, output, pins, _selected = staged
    source = pins["source_root"] / SOURCE
    baseline = source.read_bytes()
    verified = verify_blue_replay(
        staged=info, output_parent=output, source_root=pins["source_root"],
    )
    produced = prepare_docker_candidate(
        staged=info, output_parent=output, source_root=pins["source_root"],
        replay_sha256=verified["report_sha256"],
    )
    context = Path(produced["build_context"])
    assert context.is_dir()
    assert context.parent == output / ("blue-patch-" + info["job_id"].replace("-", ""))
    assert pins["source_root"].resolve() not in context.resolve().parents
    assert (context / SOURCE).read_bytes() != baseline
    assert sha256((context / SOURCE).read_bytes()).hexdigest() == verified["staged_source_sha256"]
    assert (context / "dummy_apps/vulnerable_store/Dockerfile").is_file()
    assert (context / "pyproject.toml").is_file()
    assert (context / "requirements/isolated-py313-linux-amd64.lock").is_file()
    assert (context / "infrastructure/executor/run_verification_test.py").is_file()
    assert (context / ".dockerignore").is_file()
    from services.isolated_compose_mock_adapter import verify_isolation_yaml
    verify_isolation_yaml(context)
    assert not (context / ".git").exists()
    assert not (context / "models").exists()
    compose = yaml.safe_load((context / "compose.blue.yaml").read_text())
    app, executor = compose["services"]["vulnerable-store"], compose["services"]["controlled-executor"]
    assert set(compose["services"]) == {"vulnerable-store", "controlled-executor"}
    assert compose["name"].startswith("fyp-blue-")
    assert "r4c4f" not in str(compose)
    assert app["image"] == executor["image"] == produced["image"]
    assert app["build"] == executor["build"] == {
        "context": ".", "dockerfile": "dummy_apps/vulnerable_store/Dockerfile",
    }
    assert all(c["read_only"] and not c["privileged"] and c["cap_drop"] == ["ALL"]
               and c.get("ports", []) == [] for c in (app, executor))
    assert compose["networks"]["security-lab"]["internal"] is True
    assert compose["networks"]["security-lab"]["attachable"] is False
    assert produced["image_built"] is False
    assert produced["docker_executed"] is False
    assert produced["independent_admission_granted"] is False
    assert produced["final_repair_accepted"] is False
    assert source.read_bytes() == baseline
    receipt = context.parent / "candidate.json"
    assert receipt.is_file()
    assert sha256(receipt.read_bytes()).hexdigest() == produced["candidate_sha256"]
    expected = json.loads(receipt.read_text())["file_sha256"]
    assert all(
        sha256((context / name).read_bytes()).hexdigest() == digest
        for name, digest in expected.items()
    )


def test_missing_accepted_offline_replay_blocks_build_candidate(staged):  # noqa: F811
    from services.blue_docker import BlueDockerBlocked, prepare_docker_candidate
    info, output, pins, _selected = staged
    with pytest.raises(BlueDockerBlocked):
        prepare_docker_candidate(
            staged=info, output_parent=output, source_root=pins["source_root"],
            replay_sha256="0" * 64,
        )
    assert not (Path(info["branch_repo"]).parent / "docker-context").exists()


@pytest.mark.parametrize("change", ["report", "source", "diff", "untrusted_parent"])
def test_changed_evidence_or_staged_patch_never_builds_candidate(staged, change):  # noqa: F811
    from services.blue_docker import BlueDockerBlocked, prepare_docker_candidate
    from services.blue_replay import verify_blue_replay
    info, output, pins, _selected = staged
    verified = verify_blue_replay(
        staged=info, output_parent=output, source_root=pins["source_root"],
    )
    if change == "report":
        (Path(info["branch_repo"]).parent / "replay.json").write_text("{}")
    elif change == "source":
        (Path(info["branch_repo"]) / SOURCE).write_text("evil\n")
    elif change == "diff":
        info["git_diff_sha256"] = "1" * 64
    else:
        output = pins["source_root"]
    with pytest.raises(BlueDockerBlocked):
        prepare_docker_candidate(
            staged=info, output_parent=output, source_root=pins["source_root"],
            replay_sha256=verified["report_sha256"],
        )


def test_candidate_created_only_once(staged):  # noqa: F811
    from services.blue_docker import BlueDockerBlocked, prepare_docker_candidate
    from services.blue_replay import verify_blue_replay
    info, output, pins, _selected = staged
    verified = verify_blue_replay(staged=info, output_parent=output, source_root=pins["source_root"])
    args = {
        "staged": info, "output_parent": output,
        "source_root": pins["source_root"],
        "replay_sha256": verified["report_sha256"],
    }
    first = prepare_docker_candidate(**args)
    with pytest.raises(BlueDockerBlocked, match="already"):
        prepare_docker_candidate(**args)
    assert Path(first["build_context"]).is_dir()
