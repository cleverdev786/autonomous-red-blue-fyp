"""Patch-functionality checks only: no Docker, model claim or live-source edits."""
from hashlib import sha256

import pytest

pytest_plugins = ("test_isolated_compose_executor",)


@pytest.mark.parametrize("scenario,registered_test", [
    ("xss", "xss-reflection-001"),
    ("traversal", "path-traversal-private-file-001"),
])
def test_trusted_non_sql_patch_passes_registered_and_functional_replay(
    environment, tmp_path, scenario, registered_test,
):
    from services.non_sql_local_replay import verify_non_sql_local_replay

    root = environment[0]
    vulnerable_source = root / "dummy_apps/vulnerable_store/app/scenario_routes.py"
    before = vulnerable_source.read_bytes()
    output = verify_non_sql_local_replay(
        source_root=root, scenario=scenario, working_parent=tmp_path,
    )
    assert output["status"] == "passed"
    assert output["registered_test_id"] == registered_test
    assert output["registered_exploit_evidence"] == []
    assert output["registered_steps_executed"] == 2
    assert output["functional_checks"]
    assert all(output["functional_checks"].values())
    assert output["replay_mode"] == "in_process_registered_test"
    assert output["patch_origin"] == "trusted_deterministic_builder"
    assert output["model_localization_used"] is False
    assert output["docker_replayed"] is False
    assert output["final_research_qualified"] is False
    assert sha256(vulnerable_source.read_bytes()).hexdigest() == sha256(before).hexdigest()


@pytest.mark.parametrize("scenario", ["xss", "traversal"])
def test_non_sql_replay_refuses_unpinned_source(environment, tmp_path, scenario):
    from services.non_sql_local_replay import (
        NonSqlReplayBlocked, verify_non_sql_local_replay,
    )

    root = environment[0]
    source = root / "dummy_apps/vulnerable_store/app/scenario_routes.py"
    source.write_bytes(source.read_bytes() + b"\n# drift")
    with pytest.raises(NonSqlReplayBlocked):
        verify_non_sql_local_replay(
            source_root=root, scenario=scenario, working_parent=tmp_path,
        )
