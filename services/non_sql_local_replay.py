"""Isolated in-process registered XSS/traversal security and functional replay.

This exercises the exact trusted compiler patch against a temporary FastAPI
application. It is NOT a Docker replay, model-led repair, or research result.
"""
from __future__ import annotations

import tempfile
from hashlib import sha256
from pathlib import Path
from types import ModuleType
from unittest.mock import patch

from fastapi.testclient import TestClient

from dummy_apps.vulnerable_store.app import main as lab_main
from dummy_apps.vulnerable_store.app.config import StoreSettings
from schemas.red_team import HttpExchangeEvidence
from security_tests.registry import SecurityTestRegistry
from services.trusted_remediation_compiler import (
    EXPECTED_SOURCE_SHA256, SOURCE, _PATH_NEW, _PATH_OLD,
    _XSS_IMPORT_NEW, _XSS_IMPORT_OLD, _XSS_SINK_NEW, _XSS_SINK_OLD,
)

SCENARIOS = {
    "xss": ("xss-reflection-001", "/scenarios/xss/search", (
        (_XSS_IMPORT_OLD, _XSS_IMPORT_NEW),
        (_XSS_SINK_OLD, _XSS_SINK_NEW),
    )),
    "traversal": (
        "path-traversal-private-file-001", "/scenarios/path-traversal/read",
        ((_PATH_OLD, _PATH_NEW),),
    ),
}


class NonSqlReplayBlocked(RuntimeError):
    """Only the hash-pinned local synthetic source/patch may be replayed."""


def verify_non_sql_local_replay(
    *, source_root: Path, scenario: str, working_parent: Path,
) -> dict:
    """Run the actual registered test against a temporary patched app instance."""
    try:
        if scenario not in SCENARIOS:
            raise NonSqlReplayBlocked("Unregistered non-SQL scenario")
        root = Path(source_root)
        parent = Path(working_parent)
        if (root.is_symlink() or not root.is_dir()
                or parent.is_symlink() or not parent.is_dir()
                or root.resolve() == parent.resolve()
                or root.resolve() in parent.resolve().parents):
            raise NonSqlReplayBlocked("Replay must use a separate existing temporary root")
        source = root / SOURCE
        if source.is_symlink() or not source.is_file():
            raise NonSqlReplayBlocked("Original source must be regular")
        original = source.read_bytes()
        if sha256(original).hexdigest() != EXPECTED_SOURCE_SHA256:
            raise NonSqlReplayBlocked("Original deliberately vulnerable baseline changed")
        text = original.decode("utf-8")
        test_id, url, edits = SCENARIOS[scenario]
        for before, after in edits:
            if text.count(before) != 1 or before == after:
                raise NonSqlReplayBlocked("Trusted remediation source anchor changed")
            text = text.replace(before, after)
        patched = text.encode("utf-8")
        compile(patched, "<verified non-SQL temporary patched source>", "exec")
        module = ModuleType("dummy_apps.vulnerable_store.app._registered_non_sql_patch")
        module.__package__ = "dummy_apps.vulnerable_store.app"
        exec(
            compile(patched, "<verified non-SQL temporary patched source>", "exec"),
            module.__dict__,
        )
        test = SecurityTestRegistry.default().get(test_id)
        steps = test.build_steps()
        if (len(steps) != 2
                or any(step.endpoint_id != steps[0].endpoint_id
                       or getattr(step.method, "value", None) != "GET"
                       or step.json_body is not None for step in steps)):
            raise NonSqlReplayBlocked("Registered GET steps no longer match")
        with tempfile.TemporaryDirectory(
            prefix="mars-nonsql-inprocess-", dir=parent,
        ) as temporary:
            runtime = Path(temporary)
            settings = StoreSettings(
                database_url=f"sqlite:///{runtime / 'store.db'}",
                seed_files_dir=runtime / "seeds",
                scenario_files_dir=runtime / "scenarios",
            )
            with patch.object(lab_main, "build_scenario_router", module.build_scenario_router):
                app = lab_main.create_app(settings, reset_on_start=True)
            exchanges = []
            with TestClient(app) as client:
                for index, step in enumerate(steps):
                    response = client.get(url, params=dict(step.query_params))
                    exchanges.append(HttpExchangeEvidence(
                        exchange_id=f"local-replay-{index}",
                        request_id=f"local-replay-{index}", step_id=step.step_id,
                        endpoint_id=step.endpoint_id, method="GET",
                        status_code=response.status_code,
                        body_excerpt=response.text[:2000], duration_ms=0,
                    ))
                health = client.get("/health")
                if scenario == "xss":
                    functional = {
                        "normal_search_works": (
                            exchanges[0].status_code == 200
                            and "Search term: notebook" in exchanges[0].body_excerpt
                        ),
                        "script_marker_rendered_as_text": (
                            exchanges[1].status_code == 200
                            and "&lt;script&gt;" in exchanges[1].body_excerpt
                            and "<script>" not in exchanges[1].body_excerpt
                        ),
                    }
                else:
                    functional = {
                        "public_file_still_readable": (
                            exchanges[0].status_code == 200
                            and "Public scenario guide" in exchanges[0].body_excerpt
                        ),
                        "private_file_forbidden": (
                            exchanges[1].status_code == 403
                            and "FYP_SCENARIO_SECRET=" not in exchanges[1].body_excerpt
                        ),
                    }
                functional["health_responds"] = health.status_code == 200
            exploits = test.evaluate(tuple(exchanges))
            passed = not exploits and all(functional.values())
            return {
                "status": "passed" if passed else "failed",
                "scenario": scenario, "registered_test_id": test_id,
                "registered_steps_executed": len(exchanges),
                "registered_exploit_evidence": [x.evidence_id for x in exploits],
                "functional_checks": functional,
                "source_sha256": sha256(original).hexdigest(),
                "patched_source_sha256": sha256(patched).hexdigest(),
                "replay_mode": "in_process_registered_test",
                "patch_origin": "trusted_deterministic_builder",
                "model_localization_used": False,
                "docker_replayed": False, "final_research_qualified": False,
            }
    except NonSqlReplayBlocked:
        raise
    except (OSError, ValueError, SyntaxError, KeyError, TypeError) as exc:
        raise NonSqlReplayBlocked("Trusted in-process replay preparation failed") from exc
