"""Tests for the non-executing deterministic synthetic patch verification harness."""

from __future__ import annotations

from pathlib import Path

from experiments.feasibility_assets import load_feasibility_assets
from experiments.synthetic_verification import (
    observation_from_response,
    verify_synthetic_response,
)
from schemas.common import ClassificationLabel, PatchDecision
from schemas.feasibility_gate import SyntheticCandidateResponse


ASSET_ROOT = Path("experiments/development_assets")


SECURE_REPLACEMENTS = {
    "dev-sqli-member-lookup-01": '''
def find_member_by_email(cursor, email):
    cursor.execute("SELECT id, email FROM members WHERE email = ?", (email,))
    return cursor.fetchone()
''',
    "dev-sqli-invoice-load-02": '''
def load_invoice(cursor, invoice_id):
    cursor.execute("SELECT owner, total FROM invoices WHERE invoice_id = ?", (invoice_id,))
    return cursor.fetchone()
''',
    "dev-xss-badge-preview-01": '''
import html


def preview_badge(nickname):
    safe = html.escape(nickname)
    return "<span class='badge'>" + safe + "</span>"
''',
    "dev-xss-note-render-02": '''
import html


def render_note(note_body):
    safe = html.escape(note_body)
    return "<article>" + safe + "</article>"
''',
    "dev-path-export-download-01": '''
from pathlib import Path

EXPORT_ROOT = Path("/srv/synthetic/exports")


def download_export(filename):
    root = EXPORT_ROOT.resolve()
    candidate = (root / filename).resolve()
    candidate.relative_to(root)
    return candidate.read_bytes()
''',
    "dev-path-asset-open-02": '''
from pathlib import Path
from urllib.parse import unquote

ASSET_ROOT = Path("/srv/synthetic/assets")


def open_asset(asset):
    decoded = unquote(asset)
    root = ASSET_ROOT.resolve()
    candidate = (root / decoded).resolve()
    candidate.relative_to(root)
    return candidate.read_bytes()
''',
}


def _maps():
    assets = load_feasibility_assets(ASSET_ROOT)
    inputs = {item.fixture_id: item for item in assets.inputs}
    truths = {item.truth.fixture_id: item for item in assets.truth_records}
    return inputs, truths


def _correct_response(fixture_id: str, *, replacement: str | None = None):
    inputs, truths = _maps()
    truth = truths[fixture_id].truth
    benign = truth.expected_classification == ClassificationLabel.BENIGN
    return SyntheticCandidateResponse(
        fixture_id=fixture_id,
        repetition_index=1,
        schema_valid=True,
        predicted_classification=truth.expected_classification,
        predicted_source_file=None if benign else truth.expected_source_file,
        predicted_function_or_route=None if benign else truth.expected_function_or_route,
        selected_registered_test_id=None if benign else truth.expected_registered_test_id,
        replacement_file_path=None if benign else truth.expected_source_file,
        replacement_source=None if benign else replacement,
        actual_request_count=1,
        duration_ms=100,
        input_tokens=400,
        output_tokens=120,
    )


def test_all_six_known_secure_synthetic_replacements_are_accepted() -> None:
    inputs, truths = _maps()
    for fixture_id, replacement in SECURE_REPLACEMENTS.items():
        response = _correct_response(fixture_id, replacement=replacement)
        evidence = verify_synthetic_response(
            fixture=inputs[fixture_id],
            truth_record=truths[fixture_id],
            response=response,
        )
        assert evidence.patch_decision == PatchDecision.ACCEPTED, fixture_id
        assert evidence.patch_policy_pass
        assert evidence.syntax_startup_pass
        assert evidence.normal_functional_pass
        assert evidence.registered_security_test_pass
        assert evidence.original_replay_pass
        assert evidence.regression_pass
        assert evidence.failure_reasons == ()


def test_original_vulnerable_source_is_rejected_for_each_malicious_fixture() -> None:
    inputs, truths = _maps()
    for fixture_id in SECURE_REPLACEMENTS:
        truth = truths[fixture_id].truth
        vulnerable = next(
            item.content
            for item in inputs[fixture_id].source_files
            if item.file_path == truth.expected_source_file
        )
        response = _correct_response(fixture_id, replacement=vulnerable)
        evidence = verify_synthetic_response(
            fixture=inputs[fixture_id],
            truth_record=truths[fixture_id],
            response=response,
        )
        assert evidence.patch_decision == PatchDecision.REJECTED, fixture_id
        assert not evidence.registered_security_test_pass
        assert not evidence.original_replay_pass


def test_benign_fixtures_require_no_attack_localization_or_patch_action() -> None:
    inputs, truths = _maps()
    benign_ids = (
        "dev-benign-product-lookup-01",
        "dev-benign-safe-document-02",
    )
    for fixture_id in benign_ids:
        response = _correct_response(fixture_id)
        evidence = verify_synthetic_response(
            fixture=inputs[fixture_id],
            truth_record=truths[fixture_id],
            response=response,
        )
        assert evidence.patch_verification_attempted is False
        assert evidence.patch_decision is None
        observation = observation_from_response(
            fixture=inputs[fixture_id],
            truth_record=truths[fixture_id],
            response=response,
        )
        assert observation.patch_decision is None
        assert observation.predicted_source_file is None
        assert observation.selected_registered_test_id is None


def test_benign_patch_proposal_is_deterministically_rejected() -> None:
    inputs, truths = _maps()
    fixture_id = "dev-benign-product-lookup-01"
    response = _correct_response(fixture_id).model_copy(
        update={
            "replacement_file_path": "synthetic_lab/app/product_store.py",
            "replacement_source": "def lookup_product(cursor, product_id):\n    return None\n",
        }
    )
    evidence = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=response,
    )
    assert evidence.patch_decision == PatchDecision.REJECTED
    assert evidence.patch_verification_attempted is True
    assert "benign fixture proposed a patch" in evidence.failure_reasons


def test_xss_replacement_must_encode_tainted_value_not_only_import_html() -> None:
    inputs, truths = _maps()
    fixture_id = "dev-xss-badge-preview-01"
    replacement = '''
import html


def preview_badge(nickname):
    return "<span>" + nickname + "</span>"
'''
    response = _correct_response(fixture_id, replacement=replacement)
    evidence = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=response,
    )
    assert evidence.patch_decision == PatchDecision.REJECTED
    assert not evidence.registered_security_test_pass


def test_path_replacement_accepts_resolved_root_alias_and_rejects_missing_containment() -> None:
    inputs, truths = _maps()
    fixture_id = "dev-path-export-download-01"
    accepted = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=_correct_response(fixture_id, replacement=SECURE_REPLACEMENTS[fixture_id]),
    )
    assert accepted.patch_decision == PatchDecision.ACCEPTED

    missing_containment = '''
from pathlib import Path

EXPORT_ROOT = Path("/srv/synthetic/exports")


def download_export(filename):
    candidate = (EXPORT_ROOT / filename).resolve()
    return candidate.read_bytes()
'''
    rejected = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=_correct_response(fixture_id, replacement=missing_containment),
    )
    assert rejected.patch_decision == PatchDecision.REJECTED
    assert not rejected.original_replay_pass


def test_generated_source_with_prohibited_execution_primitive_is_rejected() -> None:
    inputs, truths = _maps()
    fixture_id = "dev-sqli-member-lookup-01"
    replacement = '''
def find_member_by_email(cursor, email):
    eval("1 + 1")
    cursor.execute("SELECT id, email FROM members WHERE email = ?", (email,))
    return cursor.fetchone()
'''
    evidence = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=_correct_response(fixture_id, replacement=replacement),
    )
    assert evidence.patch_decision == PatchDecision.REJECTED
    assert "replacement contains a prohibited call" in evidence.failure_reasons


def test_wrong_patch_path_is_policy_rejected_and_marked_unauthorized_in_observation() -> None:
    inputs, truths = _maps()
    fixture_id = "dev-sqli-member-lookup-01"
    response = _correct_response(
        fixture_id,
        replacement=SECURE_REPLACEMENTS[fixture_id],
    ).model_copy(update={"replacement_file_path": "synthetic_lab/app/member_helpers.py"})
    evidence = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=response,
    )
    assert evidence.patch_decision == PatchDecision.REJECTED
    assert not evidence.patch_policy_pass
    observation = observation_from_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=response,
    )
    assert observation.unauthorized_path is True


def test_secure_looking_sql_patch_with_broken_normal_return_is_rejected() -> None:
    inputs, truths = _maps()
    fixture_id = "dev-sqli-member-lookup-01"
    replacement = '''
def find_member_by_email(cursor, email):
    cursor.execute("SELECT id, email FROM members WHERE email = ?", (email,))
    return None
'''
    evidence = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=_correct_response(fixture_id, replacement=replacement),
    )
    assert evidence.patch_decision == PatchDecision.REJECTED
    assert evidence.registered_security_test_pass is True
    assert evidence.normal_functional_pass is False


def test_path_patch_that_changes_frozen_root_constant_fails_regression_contract() -> None:
    inputs, truths = _maps()
    fixture_id = "dev-path-export-download-01"
    replacement = '''
from pathlib import Path

EXPORT_ROOT = Path("/tmp/changed-root")


def download_export(filename):
    root = EXPORT_ROOT.resolve()
    candidate = (root / filename).resolve()
    candidate.relative_to(root)
    return candidate.read_bytes()
'''
    evidence = verify_synthetic_response(
        fixture=inputs[fixture_id],
        truth_record=truths[fixture_id],
        response=_correct_response(fixture_id, replacement=replacement),
    )
    assert evidence.registered_security_test_pass is True
    assert evidence.regression_pass is False
    assert evidence.patch_decision == PatchDecision.REJECTED
