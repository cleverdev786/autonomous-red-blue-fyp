"""Build and independently verify v2 MULTI-FUNCTION candidate source holdout.

Separate immutable bundle: v1 source-family holdout is never modified.
Three distinct registered themes, each with TWO realistic SAFE decoy routes and
ONE vulnerable observed route. No Q6, Docker, external sockets, or live registry.
This is a DEVELOPMENT CANDIDATE, not independently approved research admission.
"""
from __future__ import annotations

import argparse
import ast
import json
import tempfile
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

from fastapi.testclient import TestClient

from schemas.rq2_dataset import RQ2ClassificationDecision
from scripts.prepare_source_family_holdout import (
    CLASSIFIER_SYSTEM_PROMPT,
    FAMILIES,
    MAX_SOURCE_BYTES,
    REPO,
    SourceFamily,
    SourceFamilyBlocked,
    _schema_sha,
    _seal_json,
    _seal_source,
    _training_index,
    canonical,
    observed_exploit,
    read_strict,
    sha,
    source_location,
)
from scripts.prepare_source_family_holdout import (
    RECIPES as V1_RECIPES,
)
from services.compact_source_selection import CompactSourceSelection

V1 = Path("/home/zain/fyp-provenance/source-family-holdout-v1")
V1_MANIFEST_SHA = "5e8699bbdb46b941716a509278184de6320b68c4f3643af25aad9c0f56dfb796"
V1_PROTOCOL_SHA = "fbfd32007d3c2ae64a4b8124efbb91f5293589dd197b7dcfc071c99b323c9905"
_FAMILY_CLASS = {
    "spectrometry": "sql_injection",
    "weatherbeacon": "xss",
    "magnetometry": "path_traversal",
}

SQL_SAFE_DECOYS = '''
    @app.get("/spectra/lookup")
    def lookup_public_beam(sample_code: str):
        statement = (
            "SELECT intensity FROM beam_log "
            "WHERE code = ? AND visibility = 'public' LIMIT 1"
        )
        with sqlite3.connect(database) as conn:
            item = conn.execute(statement, (sample_code,)).fetchone()
        if item is None:
            return JSONResponse({"intensity": None}, status_code=404)
        return {"intensity": item[0]}

    @app.get("/spectra/calibration")
    def calibration_beam(sample_code: str):
        statement = "SELECT COUNT(*) FROM beam_log WHERE code = ? AND visibility = 'public'"
        with sqlite3.connect(database) as conn:
            count = conn.execute(statement, (sample_code,)).fetchone()[0]
        return {"public_count": count}

'''

XSS_SAFE_DECOYS = '''
    @app.get("/beacon/preview", response_class=HTMLResponse)
    def preview_caption(note: str) -> str:
        safe = escape(note, quote=True)
        return '<main class="preview"><output data-note="' + safe + '">' + safe + "</output></main>"

    @app.get("/beacon/ticker", response_class=HTMLResponse)
    def ticker_caption(note: str) -> str:
        safe = escape(note, quote=True)
        return '<section class="ticker"><span title="' + safe + '">' + safe + "</span></section>"

'''

PATH_SAFE_DECOYS = '''
    @app.get("/magnet/public")
    def read_public_coil(file_key: str):
        record = (shared / file_key).resolve()
        if not record.is_relative_to(shared.resolve()):
            raise HTTPException(status_code=403, detail="outside shared coil space")
        if not record.is_file():
            raise HTTPException(status_code=404, detail="missing public coil file")
        return PlainTextResponse(record.read_text(encoding="utf-8"))

    @app.get("/magnet/metadata")
    def coil_metadata(file_key: str):
        record = (shared / file_key).resolve()
        if not record.is_relative_to(shared.resolve()):
            raise HTTPException(status_code=403, detail="outside shared metadata")
        if not record.is_file():
            raise HTTPException(status_code=404, detail="missing public metadata")
        return {"bytes": len(record.read_bytes()), "public": True}

'''

_V1_BY_FAMILY = {r.name: r for r in V1_RECIPES}


def _derive_source(name: str) -> str:
    base = _V1_BY_FAMILY[name].source
    if name == "spectrometry":
        anchor = '    @app.get("/spectra/read")'
        decoys = SQL_SAFE_DECOYS
    elif name == "weatherbeacon":
        base = base.replace("from pathlib import Path", "from html import escape\nfrom pathlib import Path", 1)
        anchor = '    @app.get("/beacon/caption", response_class=HTMLResponse)'
        decoys = XSS_SAFE_DECOYS
    elif name == "magnetometry":
        anchor = '    @app.get("/magnet/record")'
        decoys = PATH_SAFE_DECOYS
    else:
        raise SourceFamilyBlocked("unregistered v2 source family")
    if base.count(anchor) != 1:
        raise SourceFamilyBlocked("v2 injection anchor missing or ambiguous")
    if name == "spectrometry":
        # observed sink THIRD, after two safe SQL-using route functions
        return base.replace(anchor, decoys + anchor, 1)
    if name == "weatherbeacon":
        # observed HTML sink FIRST, followed by two safe HTML route functions
        end = "    return app"
        if base.count(end) != 1:
            raise SourceFamilyBlocked("v2 weather safe-route insertion ambiguous")
        return base.replace(end, decoys + end, 1)
    # observed file sink MIDDLE, between two working safe filesystem routes
    split = '    @app.get("/magnet/metadata")'
    if decoys.count(split) != 1 or base.count("    return app") != 1:
        raise SourceFamilyBlocked("v2 file decoy block ambiguity")
    first, last = decoys.split(split, 1)
    with_first = base.replace(anchor, first + anchor, 1)
    return with_first.replace("    return app", split + last + "    return app", 1)


def _v2_recipe(v1: SourceFamily) -> SourceFamily:
    if v1.name == "spectrometry":
        attacks = (
            "' OR 7=7 -- ",
            "' OR 'orbit'='orbit' -- ",
            "' OR code='sealed-0' OR 'a'='a' -- ",
        )
        benign = ("open-1 OR 7=7", "neutral-beam-91", "open-1 ")
        old_new = v1.old_new
    elif v1.name == "weatherbeacon":
        attacks = (
            '"><svg onload=beaconLocal91()>',
            '"><img src=x onerror=beaconLocal92()>',
            '"><script>beaconLocal93()</script>',
        )
        benign = ("reading < 10", "quoted forecast 9/11", "calm evening bulletin")
        old_new = (v1.old_new[1],)
    else:
        attacks = (
            "../sealed//private-coil.txt",
            "../sealed/../sealed/private-coil.txt",
            "../sealed/././private-coil.txt",
        )
        benign = ("././readme.txt", ".//readme.txt", "missing-v2-readout.txt")
        old_new = v1.old_new
    return replace(
        v1, source=_derive_source(v1.name),
        old_new=old_new, attacks=attacks, benign=benign,
    )


RECIPES = tuple(_v2_recipe(x) for x in V1_RECIPES)
REGISTRY = {r.name: r for r in RECIPES}
DECOY_PATHS = {
    "spectrometry": ("/spectra/lookup", "/spectra/calibration"),
    "weatherbeacon": ("/beacon/preview", "/beacon/ticker"),
    "magnetometry": ("/magnet/public", "/magnet/metadata"),
}
DECOY_FUNCTIONS = {
    "spectrometry": ("lookup_public_beam", "calibration_beam"),
    "weatherbeacon": ("preview_caption", "ticker_caption"),
    "magnetometry": ("read_public_coil", "coil_metadata"),
}
EXPECTED_VULNERABLE_ORDINAL = {
    "spectrometry": 3,
    "weatherbeacon": 1,
    "magnetometry": 2,
}
SOURCE_PROMPT_V2 = (
    "Given the observed HTTP exchanges and a numbered source view containing "
    "THREE competing route functions (two can be safe), identify the function "
    "whose executable behavior explains the observed exploit and the exact "
    "sink line within that function. Use only the visible function names and "
    "line numbers. Return exactly function_or_route, sink_line, root_cause, "
    "confidence. Do not propose patches, payloads or commands. Do not assume "
    "that the first or last candidate is vulnerable."
)

PROTOCOL = {
    "schema": "multi-function-source-family-development-protocol-v2",
    "candidate_only": True,
    "research_final_admission": False,
    "registered_executor_dispatch_authorized": False,
    "new_model_calls_performed_in_preparation": 0,
    "derived_from_v1": True,
    "v1_model_exposure": "none reported or authorized",
    "source_families": list(FAMILIES),
    "independent_external_review_required": True,
    "source_functions_visible_per_family": 3,
    "safe_operational_decoys_per_family": 2,
    "vulnerable_function_position_per_family": EXPECTED_VULNERABLE_ORDINAL,
    "all_model_inputs_new_vs_v1": True,
    "evaluation_cases": 18,
    "positive_cases": 9,
    "benign_controls": 9,
    "classification_accuracy_min": 16,
    "classification_positive_correct_min": 8,
    "classification_benign_correct_min": 8,
    "classification_each_vulnerability_correct_min": 2,
    "function_and_sink_joint_correct_min": 8,
    "function_and_sink_each_vulnerability_min": 2,
    "unknown_benign_is_not_true_negative": True,
    "no_patch_based_on_truth_or_unverified_red": True,
    "no_retries": True,
    "classifier_system_prompt": CLASSIFIER_SYSTEM_PROMPT,
    "source_system_prompt": SOURCE_PROMPT_V2,
    "classification_schema_sha256": _schema_sha(RQ2ClassificationDecision),
    "source_schema_sha256": _schema_sha(CompactSourceSelection),
    "model_visible_source_field_names": [
        "route", "source_sha256", "numbered_candidate_functions",
        "candidate_function_names",
    ],
    "model_visible_classification_field_names": ["route", "observations"],
    "generation": {
        "model": "qwen25coder3b-specialist-Q6_K-b10964.gguf",
        "model_sha256": "07bcec4047a457766a92c9737fd0ac8045e328ccf703baf43768c2ea962bf7a9",
        "temperature": 0,
        "top_p": 0.8,
        "top_k": 20,
        "ctx": 1536,
        "max_output_tokens": 160,
        "seed": None,
        "max_attempts_per_role": 1,
    },
    "limitations": [
        "Derived from the same three synthetic themes as v1, not three new third-party codebases.",
        "All training overlap checks are literal or registry-based, not independent semantic provenance.",
        "Observed route is supplied as legitimate task context, not evaluator ground truth.",
        "Must not treat v2 candidate registration as authority to run the live Docker executor.",
        "Human independent approval and registered run admission required before model exposure.",
    ],
}


def allowed_functions(recipe: SourceFamily) -> tuple[ast.FunctionDef, ...]:
    tree = ast.parse(recipe.source)
    requested = frozenset((*DECOY_FUNCTIONS[recipe.name], recipe.function))
    nodes = [
        node for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name in requested
    ]
    if (
        len(nodes) != 3
        or {n.name for n in nodes} != requested
        or len({n.name for n in nodes}) != 3
        or not all(n.decorator_list for n in nodes)
    ):
        raise SourceFamilyBlocked("multi-function candidate AST topology rejected")
    return tuple(sorted(nodes, key=lambda n: n.lineno))


def source_view(recipe: SourceFamily) -> dict:
    lines = recipe.source.splitlines()
    blocks: list[str] = []
    names: list[str] = []
    for fn in allowed_functions(recipe):
        start = min(d.lineno for d in fn.decorator_list)
        stop = fn.end_lineno
        blocks.append("\n".join(
            f"{i:03d} {lines[i - 1]}" for i in range(start, stop + 1)
        ))
        names.append(fn.name)
    view = {
        "route": recipe.route,
        "source_sha256": sha(recipe.source.encode()),
        "numbered_candidate_functions": "\n\n".join(blocks),
        "candidate_function_names": names,
    }
    if (
        len(set(names)) != 3
        or names.index(recipe.function) + 1 != EXPECTED_VULNERABLE_ORDINAL[recipe.name]
        or source_location(recipe) not in {
            i for fn in allowed_functions(recipe)
            for i in range(fn.lineno, fn.end_lineno + 1)
        }
    ):
        raise SourceFamilyBlocked("sink/variable candidate position not valid")
    return view


def trusted_patch(*, recipe: SourceFamily, original: bytes,
                  proposed_label: str, proposed_function: str,
                  proposed_line: int) -> bytes:
    if (
        proposed_label != _FAMILY_CLASS[recipe.name]
        or proposed_function != recipe.function
        or proposed_line != source_location(recipe)
        or sha(original) != sha(recipe.source.encode())
    ):
        raise SourceFamilyBlocked("untrusted v2 classification or source/sink identity")
    text = original.decode("utf-8")
    for old, new in recipe.old_new:
        if text.count(old) != 1 or old == new:
            raise SourceFamilyBlocked("ambiguous approved v2 repair anchor")
        text = text.replace(old, new, 1)
    replacement = text.encode()
    compile(replacement, "registered-v2-" + recipe.name, "exec")
    if replacement == original:
        raise SourceFamilyBlocked("no-op trusted v2 patch")
    return replacement


def run_case(recipe: SourceFamily, *, source: bytes, payload: str,
             data_root: Path) -> tuple[dict, bool]:
    """Only execute exact pinned source or trusted deterministic preview in memory."""
    original = recipe.source.encode()
    patched = trusted_patch(
        recipe=recipe, original=original, proposed_label=_FAMILY_CLASS[recipe.name],
        proposed_function=recipe.function, proposed_line=source_location(recipe),
    )
    if source not in (original, patched) or len(source) > MAX_SOURCE_BYTES:
        raise SourceFamilyBlocked("unapproved source cannot execute")
    scope = {"__name__": "sealed_v2_" + recipe.name}
    exec(compile(source, recipe.name + ".py", "exec"), scope)  # noqa: S102
    app = scope["create_app"](data_root)
    with TestClient(app) as client:
        standard = client.get(recipe.route, params={recipe.parameter: recipe.control})
        observed = client.get(recipe.route, params={recipe.parameter: payload})
        good_value = (
            "open-1" if recipe.name == "spectrometry"
            else "ordinary weather report" if recipe.name == "weatherbeacon"
            else "readme.txt"
        )
        healthy = client.get(recipe.route, params={recipe.parameter: good_value})
        decoy_responses = [
            (client.get(path, params={recipe.parameter: good_value}),
             client.get(path, params={recipe.parameter: payload}))
            for path in DECOY_PATHS[recipe.name]
        ]
    if recipe.name == "spectrometry":
        if healthy.status_code != 200 or healthy.json().get("intensity") != "range-normal":
            raise SourceFamilyBlocked("valid spectrometry lookup failed")
    elif recipe.name == "weatherbeacon":
        if healthy.status_code != 200 or good_value not in healthy.text:
            raise SourceFamilyBlocked("valid weather caption failed")
    elif healthy.status_code != 200 or "Public coil readout." not in healthy.text:
        raise SourceFamilyBlocked("valid public magnet record failed")
    for benign, attack in decoy_responses:
        if benign.status_code != 200:
            raise SourceFamilyBlocked("legitimate decoy route not functional")
        if observed_exploit(recipe, attack):
            raise SourceFamilyBlocked("decoy route vulnerable for attacker payload")
    observation = {
        "route": recipe.route,
        "observations": [
            {"method": "GET", "parameters": {recipe.parameter: recipe.control},
             "status_code": standard.status_code,
             "response_excerpt": standard.text[:380]},
            {"method": "GET", "parameters": {recipe.parameter: payload},
             "status_code": observed.status_code,
             "response_excerpt": observed.text[:380]},
        ],
    }
    return observation, observed_exploit(recipe, observed)


def contamination() -> dict:
    # Validate full pre-existing v1 evidence and training index without mutation.
    if (
        sha(read_strict(V1 / "manifest.json")) != V1_MANIFEST_SHA
        or sha(read_strict(V1 / "frozen-protocol.json")) != V1_PROTOCOL_SHA
    ):
        raise SourceFamilyBlocked("previous v1 freeze identity drift")
    prior = json.loads(read_strict(V1 / "manifest.json"))
    if prior["case_count"] != 18:
        raise SourceFamilyBlocked("v1 manifest cardinality drift")
    report = _training_index()
    corpus_files = [Path(p) for p in report["corpora"]]
    source_old = {sha(read_strict(V1 / "source" / (name + ".py"))) for name in FAMILIES}
    previous_cases = {c["case_id"]: c for c in prior["cases"]}
    if len(previous_cases) != 18:
        raise SourceFamilyBlocked("v1 case registry is not complete")
    old_inputs: set[str] = set()
    for i in range(1, 19):
        case_id = f"sfh-v1-{i:03d}"
        raw = read_strict(V1 / "model-inputs" / (case_id + ".json"))
        digest = sha(raw)
        if digest != previous_cases[case_id]["model_input_sha256"]:
            raise SourceFamilyBlocked("v1 archived input does not match pinned manifest")
        old_inputs.add(digest)
    if len(old_inputs) != 18:
        raise SourceFamilyBlocked("v1 input archive duplicates")
    payloads_v1: set[str] = set()
    for i in range(1, 19):
        obj = json.loads(read_strict(V1 / "model-inputs" / (f"sfh-v1-{i:03d}.json")))
        payloads_v1.update(obj["observations"][1]["parameters"].values())
    literal_corpora = [read_strict(f, 8_000_000) for f in corpus_files]
    for recipe in RECIPES:
        code = recipe.source.encode()
        if sha(code) in source_old:
            raise SourceFamilyBlocked("v2 reuses exact original v1 source")
        if any(code in read_strict(f, 8_000_000) for f in corpus_files):
            raise SourceFamilyBlocked("v2 exact source reused in training/dev corpus")
        for item in (*recipe.attacks, *recipe.benign):
            if item in payloads_v1:
                raise SourceFamilyBlocked("v2 request reused v1 payload string")
            if any(item.encode("utf-8") in raw for raw in literal_corpora):
                raise SourceFamilyBlocked("v2 request already present in prior training/dev corpus")
    report.update({
        "previous_v1_manifest_sha256": V1_MANIFEST_SHA,
        "previous_v1_protocol_sha256": V1_PROTOCOL_SHA,
        "v1_model_input_sha256": sorted(old_inputs),
        "v1_source_sha256": sorted(source_old),
        "v1_payload_values_sha256": sha(canonical(sorted(payloads_v1))),
        "independence_scope": "Literal-difference and training-registry check, NOT semantic independence",
    })
    return report


def _ensure_output(out: Path) -> None:
    if (
        not out.is_absolute()
        or out.exists()
        or out.is_symlink()
        or REPO == out
        or REPO in out.parents
        or V1 == out
        or V1 in out.parents
    ):
        raise SourceFamilyBlocked("v2 output must be new, absolute and outside v1/live repository")


def freeze(out: Path) -> dict:
    _ensure_output(out)
    training = contamination()
    out.mkdir(parents=True, mode=0o700)
    out.chmod(0o700)
    truth = {}
    cases = []
    sources = {}
    patches = {}
    excerpts = {}
    index = 0
    for recipe in RECIPES:
        src = recipe.source.encode()
        view = source_view(recipe)
        if len(allowed_functions(recipe)) != 3:
            raise SourceFamilyBlocked("v2 must present exactly three callable functions")
        fixed = trusted_patch(
            recipe=recipe, original=src, proposed_label=_FAMILY_CLASS[recipe.name],
            proposed_function=recipe.function, proposed_line=source_location(recipe),
        )
        _seal_source(out / "source" / (recipe.name + ".py"), src)
        _seal_source(out / "trusted-preview" / (recipe.name + ".py"), fixed)
        _seal_json(out / "source-views" / (recipe.name + ".json"), view)
        sources[recipe.name] = sha(src)
        patches[recipe.name] = sha(fixed)
        excerpts[recipe.name] = sha(canonical(view))
        for malicious, prompts in ((True, recipe.attacks), (False, recipe.benign)):
            for payload in prompts:
                index += 1
                case_id = f"sfh-v2-{index:03d}"
                with tempfile.TemporaryDirectory(prefix="sfh-v2-before-") as t:
                    observed, exploited = run_case(
                        recipe, source=src, payload=payload, data_root=Path(t),
                    )
                if exploited is not malicious:
                    raise SourceFamilyBlocked("v2 baseline truth mismatch: " + case_id)
                with tempfile.TemporaryDirectory(prefix="sfh-v2-after-") as t:
                    _, after = run_case(
                        recipe, source=fixed, payload=payload, data_root=Path(t),
                    )
                if after:
                    raise SourceFamilyBlocked("v2 trusted repair failed: " + case_id)
                input_sha = sha(canonical(observed))
                _seal_json(out / "model-inputs" / (case_id + ".json"), observed)
                truth[case_id] = {
                    "family": recipe.name,
                    "expected_classification": (
                        _FAMILY_CLASS[recipe.name] if malicious else "benign"
                    ),
                    "expected_exploit": malicious,
                    "expected_function": recipe.function if malicious else None,
                    "expected_sink_line": source_location(recipe) if malicious else None,
                    "input_sha256": input_sha,
                }
                cases.append({
                    "case_id": case_id,
                    "family_slot": recipe.name,
                    "model_input_sha256": input_sha,
                    "source_sha256": sha(src),
                    "source_view_sha256": sha(canonical(view)),
                })
    if index != 18 or len({c["model_input_sha256"] for c in cases}) != 18:
        raise SourceFamilyBlocked("v2 case uniqueness/count invalid")
    if {c["model_input_sha256"] for c in cases} & set(training["v1_model_input_sha256"]):
        raise SourceFamilyBlocked("v2 model input repeated verbatim from v1")
    _seal_json(out / "evaluator-only" / "truth.json", truth)
    _seal_json(out / "frozen-protocol.json", PROTOCOL)
    _seal_json(out / "candidate-registry.json", {
        "schema": "nonlive-multifunction-candidate-registry-v2",
        "admitted_to_live_executor": False,
        "families": [
            {"name": recipe.name, "route": recipe.route,
             "candidate_function_names": source_view(recipe)["candidate_function_names"]}
            for recipe in RECIPES
        ],
    })
    manifest = {
        "schema": "source-family-multi-function-prequalification-v2",
        "development_only": True,
        "scientifically_independent_approved": False,
        "model_calls": 0,
        "docker_runs": 0,
        "frozen_utc": datetime.now(UTC).isoformat(),
        "case_count": len(cases),
        "family_count": len(RECIPES),
        "candidate_functions_per_family": 3,
        "verified_safe_decoys_per_family": 2,
        "original_source_sha256": sources,
        "trusted_preview_sha256": patches,
        "model_source_view_sha256": excerpts,
        "frozen_protocol_sha256": sha(read_strict(out / "frozen-protocol.json")),
        "evaluator_truth_sha256": sha(read_strict(out / "evaluator-only/truth.json")),
        "candidate_registry_sha256": sha(read_strict(out / "candidate-registry.json")),
        "training_and_v1_contamination": training,
        "cases": cases,
        "builder_sha256": sha(read_strict(Path(__file__))),
        "admission": "candidate-only; requires independent review before blind Q6 test",
    }
    _seal_json(out / "manifest.json", manifest)
    return manifest


def verify(out: Path) -> dict:
    raw_manifest = read_strict(out / "manifest.json")
    manifest = json.loads(raw_manifest)
    if raw_manifest != canonical(manifest):
        raise SourceFamilyBlocked("v2 manifest is no longer canonical")
    if (
        manifest["schema"] != "source-family-multi-function-prequalification-v2"
        or manifest["model_calls"] != 0
        or manifest["docker_runs"] != 0
        or manifest["family_count"] != 3
        or manifest["case_count"] != 18
        or manifest["scientifically_independent_approved"] is not False
        or sha(read_strict(Path(__file__))) != manifest["builder_sha256"]
        or sha(read_strict(out / "frozen-protocol.json")) != manifest["frozen_protocol_sha256"]
        or json.loads(read_strict(out / "frozen-protocol.json")) != PROTOCOL
        or sha(read_strict(out / "evaluator-only/truth.json")) != manifest["evaluator_truth_sha256"]
        or sha(read_strict(out / "candidate-registry.json")) != manifest["candidate_registry_sha256"]
        or contamination() != manifest["training_and_v1_contamination"]
    ):
        raise SourceFamilyBlocked("v2 freeze manifest/protocol/inputs drift")
    truths = json.loads(read_strict(out / "evaluator-only/truth.json"))
    if set(truths) != {c["case_id"] for c in manifest["cases"]}:
        raise SourceFamilyBlocked("v2 truth/case index mismatch")
    registry_data = {
        "schema": "nonlive-multifunction-candidate-registry-v2",
        "admitted_to_live_executor": False,
        "families": [
            {"name": recipe.name, "route": recipe.route,
             "candidate_function_names": source_view(recipe)["candidate_function_names"]}
            for recipe in RECIPES
        ],
    }
    if read_strict(out / "candidate-registry.json") != canonical(registry_data):
        raise SourceFamilyBlocked("v2 candidate registry changed")
    for recipe in RECIPES:
        original = read_strict(out / "source" / (recipe.name + ".py"), MAX_SOURCE_BYTES)
        fixed = read_strict(out / "trusted-preview" / (recipe.name + ".py"), MAX_SOURCE_BYTES)
        view = read_strict(out / "source-views" / (recipe.name + ".json"))
        if (
            original != recipe.source.encode()
            or sha(original) != manifest["original_source_sha256"][recipe.name]
            or sha(fixed) != manifest["trusted_preview_sha256"][recipe.name]
            or view != canonical(source_view(recipe))
            or sha(view) != manifest["model_source_view_sha256"][recipe.name]
            or fixed != trusted_patch(
                recipe=recipe, original=original,
                proposed_label=_FAMILY_CLASS[recipe.name],
                proposed_function=recipe.function,
                proposed_line=source_location(recipe),
            )
        ):
            raise SourceFamilyBlocked("v2 trusted source/view/preview changed")
    counted = {"malicious": 0, "benign": 0, "patched_replay": 0, "safe_decoy_routes": 6}
    previous = set(manifest["training_and_v1_contamination"]["v1_model_input_sha256"])
    seen: set[str] = set()
    for row in manifest["cases"]:
        case_id = row["case_id"]
        family = row["family_slot"]
        if family not in REGISTRY:
            raise SourceFamilyBlocked("v2 unexpected family slot")
        recipe = REGISTRY[family]
        raw = read_strict(out / "model-inputs" / (case_id + ".json"))
        input_data = json.loads(raw)
        if (
            raw != canonical(input_data)
            or sha(raw) != row["model_input_sha256"]
            or row["model_input_sha256"] in previous | seen
            or row["source_sha256"] != manifest["original_source_sha256"][family]
            or row["source_view_sha256"] != manifest["model_source_view_sha256"][family]
            or any(field in input_data for field in (
                "expected_classification", "expected_exploit", "sink_line",
                "expected_function", "ground_truth",
            ))
        ):
            raise SourceFamilyBlocked("v2 model input identity or truth separation failed")
        seen.add(row["model_input_sha256"])
        truth = truths[case_id]
        if (
            truth["family"] != family
            or truth["input_sha256"] != sha(raw)
            or truth["expected_classification"] != (
                _FAMILY_CLASS[family] if truth["expected_exploit"] else "benign"
            )
        ):
            raise SourceFamilyBlocked("v2 evaluator truth metadata mismatch")
        if truth["expected_exploit"]:
            if (truth["expected_function"] != recipe.function or
                truth["expected_sink_line"] != source_location(recipe)):
                raise SourceFamilyBlocked("v2 trusted evaluator function/sink drift")
        elif truth["expected_function"] is not None or truth["expected_sink_line"] is not None:
            raise SourceFamilyBlocked("v2 benign truth contains remediation target")
        payload = input_data["observations"][1]["parameters"][recipe.parameter]
        with tempfile.TemporaryDirectory(prefix="sfh-v2-verification-") as t:
            observed, exploited = run_case(
                recipe, source=recipe.source.encode(),
                payload=payload, data_root=Path(t),
            )
        if canonical(observed) != raw or exploited != truth["expected_exploit"]:
            raise SourceFamilyBlocked("v2 baseline replay differs from freeze")
        with tempfile.TemporaryDirectory(prefix="sfh-v2-repaired-") as t:
            _, after = run_case(
                recipe, source=read_strict(
                    out / "trusted-preview" / (recipe.name + ".py"), MAX_SOURCE_BYTES,
                ),
                payload=payload, data_root=Path(t),
            )
        if after:
            raise SourceFamilyBlocked("v2 trusted patch regression")
        if exploited:
            counted["malicious"] += 1
            counted["patched_replay"] += 1
        else:
            counted["benign"] += 1
    if counted != {
        "malicious": 9, "benign": 9, "patched_replay": 9,
        "safe_decoy_routes": 6,
    }:
        raise SourceFamilyBlocked("v2 finished with incorrect case counts")
    return counted


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--output-root", required=True, type=Path)
    ap.add_argument("--verify-only", action="store_true")
    args = ap.parse_args()
    if args.verify_only:
        print("V2_READ_ONLY_VERIFY_PASS", json.dumps(verify(args.output_root), sort_keys=True))
    else:
        result = freeze(args.output_root)
        print("V2_CANDIDATE_FROZEN", args.output_root, "cases", result["case_count"],
              "model_calls", result["model_calls"])
        print("V2_INDEPENDENT_REPLAY", json.dumps(verify(args.output_root), sort_keys=True))
        print("RESEARCH_ADMISSION_FALSE; NO_Q6; NO_DOCKER")


if __name__ == "__main__":
    main()
