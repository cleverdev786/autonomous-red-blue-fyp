"""Prepare and audit a SEALED DEVELOPMENT candidate holdout of unseen source families.

Only FastAPI TestClient in-process, synthetic local paths and files, no model calls,
Docker, Git changes, or final research admission. Never overwrite an existing freeze.
Training-family distinction and mechanical duplication checks are NOT proof of
semantic independence; human/source-registry review is a later admission condition.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from pathlib import Path

from fastapi.testclient import TestClient

from schemas.rq2_dataset import RQ2ClassificationDecision
from services.compact_source_selection import CompactSourceSelection

REPO = Path(__file__).resolve().parents[1]
TRAIN = Path("/home/zain/Documents/RED FYP/ft-pilot-export/ft-pilot-refresh-v2")
PRIOR_INPUTS = REPO / "experiments/datasets/rq2-classification-v1/inputs.jsonl"
FAMILIES = ("spectrometry", "weatherbeacon", "magnetometry")

SPECTROMETRY = '''from __future__ import annotations

import sqlite3
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import JSONResponse


def create_app(data_root: Path) -> FastAPI:
    database = data_root / "sky-readings.db"
    with sqlite3.connect(database) as conn:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS beam_log (code TEXT, visibility TEXT, intensity TEXT)"
        )
        conn.execute("DELETE FROM beam_log")
        conn.executemany(
            "INSERT INTO beam_log VALUES (?, ?, ?)",
            [
                ("sealed-0", "restricted", "SPECTRAL_PRIVATE_SYNTHETIC_ONLY"),
                ("open-1", "public", "range-normal"),
            ],
        )

    app = FastAPI()

    @app.get("/spectra/read")
    def read_beam(sample_code: str):
        statement = (
            "SELECT intensity FROM beam_log "
            f"WHERE code = '{sample_code}' AND visibility = 'public' LIMIT 1"
        )
        with sqlite3.connect(database) as conn:
            item = conn.execute(statement).fetchone()
        if item is None:
            return JSONResponse({"intensity": None}, status_code=404)
        return {"intensity": item[0]}

    return app
'''

WEATHERBEACON = '''from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import HTMLResponse


def create_app(_data_root: Path) -> FastAPI:
    app = FastAPI()

    @app.get("/beacon/caption", response_class=HTMLResponse)
    def caption_view(note: str) -> str:
        return (
            '<main class="beacon">'
            f'<output data-note="{note}">{note}</output>'
            "</main>"
        )

    return app
'''

MAGNETOMETRY = '''from __future__ import annotations

from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse


def create_app(data_root: Path) -> FastAPI:
    shared = data_root / "shared"
    secure = data_root / "sealed"
    shared.mkdir(parents=True, exist_ok=True)
    secure.mkdir(parents=True, exist_ok=True)
    (shared / "readme.txt").write_text("Public coil readout.\\n", encoding="utf-8")
    (secure / "private-coil.txt").write_text(
        "COIL_PRIVATE_SYNTHETIC_ONLY\\n", encoding="utf-8"
    )
    app = FastAPI()

    @app.get("/magnet/record")
    def record_view(file_key: str):
        record = (shared / file_key).resolve()
        if not record.is_relative_to(data_root.resolve()):
            raise HTTPException(status_code=403, detail="outside monitored root")
        if not record.is_file():
            raise HTTPException(status_code=404, detail="missing")
        return PlainTextResponse(record.read_text(encoding="utf-8"))

    return app
'''

@dataclass(frozen=True)
class SourceFamily:
    name: str
    route: str
    parameter: str
    function: str
    source: str
    sink_anchor: str
    old_new: tuple[tuple[str, str], ...]
    control: str
    attacks: tuple[str, ...]
    benign: tuple[str, ...]
    private_marker: str = ""


SPE = SourceFamily(
    "spectrometry", "/spectra/read", "sample_code", "read_beam", SPECTROMETRY,
    "item = conn.execute(statement).fetchone()",
    (
        (
            'f"WHERE code = \'{sample_code}\' AND visibility = \'public\' LIMIT 1"',
            '"WHERE code = ? AND visibility = \'public\' LIMIT 1"',
        ),
        (
            "conn.execute(statement).fetchone()",
            "conn.execute(statement, (sample_code,)).fetchone()",
        ),
    ),
    "not-listed",
    ("' OR 1=1 -- ", "' OR 'z'='z' -- ", "' OR code='sealed-0' -- "),
    ("public OR 1=1", "open-1", "not-listed"),
    "SPECTRAL_PRIVATE_SYNTHETIC_ONLY",
)
BEACON = SourceFamily(
    "weatherbeacon", "/beacon/caption", "note", "caption_view", WEATHERBEACON,
    'f\'<output data-note="{note}">{note}</output>\'',
    (
        ("from pathlib import Path", "from html import escape\nfrom pathlib import Path"),
        (
            ('        return (\n            \'<main class="beacon">\'\n'
            '            f\'<output data-note="{note}">{note}</output>\'\n'
            '            "</main>"\n        )'),
            ('        safe_note = escape(note, quote=True)\n'
            '        return (\n            \'<main class="beacon">\'\n'
            '            f\'<output data-note="{safe_note}">{safe_note}</output>\'\n'
            '            "</main>"\n        )'),
        ),
    ),
    "regular beacon report",
    ('"><svg onload=probeSpectra1()>', '"><img src=x onerror=probeSpectra2()>',
     '"><script>probeSpectra3()</script>'),
    ("status < normal", "quoted reading 4/6", "telemetry note"),
)
MAG = SourceFamily(
    "magnetometry", "/magnet/record", "file_key", "record_view", MAGNETOMETRY,
    "if not record.is_relative_to(data_root.resolve()):",
    ((
        "if not record.is_relative_to(data_root.resolve()):",
        "if not record.is_relative_to(shared.resolve()):",
    ),),
    "missing-guide.txt",
    ("../sealed/private-coil.txt", "../shared/../sealed/private-coil.txt",
     "../sealed/./private-coil.txt"),
    ("./readme.txt", "readme.txt", "notes-absent.txt"),
    "COIL_PRIVATE_SYNTHETIC_ONLY",
)
RECIPES = (SPE, BEACON, MAG)
RECIPE_BY_NAME = {i.name: i for i in RECIPES}
MAX_SOURCE_BYTES = 20_000

# Exact prompt instructions and structured output schemas belong to the freeze.
CLASSIFIER_SYSTEM_PROMPT = (
    "Given two HTTP observations of the SAME safe synthetic local application "
    "route, classify the vulnerability based on observed request and response "
    "behavior. Only labels sql_injection, xss, path_traversal, benign, unknown. "
    "If both observations show normal or blocked behavior, return benign; "
    "do not infer a vulnerability merely from the endpoint name or text that "
    "looks like an attack. Return exactly classification, confidence, reason. "
    "Never execute tools or propose commands."
)
SOURCE_SYSTEM_PROMPT = (
    "Identify the vulnerable function and exact sink line in the numbered "
    "fixed synthetic source excerpt. Choose only a line shown in the excerpt. "
    "Return exactly function_or_route, sink_line, root_cause, confidence. "
    "No generated code, shell commands, patch text or unlisted keys."
)


def _schema_sha(model: type) -> str:
    raw = json.dumps(
        model.model_json_schema(), sort_keys=True,
        separators=(",", ":"), ensure_ascii=False,
    ).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


# Frozen acceptance requirements are set here BEFORE any model exposure.
PROTOCOL = {
    "schema": "unseen-source-family-development-protocol-v1",
    "candidate_only": True,
    "research_final_admission": False,
    "registered_executor_dispatch_authorized": False,
    "classifier_inputs": 18,
    "malicious": 9,
    "benign": 9,
    "classification_system_prompt_v1": CLASSIFIER_SYSTEM_PROMPT,
    "source_localization_system_prompt_v1": SOURCE_SYSTEM_PROMPT,
    "classification_response_schema_sha256": _schema_sha(RQ2ClassificationDecision),
    "source_response_schema_sha256": _schema_sha(CompactSourceSelection),
    "classifier_input_field_names": ["route", "observations"],
    "source_selection_input_field_names": [
        "route", "observations", "function_excerpt", "source_sha256"
    ],
    "known_source_families_disjoint_from_training_registry": True,
    "benign_unknown_prediction_scores_as_error": True,
    "source_localization_nonpositive_or_unverified_predicted_cases_get_no_patch": True,
    "classify_min_correct": 16,
    "classify_malicious_min_correct": 8,
    "classify_benign_min_correct": 8,
    "classify_per_vulnerability_min_correct": 2,
    "source_localization_min_correct_on_9_positive_cases": 8,
    "source_localization_per_vulnerability_min_correct": 2,
    "no_unregistered_or_unverified_patch_application": True,
    "source_compiler": "candidate_trusted_exact_anchor_ast_only",
    "inference_settings": {
        "model": "qwen25coder3b-specialist-Q6_K-b10964.gguf",
        "model_sha256": "07bcec4047a457766a92c9737fd0ac8045e328ccf703baf43768c2ea962bf7a9",
        "temperature": 0,
        "top_p": 0.8,
        "top_k": 20,
        "context_tokens": 1536,
        "max_output_tokens": 160,
        "max_attempts_per_role": 1,
        "seed": None,
    },
    "completion_conditions": [
        "independent researcher approves theme and training-family exclusion",
        "source excerpts and model inputs remain sealed and immutable",
        "registered target/test/endpoint semantics separately reviewed",
        "live Docker admission independently approved and pristine checkout",
        "actual evaluator truth never enters model requests",
        "classifier routes only on predictions; unknown is manual review",
        "every benign model-positive attempt verified and counted as false positive",
        "independent registered Red evidence required before any repair",
        "no admission to RQ1/RQ2/RQ3 just from this candidate holdout",
    ],
}

class SourceFamilyBlocked(ValueError):
    pass


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")) + "\n").encode()


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_strict(path: Path, size_limit: int = 1_000_000) -> bytes:
    if not path.is_file() or path.is_symlink() or path.stat().st_size > size_limit:
        raise SourceFamilyBlocked("missing, symlinked, or oversized candidate file")
    result = path.read_bytes()
    if len(result) > size_limit:
        raise SourceFamilyBlocked("oversized candidate read")
    return result


def source_location(recipe: SourceFamily) -> int:
    lines = recipe.source.splitlines()
    matches = [i for i, line in enumerate(lines, 1) if recipe.sink_anchor in line]
    if len(matches) != 1:
        raise SourceFamilyBlocked("registered sink ambiguous")
    tree = ast.parse(recipe.source)
    fs = [n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)
          and n.name == recipe.function]
    if len(fs) != 1 or not fs[0].lineno <= matches[0] <= fs[0].end_lineno:
        raise SourceFamilyBlocked("sink outside registered function")
    return matches[0]


def patch_preview(
    *, name: str, frozen_source: bytes, proposed_class: str,
    proposed_function: str, proposed_sink: int,
) -> bytes:
    """Offline trusted exact-anchor repair bytes; model supplies NO edit text."""
    recipe = RECIPE_BY_NAME.get(name)
    if recipe is None or proposed_class != {
        "spectrometry": "sql_injection",
        "weatherbeacon": "xss",
        "magnetometry": "path_traversal",
    }[name] or proposed_function != recipe.function or proposed_sink != source_location(recipe):
        raise SourceFamilyBlocked("unregistered model selection or sink")
    expected = recipe.source.encode("utf-8")
    if len(frozen_source) > MAX_SOURCE_BYTES or sha(frozen_source) != sha(expected):
        raise SourceFamilyBlocked("source bytes do not match frozen recipe")
    text = frozen_source.decode("utf-8")
    for old, new in recipe.old_new:
        if text.count(old) != 1 or old == new:
            raise SourceFamilyBlocked("untrusted or ambiguous fixed patch anchor")
        text = text.replace(old, new, 1)
    patched = text.encode("utf-8")
    compile(patched, recipe.name + "-patched", "exec")
    if patched == frozen_source:
        raise SourceFamilyBlocked("patch had no effect")
    return patched


class ScriptProbe(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.danger = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"svg", "script", "img"}:
            self.danger = True
        if any(key.startswith("on") for key, _ in attrs):
            self.danger = True


def observed_exploit(recipe: SourceFamily, response: object) -> bool:
    body = response.text
    if recipe.name == "weatherbeacon":
        parser = ScriptProbe()
        parser.feed(body)
        return parser.danger
    return recipe.private_marker in body


def run_case(
    recipe: SourceFamily,
    *,
    source: bytes,
    payload: str,
    data_root: Path,
) -> tuple[dict, bool]:
    """In-process deterministic HTTP observation on a disposable application."""
    if len(source) > MAX_SOURCE_BYTES:
        raise SourceFamilyBlocked("source exceeds registered bound")
    original = recipe.source.encode("utf-8")
    approved_patch = patch_preview(
        name=recipe.name, frozen_source=original,
        proposed_class={
            "spectrometry": "sql_injection",
            "weatherbeacon": "xss",
            "magnetometry": "path_traversal",
        }[recipe.name],
        proposed_function=recipe.function, proposed_sink=source_location(recipe),
    )
    if source not in (original, approved_patch):
        raise SourceFamilyBlocked("untrusted candidate source cannot execute")
    module_globals: dict = {"__name__": "approved_source_family_" + recipe.name}
    # Only exact source or trusted deterministic exact-anchor preview is executable.
    exec(compile(source, recipe.name + ".py", "exec"), module_globals)  # noqa: S102
    app = module_globals["create_app"](data_root)
    with TestClient(app) as client:
        control_response = client.get(
            recipe.route, params={recipe.parameter: recipe.control}
        )
        target_response = client.get(recipe.route, params={recipe.parameter: payload})
        health = client.get(recipe.route, params={recipe.parameter: (
            "open-1" if recipe.name == "spectrometry"
            else "normal report" if recipe.name == "weatherbeacon"
            else "readme.txt"
        )})
    if recipe.name == "spectrometry":
        if health.status_code != 200 or health.json()["intensity"] != "range-normal":
            raise SourceFamilyBlocked("SQL family legitimate function failed")
    elif recipe.name == "weatherbeacon":
        if health.status_code != 200 or "normal report" not in health.text:
            raise SourceFamilyBlocked("HTML family legitimate function failed")
    elif health.status_code != 200 or "Public coil readout." not in health.text:
        raise SourceFamilyBlocked("file family legitimate function failed")
    exploit = observed_exploit(recipe, target_response)
    observed = {
        "route": recipe.route,
        "observations": [
            {
                "method": "GET",
                "parameters": {recipe.parameter: recipe.control},
                "status_code": control_response.status_code,
                "response_excerpt": control_response.text[:380],
            },
            {
                "method": "GET",
                "parameters": {recipe.parameter: payload},
                "status_code": target_response.status_code,
                "response_excerpt": target_response.text[:380],
            },
        ],
    }
    return observed, exploit


def _training_index() -> dict:
    family_file = TRAIN / "family_registry.json"
    registry = json.loads(read_strict(family_file, 50_000))
    train_themes = {f["app_theme"] for f in registry["families"]}
    if any(name in train_themes for name in FAMILIES):
        raise SourceFamilyBlocked("candidate source family theme reused from fine-tuning")
    corpora = (
        TRAIN / "data-check/train.jsonl",
        TRAIN / "data-check/validation.jsonl",
        TRAIN / "data-check/fixtures.jsonl",
        PRIOR_INPUTS,
    )
    unique_markers = (
        "SPECTRAL_PRIVATE_SYNTHETIC_ONLY",
        "COIL_PRIVATE_SYNTHETIC_ONLY",
        "probeSpectra1",
        "probeSpectra2",
        "probeSpectra3",
        "beam_log",
        "sample_code",
        "caption_view",
        "record_view",
    )
    result: dict = {
        "training_registry_sha256": sha(read_strict(family_file)),
        "training_family_count": len(registry["families"]),
        "candidate_themes": list(FAMILIES),
        "old_theme_overlap": [],
        "corpora": {},
        "distinctive_marker_hits": {},
        "limits": "Exact byte/theme/marker checks; NOT proof of semantic independence.",
    }
    for path in corpora:
        raw = read_strict(path, 8_000_000)
        result["corpora"][str(path)] = sha(raw)
        for marker in unique_markers:
            if marker.encode() in raw:
                result["distinctive_marker_hits"].setdefault(marker, []).append(str(path))
        for recipe in RECIPES:
            if recipe.source.encode() in raw:
                raise SourceFamilyBlocked("complete source text was present in prior corpus")
    if result["distinctive_marker_hits"]:
        raise SourceFamilyBlocked("distinctive source/attack marker collision with prior corpus")
    return result


def _seal_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(canonical(value))
    path.chmod(0o600)


def _seal_source(path: Path, source: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("xb") as stream:
        stream.write(source)
    path.chmod(0o600)


def build(output: Path) -> dict:
    if not output.is_absolute() or output.exists() or output.is_symlink():
        raise SourceFamilyBlocked("a NEW absolute external output root is required")
    if output == REPO or REPO in output.parents:
        raise SourceFamilyBlocked("candidate evidence cannot live inside live repository")
    contamination = _training_index()
    for recipe in RECIPES:
        source_location(recipe)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    output.chmod(0o700)
    originals: dict[str, str] = {}
    patch_hashes: dict[str, str] = {}
    source_metadata: dict = {}
    all_inputs: dict = {}
    truths: dict = {}
    manifest_cases: list[dict] = []
    ordinal = 0
    for recipe in RECIPES:
        source = recipe.source.encode("utf-8")
        source_file = output / "source" / (recipe.name + ".py")
        _seal_source(source_file, source)
        originals[recipe.name] = sha(source)
        label = {
            "spectrometry": "sql_injection",
            "weatherbeacon": "xss",
            "magnetometry": "path_traversal",
        }[recipe.name]
        location = source_location(recipe)
        fixed = patch_preview(
            name=recipe.name, frozen_source=source,
            proposed_class=label, proposed_function=recipe.function,
            proposed_sink=location,
        )
        patch_hashes[recipe.name] = sha(fixed)
        source_metadata[recipe.name] = {
            "source_sha256": sha(source),
            "candidate_patch_sha256": sha(fixed),
            "sink_line_evaluator_only": None,
        }
        _seal_source(output / "trusted-preview" / (recipe.name + ".py"), fixed)
        lines = recipe.source.splitlines()
        fn = next(n for n in ast.walk(ast.parse(recipe.source))
              if isinstance(n, ast.FunctionDef) and n.name == recipe.function)
        excerpt = "\n".join(
            f"{n:03d} {lines[n - 1]}" for n in range(fn.lineno, fn.end_lineno + 1)
        )
        _seal_json(output / "source-excerpts" / (recipe.name + ".json"), {
            "source_sha256": sha(source),
            "function_excerpt": excerpt,
            "route": recipe.route,
        })
        for malicious, payloads in ((True, recipe.attacks), (False, recipe.benign)):
            for payload in payloads:
                ordinal += 1
                case_id = f"sfh-v1-{ordinal:03d}"
                with tempfile.TemporaryDirectory(prefix="sfh-capture-") as td:
                    observed, exploit = run_case(
                        recipe, source=source, payload=payload,
                        data_root=Path(td),
                    )
                if exploit != malicious:
                    raise SourceFamilyBlocked("prospective case truth failed: " + case_id)
                assert case_id not in truths
                all_inputs[case_id] = observed
                truths[case_id] = {
                    "expected_classification": label if malicious else "benign",
                    "expected_exploit": malicious,
                    "family": recipe.name,
                    "function": recipe.function,
                    "sink_line": location if malicious else None,
                    "input_sha256": sha(canonical(observed)),
                }
                _seal_json(output / "model-inputs" / (case_id + ".json"), observed)
                manifest_cases.append({
                    "case_id": case_id,
                    "model_input_sha256": sha(canonical(observed)),
                    "source_sha256": sha(source),
                    "source_excerpt_sha256": sha(read_strict(
                        output / "source-excerpts" / (recipe.name + ".json")
                    )),
                    "family_slot": recipe.name,
                })
    if ordinal != 18 or len({sha(canonical(v)) for v in all_inputs.values()}) != 18:
        raise SourceFamilyBlocked("candidate model input cardinality/uniqueness invalid")
    _seal_json(output / "evaluator-only" / "truth.json", truths)
    _seal_json(output / "frozen-protocol.json", PROTOCOL)
    _seal_json(output / "candidate-registry.json", {
        "schema": "nonlive-source-family-candidate-registry-v1",
        "admitted_to_live_executor": False,
        "family_routes": [
            {"name": r.name, "route": r.route, "function": r.function}
            for r in RECIPES
        ],
    })
    manifest = {
        "schema": "source-family-prequalification-bundle-v1",
        "development_only": True,
        "source_family_count": len(RECIPES),
        "case_count": ordinal,
        "model_calls": 0,
        "actual_live_executor_runs": 0,
        "frozen_utc": datetime.now(UTC).isoformat(),
        "training": contamination,
        "sources": originals,
        "trusted_patch_previews": patch_hashes,
        "frozen_protocol_sha256": sha(read_strict(output / "frozen-protocol.json")),
        "evaluator_truth_sha256": sha(read_strict(output / "evaluator-only" / "truth.json")),
        "cases": manifest_cases,
        "code_builder_sha256": sha(read_strict(Path(__file__))),
        "not_scientifically_admitted_reason": (
            "Unseen candidate source themes have not been independently approved; "
            "no registered executor integration or blinded Q6 run exists."
        ),
    }
    _seal_json(output / "manifest.json", manifest)
    return manifest


def verify(output: Path) -> dict:
    """Read-only verification of an existing prospective candidate bundle."""
    manifest = json.loads(read_strict(output / "manifest.json"))
    if (
        manifest["schema"] != "source-family-prequalification-bundle-v1"
        or manifest["model_calls"] != 0
        or manifest["actual_live_executor_runs"] != 0
        or manifest["case_count"] != 18
    ):
        raise SourceFamilyBlocked("candidate manifest scope or cardinality drift")
    if sha(read_strict(Path(__file__))) != manifest["code_builder_sha256"]:
        raise SourceFamilyBlocked("prospective builder has changed since seal")
    if sha(read_strict(output / "frozen-protocol.json")) != manifest["frozen_protocol_sha256"]:
        raise SourceFamilyBlocked("protocol changed after freeze")
    if json.loads(read_strict(output / "frozen-protocol.json")) != PROTOCOL:
        raise SourceFamilyBlocked("model thresholds/settings changed")
    if sha(read_strict(output / "evaluator-only/truth.json")) != manifest["evaluator_truth_sha256"]:
        raise SourceFamilyBlocked("truth file has been modified")
    truth = json.loads(read_strict(output / "evaluator-only/truth.json"))
    training = _training_index()
    if training != manifest["training"]:
        raise SourceFamilyBlocked("training corpus has changed since sealing")
    counts = {"malicious": 0, "benign": 0, "patched_replay": 0}
    for recipe in RECIPES:
        original = read_strict(output / "source" / (recipe.name + ".py"), MAX_SOURCE_BYTES)
        fixed = read_strict(output / "trusted-preview" / (recipe.name + ".py"), MAX_SOURCE_BYTES)
        if sha(original) != manifest["sources"][recipe.name] or original != recipe.source.encode():
            raise SourceFamilyBlocked("candidate source changed")
        if sha(fixed) != manifest["trusted_patch_previews"][recipe.name]:
            raise SourceFamilyBlocked("trusted preview changed")
        classification = {
            "spectrometry": "sql_injection",
            "weatherbeacon": "xss",
            "magnetometry": "path_traversal",
        }[recipe.name]
        expected = patch_preview(
            name=recipe.name, frozen_source=original,
            proposed_class=classification, proposed_function=recipe.function,
            proposed_sink=source_location(recipe),
        )
        if expected != fixed:
            raise SourceFamilyBlocked("trusted preview not reproducible")
        lines = recipe.source.splitlines()
        function = next(
            n for n in ast.walk(ast.parse(recipe.source))
            if isinstance(n, ast.FunctionDef) and n.name == recipe.function
        )
        proper_excerpt = "\n".join(
            f"{n:03d} {lines[n - 1]}"
            for n in range(function.lineno, function.end_lineno + 1)
        )
        excerpt = read_strict(output / "source-excerpts" / (recipe.name + ".json"))
        if json.loads(excerpt) != {
            "route": recipe.route, "source_sha256": sha(original),
            "function_excerpt": proper_excerpt,
        }:
            raise SourceFamilyBlocked("source excerpt changed after freeze")
    for case in manifest["cases"]:
        k = case["case_id"]
        original = read_strict(output / "model-inputs" / (k + ".json"))
        inp = json.loads(original)
        if sha(original) != case["model_input_sha256"]:
            raise SourceFamilyBlocked("model input modified after freeze")
        if canonical(inp) != original:
            raise SourceFamilyBlocked("noncanonical model input")
        if any(
            forbidden in original.decode("utf-8")
            for forbidden in (
                "expected_classification", "expected_exploit",
                "sink_line", "evaluator_only", "ground_truth",
            )
        ):
            raise SourceFamilyBlocked("evaluator-only truth leaked into model input")
        family_excerpt = output / "source-excerpts" / (case["family_slot"] + ".json")
        if sha(read_strict(family_excerpt)) != case["source_excerpt_sha256"]:
            raise SourceFamilyBlocked("source excerpt SHA does not match freeze")
        t = truth[k]
        if t["input_sha256"] != sha(original) or case["family_slot"] != t["family"]:
            raise SourceFamilyBlocked("model-input/truth identity mismatch")
        recipe = RECIPE_BY_NAME[t["family"]]
        input_obs = inp["observations"]
        payload = input_obs[1]["parameters"][recipe.parameter]
        with tempfile.TemporaryDirectory(prefix="sfh-verify-") as td:
            observed, exploit = run_case(
                recipe, source=recipe.source.encode(), payload=payload,
                data_root=Path(td),
            )
        if canonical(observed) != original or exploit != t["expected_exploit"]:
            raise SourceFamilyBlocked("frozen HTTP observation did not reproduce")
        if exploit:
            counts["malicious"] += 1
            with tempfile.TemporaryDirectory(prefix="sfh-patched-") as td:
                _, fixed_exploit = run_case(
                    recipe, source=read_strict(
                        output / "trusted-preview" / (recipe.name + ".py")
                    ),
                    payload=payload, data_root=Path(td),
                )
            if fixed_exploit:
                raise SourceFamilyBlocked("trusted repaired family still vulnerable")
            counts["patched_replay"] += 1
        else:
            counts["benign"] += 1
            with tempfile.TemporaryDirectory(prefix="sfh-patched-benign-") as td:
                _, patched_exploit = run_case(
                    recipe, source=read_strict(
                        output / "trusted-preview" / (recipe.name + ".py")
                    ),
                    payload=payload, data_root=Path(td),
                )
            if patched_exploit:
                raise SourceFamilyBlocked("trusted repair disrupted benign boundary")
    if counts != {"malicious": 9, "benign": 9, "patched_replay": 9}:
        raise SourceFamilyBlocked("unexpected family control/truth/replay counts")
    return counts


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output-root", required=True, type=Path)
    parser.add_argument("--verify-only", action="store_true")
    args = parser.parse_args()
    out = args.output_root
    if args.verify_only:
        result = verify(out)
        print("SOURCE_FAMILY_READ_ONLY_VERIFY_PASS", json.dumps(result, sort_keys=True))
        return
    manifest = build(out)
    print("SOURCE_FAMILY_CANDIDATE_FROZEN", str(out),
          "source_families", len(manifest["sources"]),
          "model_inputs", manifest["case_count"], "model_calls", manifest["model_calls"])
    result = verify(out)
    print("SOURCE_FAMILY_REPLAY_AND_INTEGRITY_PASS", json.dumps(result, sort_keys=True))
    print("M21_RESEARCH_ADMISSION FALSE")


if __name__ == "__main__":
    main()
