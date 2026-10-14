# Q6 Compact Source Selection, Development Protocol v1

**Status:** source and tests written; live model-to-compiler qualification **not yet established**.

## Purpose and version
`services/compact_source_selection.py` freezes `q6-compact-source-development-v1`. It is a strictly DEVELOPMENT-only bridge from a model-supplied, four-field structured suggestion to the pre-existing deterministic `TrustedRemediationCompiler.prepare()`. It does not change the archived M20 `INELIGIBLE` decision, admit M21, or execute a generated patch. Q6_K remains the chosen classification specialist.

## Model output contract
The model may choose `function_or_route` (allowlisted synthetic handlers), `sink_line` (integer), `root_cause` (bounded nonblank text), and `confidence` (0–1). Pydantic uses `extra="forbid"`, `frozen=True`, `strict=True`. The model does not choose the run ID, source file, endpoint, execution path, test ID, template replacement, Git branch or target identity.

The trusted caller determines the run ID and one approved source window from neutral already-admitted context. The adapter hashes the exact expected `scenario_routes.py`, verifies the approved excerpt, rechecks trusted run identity and triage, and validates that the suggested line lies inside a real nested function in the pinned AST. The existing compiler independently validates the scenario class, sink line overlap, source SHA, expected route decorator, strategy policy and exact source replacement anchors. Any disagreement rejects preparation. A compiler's original deterministic provenance does NOT claim model response usage; the separate raw provider receipt must carry true model provenance.

## Development-only runtime attempt contract (new, not the old M20 study)
- One fresh, specifically identified synthetic SQLi triage and bounded source-selection pair, up to two model requests; no retries, no substitution on timeout and no use of prior failures as successes.
- Q6_K model and pinned server SHA values remain as in Gate 5G; fail closed on drift.
- `llama.cpp` server on `127.0.0.1` with systemd user-scope memory limit 3400 MiB, swap limit 512 MiB, one slot, `ctx-size=1536`, `batch-size=64`, `ubatch-size=16`, two CPU threads, no GPU layers.
- Temperature 0; `top_p=0.8`, `top_k=20`, no seed; JSON-schema response format with independent strict Pydantic validation. Maximum output 160 tokens per request, each timeout 240 seconds, no automatic retry.
- Prepare only inside an owned disposable temporary directory with a byte-identical approved source file; never apply or execute the patch. Never contact the dummy web target or operate Docker in this gate.
- Save exact request/response bytes, SHA-256, schema, version, token usage when genuinely reported, wall-clock status, rejection and timeout receipts, source snapshot and compiler provenance. Preserve original Gate 5G timeouts separately. Unknown usage stays NOT_REPORTED.
- Explicitly report PASS only if real typed triage + real typed selection both pass and `TrustedRemediationCompiler.prepare()` returns `prepared`. Independently check source bytes remain identical.
- If the budget, model, trusted source, prior existing systemd service or current Git source changes unexpectedly: BLOCKED. No partial success becomes final admission.

## Verification and science
Run focused provider, compact adapter and compiler tests, complete pytest, Python compilation, Ruff, `git diff --check`, and source SHA/status integrity checks. Store reports and model logs outside the live repository. Original M20 official 2/6 result is immutable and the independent new-holdout qualification, final freeze, 18 RQ1 and 180 RQ2 observations all remain blocked until separately accepted.

## Handoff checklist mapping
- F03: remains **open** until genuine Q6 source finding is typed and prepared by the trusted compiler.
- F04/F05/F14: only limited offline coverage in this gate, not complete end-to-end acceptance.
- G03: remains **open** until separate engineering evidence demonstrates the new compiler bridge, without relabeling M20.

## Gate 5H final development result (2026-10-10)

Two independently preserved live attempts: first failed schema validation; second passed real typed Q6 classification, compact source localization and trusted compiler in-memory preparation. Original source was unchanged, no patch applied, no registered attack run, no final research admission. The final independent compiler replay reproduced the prepared patch hash. Complete Python suite: 854 passed earlier; a fresh focused regression and Ruff check also passed. Original M20 INELIGIBLE result is unchanged. See external Gate5H closeout and evidence index for exact paths and hashes.
