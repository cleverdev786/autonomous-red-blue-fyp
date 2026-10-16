# Sentinel Archived Evidence Review

## Purpose

This development-only, read-only feature connects an already saved Q8 synthetic
classification to separately executed, externally pinned, registered Red evidence.
It reuses the original registered-test verifier and Blue source-analysis decision
gate. It does **not** dispatch tests, start Docker, run a model, localize source,
prepare/apply a patch, or qualify the model for final scientific evaluation.

**API:** `GET /api/console/assessment/review` (no request body or arbitrary
path input; `Cache-Control: no-store`). Model Studio exposes **Review pinned
Red evidence**. If no approval has been configured, it reports
`not_configured` and authorizes nothing.

## Operator-controlled evidence link

Only after a separately approved registered test has actually executed and its
raw evidence has been reviewed, an operator may prepare one external JSON file.
Do not create this manifest as part of a model response or derive the required
approval digest from an untrusted browser request.

The file **must be outside the Git repository**, be a regular file with no
symlink path components, and use this exact schema:

```json
{
  "schema_version": "sentinel-evidence-link-v1",
  "model_evidence_dir": "/absolute/external/probe-0123456789abcdef",
  "model_files": {
    "q8-input.json": "<sha256>",
    "q8-raw-completion.json": "<sha256>",
    "q8-gateway.json": "<sha256>",
    "q8-assessment-plan.json": "<sha256>"
  },
  "red_evidence_dir": "/absolute/external/evidence/approved-case",
  "red_admission_path": "/absolute/external/admission.json",
  "red_admission_sha256": "<sha256>",
  "red_receipt_sha256": "<sha256>",
  "red_run_id": "approved-run-id"
}
```

Each `<sha256>` placeholder is a full lowercase 64-character SHA-256 digest
obtained from the actual approved file. No placeholder may be submitted literally.
The model case must match the existing `probe-<16 lowercase hex>` naming pattern.
Red admission and receipt digests must come from an independently controlled
approval record, **not** from a user-submitted API payload or model output.
The approval is scoped to one historical archived case and cannot be reused as
permission for a fresh dispatch.

Provide the external approval manifest's absolute path and its **separately
verified** SHA-256 digest through the server process environment:

```shell
FYP_ASSESSMENT_APPROVAL_PATH=/absolute/external/evidence-link.json
FYP_ASSESSMENT_APPROVAL_SHA256=<independently-verified-sha256>
```

Those variables are not created automatically, and no operator approval is
currently installed by this development gate.

## Review decision

The service checks the external approval SHA, each model evidence file SHA,
the original raw model JSON against the recorded gateway, and the unchanged
registry-bound eight-stage plan. The model classification is preserved verbatim.
For `unknown`, Blue requires manual review. For model-predicted `benign`,
there is **no trusted-safe conclusion**. For an incompatible class/test/endpoint,
the Red archive is not even read.

Only an eligible attack-class prediction proceeds to independent archived-Red
verification. That verifier compares the pinned admission and receipt, source
files, registered command, source/container identities, raw process bytes and
the deterministic exploit evaluator. The existing Blue gate must also match
the selected test, endpoint, vulnerability class and run.

A successful **archived development evidence** review can mark Blue *source
analysis eligible*. This is not fresh runtime attestation, model qualification,
or permission to execute Blue localization. Remediation preparation, patch
application, post-patch verification and final research admission **remain false**.

Failed, missing, changed, forged or inconclusive archives fail closed. The route
never builds, starts, stops, dispatches or retries Docker; it never writes files.
The saved Q8 examples are hand-authored HTTP pairs, not real captured Red
requests; the two evidence streams must not be misrepresented as one observation.

## Tests

`tests/test_evidence_review.py` validates default refusal, success under
offline injected executor fixtures, `benign`/`unknown` refusal, wrong
class, per-file tampering, wrong pins, wrong run, missing/inconclusive Red
receipts, unbound raw model answers and the FastAPI route. Existing archived
evidence and policy tests remain unchanged.

## October 15 registered SQLi evidence, separate from Q8

The author-authorized, single registered SQLi development attempt completed as
`sql-20261015-c1`: the original executor returned
`baseline_exploit_confirmed`; the separate archived binder confirmed the
admission, receipt, 2 HTTP requests and unmodified source. Review provenance is
**author-authorized self-review, not independent scientific admission**.

A separate read-only endpoint `GET /api/console/assessment/registered-red`
shows this receipt under **Evidence & audit** without requiring a fictitious
matching model output. It accepts no browser parameters, never dispatches Red,
and never grants Blue source-analysis or remediation permissions. The original
`/assessment/review` Q8-to-Red gate remains unchanged and requires a genuine,
complete, class-aligned model archive.

The registered-Red display requires two operator-controlled environment values:

```shell
FYP_REGISTERED_RED_DISPLAY_PATH=/home/zain/.local/state/sentinel-fyp/development-gates/2026-10-15-red-preflight/registered-red-display-approval.json
FYP_REGISTERED_RED_DISPLAY_SHA256=a5159cf9723ff72325cbc97086a21a2b3bef53ddc9247c36e58f707ab999e635
```

The JSON is stored outside Git, fixes the clean execution source root, evidence
directory, admission path and both SHA-256 pins. The service runs the existing
`verify_archived_registered_red` against those paths, checks the exact SQLi
test and run, and returns only a limited archive status. Missing, stale, invalid
or altered pins fail closed. Do not copy the environment values into Git or
present archived verification as current Docker health attestation.

The one genuine October 14 Q8 console inference saved a synthetic
`ordinary_search` example with an `xss` prediction and did **not** save
`q8-assessment-plan.json`. It is not the SQLi model classification required
to authorize the archived SQLi Blue gate. Source lines 48 and 53 were
separately identified by trusted deterministic source review, not Q8.
The registered-Red display preserves `model_decision=null`,
`model_alignment_status=not_established`, and
`source_analysis_authorized=false`.

**Next engineering gate:** obtain a genuine, independently pinned,
class-aligned model archive, or record Blue as withheld. Do not retrofit a
historical model prediction, infer evaluator truth, or apply a patch.


## Phase 5: XSS and traversal archived registered replays

The original registered XSS and path-traversal test implementations executed once
each against a separately operator-attested patched Docker stack. Both saved
results were recomputed by their frozen registered evaluators and showed no
exploit evidence. Their controls remained successful: XSS retained HTTP 200
with HTML-escaped marker; traversal retained HTTP 200 for the public guide and
returned 403 for the synthetic private-file path.

The additive `GET /api/console/assessment/phase5-replays` endpoint reads only
operator-pinned archives. To show these archives in a locally started console,
set these **server-side** environment variables to the file and independent
digest saved under the external development-gates directory:

- `FYP_PHASE5_REPLAY_APPROVAL_PATH`
- `FYP_PHASE5_REPLAY_APPROVAL_SHA256`

The browser cannot choose evidence paths, change pins, dispatch Red or apply
patches. Missing or tampered records fail closed. The current approved manifest
is `phase5-patched-replay-display-approval.json`, SHA-256
`3e14fac83bc2414038badf7a4b661e15ece8b94d744c906ad6644af3a6933dcd`.

This is **archived development self-review only**. No new genuine Q8 XSS or
path-traversal decision was obtained, and Q8 did not initiate the original
registered Red runs. The patched-Docker security replays passed. The separate
live Docker legitimate-function command was blocked by remote safety checks,
so live patched-Docker functional acceptance remains unverified. Earlier
disposable-app functional checks do not replace that requirement. No final
scientific research qualification is implied.
