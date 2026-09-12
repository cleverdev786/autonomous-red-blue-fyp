# Milestone 18 — RQ2 Frozen Classification Dataset

## Scope

Milestone 18 freezes the versioned dataset used by the future RQ2 comparison. It does not run the Rule Only, LLM Only, or Hybrid benchmark and does not create a final-evaluation experiment.

The frozen identity is `rq2-classification` / `v1`. The permanent artifacts live under `experiments/datasets/rq2-classification-v1/`.

## Dataset composition

The verified dataset contains exactly 60 controlled observations:

- SQL Injection: 10
- XSS: 10
- Path Traversal: 10
- Benign: 30
- Unknown ground truth: 0

The 60 observations come from 10 repetitions of each existing registered deterministic security test. Each repetition contributes its existing control step plus its existing attack step. No new payloads, test IDs, vulnerability classes, targets, endpoints, or execution authority were added.

The duplication audit records 60 unique event IDs and 60 unique classifier-input hashes but only 6 unique semantic-input hashes. This is deliberate: v1 represents repeated controlled observations of six registered control/attack semantics, not broad payload-family generalization.

## Capture and separation boundary

The controlled executor remained the only HTTP execution path. Runtime events were correlated using the existing `run_id` and deterministic `request_id` chain, then projected into the existing normalized application-event semantics. Runtime correlation and evaluator provenance are removed from classifier-visible content.

Classifier-visible content and evaluator truth are stored separately:

- `inputs.jsonl` contains opaque dataset event IDs, the run-neutral normalized event, and integrity hashes;
- `ground_truth.jsonl` contains evaluation-only labels and source provenance;
- `manifest.json` freezes identity, counts, source framework commit, generation method, file hashes, and duplication audit.

Structural leakage checks reject evaluator-only field names. Value checks reject evaluator-only provenance values that have no legitimate observable role. The corrective M18 regression specifically permits the legitimate observable application component `vulnerable-store` even though the same text is also the registered target ID.

## Integrity

Verified SHA-256 values:

```text
inputs.jsonl
9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5

ground_truth.jsonl
376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f

manifest.json
8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345
```

The classifier-only loader was verified with no truth file present. The same ordered classifier-input hashes were used for the future `rule_only`, `llm_only`, and `hybrid` conditions. Runtime-correlation materialization was checked 180 times (60 items x 3 mode labels) without changing frozen semantic content. No classifier was executed.

## Metric correction

M18 also corrected RQ2 macro F1 after a focused regression exposed that averaging over all five prediction labels made a perfect four-ground-truth-class dataset score 0.8 because `unknown` had zero support. Macro F1 now averages per-class F1 only across ground-truth classes with support greater than zero. All five per-class results, the five-label confusion matrix, and `unknown_rate` remain reported. An incorrect `unknown` prediction still reduces accuracy and the true class performance while increasing `unknown_rate`.

## Verification record

The corrected development-laptop suite passed:

```text
301 passed, 1 non-failing Starlette deprecation warning
```

Controlled runtime VERIFY confirmed:

```text
item_count = 60
class counts = 10 SQLi / 10 XSS / 10 Path Traversal / 30 benign
unique_event_ids = 60
unique_classifier_input_hashes = 60
unique_semantic_input_hashes = 6
runtime provenance matches = 60
classifier-only load count = 60
mode-neutral materializations checked = 180
SQLAlchemy tables = 20
disposable dataset rows = 60
disposable truth rows = 60
event classifications = 0
FINAL_EVALUATION configurations = 0
FINAL_EVALUATION runs = 0
```

The first VERIFY attempt stopped on a false-positive leakage check involving `vulnerable-store`. No implementation file changed during that VERIFY attempt. A narrow corrective IMPLEMENT/TEST pass fixed only that validator rule, preserved the original 60 runtime captures byte-for-byte, passed 301 tests, and VERIFY then resumed from those captures without rerunning the 30 registered executions.

## Boundary

M18 does not execute the RQ2 comparison. The final provider/model/prompt/configuration freeze remains a later milestone, and final controlled experiments remain unrun. M19 and later milestones remain separately gated.
