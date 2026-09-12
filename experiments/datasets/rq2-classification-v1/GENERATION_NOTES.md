# RQ2 Classification Dataset v1 — Generation Notes

Dataset identity: `rq2-classification` / `v1`.

This dataset was captured from the existing controlled development-laptop runtime using only the three registered deterministic tests already present at permanent Milestone 17 (`25ebfdbee1c6ca310c073c21fca3b81603e366ab`). No new attack payloads, test IDs, vulnerability classes, targets, endpoints, or execution capabilities were introduced.

Generation method: `controlled-runtime-capture-v1`. Each registered test was executed 10 times. Every execution contributed exactly one semantic control observation and one semantic attack observation, producing 60 observations total: 10 SQL Injection, 10 XSS, 10 Path Traversal, and 30 benign. These are repeated controlled observations, not 60 distinct payload variants.

The runtime capture retained evaluator-only provenance (`run_id`, `request_id`, source event ID, registered test/step identity, repetition, and control/attack role). The permanent classifier-visible dataset stores only the run-neutral normalized event projection. Ground truth and source provenance are physically separate from classifier-visible input.

Verified duplication audit: 60 unique event IDs, 60 unique classifier-input SHA-256 values, and 6 unique semantic-input SHA-256 values corresponding to the six repeated registered control/attack semantics.

Verified file digests:

- `inputs.jsonl`: `9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5`
- `ground_truth.jsonl`: `376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f`
- `manifest.json`: `8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345`

Runtime VERIFY seeded the existing evaluation-only storage into a disposable SQLite database and confirmed 60 dataset items, 60 ground-truth rows, 0 event classifications, 0 `FINAL_EVALUATION` configurations/runs, and exactly 20 SQLAlchemy tables. Rule Only, LLM Only, and Hybrid were not executed.

A first VERIFY attempt correctly stopped when the value-leakage validator falsely rejected the legitimate observable component value `vulnerable-store` because it matched evaluator `source_target_id`. A narrow corrective implementation removed only that false-positive value comparison while preserving strict field-name leakage checks and evaluator-only provenance checks. The corrected suite passed 301 tests before VERIFY resumed from the preserved 60 runtime captures.
