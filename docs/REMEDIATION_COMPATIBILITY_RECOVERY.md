# Remediation Outcome Compatibility Recovery

## Status and authority

Recovery compatibility checkpoint, 2026-10-09. This checkpoint implements and verifies **only** the versioned remediation decision/outcome contract and its guarded no-patch persistence path. The work was applied in the primary checkout on an isolated recovery branch from `m20-work` at `f3f0b790e71621fd70f1bf6851f3c113f382f72f`. It does not alter the M20 official DEVELOPMENT feasibility-v1 protocol or decision.

**M20 remains CLOSED with no eligible candidate.** The official Q6_K result remains **INELIGIBLE**, no final experiment freeze has been established, and M21 final experiments remain blocked. Milestones 1-19 remain complete. The permanent RQ2-v1 dataset is unchanged.

## Implementation scope

- `schemas/remediation.py`: `RemediationDecision` provides finite, typed repair strategies (`sqlalchemy_named_bind`, `html_text_escape`, `canonical_public_root`) or an explicit no-action reason. The schema contains no model-supplied patch text, file paths or shell commands. `RemediationAttemptResult` records versioned decisions, provenance hashes and dispositions.
- `schemas/experiment_results.py`: registers `remediation_attempt_result` as an additive artifact type. Existing `PatchProposal`, `PreparedPatch` and `PatchGenerationResult` schemas are not modified.
- `storage/repositories.py`: stores PREPARED provenance only when a compatible legacy patch-generation artifact exists, and atomically stores approved terminal non-patch outcomes. Terminal outcomes cannot claim a prepared patch and cannot bypass policy validation.
- `orchestrator/policy_engine.py`: supplies `validate_no_patch_termination`, a narrow, independent permission check for trusted benign or actionable Blue analysis. The ordinary workflow transition rules remain unchanged.
- `orchestrator/remediation_outcome_flow.py`: checks no-patch authorization, verifies linked blocked-policy audit evidence when applicable, and records authorization, storage failures and successful finalization in the audit log.
- `experiments/rq1_runner.py`: adds `RQ1RemediationExecutionResult` and an explicit `complete_without_patch` development entry point. The legacy `RQ1ExecutionResult` and `run()` behavior remain unchanged.
- `tests/test_remediation_compatibility.py`: tests dispositions, malformed or inconsistent decisions, evidence identities, storage invariants, permitted/blocked endings and legacy-artifact compatibility.

The seven implemented dispositions are `PREPARED`, `NO_ACTION`, `UNSUPPORTED`, `INVALID_OUTPUT`, `COMPILER_REJECTED`, `POLICY_BLOCKED` and `PROVIDER_FAILED`. Completing a non-patch attempt means that evaluation of that attempt terminated; it does **not** mean a vulnerability was repaired. No-patch and rejected cases must remain in later research denominators.

## Safety and evidence boundaries

- No source-rewriting compiler, local/remote model provider, inference, retraining, Docker patch execution or Git patch-application automation is added by this checkpoint.
- No-action storage requires the existing registered target, matching run/target and persisted Blue evidence; once an attempt is closed, no fake patch or Git evidence is constructed.
- A policy-blocked record must point to actual, matching blocked audit evidence; a claimed blocked event is not sufficient.
- A PREPARED outcome must reference an already persisted compatible legacy patch artifact, matching its identity and hashes.
- Final RQ1 no-patch termination remains explicitly **blocked** until a separately authorized and frozen Red-evidence/final-experiment integration gate. This implementation does not qualify Q6_K for final research.
- `storage/models.py` and the established 20-table SQLAlchemy schema are unchanged. New results use the existing `result_artifacts` table and additive typed registration.
- The legacy research schema and canonical serialization contracts are preserved. This checkpoint does not rewrite or re-evaluate historical artifacts.

## Verified tests and integrity

The verification was performed on the primary development machine with Python 3.12.3, from the uncommitted applied patch, before this documentation checkpoint.

```bash
PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv/bin/python -m pytest -q -p no:cacheprovider \
  tests/test_remediation_compatibility.py tests/test_schemas.py \
  tests/test_experiment_storage.py tests/test_policy_engine.py \
  tests/test_rq1_single_agent.py tests/test_experiment_metrics.py \
  tests/test_experiment_freeze.py tests/test_m20_part_b_rq1_attempt_selection.py

PYTHONDONTWRITEBYTECODE=1 PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 \
  .venv/bin/python -m pytest -q -p no:cacheprovider
```

Observed **focused: 123 passed**, **full: 418 passed**, with **one non-failing FastAPI/Starlette deprecation warning** in the full suite. `git diff --check` and non-mutating reverse-patch applicability checks passed. The SQLAlchemy metadata contained **exactly 20 tables**. The branch HEAD remained at the M20 base commit during TEST/VERIFY, with precisely seven approved source/test paths modified or added.

The compatibility patch used for this checkpoint has SHA-256:

```text
1e557168d35a9e16cbe14ab6a7fc418114a213c60001172a966a401632ae7b69
```

Frozen evidence files retained their pre-application SHA-256 hashes:

```text
docs/M20_DEVELOPMENT_FEASIBILITY.md
8ccf0fe8467528abed1dbbf415f9f82c976f6602b7247e9ce17a61c0d468d501

experiments/datasets/rq2-classification-v1/inputs.jsonl
9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5

experiments/datasets/rq2-classification-v1/ground_truth.jsonl
376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f

experiments/datasets/rq2-classification-v1/manifest.json
8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345
```

These are static/software verification results, not proof of real-model remediation, isolated attack replay, compiler correctness or final research performance.

## Next gate, not authorized by this checkpoint

The next scope-controlled activity is a separately approved structured-plan diagnostic for existing Q6_K, followed, only if justified and separately authorized, by three narrow deterministic source-pattern builders and genuine end-to-end security verification. Final RQ1/RQ2 experiments and feasibility-v2 require independent versioned protocols, evidence and authorization. RQ3 remains outside the recovery critical path.

Neither the sealed Q6_K 75-call feasibility-v1 exposure nor any frozen M20 selector is to be rerun or amended to improve its outcome.
