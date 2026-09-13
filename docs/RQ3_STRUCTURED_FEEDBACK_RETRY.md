# Milestone 19 — RQ3 Structured Feedback Retry

## Status

Milestone 19 is implemented, development-laptop tested, and runtime/integration verified. This document records the post-Phase-1 operationalization of RQ3 without rewriting the frozen Phase-1 research/design evidence.

The permanent Phase-1 files remain historical design evidence. Where M19 resolved implementation or methodological ambiguity, the clarification is recorded here rather than retroactively changing the original research plan.

## Scope

RQ3 compares two stored retry-feedback conditions after a first patch attempt is deterministically verified as `REJECTED`, baseline restoration succeeds, and the shared run budget authorizes another patch attempt:

1. `RetryFeedbackMode.NONE`
2. `RetryFeedbackMode.STRUCTURED`

`ACCEPTED`, `FAILED`, and `POLICY_BLOCKED` are terminal for the RQ3 patch-treatment controller and do not automatically retry.

The stored `ExperimentConfiguration.retry_feedback_mode` is the treatment authority. The caller does not supply a separate treatment mode. Paired RQ3 configurations must match except for `config_id` and `retry_feedback_mode`.

## Retry Execution Invariants

The RQ3 controller starts from already-produced Blue analysis and Red evidence rather than rerunning the Blue pipeline. Across attempts it reuses:

- the same original Blue analysis and source context;
- the same stored baseline commit;
- one shared `RunLimitTracker` without resetting attempt/model/runtime budgets.

The actual retry state transition is:

```text
REJECTED -> PATCH_GENERATING
```

Only a verified `REJECTED` attempt with successful baseline restoration may proceed to another patch attempt when budget remains.

A patch-attempt research row is created before downstream retry generation/verification. Therefore an authorized retry remains represented even if later provider/orchestration work becomes `FAILED`, `POLICY_BLOCKED`, or is genuinely interrupted/incomplete.

## NONE Condition

`RetryFeedbackMode.NONE` reuses the original vulnerability/source context but supplies `retry_feedback=None`.

No retry-feedback artifact is persisted for this condition.

## STRUCTURED Condition

`RetryFeedbackMode.STRUCTURED` derives one bounded feedback object internally from only the immediately previous attempt (`N-1 -> N`). The feedback artifact preserves exact source-attempt and receiving-attempt linkage.

Allowed structured content is derived from trusted typed evidence and may include:

- failed verification stage;
- a trusted registered failing test ID when compatible typed evidence exists;
- a deterministic sanitized error/assertion summary;
- original exploit-replay outcome;
- prior patch-diff metadata summary;
- policy reason code where applicable.

The current regression evidence model does not provide a safe compatible per-test identifier namespace, so `regression_failure_ids` remains empty rather than inventing IDs.

`original_replay_succeeded` uses exploit semantics:

- `True`: replay completed, did not time out, and exploit evidence was observed;
- `False`: replay completed, did not time out, and exploit evidence was not observed;
- `None`: absent or inconclusive.

## Feedback Safety Boundary

Raw unrestricted execution text is never forwarded into retry model context. The trusted builder does not pass:

- raw stdout or stderr;
- pytest output;
- shell commands or shell output;
- traceback text;
- arbitrary exception strings;
- absolute host paths;
- unrestricted diff/code content;
- evaluator ground truth.

The feedback object is a bounded typed research artifact, not a transcript of the failed attempt.

## Methodological Clarification Finalized Before Final Experiments

### RQ3 second-attempt denominator

The frozen Phase-1 research plan specified `second-attempt patch acceptance rate` and `repeated-failure rate`, but it did not explicitly define how an actual second attempt ending as `POLICY_BLOCKED`, `FAILED`, or genuinely interrupted/incomplete should affect the primary denominator.

Before any final experiment, M19 operationalized this ambiguity as follows:

**Primary second-attempt denominator = all actual second attempts.**

The following outcomes remain separately represented:

- `ACCEPTED`
- `REJECTED`
- `POLICY_BLOCKED`
- `FAILED`
- genuinely interrupted/incomplete

Therefore:

```text
second_attempt_acceptance_rate = ACCEPTED second attempts / all actual second attempts
repeated_failure_rate = REJECTED second attempts / all actual second attempts
```

An evaluable-only diagnostic may also be reported:

```text
evaluable_second_attempt_acceptance_rate = ACCEPTED / (ACCEPTED + REJECTED)
```

but it is secondary only and must never replace the primary denominator.

This is a later methodological clarification, not a rewrite of the original RQ3 research question, hypothesis, independent variable, or Phase-1 plan. It was fixed before Milestone 20 experiment freeze and before any final RQ3 experiment.

## Model-Usage Evidence

Patch-generation model calls are persisted per attempt. When the provider does not report token or cost telemetry:

- token values remain `NULL`;
- cost remains `NULL`;
- usage status is `NOT_REPORTED`.

Unavailable telemetry is never converted to zero.

## Development-Laptop TEST Evidence

```text
Approved implementation patch SHA-256:
c0db469fb091e3b9bc3442c61441ccc1a691dff453326555dd21c02a1bcc9d21

Focused M19 tests: 56 passed
Affected M12-M18 regression tests: 222 passed, 1 known non-failing Starlette warning
Complete development-laptop suite: 313 passed, 1 known non-failing Starlette warning
Targeted research-validity tests: 8 passed
```

The live 10-file M19 implementation was also proven byte-identical to a fresh permanent-M18 tree with the approved implementation patch applied.

## Runtime / Integration VERIFY Evidence

Runtime verification used disposable DEVELOPMENT research storage and disposable Git/runtime evidence only. No actual final experiment was executed.

Verified behavior included:

- stored RQ3 configuration as the sole retry-feedback treatment authority;
- paired-treatment isolation validator;
- reuse of the same original Blue/source context;
- persistence of first and subsequent patch attempts;
- actual authorized `REJECTED -> PATCH_GENERATING` audit transition;
- no automatic retry from `ACCEPTED`, `FAILED`, or `POLICY_BLOCKED`;
- real Git baseline restoration to clean `main`/stored base commit in a disposable repository;
- one shared budget tracker across attempts;
- NONE with no persisted/forwarded retry feedback;
- STRUCTURED with exact `N-1 -> N` feedback linkage;
- exclusion of unrestricted failure output from model retry context;
- authorized attempt 2 retained across provider failure, policy block, and external interruption;
- retry model-call persistence with `NULL / NOT_REPORTED` telemetry;
- separate second-attempt `ACCEPTED`, `REJECTED`, `POLICY_BLOCKED`, `FAILED`, and incomplete outcomes.

A disposable combined metric fixture containing one actual second attempt of each outcome produced:

```text
eligible second attempts: 5
ACCEPTED:       1 (0.20)
REJECTED:       1 (0.20)
POLICY_BLOCKED: 1 (0.20)
FAILED:         1 (0.20)
incomplete:     1 (0.20)
```

This directly verifies the primary all-second-attempt denominator.

## Storage and Dataset Invariants

M19 adds no SQLAlchemy table. The schema remains exactly 20 tables.

The permanent M18 RQ2 dataset remains frozen and unchanged:

```text
inputs.jsonl        9a7db4522d96c2a4d27b6f131bd145c6fd38b7614e0ccbbef8ab7dbf4cc5c6f5
ground_truth.jsonl 376cac8cbf7963aa0630f0a2437f555d56861c945beda2a0ffdb63f47391781f
manifest.json       8131e0ad2a40a6963fe9f405445352ce8af287f6ab41297f80ebba0735e31345
```

## Final-Evaluation Boundary

All M19 runtime/integration verification configurations were `DEVELOPMENT`.

Synthetic `RunType.FINAL_EVALUATION` rows used by unit-test metric fixtures exist only in disposable test databases so `final_only=True` metric behavior can be tested. They are not real final experiments and create no persistent final-evaluation artifact.

```text
Persistent FINAL_EVALUATION configurations created by M19: 0
Persistent FINAL_EVALUATION runs created by M19: 0
Actual RQ1 final experiments executed: 0
Actual RQ2 final experiments executed: 0
Actual RQ3 final experiments executed: 0
```

Milestone 20 remains the experiment-freeze gate. No provider/model/prompt/final experiment values are frozen by M19.
