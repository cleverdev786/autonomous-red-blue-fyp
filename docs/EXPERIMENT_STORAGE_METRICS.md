# Milestone 15 — Experiment Storage and Metrics

## Scope

Milestone 15 implements the local research-evidence store required by the frozen
`RESEARCH_PLAN.md`. It records existing typed pipeline outputs and recomputes
research metrics from stored evidence. It does not implement a new agent,
verification decision, retry strategy, experience selector, final dataset, final
experiment runner, score formula, or dashboard.

The design rule is:

```text
existing typed pipeline result
→ canonical JSON + SHA-256
→ normalized SQLAlchemy rows derived in the same transaction
→ deterministic post-run metric queries
```

Persistence is observational. Stored results are never fed back into Red/Blue
reasoning in this milestone.

## Local storage boundary

`storage/database.py` accepts SQLite only. File-backed databases may be restricted
to a supplied project root. Foreign-key enforcement is enabled for every SQLite
connection. SQLAlchemy is already an approved project dependency; Milestone 15
adds no database dependency.

The default project setting remains `sqlite:///./data/fyp.db`, while automated and
runtime verification use temporary SQLite files.

## Experiment subjects

The experiment configuration schema now distinguishes the frozen research units:

- RQ1/RQ3 are scenario-scoped and require `scenario_ids`;
- RQ2 is dataset-scoped and requires `dataset_id` with no fake scenario ID.

Development and final-evaluation runs remain explicitly separate.

## Canonical artifacts

The artifact store supports registered Pydantic evidence types only:

- `LogReadResult`;
- `MonitoringResult`;
- `SourceReadResult`;
- `RedTeamRunResult`;
- `BlueTeamAnalysisResult`;
- `PatchGenerationResult`;
- `PatchBranchResult`;
- `PatchVerificationResult`;
- `PatchRetryFeedback`.

For every artifact, storage serializes `model_dump(mode="json")` as sorted compact
UTF-8 JSON, calculates SHA-256 itself, then derives normalized rows from that same
validated object. Callers cannot separately claim a conflicting normalized result.

## Ground-truth separation

Execution-side persistence uses `ExperimentWriteRepository`. It exposes no scenario
or classification-ground-truth read API.

Evaluation truth uses a separate `EvaluationTruthRepository` for:

- versioned `ScenarioGroundTruth` snapshots;
- frozen RQ2 classifier-visible dataset items;
- separately stored RQ2 labels.

`experiments/runner.py` does not import the evaluation repository. Metrics and
post-run analysis may explicitly join predictions to truth after execution.

## RQ1 versus RQ2 classification records

RQ1/full-pipeline triage is one run-level `TriageResult` over a `LogReadResult` and
is stored in `run_classifications`.

RQ2 stores one `event_classifications` row per frozen dataset item, condition and
run. The dataset item and its evaluation-only truth are separate rows so the same
normalized event can be compared under rule-only, LLM-only and hybrid conditions.

## Patch-attempt retention

Patch attempts are first-class records identified by `(run_id, attempt_number)`.
Earlier rejected or blocked attempts are never overwritten by a later accepted
attempt.

Stored evidence includes prepared diff/hash/size data, branch evidence,
verification stages, acceptance/rejection/block/failure state, and accepted local
branch commit SHA where applicable.

`PatchRetryFeedback` is inert evidence only. When a later milestone provides
feedback, Milestone 15 can correlate its source attempt and receiving attempt; it
does not generate or apply retries.

## Verification evidence and normal-task metric

Milestone 14 patch decisions are unchanged. Milestone 15 adds observational detail:

- functional verification emits typed per-check outcomes;
- M14 still performs the same fixed HTTP checks in the same order and stops after
  the first failed check;
- remaining checks are recorded as `not_run` without performing extra HTTP work;
- security and original-replay stages retain their structured registered
  `TestExecutionResult` as evidence.

This makes the frozen metric

`passed normal functional tests / total normal functional tests`

reproducible without parsing free-form stage text.

## Model calls, tokens and cost

Every model call may be correlated to a run and, where applicable, a classification
observation, patch attempt, or Red attempt.

Token telemetry and monetary-cost telemetry have separate statuses.

Token status:

- `reported`;
- `not_reported`;
- `not_applicable`.

Cost status:

- `provider_reported`;
- `derived`;
- `not_reported`;
- `not_applicable`.

Derived cost requires a pricing version and currency. Missing provider telemetry
remains `NULL/not_reported`; it is never silently converted to zero. A rule-only
condition with no model calls legitimately aggregates to zero calls/tokens/cost.

## Provenance

Each run may persist an immutable version manifest containing:

- framework and baseline commit SHAs;
- prompt-set and per-role prompt versions;
- schema-set version;
- agent/configuration version;
- context-policy version;
- scenario or dataset version;
- rule version;
- test-suite version;
- verification-policy version;
- Python/Docker/Compose/software versions;
- seed where supported.

This records controlled-variable differences instead of hiding them.

## Audit separation

`AuditService` and `data/audit/audit.jsonl` remain the authoritative operational
audit trail. The research database stores only:

- an audit-source reference;
- event/blocked/failed counts;
- first/last event IDs;
- canonical per-run audit digest;
- bounded references for blocked policy events.

Full audit targets/evidence are not copied into research-result tables, and metric
calculation does not rewrite the audit file.

## Scores

The database contains only a future score-record sink. Milestone 15 defines no
scoring formula and research metrics never read score rows. Deterministic Red/Blue
score calculation remains Milestone 16.

## Observational experiment runner

`experiments/runner.py` manages only configuration registration, run lifecycle,
provenance, stage timing/model-call recording, and final run status. It imports no
Red/Blue/Patch flows and dispatches none of these later-milestone variables:

- RQ1 single-agent implementation / experience selection (Milestone 17);
- frozen RQ2 dataset execution (Milestone 18);
- RQ3 structured retry execution (Milestone 19);
- experiment freeze (Milestone 20);
- final controlled experiments (Milestone 21);
- final research analysis (Milestone 22).

## Recomputed research metrics

`experiments/metrics.py` recomputes raw counts/rates from stored rows rather than
persisting authoritative aggregates.

RQ1 support includes:

- patch-attempt acceptance rate;
- eventual repair rate;
- original replay pass rate;
- regression rate;
- classification accuracy;
- source-file and function/route localization accuracy;
- attempts per run;
- time to first patch;
- time to accepted patch;
- total run time;
- model calls/tokens/cost with completeness flags.

RQ2 support includes the fixed five-label confusion matrix and:

- accuracy;
- per-class precision/recall/F1;
- macro F1;
- attack detection rate;
- benign false-positive rate;
- unknown rate;
- classification time;
- model calls/tokens/cost.

Zero-denominator precision/recall/F1 is deterministically reported as `0.0`.

RQ3 support includes:

- second-attempt acceptance rate;
- average attempts to accepted patch;
- repeated-failure rate;
- regression rate;
- time to accepted patch;
- additional retry model calls/tokens/cost.

Red support includes:

- confirmed attack success rate;
- unconfirmed claim rate;
- reproducible-evidence rate;
- duplicate-attempt rate;
- policy violation count;
- requests per confirmed vulnerability;
- time to confirmed vulnerability.

Normal Application Task Success is recomputed independently from typed functional
check rows.

## Failure retention

The schema permits accepted, rejected, policy-blocked, failed and still-running
partial records. A successful later attempt does not erase an earlier failed
attempt. An interrupted `running` record remains available for later completeness
analysis instead of being deleted.

## Milestone boundary

Milestone 15 does not execute real RQ comparisons. It only makes their evidence
persistable and their frozen metrics reproducible. The next roadmap milestones
remain separately gated.


## Verification status

Milestone 15 is technically verified. Final staged Git review and the permanent
Milestone 15 commit remain pending. No final RQ1/RQ2/RQ3 experiment has been run,
and Milestone 16 scoring remains locked.

Authoritative development-laptop verification on 2026-08-29 recorded:

```text
Python compilation: PASS
Full pytest suite: 257 passed, 1 warning
Focused experiment storage: 14 passed
Focused experiment metrics: 7 passed
Schema suite: 24 passed
Milestone 14 verification regression: 23 passed
GitService regression: 21 passed
Combined focused M15/schema/M14 gate: 68 passed
SQLAlchemy schema: PASS — exactly 20 tables
```

The controlled file-backed runtime gate used only
`/tmp/fyp-m15-runtime/research.db` and a separate disposable audit JSONL. It did
not execute agents, Docker, Git patch branches, retries, score formulas, or final
research experiments.

Runtime verification proved:

- all 20 SQLAlchemy tables initialize in a real file-backed SQLite database;
- accepted/rejected RQ1 evidence persists through typed repositories;
- `POLICY_BLOCKED`, `FAILED`, and interrupted `RUNNING` records survive without
  deletion;
- RQ2 classifier-visible items and evaluation-only labels remain separate for all
  five frozen labels;
- RQ3 multiple-attempt and structured-feedback evidence persists without executing
  retry behavior;
- the database closes/reopens successfully with 27 canonical artifacts and every
  artifact SHA-256 revalidates after reopen;
- RQ1, RQ2, RQ3-support, Red, and Normal Application Task Success metrics are
  reproducible from stored raw evidence;
- the synthetic normal-task fixture reproduced 9 passed checks out of 17 stored
  functional checks;
- unknown LLM token/cost telemetry remains `NULL/not_reported` rather than becoming
  zero;
- a future score row can be stored without changing any RQ/Red/normal research
  metric;
- the separate audit JSONL remains authoritative while only its manifest/digest and
  bounded policy reference enter SQLite; full audit target/evidence payloads are not
  copied into the research database.

The disposable runtime database contained the following representative evidence
after reopen:

```text
runs: 11
artifacts: 27
patch_attempts: 7
functional_checks: 17
event_classifications: 16
dataset_items: 6
classification_truth: 6
agent_calls: 13
policy_refs: 1
scores: 1
```

Permanent-repository integrity also passed: branch refs and exact working-tree
status were identical before and after the runtime gate, all 24 Milestone 15 source
files remained byte-identical, no `agent-patch/*` branch appeared, permanent
`data/fyp.db` remained absent, `experiment-results/` remained unchanged, and the
permanent audit state remained unchanged. The permanent repository therefore
remained `main@cf45fc2` throughout runtime verification.
