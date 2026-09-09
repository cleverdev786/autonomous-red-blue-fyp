# Milestone 17 - Experience Memory and RQ1 Single-Agent Baseline

## Status

Milestone 17 is **technically verified with the final staged Git review and commit pending**.

Permanent prerequisite checkpoint:

```text
Milestone 16 commit:
927746e41eca43bb4221dbdd9784ec47f4208cee

Short SHA:
927746e

Commit:
Complete Milestone 16 dashboard and scoring
```

Milestone 17 adds two controlled capabilities:

1. bounded experience summaries and deterministic strategy selection for development/exploratory use;
2. the RQ1 single-agent Blue baseline for comparison with the existing specialized multi-agent Blue architecture.

It does not implement the RQ2 frozen dataset, structured retry feedback, the final experiment freeze, final RQ runs, or results analysis.

---

## 1. Experience Memory Boundary

Experience memory is not a second mutable memory database. `services/experience_store.py` projects a small bounded view from the existing canonical M15/M16 research evidence through `ResearchReadRepository`.

The store reads terminal RQ1 outcomes for the same scenario and trusted strategy identity. Strategy identity comes from the stored run provenance field `agent_configuration_version`; M17 does not invent a family of arbitrary default/conservative/security-first strategy behaviors.

The fixed bound is:

```text
MAX_EXPERIENCE_RECORDS_PER_STRATEGY = 20
```

The stable ordering is:

```text
completed_at DESC
started_at DESC
run_id ASC
```

The ordering version is:

```text
completed_started_run-v1
```

The Blue score input is the already-persisted M16 scoring version:

```text
red-blue-v1
```

The store does not recompute M16 scores.

### ExperienceSummary fields

The bounded summary contains only:

```text
source_run_id
scenario_id
strategy_id
run_status
blue_score | None
patch_accepted
regression_detected
policy_block_count
duplicate_patch_count
attempt_count
```

The schema forbids extra fields. It therefore cannot carry new targets, endpoints, commands, URLs, filesystem paths, tools, permissions, attempt limits, network authority, Git authority, or Docker authority.

### Missing-score rule

A missing Blue score means unknown evidence:

```text
missing score != 0
```

`blue_score` remains `None`. Unscored history is counted as history but is excluded from the mean reward score used for ranking.

The experience projection does not read evaluator ground-truth classification tables.

---

## 2. Experience Modes

M17 supports exactly the existing three `ExperienceMode` values.

### DISABLED

```text
no ExperienceStore lookup
configured trusted strategy must be registered and policy-approved
```

This is the required mode for final primary RQ1/RQ2 evaluations.

### FROZEN_IDENTICAL

```text
use only a caller-supplied immutable ExperienceSnapshot
snapshot scenario must match the current scenario
no live history lookup
```

This mode exists for controlled comparisons where exactly the same frozen history must be supplied.

### ENABLED_EXPLORATORY

```text
load current bounded history from ExperienceStore
rank only registered and policy-approved candidates
```

This mode is for development/exploratory use, not final primary RQ1/RQ2 evaluation.

`ExperimentConfiguration` rejects final RQ1/RQ2 configurations when experience mode is not `DISABLED`.

---

## 3. Deterministic Selection Policy

`orchestrator/selection_policy.py` does not train a model and does not implement reinforcement learning.

Out of scope:

```text
Q-learning
policy gradients
online learning
random exploration
self-modifying agents
learned permission changes
```

The selector first rejects unknown candidates. It then calls:

```text
PolicyEngine.validate_strategy_selection()
```

A strategy is eligible only when it is both:

```text
registered
AND
allowed by current trusted policy
```

Historical reward can never override a policy denial.

For eligible strategies with scored history, ranking is deterministic in this order:

```text
1. higher mean Blue score
2. higher patch acceptance rate
3. lower regression rate
4. fewer policy blocks
5. fewer duplicate patches
6. lower mean attempt count
7. lexical strategy_id tie-break
```

If there is no comparable scored history, the selector uses the configured trusted strategy when it remains eligible. If that strategy is policy-blocked, it uses the first eligible registered strategy in deterministic lexical order.

---

## 4. Canonical Selection Evidence

Every persisted experience-based choice is a typed `SelectionDecision` artifact containing:

```text
run_id
experience_mode
scenario_id
candidate_strategy_ids
eligible_strategy_ids
selected_strategy_id
history_limit_per_strategy
snapshot_sha256 | None
bounded observations
reason
```

Persistence uses the existing `result_artifacts` mechanism:

```text
ArtifactType.SELECTION_DECISION = "selection_decision"
```

The artifact payload is canonical JSON with the existing SHA-256 integrity mechanism. No new SQLAlchemy table is required.

Verified schema count:

```text
20 tables
```

---

## 5. RQ1 Experimental Variable

RQ1 compares:

```text
one general-purpose Blue architecture
vs
specialized multi-agent Blue architecture
```

The intended independent variable is the Blue reasoning architecture only.

`validate_rq1_configuration_pair()` requires paired configurations to match in every stored setting except:

```text
config_id
blue_team_mode
```

That keeps the same research question, scenario, classification configuration, experience mode, retry mode, model/provider settings, limits, and other stored controls.

The runner derives the condition from the stored `ExperimentConfiguration`. `RQ1ExperimentRunner.run()` does not accept a second `blue_team_mode` argument.

---

## 6. Single General Blue Agent

`agents/blue/single_agent.py` defines one logical general-purpose Blue persona:

```text
AgentRole.BLUE_SINGLE_AGENT
```

The same role is used across four bounded reasoning stages:

```text
monitoring
triage/classification
code analysis
patch proposal
```

The response model and typed input adapter may change by stage, but the provider-facing role does not. This prevents the single-agent condition from hiding specialist personas behind one label.

The single-agent adapters replace only the reasoning persona. They inherit the existing:

```text
BlueTeamFlow.run
PatchGenerationFlow.run
```

behavior.

---

## 7. Specialized Multi-Agent Condition

The comparison condition retains the existing specialized roles:

```text
BLUE_MONITORING
BLUE_TRIAGE
BLUE_CODE_ANALYSIS
BLUE_PATCH_GENERATION
```

Both RQ1 conditions explicitly include monitoring before analysis and then normalize into the existing typed Blue/Patch contracts.

M17 does not modify:

```text
orchestrator/blue_team_flow.py
orchestrator/patch_generation_flow.py
orchestrator/scoring.py
storage/models.py
dashboard/*
verification/*
```

---

## 8. Shared Downstream Pipeline

After the Blue reasoning architecture produces normalized evidence, both conditions use the same existing downstream boundaries:

```text
PatchGenerationFlow behavior
PatchBranchFlow / Git isolation
PatchVerificationPipeline
ExperimentWriteRepository
research database
```

Controlled runtime verification injected the same branch-flow object and the same verification-pipeline object into both conditions and confirmed both were called once for their respective development runs.

`proposed_security_test` remains optional. M17 does not introduce a new requirement that every RQ1 patch proposal must contain a generated security test.

The final RQ1 classification mode is not frozen in M17. The single-agent condition rejects `RULE_ONLY` because the general Blue agent must produce the classification output; the final choice between allowed model-involving modes remains an M20 experiment-freeze decision.

---

## 9. Safety Boundary

Experience and the RQ1 single-agent baseline do not gain direct sensitive authority.

Experience may only influence which already-trusted strategy ID is selected. It cannot create or expand:

```text
targets
endpoints
URLs
network destinations
HTTP methods
payload authority
filesystem paths
shell commands
tools
permissions
attempt/runtime limits
Git authority
Docker authority
environment-reset authority
```

PolicyEngine remains authoritative. Existing deterministic services remain responsible for source reading, patch preparation, Git isolation, verification, registered security tests, and storage.

No new vulnerability class or public/real target is introduced.

---

## 10. Automated Verification

Authoritative development-laptop result after applying the M17 implementation:

```text
Focused M17/integration tests:
113 passed, 1 non-failing Starlette warning

Full suite:
286 passed, 1 non-failing Starlette warning

Failures: 0
Errors: 0
Unexpected skips: 0

SQLAlchemy tables:
20
```

The focused gate covers experience selection, RQ1 single-agent behavior, schemas, policy, experiment storage, metrics, scoring, and dashboard integration.

Static safety checks confirmed the new M17 core has no direct subprocess, shell, Git service, controlled-executor, environment-service, HTTP client, or socket authority. No arbitrary example strategy IDs were introduced.

---

## 11. Controlled Experience Runtime Verification

Runtime evidence was created only under:

```text
/tmp/fyp-m17-runtime
```

The experience fixture created 25 terminal development runs for each of two trusted strategy IDs, then exercised the real `ExperienceStore` and `SelectionPolicy`.

Verified results:

```text
20 newest records retained per strategy: PASS
stable ordering on repeated reads: PASS
newest unscored run preserved as blue_score=None: PASS
experience reads changed no DB rows: PASS
experience reads changed no SQLite bytes: PASS
DISABLED performed zero live lookup: PASS
FROZEN_IDENTICAL used supplied snapshot only: PASS
ENABLED_EXPLORATORY used bounded live history: PASS
unscored run excluded from reward average: PASS
higher reward selected when policy allowed: PASS
policy denial overrode higher reward: PASS
unregistered strategy rejected: PASS
SelectionDecision canonical artifact persisted: PASS
artifact SHA-256 revalidated: PASS
SQLAlchemy table count remained 20: PASS
FINAL_EVALUATION configurations: 0
```

---

## 12. Controlled Paired RQ1 Runtime Verification

The RQ1 runtime created two development configurations using the same disposable research database.

They differed only by:

```text
config_id
blue_team_mode
```

Verified single-agent roles:

```text
BLUE_SINGLE_AGENT
BLUE_SINGLE_AGENT
BLUE_SINGLE_AGENT
BLUE_SINGLE_AGENT
```

Verified multi-agent roles:

```text
BLUE_MONITORING
BLUE_TRIAGE
BLUE_CODE_ANALYSIS
BLUE_PATCH_GENERATION
```

Additional results:

```text
runner has no independent blue_team_mode parameter: PASS
stored config selected SINGLE_AGENT: PASS
stored config selected MULTI_AGENT: PASS
paired normalized inputs equivalent: PASS
equivalent normalized patch output: PASS
proposed_security_test optional in both conditions: PASS
single adapter reused BlueTeamFlow.run: PASS
single patch adapter reused PatchGenerationFlow.run: PASS
same downstream branch-flow object used: PASS
same verification-pipeline object used: PASS
same research DB/storage path used: PASS
same canonical artifact stages persisted: PASS
SQLAlchemy tables remained 20: PASS
development configurations only: PASS
```

This runtime gate verifies M17 architecture and condition isolation with controlled development fixtures. It does not repeat the full M13/M14 real Git/Docker remediation campaign because M17 does not change those verified subsystems.

---

## 13. Repository Integrity

After controlled runtime verification:

```text
all 14 M17 source files byte-identical to pre-runtime state: PASS
Git working-tree status unchanged: PASS
branch/ref state unchanged: PASS
runtime VERIFY staged nothing: PASS
HEAD remained permanent M16 927746e: PASS
permanent data/fyp.db remained absent: PASS
git diff --check: PASS
runtime databases and drivers remained under /tmp/fyp-m17-runtime: PASS
```

No final RQ experiment was executed.

---

## 14. Current Gate

```text
DESIGN       PASS
IMPLEMENT    PASS
TEST         PASS
VERIFY       PASS
DOCUMENT     IN PROGRESS / final review pending
COMMIT       PENDING
M18          LOCKED
```

After this documentation change is reviewed, the next action is the exact staged Git review for the complete Milestone 17 scope. Do not start M18 and do not run final RQ experiments until the M17 commit is confirmed.
