# MILESTONES

## Project Title
**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Purpose
This document converts the approved 16-week project plan into small, testable implementation gates.

A milestone is complete only when:
- the required deliverables exist;
- the required tests pass;
- the completion criteria are met;
- the result is recorded in `PROGRESS.md`.

The project must follow:

**DESIGN → IMPLEMENT → TEST → VERIFY → DOCUMENT → COMMIT**

Do not start later features early if the current milestone is not stable.

---

# MILESTONE 0 — PHASE 1 FOUNDATION

## Target Week
Week 1

## Objective
Freeze the academic, research, safety, and architectural foundation before coding begins.

## Required Deliverables
- `PROJECT_CHARTER.md`
- `RESEARCH_PLAN.md`
- `SAFETY_BOUNDARIES.md`
- `ARCHITECTURE.md`
- `MILESTONES.md`
- `PROGRESS.md`

## Completion Criteria
- proposal approved;
- exactly three vulnerability categories are frozen;
- RQ1 and RQ2 are primary;
- RQ3 is secondary;
- deterministic execution boundary is frozen;
- architecture supports all research questions;
- no unresolved contradiction remains between Phase 1 documents.

## Must Not Start Yet
- vulnerable routes;
- attack executor;
- Red Team agents;
- Blue Team agents;
- patch generation;
- dashboard.

---

# MILESTONE 1 — THREAT MODEL AND REPOSITORY FOUNDATION

## Target Week
Week 2

## Objective
Complete the detailed Phase 2 threat model first, then create the minimum project repository structure and Python environment without adding application logic.

## Required Threat-Model Deliverable

```text
docs/architecture/THREAT_MODEL.md
```

The threat model must define at minimum:

- assets to protect;
- trusted and untrusted components;
- data-flow/trust boundaries;
- attacker capabilities inside the dummy environment;
- misuse cases involving LLM outputs;
- network escape risks;
- filesystem/path escape risks;
- Git/patch abuse risks;
- secret leakage risks;
- denial-of-resource/loop risks;
- mitigations mapped to the policy engine and safety tests.

**No application or agent implementation begins until this threat model is reviewed and consistent with `SAFETY_BOUNDARIES.md`.**

## Required Files

```text
README.md
.gitignore
.env.example
pyproject.toml

docs/
orchestrator/
schemas/
services/
llm/
tests/
```

Only directories required for the immediate work should be created.

## Deliverables
- Python package initialized;
- dependency management configured;
- formatting/linting/test commands documented;
- initial environment variables documented;
- empty module imports work;
- basic test runner works.

## Recommended Initial Dependencies
- FastAPI
- Uvicorn
- Pydantic
- SQLAlchemy
- Pytest
- httpx
- GitPython

Optional tooling:
- Ruff

## Tests
- test package imports;
- test configuration loads;
- one trivial test proves `pytest` works.

## Verification
Linux:

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
pytest
```

Windows PowerShell:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
pytest
```

## Completion Criteria
- clean environment can install project;
- `pytest` passes;
- no application logic is required yet;
- repository layout matches architecture.

## Must Not Start Yet
- security-test payload logic;
- LLM agents;
- Git patch automation;
- dashboard.

---

# MILESTONE 2 — CORE SCHEMAS AND CONFIGURATION

## Target Week
Week 2

## Objective
Define typed data contracts before implementing orchestration logic.

## Required Modules

```text
schemas/
├── common.py
├── targets.py
├── red_team.py
├── blue_team.py
├── patches.py
├── verification.py
└── experiments.py
```

## Initial Schemas
At minimum:

- `TargetDefinition`
- `EndpointDefinition`
- `SecurityTestDefinition`
- `ReconnaissanceResult`
- `AttackPlan`
- `TestExecutionResult`
- `AttackVerification`
- `MonitoringResult`
- `TriageResult`
- `CodeFinding`
- `PatchProposal`
- `VerificationResult`
- `PolicyDecision`
- `ExperimentConfiguration`
- `ExperimentRunSummary`

## Tests
- valid example objects parse;
- missing required fields fail;
- invalid classification labels fail;
- invalid target/test identifiers fail where schema-level validation is appropriate;
- serialization round-trip works.

## Completion Criteria
- agent and service boundaries can communicate through typed objects;
- all action-relevant outputs have schemas;
- no agent needs free-form dictionaries for privileged actions.

---

# MILESTONE 3 — DUMMY APPLICATION BASELINE

## Target Week
Week 3

## Objective
Build a normal local FastAPI application before introducing deliberate vulnerabilities.

## Suggested Dummy Application
A small "Vulnerable Store" or student-style portal with simple features such as:

- login;
- product/search page;
- file/document download;
- normal data display.

The app should remain small enough to understand completely.

## Required Structure

```text
dummy_apps/
└── vulnerable_store/
    ├── app/
    ├── tests/
    ├── scenarios/
    ├── Dockerfile
    └── README.md
```

## Deliverables
- FastAPI application;
- SQLite database;
- deterministic seed data;
- normal routes;
- health endpoint;
- functional test suite.

## Tests
At minimum:

- health endpoint works;
- login normal flow works;
- search normal flow works;
- file download normal flow works;
- missing resource errors handled;
- seeded DB state is reproducible.

## Completion Criteria
- all normal functional tests pass;
- no deliberate vulnerability is required yet;
- app can be reset to known data state.

## Must Not Start Yet
- agent-driven testing;
- patch generation;
- dashboard.

---

# MILESTONE 4 — DELIBERATE VULNERABILITY SCENARIOS

## Target Week
Week 4

## Objective
Add exactly one controlled scenario for each approved vulnerability category.

## Required Scenarios
1. SQL Injection
2. Cross-Site Scripting
3. Directory / Path Traversal

## Deliverables
Each scenario must include:

- `scenario_id`;
- vulnerable route;
- vulnerable source location;
- documented root cause;
- expected normal behaviour;
- deterministic security test;
- known secure behaviour;
- reset method;
- baseline Git commit reference;
- ground-truth record.

## Tests
- each scenario is reproducibly vulnerable under its registered test;
- benign functional usage still works;
- test cannot target anything outside the dummy app.

## Completion Criteria
- three ground-truth scenarios exist;
- each has a matching deterministic test;
- each can be restored repeatedly;
- baseline code is committed.

## Must Not Start Yet
- LLM attack execution;
- patch-generation agent.

---

# MILESTONE 5 — DOCKER ISOLATION AND RESET

## Target Week
Week 5

## Objective
Place the dummy app and controlled test path inside a reproducible isolated environment.

## Required Deliverables
- `docker-compose.yml`;
- dummy app container;
- isolated internal network;
- mandatory controlled-executor container for security-test execution;
- health checks;
- reset scripts;
- resource-limit configuration.

## Safety Requirements
- attack/test container has no public internet access;
- no privileged container;
- no Docker socket mounted into agent/test containers;
- no host-home-directory mount;
- only required project paths mounted.

## Tests
- dummy app reachable from controlled executor;
- public internet destination is not reachable from attack executor;
- unregistered container/host is not used;
- reset restores seeded database;
- reset restores Git/application baseline where applicable;
- failed reset prevents next run.

## Completion Criteria
- environment starts from one command;
- environment resets from one command;
- reset is reproducible;
- isolation tests pass.

---

# MILESTONE 6 — TARGET REGISTRY AND POLICY ENGINE

## Target Week
Week 5–6

## Objective
Implement the core safety gate before any autonomous Red Team behaviour.

## Required Modules

```text
services/target_registry.py
orchestrator/policy_engine.py
orchestrator/limits.py
```

## Policy Checks
At minimum:

- registered target;
- registered hostname;
- registered port;
- allowed endpoint;
- allowed method;
- registered test ID;
- source-root boundary;
- patch writable-root boundary;
- workflow-state validity;
- attempt budget;
- timeout budget.

## Tests
Mandatory safety tests:

- unknown target rejected;
- unknown endpoint rejected;
- wrong method rejected;
- unknown test rejected;
- path outside root rejected;
- `../` path escape rejected;
- forbidden patch path rejected;
- invalid state transition rejected;
- attempt limit enforced.

## Completion Criteria
- all sensitive requests can receive a structured `PolicyDecision`;
- blocked actions produce reason codes;
- no controlled executor is allowed to run without policy approval.

---

# MILESTONE 7 — DETERMINISTIC SECURITY-TEST HARNESS

## Target Week
Week 6

## Objective
Create the controlled security testing layer before connecting LLM planning.

## Required Structure

```text
security_tests/
├── base.py
├── registry.py
├── sql_injection/
├── xss/
└── path_traversal/

services/controlled_executor.py
```

## Deliverables
- test registry;
- request templates;
- maximum request counts;
- timeouts;
- success evidence rules;
- structured execution results.

## Tests
- each registered test works only against approved route;
- arbitrary test ID fails;
- request count enforced;
- timeout enforced;
- redirect escape blocked;
- response evidence stored reproducibly.

## Completion Criteria
- all three vulnerabilities can be exercised without an LLM;
- security tests are deterministic and repeatable;
- policy engine controls every request.

---

# MILESTONE 8 — RED TEAM MVP

## Target Week
Week 7

## Objective
Add Red Team reasoning around the already-safe deterministic executor.

## Required Modules

```text
agents/base.py
agents/red/reconnaissance.py
agents/red/attack_planner.py
agents/red/attack_verifier.py

llm/interface.py
llm/mock_provider.py
```

## Deliverables
- common agent interface;
- mock LLM provider;
- reconnaissance result;
- structured attack plan;
- controlled executor integration;
- attack verification;
- Red Team evidence record.

## Initial Flow

```text
Approved Target Metadata
→ Reconnaissance
→ Attack Plan
→ Policy Validation
→ Deterministic Executor
→ Attack Verification
→ Evidence
```

## Tests
- mock agent produces valid plan;
- invalid plan rejected;
- unknown test rejected;
- Red agent cannot directly send HTTP;
- confirmed scenario produces evidence;
- unconfirmed test remains unconfirmed;
- max attempts enforced.

## Completion Criteria
- Red Team full flow works with mock provider;
- all three scenarios can be tested through the orchestrator;
- no LLM has privileged execution authority.

---

# MILESTONE 9 — STRUCTURED LOGGING AND AUDIT SYSTEM

## Target Week
Week 8

## Objective
Create the observable evidence required by the Blue Team and experiments.

## Required Modules

```text
services/log_reader.py
services/audit_service.py
```

Dummy app must emit structured JSON events.

## Required Event Categories
At minimum:

- HTTP request;
- validation event;
- database-related event;
- file-access event;
- application error;
- experiment/audit event.

## Tests
- logs include run ID/request ID;
- current run can be isolated from prior runs;
- malformed logs handled safely;
- blocked policy action produces audit entry;
- successful sensitive action produces audit entry;
- secret/environment values are not logged.

## Completion Criteria
- a confirmed attack produces structured evidence suitable for Blue Team triage;
- audit history explains every sensitive action.

---

# MILESTONE 10 — RULE-BASED DETECTION BASELINE

## Target Week
Week 8

## Objective
Implement the deterministic baseline needed for RQ2.

## Deliverables
- normalized event model;
- rule engine;
- fixed output labels:
  - `sql_injection`
  - `xss`
  - `path_traversal`
  - `benign`
  - `unknown`

## Tests
- known SQLi event classified by rule baseline;
- known XSS event classified;
- known traversal event classified;
- benign events remain benign where expected;
- unknown patterns can return `unknown`.

## Completion Criteria
- rule-only RQ2 condition can run without any LLM;
- classification result is stored.

---

# MILESTONE 11 — BLUE TEAM TRIAGE AND CODE ANALYSIS

## Target Week
Week 9

## Objective
Implement Blue Team detection/classification and source localization.

## Required Modules

```text
agents/blue/monitoring.py
agents/blue/triage.py
agents/blue/code_analysis.py
services/source_reader.py
```

## Deliverables
- normalized monitoring input;
- LLM-only triage mode;
- hybrid triage mode;
- constrained source reader;
- code finding output.

## Tests
- labels outside approved set rejected;
- source reads outside root rejected;
- `.env` and secret-like files rejected;
- correct scenario source file can be provided;
- mock provider can localize a known scenario;
- rule-only, LLM-only and hybrid pathways produce comparable stored outputs.

## Completion Criteria
- RQ2 architecture is operational;
- Blue Team can move from logs to a structured code finding.

---

# MILESTONE 12 — PATCH GENERATION AND PATCH POLICY

## Target Week
Week 10

## Objective
Generate structured remediation proposals without granting the LLM direct write access.

## Required Modules

```text
agents/blue/patch_generation.py
services/patch_service.py
schemas/patches.py
```

## Deliverables
- patch proposal schema;
- approved file list;
- diff generation;
- patch-size controls;
- prohibited-file checks;
- optional security-test proposal.

## Tests
- patch outside writable roots rejected;
- secret/config file modification rejected;
- excessive patch rejected;
- valid small patch accepted by policy;
- LLM cannot write directly to disk.

## Completion Criteria
- patch proposal can be converted to a deterministic diff safely;
- no Git branch work yet depends on arbitrary LLM commands.

---

# MILESTONE 13 — GIT AUTOMATION

## Target Week
Week 11

## Objective
Place every patch attempt on an isolated Git branch while protecting the baseline.

## Required Module

```text
services/git_service.py
```

## Deliverables
- verify clean baseline;
- create patch branch;
- deterministic branch naming;
- inspect diff;
- restore baseline;
- commit accepted patch.

## Mandatory Restrictions
- no automatic merge;
- no agent-controlled push;
- no force push;
- no arbitrary Git command interface.

## Tests
- baseline branch cannot receive generated patch;
- branch created per attempt;
- invalid branch name rejected;
- diff captured;
- restore baseline works;
- automatic merge operation does not exist in agent interface.

## Completion Criteria
- patch attempt is isolated;
- failed patch cannot corrupt baseline;
- clean state can be restored.

---

# MILESTONE 14 — PATCH VERIFICATION PIPELINE

## Target Week
Week 11

## Objective
Complete the core end-to-end remediation loop, including the named Blue Team Patch Verification role implemented through deterministic verification services.

## Required Structure

```text
verification/
├── pipeline.py
├── syntax.py
├── functional.py
├── security.py
├── regression.py
└── decisions.py
```

## Mandatory Verification Order
1. patch policy;
2. path/diff validation;
3. syntax/import checks;
4. application startup;
5. functional tests;
6. relevant security test;
7. original Red Team attack replay;
8. regression tests;
9. deterministic accept/reject decision.

## Tests
- insecure patch rejected;
- patch breaking normal function rejected;
- original attack still working causes rejection;
- safe patch passing all checks accepted;
- accepted patch committed only to generated branch.

## Completion Criteria
The core MVP works end to end:

```text
Attack
→ Detect
→ Classify
→ Locate
→ Patch
→ Branch
→ Verify
→ Accept/Reject
```

## Critical Schedule Gate
**By the end of this milestone, the project must work without the dashboard.**

---

# MILESTONE 15 — EXPERIMENT STORAGE AND METRICS

## Target Week
Week 12

## Objective
Store all data required by the frozen research plan.

## Required Structure

```text
storage/
├── database.py
├── models.py
└── repositories.py

experiments/
├── runner.py
├── configurations/
├── metrics.py
└── analysis.py
```

## Required Stored Data
Must cover all fields defined in `RESEARCH_PLAN.md`, including:

- run condition;
- scenario;
- model;
- prompt version;
- attempts;
- classifications;
- code findings;
- patches;
- verification;
- timings;
- tokens;
- cost;
- audit;
- scores.

## Tests
- complete run can be persisted;
- failed run can be persisted;
- policy-blocked run can be persisted;
- metrics recompute from stored records;
- development/final run types remain distinct.

## Completion Criteria
- all RQ1/RQ2/RQ3 measurements can be reproduced from stored data.

---

# MILESTONE 16 — DASHBOARD AND SCORING

## Target Week
Week 12

## Objective
Add a simple interface for demonstration and experiment visibility.

## Required Structure

```text
dashboard/
├── api/
└── frontend/
```

## Minimum Views
- Overview
- Runs
- Run Detail
- Findings
- Patch Verification
- Metrics
- Audit

## Scoring
Red/Blue scoring must use deterministic stored outcomes.

Research metrics must remain separate from game-style scores.

## Tests
- API returns stored run data;
- dashboard handles failed runs;
- dashboard does not control unsafe operations directly;
- experiment can still run without dashboard.

## Completion Criteria
- complete run can be explained visually;
- dashboard does not block CLI/orchestrator operation.

---

# MILESTONE 17 — EXPERIENCE MEMORY AND RQ1 SINGLE-AGENT BASELINE

## Target Week
Week 13

## Objective
Implement the bounded stored-experience/reward-guided selection mechanism required by the project design, and implement the single-agent comparison condition for RQ1.

## Experience / Selection Deliverables

```text
services/experience_store.py
orchestrator/selection_policy.py
```

The experience mechanism stores bounded outcome summaries and the selector may rank only registered, policy-approved strategies.

It is not reinforcement learning.

For final RQ1/RQ2 experiments, experience-guided selection must be disabled or held identical across compared conditions so it does not confound the primary research variables.

## Experience / Selection Tests
- unregistered strategy cannot be selected;
- experience cannot expand targets/endpoints/tools;
- policy engine still overrides selection;
- duplicate/policy-blocked outcomes can be penalized;
- selection reason is recorded;
- feature can be disabled for frozen primary experiments.

## RQ1 Objective
Implement the comparison condition for RQ1.

## Deliverable
A single general-purpose Blue Team agent that produces:

- classification;
- source localization;
- root cause;
- patch proposal;
- security-test proposal.

Everything after the proposal must reuse the same:

- policy engine;
- patch service;
- Git service;
- verification pipeline;
- storage.

## Tests
- same scenario can run in single-agent or multi-agent mode;
- condition is stored correctly;
- same acceptance rules apply to both.

## Completion Criteria
RQ1 experiment runner can switch conditions without changing core safety or verification logic.

---

# MILESTONE 18 — RQ2 FROZEN CLASSIFICATION DATASET

## Target Week
Week 13

## Objective
Create the final labelled event dataset.

## Minimum Dataset
- 10 SQL Injection events
- 10 XSS events
- 10 Path Traversal events
- 30 benign events

Total: **60**

## Preferred Dataset
Total: **120**

## Deliverables
- event IDs;
- ground-truth labels;
- frozen normalized input;
- dataset version;
- generation/source notes.

## Tests
- no ground-truth label leaks into classifier input;
- same dataset feeds all three classification modes;
- confusion matrix generation works.

## Completion Criteria
RQ2 final evaluation can run from one frozen dataset version.

---

# MILESTONE 19 — RQ3 STRUCTURED FEEDBACK RETRY

## Target Week
Week 13–14

## Objective
Implement the optional secondary research condition.

## Deliverables
Two retry modes:

1. no structured failure feedback;
2. structured failure feedback.

Structured feedback may contain:

- failed verification stage;
- test ID;
- sanitized error/assertion summary;
- replay outcome;
- regression failures;
- prior diff summary;
- policy rejection reason.

## Tests
- raw arbitrary shell output not forwarded;
- condition stored;
- attempt budget still enforced;
- RQ3 can be disabled without affecting MVP.

## Completion Criteria
Secondary experiment is runnable if schedule allows.

---

# MILESTONE 20 — EXPERIMENT FREEZE

## Target Week
Week 14

## Objective
Freeze the system before final evaluation.

## Freeze Items
- scenario versions;
- baseline commits;
- prompts;
- schemas;
- rule definitions;
- model settings;
- test suites;
- acceptance criteria;
- experiment configurations;
- analysis scripts.

## Deliverables
- version manifest;
- final experiment configuration files;
- clean tagged/committed baseline.

## Completion Criteria
No development tuning occurs inside final-evaluation runs.

Any later change requires:
- a new experiment version; or
- repetition of affected runs.

---

# MILESTONE 21 — FINAL CONTROLLED EXPERIMENTS

## Target Week
Week 14

## Objective
Run the final research evaluation.

## RQ1 Minimum
3 scenarios × 2 conditions × 3 repetitions = **18 runs**

## RQ1 Preferred
6 scenarios × 2 conditions × 5 repetitions = **60 runs**

## RQ2 Minimum
60 labelled events × 3 classifier conditions.

## RQ3
Run only if core experiments and analysis pipeline are stable.

## Rules
- environment reset between independent runs;
- failures retained;
- system errors retained and marked;
- no cherry-picking;
- all versions recorded.

## Completion Criteria
- frozen result dataset exported;
- raw results preserved;
- no missing required metric fields.

---

# MILESTONE 22 — RESULTS ANALYSIS

## Target Week
Week 15

## Objective
Answer the research questions using the frozen experiment data.

## Required Outputs
RQ1:
- patch acceptance;
- regression;
- localization accuracy;
- attempts;
- time;
- model calls;
- token/cost comparison.

RQ2:
- confusion matrices;
- accuracy;
- macro F1;
- per-class precision/recall/F1;
- benign false-positive rate;
- runtime/model cost.

RQ3 if completed:
- second-attempt acceptance;
- repeated failures;
- time and token overhead.

## Required Visuals
Recommended:

- patch acceptance comparison;
- regression comparison;
- time-to-patch comparison;
- model-cost comparison;
- classifier confusion matrices;
- classification metric comparison;
- per-vulnerability comparison.

## Completion Criteria
Each primary research question has a direct evidence-based answer.

---

# MILESTONE 23 — FINAL REPORT

## Target Week
Week 15

## Objective
Complete the academic dissertation/report.

## Suggested Chapters
1. Introduction
2. Problem Statement and Motivation
3. Literature Review
4. Requirements and Scope
5. Methodology
6. System Architecture
7. Implementation
8. Experimental Design
9. Results
10. Discussion
11. Safety, Ethics, and Limitations
12. Conclusion and Future Work

## Completion Criteria
- figures/tables match actual implementation;
- research questions answered;
- failures and limitations reported;
- no claim exceeds experiment evidence.

---

# MILESTONE 24 — FINAL DEMONSTRATION

## Target Week
Week 16

## Objective
Prepare a reliable live demonstration.

## Recommended Demo Sequence
1. show isolated Docker environment;
2. reset to baseline;
3. start one scenario;
4. Red Team plan;
5. deterministic test execution;
6. confirmed evidence;
7. Blue Team triage;
8. source-code finding;
9. patch proposal;
10. generated Git branch;
11. verification pipeline;
12. accept/reject result;
13. dashboard;
14. research comparison.

## Backup
Prepare a recorded demonstration of the final frozen build.

## Completion Criteria
- demo works from a clean environment;
- backup demo exists;
- no internet-dependent feature is required for basic demonstration.

---

# MILESTONE 25 — PRESENTATION AND VIVA

## Target Week
Week 16

## Objective
Prepare to explain both the engineering and research contribution.

## Presentation Must Cover
- problem;
- motivation;
- system design;
- why multi-agent;
- why deterministic execution;
- security boundaries;
- Red Team flow;
- Blue Team flow;
- patch verification;
- research questions;
- experiment method;
- results;
- limitations;
- future work.

## Viva Preparation Topics
Be prepared to explain:

- difference between agent reasoning and tool execution;
- why the framework is not an unrestricted hacking system;
- why SQLite was sufficient;
- why a custom orchestrator was used;
- why patch acceptance is deterministic;
- why RQ1 is a fair comparison;
- why RQ2 includes benign events;
- what causes false positives;
- what causes regressions;
- threats to validity;
- why full reinforcement learning was excluded.

## Completion Criteria
- final slides ready;
- demo script ready;
- expected viva questions rehearsed;
- final repository tag/release created.

---

# 16-WEEK SUMMARY

| Week | Main Milestones |
|---|---|
| 1 | Phase 1 foundation |
| 2 | Repository, schemas, configuration |
| 3 | Dummy application baseline |
| 4 | Three vulnerable scenarios |
| 5 | Docker isolation, reset, policy foundation |
| 6 | Test harness and policy completion |
| 7 | Red Team MVP |
| 8 | Structured logging and rule baseline |
| 9 | Blue triage and code analysis |
| 10 | Patch generation and patch policy |
| 11 | Git automation and verification pipeline |
| 12 | Storage, metrics, dashboard |
| 13 | RQ1/RQ2 experiment configurations |
| 14 | RQ3 if possible, freeze, final experiments |
| 15 | Analysis and report |
| 16 | Demo, presentation, viva |

---

# CRITICAL DELIVERY GATES

## Gate A — Before Red Team Agents
Must already have:
- target registry;
- policy engine;
- deterministic security tests;
- isolated local target;
- request limits.

## Gate B — Before Patch Generation
Must already have:
- structured logs;
- Blue classification;
- source reader restrictions;
- patch path policy.

## Gate C — Before Final Experiments
Must already have:
- full end-to-end pipeline;
- reset;
- experiment storage;
- frozen prompts/rules/scenarios;
- all mandatory safety tests passing.

## Gate D — Before Dashboard Polish
Must already have:
- working end-to-end MVP without dashboard.

---

# SCOPE-PROTECTION RULES

The following should be postponed until the core milestones are complete:

- extra vulnerability classes;
- multiple dummy applications;
- full reinforcement learning;
- autonomous target discovery;
- advanced dashboard animation;
- cloud deployment;
- automatic patch merging;
- production CI integration;
- complex distributed agent frameworks.

A new feature should be accepted only when it directly supports:
- the approved proposal;
- an approved research question; or
- the reliability/safety of the MVP.

---

# MILESTONE TRACKING RULE

For each milestone, `PROGRESS.md` should record:

```text
Milestone:
Status:
Date Started:
Date Completed:
Files Added:
Files Changed:
Tests Added:
Verification Result:
Known Issues:
Next Milestone:
```

No milestone should be marked complete only because code was written.

It is complete when its defined tests and completion criteria pass.

---

## Milestone Plan Status
**FROZEN FOR PHASE 1**
