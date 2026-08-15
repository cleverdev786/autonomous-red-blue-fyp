# ARCHITECTURE

## Project Title
**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Phase
**Phase 1 — Proposal, Objectives, Research Questions, Scope, and Ethics**

## Architecture Status
**FROZEN FOR PHASE 1**

This document maps the approved project charter, research plan, and safety boundaries into a concrete system design.

---

# 1. Architecture Goals

The architecture must satisfy five goals simultaneously:

1. **Safety**
   - LLMs must never directly control unrestricted network, shell, Docker, Git, or filesystem operations.

2. **Reproducibility**
   - Every experiment must be repeatable from a known application, database, container, and Git baseline.

3. **Research Validity**
   - Single-agent, multi-agent, rule-only, LLM-only, hybrid, and feedback conditions must reuse the same core system wherever possible.

4. **Maintainability**
   - Modules should remain small, explicit, typed, and understandable for a BS-level project.

5. **Demonstrability**
   - The full workflow should be visible and explainable during the final demo and viva.

---

# 2. High-Level System Architecture

```text
┌───────────────────────────────────────────────────────────────┐
│                    React Results Dashboard                    │
│ Runs | Findings | Patches | Tests | Metrics | Scores | Audit │
└──────────────────────────────┬────────────────────────────────┘
                               │
                               │ local read/control API
                               ▼
┌───────────────────────────────────────────────────────────────┐
│                       Dashboard API                           │
│               FastAPI routes for local UI                     │
└──────────────────────────────┬────────────────────────────────┘
                               │
                               ▼
┌───────────────────────────────────────────────────────────────┐
│                     CENTRAL ORCHESTRATOR                      │
│                                                               │
│  State Machine                                                │
│  Policy Engine                                                │
│  Experiment Manager                                           │
│  Agent Router                                                 │
│  Attempt / Time Limits                                        │
│  Scoring                                                      │
│  Audit Coordination                                           │
└───────────────┬───────────────────────────────┬───────────────┘
                │                               │
                │ structured prompts/results    │ deterministic calls
                ▼                               ▼
┌─────────────────────────────┐      ┌──────────────────────────┐
│         LLM AGENTS          │      │ DETERMINISTIC SERVICES   │
│                             │      │                          │
│ Red Team                    │      │ Target Registry          │
│ - Reconnaissance            │      │ Controlled Test Executor │
│ - Attack Planner            │      │ Log Reader               │
│ - Attack Verifier           │      │ Source Reader            │
│                             │      │ Patch Service            │
│ Blue Team                   │      │ Git Service              │
│ - Monitoring               │      │ Test Runner              │
│ - Triage                   │      │ Environment Service      │
│ - Code Analysis            │      │ Audit Service            │
│ - Patch Generation         │      │ Metrics Service          │
└──────────────┬──────────────┘      └──────────────┬───────────┘
               │                                      │
               │ no direct privileged action          │ approved operations only
               └──────────────────────┬───────────────┘
                                      ▼
                         ┌──────────────────────────┐
                         │    DUMMY APP SANDBOX     │
                         │                          │
                         │ FastAPI app              │
                         │ SQLite database          │
                         │ Structured JSON logs     │
                         │ Vulnerable scenarios     │
                         │ Functional tests         │
                         │ Security tests           │
                         └─────────────┬────────────┘
                                       │
                                       ▼
                         ┌──────────────────────────┐
                         │ PATCH / VERIFY SANDBOX   │
                         │                          │
                         │ Working Git branch       │
                         │ Restricted source tree   │
                         │ Pytest                   │
                         │ Attack replay            │
                         │ Regression suite         │
                         └─────────────┬────────────┘
                                       │
                                       ▼
                         ┌──────────────────────────┐
                         │  EXPERIMENT DATA STORE   │
                         │                          │
                         │ Runs                     │
                         │ Events                   │
                         │ Agent outputs            │
                         │ Patches                  │
                         │ Test results             │
                         │ Metrics                  │
                         │ Audit records            │
                         └──────────────────────────┘
```

---

# 3. Architectural Trust Boundary

The architecture is intentionally divided into:

## 3.1 Untrusted Reasoning Layer

Contains all LLM-backed agents.

LLM agents may:

- interpret approved context;
- classify;
- plan;
- recommend;
- produce structured patch proposals;
- explain reasoning in bounded outputs.

LLM agents may not directly:

- run arbitrary commands;
- send arbitrary HTTP requests;
- write arbitrary files;
- manipulate Git directly;
- control Docker directly;
- merge branches;
- access host files;
- select arbitrary network targets.

## 3.2 Trusted Control Layer

Contains deterministic code.

The trusted layer decides:

- whether a target is valid;
- whether an endpoint is valid;
- whether a test is registered;
- whether a requested file is readable;
- whether a patch path is writable;
- whether the current workflow transition is legal;
- whether a request may be executed;
- whether a patch passes verification;
- whether the run must stop.

---

# 4. Runtime Components

The MVP should use a small number of clearly separated runtime components.

## 4.1 Orchestrator Process

Primary Python process.

Responsibilities:

- manage experiment runs;
- manage workflow state;
- route agent calls;
- validate agent outputs;
- call deterministic services;
- enforce limits;
- store results;
- calculate scores;
- expose run state to the local dashboard API.

Recommended technology:

- Python
- Pydantic
- SQLAlchemy
- FastAPI for local orchestration/dashboard endpoints where useful

## 4.2 Dummy Application Container

Contains:

- FastAPI vulnerable application;
- SQLite database or application-local DB file;
- structured request/security logging;
- deterministic seeded data;
- application functionality;
- vulnerable routes.

The application should not contain the orchestration logic.

## 4.3 Controlled Test Executor Container

**Mandatory for security-test execution in the MVP.**

The controlled executor must run in a network-isolated container so that the security-testing path is physically separated from any orchestrator process that may communicate with an optional cloud LLM provider.

Responsibilities:

- execute registered HTTP security-test templates;
- talk only to the registered dummy application;
- enforce request timeout;
- enforce request count;
- return structured results.

This container must have no outbound public internet access.

## 4.4 Verification Environment

A controlled working tree/branch where generated patches are tested.

It may reuse the dummy application build where practical, but conceptually it is separate from the baseline.

Responsibilities:

- apply approved patch;
- build/start application if required;
- run test suites;
- replay original Red Team test;
- return deterministic pass/fail result.

## 4.5 Dashboard Frontend

React + Vite.

The dashboard should remain a presentation/readout layer rather than a security-control layer.

Its first version should show:

- run list;
- current state;
- confirmed finding;
- classification;
- source location;
- patch diff summary;
- verification results;
- score;
- timings;
- experiment metrics.

---

# 5. Central Orchestrator

The orchestrator is the core coordination component.

It should not itself contain all business logic.

Instead it coordinates dedicated modules.

Recommended internal modules:

```text
orchestrator/
├── main.py
├── workflow.py
├── state_machine.py
├── policy_engine.py
├── limits.py
├── agent_router.py
├── scoring.py
└── errors.py
```

## 5.1 Responsibilities

The orchestrator:

1. creates an experiment run;
2. checks that the environment is reset;
3. loads target/scenario configuration;
4. enters the correct workflow state;
5. calls the required agent;
6. validates structured output;
7. asks policy engine for authorization;
8. calls deterministic service;
9. records evidence/result;
10. transitions state;
11. enforces retry and attempt limits;
12. terminates in a defined terminal state.

## 5.2 What the Orchestrator Must Not Do

Avoid turning `workflow.py` into a giant file that:

- sends raw HTTP;
- edits files;
- runs Git;
- executes tests;
- parses every log;
- performs database logic directly.

Those responsibilities belong to dedicated services.

---

# 6. State Machine

The system must use an explicit finite-state workflow.

Recommended states:

```text
CREATED
ENVIRONMENT_PREPARING
READY
RECONNAISSANCE
ATTACK_PLANNING
ATTACK_EXECUTING
ATTACK_VERIFYING
BLUE_MONITORING
TRIAGE
CODE_ANALYSIS
PATCH_GENERATING
PATCH_VALIDATING
PATCH_BRANCH_CREATING
PATCH_APPLYING
PATCH_VERIFYING
ACCEPTED
REJECTED
FAILED
POLICY_BLOCKED
COMPLETED
```

## 6.1 Normal Flow

```text
CREATED
   ↓
ENVIRONMENT_PREPARING
   ↓
READY
   ↓
RECONNAISSANCE
   ↓
ATTACK_PLANNING
   ↓
ATTACK_EXECUTING
   ↓
ATTACK_VERIFYING
   │
   ├── unconfirmed → next bounded attack attempt / REJECTED
   │
   └── confirmed
          ↓
BLUE_MONITORING
   ↓
TRIAGE
   ↓
CODE_ANALYSIS
   ↓
PATCH_GENERATING
   ↓
PATCH_VALIDATING
   ↓
PATCH_BRANCH_CREATING
   ↓
PATCH_APPLYING
   ↓
PATCH_VERIFYING
   │
   ├── failed → bounded retry or REJECTED
   └── passed → ACCEPTED
                    ↓
                COMPLETED
```

## 6.2 Terminal States

- `COMPLETED`
- `FAILED`
- `POLICY_BLOCKED`

`ACCEPTED` and `REJECTED` may either be final patch states or transition into `COMPLETED`.

---

# 7. Policy Engine

Recommended location:

```text
orchestrator/policy_engine.py
```

The policy engine should expose specific validation functions.

Examples:

```text
validate_target(...)
validate_endpoint(...)
validate_http_method(...)
validate_test(...)
validate_source_read(...)
validate_patch_path(...)
validate_patch_size(...)
validate_git_operation(...)
validate_state_transition(...)
validate_attempt_budget(...)
```

The policy engine returns a structured decision such as:

```text
allowed: bool
reason_code: str
message: str
```

The executor or service must not run before receiving an allowed decision.

---

# 8. Target Registry

Recommended location:

```text
services/target_registry.py
```

A target registry should define all approved application targets.

Example conceptual configuration:

```yaml
target_id: vulnerable_store
container_name: fyp-vulnerable-store
hostname: vulnerable-store
port: 8000
scheme: http

allowed_endpoints:
  - /login
  - /search
  - /files/{name}

allowed_methods:
  /login: [POST]
  /search: [GET]
  /files/{name}: [GET]

allowed_tests:
  - sqli_login_001
  - xss_search_001
  - traversal_file_001

source_root: dummy_apps/vulnerable_store/
writable_patch_roots:
  - dummy_apps/vulnerable_store/app/
  - dummy_apps/vulnerable_store/tests/
```

The final file format may use YAML, JSON, or typed Python/Pydantic configuration.

---

# 9. Agent Interface

All agents should implement a small shared interface.

Recommended:

```text
agents/base.py
```

Conceptual interface:

```python
class Agent:
    def run(self, context: AgentContext) -> AgentResult:
        ...
```

Actual implementation should be async only if needed.

Every agent receives:

- role-specific approved context;
- current run ID;
- scenario ID;
- allowed labels/options;
- model configuration.

Every agent returns a Pydantic model.

---

# 10. Red Team Architecture

Recommended files:

```text
agents/red/
├── reconnaissance.py
├── attack_planner.py
└── attack_verifier.py
```

## 10.1 Reconnaissance Agent

Input:

- approved application manifest;
- approved endpoint metadata;
- known fields;
- bounded previous-attempt summaries.

Output:

```text
ReconnaissanceResult
```

Possible fields:

```text
candidate_endpoints
input_fields
candidate_test_categories
rationale
```

It does not scan arbitrary networks.

## 10.2 Attack Planning Agent

Input:

- reconnaissance result;
- registered tests;
- attempt history;
- allowed vulnerability classes.

Output:

```text
AttackPlan
```

Fields should include:

```text
test_id
target_id
endpoint_id
vulnerability_class
parameter_choices
rationale
```

## 10.3 Controlled Test Executor

Not an LLM agent.

Recommended file:

```text
services/controlled_executor.py
```

Responsibilities:

- validate test ID;
- validate endpoint/method;
- instantiate registered request template;
- enforce timeout and request limits;
- execute request;
- return structured evidence.

Output:

```text
TestExecutionResult
```

## 10.4 Attack Verification Agent

Input:

- execution result;
- registered success criteria;
- relevant evidence.

Output:

```text
AttackVerification
```

Fields:

```text
confirmed
confidence
evidence_ids
reason
```

Final confirmation should use deterministic success evidence where possible.

---

# 11. Blue Team Architecture

Recommended files:

```text
agents/blue/
├── monitoring.py
├── triage.py
├── code_analysis.py
└── patch_generation.py
```

## 11.1 Monitoring Agent

Reads normalized structured events from the current run.

The deterministic log reader should first collect/normalize logs.

Recommended service:

```text
services/log_reader.py
```

Monitoring output:

```text
MonitoringResult
```

## 11.2 Triage Agent

Input:

- normalized logs;
- approved labels;
- optional deterministic rule findings.

Output:

```text
TriageResult
```

Fields:

```text
is_suspicious
classification
confidence
supporting_event_ids
reason
```

Allowed classification labels:

```text
sql_injection
xss
path_traversal
benign
unknown
```

## 11.3 Code Analysis Agent

Input:

- triage result;
- approved source files/snippets;
- route metadata;
- relevant logs.

Output:

```text
CodeFinding
```

Fields:

```text
file_path
function_or_route
root_cause
supporting_lines
confidence
```

The agent does not browse the entire host filesystem.

## 11.4 Patch Generation Agent

Input:

- confirmed finding;
- approved code context;
- required security behaviour;
- optional structured retry feedback.

Output:

```text
PatchProposal
```

Fields:

```text
files
changes
security_rationale
test_plan
expected_effect
regression_risks
```

The output is a proposal, not a direct disk write.

## 11.5 Patch Verification Agent / Verification Role

The project specification names Patch Verification as a Blue Team role. In the MVP, this role is deliberately implemented as a **controlled deterministic verification role** rather than an LLM with privileged execution access.

It is backed by:

```text
verification/pipeline.py
verification/decisions.py
services/test_runner.py
services/controlled_executor.py
```

Responsibilities:

- request only registered verification stages;
- consume structured test results;
- replay the original confirmed Red Team test through the controlled executor;
- collect functional, security, replay, and regression outcomes;
- provide a structured verification explanation for audit/display;
- return the deterministic final decision produced by the verification decision engine.

The Patch Verification role cannot:

- invent shell commands;
- bypass tests;
- change acceptance criteria;
- approve its own patch based on an LLM opinion;
- merge a branch.

This preserves the named Blue Team role while keeping final patch acceptance reproducible and safe.

---

# 12. Source Reader

Recommended file:

```text
services/source_reader.py
```

The source reader is a deterministic service.

Responsibilities:

- resolve paths;
- ensure path is inside approved source root;
- reject denylisted files;
- limit bytes/lines returned;
- log every read.

It should provide agents only the minimum required source context.

---

# 13. Patch Service

Recommended file:

```text
services/patch_service.py
```

Responsibilities:

1. validate proposed paths;
2. validate patch format;
3. enforce max file count;
4. enforce diff size;
5. reject prohibited files;
6. produce a deterministic diff;
7. apply approved changes to the current patch branch;
8. store patch metadata.

The patch service should not decide whether a patch is secure.

The verification pipeline decides acceptance.

---

# 14. Git Service

Recommended file:

```text
services/git_service.py
```

Allowed operations:

- verify clean baseline;
- inspect current branch;
- create patch branch;
- compute diff;
- commit accepted patch;
- restore working tree;
- return to baseline.

Not allowed:

- automatic merge;
- agent-controlled force push;
- agent-controlled remote push;
- arbitrary Git commands from LLM output.

Recommended branch name:

```text
agent-patch/<run_id>/<attempt_id>
```

---

# 15. Verification Pipeline

Recommended directory:

```text
verification/
├── pipeline.py
├── syntax.py
├── functional.py
├── security.py
├── regression.py
└── decisions.py
```

## 15.1 Verification Order

```text
Patch Policy Check
        ↓
Path / Diff Validation
        ↓
Syntax / Import Check
        ↓
Application Startup Check
        ↓
Functional Tests
        ↓
Relevant Security Test
        ↓
Original Red Attack Replay
        ↓
Regression Tests
        ↓
Final Deterministic Decision
```

## 15.2 Acceptance Rule

Every mandatory stage must pass.

The decision engine should return:

```text
ACCEPTED
REJECTED
```

with structured reasons.

---

# 16. Environment Service

Recommended file:

```text
services/environment_service.py
```

Responsibilities:

- verify Docker environment is available;
- start registered project services;
- stop registered project services;
- reset database/application fixtures;
- restore baseline Git state;
- wait for local health check;
- fail safely if reset is incomplete.

The environment service should never expose generic Docker command execution to an agent.

---

# 17. Audit Service

Recommended file:

```text
services/audit_service.py
```

Audit events should be append-oriented.

Every sensitive action records:

```text
event_id
timestamp
run_id
component
actor_type
operation
target
policy_decision
policy_reason
execution_status
duration_ms
evidence_reference
error_code
```

Audit logging should occur for both:

- successful operations;
- blocked operations.

---

# 18. Experiment Manager

Recommended directory:

```text
experiments/
├── runner.py
├── configurations/
├── metrics.py
└── analysis.py
```

Responsibilities:

- load frozen experiment configuration;
- create run IDs;
- select condition;
- execute repetitions;
- store model/config metadata;
- mark development vs final evaluation;
- export experiment results.

---

# 19. Experiment Database

Recommended initial database:

**SQLite**

Use SQLAlchemy so the storage layer is not tightly coupled to raw SQL.

Suggested core tables:

## 19.1 `experiment_runs`

Fields:

```text
id
run_type
research_question
condition
scenario_id
status
started_at
completed_at
baseline_commit
model_provider
model_name
prompt_version
seed
total_runtime_ms
policy_violation_count
```

## 19.2 `agent_calls`

```text
id
run_id
agent_role
model_name
started_at
duration_ms
input_tokens
output_tokens
estimated_cost
result_status
```

## 19.3 `security_tests`

```text
id
run_id
test_id
attempt_number
vulnerability_class
execution_status
confirmed
evidence_reference
duration_ms
```

## 19.4 `classifications`

```text
id
run_id
condition
predicted_label
ground_truth_label
confidence
duration_ms
```

## 19.5 `code_findings`

```text
id
run_id
file_path
function_or_route
ground_truth_file
ground_truth_function
confidence
```

## 19.6 `patch_attempts`

```text
id
run_id
attempt_number
branch_name
diff_reference
status
rejection_reason
files_changed
insertions
deletions
```

## 19.7 `verification_results`

```text
id
patch_attempt_id
syntax_passed
startup_passed
functional_passed
security_passed
replay_passed
regression_passed
accepted
duration_ms
```

## 19.8 `audit_events`

Fields defined by the safety document.

This schema is conceptual and may be normalized during implementation.

---

# 20. Structured Application Logging

The dummy application should output structured JSON events.

Example conceptual event:

```json
{
  "timestamp": "...",
  "run_id": "...",
  "request_id": "...",
  "event_type": "http_request",
  "route": "/search",
  "method": "GET",
  "status_code": 200,
  "security_features": {},
  "error_type": null
}
```

Sensitive raw values should be minimized or sanitized.

Separate security-relevant event types may include:

```text
http_request
validation_failure
database_query_event
file_access_event
application_error
authentication_event
```

The exact schema will be frozen during the logging implementation phase.

---

# 21. LLM Provider Abstraction

Recommended directory:

```text
llm/
├── interface.py
├── mock_provider.py
├── local_provider.py
├── cloud_provider.py
├── response_validation.py
└── prompts/
```

## 21.1 Common Provider Interface

Conceptually:

```python
class LLMProvider:
    def generate(self, request: LLMRequest) -> LLMResponse:
        ...
```

The agent layer should not contain provider-specific API logic.

## 21.2 Mock Provider

Mandatory.

Uses predetermined structured outputs for:

- unit tests;
- integration tests;
- deterministic demos;
- CI;
- debugging without model cost.

## 21.3 Local Provider

Optional where practical for final experiments.

## 21.4 Cloud Provider

Optional for difficult analysis/patch generation.

Provider API secrets stay outside agent prompts and experiment outputs.

---

# 22. Prompt and Schema Versioning

Every final evaluation run should record:

```text
prompt_version
schema_version
rule_version
scenario_version
```

Recommended prompt layout:

```text
llm/prompts/
├── red_recon/
├── red_plan/
├── red_verify/
├── blue_monitor/
├── blue_triage/
├── blue_code_analysis/
└── blue_patch/
```

Prompt text should be frozen before final experiments begin.

---

# 23. Research Configuration Architecture

The architecture must support RQ1, RQ2, and RQ3 without duplicating the system.

---

# 24. RQ1 Architecture — Single Agent vs Multi-Agent

## Condition A: Single-Agent Blue Team

Reuse:

- same target;
- same logs;
- same source reader;
- same patch service;
- same Git service;
- same verification pipeline;
- same safety policy.

Difference:

```text
Blue evidence
     ↓
Single General Blue Agent
     ↓
Classification + Code Finding + Patch Proposal
```

## Condition B: Multi-Agent Blue Team

```text
Blue evidence
     ↓
Monitoring
     ↓
Triage
     ↓
Code Analysis
     ↓
Patch Generation
```

Everything after patch proposal remains identical.

This is essential for a fair comparison.

---

# 25. RQ2 Architecture — Classification Modes

## Rule-Only

```text
Structured Logs
     ↓
Deterministic Rule Engine
     ↓
Classification
```

## LLM-Only

```text
Structured Logs
     ↓
LLM Triage Agent
     ↓
Classification
```

## Hybrid

```text
Structured Logs
     ↓
Rule Feature Extraction
     ↓
LLM Triage Agent
     ↓
Classification
```

All three use:

- same event dataset;
- same allowed labels;
- same evaluation code.

---

# 26. RQ3 Architecture — Feedback-Guided Retry

Only affects patch retry context.

## No Feedback

```text
Original Finding
     ↓
Patch Generator Retry
```

## Structured Feedback

```text
Original Finding
Failed Verification Result
Sanitized Test Failure Summary
Prior Diff Summary
     ↓
Patch Generator Retry
```

No raw unrestricted shell output is forwarded.

---

# 26A. Stored Experience and Reward-Guided Selection

The MVP will include a deliberately small experience mechanism instead of full reinforcement learning.

Recommended modules:

```text
services/experience_store.py
orchestrator/selection_policy.py
```

## Experience Store

Stores bounded outcome summaries such as:

```text
experience_id
scenario_or_class
strategy_id
agent_role
confirmed_success
patch_accepted
regression_detected
score
policy_blocked
attempt_count
```

It should store summaries and references, not unrestricted hidden model state.

## Selection Policy

The selector may rank only registered candidate strategies or agent configurations using stored deterministic outcomes.

A simple policy is sufficient, for example:

1. filter to registered strategies allowed by policy;
2. calculate historical average reward/success for the relevant scenario class;
3. penalize duplicate or policy-blocked strategies;
4. choose the highest-ranked candidate with a deterministic tie-break;
5. record why it was selected.

This is **reward-guided selection**, not reinforcement-learning training.

## Safety Rule

Experience can influence **which approved option is selected**, but never what actions are permitted.

The policy engine remains authoritative.

## Research Rule

For final RQ1 and RQ2 comparisons, experience-guided selection must be disabled or held identical across compared conditions so it does not become an uncontrolled experimental variable.

---

# 27. Dashboard Architecture

Recommended structure:

```text
dashboard/
├── api/
└── frontend/
```

## 27.1 API Responsibilities

The dashboard API may expose:

- run list;
- run details;
- findings;
- patch attempts;
- verification status;
- experiment metrics;
- scores;
- audit events.

The first version may also expose limited local controls such as:

- start registered experiment;
- cancel current experiment;
- reset registered environment.

Any control action must route through the orchestrator and policy layer.

## 27.2 Frontend Pages

Minimum:

```text
Overview
Runs
Run Detail
Patch Verification
Experiments
Metrics
Audit
```

The dashboard must not become a dependency for core experiment execution.

A CLI or direct orchestrator command should still be able to execute experiments.

---

# 28. Recommended Repository Structure

```text
autonomous-red-blue-fyp/
├── README.md
├── .gitignore
├── .env.example
├── pyproject.toml
├── docker-compose.yml
│
├── docs/
│   ├── phase-1/
│   │   ├── PROJECT_CHARTER.md
│   │   ├── RESEARCH_PLAN.md
│   │   ├── SAFETY_BOUNDARIES.md
│   │   ├── ARCHITECTURE.md
│   │   ├── MILESTONES.md
│   │   └── PROGRESS.md
│   ├── architecture/
│   ├── experiments/
│   ├── report/
│   ├── presentation/
│   └── viva/
│
├── orchestrator/
│   ├── __init__.py
│   ├── main.py
│   ├── workflow.py
│   ├── state_machine.py
│   ├── policy_engine.py
│   ├── agent_router.py
│   ├── limits.py
│   ├── scoring.py
│   └── errors.py
│
├── agents/
│   ├── __init__.py
│   ├── base.py
│   ├── red/
│   │   ├── reconnaissance.py
│   │   ├── attack_planner.py
│   │   └── attack_verifier.py
│   └── blue/
│       ├── monitoring.py
│       ├── triage.py
│       ├── code_analysis.py
│       └── patch_generation.py
│
├── schemas/
│   ├── __init__.py
│   ├── common.py
│   ├── targets.py
│   ├── red_team.py
│   ├── blue_team.py
│   ├── patches.py
│   ├── verification.py
│   └── experiments.py
│
├── services/
│   ├── __init__.py
│   ├── target_registry.py
│   ├── controlled_executor.py
│   ├── log_reader.py
│   ├── source_reader.py
│   ├── patch_service.py
│   ├── git_service.py
│   ├── test_runner.py
│   ├── environment_service.py
│   └── audit_service.py
│
├── llm/
│   ├── __init__.py
│   ├── interface.py
│   ├── mock_provider.py
│   ├── local_provider.py
│   ├── cloud_provider.py
│   ├── response_validation.py
│   └── prompts/
│
├── dummy_apps/
│   └── vulnerable_store/
│       ├── app/
│       ├── tests/
│       ├── scenarios/
│       ├── Dockerfile
│       └── README.md
│
├── security_tests/
│   ├── __init__.py
│   ├── base.py
│   ├── registry.py
│   ├── sql_injection/
│   ├── xss/
│   └── path_traversal/
│
├── verification/
│   ├── __init__.py
│   ├── pipeline.py
│   ├── syntax.py
│   ├── functional.py
│   ├── security.py
│   ├── regression.py
│   └── decisions.py
│
├── experiments/
│   ├── runner.py
│   ├── configurations/
│   ├── scenarios/
│   ├── metrics.py
│   └── analysis.py
│
├── storage/
│   ├── database.py
│   ├── models.py
│   └── repositories.py
│
├── dashboard/
│   ├── api/
│   └── frontend/
│
├── infrastructure/
│   ├── docker/
│   ├── networks/
│   ├── resource_limits/
│   └── reset/
│
├── tests/
│   ├── unit/
│   ├── integration/
│   ├── policy/
│   ├── safety/
│   └── end_to_end/
│
├── scripts/
│   ├── setup_linux.sh
│   ├── setup_windows.ps1
│   ├── start_environment.sh
│   ├── start_environment.ps1
│   ├── reset_environment.sh
│   └── reset_environment.ps1
│
└── data/
    ├── logs/
    ├── runs/
    ├── evidence/
    └── exports/
```

Only the directories needed by the current milestone should be created during implementation.

---

# 29. Error Architecture

Define explicit error categories.

Suggested hierarchy:

```text
ProjectError
├── ConfigurationError
├── PolicyViolationError
├── InvalidStateTransitionError
├── AgentOutputValidationError
├── TargetValidationError
├── TestExecutionError
├── EnvironmentResetError
├── PatchValidationError
├── GitOperationError
├── VerificationError
└── StorageError
```

Errors must be translated into:

- structured run result;
- audit event;
- terminal or retry decision.

Avoid silently swallowing exceptions.

---

# 30. Retry Architecture

Retries must be bounded.

Possible retryable cases:

- malformed LLM structured output;
- transient model-provider failure;
- patch rejection when attempt budget remains;
- optional attack attempt when previous attempt is unconfirmed.

Non-retryable cases:

- severe policy violation;
- invalid target;
- failed environment reset;
- missing baseline commit;
- forbidden patch path;
- maximum attempt limit reached.

---

# 31. Scoring Architecture

Recommended file:

```text
orchestrator/scoring.py
```

Scoring must use stored outcomes rather than LLM opinion.

Inputs:

- confirmed attack result;
- classification correctness;
- localization correctness;
- patch verification;
- regression outcome;
- duplicate attempts;
- policy violations.

Research metrics and game-style scores must remain separate.

---

# 32. Environment Reset Sequence

Recommended reset order:

```text
Stop registered services
        ↓
Restore Git baseline
        ↓
Restore scenario files
        ↓
Reset database / fixtures
        ↓
Clear run-scoped logs
        ↓
Start registered services
        ↓
Wait for health check
        ↓
Run baseline functional sanity check
        ↓
Mark environment READY
```

If any stage fails, the experiment must not begin.

---

# 33. End-to-End MVP Data Flow

```text
1. User / experiment runner starts registered run
2. Experiment Manager loads scenario + condition
3. Environment Service restores baseline
4. Orchestrator enters READY
5. Reconnaissance Agent receives approved target metadata
6. Attack Planning Agent selects registered test
7. Policy Engine validates plan
8. Controlled Executor performs local test
9. Attack Verification confirms or rejects result
10. Log Reader collects current run events
11. Blue Team condition executes
12. Code finding is produced
13. Patch proposal is produced
14. Patch policy validates paths/change size
15. Git Service creates patch branch
16. Patch Service applies change
17. Verification Pipeline runs
18. Decision Engine accepts or rejects
19. Result, evidence, metrics, cost and scores are stored
20. Dashboard displays result
21. Environment is reset before next independent run
```

---

# 34. Phase 2 Implementation Order Implied by Architecture

The architecture suggests this development order:

1. Detailed threat model and trust-boundary review
2. Repository foundation
3. Schemas and configuration
4. Dummy application
5. Baseline functional tests
6. Docker isolation
7. Environment reset
8. Target registry
9. Policy engine
10. Deterministic security-test registry
11. Controlled executor
12. Red Team planning/verification
13. Structured logs
14. Blue Team triage
15. Source reader/code analysis
16. Patch proposal schema/service
17. Git service
18. Verification pipeline
19. Experiment storage
20. Stored experience / reward-guided selection
21. RQ1/RQ2/RQ3 configurations
22. Dashboard
23. Final experiments

---

# 35. Architecture Decision Summary

The following decisions are frozen:

1. **Small custom orchestrator**
   - No heavy agent framework for the MVP.

2. **Pydantic-validated agent outputs**
   - All actionable LLM outputs use schemas.

3. **Deterministic privileged services**
   - HTTP, files, Git, tests, reset, and patching are service-controlled.

4. **FastAPI dummy application**
   - Suitable for controlled routes, logging, and testing.

5. **SQLite first**
   - Appropriate for a one-machine FYP and experiment metadata.

6. **SQLAlchemy storage layer**
   - Avoid hard-coupling the application to raw SQLite access.

7. **Docker isolation**
   - Dummy app and test execution are containerized.

8. **Separate patch branch per attempt**
   - Baseline remains protected.

9. **No automatic merge**
   - Human-controlled only.

10. **React dashboard**
    - Presentation and experiment visibility, not core control logic.

11. **Mock provider mandatory**
    - Tests and demos do not depend on paid APIs.

12. **Research conditions share the same core pipeline**
    - Only the experimental variable changes.

13. **Environment reset is a hard gate**
    - No independent run begins from unknown state.

14. **Patch acceptance is deterministic**
    - Agents do not approve themselves.

---

# 36. Architecture Consistency Check

## With Project Charter
- One initial dummy application: **consistent**
- Three vulnerability classes: **consistent**
- Red/Blue agents: **consistent**
- Central orchestrator: **consistent**
- Git branch patches: **consistent**
- Mock-model operation: **consistent**

## With Research Plan
- RQ1 single vs multi-agent configuration: **supported**
- RQ2 rule/LLM/hybrid configuration: **supported**
- RQ3 structured feedback retry: **supported**
- model/token/timing metrics: **supported**
- development vs final runs: **supported**
- repeated experiments: **supported**

## With Safety Boundaries
- no unrestricted shell: **supported**
- target registry: **supported**
- endpoint/test allowlists: **supported**
- restricted source reads: **supported**
- restricted patch writes: **supported**
- no auto-merge: **supported**
- Docker isolation: **supported**
- audit logging: **supported**
- bounded retries: **supported**

No direct contradiction has been identified between the frozen Phase 1 documents.

---

# 37. Architecture Exit Criteria

The architecture is ready for milestone planning when:

- [x] trusted/untrusted boundary defined;
- [x] runtime components defined;
- [x] orchestrator responsibilities defined;
- [x] state machine defined;
- [x] policy engine defined;
- [x] Red Team flow defined;
- [x] Blue Team flow defined;
- [x] deterministic service interfaces defined;
- [x] patch workflow defined;
- [x] Git workflow defined;
- [x] verification workflow defined;
- [x] experiment storage defined conceptually;
- [x] LLM abstraction defined;
- [x] RQ1 architecture defined;
- [x] RQ2 architecture defined;
- [x] RQ3 architecture defined;
- [x] dashboard boundary defined;
- [x] reset flow defined;
- [x] repository structure proposed;
- [x] safety consistency checked;
- [ ] milestones mapped to implementation tasks;
- [ ] final Phase 1 consistency review completed;
- [ ] detailed Phase 2 threat model completed before application implementation begins.

---

## Architecture Status
**FROZEN FOR PHASE 1**
