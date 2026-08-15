# SAFETY BOUNDARIES

## Project Title
**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Phase
**Phase 1 — Proposal, Objectives, Research Questions, Scope, and Ethics**

## Document Purpose
This document converts the project’s safety principles into enforceable technical boundaries.

The goal is to ensure that the framework behaves as a controlled academic security laboratory rather than an unrestricted autonomous hacking system.

All later implementation decisions must remain compatible with this document.

---

# 1. Core Safety Principle

The system may reason about security testing, but sensitive actions must be performed only by deterministic services operating under explicit policy.

The following rule is mandatory:

> **LLMs may recommend actions. Deterministic code decides whether those actions are permitted and performs them.**

No LLM agent may directly receive unrestricted access to:

- a shell;
- Docker;
- Git;
- the host filesystem;
- arbitrary network destinations;
- arbitrary HTTP requests;
- arbitrary file writes;
- operating-system process execution.

---

# 2. Trust Model

The project will classify components as either **trusted control components** or **untrusted recommendation components**.

## 2.1 Trusted Control Components

Trusted components are deterministic project modules whose behaviour is explicitly implemented and tested.

Examples:

- central orchestrator;
- policy engine;
- target registry;
- controlled HTTP executor;
- source-code reader;
- patch application service;
- Git service;
- test runner;
- environment reset service;
- audit logger;
- scoring engine;
- experiment manager.

Trusted components are allowed to perform privileged project operations only within their own restricted interfaces.

## 2.2 Untrusted Recommendation Components

All LLM-backed agents are treated as untrusted.

Examples:

- reconnaissance agent;
- attack planning agent;
- attack verification agent;
- monitoring agent;
- triage/classification agent;
- code analysis agent;
- patch generation agent.

Their outputs must:

1. use predefined schemas;
2. pass Pydantic validation;
3. pass policy validation;
4. be rejected if outside the current workflow state;
5. never directly trigger a sensitive action.

---

# 3. Target Boundary

## 3.1 Allowed Target

The MVP may operate only against the deliberately vulnerable dummy application included in the project repository and launched through the approved local Docker Compose environment.

## 3.2 Prohibited Targets

The framework must reject any attempt to interact with:

- real websites;
- public websites;
- public IP addresses;
- university systems;
- corporate systems;
- personal systems;
- cloud production environments;
- home-network devices;
- external APIs not required for the approved LLM provider;
- arbitrary Docker containers;
- any target not explicitly registered.

## 3.3 Target Registry

Every permitted application must be defined in a target registry.

A target entry must include at least:

```text
target_id
container_name
hostname
port
allowed_scheme
allowed_endpoints
allowed_http_methods
allowed_test_ids
source_root
writable_patch_roots
log_sources
reset_command_id
max_requests_per_attempt
max_attempt_duration
```

The system must refuse to operate on targets that are not registered.

## 3.4 No Dynamic Target Discovery

The Red Team must not discover arbitrary machines or services.

The reconnaissance stage may only inspect metadata or routes belonging to the already approved dummy application.

No generic network scanning is part of the project.

---

# 4. Network Boundary

## 4.1 Attack Network

The dummy application and controlled test executor should communicate through an isolated Docker network.

The attack/test execution environment must not require outbound internet access.

## 4.2 External Network Access

Attack containers must have no route to the public internet.

The architecture should separate:

- **security-testing network**
- **optional LLM-provider communication**

If a cloud LLM is used, that communication should occur from the orchestrator/provider layer, not from the attack executor container.

## 4.3 Destination Validation

Before any HTTP request is executed, the controlled executor must validate:

- hostname;
- port;
- scheme;
- endpoint path;
- HTTP method;
- registered test ID;
- request count;
- current experiment state.

If any check fails, the request must not be sent.

## 4.4 Redirect Handling

Automatic redirects must not be allowed to escape the approved target.

If redirects are enabled at all, each redirect destination must be revalidated against the target registry.

---

# 5. Controlled Security-Test Boundary

## 5.1 Approved Vulnerability Categories

The MVP may perform tests only for:

1. SQL Injection
2. Cross-Site Scripting
3. Directory / Path Traversal

## 5.2 Registered Test Definitions

The deterministic test harness must execute only registered test definitions.

Each test definition should contain:

```text
test_id
vulnerability_class
target_id
endpoint
method
allowed_parameter_names
request_template
success_evidence_rules
max_requests
timeout_seconds
```

## 5.3 No Arbitrary Payload Execution

An LLM must not be allowed to send a free-form raw request directly to the application.

The attack planning agent may select:

- an approved test ID;
- approved parameters;
- approved test options.

The executor must construct the final request from a registered template.

## 5.4 Attempt Limits

Every experiment must define:

- maximum reconnaissance actions;
- maximum attack plans;
- maximum security-test executions;
- maximum requests per test;
- maximum repeated tests;
- maximum patch attempts;
- maximum model calls;
- total experiment timeout.

Once a limit is reached, the workflow must stop or move to a terminal state.

---

# 6. Shell and Process Boundary

## 6.1 No General Shell Tool

LLM agents must never receive a tool such as:

```text
run_shell(command: str)
```

or any equivalent unrestricted interface.

## 6.2 Registered Operations Only

If a system operation is needed, it must be exposed as a specific deterministic function.

Examples:

```text
run_registered_test(test_id)
run_test_suite(suite_id)
create_patch_branch(run_id, attempt_id)
reset_registered_environment(target_id)
read_approved_log(run_id)
```

The operation implementation may internally use subprocesses where necessary, but the LLM cannot control the command string.

## 6.3 Command Allowlisting

Commands used internally by deterministic services must be:

- hard-coded or configuration-registered;
- parameterized safely;
- invoked without shell interpolation where possible;
- time-limited;
- logged;
- covered by tests.

---

# 7. Filesystem Boundary

## 7.1 Host Filesystem

Attack containers must not mount the entire host filesystem.

The system must not expose:

- user home directories;
- SSH keys;
- browser profiles;
- unrelated repositories;
- system configuration directories;
- secret stores;
- personal files.

## 7.2 Approved Source Root

Source-code reading must be restricted to the current dummy application repository root or a controlled working copy.

## 7.3 Read Allowlist

The source reader may access only approved file types and directories required for the experiment.

Suggested initial readable areas:

```text
dummy_apps/<app>/app/
dummy_apps/<app>/tests/
dummy_apps/<app>/scenarios/
```

## 7.4 Explicit Read Denylist

The source reader must reject paths matching or resolving into:

```text
.git/
.env
.env.*
*.pem
*.key
*.p12
*.pfx
secrets/
credentials/
node_modules/
__pycache__/
data/private/
```

The exact denylist may be extended during implementation.

## 7.5 Path Normalization

Before a file is read or written:

1. resolve the path;
2. normalize relative components;
3. verify it remains inside the approved root;
4. reject symbolic-link escape where relevant.

This is mandatory because the project itself studies path traversal.

---

# 8. Patch Boundary

## 8.1 Patch Proposals

The LLM patch agent produces a structured proposal.

It does not directly write to disk.

A patch proposal must identify:

- intended files;
- intended changes;
- security rationale;
- expected effect;
- associated test;
- possible regression risk.

## 8.2 Writable Paths

Generated patches may modify only approved source and test directories.

For the MVP, infrastructure-level modifications should normally be rejected.

Examples of normally disallowed generated changes:

- Docker daemon configuration;
- host scripts;
- CI secrets;
- environment files;
- dependency lockfiles unless explicitly required;
- Git hooks;
- system services;
- unrelated project directories.

## 8.3 Maximum Patch Size

The policy engine should enforce configurable limits such as:

- maximum files modified per attempt;
- maximum inserted lines;
- maximum deleted lines;
- maximum total diff size.

Exact values will be selected during implementation and documented in configuration.

## 8.4 Patch Review Before Execution

Before tests are run, the deterministic patch service must:

1. validate paths;
2. inspect the diff;
3. reject prohibited file types;
4. reject out-of-scope files;
5. reject excessive changes;
6. record the diff hash/reference.

---

# 9. Git Boundary

## 9.1 Baseline Protection

The baseline branch must never be modified directly by an agent-generated patch.

## 9.2 Branch Per Patch Attempt

Every patch attempt must use a separate branch.

Recommended naming pattern:

```text
agent-patch/<run_id>/<attempt_id>
```

## 9.3 Git Service Restrictions

The deterministic Git service may expose only specific operations, such as:

- verify clean baseline;
- create approved branch;
- calculate diff;
- commit an accepted patch;
- restore baseline;
- inspect current branch.

The LLM does not receive raw Git command execution.

## 9.4 No Automatic Merge

Automatic merging is prohibited in the MVP.

Even a fully accepted patch remains on its generated branch until a human explicitly chooses to merge it.

## 9.5 No Remote Push by Agents

Agent workflows must not automatically push generated branches to external remotes.

Remote publication, if ever needed for the final project, must be a separate human-controlled action.

---

# 10. Docker Boundary

## 10.1 Container Isolation

The dummy application and test environment must be containerized.

## 10.2 No Privileged Containers

Project containers must not run with Docker privileged mode.

## 10.3 Docker Socket

The Docker socket must not be mounted into an LLM-controlled or attack container.

## 10.4 Host Mounts

Only necessary project directories may be mounted.

Read-only mounts should be used when write access is not required.

## 10.5 Resource Controls

Where supported, containers should use limits for:

- CPU;
- memory;
- process count;
- execution time.

## 10.6 Container Identity

The orchestrator must interact only with registered project containers.

No general "run arbitrary container" feature should be exposed to agents.

---

# 11. Secrets and Personal Data Boundary

## 11.1 Fabricated Data Only

The dummy application must use synthetic users, records, documents, and credentials.

## 11.2 No Production Secrets

The repository must not contain:

- real API keys;
- real passwords;
- real personal data;
- university credentials;
- production database credentials.

## 11.3 LLM Provider Keys

If cloud-model access is used, provider credentials must be held by the orchestrator environment and never shown to agents or stored in experiment prompts.

## 11.4 Logging Redaction

Audit and experiment logs must not record secret values.

---

# 12. LLM Input Boundary

LLMs should receive the minimum context required for their assigned role.

## 12.1 Reconnaissance Agent May Receive

- approved application manifest;
- registered routes;
- approved field metadata;
- previous permitted attempt summaries.

## 12.2 Triage Agent May Receive

- normalized structured logs;
- registered labels;
- deterministic detection features where applicable.

## 12.3 Code Analysis Agent May Receive

- approved relevant source snippets;
- route information;
- sanitized logs;
- classification result.

## 12.4 Patch Agent May Receive

- approved source context;
- root-cause finding;
- test expectations;
- structured failure feedback where applicable.

## 12.5 Prohibited Context

Agents must not receive unrelated:

- host files;
- credentials;
- secret environment values;
- personal user data;
- external-system information.

---

# 13. LLM Output Boundary

All agent outputs must be structured and schema validated.

Free-form explanations may be stored for research, but actionable fields must use constrained schemas.

Examples:

```text
AttackPlan
AttackVerification
TriageResult
CodeFinding
PatchProposal
PatchRetryContext
```

Invalid output must be rejected or retried within a bounded retry limit.

The system must never treat malformed LLM output as an implicit authorization.

---

# 14. Workflow-State Boundary

Sensitive actions must only be valid during the correct workflow stage.

Example:

```text
CREATED
→ ENVIRONMENT_PREPARING
→ RECONNAISSANCE
→ ATTACK_PLANNING
→ ATTACK_EXECUTING
→ ATTACK_VERIFYING
→ BLUE_MONITORING
→ TRIAGE
→ CODE_ANALYSIS
→ PATCH_GENERATING
→ PATCH_VALIDATING
→ PATCH_APPLYING
→ PATCH_VERIFYING
→ ACCEPTED / REJECTED / FAILED / POLICY_BLOCKED
```

Examples of invalid transitions:

- patch generation before a confirmed finding;
- patch application before policy validation;
- verification before a patch exists;
- accepted state without all mandatory tests passing.

Invalid transitions must be rejected and audited.

---

# 15. Verification Boundary

Patch acceptance is deterministic.

An LLM must not decide that its own patch is successful.

A patch is accepted only when all required checks pass:

1. policy validation;
2. allowed file/path validation;
3. syntax/startup validation;
4. functional tests;
5. relevant security test;
6. replay of the original confirmed Red Team test;
7. regression tests;
8. required safety checks.

Any mandatory failure results in rejection.

---

# 16. Environment Reset Boundary

Every independent experiment must start from a known baseline.

The reset process must restore:

- database state;
- application fixtures;
- relevant files;
- Git baseline;
- experiment-specific logs where appropriate;
- container state where required.

Reset must be deterministic and logged.

If reset fails, the next experiment must not start.

---

# 17. Audit Logging Requirements

Every security-sensitive operation must produce an audit event.

Minimum fields:

```text
event_id
timestamp
run_id
component
actor_type
operation
requested_target
policy_decision
policy_reason
execution_status
duration_ms
evidence_reference
error_code
```

Additional fields may be added later.

Audit events should be append-oriented and should not be silently edited during a run.

---

# 18. Policy Violation Handling

A policy violation is any attempted action outside the approved boundaries.

Examples:

- unknown target;
- disallowed endpoint;
- disallowed HTTP method;
- unregistered test;
- request limit exceeded;
- patch outside writable roots;
- attempt to access secret file;
- prohibited Git operation;
- invalid workflow transition.

## Required Response

The system must:

1. block the action;
2. record the violation;
3. increment the violation count;
4. move the affected workflow to `POLICY_BLOCKED` when required;
5. avoid executing the prohibited operation;
6. preserve evidence for later review.

For severe violations, the complete experiment should terminate immediately.

---

# 19. Resource and Loop Limits

The framework must never allow unlimited autonomous loops.

Each run must have configuration limits for:

- model calls;
- attack plans;
- attack attempts;
- patch attempts;
- tool calls;
- HTTP requests;
- wall-clock runtime;
- test runtime;
- patch size.

The orchestrator is responsible for enforcing these limits.

---

# 20. Safety Test Suite

Before Red Team implementation is considered ready, automated tests must verify at least the following:

## Target Safety
- [ ] unregistered hostname is rejected;
- [ ] unregistered port is rejected;
- [ ] unregistered endpoint is rejected;
- [ ] disallowed HTTP method is rejected.

## Test Harness Safety
- [ ] unknown test ID is rejected;
- [ ] test request limit is enforced;
- [ ] duplicate/attempt limits are enforced;
- [ ] redirect escape is blocked.

## Filesystem Safety
- [ ] path outside source root is rejected;
- [ ] `../` traversal is normalized and blocked;
- [ ] secret/environment files are rejected;
- [ ] symlink escape is rejected where supported.

## Patch Safety
- [ ] patch outside writable roots is rejected;
- [ ] excessive patch size is rejected;
- [ ] prohibited file types are rejected;
- [ ] baseline branch cannot be modified directly.

## Git Safety
- [ ] patch branch naming is validated;
- [ ] automatic merge is unavailable;
- [ ] agent-controlled remote push is unavailable.

## Workflow Safety
- [ ] invalid state transitions are rejected;
- [ ] patch cannot be applied before validation;
- [ ] patch cannot be accepted without all required tests.

## Limit Safety
- [ ] attack-attempt limit is enforced;
- [ ] patch-attempt limit is enforced;
- [ ] experiment timeout is enforced;
- [ ] model-call limit is enforced.

## Audit Safety
- [ ] blocked actions create audit events;
- [ ] successful sensitive actions create audit events;
- [ ] logs do not expose secrets.

These tests are mandatory gates, not optional quality improvements.

---

# 21. Human-Controlled Actions

The following actions remain human-controlled in the MVP:

- approving major scope changes;
- merging generated branches;
- publishing code to remote repositories;
- enabling a cloud LLM provider;
- changing target-registry definitions;
- changing safety policies;
- choosing whether an optional experiment is included in final evaluation.

---

# 22. Safety vs Research Integrity

Safety controls must remain constant across experimental conditions unless a safety control itself is explicitly the research variable.

The project must never weaken safety restrictions to make one agent configuration perform better.

Examples:

- single-agent and multi-agent conditions use the same writable paths;
- all classifier conditions use the same approved event data;
- all patch conditions use the same verification rules;
- all attack attempts use the same target boundary.

---

# 23. Safety Failure vs Experimental Failure

These outcomes must be distinguished.

## Experimental Failure

Examples:

- agent classifies incorrectly;
- patch fails tests;
- patch causes regression;
- attack attempt is unconfirmed.

These are valid research results.

## Safety Failure / Policy Block

Examples:

- agent requests an unknown target;
- patch attempts to modify a forbidden file;
- request exceeds policy;
- invalid privileged action is requested.

These must be recorded separately and must not be reported as ordinary model-quality failures.

---

# 24. Safety Acceptance Criteria for Phase 1

The safety model is considered sufficiently defined for architecture work when:

- trusted and untrusted components are clearly separated;
- target policy is explicit;
- network boundaries are explicit;
- filesystem boundaries are explicit;
- patch and Git restrictions are explicit;
- LLM input/output boundaries are explicit;
- workflow-state enforcement is required;
- attempt/resource limits are required;
- audit fields are identified;
- violation handling is defined;
- mandatory safety tests are listed;
- no component requires unrestricted LLM shell/network authority.

---

# 25. Frozen Safety Decisions

The following decisions are frozen for the MVP:

1. Only registered local dummy targets may be tested.
2. Attack/test containers must not have outbound internet access.
3. LLMs never receive arbitrary shell execution.
4. LLMs never directly control Docker.
5. LLMs never directly control Git.
6. LLMs never directly send arbitrary HTTP requests.
7. Sensitive actions use deterministic service interfaces.
8. Source reads are constrained to approved roots.
9. Patch writes are constrained to approved roots.
10. Baseline branch is protected.
11. One branch is created per patch attempt.
12. No automatic merge.
13. No agent-controlled remote push.
14. Resource and attempt limits are mandatory.
15. Policy violations are blocked and audited.
16. Failed environment reset blocks the next experiment.
17. Patch acceptance is test-based, not model-based.
18. Real credentials and personal data are prohibited.
19. Safety rules apply equally across research conditions.
20. Full autonomous unrestricted exploitation is out of scope.
21. Stored experience or reward-guided selection may rank only registered, policy-approved strategies and must never expand permissions, targets, tools, or limits.

---

## Safety Boundaries Status
**FROZEN FOR PHASE 1**

Exact numeric limits and concrete configuration values will be selected during implementation, but the boundaries themselves must not be weakened without an explicit documented design decision.
