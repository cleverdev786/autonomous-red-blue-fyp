# PROJECT CHARTER

## Project Title
**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Project Status
**University Proposal: Approved**

## 1. Project Purpose
Design, implement, and evaluate a controlled multi-agent Red-Blue framework that can detect, classify, locate, remediate, and verify selected web-application vulnerabilities inside an isolated local environment.

The project is both:
- a working software prototype; and
- an experimental AI/cybersecurity research project.

## 2. Approved Vulnerability Scope
The first version is limited to exactly three vulnerability categories:

1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Directory / Path Traversal

Additional vulnerability classes are outside the MVP and may only be considered after the complete approved workflow is working.

## 3. Approved Target Scope
The framework may operate only against deliberately vulnerable dummy applications created specifically for this FYP.

The initial MVP will use:
- one dummy web application;
- local execution only;
- Docker-based isolation;
- fabricated data only.

The framework must not scan, attack, access, or test:
- real websites;
- public IP addresses;
- private organizations;
- university infrastructure;
- production systems;
- external servers; or
- any unauthorized target.

## 4. Core Red Team Workflow
The Red Team will contain the following logical roles:

1. **Reconnaissance Agent**
   - Maps only permitted application routes, forms, and input fields.
   - Does not perform open-ended network discovery.

2. **Attack Planning Agent**
   - Selects one approved vulnerability test.
   - Produces a structured test plan.

3. **Controlled Test Executor**
   - Deterministic program, not an unrestricted LLM tool.
   - Executes only allowlisted local requests.

4. **Attack Verification Agent**
   - Determines whether the test actually succeeded.
   - Stores reproducible evidence.

## 5. Core Blue Team Workflow
The Blue Team will contain the following logical roles:

1. **Monitoring Agent**
   - Reads structured application/server logs.

2. **Triage / Classification Agent**
   - Detects suspicious behaviour.
   - Classifies the likely vulnerability.

3. **Code Analysis Agent**
   - Identifies the relevant source file, route/function, and probable root cause.

4. **Patch Generation Agent**
   - Produces a structured patch proposal.
   - Produces or proposes an associated security test.

5. **Patch Verification Agent / Verification Role**
   - Is implemented as a controlled verification role backed by deterministic test services.
   - Requests only registered verification stages.
   - Reviews structured verification evidence for explanation and audit purposes.
   - Replays the original Red Team test through the registered verification pipeline.
   - Runs security, functional, and regression checks through deterministic services.
   - Does **not** override the deterministic final accept/reject decision.

## 6. Central Orchestrator
A central Python orchestrator will control the complete workflow.

It must:
- enforce workflow order;
- validate agent outputs;
- enforce target and endpoint allowlists;
- enforce file/path restrictions;
- enforce request, model-call, and attempt limits;
- enforce execution timeouts;
- prevent infinite loops;
- store evidence and audit events;
- trigger deterministic services;
- calculate experiment metrics and Red/Blue scores.

LLM outputs are recommendations, not authority.

An LLM must never directly receive unrestricted:
- shell access;
- network access;
- Docker control;
- Git control;
- host filesystem access; or
- arbitrary command execution.

## 7. Patch Workflow
Every generated patch must follow this sequence:

1. Confirm vulnerability.
2. Classify the issue.
3. Locate the probable vulnerable source code.
4. Generate a structured patch proposal.
5. Validate the proposal against policy.
6. Create a separate Git branch.
7. Apply the approved patch.
8. Record the diff.
9. Run syntax/startup checks.
10. Run functional tests.
11. Run the relevant security test.
12. Replay the original confirmed Red Team test.
13. Run regression tests.
14. Accept or reject the patch.
15. Record the complete result.

### Merge Rule
**No automatic merge is allowed in the MVP.**

A generated patch may be committed to its own branch after successful verification, but merging remains a human decision.

## 8. Primary Research Questions

### RQ1 — Multi-Agent Remediation
**Does a specialized multi-agent Blue Team achieve a higher successful patch-acceptance rate than a single general-purpose Blue Team agent?**

Primary metrics:
- patch acceptance rate;
- security-test pass rate;
- regression rate;
- patch attempts;
- time to accepted patch;
- model calls;
- token/API cost.

### RQ2 — Hybrid Detection and Classification
**Does combining deterministic/rule-based detection with LLM-based analysis improve vulnerability-classification performance compared with rule-only and LLM-only approaches?**

Primary metrics:
- classification accuracy;
- detection rate;
- false-positive rate;
- time to detection;
- model calls;
- inference cost.

## 9. Secondary Research Question

### RQ3 — Structured Failure Feedback
**Does structured feedback from failed security and regression tests improve subsequent patch attempts?**

This is a secondary/exploratory question. If schedule pressure occurs, RQ1 and RQ2 take priority.

## 10. MVP Definition
The MVP is complete when the framework can demonstrate the full workflow for all three approved vulnerability categories:

- local vulnerable application starts in Docker;
- Red Team produces a structured plan;
- deterministic executor performs an approved test;
- attack result is verified;
- structured logs are collected;
- Blue Team detects and classifies the issue;
- Blue Team identifies the relevant source location;
- a patch is proposed;
- a separate Git branch is created;
- the patch is applied only within approved paths;
- functional, security, replay, and regression tests execute;
- patch is accepted or rejected deterministically;
- evidence is stored;
- scores and experiment metrics are recorded;
- basic results are visible in a dashboard;
- environment can be reset to baseline;
- system can demonstrate the workflow with a mock model.

## 11. Technology Baseline
Initial technology choices:

- Python
- FastAPI
- SQLite
- SQLAlchemy
- Pydantic
- Pytest
- Docker / Docker Compose
- Git / GitPython
- React + Vite
- Replaceable LLM provider interface
- Mock LLM provider
- Local LLM support where practical
- Optional cloud model for selected difficult tasks

### Architecture Constraint
Do not introduce a large agent framework unless a later requirement clearly justifies it. The first implementation should use a small, explicit orchestrator that is easy to debug and explain.

## 12. Mandatory Safety Boundaries
The project must include:

- no outbound internet access for attack containers;
- no arbitrary shell access for LLM agents;
- no host filesystem access;
- no real credentials or personal information;
- strict target, endpoint, HTTP-method, and test allowlists;
- controlled source-file access;
- CPU and memory limits where practical;
- request and execution-time limits;
- maximum attack attempts;
- maximum patch attempts;
- complete audit logs;
- automatic environment reset;
- separate Git branches for generated patches;
- no automatic merge.

A policy violation must stop or reject the attempted action and be recorded.

## 13. Explicitly Excluded from the MVP
The following are not part of the approved MVP:

- real-world penetration testing;
- public internet reconnaissance;
- arbitrary port scanning;
- credential attacks;
- denial-of-service testing;
- malware;
- social engineering;
- exploit chaining;
- unrestricted autonomous hacking;
- automatic production deployment;
- automatic patch merging;
- full reinforcement-learning training;
- self-replicating agents.

Full reinforcement learning is future work only unless the complete approved system is finished early.

## 14. Definition of Project Success
The project succeeds if it can safely and reproducibly:

1. detect a controlled vulnerability;
2. confirm it with evidence;
3. classify it;
4. identify its source-code cause;
5. generate a constrained patch;
6. place that patch on a separate branch;
7. verify that the vulnerability is removed;
8. confirm normal application behaviour still works;
9. accept or reject the patch using deterministic tests; and
10. record enough evidence and metrics to evaluate the research questions.

## 15. Scope-Change Rule
Any future scope change must answer:

1. Is it required by the approved proposal?
2. Does it directly support an approved research question?
3. Does it threaten the 16-week delivery plan?
4. Does it increase security or implementation risk?
5. Can it be postponed until after the MVP?

If it is not necessary for the MVP or research evaluation, it should normally be postponed.

## 16. Phase 1 Approval Checklist
Before implementation begins, confirm:

- [x] University proposal approved
- [x] Academic title frozen
- [x] Three vulnerability categories frozen
- [x] One initial dummy application
- [x] External targets prohibited
- [x] Deterministic executor required
- [x] LLM shell/network authority prohibited
- [x] Separate patch branches required
- [x] Automatic merge excluded
- [x] Mock-model operation required
- [x] RQ1 defined
- [x] RQ2 defined
- [x] RQ3 treated as secondary
- [x] Full reinforcement learning treated as future work
- [ ] Research plan document completed
- [ ] Safety-boundaries document completed
- [ ] Architecture document completed
- [ ] Milestones document completed
- [ ] Phase 1 consistency review completed

---

## Charter Status
**FROZEN FOR PHASE 1**

Changes should be deliberate and recorded rather than silently added during implementation.
