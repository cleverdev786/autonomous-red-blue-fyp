# RESEARCH PLAN

## Project Title
**AN AUTONOMOUS MULTI-AGENT RED-BLUE FRAMEWORK FOR WEB APPLICATION VULNERABILITY DETECTION AND REMEDIATION**

## Phase
**Phase 1 — Proposal, Objectives, Research Questions, Scope, and Ethics**

## Status
**Research design frozen for the MVP, subject only to documented supervisor-approved changes.**

---

# 1. Purpose of This Research Plan

This project is not only a software-development project. It must also answer measurable research questions.

The purpose of this document is to define, before implementation:

- the research questions;
- hypotheses;
- independent and dependent variables;
- experimental conditions;
- datasets and scenarios;
- metrics;
- repetition strategy;
- fairness rules;
- evidence to collect;
- analysis method;
- minimum and preferred experiment sizes;
- success criteria;
- threats to validity.

The software architecture and experiment logging must later be designed so that all required measurements in this document can be collected automatically.

---

# 2. Research Strategy

The project will use a **controlled experimental comparison** inside a deliberately vulnerable local web application.

The system will not be evaluated against real websites or external systems.

The same vulnerable scenarios, baseline source code, test suites, resource limits, and evaluation rules will be reused across experimental conditions wherever possible.

The study will primarily compare:

1. **Single-agent vs specialized multi-agent Blue Team remediation**
2. **Rule-only vs LLM-only vs hybrid vulnerability classification**
3. **Patch retries without vs with structured failure feedback** as a secondary experiment

---

# 3. Research Questions

## RQ1 — Primary
### Multi-Agent Remediation

**Does a specialized multi-agent Blue Team achieve a higher successful patch-acceptance rate than a single general-purpose Blue Team agent?**

### Rationale

A single general-purpose model must perform several tasks at once:

- understand logs;
- classify the vulnerability;
- locate vulnerable code;
- reason about the root cause;
- generate a patch;
- produce a security test.

The multi-agent design separates these responsibilities into specialized stages.

The research will test whether this separation improves remediation quality and reliability enough to justify the additional model calls and execution time.

---

## RQ2 — Primary
### Hybrid Detection and Classification

**Does combining deterministic/rule-based detection with LLM-based analysis improve vulnerability-classification performance compared with rule-only and LLM-only approaches?**

### Rationale

Rule-based detection is fast, reproducible, and inexpensive, but can fail on unfamiliar patterns.

LLM-based analysis can interpret richer context but may produce inconsistent or incorrect classifications.

The hybrid configuration will test whether deterministic evidence and LLM reasoning complement one another.

---

## RQ3 — Secondary / Exploratory
### Structured Failure Feedback

**Does structured feedback from failed security and regression tests improve subsequent patch attempts?**

### Rationale

When a generated patch fails, simply requesting another patch may repeat the same error.

The project will test whether structured feedback containing the relevant failure evidence improves a later patch attempt.

RQ3 is secondary. If schedule pressure occurs, RQ1 and RQ2 take priority.

---

# 4. Hypotheses

## H1 — Multi-Agent Remediation Hypothesis

The specialized multi-agent Blue Team will achieve a higher patch-acceptance rate and lower regression rate than the single general-purpose Blue Team.

Expected trade-off:

- higher number of model calls;
- potentially greater token usage;
- potentially greater execution time.

Therefore, success will be evaluated using both effectiveness and resource-efficiency metrics.

---

## H2 — Hybrid Classification Hypothesis

The hybrid rule-based + LLM configuration will achieve better overall vulnerability-classification accuracy than rule-only or LLM-only configurations.

It is also expected to reduce unnecessary LLM calls for events that can be classified confidently using deterministic rules.

---

## H3 — Structured Feedback Hypothesis

A patch-generation retry that receives structured test failure feedback will have a higher subsequent patch-acceptance rate than a retry that receives only the original vulnerability context.

---

# 5. Experimental System Under Test

The experiments will use:

- one deliberately vulnerable local web application;
- Docker-based isolation;
- fabricated data only;
- exactly three approved vulnerability classes:
  1. SQL Injection;
  2. Cross-Site Scripting;
  3. Directory / Path Traversal.

## Minimum Scenario Set

The absolute minimum experiment-ready system will contain:

- 1 SQL Injection scenario;
- 1 XSS scenario;
- 1 Path Traversal scenario.

Total minimum: **3 vulnerable scenarios**

## Preferred Scenario Set

The preferred final evaluation will contain:

- 2 SQL Injection scenarios;
- 2 XSS scenarios;
- 2 Path Traversal scenarios.

Total preferred: **6 vulnerable scenarios**

The scenarios should differ enough that the model cannot succeed only by memorizing one code pattern.

---

# 6. Scenario Ground Truth

Every vulnerable scenario must have a frozen ground-truth record containing:

- `scenario_id`;
- vulnerability class;
- vulnerable endpoint;
- HTTP method;
- relevant input field;
- vulnerable source file;
- vulnerable function or route;
- root cause;
- expected successful security-test result;
- expected structured-log evidence;
- known secure behaviour;
- normal functional behaviour;
- baseline Git commit;
- reset procedure.

Ground truth must be written before the scenario is used in final experiments.

Development-time modifications must not silently change the final ground truth.

---

# 7. RQ1 Experimental Design — Single Agent vs Multi-Agent Blue Team

## 7.1 Independent Variable

**Blue Team architecture**

Two conditions:

### Condition A — Single-Agent Blue Team

One general-purpose Blue Team agent receives the relevant approved evidence and must produce:

- vulnerability classification;
- source-code location;
- root-cause analysis;
- patch proposal;
- associated security test.

Deterministic services still apply and verify the patch.

### Condition B — Specialized Multi-Agent Blue Team

Separate logical agents perform:

1. Monitoring
2. Triage / Classification
3. Code Analysis
4. Patch Generation

The same deterministic patch application and verification pipeline is used.

---

## 7.2 Controlled Variables

The following should remain the same between Condition A and Condition B:

- vulnerable scenario;
- baseline Git commit;
- application data;
- Docker environment;
- available source-code files;
- available log evidence;
- approved tool interfaces;
- policy restrictions;
- maximum patch attempts;
- verification tests;
- model provider;
- model name;
- model temperature;
- model context policy;
- experiment timeout;
- final patch-acceptance rules.

If exact equality is impossible, the difference must be recorded.

---

## 7.3 Dependent Variables

Primary:

- patch acceptance rate;
- original attack replay pass rate;
- regression rate;
- vulnerability-classification accuracy;
- source-file localization accuracy;
- function/route localization accuracy.

Efficiency:

- time to first patch;
- time to accepted patch;
- number of patch attempts;
- model calls;
- input tokens;
- output tokens;
- estimated model cost;
- total run time.

---

## 7.4 Patch Acceptance Definition

A patch is **accepted** only if all mandatory verification checks pass:

1. Patch policy validation passes.
2. Modified files are within the approved path allowlist.
3. Application syntax/startup checks pass.
4. Normal functional tests pass.
5. Relevant security test passes.
6. Original confirmed Red Team test no longer succeeds.
7. Regression tests pass.
8. No mandatory safety rule is violated.

If any mandatory check fails, the patch is rejected.

---

## 7.5 RQ1 Minimum Repetitions

### Minimum viable evaluation

For each scenario:

- Single-agent condition: 3 runs
- Multi-agent condition: 3 runs

With 3 vulnerable scenarios:

`3 scenarios × 2 conditions × 3 runs = 18 experiment runs`

### Preferred evaluation

For each scenario:

- Single-agent condition: 5 runs
- Multi-agent condition: 5 runs

With 6 scenarios:

`6 scenarios × 2 conditions × 5 runs = 60 experiment runs`

The preferred evaluation should be used only if model cost and available time allow it.

---

# 8. RQ2 Experimental Design — Classification Strategy

## 8.1 Independent Variable

**Classification method**

Three conditions:

### Condition A — Rule Only

Classification uses deterministic signatures and structured event rules only.

No LLM classification call is made.

### Condition B — LLM Only

The LLM receives the approved structured event/log context and produces the vulnerability classification.

Deterministic rules do not provide a predicted class.

### Condition C — Hybrid

Deterministic rules first extract or score suspicious features.

The LLM then receives:

- normalized event context;
- rule findings;
- supporting evidence;
- allowed class labels.

The final classification is validated against the allowed output schema.

---

## 8.2 Classification Labels

The classifier must use exactly these labels:

- `sql_injection`
- `xss`
- `path_traversal`
- `benign`
- `unknown`

This prevents uncontrolled label invention and simplifies evaluation.

---

## 8.3 Dataset

RQ2 should use a frozen event dataset containing both malicious and benign events.

### Minimum dataset

At least:

- 10 SQL Injection-related events
- 10 XSS-related events
- 10 Path Traversal-related events
- 30 benign events

Minimum total: **60 labelled events**

### Preferred dataset

At least:

- 20 SQL Injection-related events
- 20 XSS-related events
- 20 Path Traversal-related events
- 60 benign events

Preferred total: **120 labelled events**

Events may be generated through approved local scenario execution and normal application usage.

The ground-truth label must be stored separately from the input provided to the classifier.

---

## 8.4 Controlled Variables

Across classification conditions:

- same frozen event dataset;
- same label set;
- same event normalization;
- same evaluation code;
- same LLM model/settings for LLM-only and hybrid;
- same maximum context size where practical.

---

## 8.5 Dependent Variables

- overall classification accuracy;
- per-class precision;
- per-class recall;
- per-class F1 score;
- macro F1 score;
- attack detection rate;
- benign false-positive rate;
- `unknown` rate;
- time per classification;
- model calls;
- token usage;
- estimated cost.

A confusion matrix will be produced for each classification condition.

---

# 9. RQ3 Experimental Design — Structured Failure Feedback

RQ3 applies only to cases where the first generated patch fails verification and another attempt is allowed.

## 9.1 Independent Variable

**Retry feedback strategy**

### Condition A — No Structured Failure Feedback

The retry receives:

- original vulnerability context;
- original source-code context.

It does not receive detailed failed-test output from the previous attempt.

### Condition B — Structured Failure Feedback

The retry additionally receives an approved structured summary containing, where relevant:

- failed verification stage;
- failing test identifier;
- sanitized assertion/error summary;
- original attack replay outcome;
- regression failures;
- relevant patch-diff summary;
- safety/policy rejection reason.

Raw unrestricted command output is not passed directly to an LLM.

---

## 9.2 Dependent Variables

- second-attempt patch acceptance rate;
- average attempts to accepted patch;
- regression rate;
- repeated-failure rate;
- time to accepted patch;
- additional token usage;
- additional model cost.

---

## 9.3 RQ3 Scope Limit

RQ3 will not be expanded into reinforcement learning.

The experiment studies **structured feedback-guided retry**, not model training.

---

# 10. Red Team Evaluation Metrics

Although the primary experiments focus on Blue Team behaviour, the Red Team must also be measured.

Metrics:

- confirmed attack success rate;
- unconfirmed/false-positive claim rate;
- reproducible-evidence rate;
- duplicate-attempt rate;
- policy violation count;
- requests per confirmed vulnerability;
- time to confirmed vulnerability.

A Red Team "success" requires deterministic or reproducible evidence, not only an LLM claim.

---

# 11. Metric Definitions

## Attack Detection Rate

`correctly detected confirmed attacks / total confirmed attacks`

## Classification Accuracy

`correct classifications / total labelled events`

## Precision for a Class

`true positives / (true positives + false positives)`

## Recall for a Class

`true positives / (true positives + false negatives)`

## F1 Score

`2 × (precision × recall) / (precision + recall)`

## Patch Acceptance Rate

`accepted patch attempts / total patch attempts`

A second analysis may also report:

`scenarios eventually repaired / total scenarios attempted`

These two rates must not be confused.

## Regression Rate

`patch attempts that introduce functional regressions / total patch attempts tested`

## Source-File Localization Accuracy

`runs identifying the correct vulnerable source file / total evaluated runs`

## Function-Level Localization Accuracy

`runs identifying the correct vulnerable function or route / total evaluated runs`

## Benign False-Positive Rate

`benign events incorrectly classified as attacks / total benign events`

## Normal Application Task Success

`passed normal functional tests / total normal functional tests`

---

# 12. Experiment Run Record

Every experiment run must store at least:

- `run_id`;
- timestamp;
- scenario ID;
- experiment question;
- experimental condition;
- baseline Git commit;
- random seed where supported;
- LLM provider;
- model name;
- model configuration;
- prompt/schema version;
- agent configuration;
- attack/test identifier;
- attack result;
- verification evidence reference;
- classification result;
- expected classification;
- source-code location prediction;
- expected source-code location;
- patch attempt number;
- changed files;
- patch diff reference;
- functional-test result;
- security-test result;
- replay-test result;
- regression-test result;
- patch decision;
- rejection reason if applicable;
- policy violations;
- stage timings;
- total run time;
- model-call count;
- input token count;
- output token count;
- estimated monetary cost;
- system error status;
- final Red score;
- final Blue score.

---

# 13. Development Runs vs Final Experimental Runs

Two classes of runs must be kept separate.

## Development Runs

Used to:

- debug code;
- tune prompts;
- improve rules;
- fix environment problems;
- develop scenarios.

They must be marked:

`run_type = development`

Development runs must not be silently included in final experimental results.

## Final Evaluation Runs

Used to answer the research questions.

They must be marked:

`run_type = final_evaluation`

Before final evaluation begins:

- scenarios must be frozen;
- prompts must be versioned/frozen;
- rule sets must be frozen;
- test suites must be frozen;
- model configuration must be frozen;
- evaluation scripts must be frozen.

If something must be changed after final evaluation begins, the affected runs must be repeated or clearly separated into another experiment version.

---

# 14. Randomness and Reproducibility

Where supported:

- store model temperature;
- store seeds;
- use deterministic application fixtures;
- reset application/database state between runs;
- restore the baseline repository commit;
- use the same Docker image versions;
- record software versions;
- record prompt versions;
- record scenario versions.

LLM services may still produce nondeterministic outputs. Repetition is therefore required instead of assuming one model call represents typical performance.

---

# 15. Fair-Comparison Rules

The following rules are mandatory for meaningful comparisons.

1. Do not give one condition access to ground-truth information that another condition does not receive.
2. Use the same scenario version across compared runs.
3. Use the same test and patch acceptance criteria.
4. Use the same model for architecture comparisons unless the model itself is the variable.
5. Use the same model parameters where possible.
6. Record any difference in available context.
7. Keep the same maximum patch-attempt count.
8. Keep the same environment reset process.
9. Keep unsuccessful runs in the result set.
10. Do not remove inconvenient failures.
11. Report system errors separately from successful or rejected patch decisions.
12. Record token/cost differences instead of hiding the extra expense of multi-agent workflows.

The multi-agent condition is allowed to make more calls when the architecture genuinely requires them. That additional resource use must be measured and reported as part of the comparison.

---

# 15A. Stored Experience and Reward-Guided Selection Control

The project will include a small stored-experience mechanism and a bounded reward-guided selection policy, as requested in the project specification.

Its purpose is to reuse previous experiment outcomes without implementing full reinforcement learning.

The mechanism may store information such as:

- registered strategy or agent-role identifier;
- vulnerability/scenario category;
- prior success/failure outcome;
- deterministic Red/Blue score;
- duplicate-attempt penalty;
- policy-block count;
- average verification outcome.

The selector may choose only among **already registered and policy-approved** strategies or agent configurations.

It must never:

- create a new target;
- expand an allowlist;
- bypass the policy engine;
- create a new tool;
- increase attempt limits;
- weaken verification requirements.

## Experimental-Control Rule

Stored experience / reward-guided selection is **not a primary research variable** in RQ1 or RQ2.

For final RQ1 and RQ2 comparisons it must either:

1. be disabled for all compared conditions; or
2. be held identical and frozen across all compared conditions.

This prevents memory or score-guided selection from confounding the single-agent/multi-agent or classifier comparisons.

A dedicated memory/selection study may be treated as optional secondary analysis only after the primary experiments are complete.

---

# 16. Model Strategy

## Required

The system must work with a **mock LLM provider** for:

- automated tests;
- deterministic demonstrations;
- development without API cost.

## Practical Experiments

A local model should be used where its quality is sufficient.

## Optional Cloud Model

A cloud model may be used for selected difficult code-analysis or patch-generation experiments.

Cloud access is not required for every part of the demonstration.

## Model Comparison

Local-vs-cloud model comparison is secondary analysis only.

It must not become an additional primary research question unless the core project is completed early.

---

# 17. Data Analysis Plan

The final analysis will primarily use descriptive statistics and controlled comparisons appropriate for a BS-level FYP.

## RQ1 Analysis

For single-agent and multi-agent conditions, report:

- patch acceptance percentage;
- scenario repair percentage;
- regression percentage;
- localization accuracy;
- mean and median patch attempts;
- mean and median time to accepted patch;
- model calls;
- token usage;
- estimated cost.

Results should also be shown separately for:

- SQL Injection;
- XSS;
- Path Traversal.

## RQ2 Analysis

For rule-only, LLM-only, and hybrid conditions, report:

- confusion matrices;
- overall accuracy;
- macro F1;
- per-class precision/recall/F1;
- benign false-positive rate;
- attack detection rate;
- average classification time;
- model calls and cost.

## RQ3 Analysis

For failed first attempts, compare:

- second-attempt acceptance rate;
- repeated-failure rate;
- regressions;
- time;
- additional model usage.

## Visualisations

Recommended final charts:

- patch acceptance by Blue Team architecture;
- regression rate by Blue Team architecture;
- time to patch by architecture;
- model usage/cost by architecture;
- confusion matrix per classifier;
- classification accuracy/F1 comparison;
- patch retry success with and without feedback;
- per-vulnerability success comparison.

---

# 18. Statistical Testing

Formal statistical significance testing is optional rather than mandatory for the MVP.

If the final sample size is sufficient, appropriate tests may be added with supervisor approval.

The report must not claim statistical significance based only on percentage differences.

At minimum, the project will report:

- sample sizes;
- raw counts;
- percentages;
- mean;
- median;
- minimum;
- maximum;
- standard deviation where meaningful.

---

# 19. Success Criteria

The research component is considered successfully implemented when:

- all final runs are traceable to a scenario and baseline commit;
- ground truth exists for every evaluated scenario/event;
- RQ1 has comparable single-agent and multi-agent results;
- RQ2 has rule-only, LLM-only, and hybrid results;
- failed and successful runs are both retained;
- patch acceptance is decided by tests rather than model opinion;
- regressions are measured;
- resource/model usage is measured;
- final metrics can be exported and reproduced from stored run data;
- conclusions explicitly answer the research questions.

The project does **not** require every LLM-generated patch to succeed.

Failure cases are valid experimental results.

---

# 20. Threats to Validity

## 20.1 Small Scenario Count

A small set of vulnerabilities may not represent real-world web security.

### Mitigation
- include multiple variants where time permits;
- report conclusions only for the controlled project environment;
- avoid claiming universal generalization.

## 20.2 Scenario Memorization

Repeated use of the same vulnerable source code may make later runs easier.

### Mitigation
- reset model conversation state between independent runs;
- use separate scenario variants;
- do not expose ground truth;
- randomize run order where practical.

## 20.3 Prompt Bias

Prompts may unintentionally favor one condition.

### Mitigation
- version prompts;
- keep instructions comparable;
- freeze prompts before final experiments;
- document meaningful prompt differences.

## 20.4 Model Nondeterminism

The same prompt may produce different outputs.

### Mitigation
- repeat experiments;
- record model settings;
- use fixed seeds where available;
- report variation.

## 20.5 Unequal Resource Use

The multi-agent architecture may use more model calls.

### Mitigation
- measure model calls, tokens, time, and cost;
- compare both effectiveness and efficiency;
- do not describe a more expensive architecture as "better" without discussing cost.

## 20.6 Overfitting Detection Rules

Rule-based logic could be designed specifically around the final dataset.

### Mitigation
- freeze rules before final evaluation;
- include benign events;
- keep development and final datasets/runs clearly separated.

## 20.7 Test-Suite Weakness

A patch may pass a weak security test without actually fixing the root cause.

### Mitigation
- replay the original attack;
- include security-test variants where practical;
- maintain documented ground truth;
- review accepted patches manually for final analysis.

## 20.8 External Model Changes

Cloud-model providers may update models during the project.

### Mitigation
- record exact model identifiers and dates;
- freeze final experiments into a short time window where practical;
- keep a mock/local-model path for reproducibility.

---

# 21. Experiment Priority

If project time becomes limited:

## Must Complete
1. RQ1
2. RQ2

## Complete If Core System Is Stable
3. RQ3

## Optional / Future Work
- local-vs-cloud model study;
- full reinforcement learning;
- additional vulnerability categories;
- multi-application generalization.

---

# 22. Research Freeze Checklist

Before Phase 1 is complete:

- [x] RQ1 defined
- [x] RQ2 defined
- [x] RQ3 classified as secondary
- [x] hypotheses defined
- [x] independent variables defined
- [x] dependent variables defined
- [x] minimum scenario count defined
- [x] preferred scenario count defined
- [x] RQ1 repetition strategy defined
- [x] RQ2 dataset target defined
- [x] patch acceptance definition defined
- [x] experiment run fields defined
- [x] development vs final runs separated
- [x] fairness rules defined
- [x] analysis plan defined
- [x] threats to validity documented
- [ ] storage schema later mapped to all required fields
- [ ] architecture later verified against this research plan

---

## Research Plan Status
**FROZEN FOR PHASE 1**

Any modification to a primary research question, experimental condition, metric definition, or final-evaluation rule should be documented rather than changed silently.
