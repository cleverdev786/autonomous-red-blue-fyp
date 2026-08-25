# Milestone 10 — Rule-Based Detection Baseline

## Status

**COMPLETE — automated verification and development-laptop Docker/runtime verification passed, and the milestone is permanently committed at `5c494ba` (`5c494bab1ffe579cc22eab092764c5dc4101e8d8`).**

## Purpose

Milestone 10 implements the deterministic **rule-only** classification condition required by RQ2.

The implemented boundary is deliberately small:

```text
Milestone 9 structured application logs
        ↓
LogReader
        ↓
LogReadResult
        ↓
RuleEngine
        ↓
TriageResult
```

No LLM, Blue agent, Red execution result, audit record, scenario ground truth, security-test definition, Docker capability, or source-code access is required by the rule-only classifier.

## Reused Contracts

Milestone 10 introduces no duplicate event or classification schema.

It reuses:

- `ApplicationLogEvent` and `LogReadResult` from `schemas/logging.py`;
- `ClassificationLabel` from `schemas/common.py`;
- `TriageResult` from `schemas/blue_team.py`.

The allowed classifications therefore remain exactly:

```text
sql_injection
xss
path_traversal
benign
unknown
```

## RuleEngine

`services/rule_engine.py` is a deterministic trusted service with one classification responsibility:

```text
LogReadResult → TriageResult
```

The service has no filesystem, HTTP, Docker, shell, Git, LLM, agent, audit-write, policy, or registered-security-test authority.

Before classification, it verifies that every supplied application event has the same `run_id` as the enclosing `LogReadResult`. Mixed-run input fails closed rather than being silently combined.

## Observable Rule Inputs

Rules inspect only bounded structured application attributes already emitted by Milestone 9.

They do not inspect:

- scenario IDs;
- registered test IDs;
- vulnerability ground truth;
- Red Team attack plans;
- Red execution evidence;
- audit records;
- registry endpoint IDs;
- raw vulnerable route paths;
- source-code ground truth.

Neutral `route_name` values such as `login`, `search`, and `file_read` are not classification signals and cannot determine a vulnerability class on their own.

## Deterministic Signatures

### SQL Injection

The baseline detects generic SQL syntax relationships rather than matching the current registered-test payload exactly. Supported observations include boolean SQL comparison patterns combined with SQL comments and `UNION SELECT` syntax.

A lone apostrophe or ordinary text is insufficient. This avoids classifying benign values such as an ordinary name containing an apostrophe as SQL injection.

### Cross-Site Scripting

The baseline detects executable markup indicators including script elements, event-handler attributes, and `javascript:` URI syntax after bounded decoding/unescaping.

Harmless angle-bracket-like text is insufficient by itself.

### Path Traversal

Traversal rules apply only to path/file-like attribute names and detect real parent-directory path segments after bounded URL decoding and slash normalization.

A filename merely containing two dots, such as `report..txt`, is not treated as traversal.

## Aggregation Semantics

Classification is deterministic:

```text
one supported vulnerability signature
    → that vulnerability label

no supported vulnerability signature with valid events
    → benign

multiple conflicting vulnerability signatures
    → unknown

no normalized events
    → unknown
```

No vulnerability-class precedence is used.

Supporting event IDs are actual `ApplicationLogEvent.event_id` values, de-duplicated and sorted so input event order does not affect the result.

## Confidence Convention

Milestone 10 does not claim probabilistic calibration.

The fixed convention is:

```text
specific deterministic rule match → 1.0
clean benign result              → 1.0
unknown / ambiguous              → 0.0
```

This convention is transparent and reproducible for the RQ2 baseline.

## Research-Validity Protections

The rule-only condition is intentionally separated from ground truth and Red Team state. In particular:

- route names alone cannot classify;
- exact security-test IDs or payload IDs are unavailable to the engine;
- audit records are outside classifier input;
- rule signatures are generic rather than exact registered-test-string equality;
- the same normalized Milestone 9 evidence contract can later be supplied to LLM-only and hybrid RQ2 conditions.

The Milestone 10 rules should be treated as a development baseline to be frozen before final RQ2 evaluation. They must not be tuned after inspecting final labelled evaluation results without creating a new experiment version and repeating affected evaluations.

## Result Retention Boundary

Milestone 10 returns the existing immutable, JSON-serializable `TriageResult` contract.

Formal persistent experiment storage remains a later milestone responsibility. Development/runtime verification results may be retained under ignored local `data/` paths without introducing a classification database or storage service here.

## Automated Verification

Commands executed locally against the committed Milestone 9 baseline `4058143` plus the Milestone 10 implementation:

```bash
python3 -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python3 -m pytest -q -p no:cacheprovider

git diff --check
```

Observed results:

```text
Python compilation: PASS (exit code 0)
Pytest: 133 passed, 1 warning in 3.17s
git diff --check: PASS
```

Focused Milestone 10 coverage includes:

- SQL Injection classification;
- XSS classification;
- Path Traversal classification;
- generalized/non-exact signature forms;
- representative benign false-positive protection;
- neutral-route non-leakage;
- empty input returning `unknown`;
- conflicting supported signatures returning `unknown` without precedence;
- mixed-run input rejection;
- deterministic output under event reordering/repetition;
- supporting-event integrity;
- no imports from LLM, agent, Red, audit, orchestrator, scenario-ground-truth, or security-test modules.

## Runtime Gate

**PASS — development-laptop Docker/runtime verification completed on 2026-08-19.**

Verified classifications from real Milestone 9 structured application evidence:

```text
m10-attack-001 → sql_injection   PASS
m10-attack-002 → xss             PASS
m10-attack-003 → path_traversal  PASS

m10-benign-001 → benign          PASS
m10-benign-002 → benign          PASS
m10-benign-003 → benign          PASS
```

Additional runtime checks passed:

- clean Docker reset/rebuild;
- Docker isolation and controlled-executor public-internet block;
- six classification JSON artifacts retained under ignored `data/m10-results/`;
- supporting attack event IDs remained members of the supplied normalized event sets;
- rule-only runtime completed without loading any LLM or agent module;
- final Docker isolation re-check;
- final `git diff --check`.

The three benign runtime requests executed successfully inside `vulnerable-store` against `127.0.0.1:8000` and produced the expected correlated structured application events. This was a human-operated verification path only; no agent or rule-engine execution authority was added.

### Docker host-port environment note

The development machine's Docker runtime accepted the Compose-requested host binding:

```text
HostConfig.PortBindings={"8000/tcp":[{"HostIp":"127.0.0.1","HostPort":"8000"}]}
```

but the live container network state reported:

```text
NetworkSettings.Ports={"8000/tcp":null}
```

so host-side requests to `127.0.0.1:8000` were refused even though the application itself remained healthy. This was classified as a development-environment Docker runtime/networking issue rather than a RuleEngine or vulnerable-application failure.

No Compose file, Docker network, isolation setting, or repository implementation was changed to bypass it. The benign verification traffic was instead generated from inside `vulnerable-store` to its own loopback interface, preserving the existing `internal: true` lab boundary.

The final automated/runtime evidence closed the Milestone 10 verification gate. Final Git review also passed, and the completed milestone was permanently committed at `5c494ba` (`5c494bab1ffe579cc22eab092764c5dc4101e8d8`).

## Locked Follow-On Work

Milestone 10 does not implement:

- Blue monitoring/triage/code-analysis agents;
- LLM-only classification;
- hybrid classification;
- constrained source reading;
- persistent experiment storage;
- experiment metrics/dataset execution;
- patch generation or verification.

Those remain later-milestone responsibilities.
