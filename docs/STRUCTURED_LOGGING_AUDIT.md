# Structured Logging and Audit System

## Milestone

**Milestone 9 — Structured Logging and Audit System**

## Status

**COMPLETE — implementation, automated verification, Docker/runtime verification, final Git review, and commit have passed.**

Milestone 9 is permanently committed at `4058143`.

Verified results:

```text
Local automated verification:
Python compile check: PASS
Pytest: 108 passed
git diff --check: PASS

Development laptop — 2026-08-18:
Python compile check: PASS (exit code 0)
Pytest: 108 passed, 1 warning in 3.00s
Docker clean reset/rebuild: PASS
Docker isolation verification: PASS
Public internet blocked from controlled-executor: PASS
Milestone 7 registered security-test regression: PASS
SQL Injection correlated Red Team runtime: PASS
XSS correlated Red Team runtime: PASS
Path Traversal correlated Red Team runtime: PASS
LogReader exact run isolation: PASS
Executor/application request-ID correlation: PASS
Required runtime event categories: PASS
Forbidden registry/ground-truth structural metadata check: PASS
Audit runtime verification: PASS
Final Docker isolation re-check: PASS
```

The pytest warning is an upstream Starlette/FastAPI TestClient deprecation warning from the virtual environment and did not fail the suite.

## Objective

Provide structured observable application evidence for later Blue Team and experiment milestones without exposing ground truth or broadening agent/executor authority.

The application evidence path is:

```text
ControlledExecutor
  ↓ fixed run_id + executor-generated request_id
vulnerable-store
  ↓ structured JSON to stdout
human/runtime Docker-log collection
  ↓
data/logs/vulnerable-store.jsonl
  ↓
LogReader
  ↓
validated ApplicationLogEvent objects for one exact run
```

Audit evidence is separate:

```text
RedTeamFlow policy/execution actions
  ↓
AuditService
  ↓
append-oriented data/audit/audit.jsonl
```

Audit records are not Blue/RQ2 application-classification input.

## Application Event Contract

`schemas/logging.py` defines `ApplicationLogEvent` with trusted structural fields:

```text
schema_version
event_id
timestamp
run_id
request_id
event_type
component
route_name
method
status_code
attributes
error_type
```

Required application categories are:

- `http_request`;
- `validation_event`;
- `database_event`;
- `file_access_event`;
- `application_error`.

### Structural-field integrity

`dummy_apps/vulnerable_store/app/structured_logging.py` constructs structural fields separately from caller-supplied attributes. Caller attributes are bounded and nested only under `attributes`.

Caller attributes cannot replace or inject the structural names:

```text
schema_version
event_id
timestamp
run_id
request_id
event_type
component
route_name
method
status_code
attributes
error_type
```

Sensitive attribute names such as password, authorization, cookie, token, API-key, secret, database-URL, and environment-related fields are discarded.

String attributes are length-bounded and the number of attributes per event is bounded.

## Correlation Boundary

Milestone 9 adds one non-actionable correlation field to controlled execution:

```text
run_id
```

`ControlledExecutor` validates that ID and deterministically generates one opaque `request_id` per registered request step.

`HttpTransport.send()` receives only fixed correlation values in addition to its existing already-authorized request fields. It still exposes no arbitrary header mapping.

`HttpxTransport` alone converts correlation into the fixed internal headers:

```text
X-FYP-Run-ID
X-FYP-Request-ID
```

`TestExecutionResult` now carries `run_id`, and each `HttpExchangeEvidence` carries its executor-generated `request_id`. This provides a deterministic evidence chain from Red run → execution → HTTP exchange → application event.

## Ground-Truth Separation

Blue-facing application logs intentionally exclude:

- `test_id`;
- vulnerability class;
- registry endpoint IDs;
- request-template/evidence-rule IDs;
- scenario ground-truth data;
- source-code ground truth;
- raw scenario route paths.

Baseline and vulnerable routes are mapped to neutral operational route names such as:

```text
health
login
search
documents
file_read
other
```

The logger records observations rather than vulnerability classifications. Milestone 10 now performs rule-derived classification separately in `services/rule_engine.py`; the logger itself remains classification-free.

## LogReader

`services/log_reader.py` has no Docker or subprocess authority.

It resolves log files exclusively from `TargetDefinition.log_sources`, currently:

```text
data/logs/vulnerable-store.jsonl
```

It:

- reads only registry-approved project-relative sources;
- ignores non-JSON runtime noise;
- safely rejects malformed claimed structured events;
- validates application events with Pydantic;
- de-duplicates by `event_id`;
- filters exact `run_id`;
- returns bounded parser diagnostics in `LogReadResult`.

Docker log acquisition remains a human/runtime responsibility for Milestone 9. A later `EnvironmentService` may automate acquisition without changing `LogReader`.

## AuditService

`services/audit_service.py` writes typed append-oriented audit JSONL at the fixed project-relative path:

```text
data/audit/audit.jsonl
```

Each `AuditEvent` records:

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

The Red Team flow records current sensitive policy decisions, workflow transitions, model-call authorization/results, registered-test authorization, and controlled-execution outcomes.

Both allowed/successful and blocked operations are retained. Agents cannot create audit events directly and `AuditService` does not authorize operations.

## Automated Coverage

Milestone 9 tests verify:

- structural event-field validation;
- caller attributes cannot override structural fields;
- sensitive attribute names are removed;
- newline/quote-heavy values remain one JSON line;
- neutral route names do not expose raw scenario paths or registry ground truth;
- HTTP, validation, database, file-access, and application-error events;
- executor-generated request IDs correlate with application events;
- no generic header interface is exposed;
- exact run isolation;
- event de-duplication;
- malformed/noise log handling;
- `LogReader` has no Docker/subprocess capability;
- append-oriented audit filtering;
- successful sensitive execution audit history;
- blocked model-call policy audit history;
- all Milestone 1–8 regression tests.

## Runtime Gate

**PASS — development-laptop runtime verification completed successfully on 2026-08-18.**

The required runtime gate verified:

- clean Docker reset/rebuild;
- Docker isolation remained intact;
- Milestone 7 registered-test regression;
- three Red Team runs with opaque run IDs;
- Docker stdout collection into the registered log source;
- exact `LogReader` run isolation;
- request-ID correlation between executor evidence and application logs;
- required application event categories;
- absence of ground-truth structural metadata/secrets;
- append-oriented audit history for each run;
- final `git diff --check` and Git review.

The final Git review/commit step also completed, and Milestone 9 is permanently committed at `4058143`. No Blue Team behavior was implemented by Milestone 9.

## Docker/Laptop Verification

Development-laptop verification completed successfully on 2026-08-18.

The lab was rebuilt from a clean runtime state and both services became healthy. Isolation checks confirmed that `controlled-executor` could reach `vulnerable-store` on the internal lab network while public internet access remained blocked.

The existing Milestone 7 registered-test harness was rerun after the correlation changes. SQL Injection, XSS, and Path Traversal all still produced deterministic evidence.

The complete Milestone 9 mock-provider Red Team flow was then executed with opaque run IDs:

```text
m9-run-001
m9-run-002
m9-run-003
```

For all three runs:

- `RedTeamRunResult.run_id` matched the requested run ID;
- `TestExecutionResult.run_id` matched the same run ID;
- each HTTP exchange had an executor-generated `request_id`;
- execution completed successfully without timeout;
- deterministic evidence was retained;
- verification was confirmed;
- final workflow state was `blue_monitoring`.

The vulnerable-store Docker stdout was captured into the already-registered log source:

```text
data/logs/vulnerable-store.jsonl
```

`LogReader` verification showed:

```text
m9-run-001: 4 events, 2 correlated executor requests
m9-run-002: 4 events, 2 correlated executor requests
m9-run-003: 4 events, 2 correlated executor requests
ignored lines: 60
malformed structured lines: 0
duplicate events: 0
```

Exact run isolation, executor/application request-ID correlation, required Milestone 9 runtime event categories, and the absence of forbidden registry/ground-truth structural metadata all passed.

Audit verification inside the controlled runtime produced:

```text
14 audit records per run
3 successful model calls per run
registered-test authorization recorded
successful controlled execution recorded
```

The final Docker isolation re-check also passed, confirming that Milestone 9 logging/audit changes did not weaken the existing network boundary.

No Blue Team behavior was implemented or executed.
