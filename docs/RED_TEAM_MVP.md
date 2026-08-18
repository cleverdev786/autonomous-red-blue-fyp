# Red Team MVP — Milestone 8

## Status

**Implementation, automated verification, and Docker/runtime verification have passed.**

Milestone 8 is technically verified. The remaining workflow step is the final Git diff/status review and commit.

Verified results:

```text
Automated implementation environment:
Python compile check: PASS
Pytest: 96 passed in 0.81s
git diff --check: PASS

Development laptop — 2026-08-17:
Python compile check: PASS (exit code 0)
Pytest: 96 passed, 1 warning in 2.36s
Docker clean reset/rebuild: PASS
Docker isolation verification: PASS
Public internet blocked from controlled-executor: PASS
SQL Injection Red Team runtime: PASS
XSS Red Team runtime: PASS
Path Traversal Red Team runtime: PASS
Final state for all confirmed runs: blue_monitoring
```

The pytest warning is an upstream Starlette/FastAPI TestClient deprecation warning from the virtual environment; it did not fail the suite.

## Objective

Milestone 8 adds the first typed Red Team reasoning workflow around the already-verified deterministic security-test executor.

The Red Team remains an untrusted recommendation layer. It has no direct HTTP, shell, Docker, Git, or unrestricted filesystem authority. Actionable execution still passes through deterministic policy and the existing `ControlledExecutor`.

## Architectural Layers

```text
agents/
    untrusted Red/Blue role reasoning contracts

llm/
    provider-neutral structured-generation interface and providers

orchestrator/
    workflow coordination, model-call authorization, state transitions,
    deterministic plan/evidence integrity checks

services/
    trusted deterministic registry projection and execution services

security_tests/
    fixed deterministic registered security-test implementations
```

`agents/base.py` and `llm/interface.py` are intentionally separate:

- `agents/base.py` defines the common typed agent-reasoning contract.
- `llm/interface.py` defines the provider-neutral structured-generation contract.

Agents do not own or invoke providers. `RedTeamFlow` authorizes each model call, consumes one model-call budget unit, invokes the provider, and then validates the returned Pydantic result.

## Approved Flow

```text
READY
  ↓
RECONNAISSANCE
  ↓
ATTACK_PLANNING
  ↓
ATTACK_EXECUTING
  ↓
ATTACK_VERIFYING
  ├── confirmed + valid deterministic evidence → BLUE_MONITORING
  └── otherwise                              → REJECTED
```

Every transition uses `PolicyEngine.validate_state_transition()`.

`BLUE_MONITORING` is only a handoff state in Milestone 8. No Blue Team behavior is implemented or executed.

The existing retry transition from `ATTACK_VERIFYING` back to `ATTACK_PLANNING` is not used by this single-attempt MVP.

## Reconnaissance Boundary

`ReconnaissanceService.build_reconnaissance_context()` exposes only:

- target ID;
- endpoint IDs;
- allowed HTTP methods;
- declared input-field names.

It does not expose registered test IDs, vulnerability categories, test mappings, registered parameter names, request-template IDs, evidence-rule IDs, payloads, target network coordinates, source paths, or scenario ground truth.

The Reconnaissance Agent therefore describes the approved attack surface rather than selecting an attack strategy.

## Separate Attack-Planning Catalog

`ReconnaissanceService.build_attack_planning_catalog()` produces a separate typed planning catalog containing only:

- registered `test_id`;
- vulnerability class;
- registered `endpoint_id`;
- allowed parameter names;
- safe description.

It does not contain payload/template contents, evidence-rule implementation, target hostname/port, arbitrary URLs, source paths, or scenario ground truth.

The Attack Planning Agent receives `ReconnaissanceResult` and this planning catalog as separate inputs and returns the existing typed `AttackPlan`.

Before execution, `RedTeamFlow` checks that the recommendation matches the catalog and reconnaissance output and then calls `PolicyEngine.validate_security_test()`.

## Controlled Execution Boundary

Only the existing `ControlledExecutor` performs the registered HTTP sequence.

The flow passes only:

```text
AttackPlan.test_id
attempt_number
run_id          # opaque correlation only
```

to `ControlledExecutor.execute_registered_test()`.

Milestone 9 later extended the executor with this non-actionable `run_id` and executor-generated per-request correlation. It did not add arbitrary headers, URLs, methods, payloads, or agent execution authority. Target registry, policy engine, run-limit tracker, registered security tests/configuration, and Compose isolation remain unchanged.

## Verification Integrity

`AttackVerification` is advisory interpretation over deterministic execution evidence.

The orchestrator enforces that:

- execution target/test IDs match the `AttackPlan`;
- verification target/test IDs match the plan;
- cited evidence IDs exist in `TestExecutionResult.evidence`;
- confirmation requires at least one cited deterministic evidence ID;
- empty deterministic evidence cannot become confirmed;
- timed-out execution cannot become confirmed;
- incomplete execution cannot become confirmed;
- verifier-generated text never creates a new evidence object.

A valid confirmed result transitions to `BLUE_MONITORING`. Anything unconfirmed or evidence-invalid transitions to `REJECTED`.

## Model-Call Budget

One successful single-attempt flow makes exactly three provider calls:

1. Reconnaissance Agent;
2. Attack Planning Agent;
3. Attack Verification Agent.

Before each provider invocation:

1. `PolicyEngine.validate_model_call_budget()` must allow the call;
2. `RunLimitTracker.consume_model_calls()` consumes one authorized unit;
3. the provider is invoked;
4. the returned result is validated against the agent's Pydantic output model.

A denied call is not invoked and does not consume another model-call unit.

## Mock Provider

`MockProvider` is deterministic and performs no external communication. It exists so Milestone 8 can verify the complete agent/orchestration architecture without adding a cloud-model dependency or credentials.

The runtime fixture `--test-id` configures the MockProvider's expected planning choice. It is not passed directly from the CLI to `ControlledExecutor`. Milestone 9 also requires an opaque `--run-id` used only for structured-log/audit correlation.

The runtime path is:

```text
CLI --test-id fixture + opaque --run-id correlation
  ↓
MockProvider configuration
  ↓
Reconnaissance Agent
  ↓
ReconnaissanceResult
  ↓
Attack Planning Agent
  ↓
AttackPlan.test_id
  ↓
deterministic validation
  ↓
ControlledExecutor.execute_registered_test()
```

## Runtime-Container Clarification

`infrastructure/executor/run_red_team_mvp.py` is a **Milestone 8 runtime-verification entry point only**.

For this milestone, the complete MockProvider flow is run inside the `controlled-executor` container because MockProvider performs no external communication and this provides a simple reproducible Docker gate.

This does **not** place the future production orchestration/LLM provider layer inside the attack-executor container. The architectural distinction remains:

```text
agents / llm / orchestrator
    reasoning and coordination layer

ControlledExecutor
    restricted deterministic security-test execution boundary
```

Future provider deployment/runtime placement must preserve that distinction.

## Automated Test Coverage

Milestone 8 automated tests verify:

- reconnaissance and planning views are separate and restricted;
- agents do not own provider/executor authority;
- all three registered scenarios complete through the full mock Red Team flow in-process;
- successful flow consumes exactly three model calls;
- every successful workflow transition is policy validated;
- attack plans outside the catalog fail before executor invocation;
- endpoint, vulnerability-class, and parameter-name mismatches fail closed;
- malformed agent output fails Pydantic validation;
- exhausted model-call budget blocks before the next provider invocation;
- target/test execution identity mismatches transition to `REJECTED` without verifier execution;
- empty evidence, timeout, incomplete execution, invented evidence IDs, and uncited confirmation cannot be promoted to confirmed findings;
- the runtime helper contains no direct call from CLI fixture input to `execute_registered_test()`;
- the registered runtime selection is observable in `AttackPlan.test_id` before execution.

Full repository result:

```text
96 passed in 0.81s
```

## Docker/Laptop Verification

Development-laptop verification completed successfully on 2026-08-17.

The clean Docker reset rebuilt the lab image and both services became healthy. Isolation checks confirmed that `controlled-executor` could reach `vulnerable-store` on the internal lab network while public internet access remained blocked.

The complete mock-provider Red Team flow was then executed for all three registered tests:

```text
sqli-login-bypass-001
xss-reflection-001
path-traversal-private-file-001
```

Each run visibly produced:

```text
ReconnaissanceResult
→ AttackPlan.test_id
→ deterministic registered-test execution
→ TestExecutionResult with evidence
→ AttackVerification citing existing evidence IDs
→ final_state: blue_monitoring
```

All three executions reported `completed: true`, `timed_out: false`, non-empty deterministic evidence, confirmed verification, and the `blue_monitoring` handoff state.

No Blue Team behavior executed after the handoff.

## Still Locked

Milestone 8 does not implement:

- Blue Team monitoring/triage/analysis agents;
- patch generation or patch retry;
- Git patch branches or automation;
- patch application/verification pipeline;
- experiment runner;
- research dashboard/React UI;
- experience/reward-guided selection;
- real cloud/external LLM providers;
- new vulnerability classes;
- new registered security-test payloads;
- crawler/scanner behavior;
- generic HTTP execution.
