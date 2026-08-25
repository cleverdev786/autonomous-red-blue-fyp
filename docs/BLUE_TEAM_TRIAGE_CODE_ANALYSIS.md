# Milestone 11 — Blue Team Triage and Code Analysis

## Status

**TECHNICALLY VERIFIED — implementation, automated verification, and development-laptop runtime verification PASS; final staged Git review and commit PENDING.**

Milestone 11 implements the first typed Blue Team analysis workflow without adding patch generation, external model integration, arbitrary filesystem access, or new attack authority.

## Objective

Milestone 11 operationalizes the frozen RQ2 classification architecture and adds bounded source localization:

```text
LogReadResult
    ↓
rule_only | llm_only | hybrid
    ↓
TriageResult
    ↓
policy-controlled SourceReader
    ↓
bounded SourceReadResult
    ↓
CodeAnalysisAgent
    ↓
CodeFinding
```

The classification stage always consumes the same normalized `LogReadResult`. Source code is not supplied to classification and is read only after a supported vulnerability classification requires code analysis.

## Implemented Components

### Blue reasoning roles

```text
agents/blue/monitoring.py
agents/blue/triage.py
agents/blue/code_analysis.py
```

All three roles subclass the existing `TypedReasoningAgent` contract. They prepare bounded structured provider inputs and validate typed provider outputs. They do not invoke providers themselves and receive no shell, Docker, Git, HTTP, or direct filesystem authority.

`MonitoringAgent` is implemented for the specialized Blue Team architecture but is intentionally not inserted into the RQ2 classifier path. This prevents an extra LLM stage from changing the `llm_only` and `hybrid` classification conditions relative to `rule_only`.

### Comparable RQ2 classification modes

`orchestrator/blue_team_flow.py` provides one classification interface:

```text
LogReadResult + ClassificationMode → TriageResult
```

Modes are:

```text
rule_only
llm_only
hybrid
```

Behavior:

```text
rule_only:
LogReadResult → existing RuleEngine → TriageResult

llm_only:
LogReadResult → TriageAgent → TriageResult

hybrid:
LogReadResult → existing RuleEngine
              → LogReadResult + deterministic TriageResult
              → TriageAgent
              → final TriageResult
```

The existing Milestone 10 `RuleEngine` is unchanged. `rule_only` classification performs zero provider/model calls.

All model-backed results are deterministically checked after Pydantic validation. The orchestrator rejects:

- a mismatched `run_id`;
- supporting event IDs absent from the supplied normalized run;
- vulnerability labels marked non-suspicious;
- vulnerability classifications without supporting evidence IDs;
- benign classifications marked suspicious.

The approved `ClassificationLabel` enum remains the only label set:

```text
sql_injection
xss
path_traversal
benign
unknown
```

### Bounded source reader

`services/source_reader.py` is a deterministic trusted service. It is the only new Milestone 11 component that reads source files.

Every source read is checked by the existing `PolicyEngine.validate_source_read()` and then narrowed further by Milestone 11 restrictions:

- only the registered target is accepted;
- only files beneath `dummy_apps/vulnerable_store/app/` are exposed;
- only `.py` application source files are exposed;
- the scenario ground-truth directory is excluded;
- tests are excluded;
- `.env`, secret-like files, credential paths, absolute paths, traversal paths, and policy-denied paths remain blocked;
- resolved paths must remain inside the approved application source root;
- source files and returned context are size bounded;
- reads and blocked reads are recorded through `AuditService`.

The service returns typed `SourceSnippet` objects inside `SourceReadResult`. It never gives an LLM an `open()`, `Path`, filesystem browser, or arbitrary read tool.

### Relevant-source selection

The deterministic source selector uses only neutral route names already present in Milestone 9 logs, such as:

```text
login
search
file_read
```

It scans a bounded number of approved application Python files for matching function names and returns bounded snippets around those functions. It does not use scenario IDs, registered security-test IDs, Red Team execution objects, or scenario ground truth to choose source context.

### Code analysis

`CodeAnalysisAgent` receives only:

- the validated `TriageResult`;
- supporting normalized application events;
- bounded approved `SourceReadResult` snippets.

The resulting `CodeFinding` is then checked deterministically. A finding is rejected if:

- its `run_id` does not match;
- it cites a file that was not supplied to the agent;
- it provides no supporting source lines;
- any supporting line range falls outside the supplied snippet bounds.

For `benign` and `unknown` classifications, code analysis is skipped and no artificial `CodeFinding` is created.

### Typed Milestone 11 result

`BlueTeamAnalysisResult` records:

```text
run_id
target_id
classification_mode
triage
code_finding
final_state
```

This result is JSON serializable and keeps the three RQ2 classification conditions on a comparable `TriageResult` contract. Formal experiment persistence remains locked for its later milestone.

## Mock Provider

The existing `llm/mock_provider.py` now supports the Blue monitoring, triage, and code-analysis roles while preserving existing Red Team behavior.

The Blue mock is deterministic and performs no external I/O. Code localization searches only the source snippets supplied in its input. It does not import or read scenario ground-truth records or registered security-test implementations.

## Safety and Research Boundaries

Milestone 11 preserves these controls:

- classification input is the same `LogReadResult` across RQ2 modes;
- source code is excluded from classification input;
- source access happens only after triage;
- agents receive no direct filesystem authority;
- scenario ground-truth files are not exposed;
- no Red Team attack plan, execution result, test ID, or scenario ID is required for classification;
- model calls are authorized and counted by the existing policy/budget layer;
- blocked source reads and model-call authorization are auditable;
- no new vulnerability class is introduced;
- no external/cloud LLM provider is introduced;
- no patch generation or write authority is introduced.

A full Blue analysis using `rule_only` classification may later invoke the code-analysis model after classification if the deterministic result is actionable. This does not change the RQ2 rule-only classifier itself: `BlueTeamFlow.classify(..., rule_only)` remains model-free and is the classification path used for RQ2 comparison.

## Automated Verification

Implementation-workspace commands:

```bash
python -m compileall -q \
  agents orchestrator schemas services llm dummy_apps infrastructure security_tests

python -m pytest -q -p no:cacheprovider
```

Observed result:

```text
Python compilation: PASS
Pytest: 153 passed
```

Focused Milestone 11 coverage adds 20 tests for:

- rejection of labels outside the frozen RQ2 set;
- bounded valid application-source reads;
- blocking outside-root, `.env`, scenario ground-truth, and test-file reads;
- source-read audit evidence;
- bounded neutral-route source selection;
- rule-only zero-provider classification;
- LLM-only independence from `RuleEngine`;
- hybrid inclusion of the deterministic rule result;
- shared `TriageResult` output contract across all modes;
- invented supporting-event rejection;
- standalone monitoring role behavior;
- model-call budget enforcement before provider invocation;
- full XSS logs-to-code-finding localization;
- benign rule-only stop after triage;
- rejection of findings that cite unsupplied files;
- mock-provider ground-truth/import separation.

The optional Ruff check was not executed in the implementation workspace because Ruff was not installed there. No dependency was added or changed for Milestone 11.

The permanent repository was then rechecked on the development laptop before runtime verification:

```text
Python compilation: PASS
Full pytest suite: 153 passed, 1 warning in 3.29s
Focused Milestone 11 suite: 20 passed in 0.44s
git diff --check: PASS
```

The warning was the existing non-failing Starlette/FastAPI TestClient deprecation warning.

## Runtime Gate

**PASS — development-laptop runtime verification completed successfully on 2026-08-25.**

The runtime gate used the permanent repository and the existing isolated Docker lab. No Docker/network control was weakened.

### Environment and regression checks

```text
Clean Docker reset/rebuild: PASS
Both services healthy: PASS
controlled-executor -> vulnerable-store lab reachability: PASS
controlled-executor public internet block: PASS
Registered SQLi/XSS/Path Traversal tests: PASS
```

All three existing registered tests again produced deterministic evidence.

### Correlated Red-to-Blue evidence

Three opaque runtime runs were executed through the existing registered Red Team workflow:

```text
m11-runtime-sqli -> confirmed -> final_state=blue_monitoring
m11-runtime-xss  -> confirmed -> final_state=blue_monitoring
m11-runtime-path -> confirmed -> final_state=blue_monitoring
```

The vulnerable-store structured log stream contained four matching records for each run ID. `LogReader` normalized each run as:

```text
4 events
malformed=0
duplicates=0
```

The observed `ignored=74` value reflected unrelated container/startup traffic and was not used as a pass/fail condition.

### Blue classification and localization

The host-side verification produced:

```text
m11-runtime-sqli:
  rule_only = sql_injection
  hybrid    = sql_injection
  llm_only  = sql_injection
  source    = dummy_apps/vulnerable_store/app/scenario_routes.py
  function  = vulnerable_login

m11-runtime-xss:
  rule_only = xss
  hybrid    = xss
  llm_only  = xss
  source    = dummy_apps/vulnerable_store/app/scenario_routes.py
  function  = vulnerable_search

m11-runtime-path:
  rule_only = path_traversal
  hybrid    = path_traversal
  llm_only  = path_traversal
  source    = dummy_apps/vulnerable_store/app/scenario_routes.py
  function  = vulnerable_file_read
```

For each run, `rule_only` classification made zero provider calls. Its subsequent actionable code-analysis step invoked only `BLUE_CODE_ANALYSIS`. `hybrid` and `llm_only` used the deterministic mock Blue triage/code-analysis roles as intended for runtime wiring verification.

### Specialized monitoring and ground-truth boundary

Standalone `MonitoringAgent` verification over real normalized XSS logs passed.

An explicit attempted read of:

```text
dummy_apps/vulnerable_store/scenarios/sqli-login-001.json
```

through `SourceReader` was blocked, and the blocked `source_read` operation was present in the audit record. This directly verifies that scenario ground truth remains outside Blue model-visible source context.

### Final isolation re-check

After Blue verification:

```text
PASS: both services are healthy.
PASS: controlled-executor can reach vulnerable-store on the lab network.
PASS: public internet is blocked from controlled-executor.
PASS: Docker lab isolation checks completed.
```

`git diff --check` also remained clean, and the Git-visible source changes stayed limited to the Milestone 11 implementation/documentation scope.

Milestone 11 is technically verified. Formal completion still requires the complete staged Git review and the milestone commit. Milestone 12 remains locked until both are complete.
