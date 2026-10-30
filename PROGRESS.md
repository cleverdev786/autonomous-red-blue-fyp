# MARS development progress

**Updated:** 2026-10-30

**Active branch:** `development`

**Current delivery:** Red Team T01–T36 implemented, verified, and committed; push handed off to the repository owner

## Current state

The model-free Red Team release is functionally complete for the authorized local `vulnerable-store` lab. It includes deterministic reconnaissance, planning, controlled execution, verification, durable orchestration, Manual and Autonomous modes, protected APIs, the React operator workspace, real Docker acceptance evidence, adversarial regressions, and an operator runbook.

The release boundary remains deliberately narrow:

- target: the registered local synthetic Docker lab only;
- vulnerability classes: SQL injection, reflected XSS, and path traversal;
- profile: one fixed Standard budget;
- scanner: digest-pinned ZAP 2.17.0, on demand and narrowly gated;
- no arbitrary target import, authenticated crawling, broad active scan, Blue execution, or Red model-provider dependency.

## Red Team roadmap

| Phase | Tasks | Status |
| --- | --- | --- |
| A — baseline and contracts | T01–T04 | complete |
| B — persistence and policy | T05–T08 | complete |
| C — Docker/ZAP reconnaissance | T09–T12 | complete |
| D — deterministic planning | T13–T15 | complete |
| E — execution and verification | T16–T21 | complete |
| F — orchestration | T22–T25 | complete |
| G — API and dashboard | T26–T33 | complete |
| H — acceptance and handoff | T34–T36 | complete and committed; owner push handoff complete |

Authoritative task-level evidence remains in [tasks/todo.md](tasks/todo.md).

## Latest acceptance evidence

T34 was regenerated on 2026-10-30 against the isolated Docker lab:

- opt-in test: `1 passed in 67.76s`;
- three real registered Docker invocations and six HTTP requests;
- executor duration: 2,319 ms total;
- Manual workflow: 9 agent tasks, 3/3 eligible tests completed, 3 confirmed findings, 1 separate suspected observation, 2 coverage gaps;
- Autonomous workflow: 8 agent tasks, 3/3 eligible tests completed, 3 confirmed findings, 2 coverage gaps;
- cancel path: one queued reconnaissance task cancelled before dispatch;
- output: `/tmp/mars-red-t34-acceptance.json`.

T35 operational and security acceptance:

- opt-in restart/cancellation test: `1 passed`;
- one controlled dispatch, zero redelivery, preserved evidence bytes;
- four jobs restored as cancelled;
- 21 unrelated containers unchanged;
- negative/permission regression groups: 174 passed;
- output: `/tmp/mars-red-t35-operational.json`.

Frontend contract tests and the production build passed; the build transformed 45 modules. Compose validation, Ruff, and diff checks passed at the T35 checkpoint. T36 adds launcher lifecycle tests, refreshed documentation, a runbook, and the acceptance report; its final verification is recorded in the task tracker.

## Desktop lifecycle

`MARS Dashboard.desktop` now launches `launch-mars.sh`, which starts and waits for the full base Docker lab before starting the FastAPI/React application. The desktop entry also exposes **Stop MARS services**, backed by `stop-mars.sh`.

The stop path verifies the recorded backend PID, stops only the registered base Compose project, removes orphan containers in that project, and preserves the named volume. ZAP remains excluded from automatic startup.

## Documentation

- [README](README.md): current setup, architecture, safety, and verification
- [Red Team runbook](docs/RED_TEAM_RUNBOOK.md): startup/shutdown, local access, budgets, operation, reset, ZAP, privacy, troubleshooting, and rollback
- [Red Team acceptance report](docs/RED_TEAM_ACCEPTANCE_REPORT.md): measured T34/T35 results and limitations
- [Task tracker](tasks/todo.md): acceptance criteria and command-level checkpoints

## Historical research status

Milestones 1–19 remain historically complete. M20's official Q6_K frozen DEVELOPMENT feasibility-v1 exposure remains preserved and `INELIGIBLE` because only 2/6 patch-verification fixtures passed. It must not be rerun to improve the result.

No final experiment configuration has been admitted. No final RQ1/RQ2/RQ3 experiment has run. M21 remains blocked until an explicit pre-final-evaluation research-design decision is made. Red Team product acceptance does not change those research conclusions.

## Remaining release actions

- Review the complete working-tree diff, including the accumulated uncommitted T34–T36 changes.
- Obtain human approval for the final release checkpoint.
- Release commit authorized and created.
- Push handed off to the repository owner; Codex did not push.

The unrelated pre-existing lowercase `agents.md` deletion is not part of the Red Team release work and remains unmodified.
