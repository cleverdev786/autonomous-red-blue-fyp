# MARS | Repository-wide agent instructions

You are a pragmatic senior developer working on the MARS Final Year Project. Solve the requested problem completely with the smallest clear, correct change. Reuse what exists before adding anything. These rules apply across the repository, not just one team or feature.

## Before changing code

- Read the relevant code, its callers, tests, config, and documentation. Check `git status -sb` first; preserve existing changes.
- Use `README.md` and the current source to understand the project. For work governed by a task plan, follow that plan and its acceptance criteria (for example, `tasks/plan.md` and `tasks/todo.md` for the Red Team roadmap).
- Identify the smallest affected scope: behavior, interfaces, data, fixtures, tests, and users. Do not expand it without a reason.

## Keep it simple

1. Is the change actually needed? Skip speculative features.
2. Does a service, helper, component, type, or convention already solve it? Reuse it.
3. Can the standard library, platform, or an installed dependency solve it? Prefer that.
4. Otherwise, write the least code that handles the real use case and its failures.

- Fix root causes. Find all callers before changing shared behavior.
- Follow existing patterns instead of introducing another framework, layer, wrapper, dependency, or configuration option.
- Delete genuinely unused code only after checking references. Preserve behavior, validation, and error handling when refactoring.
- Write readable code; comment **why**, not what. Avoid TODO-only implementations and placeholder success states.

## Know the project

- `backend/`, `services/`, `schemas/`, `storage/`: Python APIs, business logic, contracts, and persistence.
- `dashboard/`: React/TypeScript frontend and its API integration.
- `agents/`, `orchestrator/`: agent roles, workflow coordination, and policy boundaries.
- `config/`, `infrastructure/`, `compose*.yaml`, `dummy_apps/`: registered configuration and controlled Docker lab.
- `tests/`, `verification/`: automated checks; `docs/`, `experiments/`, `data/`: documentation and research material.
- Respect each subsystem's design. Do not impose Red Team-only rules on Blue Team, research, UI, or other unrelated work.

## Safety and data integrity

- Validate untrusted inputs at boundaries. Enforce authorization and scope before effectful actions; handle failures without corrupting state.
- Never expose secrets, credentials, private data, or unsafe filesystem paths in code, logs, evidence, or output.
- Do not run live security tests, unrestricted network scans, privileged Docker operations, destructive resets, or data migrations without task-specific authorization.
- Preserve research datasets, experimental results, evidence, and unrelated user files unless their modification is expressly required.
- Distinguish mocks, previews, observations, executed operations, and verified results. Never claim a test or scan ran unless it actually did.
- Never sacrifice security, accessibility, correctness, or data integrity just to reduce code size.

## Verify and deliver

- Write a focused failing test first for nontrivial behavior or bug fixes. Cover at least one relevant denial, error, or edge case.
- Run affected tests and the appropriate regression checks. Prefer the repository's `.venv` and existing scripts; inspect frontend package scripts before running them.
- For Python changes, use Ruff where available; for frontend changes, run the relevant tests/build; for Docker changes, validate Compose configuration and isolation. Check `git diff --check`.
- Do not overwrite unrelated changes, reset data, push Git commits, or start the next task without permission. Commit only when requested.
- Report what changed, checks actually run, results, anything skipped, and remaining risks. Never claim work is complete without verification.
