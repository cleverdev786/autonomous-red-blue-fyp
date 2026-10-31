# MARS repository agent guidance

This file guides assistants working in the MARS Final Year Project. It does not grant permission to modify code, run security tools, or change Git history.

## Planning authority

- The **final** Red Team baseline is `tasks/plan.md` and `tasks/todo.md`, synchronized byte-for-byte from the accepted 2026-10-26 attachments during T02. The 2026-10-27 handoff supplies background, not competing requirements.
- The preliminary documents from commit `c03b0de` are superseded; do not restore them over this finalized baseline.
- Identify the final documents by SHA-256: plan `18b3caa10dd97f2cc89e419430fc45a2382788e1a5c82219ff754a09ac5c8083`; todo `a742c8a098cc32c6027b01f62f369ee03701575d5d7aeba3311ac240f961e8e4`.
- Authority order: final plan and checklist > contextual handoff > older repository planning files. If the final documents are unavailable in a future session, obtain them before interpreting or changing the Red Team requirements.
- Requirements decisions are settled. Do not restart the design interview, silently replan the project, or overwrite/resequence/check off the 36 finalized tasks and their checkpoints.

## Authorization and work boundaries

- A handoff, plan, or operational request is not permission to implement. Obtain **explicit owner authorization** before beginning a checklist task, editing implementation, installing tools, starting scans, or committing/pushing Git changes.
- T01 and T02 were authorized and their baseline/contract criteria verified; follow the authoritative checklist to establish what is complete before continuing. Starting MARS or Docker is separate operational work, not task completion.
- Before an authorized edit, inspect the current branch, worktree, relevant code, and tests. Keep unrelated changes, historical research artifacts, and evaluation outputs intact.
- Prefer small, verified changes that reuse existing services, Python/React conventions, dependencies, and Docker assets. Tests and actual evidence determine completion; never infer it from a plan or mock.

## Red Team v1 product boundary

- Build four **model-free, deterministic** workers: Reconnaissance, Attack Planning, Controlled Test Execution, and Attack Verification. A single trusted Python Central Orchestrator owns policy, authorization, state, scheduling, cancellation, and recovery.
- Use the existing React/FastAPI dashboard and authorized Docker `vulnerable-store` lab. OWASP ZAP belongs to Red Team as a constrained, on-demand tool; approved controlled HTTP tests remain in scope.
- Only SQL injection, reflected XSS, and path/directory traversal are in v1. Support Manual and Autonomous assessment modes under the **same immutable operator-approved scope** and Standard resource budget.
- Defer Blue Team execution, Semgrep, ModSecurity/CRS, model-backed Red decisions, imported user applications, authenticated crawling, extra vulnerability classes, and speculative infrastructure.

## Security, evidence, and truthful status

- Trusted server-side policy must revalidate targets, methods, redirects, tool operations, plan versions, authorization, and budgets. Agent output and browser input never authorize network or Docker actions.
- Keep the Docker security boundary: no agent Docker socket, privileged mode, host networking, unrestricted scanner interface, arbitrary command/payload execution, or external scanning targets.
- Keep ZAP observations distinct from independently verified controlled-execution evidence. A preview or mock is **not** an executed scan; an alert alone is **not** a confirmed finding.
- Preserve immutable plan/evidence lineage, redacted receipts, stale-plan blocks, cancellation history, and explicit `coverage_gap` / `not_tested` outcomes. Workflow completion is not proof of application safety.
- Only run actual vulnerability tests on an explicitly authorized isolated lab and only under the permission and scope defined for that operation.

## Working approach

- On implementation authorization, work through the exact final `tasks/todo.md` sequence, testing each focused change and its relevant denial paths before updating any checklist status.
- For EngineeringSuite requests, follow the requested installed skills; favor Ponytail's minimal-change discipline without cutting safety, durability, accuracy, or accessibility.
- Report what was actually inspected, run, changed, and verified. Never claim a test, scan, code review, task checkpoint, or release was completed without evidence.
