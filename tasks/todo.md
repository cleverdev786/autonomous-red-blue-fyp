# MARS Red Team frontend + backend: proposed task checklist

**Plan:** [tasks/plan.md](plan.md). **No tasks started or implemented.**
All task checkboxes are deliberately unchecked until the user reviews this plan.

## Phase 0: Contracts and security boundary
- [ ] **T1** Unify Red phase/plan/evidence types with existing schemas. Accept only registered IDs; reject malformed evidence and target inputs. Verify typed-schema tests.
- [ ] **T2** Design and test explicit operator execution permission, idempotency, receipt persistence, cancellation and restart semantics. Verify denial and duplicate-dispatch tests.
- [ ] **Checkpoint A** Approve target registration, browser authority and trusted Docker execution model before creating any effectful API.

## Phase 1: Read-only recon user experience
- [ ] **T3** Expose authenticated, read-only, policy-filtered registered targets and endpoint metadata. Verify unknown target and no side effects.
- [ ] **T4** Replace the Red Team placeholder with scope, four-stage timeline and honest empty/offline/blocked states. Verify `npm test`, `npm run build` and browser checks.
- [ ] **Checkpoint B** Red Team page shows trustworthy registered scope, with zero automatic attack requests.

## Phase 2: Bounded attack plan
- [ ] **T5** Preview offline registered-test plans; optionally validate model advice against registry/policy. Verify planned test is not an executed test.
- [ ] **Checkpoint C** Reviewed plan has immutable target, test ID and limits; no dispatch without user approval.

## Phase 3: Real lab execution
- [ ] **T6** Execute one specifically admitted registered test through the existing restricted Docker executor, with hard resource/time limits and auditable operator approval. Verify actual local synthetic Docker replay, blocked destinations and cancellation.
- [ ] **Checkpoint D** One real bounded attack receipt, no unauthorized request/host modification.

## Phase 4: Verification and handoff
- [ ] **T7** Bind structured attack evidence to the plan and execution, display trusted verdict and references, hand off confirmed authorized findings. Verify negative/timeout/tamper cases and evidence rendering.
- [ ] **Checkpoint E** Provenance-complete Red assessment available without cloud or local-model dependency.

## Phase 5: Optional tool adapters (NOT required for MVP)
- [ ] **T8** Decide whether ZAP passive-only scanner adds real value on the sandbox. If yes, add digest-pinned restricted ephemeral Docker adapter and verify zero scope escapes.
- [ ] **T9** Decide whether Semgrep local static rules add real value. If yes, add read-only digest-pinned container + fixture comparisons. Bandit/Nuclei remain deferred unless independently justified.
- [ ] **Checkpoint F** No new scanner dependency without a measured additional finding and repeatable provenance.

## Phase 6: Whole-system gate
- [ ] **T10** Full tests, build, manual browser checks, Docker health, resource contention, cancellation and rollback. Confirm archived research datasets/evidence unchanged.
- [ ] **Checkpoint G** User review and explicit approval required before release or extending target scope.
