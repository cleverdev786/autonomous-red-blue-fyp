# MARS UI/UX redesign plan: Tailwind CSS + shadcn/ui

**Status:** Engineering implemented through Phase 5, including the owner's follow-up fixes and explicit commit authorization on 2026-10-30. See `tasks_ui.md` and phase reports for verified progress and remaining human acceptance evidence.
**Priority:** Overview and Red Team; preserve the existing application login and Blue Team route.
**Code baseline:** `development` at `56ff2af5916d152124dd64df84a8ccc769b27597`, one local commit ahead of `origin/development` at the handoff. `D agents.md` is pre-existing; **do not touch it**. Verify again before implementing.
**Authoritative inputs:** `MARS_Context_Handoff_2026-10-30.md`, live read-only checkout, user-provided light/dark screenshots, source excerpts, public Figma community references, Firecrawl research and EngineeringSuite skills.
**Companion:** `tasks_ui.md` is the ordered, testable implementation tracker.

## 1. Product decision and scope

**Design read:** MARS is a task-focused **local security-operations application**, not a marketing landing page. Design for an operator who needs to assess a registered application, understand authorization boundaries, watch deterministic worker progress, inspect verified findings, and distinguish workflow completion from security coverage. Use a calm **operational** look: disciplined typography, legible tables, quiet neutral surfaces, strong hierarchy, one intentional MARS accent, and restrained status colors/motion.

**Accepted UI direction for this plan:** migrate **incrementally** from React 18 + Vite 6 + TypeScript + vanilla CSS to **Tailwind CSS v4 and selective shadcn/ui components**, without changing FastAPI, Red policy, authentication, durable workflow, operation semantics, API contracts or evidence. Shadcn components are copied source, not a black-box platform; vet their dependencies and adapt them to MARS. Do not install the entire registry or mix multiple design systems. Preserve current functioning screens while rolling out a compatible layer.

**Immediate navigation focus:** Overview, Red Team, Blue Team entry (Blue behavior/implementation untouched). Legacy Assessments, Findings, Reports, Remediation and System are from the old information architecture; **de-emphasize from primary navigation only after auditing routes and preserving legacy deep links and essential System actions**. Do not delete their code, research data or docs during this UI phase. Blue Team should be honestly labeled as unavailable/deferred if that's the actual state, rather than implying readiness.

**User journey to optimize:** Log in → Overview (readiness + latest Red assessment + next action) → Red Team (assessment list) → New assessment → explicit Standard scope review/authorization → Manual stage controls or Autonomous progress → findings, coverage, evidence → return/resume. No navigation or rendering event starts a security operation.

**Excluded:** Blue Team functional development, backend architecture cleanup, old Red code/doc deletion, new targets/classes/profiles, changing or weakening trusted security controls, running real scans for design evaluation, replacing React/Vite/FastAPI, automatic dependency install in planning phase.

## 2. Baseline findings: source confirmed vs. screenshot observed

| Priority | Evidence | Finding and product impact | Validation before edit |
|---|---|---|---|
| P0 | Screenshots Overview light/dark; `overview/OverviewPanel.tsx` | Hero CTA **Browse assessments** links to legacy `/dashboard/assessments`; Red/Blue cards say **“tools coming later”**. Overview promotes older product pillars instead of the implemented Red assessment. | Map source of current Red metrics/readiness, correct copy, avoid inventing Blue readiness. |
| P0 | Screenshots Red initial state | “Red dashboard unavailable” and “No database connection” dominate large empty space in some sessions; these are genuine unavailable states, **not proof backend is permanently broken**. User cannot distinguish unavailable Red service, missing legacy DB and no assessments. | Test each API/error condition individually; map actionable retry/recovery messaging. |
| P0 | Screenshots Red with stored runs; `RedDashboard.tsx`, `NewAssessment.tsx` | Creation form takes priority above active assessments, metrics and history, even on returning visits; after completing actions the operator may need to locate the workspace. | Preserve `authorize-and-start` behavior introduced at `56ff2af`; verify no duplicate start from recovery effects. |
| P0 | `product.css` around 240, 357, 665, 838; `tokens.css` | Repeated dark selectors, hardcoded gradients/surface/sidebar colors, conflicting palette direction (cobalt/light vs violet/cyan/dark). Cascade is brittle; rendered failure not yet proven for every selector. | Capture computed styles and screenshots in both modes before changing selectors. |
| P1 | Screenshots workstation light/dark | Large empty paddings, inconsistent emphasis and font density; light UI is much brighter and more card-heavy; findings' severity and source paths scan poorly in both; long assessment IDs dominate. | Test actual responsive and zoom behavior, contrast of statuses/labels. |
| P1 | Screenshot Autonomous workspace | Four agent timeline is clear but repeated “stage-transition”, right-side timestamps and large bordered panel obscure actionable detail; title remains “Live” after terminal state. | Show stage status, count, last meaningful action, error if any; no false progress. |
| P1 | Screenshot Findings | Findings table labels like “high”, “sql injection”, “Validated metadata” and “Inspect” require interpretation; report link currently routes to legacy Reports. | Define structured, human-readable finding summary from available DTO data, not invented impact. |
| P1 | `routes.ts`, `App.tsx` | All old sections remain primary route entries. `RedDashboard` holds selected assessment in React state, not a route. | Preserve old URLs, redirects/fallbacks and auth when introducing canonical assessment URLs. |
| P1 | `App.tsx`, `LoginScreen.tsx` | Theme selection is stored in `localStorage`, initialized from system preference; existing login is application-wide. | Verify first paint/no theme flash and login theme parity; preserve session and CSRF behavior. |
| P1 | `check-theme.cjs` | Validates token hex, selected contrast pairs and CSS snippets, **not computed CSS, browser theme transitions or keyboard flow**. | Implement browser-based matrix with a test harness and screenshot diff; don't claim WCAG pass yet. |
| P2 | `package.json` | React/Vite/TS with only React runtime deps; no Tailwind/shadcn/Radix. | Audit npm/Node/version compatibility and validate rollout in a side-by-side proof of concept. |

**What the screenshots do establish:** the Red Team is a real application and can show verified assessments (e.g., 9 findings, 9/9 in a pictured state), not just the unavailable screen. Counts must come from live APIs; screenshots are **historical examples, not canonical fixtures to hardcode**. Light/dark screenshots show the same workflow content but different visual density; they do not by themselves establish numerical contrast compliance.

## 3. Target information architecture

### Shared app shell

- Persistent compact left rail with meaningful accessible names, active-state indicator, keyboard controls and mobile expandable navigation. Top utility bar: breadcrumb, optional environment/runtime state when backed by a status API, theme switch, account/logout (when available). The MARS mark remains.
- Primary navigation: **Overview**, **Red Team**, **Blue Team**. Blue stays reachable, but unchanged. Any required System/account access should remain discoverable as secondary utility. Legacy destinations remain via deep links and a secondary grouping until a separate cleanup is authorized.
- Canonical route candidates: `/dashboard/` (Overview), `/dashboard/red-team` (Red), `/dashboard/red-team/assessments/:id` (workspace), `/dashboard/blue-team` (Blue). Route addition must preserve browser history/back, refresh and invalid/unauthorized states. Do not rename actual API routes without a separate contract plan.

### Overview, revised composition

**Owner clarification (2026-10-30):** Overview is a concise workspace entry: a hero at the top, followed by a bento grid with Red Team and Blue Team cards and explicit “Open Red Team” / “Open Blue Team” button-styled links. Keep detailed Red metrics/history inside Red Team. The following earlier detailed Overview composition is superseded where it conflicts with this clarification.

1. Clear product header: “Workspace overview”, current local environment/status only if verified.
2. **Primary action:** “New Red assessment” or “Resume assessment” (context-dependent); a linked recent assessment is more useful than the old “Browse assessments” hero.
3. **Status strip:** Red service readiness, registered target and active assessment when available; separate truthfully reported unavailable/offline/unauthenticated/no-data states.
4. Compact real-data metrics prioritized by meaning: verified findings, covered vs eligible endpoints, running/queued assessments and gaps; avoid duplicating Red-only metrics with ambiguous old research totals.
5. Recent Red activity as a readable status list/table with time, target and status; old research run history may be under a clearly titled secondary/historical section if still useful.
6. Blue entry is visible but subdued and honestly described; don't create new Blue functionality.

### Red Team landing

- First viewport: title + one primary **New assessment** action, current/resumable assessment panel, status metrics and summary/filters. Not a full-width technical creation form.
- History table: target, mode, status, findings/coverage, updated, open/resume action; readable short ID with full ID available on detail/tooltip/copy. Pagination and filters work with server data. Do not imply all findings from all assessments are unique vulnerabilities.
- New assessment should be a deliberate flow: target/mode → server-owned Standard scope/budget review → create draft → explicit authorization; for Autonomous the currently implemented **authorize-and-start** may perform a combined user-intent action. Do not accidentally reintroduce a second Red login.
- Opening a workspace should not enqueue any work. Start/authorization command acknowledgment should navigate to that workspace once, preserving idempotency.

### Assessment workspace

- Clear summary header: registered target, short assessment ID, Manual/Autonomous, profile, status, actual next action and last update. Stop/cancel only when allowed.
- **Four compact stage rows** (Recon, Planning, Execution, Verification) with consistent state labels: waiting, queued, running, succeeded, blocked, failed, cancelled, stale. Use icon+text+time; highlight one active stage only; expand Inspect/history on demand. Separate detailed shared event history.
- Persistent boundary: workflow status and **security coverage** displayed independently. A successful workflow is not proof the target is safe.
- Findings table with humanized class, route, severity, outcome and link to exact evidence. An accessible detail **sheet** or dialog can show short evidence; long linkable audit evidence should be a page. Preserve original provenance/receipt/hash fields inside a technical section, never fake exploit impact.
- Terminal stage header says **“Assessment timeline”**, not indefinitely “Live assessment timeline.”

## 4. Design system and component specification

### Foundation choices

- Use **Tailwind CSS v4** and **shadcn/ui** *selectively*. Verify current official React 18/Vite support against the user's lockfile and CLI before selecting install commands. No unsanctioned upgrade to React 19, no unbounded npm package installs. Keep CSS variables as the single source of theme truth and map shadcn semantic aliases onto them.
- Existing theme uses `data-theme="dark"`. During migration select **one compatible strategy**, e.g., Tailwind `dark` variant targeting `html[data-theme="dark"]`, while preserving `mars-theme` persistence, native `color-scheme` and system preference first-run. Do not let `.dark` and `data-theme` compete. Migration must keep old CSS working until each screen is validated.
- Prefer shadcn components: `Button`, `Input`, `Select`, `RadioGroup`, `Card` only when grouping adds meaning, `Dialog`/`Sheet`, `DropdownMenu`, `Tabs`, `Badge` only for meaningful state, `Tooltip`, `Skeleton`, `Separator`, `Table` primitives, `Alert`, `Progress`. Complex data-table sorting/filtering is optional and only justified by actual data volumes; default to semantic tables and existing paging. No slider for Standard budget values because the budget is server-owned and fixed.
- Use one icon family consistently, likely Lucide (already familiar from shadcn) but avoid decorative icons per sentence; no emoji for important workflow status.

### Tokens (role contracts, final hues require rendered review)

| Group | Roles and invariant |
|---|---|
| Surface | `background`, `foreground`, `card`, `card-foreground`, `muted`, `muted-foreground`, `popover`, `border`, `input` |
| Action | `primary`, `primary-foreground`, `secondary`, `accent`, `ring`, `destructive`; one brand emphasis, do not use verdict green/red as branding |
| Status | `success`, `warning`, `danger`, `info`, `neutral` with icon, text and subtle surface; **confirmed vs suspected vs coverage gap** have distinct copy |
| Navigation | `sidebar`, `sidebar-foreground`, active/hover/focus states, selection indicator |
| Type | Geist-like readable UI sans; JetBrains Mono (fallbacks) for IDs, timestamps/hashes; tabular numerals; a modest hierarchy (body 14–16px, labels ≥12px); avoid 9px labels |
| Density | spacing scale from 4px increments, compact 36–44px controls as context requires, table row 44–56px, functional max-width with sensible wide-desktop table strategy |
| Geometry | control radius ~8px, panels ~12px, sparing shadows in light mode, almost none in dark; borders only where needed for grouping |
| Motion | 150–220ms color/opacity transitions, no decorative continual motion, progress only for real running state; `prefers-reduced-motion` disables movement |

**Theme gate:** computed contrast >= 4.5:1 for ordinary text, >=3:1 for large text and meaningful UI graphics/controls; focus is visible; both modes retain table dividers, disabled/hover states, form inputs, overlays and colored status cues. Automated axe or equivalent + actual keyboard/manual review, not simply source-token checks. Respect forced-colors and 200% zoom where possible.

### Reusable component interfaces (planning-only)

| Component | Input / behavior | Verification |
|---|---|---|
| `AppShell` | active section, breadcrumbs, navigation, login/session theme; semantic `<main>` | nav, focus, mobile menu, keyboard, no lost current route |
| `ThemeProvider` | initial user preference/system fallback; setters; single root attribute | no flash, reload and OS preference, light/dark contrast |
| `PageHeader` | title, description, optional primary action | consistent title hierarchy, narrow layout |
| `StatusIndicator` | typed state, label, optional timestamp; never success color alone | states including queued/stale/blocked and screen reader text |
| `AssessmentSummary` | server-backed assessment meta, status and allowed actions | no implicit start, no fictional metrics |
| `AssessmentStageList` | four server-owned stage statuses and permitted actions | no dispatch on mount; correct disabled/reason states, ARIA |
| `AssessmentTable` | server-supplied paginated assessments | long IDs, zero rows, loading, error, keyboard rows |
| `FindingsTable` | persisted finding/gap DTOs + filter | safe long paths, honest outcomes, paginated/filter semantics |
| `EvidenceInspector` | selected evidence reference and permitted metadata | keyboard focus, Escape, trap, return focus, redaction |
| `EmptyState` / `ErrorState` | precise issue, action, retry where safe | distinguish offline vs unauthorized vs empty vs zero findings |

Do not build a giant generic component library before proving the first Overview and Red Team slices. Reuse shadcn source components and colocate only MARS-specific composites needed by more than one view.

## 5. UX state and interaction contracts

| Surface | Must handle |
|---|---|
| Login | checking session, invalid credentials, locked/busy submit, network interruption, logout/session expiry, no password exposure; theme in both modes |
| Overview | first-use empty, real ready, partial data, Red API unavailable, legacy research DB absent, loading, denied session, refresh |
| New assessment | no registered target, selecting target, Manual/Autonomous, Standard scope review, draft, authorized, queued/running, backend failure, cancellation, recovery; idempotent command IDs |
| Workspace | reload/deep link, unknown ID, denied access, queued, running, stale plan, blocked, failed, cancelled, completed, completed_with_limitations |
| Findings | zero valid findings, suspected-only alert, confirmed, inconclusive, not-confirmed, multiple rows, long paths, unavailable evidence, data-redaction errors |
| Theme & responsive | light/dark persistence, operating-system default, first-frame paint, desktop to phone (320/390/768/1024/1440/1920), 200% zoom, keyboard only, reduced motion |

**Microcopy principles:** real action verbs and outcomes. Replace “stage-transition” with a user-facing event (“Reconnaissance completed”) when truthful; “View evidence” rather than generic “Inspect” where clear; avoid overclaiming vulnerability impact. Keep raw IDs and hashes available but secondary. Label unavailable state separately from an empty dataset. Feedback must state whether a command was **accepted/queued**, **running**, or **completed**, without conflation.

## 6. Migration architecture: safe incremental approach

```text
Existing APIs, auth, Red store and orchestrator (unchanged)
                       │
             React 18 / Vite 6 app
                       │
       One theme bridge with CSS tokens
                       │
      Tailwind v4 utility/layout layer
                       │
    Selected shadcn/ui source components
                       │
       MARS composed views by domain
          ├─ Overview
          └─ Red Team
        legacy views + Blue still render
```

**Order:** first establish baseline screenshots/tests, then prototype theme and 2–3 components without replacing the entire UI, migrate shell/Overview, migrate Red landing/setup, then stage list and findings, then harden accessibility/performance, finally remove only redundant style rules **after verified call-site migration**. Keep legacy CSS as controlled compatibility until all untouched pages pass theme parity. Avoid duplicate style engines toggling contradictory colors.

**Preserved behavioral/security invariants:** one app login; session-cookie auth; Origin/CSRF/request-id checks; immutable Standard policy and registered targets/tests; no implicit scan on view, theme toggle, recovery or evidence dialog; fixed tool budgets; independent verification/provenance; Blue untouched; no research dataset alteration. Do not run live Docker scans as part of UI testing unless explicitly authorized. Use mocks or read-only real records.

## 7. External inspiration and Figma references (researched, not imported)

| Verified public reference | Relevant idea | Caution |
|---|---|---|
| [Figma shadcn/ui Design System](https://www.figma.com/community/file/1203061493325953101/shadcn-ui-design-system) | Component semantics, light/dark tokens | Community Figma reference, not a drop-in repository library. Verify variants/permissions before reuse. |
| [Figma shadcn/ui components with variables, Oct 2026](https://www.figma.com/community/file/1342715840824755935/shadcn-ui-components-with-variables-tailwind-classes-updated-october-2026) | Variable-driven component states | Verify licensing, maintenance and actual version before adoption. |
| [Figma SOC Dashboard (Cyber Security)](https://www.figma.com/community/file/1596233030947325421/soc-dashboard-cyber-security) | Operational density, real alert hierarchy, tables | Do not mimic fake threat metrics or decorative glows. |
| [Figma Fortify360 IAM Security Dashboard](https://www.figma.com/community/file/1608845230650288436/fortify360-enterprise-iam-security-dashboard-ui-kit) | Professional enterprise navigation and structured tables | IAM features are not the MARS feature set. Adapt only patterns. |
| [Figma Analytics Dashboard UI Kit Starter](https://www.figma.com/community/file/1587366900893623487/analytics-dashboard-ui-kit-starter-figma) | Neutral layout rhythm, dashboard hierarchy | KPI counts must come from Red server. |
| [21st.dev Table With Dialog](https://21st.dev/@ruixen.ui/components/table-with-dialog) | Compact data rows and view-detail workflow | Its shadcn/Tailwind dependencies may differ; prefer native shadcn. |
| [21st.dev Timeline](https://21st.dev/@nyxbui/components/timeline) | Four-status step list | Use real state, low motion, not demo sample content. |
| [21st.dev modal guidance](https://21st.dev/blog/react-modal-dialog-components) | Short modal vs sheet vs full page by task | Long evidence should have linkable route. |
| [StandoutMCP AI-slop checklist](https://standoutmcp.io/guides/fix-vibe-coded-ui-checklist) | Strong hierarchy, one accent, meaningful states, keyboard/focus | Marketing advice is not a formal WCAG test. |
| [Creative Mind Habits UI critique](https://www.creativemindhabits.com/posts/2026-06-21-how-to-make-your-vibe-coded-app-not-look-vibe-coded/) | Authentic language, deliberate whitespace, empty/loading | Applies to app content, not a request for a decorative landing hero. |
| [VibeMole anti-template UI](https://vibemole.com/resources/avoid-vibecoded-app-design) | Avoid nested cards, pills, vague copy and same-size grids | Keep status labels where functionally useful. |
| [Official shadcn Vite setup](https://ui.shadcn.com/docs/installation/vite), [Tailwind v4](https://ui.shadcn.com/docs/tailwind-v4), [theming](https://ui.shadcn.com/docs/theming) | Exact installation/variable integration reference at implementation time | Verify current versions before running CLI. |

**Figma access note:** No editable MARS Figma source file or Figma file key was supplied. Public community references were discovered and linked; no native Figma file was opened, copied or edited. The next design phase may make a Figma moodboard/component spec **only if separately authorized**.

## 8. Acceptance gates and evidence

- **Gate A:** Baseline route, screenshot, theme and browser error matrix (existing light/dark images are preliminary); stable Git status, no scan triggered.
- **Gate B:** Tailwind/shadcn coexistence in a single isolated UI slice; build, tests, light/dark and legacy smoke pass; no React version migration.
- **Gate C:** Approved tokens/layout/component standards, computed contrast checks and keyboard/focus states in both themes.
- **Gate D:** Overview tells the truth about Red assessment readiness, real activity, and the next action without old “coming later” copy.
- **Gate E:** Red create/authorize/start/resume journey is direct, accessible and still safe; no unintended dispatch, duplicate start, weakened auth or idempotency.
- **Gate F:** Stage timeline and findings/evidence are readable and accurate; every status has accessible label; no mock mistaken for live data.
- **Gate G:** `npm test`, `npm run build`, browser screenshots/axe, keyboard, zoom, mobile; relevant backend/auth tests only if the API changes, plus signoff for untouched Blue and old routes. Report exact checks, known gaps, and review approval.

## 9. Implementation and reporting rules

- Work in small branches/slices **only after new authorization**. Read `AGENTS.md`, live `git status`, `tasks/plan.md`, `tasks/todo.md` and current design plan; safeguard the `agents.md` deletion. No git commit/push/dependency installation implied by this plan.
- Preserve selected Figma/21st links as references, not licenses or required packages. No surprise new design library, animation engine or generic UI generation.
- For every change: record affected frontend files, checks, visual before/after in light/dark, contrast/keyboard notes and any omitted cases. Flag real API/backend outages as separate from visual design failures.
- After the UI phase, undertake a **separately authorized** architecture/docs/legacy cleanup based on the previous audit; Blue-specific refactor is not authorized.
