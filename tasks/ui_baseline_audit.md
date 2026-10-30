# MARS UI baseline audit — UI-01 to UI-04

**Date:** 2026-10-30
**Baseline:** `development` at `56ff2af` (one local commit ahead of `origin/development`)
**Scope:** read-only UI/UX audit. No assessment was created, authorized, started, cancelled, or otherwise dispatched.

## UI-01 — repository, routes, and account inventory

The working tree was already dirty before this work: `agents.md` is deleted and must remain untouched; `tasks/plan_ui.md` and `tasks/tasks_ui.md` are the user-provided, untracked UI planning inputs. The Red roadmap in `tasks/plan.md` and `tasks/todo.md` is complete through its existing tasks and was read only for compatibility constraints.

The application mounts at `/dashboard/`. Its current route map is:

| Route | Current responsibility |
| --- | --- |
| `/dashboard/` | Overview; historical stored-run state plus links to all workspaces |
| `/dashboard/red-team` | Red dashboard, new-assessment flow, and in-memory selected workspace |
| `/dashboard/blue-team` | Deferred Blue Team entry |
| `/dashboard/assessments`, `/findings`, `/remediation`, `/reports`, `/system` | Preserved legacy primary routes |
| `/dashboard/reports/*`, `/dashboard/remediation/patch-verification` | Preserved legacy deep links |

`AuthenticatedApp` first checks `/api/auth/session`; it then shows the shared login form or `App`. Theme selection is persisted as `mars-theme`, uses `html[data-theme]`, and falls back to the OS preference. The local runbook documents the FastAPI dashboard at `127.0.0.1:8090`, session-cookie authentication, and the rule that opening UI must not authorize Red operations.

## UI-02 — visual matrix

The real local dashboard at `http://127.0.0.1:8090/dashboard/` was used after authenticated access was supplied by the owner. Visual captures were reviewed interactively at the named viewport/theme/state combinations below; no assets are committed because these contain local assessment metadata and are baseline evidence rather than product assets.

| Capture ID | Route/state | Viewport | Theme | Result |
| --- | --- | ---: | --- | --- |
| `UI02-overview-dark-desktop` | Overview; historical DB unavailable | 1440×900 | dark | captured; no horizontal overflow |
| `UI02-overview-light-desktop` | Overview; historical DB unavailable | 1440×900 | light | captured; no horizontal overflow |
| `UI02-red-light-desktop` | Red landing with existing history | 1440×900 | light | captured; no horizontal overflow |
| `UI02-red-dark-desktop` | Red landing with existing history | 1440×900 | dark | captured; no horizontal overflow |
| `UI02-workspace-dark-desktop` | terminal Autonomous workspace | 1440×900 | dark | captured; no horizontal overflow |
| `UI02-finding-detail-dark-desktop` | persisted finding inspector | 1440×900 | dark | captured; inspector is inline, not a dialog |
| `UI02-red-dark-mobile` | Red landing with collapsed mobile nav | 390×844 | dark | captured; no horizontal overflow |
| `UI02-red-light-mobile` | Red landing with collapsed mobile nav | 390×844 | light | captured; no horizontal overflow |
| `UI02-overview-light-mobile` | Overview loading state | 390×844 | light | captured; no horizontal overflow |

Still required before UI-02 can be closed: login in both themes, Overview mobile dark after the read response resolves, Manual workspace, non-terminal Autonomous progress, error/empty states, and finding detail in light/mobile. Those require controlled fixtures or deliberate state setup; they must not be fabricated from historic screenshots.

## UI-03 — theme and UX defect register

| Severity | Confirmed evidence | Light/dark reproduction | Proposed later slice and proof |
| --- | --- | --- | --- |
| P0 | Overview's primary link remains **Browse assessments** and points to `/dashboard/assessments`; Red is labelled “tools coming later.” (`overview/OverviewPanel.tsx`) | visible in real light and dark desktop/mobile captures | UI-12: promote a truthful Red action/resume state and retain legacy links as secondary. Render/data-state tests plus both theme screenshots. |
| P0 | A terminal autonomous assessment is headed **Live assessment timeline** and renders raw `stage-transition` events. (`red/AssessmentWorkspace.tsx`) | visible in the terminal dark workspace capture | UI-20: use “Assessment timeline” after terminal state and human-readable event labels. Test terminal, queued, running, failed, cancelled and reduced-motion variants. |
| P0 | Recovery code can call `startRedAssessment` for a queued autonomous assessment from an effect. (`red/NewAssessment.tsx:51-63`) | source-confirmed; no command was exercised | UI-17: preserve explicitly intended recovery semantics or remove implicit dispatch. Add a regression that mounting/reloading/opening a workspace never writes. |
| P1 | Current CSS is three overlapping vanilla sheets. `styles.css` defines shell/sidebar/control rules, then later rules override them; `product.css` redefines them again. | source-confirmed; both themes require selector-specific overrides | UI-06–09: introduce Tailwind v4 incrementally, map tokens once, then delete only proven-redundant rules after call-site migration. Build plus computed-style matrix. |
| P1 | The dark theme requires a large selector block in `product.css` (`:root[data-theme="dark"]` around lines 360–439), while many light values are hard-coded throughout the same file. | visible contrast/surface inconsistency risk; token-only tests do not compute selector results | UI-07/09: replace touched literal values with semantic roles and verify computed color/contrast, hover, disabled, focus and native controls. |
| P1 | Login uses a purple radial gradient and a heavy black shadow despite the intended calm operational design. (`styles.css:195-196`) | confirmed in the 1440×900 and 390×844 light login capture | UI-07/11: use the shared semantic surface/brand treatment; confirm login parity in both themes. |
| P1 | The landing prioritizes the new-assessment form above active/history information; long assessment IDs dominate the table. | visible at 1440×900 and 390×844 | UI-15/19: history/current assessment first; short display IDs with accessible full IDs/copy affordance. Test long strings, empty/loading/pages and mobile table behavior. |
| P2 | Finding inspection expands inline and has no dialog semantics (`role="dialog"` absent). | confirmed in desktop detail capture | UI-22: use a shadcn Sheet/Dialog for short metadata and test Escape, focus trap and focus return; preserve long evidence as a route. |

Existing `check-theme.cjs` validates selected hex-token contrast pairs and source snippets; it does not validate browser-computed CSS, mobile layout, keyboard order, forced colors, or 200% zoom. Its passing status is useful but is not an accessibility sign-off.

## UI-04 — chosen design direction

The approved direction is the plan's calm operator workspace: a quiet neutral surface system, one restrained MARS brand accent, compact readable tables, clear status text plus color, and information-first layouts. It deliberately rejects the existing violet/cyan gradient hero, decorative orbit treatment, oversized cards, and any SOC-style fake telemetry or AI-glow.

Use the referenced shadcn/SOC/table/timeline sources only for interaction patterns: semantic controls, compact table scanning, staged operational status, and accessible disclosure. The implementation grammar is:

- Geist-like UI sans plus a mono face for identifiers/timestamps; tabular numerals; one visible page heading.
- Semantic light/dark tokens; status always carries text (and, where useful, icon), never color alone.
- Controls use 36–44px context-appropriate targets, ~8px control radius, ~12px panel radius, visible 2–3px focus, and 150–220ms non-decorative transitions; reduced motion removes movement.
- Mobile starts with one column and an explicit menu; desktop uses a compact rail, restrained utility bar, and a sensible reading-width content area.

This establishes the hierarchy and status grammar required before UI-05 dependency work and the UI-06 Tailwind/shadcn proof of coexistence.

## Checks actually run

- `cd dashboard/frontend && npm test` — passed all 14 existing frontend checks.
- `cd dashboard/frontend && npm run build` — passed.
- `git diff --check` — passed before documentation edits; rerun after checklist/audit edits is required for the final audit record.

No Docker service, scan, Red mutation, or backend contract change was run.

## Phase 1 — Tailwind v4 and shadcn foundation (UI-05 to UI-09)

### UI-05 — compatibility preflight

The frontend uses Node `22.22.0`, npm `10.9.4`, React `18.3.1`, Vite `6.0.5`, and TypeScript `5.7.2`. The official Tailwind Vite path is `tailwindcss` plus `@tailwindcss/vite`; the official shadcn Vite guide supports existing Vite projects and copied component source. Neither requires a React 19 upgrade, so React remains unchanged.

Installed direct dependencies are deliberately limited to Tailwind v4's Vite plugin plus shadcn's selected source requirements: `class-variance-authority`, `cn`, `lucide-react`, and the consolidated `radix-ui` package. The shadcn CLI itself is not retained as a project dependency. `npm audit` currently reports two transitive advisories (one moderate, one high); no forced/breaking audit fix was applied.

Rollback is small and local: remove `@tailwindcss/vite` from `vite.config.ts`, remove the Tailwind import/theme block and `components.json`, remove the generated component files, then remove only the listed dependencies. No API or backend change is coupled to this migration.

### UI-06 — coexistence proof

`vite.config.ts` now registers `tailwindcss()`. `styles.css` imports Tailwind's `theme` and `utilities` layers, intentionally omitting Preflight so that existing global rules do not change beneath untouched screens. The shared `ActionButton` is the isolated utility slice: it delegates to the local shadcn Button source while retaining the existing public `primary`/`secondary` API and compatibility classes.

### UI-07 — theme bridge

The existing `tokens.css` remains the single source of light/dark values. `styles.css` maps its semantic variables to Tailwind v4's `@theme inline` values, and its only Tailwind dark custom variant targets `html[data-theme="dark"]` and descendants. The persisted `mars-theme` key and native `color-scheme` behavior are unchanged; no competing `.dark` strategy was added.

### UI-08 — selected shadcn source

The repository now owns only the Phase 1 primitives: Button, Input, Select, RadioGroup, Dialog, DropdownMenu, Table, Alert, Skeleton, Tooltip, and Badge. They live under `dashboard/frontend/src/components/ui/`; no registry-wide install or generic component layer was added. `TooltipProvider` wraps the application once in `main.tsx`. Radix supplies the keyboard/focus behavior for the interactive primitives; their first feature-specific adoption occurs in the planned Overview and Red slices.

### UI-09 — scoped cascade cleanup and verification

The redundant legacy base/variant `.ui-button` block in `styles.css` was removed once the adapter owned those behaviors. Screen-specific compatibility CSS remains because Overview, Red, Blue, and legacy pages have not yet been migrated; deleting it now would be speculative and unsafe.

Checks after the change:

- `npm run test:foundation` — passed; asserts the Tailwind v4 Vite bridge, existing theme strategy, selected shadcn source, and Button adapter.
- `npm test` — passed (including the new foundation test and the existing routes/login/keyboard/theme/Red checks).
- `npm run build` — passed.
- Browser smoke against `http://127.0.0.1:8090/dashboard/` — authenticated Overview loaded after rebuild; no rendering failure observed. The live Red primary button measured 5.17:1 foreground/background contrast in light theme and 6.48:1 in dark theme; neither view overflowed its desktop viewport.
- `git diff --check` — passed.

The existing theme tests verify key token contrast pairs. Computed browser contrast, zoom, forced-colors, and keyboard/dialog matrix coverage remains deliberately scheduled for UI-24 and UI-25 rather than claimed here.
