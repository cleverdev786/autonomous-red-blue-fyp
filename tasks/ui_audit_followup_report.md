# UI audit verification and hardening — 2026-10-31

The owner supplied `/home/zain/Documents/audit report` as material to verify, and explicitly requested fixes for search flicker and vertically arranged pagination. Recommendations were checked against the current code rather than treated as instructions to replace working components or change assessment behavior. Taste, HardenUI (harden), and Ponytail were used. Impeccable's context launcher could not run because its engine/cache was unavailable; no PRODUCT.md or DESIGN.md exists in this repository, so the established implementation and UI plan supplied the design context.

## Confirmed root causes

- Legacy unlayered `nav { display:grid }` overrode Tailwind's layered `flex` utility. The pagination is now explicitly scoped as a single horizontal flex row.
- Each debounced search previously fetched targets, summary metrics, and history together and toggled the page-wide Refresh control. Table requests now fetch history alone. Metrics/target metadata have a separate effect and explicit refresh behavior; abort guards preserve latest-request ownership. Search input remains mounted and focused, with a reserved local update indicator.
- Highlight fragments were separate flex items inside status pills, introducing gaps within words and inconsistent CSS capitalization. A single text wrapper and preformatted capitalization keep text contiguous. Highlights update with acknowledged results. Fixed table layout prevents the columns changing width with each match, and dashboard content does not replay its entry animation.

## Audit dispositions

| Finding | Verified treatment |
| --- | --- |
| Floating mobile menu | Existing focus-managed dialog reused as a flush-right, full-height 288px drawer with backdrop; no new Sheet dependency or duplicate focus trap. |
| Detached collapse toggle | Moved into the brand header; collapsed rail retains both mark and toggle. |
| Loose top controls | Existing bar made a semantic sticky desktop header. |
| Two mobile header strips | Desktop utility strip hidden on mobile; account/theme actions placed inside the drawer. |
| Login theme control inside card | Moved to fixed viewport top-right. |
| Pale dark Sign in | Scoped muted violet primary with white text; global verdict and theme colors unchanged. |
| Input boundaries | Existing semantic inputs retain validation/autocomplete, now use contrasting theme background and border. Mobile input size avoids focus zoom. |
| Password reveal alignment | Centered with 50% positioning and translateY. |
| Mobile assessment card alternative | Not adopted: latest owner table brief explicitly requests a scrollable semantic table. Minimum table width, fixed columns and nonwrapping workspace buttons fix the observed failure while keeping one searchable/selectable table. |
| Dark New assessment contrast | Scoped muted violet with white text; existing hover remains. |
| Coverage progress | Native labelled progress retained, styled as a rounded 96×6px track. No cosmetic replacement of an accessible platform element. |
| Dashboard hierarchy | Metrics precede the filters; target/status/refresh sit with assessment history and search. |
| Toast obscures pagination | Existing dismissible toast moved below the header at the top-right, clear of pagination. No Sonner dependency added. |
| Manual Run escapes card | Implicit grid placement was the cause, not absolute positioning. Explicit grid areas keep metadata, actions, reason and expanded history in their assigned rows at every breakpoint. |
| Timeline dots disconnected | A one-pixel connector rail joins the stage indicators. |
| Duplicate time text | Last-action summary uses the action; exact event timestamps remain in expanded history. No elapsed duration is invented because it is not supplied by this API. |
| Tall mobile manual cards | Three-column secondary metadata and two-column actions; operation selector spans the action row. |
| Findings overflow | Already contained by keyboard-accessible overflow region and minimum-width table; retained and checked. |
| Raw severity text | Text-labelled severity pills with semantic colors; unrated remains neutral. |
| Inline audit dump | Already fixed for normal inspection: evidence opens in a focus-managed Dialog. Explicit audit deep links intentionally retain their auditable detail section; not removed. |
| Heavy dialog close border | Borderless muted/hover treatment while preserving focus visibility and accessible Close text. |
| Native red workflow dropdowns | Findings outcome, registered-operation and history page-size controls now use the installed shadcn Select. Target/status already used it. Legacy research selectors remain native themed controls; no blanket legacy rewrite. |
| Thick focus glow | Select triggers use a clear two-pixel outline and no layered glow. Kept visible focus rather than reducing it to the audit's suggested one pixel. |
| Inconsistent pills | Shared rounded shape and leading status dot; history retains one dot, without duplicating its existing dot. |

No backend authorization, command dispatch, queue, evidence, migration or deletion behavior changed in this follow-up. Existing user changes and the preexisting `agents.md` deletion are preserved. No commit or push. Pagination stays on one row and is locally scrollable if a long page-number set exceeds the available mobile width.

## Verification

- Focused failing check first: the old API had no history-only request function. Added assertion verifies a search request reaches only the assessment endpoint, without refetching metrics or target metadata.
- `npm --prefix dashboard/frontend test`: all 15 script groups passed after the changes, including API/schema errors, command denial/operation selection, routing, navigation, keyboard, themes and safe text rendering.
- `npm --prefix dashboard/frontend run build`: passed (TypeScript and Vite; 2,174 modules). A final CSS conflict correction was rebuilt and confirmed live.
- `git diff --check`: passed.
- Existing Python regression results are recorded in the preceding table report; no new Python changes were introduced here.

Live verification uses the real local app through its controls, without fixture browser scripts or screenshot-based acceptance. No assessment execution, original-history deletion, model load or patch application is authorized or needed. Audible screen-reader certification and the earlier owner signoff remain open.

Live observations:

- Reproduced the original pagination as computed `display:grid` with the third button on the next row. Rebuilt pagination computes `display:flex`; all three buttons share exactly the same Y coordinate.
- At 1440px, typing successive search queries left Refresh unchanged and retained input focus. Document-relative metric position remained 305.1875px and table width remained 1089.5625px before/after search. Completed results render as contiguous “Completed” text, with matching highlights inside a single text span. Empty and clear behavior remain covered by the preceding tests and current suite.
- Desktop rail collapses/expands from the brand header. At 390px, mobile drawer bounds were top 0, right 390, bottom 844, width 288; account controls appeared in the drawer and the duplicate utility strip was absent. Escape restored Menu focus.
- Expanded manual Inspect on retained Assessment 06: Run/Inspect stayed inside the card; history used its assigned grid area. Mobile light layout had equal 79px metadata columns, two-column actions, and document/client width 375px without overflow. Terminal Run remained disabled; no command was dispatched.
- Opened completed Assessment 05 on mobile: severity labels, three existing findings and outcome dropdown worked. Selecting confirmed retained the expected outcomes. Evidence dialog was 358px wide in a 390px viewport, close border computed to zero, Escape returned focus to the exact Inspect trigger. No evidence or history was changed.
- Login theme control was outside the card and fixed; mobile inputs computed to 16px and password remained hidden. The first pass found an old high-specificity dark text rule overriding the new primary foreground; that conflict was fixed in the one correction batch.

Limitations: five original history records were preserved; no new runs or disposable records were created for this audit. Multi-page algorithms remain covered by focused tests rather than extra live records. The registered-operation dropdown is contract/regression tested; no eligible live manual stage was started to exercise it. No new automated axe matrix, screenshot comparison, audible screen-reader certification, or overall application signoff is claimed.

Final login confirmation: white text (`rgb(255,255,255)`) on the muted violet primary (`rgb(113,83,196)`), with password reveal icon center delta 0px. Signed back in and restored the Red Team dashboard and original dark theme.
