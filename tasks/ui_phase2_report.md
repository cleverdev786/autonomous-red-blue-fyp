# Phase 2 — shell and Overview

Date: 2026-10-30. Implementation based on development 56ff2af plus the existing Phase 1 working tree.

## Changes

- Primary navigation contains Overview, Red Team and Blue Team. Research and legacy tools are grouped in a disclosure; their routes and System access remain reachable.
- The desktop rail has persistent readable labels. Mobile keeps the existing drawer, Escape handling and focus management. Overview metrics use two columns on narrow screens and four on desktop; activity rows stack on mobile.
- Overview independently reads the existing validated Red target, summary and assessment-list APIs. Loading, service unavailable, access denied, no registered target, no assessments and stored status variants have explicit feedback. Retrying only repeats reads.
- The primary action opens Red Team for review. Assessment entries also lead to Red Team; selecting an exact assessment by canonical URL remains UI-18 work. No assessment write is added to Overview.
- Findings and coverage are API values with an explicit warning that counts may include repeats across assessments and completion does not establish target safety.
- Historical research is a secondary disclosure, independent of Red availability. Blue is honestly described as deferred.
- Theme initialization now runs in the document head before React mounts, using the existing preference and OS fallback. The page title uses h1; the MARS sidebar mark is no longer a second h1.
- Sign out uses the existing session endpoint and reports failure without claiming the session ended.

## Checks

The complete frontend suite passed after the navigation, Overview and account changes. Updated Overview tests cover loading, network/service error, access denial, missing targets, empty history, running, cancelled, blocked, completed-with-limitations and escaped untrusted labels. Existing Red API, authorization, workspace, routes, keyboard-row, login and evidence checks pass.

Production build passed. git diff --check passed. The final CSS import-order correction is also covered by a subsequent build.

## Remaining acceptance evidence

UI-14 remains open: this turn has no browser-control tool available. Actual light/dark screenshots, computed contrast, mobile/zoom review, keyboard traversal, screen-reader review, drawer focus and logout interaction have not been exercised against the new implementation. The breakpoint rules are implemented, but no 320/390/768/1024/1440/1920 browser pass is claimed.

The preceding phase's audit still has UI-02 missing visual cases. Phase 2 does not silently close those gaps.

No backend contracts, Blue behavior, research data or existing agents.md deletion were changed. No commit or push was made.
