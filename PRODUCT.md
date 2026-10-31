# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

MARS serves students, researchers, and authorized security operators conducting controlled local security research and demonstrations. They need to run reproducible assessments, understand findings and evidence, and evaluate remediation through one dashboard.

## Product Purpose

MARS is a Final Year Project and research-oriented cybersecurity platform. Its purpose is to automate controlled web application vulnerability detection, verification, and remediation through a multi-agent Red–Blue framework.

The primary outcome is a working, reproducible end-to-end assessment and remediation workflow with clear evidence, findings, audit history, and a unified dashboard. This is the product goal; individual capabilities have different implementation and validation status.

## Positioning

MARS combines coordinated Red assessment and Blue remediation research in an authorized, isolated Docker lab. Explicit scope approval, bounded execution, independent verification, and traceable evidence are central to its mechanism. It is an academic research and demonstration platform, not a public vulnerability-scanning service.

## Operating Context

- The existing application uses React 18, TypeScript, and Vite with Tailwind CSS v4 and selected shadcn/Radix components, backed by Python/FastAPI services and durable assessment state/evidence.
- The main operator journey is application login → Overview → Red Team assessment history → new assessment → registered target and Manual/Autonomous mode → Standard scope review and explicit authorization → stage progress → findings, coverage, and evidence.
- Red uses deterministic Reconnaissance, Planning, Execution, and Verification workers coordinated by the Central Orchestrator. Manual and Autonomous modes share trusted policy and evidence boundaries.
- Use current source and maintained plans as truth. `tasks/plan.md` and `tasks/todo.md` govern approved Red requirements; they are not the complete specification for Blue development. Repository instructions flag `README.md` and `PROGRESS.md` as outdated.

## Capabilities and Constraints

### Current implementation

- Red assessment workflows support registered SQL injection, reflected XSS, and path traversal tests in the controlled lab, including history, workspace URLs, stage controls, cancellation, findings, coverage, and evidence inspection.
- Blue code already exists: monitoring, triage, code analysis, and patch proposal agents under `agents/blue/`; classification/localization, patch preparation, branch staging, and constrained replay services under `services/`. These are substantive implementation paths, with development and admission gates; their existence does not establish general end-to-end readiness.
- The primary `/dashboard/blue-team` route currently renders a placeholder. Existing legacy assessment, remediation, patch-verification, reports, and system routes expose other research/operator functionality. A placeholder Blue page must not be interpreted as absence of Blue backend work.

### Product boundaries and current work scope

- Security testing requires authorization and an isolated Docker environment. Public, external, production, and unapproved targets are outside the intended operating scope.
- Preserve existing architecture, behavior, authentication, authorization, registered scope, fixed budgets, provenance, redaction, and evidence integrity. Navigation, rendering, or theme changes must not start an assessment.
- Workflow completion and security coverage are distinct. Display observed outcomes accurately; do not imply that a completed assessment proves an application safe.
- Current UI work is limited to **Overview and Red Team**. Preserve other surfaces and their behavior. The research tools page design is not confirmed.
- The broader Blue goal is evidence analysis, vulnerable-code identification, patch proposals, and fix verification. Determine further work from Blue-specific source and approved decisions rather than extrapolating Red plans.

## Brand Commitments

Preserve the MARS name, existing mark, terminology, and approved UI decisions. Existing light/dark themes, shared navigation, and component conventions remain the incumbent design. `tasks/plan_ui.md`, `tasks/tasks_ui.md`, source code, and associated reports record UI decisions and their verification status; this product record does not replace them.

## Evidence on Hand

- Red requirements and completion tracking: `tasks/plan.md`, `tasks/todo.md`.
- Red operational and acceptance documentation: `docs/RED_TEAM_RUNBOOK.md`, `docs/RED_TEAM_ACCEPTANCE_REPORT.md`.
- Existing UI evidence and limitations: `tasks/ui_evidence/`, UI phase and acceptance reports under `tasks/`.
- Blue implementation evidence: `agents/blue/`, `services/blue_*.py`, `services/trusted_remediation_compiler.py`, and existing dashboard remediation/verification code.

Historical screenshots, research results, and acceptance reports retain their original scope and dates. Do not present historical counts as live data or infer research qualification from development evidence.

## Product Principles

- Make research workflows reproducible and evidence traceable.
- Keep operator authorization and server-owned policy in control of execution.
- Distinguish implemented behavior, development demonstrations, verified results, and planned work.
- Preserve research data and audit history through normal operations.
- Present one coherent operator workflow while respecting each subsystem's requirements.

## Accessibility & Inclusion

Preserve the maintained UI plan's keyboard, visible-focus, contrast, responsive, reduced-motion, and light/dark requirements. Existing automated results are scoped evidence, not comprehensive accessibility certification. No additional audience-specific accessibility needs were supplied during initialization.

## Open Decisions

- Blue-specific roadmap, release acceptance, and integration priorities require their own confirmed scope and evidence review.
- Research tools information architecture and design are unconfirmed.
- Additional audience-specific accessibility needs remain unspecified.
