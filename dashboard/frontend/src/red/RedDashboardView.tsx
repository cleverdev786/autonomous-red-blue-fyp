import { ActionButton, EmptyState, LoadingState, Notice } from "../ui";
import {
  assessmentStatuses,
  type RedAssessment,
  type RedDashboardSummary,
  type RedTarget,
} from "./api";

export type RedDashboardState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; summary: RedDashboardSummary; assessments: RedAssessment[];
      total: number; offset: number; limit: number };

const label = (value: string) => value.replaceAll("_", " ");

export function RedDashboardView({ targets, targetId, status, state, onTargetChange,
  onStatusChange, onRefresh, onPageChange, onInspect }: {
  targets: RedTarget[];
  targetId: string;
  status: string;
  state: RedDashboardState;
  onTargetChange: (value: string) => void;
  onStatusChange: (value: string) => void;
  onRefresh: () => void;
  onPageChange: (offset: number) => void;
  onInspect: (assessmentId: string) => void;
}) {
  return <div className="mars-content red-dashboard">
    <section className="red-dashboard-toolbar" aria-label="Red dashboard filters">
      <label>Target
        <select value={targetId} onChange={event => onTargetChange(event.target.value)}>
          <option value="">All Targets</option>
          {targets.map(target => <option key={target.target_id} value={target.target_id}>{target.target_id}</option>)}
        </select>
      </label>
      <label>Assessment status
        <select value={status} onChange={event => onStatusChange(event.target.value)}>
          <option value="">All statuses</option>
          {assessmentStatuses.map(item => <option key={item} value={item}>{label(item)}</option>)}
        </select>
      </label>
      <ActionButton variant="secondary" onClick={onRefresh}>Refresh</ActionButton>
    </section>

    {state.kind === "loading" && <section className="surface-card red-dashboard-state" aria-busy="true">
      <LoadingState label="Loading Red assessment data…" />
    </section>}
    {state.kind === "error" && <Notice title="Red dashboard unavailable" tone="danger">
      {state.message} Check the local Red service, then refresh.
    </Notice>}
    {state.kind === "ready" && <ReadyDashboard summary={state.summary}
      assessments={state.assessments} total={state.total} offset={state.offset}
      limit={state.limit} onPageChange={onPageChange} onInspect={onInspect} />}
  </div>;
}

function ReadyDashboard({ summary, assessments, total, offset, limit, onPageChange, onInspect }: {
  summary: RedDashboardSummary;
  assessments: RedAssessment[];
  total: number;
  offset: number;
  limit: number;
  onPageChange: (offset: number) => void;
  onInspect: (assessmentId: string) => void;
}) {
  const metrics = [
    { label: "Verified findings", value: summary.confirmed_findings,
      detail: `${summary.confirmed_findings} confirmed · ${summary.suspected_findings} suspected` },
    { label: "Endpoint coverage", value: `${summary.tested} / ${summary.eligible}`,
      detail: `${summary.coverage_gaps} open coverage gaps` },
    { label: "Active assessments", value: summary.active_assessments,
      detail: `${summary.queued_assessments} queued` },
    { label: "Agent activity", value: summary.active_stages,
      detail: `${summary.active_stages} queued or running stages` },
  ];
  return <>
    <section className="red-metrics" aria-label="Red Team metrics">
      {metrics.map(metric => <article className="red-metric" key={metric.label}>
        <span>{metric.label}</span><strong>{metric.value}</strong><small>{metric.detail}</small>
      </article>)}
    </section>
    <section className="surface-card red-history" aria-labelledby="red-history-title">
      <div className="red-history-head">
        <div><h3 id="red-history-title">Assessment history</h3>
          <p>Server-authoritative Red assessments matching the selected filters.</p></div>
        <span className="section-count">
          {total === 0 ? "0 records" : `${offset + 1}–${Math.min(offset + assessments.length, total)} of ${total}`}
        </span>
      </div>
      {assessments.length === 0 ? <EmptyState title="No matching assessments"
        description="No persisted Red assessment matches these target and status filters." /> :
        <div className="table-wrap"><table>
          <thead><tr><th scope="col">Assessment</th><th scope="col">Target</th>
            <th scope="col">Mode</th><th scope="col">Status</th>
            <th scope="col">Coverage</th><th scope="col">Active stage</th><th scope="col"><span className="sr-only">Open</span></th></tr></thead>
          <tbody>{assessments.map(item => <tr key={item.assessment_id}>
            <td><span className="red-assessment-id">{item.assessment_id}</span></td>
            <td>{item.target_id}</td><td>{item.mode}</td>
            <td><span className={`red-status red-status--${item.status}`}>{label(item.status)}</span></td>
            <td>{item.coverage.executed} / {item.coverage.eligible}</td>
            <td>{activeStage(item) ?? "None"}</td><td><button className="red-inspect-link"
              onClick={() => onInspect(item.assessment_id)}>Open workspace</button></td>
          </tr>)}</tbody>
        </table></div>}
      {total > limit && <nav className="red-history-pages" aria-label="Assessment history pages">
        <ActionButton variant="secondary" disabled={offset === 0}
          onClick={() => onPageChange(Math.max(0, offset - limit))}>Previous</ActionButton>
        <ActionButton variant="secondary" disabled={offset + assessments.length >= total}
          onClick={() => onPageChange(offset + limit)}>Next</ActionButton>
      </nav>}
    </section>
  </>;
}

function activeStage(assessment: RedAssessment): string | null {
  const active = Object.entries(assessment.stage_statuses).find(([, stage]) =>
    stage === "queued" || stage === "running");
  return active ? `${label(active[0])} · ${label(active[1])}` : null;
}
