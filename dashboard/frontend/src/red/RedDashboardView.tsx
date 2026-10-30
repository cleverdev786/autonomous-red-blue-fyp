import { ActionButton, EmptyState, LoadingState, Notice } from "../ui";
import { Button } from "../components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { assessmentPath } from "../routes";
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
      <div className="filter-field"><label id="target-filter-label">Target</label>
        <Select value={targetId || "all"} onValueChange={value => onTargetChange(value === "all" ? "" : value)}>
          <SelectTrigger aria-labelledby="target-filter-label"><SelectValue>{targetId || "All Targets"}</SelectValue></SelectTrigger>
          <SelectContent position="popper" align="start"><SelectItem value="all">All Targets</SelectItem>
            {targets.map(target => <SelectItem key={target.target_id} value={target.target_id}>{target.target_id}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <div className="filter-field"><label id="status-filter-label">Assessment status</label>
        <Select value={status || "all"} onValueChange={value => onStatusChange(value === "all" ? "" : value)}>
          <SelectTrigger aria-labelledby="status-filter-label"><SelectValue>{status ? label(status) : "All statuses"}</SelectValue></SelectTrigger>
          <SelectContent position="popper" align="start"><SelectItem value="all">All statuses</SelectItem>
            {assessmentStatuses.map(item => <SelectItem key={item} value={item}>{label(item)}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>
      <ActionButton variant="secondary" disabled={state.kind === "loading"} onClick={onRefresh}>
        {state.kind === "loading" ? "Refreshing…" : "Refresh"}</ActionButton>
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
    <p className="text-sm text-muted-foreground">Totals span stored assessments and can include repeated findings. Workflow completion does not establish target safety.</p>
    {assessments.find(item => ["queued", "running", "awaiting_authorization"].includes(item.status)) &&
      <section className="surface-card p-4"><h3>Continue an assessment</h3>
        {assessments.filter(item => ["queued", "running", "awaiting_authorization"].includes(item.status)).map(item =>
          <Button key={item.assessment_id} variant="outline" asChild><a href={assessmentPath(item.assessment_id)}
            onClick={event => { if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
              event.preventDefault(); onInspect(item.assessment_id);
            } }}>{item.target_id} · {label(item.status)}</a></Button>)}
      </section>}
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
          <tbody>{assessments.map((item, index) => <tr key={item.assessment_id}>
            <td><span className="assessment-number" title={item.assessment_id}>Assessment {String(offset + index + 1).padStart(2, "0")}</span>
              <small className="record-caption">List position · {item.profile}</small></td>
            <td>{item.target_id}</td><td>{item.mode}</td>
            <td><span className={`red-status red-status--${item.status}`}>{label(item.status)}</span></td>
            <td><span>{item.coverage.executed} / {item.coverage.eligible}</span>
              <progress aria-label={"Executed tests for assessment " + (offset + index + 1)}
                value={item.coverage.executed} max={Math.max(1, item.coverage.eligible)} /></td>
            <td>{activeStage(item) ?? "None"}</td><td><Button variant="outline" asChild>
              <a href={assessmentPath(item.assessment_id)} aria-label={"Open workspace for assessment " + item.assessment_id}
                onClick={event => { if (event.button === 0 && !event.metaKey && !event.ctrlKey && !event.shiftKey && !event.altKey) {
                  event.preventDefault(); onInspect(item.assessment_id);
                } }}>Open workspace</a></Button></td>
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
