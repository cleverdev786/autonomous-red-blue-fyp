import { useEffect, useRef, useState } from "react";
import { ApiRequestError } from "../api";
import { ActionButton, EmptyState, LoadingState, Notice } from "../ui";
import {
  cancelRedAssessment, loadRedFindingDetail, loadRedWorkspace, runRedStage,
  type RedEvent, type RedFinding, type RedFindingDetail, type RedWorkspaceBundle,
} from "./api";

const stages = ["reconnaissance", "planning", "execution", "verification"] as const;
const terminal = new Set(["completed", "completed_with_limitations", "failed", "cancelled", "blocked"]);
const label = (value: string) => value.replaceAll("_", " ");

type State = { kind: "loading" } | { kind: "error"; message: string } |
  { kind: "ready"; data: RedWorkspaceBundle };

export function AssessmentWorkspace({ token, assessmentId, onClose, onChanged }: {
  token: string; assessmentId: string; onClose: () => void; onChanged: () => void;
}) {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [refresh, setRefresh] = useState(0);
  const [commandError, setCommandError] = useState<string | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const requestIds = useRef<Record<string, string>>({});

  useEffect(() => {
    const controller = new AbortController();
    void loadRedWorkspace(token, assessmentId, controller.signal)
      .then(data => setState({ kind: "ready", data }))
      .catch(error => {
        if (error instanceof ApiRequestError && error.kind === "aborted") return;
        setState({ kind: "error", message: workspaceError(error) });
      });
    return () => controller.abort();
  }, [assessmentId, refresh, token]);

  useEffect(() => {
    if (state.kind !== "ready" || terminal.has(state.data.workspace.assessment.status)) return;
    const timer = window.setInterval(() => setRefresh(value => value + 1), 3000);
    return () => window.clearInterval(timer);
  }, [state]);

  async function command(key: string, action: (requestId: string) => Promise<unknown>) {
    const requestId = requestIds.current[key] ?? `${key}-${crypto.randomUUID()}`;
    requestIds.current[key] = requestId;
    setBusy(key); setCommandError(null);
    try {
      await action(requestId);
      delete requestIds.current[key];
      setRefresh(value => value + 1); onChanged();
    } catch (error) { setCommandError(workspaceError(error)); }
    finally { setBusy(null); }
  }

  if (state.kind === "loading") return <section className="surface-card red-workspace-panel" aria-busy="true">
    <LoadingState label="Loading assessment workspace…" />
  </section>;
  if (state.kind === "error") return <section className="surface-card red-workspace-panel">
    <Notice title="Assessment workspace unavailable" tone="danger">{state.message}</Notice>
    <div className="red-workspace-actions"><ActionButton variant="secondary" onClick={onClose}>Back to dashboard</ActionButton>
      <ActionButton onClick={() => setRefresh(value => value + 1)}>Retry</ActionButton></div>
  </section>;
  const data = state.data;
  return <AssessmentWorkspaceView data={data} busy={busy} commandError={commandError}
    onClose={onClose} onRefresh={() => setRefresh(value => value + 1)}
    onRunStage={stage => void command(`run-${stage}`, requestId =>
      runRedStage(token, assessmentId, stage, requestId))}
    onCancel={() => void command("cancel", requestId =>
      cancelRedAssessment(token, assessmentId, requestId))}
    token={token} />;
}

export function AssessmentWorkspaceView({ data, busy, commandError, onClose, onRefresh,
  onRunStage, onCancel, token }: {
  data: RedWorkspaceBundle; busy: string | null; commandError: string | null;
  onClose: () => void; onRefresh: () => void;
  onRunStage: (stage: typeof stages[number]) => void; onCancel: () => void; token: string;
}) {
  const { workspace, events, findings, coverage } = data;
  const assessment = workspace.assessment;
  const active = !terminal.has(assessment.status);
  return <section className="red-workspace-panel" aria-labelledby="red-workspace-title">
    <header className="red-workspace-header surface-card">
      <div><button className="red-back" onClick={onClose}>← Red dashboard</button>
        <span className="eyebrow">Assessment workspace</span>
        <h3 id="red-workspace-title">{assessment.target_id}</h3>
        <p><code>{assessment.assessment_id}</code> · {assessment.mode} · Standard</p></div>
      <div className="red-workspace-actions">
        <span className={`red-status red-status--${assessment.status}`}>{label(assessment.status)}</span>
        <ActionButton variant="secondary" onClick={onRefresh}>Refresh</ActionButton>
        {active && <ActionButton variant="secondary" disabled={busy !== null} onClick={onCancel}>
          {busy === "cancel" ? "Requesting stop…" : "Stop assessment"}</ActionButton>}
      </div>
    </header>
    {commandError && <Notice title="Command not accepted" tone="danger">{commandError}</Notice>}
    {assessment.mode === "manual" ? <ManualPanels data={data} busy={busy}
      onRunStage={onRunStage} /> : <AutonomousTimeline data={data} />}
    <FindingsPanel token={token} findings={findings} coverage={coverage}
      total={data.findingTotal} />
  </section>;
}

function ManualPanels({ data, busy, onRunStage }: { data: RedWorkspaceBundle;
  busy: string | null; onRunStage: (stage: typeof stages[number]) => void }) {
  const [inspected, setInspected] = useState<string | null>(null);
  const { workspace, events } = data;
  const anyRunning = workspace.stages.some(item => item.status === "queued" || item.status === "running");
  return <section className="red-agent-section" aria-labelledby="manual-agents-title">
    <div className="red-section-head"><div><span className="eyebrow">Manual control plane</span>
      <h3 id="manual-agents-title">Four bounded agents</h3></div>
      <span>Each command runs one eligible stage.</span></div>
    <div className="red-agent-grid">{stages.map((stage, index) => {
      const record = workspace.stages.find(item => item.stage === stage);
      const status = record?.status ?? "not_started";
      const reason = stageReason(stage, data, anyRunning);
      const last = [...events].reverse().find(item => item.stage === stage);
      const rerun = status === "succeeded" || status === "failed" || status === "blocked";
      return <article className={`red-agent-card red-agent-card--${status}`} key={stage}>
        <div className="red-agent-index">0{index + 1}</div>
        <div className="red-agent-title"><h4>{agentName(stage)}</h4>
          <span className={`red-status red-status--${status}`}>{label(status)}</span></div>
        <dl><div><dt>Last action</dt><dd>{last ? `${label(last.action)} · ${formatTime(last.occurred_at)}` : "No recorded action"}</dd></div>
          <div><dt>Task count</dt><dd>{stageTaskCount(stage, data)}</dd></div>
          <div><dt>Failure state</dt><dd>{["failed", "blocked"].includes(status) ? label(status) : "None"}</dd></div></dl>
        {reason && <p className="red-disabled-reason" id={`${stage}-reason`}>{reason}</p>}
        <div className="red-agent-actions">
          <ActionButton disabled={busy !== null} aria-disabled={Boolean(reason) || busy !== null}
            aria-describedby={reason ? `${stage}-reason` : undefined}
            onClick={() => { if (!reason) onRunStage(stage); }}>
            {busy === `run-${stage}` ? "Queuing…" : rerun ? "Rerun" : "Run"}</ActionButton>
          <ActionButton variant="secondary" onClick={() => setInspected(inspected === stage ? null : stage)}
            aria-expanded={inspected === stage}>Inspect</ActionButton>
        </div>
        {inspected === stage && <StageHistory stage={stage} events={events} plan={record?.plan_version ?? null} />}
      </article>;
    })}</div>
    {workspace.plans.some(plan => plan.status === "stale") && <Notice title="Plan is stale" tone="warning">
      Reconnaissance changed the surface. Run Planning again before Execution.
    </Notice>}
  </section>;
}

function AutonomousTimeline({ data }: { data: RedWorkspaceBundle }) {
  const { workspace, events } = data;
  return <section className="red-timeline surface-card" aria-labelledby="autonomous-title">
    <div className="red-section-head"><div><span className="eyebrow">Autonomous run · {terminal.has(workspace.assessment.status) ? "terminal record" : "mode locked"}</span>
      <h3 id="autonomous-title">Live assessment timeline</h3></div>
      <span>{terminal.has(workspace.assessment.status)
        ? "Terminal state · polling stopped" : "Polling every 3 seconds while non-terminal"}</span></div>
    <ol>{stages.map(stage => {
      const status = workspace.stages.find(item => item.stage === stage)?.status ?? "not_started";
      const event = [...events].reverse().find(item => item.stage === stage);
      return <li key={stage} className={`red-timeline-step red-timeline-step--${status}`}>
        <span className="red-timeline-node" aria-hidden="true" />
        <div><strong>{agentName(stage)}</strong><p>{event ? label(event.action) : "Awaiting prerequisite"}</p></div>
        <div><span className={`red-status red-status--${status}`}>{label(status)}</span>
          <time>{event ? formatTime(event.occurred_at) : "—"}</time></div>
      </li>;
    })}</ol>
  </section>;
}

function FindingsPanel({ token, findings, coverage, total }: { token: string;
  findings: RedFinding[]; coverage: RedWorkspaceBundle["coverage"]; total: number }) {
  const [filter, setFilter] = useState("all");
  const [detail, setDetail] = useState<RedFindingDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const visible = filter === "all" ? findings : findings.filter(item => item.status === filter);
  const inspect = (finding: RedFinding) => {
    setDetail(null); setDetailError(null);
    void loadRedFindingDetail(token, finding.finding_id).then(setDetail)
      .catch(error => setDetailError(workspaceError(error)));
  };
  return <section className="red-findings surface-card" aria-labelledby="red-findings-title">
    <div className="red-section-head"><div><span className="eyebrow">Verification outcomes</span>
      <h3 id="red-findings-title">Findings & coverage</h3></div>
      <label>Status <select value={filter} onChange={event => setFilter(event.target.value)}>
        <option value="all">All outcomes</option>{["confirmed", "suspected", "not_confirmed", "inconclusive"].map(item =>
          <option value={item} key={item}>{label(item)}</option>)}</select></label></div>
    {visible.length === 0 ? <EmptyState title="No matching findings"
      description="No persisted verification outcome matches this filter." /> :
      <div className="table-wrap"><table><thead><tr><th>Outcome</th><th>Severity</th><th>Category</th>
        <th>Route</th><th>Evidence</th><th><span className="sr-only">Inspect</span></th></tr></thead>
        <tbody>{visible.map(item => <tr key={item.finding_id}><td><span className={`red-status red-status--${item.status}`}>{label(item.status)}</span></td>
          <td>{item.severity ?? "Unrated"}</td><td>{item.category ? label(item.category) : "Unclassified"}</td>
          <td><code>{item.route ?? "Registered target"}</code></td><td>{item.has_evidence ? "Validated metadata" : "No stored evidence"}</td>
          <td><button className="red-inspect-link" onClick={() => inspect(item)}>Inspect</button></td></tr>)}</tbody></table></div>}
    <p className="red-findings-note">{total} persisted outcomes. <a href="/dashboard/reports">Open Reports</a> for existing exports. Blue Team handoff is pending and performs no action.</p>
    {detailError && <Notice title="Evidence detail unavailable" tone="danger">{detailError}</Notice>}
    {detail && <EvidenceDetail detail={detail} onClose={() => setDetail(null)} />}
    <div className="red-gap-list"><h4>Coverage gaps</h4>
      {coverage.gaps.length === 0 ? <p>No persisted coverage gaps.</p> : coverage.gaps.map(gap =>
        <article key={gap.gap_id}><div><strong>{label(gap.reason)}</strong><span>{label(gap.status)}</span></div>
          <p>{gap.recommendation ?? "The registered scope did not produce a completed test."}</p></article>)}</div>
  </section>;
}

function EvidenceDetail({ detail, onClose }: { detail: RedFindingDetail; onClose: () => void }) {
  return <aside className="red-evidence-detail" aria-labelledby="evidence-detail-title">
    <div><span className="eyebrow">Validated provenance</span><h4 id="evidence-detail-title">{detail.finding.finding_id}</h4></div>
    <button className="red-back" onClick={onClose}>Close inspector</button>
    <dl><div><dt>Operation</dt><dd>{detail.operation_id}</dd></div><div><dt>Plan</dt><dd>{detail.plan_version}</dd></div>
      <div><dt>Test</dt><dd>{detail.test_id ?? "Not recorded"}</dd></div><div><dt>Oracle</dt><dd>{detail.oracle_id ?? "Not recorded"}</dd></div>
      <div><dt>Provenance</dt><dd>{detail.finding.provenance ? label(detail.finding.provenance) : "Not confirmed"}</dd></div>
      <div><dt>Reproduction scope</dt><dd>{detail.finding.reproduction_scope ? label(detail.finding.reproduction_scope) : "Not available"}</dd></div></dl>
    <h5>Evidence integrity</h5>{detail.evidence.length === 0 ? <p>No evidence metadata is attached.</p> :
      <ul>{detail.evidence.map(item => <li key={item.evidence_id}><code>{item.content_type}</code>
        <span>SHA-256 {item.sha256.slice(0, 12)}…</span></li>)}</ul>}
  </aside>;
}

function StageHistory({ stage, events, plan }: { stage: string; events: RedEvent[]; plan: string | null }) {
  const rows = events.filter(item => item.stage === stage).slice(-5).reverse();
  return <div className="red-stage-history"><strong>Recent safe history</strong><p>Plan: {plan ?? "none"}</p>
    {rows.length === 0 ? <p>No stage events recorded.</p> : <ul>{rows.map(item =>
      <li key={item.event_id}><span>{label(item.action)}</span><time>{formatTime(item.occurred_at)}</time></li>)}</ul>}</div>;
}

function stageReason(stage: typeof stages[number], data: RedWorkspaceBundle, anyRunning: boolean): string | null {
  const { workspace } = data;
  if (terminal.has(workspace.assessment.status)) return "Assessment is terminal.";
  if (workspace.assessment.status === "awaiting_authorization") return "Authorize the fixed scope before running a stage.";
  if (anyRunning) return "Wait for the queued or running stage to finish.";
  if (stage === "planning" && workspace.candidate_count === 0) return "Run Recon first to record a current surface.";
  const currentPlan = [...workspace.plans].reverse().find(item => item.status === "approved");
  if (stage === "execution" && (!currentPlan || workspace.planned_operation_count !== 1))
    return "Execution requires one approved operation on the current plan.";
  const execution = workspace.stages.find(item => item.stage === "execution");
  if (stage === "verification" && execution?.status !== "succeeded")
    return "Verification requires a completed execution receipt.";
  return null;
}

function stageTaskCount(stage: typeof stages[number], data: RedWorkspaceBundle): number {
  if (stage === "reconnaissance") return data.workspace.candidate_count;
  if (stage === "planning" || stage === "execution") return data.workspace.planned_operation_count;
  return Object.values(data.workspace.finding_counts).reduce((sum, value) => sum + value, 0);
}
function agentName(stage: typeof stages[number]): string {
  return ({ reconnaissance: "Recon agent", planning: "Planning agent",
    execution: "Execution agent", verification: "Verification agent" })[stage];
}
function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
function workspaceError(error: unknown): string {
  if (error instanceof ApiRequestError) {
    if (error.kind === "timeout") return "The local service timed out. Retry keeps the same command ID.";
    if (error.kind === "network") return "The local Red service is offline or unreachable.";
    if (error.status === 409) return "The command is blocked by the current persisted prerequisites.";
    if (error.status === 401 || error.status === 403) return "The operator credential or local authorization was rejected.";
    if (error.kind === "schema") return "The server returned data outside the Red workspace contract.";
  }
  return "The Red workspace could not complete this request.";
}
