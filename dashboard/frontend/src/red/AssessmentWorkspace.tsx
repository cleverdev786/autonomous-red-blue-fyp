import { useEffect, useRef, useState } from "react";
import { ApiRequestError } from "../api";
import { ActionButton, EmptyState, LoadingState, Notice, notify } from "../ui";
import { Button } from "../components/ui/button";
import { Dialog, DialogContent, DialogTitle, DialogDescription } from "../components/ui/dialog";
import { assessmentPath } from "../routes";
import {
  cancelRedAssessment, loadRedFindingDetail, loadRedFindingPage, loadRedWorkspace, runRedStage, startRedAssessment,
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
  const [refreshing, setRefreshing] = useState(false);
  const manualRefresh = useRef(false);
  const requestIds = useRef<Record<string, string>>({});
  const commandPending = useRef(false);

  useEffect(() => {
    const controller = new AbortController();
    setRefreshing(true);
    void loadRedWorkspace(token, assessmentId, controller.signal)
      .then(data => { if (!controller.signal.aborted) {
        setState({ kind: "ready", data });
        if (manualRefresh.current) { notify("Assessment data refreshed."); manualRefresh.current = false; }
      } })
      .catch(error => {
        if (error instanceof ApiRequestError && error.kind === "aborted") return;
        setState({ kind: "error", message: workspaceError(error) });
        if (manualRefresh.current) { notify("Assessment refresh failed.", true); manualRefresh.current = false; }
      }).finally(() => { if (!controller.signal.aborted) setRefreshing(false); });
    return () => controller.abort();
  }, [assessmentId, refresh, token]);

  const assessmentStatus = state.kind === "ready" ? state.data.workspace.assessment.status : null;
  useEffect(() => {
    // Schedule after the previous read finishes so slow requests are never aborted by polling.
    if (refreshing || !assessmentStatus || terminal.has(assessmentStatus)) return;
    const timer = window.setTimeout(() => setRefresh(value => value + 1), 3000);
    return () => window.clearTimeout(timer);
  }, [assessmentStatus, refreshing, refresh]);

  async function command(key: string, action: (requestId: string) => Promise<unknown>) {
    if (commandPending.current) return;
    commandPending.current = true;
    const requestId = requestIds.current[key] ?? `${key}-${crypto.randomUUID()}`;
    requestIds.current[key] = requestId;
    setBusy(key); setCommandError(null);
    try {
      await action(requestId);
      notify("Command accepted. Awaiting worker progress.");
      delete requestIds.current[key];
      setRefresh(value => value + 1); onChanged();
    } catch (error) { setCommandError(workspaceError(error)); notify("Command was not accepted.", true); }
    finally { commandPending.current = false; setBusy(null); }
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
    onClose={onClose} refreshing={refreshing} onRefresh={() => { manualRefresh.current = true; setRefresh(value => value + 1); }}
    onRunStage={(stage, operationId) => void command(`run-${stage}-${operationId ?? "stage"}`, requestId =>
      runRedStage(token, assessmentId, stage, requestId, operationId))}
    onCancel={() => void command("cancel", requestId =>
      cancelRedAssessment(token, assessmentId, requestId))}
    onStart={() => void command("start", requestId => startRedAssessment(token, assessmentId, requestId))}
    token={token} />;
}

export function AssessmentWorkspaceView({ data, busy, commandError, onClose, onRefresh,
  onRunStage, onCancel, onStart, token, refreshing = false }: {
  data: RedWorkspaceBundle; busy: string | null; commandError: string | null;
  onClose: () => void; onRefresh: () => void;
  onRunStage: (stage: typeof stages[number], operationId?: string) => void; onCancel: () => void; token: string;
  onStart?: () => void;
  refreshing?: boolean;
}) {
  const { workspace, events, findings, coverage } = data;
  const assessment = workspace.assessment;
  const active = !terminal.has(assessment.status);
  return <section className="red-workspace-panel" aria-labelledby="red-workspace-title">
    <nav aria-label="Assessment navigation"><Button variant="outline" asChild><a href="/dashboard/red-team" onClick={event => {
        if (event.button === 0 && !event.ctrlKey && !event.metaKey && !event.altKey && !event.shiftKey) {
          event.preventDefault(); onClose();
        }
      }} className="dashboard-button">Dashboard</a></Button></nav>
    <header className="red-workspace-header surface-card">
      <div>
        <span className="eyebrow">Assessment workspace</span>
        <h3 id="red-workspace-title">{assessment.target_id}</h3>
        <p>{assessment.mode} · Standard assessment</p>
        <details className="technical-reference"><summary>Technical reference</summary><code>{assessment.assessment_id}</code></details></div>
      <div className="red-workspace-actions">
        <span className={`red-status red-status--${assessment.status}`}>{label(assessment.status)}</span>
        <ActionButton variant="secondary" disabled={refreshing} onClick={onRefresh}>{refreshing ? "Refreshing…" : "Refresh"}</ActionButton>
        {assessment.mode === "autonomous" && assessment.status === "queued" &&
          Object.keys(assessment.stage_statuses).length === 0 && onStart &&
          <ActionButton disabled={busy !== null} onClick={onStart}>Start authorized assessment</ActionButton>}
        {active && <ActionButton variant="secondary" disabled={busy !== null} onClick={onCancel}>
          {busy === "cancel" ? "Requesting stop…" : "Stop assessment"}</ActionButton>}
      </div>
    </header>
    {commandError && <Notice title="Command not accepted" tone="danger">{commandError}</Notice>}
    <section className="coverage-summary" aria-label="Security coverage">
      <strong>Security coverage</strong>
      <span>{coverage.coverage.executed} / {coverage.coverage.eligible} eligible tests executed</span>
      <span>{coverage.gaps.length} recorded gaps</span>
      <p>Workflow completion does not establish target safety.</p>
      {coverage.warnings.map(warning => <span key={warning}>{label(warning)}</span>)}
    </section>
    {assessment.mode === "manual" ? <ManualPanels data={data} busy={busy}
      onRunStage={onRunStage} /> : <AutonomousTimeline data={data} />}
    <FindingsPanel token={token} findings={findings} coverage={coverage}
      total={data.findingTotal} />
  </section>;
}

function ManualPanels({ data, busy, onRunStage }: { data: RedWorkspaceBundle;
  busy: string | null; onRunStage: (stage: typeof stages[number], operationId?: string) => void }) {
  const [inspected, setInspected] = useState<string | null>(null);
  const [selectedOperation, setSelectedOperation] = useState("");
  const { workspace, events } = data;
  const operations = workspace.operations?.filter(item => item.plan_version === workspace.assessment.current_plan_version && item.status === "approved") ?? [];
  const operationId = operations.some(item => item.operation_id === selectedOperation) ? selectedOperation : operations[0]?.operation_id;
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
        <dl><div><dt>Last action</dt><dd>{last ? `${eventLabel(last)} · ${formatTime(last.occurred_at)}` : "No recorded action"}</dd></div>
          <div><dt>Task count</dt><dd>{stageTaskCount(stage, data)}</dd></div>
          <div><dt>Failure state</dt><dd>{["failed", "blocked"].includes(status) ? label(status) : "None"}</dd></div></dl>
        {reason && <p className="red-disabled-reason" id={`${stage}-reason`}>{reason}</p>}
        <div className="red-agent-actions">
          {(stage === "execution" || stage === "verification") && operations.length > 0 &&
            <label className="operation-picker">Registered operation
              <select value={operationId} onChange={event => setSelectedOperation(event.target.value)} disabled={busy !== null || anyRunning}>
                {operations.map((item, i) => <option key={item.operation_id} value={item.operation_id}>Operation {i + 1} · {item.test_id ?? "Registered test"}</option>)}
              </select></label>}
          <ActionButton disabled={Boolean(reason) || busy !== null} aria-disabled={Boolean(reason) || busy !== null}
            aria-describedby={reason ? `${stage}-reason` : undefined}
            onClick={() => { if (!reason) onRunStage(stage, stage === "execution" || stage === "verification" ? operationId : undefined); }}>
            {busy?.startsWith(`run-${stage}`) ? "Queuing…" : rerun ? "Rerun" : "Run"}</ActionButton>
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
      <h3 id="autonomous-title">{terminal.has(workspace.assessment.status) ? "Assessment timeline" : "Live assessment timeline"}</h3></div>
      <span>{terminal.has(workspace.assessment.status)
        ? "Terminal state · polling stopped" : "Polling every 3 seconds while non-terminal"}</span></div>
    <ol>{stages.map(stage => {
      const status = workspace.stages.find(item => item.stage === stage)?.status ?? "not_started";
      const event = [...events].reverse().find(item => item.stage === stage);
      return <li key={stage} className={`red-timeline-step red-timeline-step--${status}`}>
        <span className="red-timeline-node" aria-hidden="true" />
        <div><strong>{agentName(stage)}</strong><p>{event ? eventLabel(event) : "Awaiting prerequisite"} · {stageTaskCount(stage, data)} recorded items</p>
          <details className="stage-disclosure"><summary>Stage history</summary>
            <StageHistory stage={stage} events={events}
              plan={workspace.stages.find(item => item.stage === stage)?.plan_version ?? null} />
          </details>
        </div>
        <div><span className={`red-status red-status--${status}`}>{label(status)}</span>
          <time>{event ? formatTime(event.occurred_at) : "—"}</time></div>
      </li>;
    })}</ol>
  </section>;
}

function FindingsPanel({ token, findings, coverage, total }: { token: string;
  findings: RedFinding[]; coverage: RedWorkspaceBundle["coverage"]; total: number }) {
  const [filter, setFilter] = useState("all");
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<{ items: RedFinding[]; total: number } | null>(null);
  const [pageError, setPageError] = useState<string | null>(null);
  const [pageLoading, setPageLoading] = useState(false);
  const [pageRevision, setPageRevision] = useState(0);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<RedFindingDetail | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [detailRevision, setDetailRevision] = useState(0);
  const trigger = useRef<HTMLButtonElement | null>(null);
  const auditId = typeof window === "undefined" ? null : new URLSearchParams(window.location.search).get("finding");
  const findingId = auditId ?? selected;
  useEffect(() => {
    if (offset === 0 && filter === "all") { setPage(null); setPageError(null); setPageLoading(false); return; }
    const controller = new AbortController();
    setPageLoading(true); setPageError(null);
    void loadRedFindingPage(token, coverage.assessment_id, offset, filter, controller.signal)
      .then(result => { if (!controller.signal.aborted) setPage({items: result.items, total: result.pagination.total}); })
      .catch(error => { if (!controller.signal.aborted) setPageError(workspaceError(error)); })
      .finally(() => { if (!controller.signal.aborted) setPageLoading(false); });
    return () => controller.abort();
  }, [token, coverage.assessment_id, offset, filter, pageRevision, findings]);
  useEffect(() => {
    setDetail(null); setDetailError(null);
    if (!findingId) return;
    const controller = new AbortController();
    void loadRedFindingDetail(token, findingId, controller.signal).then(result => {
      if (controller.signal.aborted) return;
      if (result.finding.assessment_id !== coverage.assessment_id) {
        setDetailError("This finding does not belong to the selected assessment."); return;
      }
      setDetail(result);
    }).catch(error => { if (!controller.signal.aborted) setDetailError(workspaceError(error)); });
    return () => controller.abort();
  }, [token, findingId, coverage.assessment_id, detailRevision]);
  const visible = offset === 0 && filter === "all" ? findings : page?.items ?? [];
  const count = offset === 0 && filter === "all" ? total : page?.total ?? 0;
  const evidence = <>{detailError ? <><Notice title="Evidence detail unavailable" tone="danger">{detailError}</Notice>
    <Button variant="outline" onClick={() => setDetailRevision(value => value + 1)}>Retry evidence</Button></> :
    detail ? <EvidenceDetail detail={detail} /> : <LoadingState label="Loading evidence metadata…" />}</>;
  return <section className="red-findings surface-card" aria-labelledby="red-findings-title">
    <div className="red-section-head"><div><span className="eyebrow">Verification outcomes</span>
      <h3 id="red-findings-title">Findings &amp; coverage</h3></div>
      <label>Status <select value={filter} onChange={event => { setFilter(event.target.value); setOffset(0); }}>
        <option value="all">All outcomes</option>{["confirmed", "suspected", "not_confirmed", "inconclusive"].map(item =>
          <option value={item} key={item}>{label(item)}</option>)}</select></label></div>
    {findings.some(item => item.status === "suspected") && <Notice title="Suspected observations">
      Suspected results require independent verification; they are not confirmed findings.
    </Notice>}
    {pageLoading ? <LoadingState label="Loading finding page…" /> : pageError ?
      <><Notice title="Findings unavailable" tone="danger">{pageError}</Notice>
        <Button variant="outline" onClick={() => setPageRevision(value => value + 1)}>Retry findings</Button></> :
      visible.length === 0 ? <EmptyState title="No matching findings"
        description="No persisted verification outcome matches this filter." /> :
      <div className="table-wrap"><table><thead><tr><th scope="col">Outcome</th><th scope="col">Severity</th><th scope="col">Category</th>
        <th scope="col">Route</th><th scope="col">Evidence</th><th scope="col"><span className="sr-only">Inspect</span></th></tr></thead>
        <tbody>{visible.map(item => <tr key={item.finding_id}><td><span className={`red-status red-status--${item.status}`}>{label(item.status)}</span></td>
          <td>{item.severity ? label(item.severity) : "Unrated"}</td><td>{categoryLabel(item.category)}</td>
          <td><code>{item.route ?? "Registered target"}</code></td><td>{item.has_evidence ? "Stored metadata" : "No stored evidence"}</td>
          <td>{auditId ? <Button variant="outline" asChild>
            <a href={assessmentPath(coverage.assessment_id) + "?finding=" + encodeURIComponent(item.finding_id)}
              aria-label={"Inspect finding " + item.finding_id}>Inspect</a></Button> :
            <Button variant="outline" onClick={event => { trigger.current = event.currentTarget; setSelected(item.finding_id); }}
              aria-label={"Inspect finding " + item.finding_id}>Inspect</Button>}</td></tr>)}</tbody></table></div>}
    {(count > 100 || offset > 0) && <nav className="red-history-pages" aria-label="Finding pages">
      <Button variant="outline" disabled={pageLoading || offset === 0} onClick={() => setOffset(value => Math.max(0, value - 100))}>Previous</Button>
      <span>{offset + 1}–{Math.min(offset + visible.length, count)} of {count}</span>
      <Button variant="outline" disabled={pageLoading || offset + visible.length >= count} onClick={() => setOffset(value => value + 100)}>Next</Button>
    </nav>}
    <Button asChild variant="outline"><a href="/dashboard/reports">Open reports</a></Button>
    {auditId ? <section className="audit-record" aria-label="Finding audit record"><h4>Finding audit record</h4>{evidence}</section> :
      <Dialog open={selected !== null} onOpenChange={open => { if (!open) setSelected(null); }}>
        <DialogContent className="evidence-dialog" onCloseAutoFocus={event => { event.preventDefault(); trigger.current?.focus(); }}>
          <DialogTitle>Finding evidence</DialogTitle>
          <DialogDescription>Persisted verification metadata for this assessment.</DialogDescription>
          {evidence}
          {selected && <Button asChild variant="outline"><a href={assessmentPath(coverage.assessment_id) + "?finding=" + encodeURIComponent(selected)}>Open audit record</a></Button>}
        </DialogContent>
      </Dialog>}
    <div className="red-gap-list"><h4>Coverage gaps</h4>
      {coverage.gaps.length === 0 ? <p>No persisted coverage gaps.</p> : coverage.gaps.map(gap =>
        <article key={gap.gap_id}><div><strong>{label(gap.reason)}</strong><span>{label(gap.status)}</span></div>
          <p>{gap.recommendation ?? "The registered scope did not produce a completed test."}</p>
          {gap.test_id && <code>{gap.test_id}</code>}</article>)}</div>
  </section>;
}

export function EvidenceDetail({ detail }: { detail: RedFindingDetail }) {
  return <div className="evidence-content">
    <p><strong>{categoryLabel(detail.finding.category)}</strong> · {label(detail.finding.status)}</p>
    <p><code>{detail.finding.route ?? "Registered target"}</code></p>
    <p>Test: <code>{detail.test_id ?? "Not recorded"}</code></p>
    <details><summary>Technical provenance and integrity</summary>
      <dl>{[
        ["Finding", detail.finding.finding_id], ["Operation", detail.operation_id], ["Plan", detail.plan_version],
        ["Oracle", detail.oracle_id ?? "Not recorded"], ["Provenance", detail.finding.provenance ?? "Not recorded"],
        ["Reproduction scope", detail.finding.reproduction_scope ?? "Not recorded"],
      ].map(([name, value]) => <div key={name}><dt>{name}</dt><dd>{value}</dd></div>)}</dl>
      <h5>Receipt references</h5>
      <ul>{detail.evidence_receipt_ids.map(id => <li key={id}><code>{id}</code></li>)}</ul>
      <h5>Evidence integrity</h5>{detail.evidence.length === 0 ? <p>No evidence metadata is attached.</p> :
        <ul>{detail.evidence.map(item => <li key={item.evidence_id}><dl>
          <div><dt>Evidence</dt><dd>{item.evidence_id}</dd></div>
          <div><dt>Receipt</dt><dd>{item.receipt_id}</dd></div>
          <div><dt>Content type</dt><dd>{item.content_type}</dd></div>
          <div><dt>SHA-256</dt><dd>{item.sha256}</dd></div>
        </dl></li>)}</ul>}
    </details>
  </div>;
}
function categoryLabel(category: string | null): string {
  return ({ sql_injection: "SQL injection", xss: "Reflected XSS", path_traversal: "Path traversal" } as Record<string, string>)[category ?? ""] ??
    (category ? label(category) : "Unclassified");
}

function StageHistory({ stage, events, plan }: { stage: string; events: RedEvent[]; plan: string | null }) {
  const rows = events.filter(item => item.stage === stage).slice(-5).reverse();
  return <div className="red-stage-history"><strong>Recent safe history</strong><p>Plan: {plan ?? "none"}</p>
    {rows.length === 0 ? <p>No stage events recorded.</p> : <ul>{rows.map(item =>
      <li key={item.event_id}><span>{eventLabel(item)}</span><time>{formatTime(item.occurred_at)}</time></li>)}</ul>}</div>;
}

function stageReason(stage: typeof stages[number], data: RedWorkspaceBundle, anyRunning: boolean): string | null {
  const { workspace } = data;
  if (terminal.has(workspace.assessment.status)) return "Assessment is terminal.";
  if (!["queued", "running"].includes(workspace.assessment.status)) return "Authorize the fixed scope before running a stage.";
  if (anyRunning) return "Wait for the queued or running stage to finish.";
  if (stage === "planning" && workspace.candidate_count === 0) return "Run Recon first to record a current surface.";
  const currentPlan = workspace.plans.find(item => item.plan_version === workspace.assessment.current_plan_version &&
    item.surface_revision === workspace.assessment.current_surface_revision && item.status === "approved");
  const approvedOperations = workspace.operations?.filter(item => item.plan_version === workspace.assessment.current_plan_version && item.status === "approved");
  if ((stage === "execution" || stage === "verification") && (!currentPlan || (approvedOperations ? approvedOperations.length === 0 : workspace.planned_operation_count !== 1)))
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
function eventLabel(event: RedEvent): string {
  return event.action === "stage-transition" ?
    `${event.stage ? agentName(event.stage) : "Stage"} · ${label(event.status)}` : label(event.action);
}
function formatTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(new Date(value));
}
function workspaceError(error: unknown): string {
  if (error instanceof ApiRequestError) {
    if (error.kind === "timeout") return "The local service timed out. Retry the request.";
    if (error.kind === "network") return "The local Red service is offline or unreachable.";
    if (error.status === 409) return "The command is blocked by the current persisted prerequisites.";
    if (error.status === 403) return "The local origin or CSRF authorization was rejected.";
    if (error.status === 401) return "Your session expired. Sign in again to view this assessment.";
    if (error.status === 404) return "This assessment does not exist or is no longer available.";
    if (error.kind === "schema") return "The server returned data outside the Red workspace contract.";
  }
  return "The Red workspace could not complete this request.";
}
