import { ActionButton, Notice, notify } from "../ui";
import type { RedTarget } from "./api";
import type { RedMode } from "./modePreference";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "../components/ui/select";
import { RadioGroup, RadioGroupItem } from "../components/ui/radio-group";

export type NewAssessmentPhase =
  | "setup" | "review" | "awaiting_authorization" | "authorized" | "active"
  | "recovered" | "cancellation_pending" | "cancelled";

export function NewAssessmentView({ targets, targetId, mode, phase, busy, error,
  assessmentId, onTargetChange, onModeChange, onReview, onCreate, onAuthorize,
  onStart, onCancel, onEdit, onReset }: {
  targets: RedTarget[];
  targetId: string;
  mode: RedMode;
  phase: NewAssessmentPhase;
  busy: boolean;
  error: string | null;
  assessmentId: string | null;
  onTargetChange: (value: string) => void;
  onModeChange: (value: RedMode) => void;
  onReview: () => void;
  onCreate: () => void;
  onAuthorize: () => void;
  onStart: () => void;
  onCancel: () => void;
  onEdit: () => void;
  onReset: () => void;
}) {
  const target = targets.find(item => item.target_id === targetId);
  return <section className="surface-card red-new-assessment" aria-labelledby="new-assessment-title">
    <div className="red-new-assessment__head">
      <div><span className="eyebrow">Controlled Red workflow</span>
        <h3 id="new-assessment-title">New assessment</h3>
        <p>Review target, mode and fixed limits.</p></div>
      {phase !== "setup" && phase !== "review" &&
        <span className="red-mode-lock">Mode locked · {mode}</span>}
    </div>
    {error && <Notice title="Assessment command rejected" tone="danger">{error}</Notice>}

    {phase === "setup" ? <form className="red-assessment-setup" onSubmit={event => {
      event.preventDefault(); onReview();
    }}>
      <div><label htmlFor="red-target">Registered target</label>
        <Select value={targetId} required disabled={busy || targets.length === 0} onValueChange={onTargetChange}>
          <SelectTrigger id="red-target" className="w-full"><SelectValue placeholder="Select target" /></SelectTrigger>
          <SelectContent position="popper" align="start">{targets.map(item => <SelectItem key={item.target_id} value={item.target_id}>
            {item.target_id}
          </SelectItem>)}</SelectContent>
        </Select>
        {!targets.length && <p role="status">No registered target is available. Refresh the dashboard to retry.</p>}
      </div>
      <div><span id="red-mode-label">Assessment mode</span>
        <RadioGroup aria-labelledby="red-mode-label" value={mode} disabled={busy}
          onValueChange={value => { if (value === "manual" || value === "autonomous") onModeChange(value); }}>
          <div className="flex items-center gap-2"><RadioGroupItem id="red-manual" value="manual" /><label htmlFor="red-manual">Manual</label></div>
          <div className="flex items-center gap-2"><RadioGroupItem id="red-autonomous" value="autonomous" /><label htmlFor="red-autonomous">Autonomous</label></div>
        </RadioGroup>
      </div>
      <ActionButton type="button" disabled={busy} aria-disabled={!target || busy}
        onClick={() => { if (target) { onReview(); notify("Standard scope ready for review."); }
          else notify("Choose a registered target first.", true); }}>Review Standard scope</ActionButton>
    </form> : target && <ScopeReview target={target} mode={mode} />}

    {phase !== "setup" && <div className="red-assessment-actions" aria-live="polite">
      {phase === "review" && <>
        <ActionButton variant="secondary" disabled={busy} onClick={onEdit}>Edit target or mode</ActionButton>
        <ActionButton disabled={busy} onClick={onCreate}>
          {busy ? "Creating draft…" : "Create authorization draft"}
        </ActionButton>
      </>}
      {phase === "awaiting_authorization" && <>
        <ActionButton disabled={busy} onClick={onAuthorize}>
          {busy ? "Starting assessment…" : mode === "autonomous" ? "Authorize and start assessment" : "Authorize fixed scope"}
        </ActionButton>
        <ActionButton variant="secondary" disabled={busy} onClick={onCancel}>Cancel assessment</ActionButton>
      </>}
      {phase === "authorized" && <>
        {mode === "autonomous" ? <ActionButton disabled={busy} onClick={onStart}>
          {busy ? "Starting…" : "Start autonomous assessment"}
        </ActionButton> : <Notice title="Manual assessment authorized" tone="success">
          No worker has run. Individual stage controls remain deliberate and separate.
        </Notice>}
        <ActionButton variant="secondary" disabled={busy} onClick={onCancel}>Cancel assessment</ActionButton>
      </>}
      {phase === "active" && <>
        <Notice title="Assessment queued" tone="success">
          {mode === "autonomous" ? "The authorized reconnaissance job is queued." : "Manual stages await an explicit run command."}
        </Notice>
        <ActionButton variant="secondary" disabled={busy} onClick={onCancel}>
          {busy ? "Requesting cancellation…" : "Cancel assessment"}
        </ActionButton>
      </>}
      {phase === "recovered" && <>
        <Notice title="Active assessment recovered">
          This persisted assessment is still non-terminal. Cancellation remains available after reload or reconnect.
        </Notice>
        <ActionButton variant="secondary" disabled={busy} onClick={onCancel}>
          {busy ? "Requesting cancellation…" : "Cancel assessment"}
        </ActionButton>
      </>}
      {phase === "cancellation_pending" && <>
        <Notice title="Cancellation requested">
          A worker may still be stopping cooperatively. MARS has recorded the request but has not reported a terminal cancellation yet.
        </Notice>
        <ActionButton variant="secondary" disabled={busy} onClick={onCancel}>
          {busy ? "Checking cancellation…" : "Request cancellation again"}
        </ActionButton>
      </>}
      {phase === "cancelled" && <>
        <Notice title="Assessment cancelled">No new work will be queued for {assessmentId}.</Notice>
        <ActionButton variant="secondary" onClick={onReset}>New assessment</ActionButton>
      </>}
    </div>}
  </section>;
}

function ScopeReview({ target, mode }: { target: RedTarget; mode: RedMode }) {
  const budget = target.standard_budget;
  return <div className="red-scope-review">
    <div><span className="eyebrow">Fixed authorization scope</span>
      <h4>{target.target_id}</h4>
      <p>Standard · {mode} · unauthenticated routes</p></div>
    <div><strong>Registered classes</strong><ul>
      {target.supported_classes.map(item => <li key={item}>{classLabel(item)}</li>)}
    </ul></div>
    <dl className="red-budget-grid">
      <div><dt>HTTP budget</dt><dd>{budget.max_http_requests} HTTP requests</dd></div>
      <div><dt>Crawl budget</dt><dd>{budget.max_crawl_requests} crawl requests</dd></div>
      <div><dt>Test budget</dt><dd>{budget.max_tests} registered tests</dd></div>
      <div><dt>Runtime</dt><dd>{budget.max_runtime_seconds} seconds</dd></div>
      <div><dt>Concurrency</dt><dd>{budget.max_parallel_operations} operation</dd></div>
      <div><dt>Traversal depth</dt><dd>{budget.max_depth} levels</dd></div>
      <div><dt>Retries</dt><dd>{budget.max_retries}</dd></div>
      <div><dt>Resources</dt><dd>{budget.max_cpu_cores} CPU · {budget.max_memory_mb} MB</dd></div>
    </dl>
    <p className="red-scope-caution" role="status">{mode === "autonomous" ? "Authorize to start autonomous assessment." : "Draft first. Authorize before execution."}</p>
  </div>;
}

function classLabel(value: string): string {
  if (value === "sql_injection") return "SQL injection";
  if (value === "xss") return "Reflected XSS";
  return "Path traversal";
}
