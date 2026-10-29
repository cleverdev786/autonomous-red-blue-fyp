import { ActionButton, Notice } from "../ui";
import type { RedTarget } from "./api";
import type { RedMode } from "./modePreference";

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
        <p>Review the registered Standard scope before creating or authorizing anything.</p></div>
      {phase !== "setup" && phase !== "review" &&
        <span className="red-mode-lock">Mode locked · {mode}</span>}
    </div>
    {error && <Notice title="Assessment command rejected" tone="danger">{error}</Notice>}

    {phase === "setup" ? <form className="red-assessment-setup" onSubmit={event => {
      event.preventDefault(); onReview();
    }}>
      <label>Registered target
        <select value={targetId} required disabled={busy}
          onChange={event => onTargetChange(event.target.value)}>
          <option value="">Select target</option>
          {targets.map(item => <option key={item.target_id} value={item.target_id}>
            {item.target_id}
          </option>)}
        </select>
      </label>
      <fieldset disabled={busy}><legend>Assessment mode</legend>
        <label><input type="radio" name="red-assessment-mode" value="manual"
          checked={mode === "manual"} onChange={() => onModeChange("manual")} /> Manual</label>
        <label><input type="radio" name="red-assessment-mode" value="autonomous"
          checked={mode === "autonomous"} onChange={() => onModeChange("autonomous")} /> Autonomous</label>
      </fieldset>
      <ActionButton type="submit" disabled={!target || busy}>Review Standard scope</ActionButton>
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
          {busy ? "Recording authorization…" : "Authorize fixed scope"}
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
      <p>Standard profile · {mode} mode · unauthenticated registered routes only</p></div>
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
    <p className="red-scope-caution">Creating the draft does not authorize or start execution.
      Authorization and Autonomous start remain separate operator actions.</p>
  </div>;
}

function classLabel(value: string): string {
  if (value === "sql_injection") return "SQL injection";
  if (value === "xss") return "Reflected XSS";
  return "Path traversal";
}
