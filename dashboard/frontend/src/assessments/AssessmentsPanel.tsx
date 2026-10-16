import { useEffect, useState } from "react";
import { createMarsJob, createMarsPlan, deleteMarsPlan, getConsoleJson, getMarsJobEvents, getMarsJobExecution, getMarsRedPreflight,
  listMarsJobs, listMarsPlans, updateMarsJob,
  type MarsJob, type MarsJobEvent, type MarsJobExecution, type MarsRedPreflight, type MarsPlan, type RegisteredScenario, type ScenarioKey } from "../api";
import { LoadingState } from "../ui";

type CatalogState =
  | { status: "loading" }
  | { status: "unavailable" }
  | { status: "ready"; items: RegisteredScenario[] };

type Scope = {
  target_id: string; registered_assessments: {
    route: string; target_id: string; endpoint_id: string; registered_test_id: string;
    method: string; endpoint_path: string; max_requests: number;
    timeout_seconds: number; execution_enabled: boolean; trusted_registry_verified: boolean;
  }[];
};

const registryRoutes: Record<ScenarioKey, string> = {
  sql: "/sql-injection/login", xss: "/xss/search", traversal: "/path-traversal/read",
};

export function AssessmentsPanel() {
  const [catalog, setCatalog] = useState<CatalogState>({ status: "loading" });
  const [scope, setScope] = useState<Scope | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioKey | null>(null);
  const [scopeError, setScopeError] = useState(false);
  const [plans, setPlans] = useState<MarsPlan[] | null>(null);
  const [draftName, setDraftName] = useState("");
  const [draftScenario, setDraftScenario] = useState<ScenarioKey>("sql");
  const [planBusy, setPlanBusy] = useState(false);
  const [planMessage, setPlanMessage] = useState("");
  const [jobs, setJobs] = useState<MarsJob[] | null>(null);
  const [jobBusy, setJobBusy] = useState(false);
  const [jobMessage, setJobMessage] = useState("");
  const [history, setHistory] = useState<{ id: string; events: MarsJobEvent[] } | null>(null);
  const [execution, setExecution] = useState<{ id: string; data: MarsJobExecution } | null>(null);
  const [executionError, setExecutionError] = useState<{ id: string; message: string } | null>(null);
  const [preflight, setPreflight] = useState<MarsRedPreflight | null>(null);
  const [preflightError, setPreflightError] = useState("");
  const [preflightBusy, setPreflightBusy] = useState(false);
  useEffect(() => {
    let active = true;
    getConsoleJson<Scope>("/assessment/registry").then(receipt => {
      if (!active) return;
      if (receipt.target_id !== "vulnerable-store" || !Array.isArray(receipt.registered_assessments) ||
          receipt.registered_assessments.some(item => item.target_id !== receipt.target_id ||
            item.trusted_registry_verified !== true || item.execution_enabled !== false)) {
        setScopeError(true);
      } else setScope(receipt);
    }).catch(() => { if (active) setScopeError(true); });
    listMarsJobs().then(items => { if (active) setJobs(items); })
      .catch(() => { if (active) setJobMessage("Job history is unavailable."); });
    listMarsPlans().then(items => { if (active) setPlans(items); })
      .catch(() => { if (active) setPlanMessage("Saved plans are unavailable."); });
    getConsoleJson<RegisteredScenario[]>("/scenarios")
      .then(items => {
        if (active) setCatalog(Array.isArray(items) ? { status: "ready", items } : { status: "unavailable" });
      })
      .catch(() => { if (active) setCatalog({ status: "unavailable" }); });
    return () => { active = false; };
  }, []);

  const selectedDraftScenario = catalog.status === "ready"
    ? catalog.items.find(item => item.id === draftScenario) : undefined;
  const registeredDraft = scope?.registered_assessments.find(row =>
    row.route === registryRoutes[draftScenario] &&
    row.registered_test_id === selectedDraftScenario?.registered_test);

  async function saveDraft(event: React.FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!registeredDraft || draftName.trim().length < 3 || planBusy) return;
    setPlanBusy(true);
    setPlanMessage("");
    try {
      const saved = await createMarsPlan(draftName.trim(), draftScenario);
      setPlans(current => [saved, ...(current ?? [])]);
      setDraftName("");
      setPlanMessage("Assessment draft saved.");
    } catch {
      setPlanMessage("Could not save this assessment draft.");
    } finally { setPlanBusy(false); }
  }

  async function removeDraft(plan: MarsPlan) {
    if (planBusy || !window.confirm("Delete draft " + plan.name + "?")) return;
    setPlanBusy(true);
    setPlanMessage("");
    try {
      await deleteMarsPlan(plan.id);
      setPlans(current => (current ?? []).filter(item => item.id !== plan.id));
      setPlanMessage("Draft removed.");
    } catch {
      setPlanMessage("Could not delete this draft.");
    } finally { setPlanBusy(false); }
  }

  async function prepareJob(plan: MarsPlan) {
    if (jobBusy) return;
    setJobBusy(true); setJobMessage("");
    try {
      const job = await createMarsJob(plan.id);
      setJobs(current => [job, ...(current ?? [])]);
      setJobMessage("Job prepared. Review its registered scope before future execution.");
    } catch {
      setJobMessage("Could not prepare job. Check the registry or existing active jobs.");
    } finally { setJobBusy(false); }
  }

  async function transitionJob(job: MarsJob, action: "review" | "cancel") {
    if (jobBusy) return;
    if (!window.confirm(action === "review"
      ? "Confirm registered scope review? This does not authorize execution."
      : "Cancel this job? No security test will be started.")) return;
    setJobBusy(true); setJobMessage("");
    try {
      const updated = await updateMarsJob(job.id, action);
      setJobs(current => (current ?? []).map(item => item.id === updated.id ? updated : item));
      setJobMessage(action === "review" ? "Scope reviewed. Execution is not yet enabled." : "Job cancelled.");
      if (preflight?.job_id === job.id) setPreflight(null);
      if (history?.id === job.id) {
        const events = await getMarsJobEvents(job.id);
        setHistory({ id: job.id, events });
      }
    } catch { setJobMessage("Job transition refused. Reload to check current status."); }
    finally { setJobBusy(false); }
  }

  async function showPreflight(job: MarsJob) {
    if (preflightBusy) return;
    if (preflight?.job_id === job.id) { setPreflight(null); return; }
    setPreflightBusy(true);
    setPreflightError("");
    setPreflight(null);
    try {
      const data = await getMarsRedPreflight(job.id);
      if (data.registered_test_id !== job.registered_test_id ||
          data.scope_sha256 !== job.scope_sha256) {
        throw new Error("Preflight no longer matches saved job");
      }
      setPreflight(data);
    } catch {
      setPreflightError("Readiness could not be verified. No execution is permitted.");
    } finally { setPreflightBusy(false); }
  }

  async function showExecution(job: MarsJob) {
    if (execution?.id === job.id) { setExecution(null); return; }
    setExecutionError(null);
    try {
      const data = await getMarsJobExecution(job.id);
      setExecution({ id: job.id, data });
    } catch {
      setExecutionError({ id: job.id, message: "Could not verify execution status. No result is being claimed." });
    }
  }

  async function showJobHistory(job: MarsJob) {
    if (history?.id === job.id) { setHistory(null); return; }
    setJobMessage("");
    try {
      setHistory({ id: job.id, events: await getMarsJobEvents(job.id) });
    } catch { setJobMessage("Job history unavailable."); }
  }

  return <div className="mars-content">
    <div className="section-title"><div><h3>Registered scenarios</h3>
      <p>Available targets for controlled assessment planning.</p></div>
      {catalog.status === "ready" && <span className="section-count">{catalog.items.length} registered</span>}
    </div>
    {catalog.status === "loading" && <section className="surface-card"><LoadingState label="Loading registered scenarios…" /></section>}
    {catalog.status === "unavailable" && <section className="surface-card empty-feature">
      <div className="empty-symbol" aria-hidden="true">◇</div>
      <h4>Scenario catalog unavailable</h4>
      <p>Could not load the local catalog. The assessment service may be disconnected.</p>
    </section>}
    {catalog.status === "ready" && (catalog.items.length ? <div className="scenario-grid">
      {catalog.items.map((item, i) => <article className="scenario-card" key={item.id}>
        <div className="scenario-top"><span className="scenario-number">0{i + 1}</span><span className="scenario-tag">Registered</span></div>
        <h4>{item.title}</h4>
        <p>{item.vector}</p>
        <dl className="scenario-meta"><div><dt>Test ID</dt><dd>{item.registered_test}</dd></div>
          <div><dt>Remediation</dt><dd>{item.remediation}</dd></div></dl>
        <button type="button" className="scenario-action" onClick={() => setSelectedScenario(item.id as ScenarioKey)}>
          View assessment scope <span aria-hidden="true">→</span>
        </button>
      </article>)}
    </div> : <section className="surface-card empty-feature">
      <h4>No registered scenarios</h4><p>The connected catalog returned no entries.</p></section>)}
    {selectedScenario && <section className="surface-card scope-panel" aria-live="polite">
      <div className="section-title"><div><h3>Assessment scope</h3>
        <p>Registered execution constraints for the selected scenario.</p></div>
        <button type="button" className="scope-close" onClick={() => setSelectedScenario(null)}>Close</button>
      </div>
      {scopeError ? <p>Trusted registry unavailable. An assessment cannot be authorized.</p> :
        !scope ? <LoadingState label="Checking registered scope…" /> : (() => {
          const item = scope.registered_assessments.find(row =>
            row.route === registryRoutes[selectedScenario] &&
            row.registered_test_id === (catalog.status === "ready"
              ? catalog.items.find(scenario => scenario.id === selectedScenario)?.registered_test : undefined));
          // Selection never creates dispatch authority; registry remains source of truth.
          return item ? <dl className="scope-facts">
            <div><dt>Target</dt><dd>{item.target_id}</dd></div>
            <div><dt>Method</dt><dd>{item.method}</dd></div>
            <div><dt>Endpoint</dt><dd>{item.endpoint_path}</dd></div>
            <div><dt>Registered test</dt><dd>{item.registered_test_id}</dd></div>
            <div><dt>Max requests</dt><dd>{item.max_requests}</dd></div>
            <div><dt>Timeout</dt><dd>{item.timeout_seconds}s</dd></div>
          </dl> : <p>This selection could not be matched to a trusted registered endpoint.</p>;
        })()}
      <p className="scope-note">The current registered plan does not authorize test dispatch. Assessment execution will require the backend's gated runner.</p>
    </section>}
    <section className="surface-card mars-draft-workspace" aria-label="Saved assessment drafts">
      <div className="section-title"><div><h3>Your assessment plans</h3>
        <p>Create a reusable draft grounded in the registered test catalog.</p></div>
        <span className="section-count">{plans?.length ?? "…"} {plans?.length === 1 ? "draft" : "drafts"}</span>
      </div>
      <form className="mars-draft-form" onSubmit={event => void saveDraft(event)}>
        <label htmlFor="mars-plan-name">Plan name
          <input id="mars-plan-name" value={draftName} maxLength={80} minLength={3} required
            onChange={event => setDraftName(event.target.value)} placeholder="e.g. Login security review" />
        </label>
        <label htmlFor="mars-plan-scenario">Scenario
          <select id="mars-plan-scenario" value={draftScenario} disabled={catalog.status !== "ready"}
            onChange={event => setDraftScenario(event.target.value as ScenarioKey)}>
            {catalog.status === "ready" && catalog.items.filter(
              item => Object.hasOwn(registryRoutes, item.id)
            ).map(item => <option key={item.id} value={item.id}>{item.title}</option>)}
          </select>
        </label>
        <button className="mars-save-plan" type="submit" disabled={planBusy || !registeredDraft ||
          !plans || draftName.trim().length < 3}>Save draft</button>
      </form>
      {planMessage && <p className="draft-feedback" role="status">{planMessage}</p>}
      {!plans && !planMessage && <LoadingState label="Loading saved plans…" />}
      {plans?.length === 0 && <p className="draft-empty">No saved plans yet. Create one above to organize your work.</p>}
      {plans && plans.length > 0 && <ul className="mars-plan-list">
        {plans.map(plan => <li key={plan.id}>
          <div><strong>{plan.name}</strong>
            <span>{plan.registered_test_id} · Draft, not executed</span></div>
          <div className="mars-plan-actions">
            <button type="button" disabled={planBusy || jobBusy || jobs === null ||
              jobs.some(job => job.plan_id === plan.id && job.state !== "cancelled")}
              onClick={() => void prepareJob(plan)}
              aria-label={"Prepare job for " + plan.name}>Prepare job</button>
            <button type="button" disabled={planBusy} onClick={() => setSelectedScenario(plan.scenario)}
              aria-label={"Open draft " + plan.name}>Open scope</button>
            <button type="button" disabled={planBusy || jobBusy || jobs === null ||
              jobs.some(job => job.plan_id === plan.id && job.state !== "cancelled")}
              onClick={() => void removeDraft(plan)}
              aria-label={"Delete draft " + plan.name}>Delete</button>
          </div>
        </li>)}
      </ul>}
    </section>
    <section className="surface-card mars-jobs" aria-label="Assessment jobs">
      <div className="section-title">
        <div><h3>Job queue</h3><p>Registered scope, approvals and audit history.</p></div>
        {jobs && <span className="section-count">{jobs.length} jobs</span>}
      </div>
      {jobMessage && <p className="draft-feedback" role="status">{jobMessage}</p>}
      {jobs === null && !jobMessage && <LoadingState label="Loading job history…" />}
      {jobs?.length === 0 && <p className="draft-empty">No jobs prepared. Choose Prepare job on a saved plan.</p>}
      {jobs && jobs.length > 0 && <ul className="mars-plan-list">
        {jobs.map(job => <li key={job.id} className="mars-job-row">
          <div className="mars-job-summary">
            <strong>{job.name}</strong>
            <span className="mars-job-state"><i className={"mars-job-state-dot mars-job-state-dot--" + job.state} aria-hidden="true"/>
              {job.registered_test_id} · {job.state.replaceAll("_", " ")}</span>
            <small>{job.method} {job.endpoint_path} · Max {job.max_requests} requests · {job.timeout_seconds}s</small>
          </div>
          <div className="mars-plan-actions">
            {job.state === "awaiting_review" &&
              <button type="button" disabled={jobBusy}
                onClick={() => void transitionJob(job, "review")}>Review scope</button>}
            {job.state !== "cancelled" &&
              <button type="button" disabled={jobBusy}
                onClick={() => void transitionJob(job, "cancel")}>Cancel</button>}
            {job.state === "scope_reviewed" &&
              <a className="mars-execution-request" download={"mars-execution-request-" + job.id + ".json"}
                href={"/api/mars/jobs/" + encodeURIComponent(job.id) + "/execution-request"}
                aria-label={"Export independent review request for " + job.name}>Export for review</a>}
            <button type="button" disabled={preflightBusy || jobBusy}
              onClick={() => void showPreflight(job)}>
              {preflight?.job_id === job.id ? "Hide preflight" : "Check readiness"}
            </button>
            <button type="button" onClick={() => void showJobHistory(job)}>
              {history?.id === job.id ? "Hide history" : "View history"}</button>
            <button type="button" onClick={() => void showExecution(job)}>
              {execution?.id === job.id ? "Hide result" : "View result"}</button>
          </div>
          {preflight?.job_id === job.id && <div className="mars-preflight" role="status">
            <strong>Execution preflight</strong>
            <dl>
              <div><dt>Job scope reviewed</dt><dd>{preflight.checks.job_scope_reviewed ? "Yes" : "No"}</dd></div>
              <div><dt>Registered scope current</dt><dd>{preflight.checks.registered_scope_current ? "Yes" : "No"}</dd></div>
              <div><dt>Independent admission</dt><dd>Not verified</dd></div>
              <div><dt>Isolated runtime</dt><dd>Not verified</dd></div>
              <div><dt>Runner</dt><dd>Not enabled</dd></div>
            </dl>
            <p>Dispatch blocked. {preflight.note}</p>
          </div>}
          {preflightError && <p className="draft-feedback" role="alert">{preflightError}</p>}
          {execution?.id === job.id && <div className="mars-preflight" role="status">
            <strong>Registered Red execution</strong>
            {execution.data.status === "not_dispatched" ?
              <p>No dispatched attempt has been recorded for this job.</p> :
              execution.data.status === "outcome_unknown" ?
              <p>One attempt was reserved. Its outcome is unknown. Do not retry automatically.</p> :
              execution.data.status === "receipt_recorded" ? <dl>
                <div><dt>Observed outcome</dt><dd>{execution.data.outcome.replaceAll("_", " ")}</dd></div>
                <div><dt>Reason</dt><dd>{execution.data.reason}</dd></div>
                <div><dt>Receipt SHA-256</dt><dd><code>{execution.data.receipt_sha256}</code></dd></div>
                <div><dt>Observation captured</dt><dd>{execution.data.observation_sha256 ? "Yes" : "No"}</dd></div>
              </dl> : null}
            <p>Development-only Red evidence. No Blue remediation or final research
              success is implied by this status.</p>
          </div>}
          {executionError?.id === job.id && <p className="draft-feedback" role="alert">{executionError.message}</p>}
          {history?.id === job.id && <ol className="mars-job-history">
            {history.events.map(event => <li key={event.sequence}>
              <span>{event.event.replaceAll("_", " ")}</span>
              <time dateTime={event.occurred_at}>{new Date(event.occurred_at).toLocaleString()}</time>
            </li>)}
          </ol>}
        </li>)}
      </ul>}
      <p className="mars-job-note">Scope review is not execution authorization. Jobs here never dispatch security tests or qualify research.</p>
    </section>
    <div className="soft-banner"><span className="banner-symbol" aria-hidden="true">i</span>
      <div><strong>Assessment planning is available</strong>
        <p>View registered scope here. Execution requires separately admitted Docker evidence. A recorded Red result can be viewed from the job queue; no Blue repair is claimed.</p></div>
      <a href="/dashboard/system">System status <span aria-hidden="true">↗</span></a>
    </div>
  </div>;
}
