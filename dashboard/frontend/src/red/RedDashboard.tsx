import { useEffect, useState } from "react";
import { ActionButton } from "../ui";
import { ApiRequestError } from "../api";
import { listRedTargets, loadRedDashboard, type RedTarget } from "./api";
import { NewAssessment } from "./NewAssessment";
import { AssessmentWorkspace } from "./AssessmentWorkspace";
import { RedDashboardView, type RedDashboardState } from "./RedDashboardView";

export function RedDashboard() {
  const [credential, setCredential] = useState("");
  const [token, setToken] = useState("");
  const [targets, setTargets] = useState<RedTarget[]>([]);
  const [targetId, setTargetId] = useState("");
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [state, setState] = useState<RedDashboardState>({ kind: "loading" });
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(null);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    void listRedTargets(token, controller.signal).then(page => setTargets(page.items)).catch(error => {
      if (error instanceof ApiRequestError && error.kind === "aborted") return;
      setState({ kind: "error", message: error instanceof ApiRequestError && error.status === 401
        ? "The operator credential was rejected."
        : "Registered Red targets could not be verified." });
    });
    return () => controller.abort();
  }, [token]);

  useEffect(() => {
    if (!token) return;
    const controller = new AbortController();
    setState({ kind: "loading" });
    void loadRedDashboard(token, { targetId, status, offset }, controller.signal).then(dashboard => {
      setState({ kind: "ready", summary: dashboard.summary,
        assessments: dashboard.assessments.items,
        total: dashboard.assessments.pagination.total,
        offset: dashboard.assessments.pagination.offset,
        limit: dashboard.assessments.pagination.limit });
    }).catch(error => {
      if (error instanceof ApiRequestError && error.kind === "aborted") return;
      setState({ kind: "error", message: error instanceof ApiRequestError && error.status === 401
        ? "The operator credential was rejected."
        : "Stored Red assessment data could not be verified." });
    });
    return () => controller.abort();
  }, [token, targetId, status, offset, refresh]);

  if (!token) return <section className="panel red-credential-panel">
    <div><h3>Connect Red assessment data</h3>
      <p className="muted">Enter the locally configured operator credential. It stays in this page’s memory and is not saved by MARS.</p></div>
    <form onSubmit={event => {
      event.preventDefault();
      const next = credential.trim();
      if (next) setToken(next);
    }}>
      <label htmlFor="red-operator-credential">Operator credential</label>
      <input id="red-operator-credential" type="password" value={credential}
        autoComplete="off" required onChange={event => setCredential(event.target.value)} />
      <ActionButton type="submit">Connect Red data</ActionButton>
    </form>
  </section>;

  if (selectedAssessmentId) return <div className="red-workspace">
    <AssessmentWorkspace token={token} assessmentId={selectedAssessmentId}
      onClose={() => setSelectedAssessmentId(null)}
      onChanged={() => setRefresh(value => value + 1)} />
  </div>;

  return <div className="red-workspace">
    <NewAssessment token={token} targets={targets}
      assessments={state.kind === "ready" ? state.assessments : []}
      onChanged={() => setRefresh(value => value + 1)} />
    <RedDashboardView targets={targets} targetId={targetId} status={status}
      state={state} onTargetChange={value => { setTargetId(value); setOffset(0); }}
      onStatusChange={value => { setStatus(value); setOffset(0); }}
      onRefresh={() => setRefresh(value => value + 1)} onPageChange={setOffset}
      onInspect={setSelectedAssessmentId}
      onDisconnect={() => {
        setToken(""); setCredential(""); setTargets([]); setTargetId("");
        setStatus(""); setOffset(0); setState({ kind: "loading" });
      }} />
  </div>;
}
