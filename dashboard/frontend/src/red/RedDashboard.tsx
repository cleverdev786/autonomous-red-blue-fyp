import { useEffect, useState } from "react";
import { ApiRequestError } from "../api";
import { listRedTargets, loadRedDashboard, type RedTarget } from "./api";
import { NewAssessment } from "./NewAssessment";
import { AssessmentWorkspace } from "./AssessmentWorkspace";
import { RedDashboardView, type RedDashboardState } from "./RedDashboardView";

export function RedDashboard() {
  const token = "";
  const [targets, setTargets] = useState<RedTarget[]>([]);
  const [targetId, setTargetId] = useState("");
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [state, setState] = useState<RedDashboardState>({ kind: "loading" });
  const [selectedAssessmentId, setSelectedAssessmentId] = useState<string | null>(null);

  useEffect(() => {
    const controller = new AbortController();
    void listRedTargets(token, controller.signal).then(page => setTargets(page.items)).catch(error => {
      if (error instanceof ApiRequestError && error.kind === "aborted") return;
      setState({ kind: "error", message: "Registered Red targets could not be verified." });
    });
    return () => controller.abort();
  }, []);

  useEffect(() => {
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
      setState({ kind: "error", message: "Stored Red assessment data could not be verified." });
    });
    return () => controller.abort();
  }, [token, targetId, status, offset, refresh]);

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
      onInspect={setSelectedAssessmentId} />
  </div>;
}
