import { useEffect, useState } from "react";
import { ApiRequestError } from "../api";
import { listRedTargets, loadRedDashboard, type RedTarget } from "./api";
import { NewAssessment } from "./NewAssessment";
import { AssessmentWorkspace } from "./AssessmentWorkspace";
import { RedDashboardView, type RedDashboardState } from "./RedDashboardView";
import { Button } from "../components/ui/button";
import { assessmentPath } from "../routes";
import { notify } from "../ui";

export function RedDashboard({ assessmentId, onNavigate }: {
  assessmentId?: string; onNavigate: (path: string) => void;
}) {
  const token = "";
  const [targets, setTargets] = useState<RedTarget[]>([]);
  const [targetId, setTargetId] = useState("");
  const [status, setStatus] = useState("");
  const [offset, setOffset] = useState(0);
  const [refresh, setRefresh] = useState(0);
  const [state, setState] = useState<RedDashboardState>({ kind: "loading" });
  const [showSetup, setShowSetup] = useState(false);
  const openAssessment = (id: string) => { setShowSetup(false); onNavigate(assessmentPath(id)); };

  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: "loading" });
    void Promise.all([listRedTargets(token, controller.signal),
      loadRedDashboard(token, { targetId, status, offset }, controller.signal)])
      .then(([page, dashboard]) => {
        if (controller.signal.aborted) return;
        setTargets(page.items);
        setState({ kind: "ready", summary: dashboard.summary, assessments: dashboard.assessments.items,
          total: dashboard.assessments.pagination.total, offset: dashboard.assessments.pagination.offset,
          limit: dashboard.assessments.pagination.limit });
        if (refresh > 0) notify("Red dashboard refreshed.");
      }).catch(error => {
        if (controller.signal.aborted || error instanceof ApiRequestError && error.kind === "aborted") return;
        setState({ kind: "error", message: "Red targets or assessment data could not be verified." });
        notify("Red dashboard could not refresh.", true);
      });
    return () => controller.abort();
  }, [token, targetId, status, offset, refresh]);

  if (assessmentId) return <div className="red-workspace mars-content">
    <AssessmentWorkspace key={assessmentId} token={token} assessmentId={assessmentId}
      onClose={() => onNavigate("/dashboard/red-team")}
      onChanged={() => setRefresh(value => value + 1)} />
  </div>;

  return <div className="red-workspace">
    <div className="mars-content flex flex-wrap items-center justify-between gap-4">
      <p className="text-muted-foreground">Review saved assessments or begin a scoped workflow.</p>
      <Button className="new-assessment-button" onClick={() => setShowSetup(value => !value)} aria-expanded={showSetup} aria-controls="red-setup">
        {showSetup ? "Close setup" : "New assessment"}
      </Button>
    </div>
    {showSetup && <div id="red-setup" className="mars-content"><NewAssessment token={token} targets={targets}
      assessments={state.kind === "ready" ? state.assessments : []}
      onOpened={openAssessment}
      onChanged={() => setRefresh(value => value + 1)} /></div>}
    <RedDashboardView targets={targets} targetId={targetId} status={status}
      state={state} onTargetChange={value => { setTargetId(value); setOffset(0); }}
      onStatusChange={value => { setStatus(value); setOffset(0); }}
      onRefresh={() => setRefresh(value => value + 1)} onPageChange={setOffset}
      onInspect={openAssessment} />
  </div>;
}
