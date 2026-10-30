import { useEffect, useState } from "react";
import { ApiRequestError } from "../api";
import { listRedTargets, loadRedDashboard, type RedAssessment, type RedDashboardSummary, type RedTarget } from "../red/api";
import { Button } from "../components/ui/button";
import { LoadingState } from "../ui";

export type RedOverviewState =
  | { kind: "loading" }
  | { kind: "error"; denied: boolean }
  | { kind: "ready"; targets: RedTarget[]; summary: RedDashboardSummary; assessments: RedAssessment[] };

export function RedOverview() {
  const [state, setState] = useState<RedOverviewState>({ kind: "loading" });
  const [revision, setRevision] = useState(0);
  useEffect(() => {
    const controller = new AbortController();
    setState({ kind: "loading" });
    void Promise.all([listRedTargets("", controller.signal),
      loadRedDashboard("", { targetId: "", status: "", offset: 0 }, controller.signal)])
      .then(([targets, dashboard]) => {
        if (!controller.signal.aborted) setState({ kind: "ready", targets: targets.items,
          summary: dashboard.summary, assessments: dashboard.assessments.items });
      }).catch(error => {
        if (!controller.signal.aborted) setState({ kind: "error",
          denied: error instanceof ApiRequestError && [401, 403].includes(error.status ?? 0) });
      });
    return () => controller.abort();
  }, [revision]);
  return <RedOverviewView state={state} onRetry={() => setRevision(value => value + 1)} />;
}

export function RedOverviewView({ state, onRetry }: { state: RedOverviewState; onRetry: () => void }) {
  return <div className="grid gap-6 md:grid-cols-[1.3fr_1fr]" role="group" aria-label="Team workspaces">
    <article className="team-card" aria-labelledby="red-entry-title" aria-busy={state.kind === "loading"}>
      <span className="eyebrow">Assessment workspace</span>
      <h2 id="red-entry-title">Red Team</h2>
      <p>Review scope, run bounded assessments and inspect verified evidence.</p>
      {state.kind === "loading" && <LoadingState label="Checking Red assessment data…" />}
      {state.kind === "error" && <div role="status">
        <p>{state.denied ? "Session access required. Sign in again to restore access." : "Red service unavailable. Data could not be verified."}</p>
        <Button variant="outline" onClick={onRetry}>Retry Red data</Button>
      </div>}
      {state.kind === "ready" && <p role="status">{state.targets.length ? state.targets.length + " registered target" + (state.targets.length === 1 ? "" : "s") : "No registered targets available"}
        {" · " + state.summary.active_assessments + " active assessment" + (state.summary.active_assessments === 1 ? "" : "s")}</p>}
      <Button asChild><a href="/dashboard/red-team">Open Red Team</a></Button>
    </article>
    <article className="team-card" aria-labelledby="blue-entry-title">
      <span className="eyebrow">Remediation workspace</span>
      <h2 id="blue-entry-title">Blue Team</h2>
      <p>Blue Team functionality is deferred. This entry remains available for the next product phase.</p>
      <Button variant="outline" asChild><a href="/dashboard/blue-team">Open Blue Team</a></Button>
    </article>
  </div>;
}
