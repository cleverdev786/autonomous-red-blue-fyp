import type { Overview } from "../api";
import { RedOverview } from "./RedOverview";
import { Button } from "../components/ui/button";

export type OverviewState =
  | { kind: "loading" }
  | { kind: "unavailable"; detail: string }
  | { kind: "ready"; overview: Overview };

export function OverviewPanel(_props: { state: OverviewState }) {
  return <div className="workspace-overview">
    <section className="workspace-hero">
      <h2>Controlled assessments. Traceable evidence.</h2>
      <p>Review authorized Red Team assessments in the isolated lab, follow agent progress and inspect verified findings.</p>
      <Button asChild><a href="/dashboard/red-team">Review Red assessments</a></Button>
    </section>
    <RedOverview />
  </div>;
}
