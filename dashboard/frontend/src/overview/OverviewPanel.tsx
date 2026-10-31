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
      <span className="eyebrow">MARS security workspace</span>
      <h2>A clear view of your security workflow.</h2>
      <p>Choose a team workspace to review assessments, follow progress and inspect evidence.</p>
      <Button asChild><a href="/dashboard/red-team">Review Red assessments</a></Button>
    </section>
    <RedOverview />
  </div>;
}
