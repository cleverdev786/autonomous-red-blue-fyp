import type { Overview } from "../api";
import { EmptyState, LoadingState } from "../ui";
import { RunTable } from "./RunTable";
import { MarsMark } from "../brand";

export type OverviewState =
  | { kind: "loading" }
  | { kind: "unavailable"; detail: string }
  | { kind: "ready"; overview: Overview };

const destinations = [
  { href: "/dashboard/assessments", glyph: "◎", title: "Assessments", detail: "Explore registered scenarios", color: "violet" },
  { href: "/dashboard/findings", glyph: "⌕", title: "Findings", detail: "Review saved observations", color: "blue" },
  { href: "/dashboard/remediation", glyph: "✧", title: "Remediation", detail: "Prepare a trusted fix preview", color: "mint" },
] as const;

export function OverviewPanel({ state }: { state: OverviewState }) {
  return <div className="workspace-overview">
    <div className="overview-top">
      <section className="welcome-card">
        <span className="welcome-kicker">MARS WORKSPACE</span>
        <h3>Manage your security workflow</h3>
        <p>Browse registered scenarios, inspect evidence and prepare trusted previews.</p>
        <a className="primary-action" href="/dashboard/assessments">Browse assessments <span aria-hidden="true">↗</span></a>
        <div className="mars-motion-visual" aria-hidden="true">
          <span className="mars-orbit mars-orbit--outer"/><span className="mars-orbit mars-orbit--inner"/>
          <span className="mars-orbit-node mars-orbit-node--one"/><span className="mars-orbit-node mars-orbit-node--two"/>
          <MarsMark className="mars-motion-mark" />
        </div>
      </section>
      <section className="snapshot-card">
        <div className="snapshot-head"><span>Run history</span><a href="/dashboard/reports" aria-label="Open reports">↗</a></div>
        {state.kind === "loading" && <LoadingState label="Loading local run summary…" />}
        {state.kind === "unavailable" && <>
          <div className="snapshot-status"><span className="snapshot-indicator snapshot-offline" /> Unavailable</div>
          <p className="snapshot-explainer">No database connection is configured for stored runs.</p>
          <span className="snapshot-note">Historical evidence is unaffected.</span>
        </>}
        {state.kind === "ready" && <>
          <div className="snapshot-number">{state.overview.total_runs}</div>
          <p className="snapshot-explainer">Runs recorded in the connected database</p>
          <span className="snapshot-note">Stored records, not final research trials</span>
        </>}
      </section>
    </div>
    <div className="section-title section-title--tools">
      <div><h3>Workspace tools</h3><p>Choose what you want to work on.</p></div>
    </div>
    <section className="tool-grid" aria-label="Workspace tools">
      {destinations.map(item => <a className="tool-card" href={item.href} key={item.title}>
        <span className={"tool-icon tool-icon--" + item.color} aria-hidden="true">{item.glyph}</span>
        <span className="tool-title">{item.title}</span>
        <span className="tool-detail">{item.detail}</span>
        <span className="tool-arrow" aria-hidden="true">↗</span>
      </a>)}
    </section>
    <div className="section-title section-title--activity">
      <div><h3>Recent activity</h3><p>Stored results from your local workspace.</p></div>
      <a className="subtle-link" href="/dashboard/reports">View reports <span aria-hidden="true">↗</span></a>
    </div>
    {state.kind === "loading" && <section className="surface-card">
      <LoadingState label="Loading local run summary…" />
    </section>}
    {state.kind === "unavailable" && <section className="surface-card empty-history">
      <span className="empty-history-icon" aria-hidden="true">▤</span>
      <div><h4>Data source unavailable</h4>
        <p>{state.detail} Connect the local run database to view recent activity.</p>
        <span className="fine-print">No stored-run totals are inferred. Archived research evidence is not affected.</span>
      </div>
    </section>}
    {state.kind === "ready" && <RecordedActivity overview={state.overview} />}
  </div>;
}

function RecordedActivity({ overview }: { overview: Overview }) {
  const statuses = Object.entries(overview.status_counts);
  const questions = Object.entries(overview.research_question_counts);
  return <div className="overview-recorded">
    {overview.total_runs === 0 ? <section className="surface-card empty-history">
      <span className="empty-history-icon" aria-hidden="true">▤</span>
      <div><EmptyState title="No stored runs in this database"
        description="No records were returned. This is not evidence of final research completion or the absence of other archives." /></div>
    </section> : <>
      <div className="recorded-breakdowns">
        <section className="surface-card"><h4>Recorded outcomes</h4>
          {statuses.length ? <dl className="overview-counts">
            {statuses.map(([status,count]) => <div key={status}><dt>{status.replaceAll("_"," ")}</dt><dd>{count}</dd></div>)}
          </dl> : <p className="muted">No breakdown available.</p>}
        </section>
        <section className="surface-card"><h4>Run categories</h4>
          {questions.length ? <dl className="overview-counts">
            {questions.map(([label,count]) => <div key={label}><dt>{label.toUpperCase()}</dt><dd>{count}</dd></div>)}
          </dl> : <p className="muted">No categories available.</p>}
        </section>
      </div>
      <section className="surface-card"><h4>Recent stored runs</h4>
        {overview.recent_runs.length ? <RunTable runs={overview.recent_runs} /> :
          <p className="muted">No recent records returned.</p>}
      </section>
    </>}
  </div>;
}
