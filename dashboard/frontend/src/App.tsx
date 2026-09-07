import { useEffect, useMemo, useState } from "react";
import {
  getJson,
  type Overview,
  type PatchVerification,
  type RunItem,
  type RunScores,
} from "./api";

type View =
  | "Overview"
  | "Runs"
  | "Run Detail"
  | "Findings"
  | "Patch Verification"
  | "Metrics"
  | "Audit";

const views: View[] = [
  "Overview",
  "Runs",
  "Run Detail",
  "Findings",
  "Patch Verification",
  "Metrics",
  "Audit",
];

function displayScore(value: string | number | null): string {
  return value === null ? "—" : String(value);
}

export default function App() {
  const [view, setView] = useState<View>("Overview");
  const [overview, setOverview] = useState<Overview | null>(null);
  const [runs, setRuns] = useState<RunItem[]>([]);
  const [selectedRun, setSelectedRun] = useState<string>("");
  const [payload, setPayload] = useState<unknown>(null);
  const [scores, setScores] = useState<RunScores | null>(null);
  const [patches, setPatches] = useState<PatchVerification | null>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    Promise.all([getJson<Overview>("/overview"), getJson<RunItem[]>("/runs")])
      .then(([nextOverview, nextRuns]) => {
        setOverview(nextOverview);
        setRuns(nextRuns);
        if (!selectedRun && nextRuns.length > 0) {
          setSelectedRun(nextRuns[0].run_id);
        }
      })
      .catch((reason: unknown) => setError(String(reason)));
  }, []);

  useEffect(() => {
    setError("");
    setPayload(null);
    setScores(null);
    setPatches(null);
    if (view === "Overview" || view === "Runs") return;
    if (view === "Metrics") {
      Promise.all([
        getJson<unknown>("/metrics/rq1"),
        getJson<unknown>("/metrics/rq2"),
        getJson<unknown>("/metrics/rq3"),
        getJson<unknown>("/metrics/red"),
        getJson<unknown>("/metrics/normal-application"),
      ])
        .then(([rq1, rq2, rq3, red, normal]) =>
          setPayload({ rq1, rq2, rq3, red, normal }),
        )
        .catch((reason: unknown) => setError(String(reason)));
      return;
    }
    if (!selectedRun) return;

    if (view === "Run Detail") {
      Promise.all([
        getJson<unknown>(`/runs/${selectedRun}`),
        getJson<RunScores>(`/runs/${selectedRun}/scores`),
      ])
        .then(([detail, nextScores]) => {
          setPayload(detail);
          setScores(nextScores);
        })
        .catch((reason: unknown) => setError(String(reason)));
      return;
    }
    if (view === "Findings") {
      getJson<unknown>(`/runs/${selectedRun}/findings`)
        .then(setPayload)
        .catch((reason: unknown) => setError(String(reason)));
      return;
    }
    if (view === "Patch Verification") {
      getJson<PatchVerification>(`/runs/${selectedRun}/patch-verification`)
        .then(setPatches)
        .catch((reason: unknown) => setError(String(reason)));
      return;
    }
    if (view === "Audit") {
      getJson<unknown>(`/runs/${selectedRun}/audit`)
        .then(setPayload)
        .catch((reason: unknown) => setError(String(reason)));
    }
  }, [view, selectedRun]);

  const selected = useMemo(
    () => runs.find((run) => run.run_id === selectedRun) ?? null,
    [runs, selectedRun],
  );

  return (
    <div className="shell">
      <aside className="sidebar">
        <div>
          <div className="eyebrow">M16 · READ ONLY</div>
          <h1>Red–Blue FYP</h1>
          <p className="muted">Experiment visibility and deterministic stored scores.</p>
        </div>
        <nav>
          {views.map((item) => (
            <button
              key={item}
              className={view === item ? "nav active" : "nav"}
              onClick={() => setView(item)}
            >
              {item}
            </button>
          ))}
        </nav>
        <div className="run-picker">
          <label htmlFor="run">Selected run</label>
          <select id="run" value={selectedRun} onChange={(event) => setSelectedRun(event.target.value)}>
            {runs.map((run) => (
              <option key={run.run_id} value={run.run_id}>{run.run_id}</option>
            ))}
          </select>
          {selected && <span className={`status ${selected.status}`}>{selected.status}</span>}
        </div>
      </aside>

      <main>
        <header className="page-header">
          <div>
            <div className="eyebrow">Dashboard</div>
            <h2>{view}</h2>
          </div>
          <div className="safety-badge">Stored evidence only · no execution controls</div>
        </header>

        {error && <div className="error">{error}</div>}
        {view === "Overview" && <OverviewPanel overview={overview} />}
        {view === "Runs" && <RunsPanel runs={runs} onSelect={(id) => { setSelectedRun(id); setView("Run Detail"); }} />}
        {view === "Run Detail" && <RunDetailPanel payload={payload} scores={scores} />}
        {view === "Findings" && <JsonPanel value={payload} />}
        {view === "Patch Verification" && <PatchPanel value={patches} />}
        {view === "Metrics" && <JsonPanel value={payload} />}
        {view === "Audit" && <JsonPanel value={payload} />}
      </main>
    </div>
  );
}

function OverviewPanel({ overview }: { overview: Overview | null }) {
  if (!overview) return <div className="panel">Loading stored overview…</div>;
  return (
    <>
      <section className="stat-grid">
        <article className="stat"><span>Total runs</span><strong>{overview.total_runs}</strong></article>
        {Object.entries(overview.status_counts).map(([status, count]) => (
          <article className="stat" key={status}><span>{status}</span><strong>{count}</strong></article>
        ))}
      </section>
      <section className="panel">
        <h3>Research-question coverage</h3>
        <div className="chips">
          {Object.entries(overview.research_question_counts).map(([rq, count]) => (
            <span className="chip" key={rq}>{rq.toUpperCase()} · {count}</span>
          ))}
        </div>
      </section>
      <section className="panel">
        <h3>Recent runs</h3>
        <RunTable runs={overview.recent_runs} />
      </section>
    </>
  );
}

function RunsPanel({ runs, onSelect }: { runs: RunItem[]; onSelect: (id: string) => void }) {
  return (
    <section className="panel">
      <h3>All stored outcomes</h3>
      <RunTable runs={runs} onSelect={onSelect} />
    </section>
  );
}

function RunTable({ runs, onSelect }: { runs: RunItem[]; onSelect?: (id: string) => void }) {
  return (
    <div className="table-wrap">
      <table>
        <thead><tr><th>Run</th><th>RQ</th><th>Status</th><th>Red</th><th>Blue</th><th>Subject</th></tr></thead>
        <tbody>
          {runs.map((run) => (
            <tr key={run.run_id} onClick={() => onSelect?.(run.run_id)} className={onSelect ? "clickable" : ""}>
              <td>{run.run_id}</td><td>{run.research_question}</td><td><span className={`status ${run.status}`}>{run.status}</span></td>
              <td>{displayScore(run.red_score)}</td><td>{displayScore(run.blue_score)}</td><td>{run.scenario_id ?? run.dataset_id}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function RunDetailPanel({ payload, scores }: { payload: unknown; scores: RunScores | null }) {
  return (
    <div className="stack">
      <JsonPanel value={payload} title="Stored run detail" />
      <section className="panel">
        <h3>Stored score evidence</h3>
        {!scores && <p className="muted">No score response loaded.</p>}
        {scores && <p className="muted">Applicability: {scores.applicability}</p>}
        {scores?.scores.map((score) => (
          <article className="score-card" key={`${score.score_type}-${score.scoring_version}`}>
            <div className="score-head"><strong>{score.score_type.toUpperCase()} · {String(score.score_value)}</strong><span>{score.scoring_version}</span></div>
            <p>Evidence integrity: <strong>{score.evidence_integrity ? "verified" : "failed"}</strong></p>
            {score.breakdown && (
              <>
                <div className="component-grid">
                  {score.breakdown.components.map((component) => (
                    <div className="component" key={component.component_id}>
                      <span>{component.component_id}</span>
                      <strong>{component.points_awarded}/{component.points_possible}</strong>
                    </div>
                  ))}
                </div>
                <div className="component-grid penalties">
                  {score.breakdown.penalties.map((penalty) => (
                    <div className="component" key={penalty.penalty_id}>
                      <span>{penalty.penalty_id}</span><strong>-{penalty.points_deducted}</strong>
                    </div>
                  ))}
                </div>
                <p className="muted">Selected patch attempt: {score.breakdown.selected_patch_attempt ?? "none"}</p>
              </>
            )}
          </article>
        ))}
      </section>
    </div>
  );
}

function PatchPanel({ value }: { value: PatchVerification | null }) {
  if (!value) return <div className="panel">Loading stored patch evidence…</div>;
  return (
    <div className="stack">
      {value.attempts.map((attempt) => (
        <section className="panel" key={attempt.attempt_number}>
          <div className="score-head"><h3>Attempt {attempt.attempt_number}</h3><span>{attempt.final_state ?? "unknown"}</span></div>
          <p className="muted">Diff SHA-256: {attempt.prepared_diff_sha256 ?? "not recorded"}</p>
          <div className="stage-list">
            {attempt.stages.map((stage) => (
              <article className="stage" key={stage.stage_id}>
                <div><strong>{stage.stage_id}</strong><span className={stage.passed ? "pass" : "fail"}>{stage.passed ? "PASS" : "FAIL"}</span></div>
                <p>{stage.details}</p>
              </article>
            ))}
          </div>
          {attempt.diff_excerpt && (
            <div>
              <h4>Bounded inert diff excerpt{attempt.diff_truncated ? " · truncated" : ""}</h4>
              <pre className="diff">{attempt.diff_excerpt}</pre>
            </div>
          )}
        </section>
      ))}
    </div>
  );
}

function JsonPanel({ value, title = "Stored data" }: { value: unknown; title?: string }) {
  return (
    <section className="panel">
      <h3>{title}</h3>
      <pre className="json">{value === null ? "Loading stored evidence…" : JSON.stringify(value, null, 2)}</pre>
    </section>
  );
}
