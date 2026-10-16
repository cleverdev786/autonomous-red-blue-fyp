import { useEffect, useMemo, useState } from "react";
import {
  getConsoleJson,
  getJson,
  type DevelopmentEvidence,
  type RegisteredScenario,
  type ScenarioKey,
  PREVIEW_TEST_IDS,
  type TrustedPreview,
  prepareConsolePreview,
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
  | "Audit"
  | "Development Evidence"
  | "Trusted Preview"
  | "Operator Status";

const views: View[] = [
  "Overview",
  "Operator Status",
  "Trusted Preview",
  "Development Evidence",
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
  const [development, setDevelopment] = useState<DevelopmentEvidence | null>(null);
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
    if (view === "Overview" || view === "Runs" || view === "Trusted Preview" || view === "Operator Status") return;
    if (view === "Development Evidence") {
      setDevelopment(null);
      let current = true;
      Promise.all([
        getConsoleJson<DevelopmentEvidence["red"]>("/assessment/registered-red"),
        getConsoleJson<DevelopmentEvidence["blue"]>("/assessment/review"),
        getConsoleJson<DevelopmentEvidence["sqli"]>("/assessment/patched-replay"),
        getConsoleJson<DevelopmentEvidence["phase5"]>("/assessment/phase5-replays"),
      ]).then(([red, blue, sqli, phase5]) => {
        if (current) setDevelopment({ red, blue, sqli, phase5 });
      }).catch((reason: unknown) => {
        if (current) setError(String(reason));
      });
      return () => { current = false; };
    }
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
    <>
    <a className="skip-to-content" href="#main-content">Skip to main content</a>
    <div className="shell">
      <aside className="sidebar">
        <div>
          <div className="eyebrow">SENTINEL · LOCAL LAB</div>
          <h1>Red–Blue FYP</h1>
          <p className="muted">Research evidence, registered previews, and local safeguards.</p>
        </div>
        <nav>
          {views.map((item) => (
            <button
              key={item}
              className={view === item ? "nav active" : "nav"}
              aria-current={view === item ? "page" : undefined}
              onClick={() => { setView(item); document.getElementById("main-content")?.focus(); }}
            >
              {item}
            </button>
          ))}
        </nav>
        {!["Development Evidence", "Trusted Preview", "Operator Status"].includes(view) && (
          <div className="run-picker">
            <label htmlFor="run">Selected run</label>
            <select id="run" value={selectedRun} onChange={(event) => setSelectedRun(event.target.value)}>
              {runs.map((run) => (
                <option key={run.run_id} value={run.run_id}>{run.run_id}</option>
              ))}
            </select>
            {selected && <span className={`status ${selected.status}`}>{selected.status}</span>}
          </div>
        )}
      </aside>

      <main id="main-content" tabIndex={-1}>
        <header className="page-header">
          <div>
            <div className="eyebrow">Dashboard</div>
            <h2>{view}</h2>
          </div>
          <div className="safety-badge">{view === "Trusted Preview" ? "Inert patch preview · no application" : view === "Operator Status" ? "Read-only local runtime" : "Stored evidence · development only"}</div>
        </header>

        {error && <div className="error">{error}</div>}
        {view === "Overview" && <OverviewPanel overview={overview} />}
        {view === "Runs" && <RunsPanel runs={runs} onSelect={(id) => { setSelectedRun(id); setView("Run Detail"); }} />}
        {view === "Run Detail" && <RunDetailPanel payload={payload} scores={scores} />}
        {view === "Findings" && <JsonPanel value={payload} />}
        {view === "Patch Verification" && <PatchPanel value={patches} />}
        {view === "Metrics" && <JsonPanel value={payload} />}
        {view === "Audit" && <JsonPanel value={payload} />}
        {view === "Development Evidence" && <DevelopmentEvidencePanel evidence={development} />}
        {view === "Trusted Preview" && <TrustedPreviewPanel />}
        {view === "Operator Status" && <OperatorStatusPanel />}
      </main>
    </div>
    </>
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

export function DevelopmentEvidencePanel({ evidence }: { evidence: DevelopmentEvidence | null }) {
  if (!evidence) return <section className="panel">Loading pinned development evidence…</section>;

  const { red, blue, sqli, phase5 } = evidence;
  const baseline = red.status === "verified_archived_red" &&
    red.red_evidence_verified === true && red.exploit_confirmed === true &&
    red.registered_test_id === "sqli-login-bypass-001";
  const model = baseline && blue.status === "evidence_bound" &&
    blue.model_origin === "q8_0_cpu_model" &&
    blue.model_input_scope === "registered_steps_plus_captured_responses" &&
    blue.red_evidence_verified === true && blue.source_analysis_authorized === true &&
    blue.registered_test_id === red.registered_test_id &&
    blue.red_run_id === red.red_run_id &&
    blue.model_decision?.classification === "sql_injection";
  const sqlReplay = model && sqli.status === "verified_archived_patched_replay" &&
    sqli.registered_replay_verified === true && sqli.exploit_confirmed === false &&
    sqli.test_id === red.registered_test_id && sqli.run_id !== red.red_run_id;

  const verifiedOther = phase5.status === "verified_archived_phase5_replays" &&
    phase5.replay_count === 2;
  const scenarios = [
    ["xss", "Reflected XSS", "xss-reflection-001", "Script marker HTML-escaped"],
    ["traversal", "Path traversal", "path-traversal-private-file-001", "Private-file request blocked"],
  ] as const;

  return (
    <div className="stack">
      <section className="panel" aria-label="Development evidence scope">
        <h3>Operator-pinned development evidence</h3>
        <p><a href="/api/console/assessment/export" download="sentinel-development-evidence.json">Download development evidence JSON</a></p>
        <p className="muted">Read-only review of saved lab executions. These are author-reviewed development runs, not independent research trials.</p>
        <p className="muted">The original SQLi Red run preceded the Q8 classification. Q8 did not initiate the registered XSS or traversal tests, and trusted deterministic templates prepared all three repairs.</p>
      </section>
      <section className="panel">
        <h3>SQL injection evidence chain</h3>
        <div className="evidence-grid">
          <div className="evidence-step"><span>1 · Registered Red baseline</span><strong>{baseline ? "Verified local-lab exploit" : "Unverified"}</strong></div>
          <div className="evidence-step"><span>2 · Q8 post-hoc classification</span><strong>{model ? "Verified archived SQLi classification" : "Unverified"}</strong></div>
          <div className="evidence-step"><span>3 · Bound Blue source eligibility</span><strong>{model ? "Verified archival handoff" : "Not authorized"}</strong></div>
          <div className="evidence-step"><span>4 · Patched Docker replay</span><strong>{sqlReplay ? "Verified exploit prevented" : "Unverified"}</strong></div>
        </div>
        <p className="muted">Patched Docker legitimate login and search/file checks: {sqlReplay && sqli.legitimate_login_verified && sqli.search_file_verified ? "verified" : "unverified"}.</p>
      </section>
      <section className="panel">
        <h3>Other registered security replays</h3>
        <div className="evidence-grid">
          {scenarios.map(([key, name, testId, outcome]) => {
            const item = phase5.results?.[key];
            const accepted = verifiedOther && item?.registered_replay_verified === true &&
              item.baseline_exploit_confirmed === true &&
              item.patched_exploit_confirmed === false &&
              item.registered_test_id === testId;
            return (
              <div className="evidence-step" key={key}>
                <span>{name}</span>
                <strong>{accepted ? outcome : "Unverified"}</strong>
                {accepted && <small>Registered run: {item.run_id}</small>}
              </div>
            );
          })}
        </div>
        <p className="muted">Disposable-app functionality passed for XSS and traversal. Separate patched-Docker legitimate-function verification remains unverified.</p>
      </section>
      <section className="panel">
        <h3>Qualification boundaries</h3>
        <p className="muted">Original live vulnerable source: unchanged. Prospective model-directed Red selection: not demonstrated. Final RQ1/RQ2 research: pending independent approval and execution.</p>
      </section>
    </div>
  );
}

export function TrustedPreviewPanel() {
  const [catalog, setCatalog] = useState<RegisteredScenario[]>([]);
  const [scenario, setScenario] = useState<ScenarioKey>("sql");
  const [preview, setPreview] = useState<TrustedPreview | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    let current = true;
    getConsoleJson<RegisteredScenario[]>("/scenarios")
      .then((items) => {
        if (!current) return;
        const allowed = items.filter(
          (item) => Object.hasOwn(PREVIEW_TEST_IDS, item.id) &&
            PREVIEW_TEST_IDS[item.id as ScenarioKey] === item.registered_test,
        );
        setCatalog(allowed);
        if (allowed.length && !allowed.some((item) => item.id === scenario)) {
          setScenario(allowed[0].id as ScenarioKey);
        }
      })
      .catch((reason: unknown) => { if (current) setError(String(reason)); });
    return () => { current = false; };
  }, []);

  const selected = catalog.find((item) => item.id === scenario);
  const verifiedPreview = preview?.prepared === true &&
    preview.applied === false && preview.verified === false &&
    preview.final_research === false && preview.scenario === scenario &&
    preview.registered_test_id === selected?.registered_test &&
    /^[a-f0-9]{64}$/.test(preview.prepared_diff_sha256);

  async function prepare() {
    if (!selected || busy) return;
    setBusy(true);
    setError("");
    setPreview(null);
    try {
      setPreview(await prepareConsolePreview(scenario));
    } catch (reason) {
      setError(String(reason));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="stack">
      <section className="panel">
        <h3>Registered vulnerability workbench</h3>
        <p className="muted">
          This prepares an inert trusted patch diff for the owned synthetic lab.
          It does not run Red tests, perform model inference, change source code,
          apply a repair, or qualify scientific research.
        </p>
        <div className="preview-controls">
          <label htmlFor="trusted-scenario">Registered scenario</label>
          <select id="trusted-scenario" value={scenario} disabled={busy || !catalog.length}
            onChange={(event) => {
              setScenario(event.target.value as ScenarioKey);
              setPreview(null);
              setError("");
            }}>
            {catalog.map((item) => (
              <option key={item.id} value={item.id}>{item.title}</option>
            ))}
          </select>
          <button type="button" disabled={!selected || busy} onClick={prepare}>
            {busy ? "Preparing…" : "Prepare trusted preview"}
          </button>
        </div>
        {selected ? (
          <p className="muted">
            Test: {selected.registered_test}. Risk: {selected.vector}.
            Remediation: {selected.remediation}.
          </p>
        ) : <p className="muted">No approved scenarios loaded. Preview is unavailable.</p>}
        {error && <p role="alert" className="error">{error}</p>}
      </section>
      {preview && <section className="panel" aria-live="polite">
        <h3>{verifiedPreview ? "Trusted patch prepared" : "Preview withheld"}</h3>
        {verifiedPreview ? (
          <>
            <p className="muted">Registered test: {preview.registered_test_id}</p>
            <p className="muted">Diff SHA-256: {preview.prepared_diff_sha256}</p>
            <p className="muted">{preview.notice}</p>
            <pre className="diff">{preview.diff_preview.slice(0, 5000)}</pre>
          </>
        ) : <p role="alert">The returned preview did not match the registered scenario or safety state. No result is accepted.</p>}
      </section>}
      <p className="muted">Need model controls or a registered replay? <a href="/">Open the original operator console</a>. Those actions are deliberately absent here.</p>
    </div>
  );
}

/** Read-only runtime inspection; no model-loading or execution actions. */
export function OperatorStatusPanel() {
  type Runtime = {
    target: string;
    execution_mode: string;
    experience_mode: string;
    model: { state: string; final_research_ready: boolean };
    rq1_final_runs_verified_here: number | null;
    rq2_final_observations_verified_here: number | null;
  };
  type Inventory = {
    model_directory_configured: boolean;
    models: { filename: string; bytes: number }[];
  };
  const [version, refresh] = useState(0);
  const [result, setResult] = useState<{ runtime: Runtime; inventory: Inventory } | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let active = true;
    setResult(null);
    setError("");
    Promise.all([
      getConsoleJson<Runtime>("/status"),
      getConsoleJson<Inventory>("/models/local"),
    ]).then(([runtime, inventory]) => {
      if (active) setResult({ runtime, inventory });
    }).catch(() => {
      if (active) setError("Local runtime status unavailable. No model or research state has been verified.");
    });
    return () => { active = false; };
  }, [version]);

  return <div className="stack">
    <section className="panel">
      <div className="runtime-heading">
        <div>
          <div className="eyebrow">LOCALHOST / LIVE SNAPSHOT</div>
          <h3>Runtime and safeguards</h3>
          <p className="muted">Current local API status, separate from archived development evidence.</p>
        </div>
        <button type="button" className="runtime-refresh" onClick={() => refresh(n => n + 1)}>
          Refresh status
        </button>
      </div>
      {error && <p role="alert" className="error">{error}</p>}
      {!result && !error && <p role="status" className="muted">Checking local runtime…</p>}
      {result && <dl className="runtime-rows" aria-label="Current system safeguards">
        <div><dt>Model process</dt><dd>{result.runtime.model.state}</dd>
          <small>File availability does not mean a model is running</small></div>
        <div><dt>Research experience mode</dt><dd>{result.runtime.experience_mode}</dd>
          <small>Primary experiments are not authorized here</small></div>
        <div><dt>Execution scope</dt><dd>{result.runtime.execution_mode}</dd>
          <small>Target: {result.runtime.target}</small></div>
        <div><dt>Final study qualification</dt><dd>{result.runtime.model.final_research_ready === true &&
          result.runtime.rq1_final_runs_verified_here !== null &&
          result.runtime.rq2_final_observations_verified_here !== null
            ? "Reported; independent review required" : "Not verified"}</dd>
          <small>Never inferred from development previews</small></div>
      </dl>}
    </section>
    {result && <section className="panel">
      <h3>Local model file inventory</h3>
      {result.inventory.models.length ? <ul className="model-inventory">
        {result.inventory.models.map(file => <li key={file.filename}>
          <strong>{file.filename}</strong>
          <span>{(file.bytes / 1024 ** 3).toFixed(2)} GiB · on disk only</span>
        </li>)}
      </ul> : <p className="muted">{result.inventory.model_directory_configured
        ? "No local GGUF files listed." : "Local model directory not configured."}</p>}
      <p className="muted">A listed file is not proof of approval, sufficient memory, or a loaded model.</p>
    </section>}
    <p className="muted">For bounded model controls and registered replays,
      {" "}<a href="/">open the original operator console</a>.
      This page does not start models or dispatch security tests.
    </p>
  </div>;
}
