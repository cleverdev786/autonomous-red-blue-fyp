import { useEffect, useMemo, useRef, useState } from "react";
import {
  getConsoleJson,
  getJson,
  type DevelopmentEvidence,
  type RegisteredScenario,
  type ScenarioKey,
  PREVIEW_TEST_IDS,
  type TrustedPreview,
  prepareConsolePreview,
  startLocalModel,
  stopLocalModel,
  type Overview,
  type PatchVerification,
  type RunItem,
  type RunScores,
} from "./api";
import { BASE_PATH, primaryRoutes, resolveRoute, type View } from "./routes";
import { OverviewPanel, type OverviewState } from "./overview/OverviewPanel";
import { RunTable } from "./overview/RunTable";
import { ActionButton, EmptyState, LoadingState, Notice } from "./ui";
import { MarsMark, NavIcon } from "./brand";
import { AssessmentsPanel } from "./assessments/AssessmentsPanel";

type RunsState =
  | { kind: "loading"; runs: RunItem[] }
  | { kind: "unavailable"; runs: RunItem[] }
  | { kind: "ready"; runs: RunItem[] };

export default function App() {
  const [route, setRoute] = useState(() => resolveRoute(window.location.pathname));
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setTheme] = useState<"light" | "dark">(() => {
    try {
      const saved = window.localStorage.getItem("mars-theme");
      if (saved === "light" || saved === "dark") return saved;
    } catch { /* Private-browsing storage may be restricted. */ }
    return window.matchMedia?.("(prefers-color-scheme: dark)").matches ? "dark" : "light";
  });
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    document.documentElement.style.colorScheme = theme;
    try { window.localStorage.setItem("mars-theme", theme); } catch { /* Storage is optional. */ }
  }, [theme]);
  const menuToggle = useRef<HTMLButtonElement>(null);
  const navigation = useRef<HTMLElement>(null);
  const initialRoute = useRef(true);
  const view: View | null = route.view;

  function navigate(path: string) {
    if (path !== window.location.pathname) window.history.pushState(null, "", path);
    setRoute(resolveRoute(window.location.pathname));
    setMenuOpen(false);
  }

  function followLink(event: React.MouseEvent<HTMLAnchorElement>, path: string) {
    if (event.button !== 0 || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
    event.preventDefault();
    navigate(path);
  }

  useEffect(() => {
    const onPopState = () => { setRoute(resolveRoute(window.location.pathname)); setMenuOpen(false); };
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  useEffect(() => {
    document.title = `${route.title} · MARS`;
    // Initial keyboard navigation must begin at the skip link, not at main.
    if (initialRoute.current) { initialRoute.current = false; return; }
    document.getElementById("main-content")?.focus();
    window.scrollTo({ top: 0, behavior: "instant" });
  }, [route.path]);

  useEffect(() => {
    if (!menuOpen) return;
    navigation.current?.querySelector<HTMLAnchorElement>("a")?.focus();
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        setMenuOpen(false);
        menuToggle.current?.focus();
      } else if (event.key === "Tab") {
        const items = Array.from(document.querySelectorAll<HTMLElement>(
          "#mars-navigation a[href], #mars-navigation select:not(:disabled), #mars-navigation button:not(:disabled)",
        )).filter(element => element.getClientRects().length > 0);
        if (!items.length) return;
        const first = items[0], last = items[items.length - 1];
        const inside = navigation.current?.parentElement?.contains(document.activeElement);
        if (event.shiftKey && (document.activeElement === first || !inside)) {
          event.preventDefault(); last.focus();
        } else if (!event.shiftKey && (document.activeElement === last || !inside)) {
          event.preventDefault(); first.focus();
        }
      }
    };
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
  }, [menuOpen]);
  const [overviewState, setOverviewState] = useState<OverviewState>({ kind: "loading" });
  const [runsState, setRunsState] = useState<RunsState>({ kind: "loading", runs: [] });
  const runs = runsState.runs;
  const [selectedRun, setSelectedRun] = useState<string>("");
  const [payload, setPayload] = useState<unknown>(null);
  const [scores, setScores] = useState<RunScores | null>(null);
  const [patches, setPatches] = useState<PatchVerification | null>(null);
  const [development, setDevelopment] = useState<DevelopmentEvidence | null>(null);
  const [error, setError] = useState<string>("");

  useEffect(() => {
    let active = true;
    // A single health gate prevents fallback zeros in both Overview and Reports.
    getJson<{ status: string; database_read_only: boolean; database_available?: boolean }>("/health")
      .then(health => {
        if (health.status !== "ok" || health.database_read_only !== true) {
          throw new Error("Local database health could not be verified.");
        }
        if (health.database_available === false) {
          if (active) {
            setOverviewState({ kind: "unavailable", detail: "Historical run database is not configured in this local service." });
            setRunsState({ kind: "unavailable", runs: [] });
          }
          return;
        }
        void getJson<Overview>("/overview")
          .then(snapshot => {
            if (!Number.isSafeInteger(snapshot.total_runs) || snapshot.total_runs < 0 ||
                !snapshot.status_counts || !snapshot.research_question_counts ||
                !Array.isArray(snapshot.recent_runs)) {
              throw new Error("Unexpected stored-run summary.");
            }
            if (active) setOverviewState({ kind: "ready", overview: snapshot });
          })
          .catch(() => {
            if (active) setOverviewState({ kind: "unavailable", detail: "The local run database could not be read or verified." });
          });
        void getJson<RunItem[]>("/runs")
          .then(nextRuns => {
            if (!Array.isArray(nextRuns)) throw new Error("Unexpected run-list response.");
            if (!active) return;
            setRunsState({ kind: "ready", runs: nextRuns });
            setSelectedRun(current => nextRuns.some(run => run.run_id === current) ? current : (nextRuns[0]?.run_id ?? ""));
          })
          .catch(() => {
            if (active) setRunsState({ kind: "unavailable", runs: [] });
          });
      })
      .catch(() => {
        if (!active) return;
        setOverviewState({ kind: "unavailable", detail: "The local run database could not be read or verified." });
        setRunsState({ kind: "unavailable", runs: [] });
      });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    let active = true;
    const failed = () => { if (active) setError("The requested stored evidence is unavailable."); };
    setError("");
    setPayload(null);
    setScores(null);
    setPatches(null);
    if (view === "Development Evidence") setDevelopment(null);
    if (view === "Development Evidence") {
      void Promise.all([
        getConsoleJson<DevelopmentEvidence["red"]>("/assessment/registered-red"),
        getConsoleJson<DevelopmentEvidence["blue"]>("/assessment/review"),
        getConsoleJson<DevelopmentEvidence["sqli"]>("/assessment/patched-replay"),
        getConsoleJson<DevelopmentEvidence["phase5"]>("/assessment/phase5-replays"),
      ]).then(([red, blue, sqli, phase5]) => {
        if (active) setDevelopment({ red, blue, sqli, phase5 });
      }).catch(failed);
    } else if (view === "Metrics") {
      void Promise.all([
        getJson<unknown>("/metrics/rq1"), getJson<unknown>("/metrics/rq2"),
        getJson<unknown>("/metrics/rq3"), getJson<unknown>("/metrics/red"),
        getJson<unknown>("/metrics/normal-application"),
      ]).then(([rq1, rq2, rq3, red, normal]) => {
        if (active) setPayload({ rq1, rq2, rq3, red, normal });
      }).catch(failed);
    } else if (selectedRun && runsState.kind === "ready") {
      // Responses from a previous route or selected run cannot update the current screen.
      if (view === "Run Detail") {
        void Promise.all([
          getJson<unknown>("/runs/" + selectedRun),
          getJson<RunScores>("/runs/" + selectedRun + "/scores"),
        ]).then(([detail, nextScores]) => {
          if (active) { setPayload(detail); setScores(nextScores); }
        }).catch(failed);
      } else if (view === "Findings") {
        void getJson<unknown>("/runs/" + selectedRun + "/findings")
          .then(data => { if (active) setPayload(data); }).catch(failed);
      } else if (view === "Patch Verification") {
        void getJson<PatchVerification>("/runs/" + selectedRun + "/patch-verification")
          .then(data => { if (active) setPatches(data); }).catch(failed);
      } else if (view === "Audit") {
        void getJson<unknown>("/runs/" + selectedRun + "/audit")
          .then(data => { if (active) setPayload(data); }).catch(failed);
      }
    }
    return () => { active = false; };
  }, [view, selectedRun, runsState.kind]);

  const selected = useMemo(
    () => runs.find((run) => run.run_id === selectedRun) ?? null,
    [runs, selectedRun],
  );

  const inRunContext = view !== null && ["Runs", "Run Detail", "Findings", "Patch Verification", "Audit"].includes(view);
  const related = route.section === "Reports" ? [
    ["Stored runs", `${BASE_PATH}/reports/runs`],
    ["Run detail", `${BASE_PATH}/reports/run-detail`],
    ["Development evidence", `${BASE_PATH}/reports/development-evidence`],
    ["Metrics", `${BASE_PATH}/reports/metrics`],
    ["Audit", `${BASE_PATH}/reports/audit`],
  ] : route.section === "Remediation" ? [
    ["Trusted preview", `${BASE_PATH}/remediation`],
    ["Patch verification", `${BASE_PATH}/remediation/patch-verification`],
  ] : [];

  return (
    <>
      <a className="skip-to-content" href="#main-content">Skip to main content</a>
      <div className="mobile-bar">
        <span className="mobile-brand"><MarsMark className="mobile-mark" /> <span>MARS <small>SECURITY PLATFORM</small></span></span>
        <button ref={menuToggle} className="menu-button" type="button" aria-controls="mars-navigation"
          aria-expanded={menuOpen} onClick={() => setMenuOpen((open) => !open)}>
          {menuOpen ? "Close menu" : "Menu"}
        </button>
      </div>
      {menuOpen && <button type="button" className="menu-backdrop" aria-label="Close navigation menu"
        onClick={() => { setMenuOpen(false); menuToggle.current?.focus(); }} />}
      <div className="shell">
        <aside className={`sidebar${menuOpen ? " menu-open" : ""}`} id="mars-navigation"
          role={menuOpen ? "dialog" : undefined} aria-modal={menuOpen ? true : undefined}
          aria-label={menuOpen ? "Navigation menu" : undefined}>
          <div className="sidebar-brand">
            <MarsMark className="brand-mark" />
            <div className="brand-type"><h1>MARS</h1><p>Security workspace</p></div>
          </div>
          <div className="sidebar-workspace-label">WORKSPACE</div>
          <nav aria-label="Primary navigation" ref={navigation}>
            {primaryRoutes.filter(item => item.section !== "System").map((item) => (
              <a key={item.path} href={item.path} className={route.section === item.section ? "nav active" : "nav"}
                aria-current={route.section === item.section ? "page" : undefined}
                onClick={(event) => followLink(event, item.path)}>
                <NavIcon name={item.section!} /><span>{item.title}</span>
                {route.section === item.section && <span className="nav-indicator" aria-hidden="true" />}
              </a>
            ))}
          </nav>

          {inRunContext && runsState.kind === "ready" && runs.length > 0 && (
            <div className="run-picker">
              <label htmlFor="run">Selected stored run</label>
              <select id="run" value={selectedRun} onChange={(event) => setSelectedRun(event.target.value)}>
                {runs.map((run) => <option key={run.run_id} value={run.run_id}>{run.run_id}</option>)}
              </select>
              {selected && <span className={`status ${selected.status}`}>{selected.status}</span>}
            </div>
          )}
          <div className="sidebar-footer">
            <a href="/dashboard/system" className={route.section === "System" ? "sidebar-system active" : "sidebar-system"}
              aria-current={route.section === "System" ? "page" : undefined}
              onClick={event => followLink(event, "/dashboard/system")}>
              <NavIcon name="System" /><span>System</span>
            </a>
          </div>
        </aside>
        <main id="main-content" tabIndex={-1} aria-hidden={menuOpen ? true : undefined}>
          <div className="utility-bar">
            <span className="utility-path">Workspace <span className="utility-separator">/</span> {route.section ?? "Page"}</span>
            <button type="button" className="theme-toggle"
              aria-label={theme === "light" ? "Switch to dark mode" : "Switch to light mode"}
              aria-pressed={theme === "dark"} onClick={() => setTheme(current => current === "light" ? "dark" : "light")}>
              <span aria-hidden="true">{theme === "light" ? "◐" : "☀"}</span>
              {theme === "light" ? "Dark mode" : "Light mode"}
            </button>
          </div>
          <header className="page-header">
            <div>
              <h2>{route.title === "Overview" ? "Workspace overview" : route.title}</h2>
              <p className="page-description">{({
                Overview: "Your security workspace at a glance.",
                Assessments: "Review registered assessment scenarios.",
                Findings: "Explore findings from saved assessment runs.",
                Remediation: "Review and prepare trusted fixes.",
                Reports: "Saved runs, evidence and reports.",
                System: "Services, configuration and runtime status.",
              } as Record<string, string>)[route.section ?? ""] ?? "Workspace"}</p>
            </div>
            {view === "Trusted Preview" && <span className="safety-badge">Preview only</span>}
          </header>
          {related.length > 0 && <nav className="section-links" aria-label={`${route.section} views`}>
            {related.map(([title, path]) => <a key={path} href={path}
              className={route.path === path ? "subnav active" : "subnav"}
              aria-current={route.path === path ? "page" : undefined}
              onClick={(event) => followLink(event, path)}>{title}</a>)}
          </nav>}
          {error && view !== "Overview" && <Notice title="This view could not load" tone="danger">{error}</Notice>}
          {route.notFound && <section className="panel"><h3>Page not found</h3>
            <p className="muted">This MARS page does not exist. No operation was started.</p>
            <a href={`${BASE_PATH}/`} onClick={(event) => followLink(event, `${BASE_PATH}/`)}>Return to overview</a>
          </section>}
          {route.section === "Assessments" && <AssessmentsPanel />}
          {view === "Overview" && <OverviewPanel state={overviewState} />}
          {view === "Runs" && <RunsPanel state={runsState} selectedRunId={selectedRun} onSelect={(id) => { setSelectedRun(id); navigate(`${BASE_PATH}/reports/run-detail`); }} />}
          {view === "Run Detail" && (selectedRun && runsState.kind === "ready" ? <RunDetailPanel payload={payload} scores={scores} /> : <EmptyStoredRuns state={runsState} />)}
          {view === "Findings" && (selectedRun ? <JsonPanel value={payload} /> : <EmptyStoredRuns state={runsState} />)}
          {view === "Patch Verification" && (selectedRun ? <PatchPanel value={patches} /> : <EmptyStoredRuns state={runsState} />)}
          {view === "Metrics" && <JsonPanel value={payload} />}
          {view === "Audit" && (selectedRun ? <JsonPanel value={payload} /> : <EmptyStoredRuns state={runsState} />)}
          {view === "Development Evidence" && <DevelopmentEvidencePanel evidence={development} />}
          {view === "Trusted Preview" && <TrustedPreviewPanel />}
          {view === "Operator Status" && <OperatorStatusPanel />}
        </main>
      </div>
    </>
  );
}

function EmptyStoredRuns({ state }: { state: RunsState }) {
  const loading = state.kind === "loading";
  const unavailable = state.kind === "unavailable";
  return <section className="panel mars-empty">
    <span className="mars-empty-icon" aria-hidden="true">▤</span>
    <div><h3>{loading ? "Loading run history" : unavailable ? "Run history unavailable" : "Select a run to continue"}</h3>
      <p>{loading ? "Checking your local run records…" :
        unavailable ? "The local run database could not be reached. Saved findings cannot be displayed." :
        "Choose a stored run in Reports to see its available evidence."}</p>
      <a href="/dashboard/reports">Go to reports <span aria-hidden="true">↗</span></a>
    </div>
  </section>;
}

export function RunsPanel({ state, onSelect, selectedRunId }: {
  state: RunsState; onSelect: (id: string) => void; selectedRunId?: string;
}) {
  return <section className="panel">
    <div className="overview-recent-head"><h3>Stored runs</h3>
      {state.kind === "ready" && <span className="section-count">{state.runs.length} records</span>}</div>
    {state.kind === "loading" ? <LoadingState label="Loading stored run list…" /> :
      state.kind === "unavailable" ? <div className="mars-empty">
        <span className="mars-empty-icon" aria-hidden="true">▤</span>
        <div><h3>Run history unavailable</h3>
          <p>Stored run database unavailable. Run records could not be read, so no totals are shown.</p>
        </div>
      </div> : <RunTable runs={state.runs} onSelect={onSelect} selectedRunId={selectedRunId} />}
  </section>;
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
  if (!value) return <section className="panel"><LoadingState label="Loading stored patch evidence…" /></section>;
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
      {value === null ? <LoadingState label="Loading stored evidence…" /> : <pre className="json">{JSON.stringify(value, null, 2)}</pre>}
    </section>
  );
}

export function DevelopmentEvidencePanel({ evidence }: { evidence: DevelopmentEvidence | null }) {
  if (!evidence) return <section className="panel"><LoadingState label="Loading pinned development evidence…" /></section>;

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
          Preview a registered remediation before applying any changes.
          This action only prepares a diff and does not modify the application.
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
          <ActionButton disabled={!selected || busy} onClick={prepare}>
            {busy ? "Preparing…" : "Prepare trusted preview"}
          </ActionButton>
        </div>
        {selected ? (
          <p className="muted">
            Test: {selected.registered_test}. Risk: {selected.vector}.
            Remediation: {selected.remediation}.
          </p>
        ) : <p className="muted">No approved scenarios loaded. Preview is unavailable.</p>}
        {error && <Notice title="Operation unavailable" tone="danger">{error}</Notice>}
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
      <p className="muted">Additional operator controls are available in the <a href="/">original console</a>.</p>
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
  const [selectedFile, setSelectedFile] = useState("");
  const [modelName, setModelName] = useState("local-security-model");
  const [pending, setPending] = useState(false);
  const [operationNotice, setOperationNotice] = useState("");

  async function operate(action: "load" | "unload") {
    if (pending || !result) return;
    if (action === "load" && !result.inventory.models.some(file => file.filename === selectedFile)) return;
    const confirmation = action === "load"
      ? "Start local model " + selectedFile + "? This uses CPU and memory on this machine."
      : "Stop the running local model session?";
    if (!window.confirm(confirmation)) return;
    setPending(true);
    setOperationNotice("");
    try {
      if (action === "load") await startLocalModel(selectedFile, modelName.trim());
      else await stopLocalModel();
      setOperationNotice(action === "load" ? "Model launch requested. Check status for readiness." : "Model stop requested.");
      refresh(n => n + 1);
    } catch (reason) {
      setOperationNotice("Operation refused: " + String(reason));
    } finally { setPending(false); }
  }

  useEffect(() => {
    let active = true;
    setResult(null);
    setError("");
    Promise.all([
      getConsoleJson<Runtime>("/status"),
      getConsoleJson<Inventory>("/models/local"),
    ]).then(([runtime, inventory]) => {
      if (active) {
        setResult({ runtime, inventory });
        setSelectedFile(current => inventory.models.some(file => file.filename === current)
          ? current : (inventory.models[0]?.filename ?? ""));
      }
    }).catch(() => {
      if (active) setError("Local runtime status unavailable. No model or research state has been verified.");
    });
    return () => { active = false; };
  }, [version]);

  return <div className="stack">
    <section className="panel">
      <div className="runtime-heading">
        <div>
          <h3>Runtime status</h3>
          <p className="muted">Current state reported by the local service.</p>
        </div>
        <ActionButton variant="secondary" className="runtime-refresh" onClick={() => refresh(n => n + 1)}>
          Refresh status
        </ActionButton>
      </div>
      {error && <Notice title="Operation unavailable" tone="danger">{error}</Notice>}
      {!result && !error && <LoadingState label="Checking local runtime…" />}
      {result && <dl className="runtime-rows" aria-label="Current system safeguards">
        <div><dt>Model process</dt><dd>{result.runtime.model.state}</dd>
          <small>Model execution status</small></div>
        <div><dt>Research experience mode</dt><dd>{result.runtime.experience_mode}</dd>
          <small>Research runs require separate approval</small></div>
        <div><dt>Execution scope</dt><dd>{result.runtime.execution_mode}</dd>
          <small>Target: {result.runtime.target}</small></div>
        <div><dt>Final study qualification</dt><dd>{result.runtime.model.final_research_ready === true &&
          result.runtime.rq1_final_runs_verified_here !== null &&
          result.runtime.rq2_final_observations_verified_here !== null
            ? "Reported; independent review required" : "Not verified"}</dd>
          <small>Independent validation required</small></div>
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
      <p className="muted">Available files are not automatically loaded or research-approved.</p>
      <div className="model-operations">
        <div><label htmlFor="model-file">Model file</label>
          <select id="model-file" value={selectedFile} onChange={event => setSelectedFile(event.target.value)}
            disabled={!result.inventory.models.length || pending}>
            {!result.inventory.models.length && <option value="">No GGUF available</option>}
            {result.inventory.models.map(file => <option key={file.filename} value={file.filename}>{file.filename}</option>)}
          </select>
        </div>
        <div><label htmlFor="model-identifier">Model identifier</label>
          <input id="model-identifier" value={modelName} maxLength={128}
            onChange={event => setModelName(event.target.value)} disabled={pending} />
        </div>
        <div className="model-operation-buttons">
          <ActionButton disabled={pending || !selectedFile || !modelName.trim()}
            onClick={() => void operate("load")}>{pending ? "Working…" : "Load model"}</ActionButton>
          <ActionButton variant="secondary" disabled={pending || result.runtime.model.state === "unloaded"}
            onClick={() => void operate("unload")}>Unload model</ActionButton>
        </div>
      </div>
      {operationNotice && <p className="model-operation-feedback" role="status">{operationNotice}</p>}
    </section>}
    <p className="muted">Other registered actions will be migrated from the <a href="/">original operator console</a>.</p>
  </div>;
}
