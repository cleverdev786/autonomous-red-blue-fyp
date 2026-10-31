"use strict";
const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const path = require("node:path");
const { createRequire } = require("node:module");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function compile(entry, load = createRequire(path.resolve("package.json"))) {
  const built = esbuild.buildSync({
    entryPoints: [entry], bundle: true, platform: "node", format: "cjs",
    packages: "external", write: false, jsx: "automatic",
    define: { "import.meta.env.VITE_API_BASE_URL": "undefined" },
  });
  const compiled = { exports: {} };
  new Function("module", "exports", "require", built.outputFiles[0].text)(
    compiled, compiled.exports, load,
  );
  return compiled.exports;
}

const redApi = compile("src/red/api.ts");
const preference = compile("src/red/modePreference.ts");
const redUi = compile("src/red/NewAssessmentView.tsx");
const response = (data, status = 200) => new Response(JSON.stringify(data), {
  status, headers: { "content-type": "application/json" },
});
const target = {
  target_id: "vulnerable-store", compatibility: "supported",
  supported_classes: ["path_traversal", "sql_injection", "xss"],
  limitations: ["unauthenticated_only"],
  standard_budget: { profile: "standard", max_http_requests: 24,
    max_crawl_requests: 12, max_tests: 3, max_runtime_seconds: 180,
    max_parallel_operations: 1, max_depth: 2, max_retries: 0,
    max_cpu_cores: 0.5, max_memory_mb: 512 },
};

(async () => {
  const storage = new Map();
  global.window = { localStorage: {
    getItem: key => storage.get(key) ?? null,
    setItem: (key, value) => storage.set(key, value),
  } };
  assert.equal(preference.loadRememberedRedMode(), "manual");
  preference.rememberRedMode("autonomous");
  assert.equal(preference.loadRememberedRedMode(), "autonomous");
  storage.set("mars-red-mode", "forged");
  assert.equal(preference.loadRememberedRedMode(), "manual");

  const requests = [];
  let cancelStatus = "cancelled";
  global.fetch = async (url, options = {}) => {
    requests.push({ url: String(url), options });
    if (url === "/api/red/operator/csrf") return response({ csrf_token: "csrf-t29" });
    if (url === "/api/red/assessments") return response({ assessment_id: "assessment-t29",
      request_id: "create-t29", status: "awaiting_authorization", job_ids: [] }, 201);
    if (String(url).endsWith("/authorize")) return response({ assessment_id: "assessment-t29",
      request_id: "authorize-t29", status: "queued", job_ids: [] }, 202);
    if (String(url).endsWith("/start")) return response({ assessment_id: "assessment-t29",
      request_id: "start-t29", status: "queued", job_ids: ["job-t29"] }, 202);
    if (String(url).endsWith("/cancel")) return response({ assessment_id: "assessment-t29",
      request_id: "cancel-t29", status: cancelStatus, job_ids: [] }, 202);
    throw new Error("unexpected URL " + url);
  };

  const created = await redApi.createRedAssessment("operator-token", {
    requestId: "create-t29", targetId: "vulnerable-store", mode: "autonomous",
    approvalId: "approval-t29",
  });
  assert.equal(created.status, "awaiting_authorization");
  assert(!requests.some(item => item.url.endsWith("/start")));
  await redApi.authorizeRedAssessment("operator-token", "assessment-t29", {
    requestId: "authorize-t29", approvalId: "approval-t29",
  });
  assert(!requests.some(item => item.url.endsWith("/start")));
  await redApi.startRedAssessment("operator-token", "assessment-t29", "start-t29");
  await redApi.cancelRedAssessment("operator-token", "assessment-t29", "cancel-t29");
  const writes = requests.filter(item => item.options.method === "POST");
  assert.deepEqual(writes.map(item => item.url), [
    "/api/red/assessments", "/api/red/assessments/assessment-t29/authorize",
    "/api/red/assessments/assessment-t29/start",
    "/api/red/assessments/assessment-t29/cancel",
  ]);
  assert(writes.every(item => !("Authorization" in item.options.headers) &&
    item.options.headers["X-Red-CSRF"] === "csrf-t29" &&
    item.options.headers["Content-Type"] === "application/json"));

  const base = { targets: [target], targetId: "vulnerable-store", mode: "autonomous",
    busy: false, error: null, assessmentId: null, onTargetChange() {}, onModeChange() {},
    onReview() {}, onCreate() {}, onAuthorize() {}, onStart() {}, onCancel() {}, onEdit() {},
    onReset() {} };
  const setup = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    { ...base, phase: "setup" }));
  const reviewButton = element => {
    if (!element || typeof element !== "object") return null;
    if (element.props?.children === "Review Standard scope") return element;
    for (const child of React.Children.toArray(element.props?.children)) {
      const found = reviewButton(child);
      if (found) return found;
    }
    return null;
  };
  let reviews = 0;
  const selectedReview = reviewButton(redUi.NewAssessmentView({...base,phase:"setup",onReview(){reviews++;}}));
  assert.equal(selectedReview.props.type, "button", "Scope review must not depend on hidden native select validation");
  selectedReview.props.onClick();
  assert.equal(reviews, 1);
  const missingReview = reviewButton(redUi.NewAssessmentView({...base,targetId:"",phase:"setup",onReview(){reviews++;}}));
  missingReview.props.onClick();
  assert.equal(reviews, 1, "A missing registered target must not reach scope review");
  assert(setup.includes("New assessment") && setup.includes("Review Standard scope"));
  assert(setup.includes('aria-describedby="red-mode-help"') && setup.includes("within the scope you authorize"));
  const manualSetup = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    {...base, phase:"setup", mode:"manual"}));
  assert(manualSetup.includes("run each stage yourself after authorizing the fixed scope"));
  assert(!setup.includes("Start autonomous assessment"));
  const review = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    { ...base, phase: "review" }));
  for (const text of ["Fixed authorization scope", "SQL injection", "24 HTTP requests",
    "3 registered tests", "2 levels", "Retries", "Edit target or mode",
    "Create authorization draft"]) assert(review.includes(text));
  assert(!review.includes("Mode locked"));
  for (const heading of ["Requests and tests", "Runtime and resources"]) assert(review.includes(heading));
  const awaiting = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    { ...base, phase: "awaiting_authorization", assessmentId: "assessment-t29",
      error: "Authorization was rejected by the server." }));
  assert(awaiting.includes("Authorize and start assessment") && awaiting.includes("Cancel assessment") &&
    awaiting.includes("Authorization was rejected by the server."));
  const authorized = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    { ...base, phase: "authorized", assessmentId: "assessment-t29" }));
  assert(authorized.includes("Start autonomous assessment") && authorized.includes("Mode locked"));
  const active = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    { ...base, phase: "active", assessmentId: "assessment-t29" }));
  assert(active.includes("Assessment queued") && active.includes("Cancel assessment"));
  const recovered = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    { ...base, phase: "recovered", assessmentId: "assessment-t29" }));
  assert(recovered.includes("Active assessment recovered") && recovered.includes("Cancel assessment"));
  const pending = renderToStaticMarkup(React.createElement(redUi.NewAssessmentView,
    { ...base, phase: "cancellation_pending", assessmentId: "assessment-t29" }));
  assert(pending.includes("Cancellation requested") && !pending.includes("Assessment cancelled"));

  const hookState = [];
  let hookCursor = 0;
  const fakeReact = {
    useRef(initial) {
      const index = hookCursor++;
      if (!(index in hookState)) hookState[index] = { current: initial };
      return hookState[index];
    },
    useState(initial) {
      const index = hookCursor++;
      if (!(index in hookState)) hookState[index] = typeof initial === "function" ? initial() : initial;
      return [hookState[index], value => {
        hookState[index] = typeof value === "function" ? value(hookState[index]) : value;
      }];
    },
    useEffect(effect) { effect(); },
  };
  const normalRequire = createRequire(path.resolve("package.json"));
  const redController = compile("src/red/NewAssessment.tsx",
    id => id === "react" ? fakeReact : normalRequire(id));
  const opened = [];
  const controllerProps = { token: "operator-token", targets: [target], assessments: [],
    onChanged() {}, onOpened(id) { opened.push(id); } };
  const renderController = () => {
    hookCursor = 0;
    return redController.NewAssessment(controllerProps).props;
  };
  const settle = () => new Promise(resolve => setImmediate(() => setImmediate(resolve)));
  requests.length = 0;
  let controls = renderController();
  assert.equal(requests.filter(item => item.options.method === "POST").length, 0);
  controls.onTargetChange("vulnerable-store");
  controls.onModeChange("autonomous");
  controls = renderController();
  controls.onReview();
  controls = renderController();
  assert.equal(controls.phase, "review");
  assert.equal(requests.filter(item => item.options.method === "POST").length, 0);
  controls.onCreate();
  await settle();
  controls = renderController();
  assert.equal(controls.phase, "awaiting_authorization");
  assert.deepEqual(requests.filter(item => item.options.method === "POST").map(item => item.url),
    ["/api/red/assessments"]);
  controls.onAuthorize();
  controls.onAuthorize();
  await settle();
  controls = renderController();
  assert.equal(controls.phase, "active");
  assert.deepEqual(opened, ["assessment-t29"], "Navigate once after acknowledged start");
  assert(requests.some(item => item.url.endsWith("/start")));
  assert.equal(requests.filter(item => item.url.endsWith("/start")).length, 1,
    "Double authorization click must enqueue only once");
  cancelStatus = "cancellation_requested";
  controls.onCancel();
  await settle();
  controls = renderController();
  assert.equal(controls.phase, "cancellation_pending");
  hookState.length = 0;
  controllerProps.assessments.push({ assessment_id: "persisted-active",
    target_id: "vulnerable-store", mode: "autonomous", profile: "standard", status: "running",
    workflow_complete: false, coverage: {}, current_plan_version: null,
    current_surface_revision: null, stage_statuses: {} });
  renderController();
  controls = renderController();
  assert.equal(controls.phase, "setup", "New assessment must not be hijacked by an existing run");
  assert.equal(controls.assessmentId, null);
  hookState.length = 0;
  controllerProps.assessments[0].status = "queued";
  requests.length = 0;
  renderController();
  renderController();
  renderController();
  await settle();
  assert.equal(requests.filter(item => item.options.method === "POST").length, 0,
    "Recovering a queued assessment must never dispatch start");
  console.log("T29 deliberate creation, remembered mode, authorization and start lock: PASS");
})().catch(error => { console.error(error); process.exitCode = 1; });
