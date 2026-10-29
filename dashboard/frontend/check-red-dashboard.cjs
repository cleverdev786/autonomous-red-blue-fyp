"use strict";
const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const path = require("node:path");
const { createRequire } = require("node:module");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function compile(entry) {
  const built = esbuild.buildSync({
    entryPoints: [entry], bundle: true, platform: "node", format: "cjs",
    packages: "external", write: false, jsx: "automatic",
    define: { "import.meta.env.VITE_API_BASE_URL": "undefined" },
  });
  const compiled = { exports: {} };
  new Function("module", "exports", "require", built.outputFiles[0].text)(
    compiled, compiled.exports, createRequire(path.resolve("package.json")),
  );
  return compiled.exports;
}

const redApi = compile("src/red/api.ts");
const redUi = compile("src/red/RedDashboardView.tsx");
const response = data => new Response(JSON.stringify(data), {
  status: 200, headers: { "content-type": "application/json" },
});
const pagination = (total, offset = 0) => ({ offset, limit: 25, total });
const summary = {
  target_id: "vulnerable-store", assessment_count: 1,
  confirmed_findings: 2, suspected_findings: 1, tested: 3, eligible: 4,
  active_assessments: 1, queued_assessments: 1, active_stages: 2,
  coverage_gaps: 1,
};
const assessment = {
  assessment_id: "as-dashboard", target_id: "vulnerable-store",
  mode: "autonomous", profile: "standard", status: "running",
  workflow_complete: false,
  coverage: { eligible: 4, executed: 3, completed: 2, blocked: 0,
    skipped: 1, observed_candidate_gaps: 1, unresolved_observations: 1,
    coverage_complete: false },
  current_plan_version: "plan-current", current_surface_revision: "surface-current",
  stage_statuses: { reconnaissance: "succeeded", planning: "succeeded",
    execution: "running", verification: "queued" },
};

(async () => {
  const requests = [];
  global.fetch = async (url, options) => {
    requests.push({ url, options });
    if (url === "/api/red/targets?offset=0&limit=200") return response({
      items: [{ target_id: "vulnerable-store", compatibility: "supported",
        supported_classes: ["path_traversal", "sql_injection", "xss"],
        limitations: ["unauthenticated_only"], standard_budget: {
          profile: "standard", max_http_requests: 24, max_crawl_requests: 12,
          max_tests: 3, max_runtime_seconds: 180, max_parallel_operations: 1,
          max_depth: 2, max_retries: 0, max_cpu_cores: 0.5, max_memory_mb: 512,
        } }], pagination: pagination(1),
    });
    if (String(url).startsWith("/api/red/summary?")) return response(summary);
    if (String(url).startsWith("/api/red/assessments?")) return response({
      items: [assessment], pagination: pagination(1),
    });
    throw new Error("unexpected URL " + url);
  };

  const targets = await redApi.listRedTargets("operator-token");
  const data = await redApi.loadRedDashboard("operator-token", {
    targetId: "vulnerable-store", status: "running", offset: 25,
  });
  assert.equal(targets.items[0].target_id, "vulnerable-store");
  assert.equal(data.summary.confirmed_findings, 2);
  assert.equal(data.assessments.items[0].status, "running");
  assert(requests.some(item => item.url.includes("target_id=vulnerable-store") &&
    item.url.includes("status=running")));
  assert(requests.some(item => item.url.includes("offset=25") && item.url.includes("limit=25")));
  assert(requests.every(item => item.options.headers.Authorization === "Bearer operator-token"));

  global.fetch = async () => response({ ...summary, confirmed_findings: "2" });
  await assert.rejects(
    redApi.loadRedDashboard("operator-token", { targetId: "", status: "" }),
    error => error.name === "ApiRequestError" && error.kind === "schema",
  );

  const html = renderToStaticMarkup(React.createElement(redUi.RedDashboardView, {
    targets: targets.items, targetId: "vulnerable-store", status: "running",
    state: { kind: "ready", summary, assessments: [assessment], total: 30,
      offset: 0, limit: 25 },
    onTargetChange() {}, onStatusChange() {}, onRefresh() {},
    onPageChange() {}, onDisconnect() {},
  }));
  for (const label of ["Verified findings", "Endpoint coverage", "Active assessments",
    "Agent activity", "All Targets", "Assessment status", "Assessment history",
    "Change credential", "Next"]) {
    assert(html.includes(label), "missing dashboard label: " + label);
  }
  assert(html.includes("2 confirmed") && html.includes("3 / 4") && html.includes("as-dashboard"));
  assert(!html.includes("Page content will be added later"));
  assert.match(html, /<table[^>]*>.*<th scope="col">Assessment<\/th>/s);
  console.log("T28 Red dashboard API contracts, filters, metrics and history: PASS");
})().catch(error => { console.error(error); process.exitCode = 1; });
