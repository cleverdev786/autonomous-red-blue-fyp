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
  assessment_id: "as-dashboard", assessment_number:73, target_id: "vulnerable-store",
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
  assert(requests.some(item => item.url.includes("offset=25") && item.url.includes("limit=10")));
  assert(requests.every(item => !("Authorization" in item.options.headers)));

  requests.length = 0;
  await redApi.listRedAssessments("", {targetId:"",status:"",query:"comp",limit:10});
  assert.equal(requests.length,1,"table input must not refetch targets or dashboard metrics");
  assert(requests[0].url.includes("q=comp"));
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
    onPageChange() {},
  }));
  for (const label of ["Verified findings", "Tests executed", "Active assessments",
    "Agent activity", "Target", "Assessment status", "Assessment history",
    "Next"]) {
    assert(html.includes(label), "missing dashboard label: " + label);
  }
  assert(html.includes("2 confirmed") && html.includes("3 / 4") && html.includes("as-dashboard"));
  assert(!html.includes("Endpoint coverage"), "test totals must not claim endpoint coverage");
  assert(html.includes("executed / eligible tests"));
  assert(html.includes("1 open coverage gap") && !html.includes("1 open coverage gaps"));
  assert(!html.includes("Page content will be added later"));
  assert.match(html, /<th[^>]*aria-sort="none"[^>]*>Assessment/s);
  assert(html.includes('type="search"') && html.includes('aria-live="polite"'));
  assert(html.includes('aria-label="Rows per page"'));
  assert(html.includes('<h2 id="red-history-title"'), "history must not skip heading level 2");
  assert.equal(redUi.canDeleteHistory(assessment), false);
  assert.equal(redUi.canDeleteHistory({...assessment,status:"completed",stage_statuses:{}}), true);
  assert.equal(redUi.canDeleteHistory({...assessment,status:"completed"}), false);
  const deletableHtml = renderToStaticMarkup(React.createElement(redUi.RedDashboardView, {
    targets:targets.items,targetId:"",status:"",state:{kind:"ready",summary,assessments:[{...assessment,status:"cancelled",stage_statuses:{}}],total:1,offset:0,limit:25},
    onTargetChange(){},onStatusChange(){},onRefresh(){},onPageChange(){},onInspect(){},onDelete:async()=>{},
  }));
  assert(!deletableHtml.includes("Delete selected") && !deletableHtml.includes('aria-label="Delete Assessment'));
  assert(deletableHtml.includes("Assessment 73") && !deletableHtml.includes("List position"));
  assert(deletableHtml.includes('aria-label="Select all deletable records on this page"'));
  let deletion;
  global.fetch=async(url,options)=>{
    if(String(url).endsWith("/csrf")) return response({csrf_token:"csrf-test"});
    deletion={url,options}; return response({assessment_ids:JSON.parse(options.body).assessment_ids});
  };
  await redApi.deleteRedHistory("",["as-terminal"]);
  assert.equal(deletion.url,"/api/red/assessments/delete-history");
  assert.equal(deletion.options.headers["X-Red-CSRF"],"csrf-test");
  assert.deepEqual(JSON.parse(deletion.options.body),{assessment_ids:["as-terminal"]});
  await redApi.deleteRedHistory("",["as-terminal","as-terminal-2"]);
  assert.deepEqual(JSON.parse(deletion.options.body),{assessment_ids:["as-terminal","as-terminal-2"]});
  await assert.rejects(redApi.deleteRedHistory("",[]));
  assert(html.includes('role="combobox"') && html.includes('aria-labelledby="target-filter-label"'));
  const searchHtml = renderToStaticMarkup(React.createElement(redUi.RedDashboardView, {
    targets:[],targetId:"",status:"",state:{kind:"ready",summary,assessments:[assessment],total:1,offset:0,limit:10},
    search:"RUN",query:"run",sort:{key:"status",direction:"desc"},
    onTargetChange(){},onStatusChange(){},onRefresh(){},onPageChange(){},onInspect(){},
  }));
  assert(searchHtml.includes("<mark>Run</mark>ning"));
  assert(searchHtml.includes('aria-sort="descending"'));
  assert.equal((searchHtml.match(/aria-sort="none"/g)||[]).length,5);
  const emptyHtml = renderToStaticMarkup(React.createElement(redUi.RedDashboardView, {
    targets:[],targetId:"",status:"",state:{kind:"ready",summary,assessments:[],total:0,offset:0,limit:10},query:"<missing>",
    onTargetChange(){},onStatusChange(){},onRefresh(){},onPageChange(){},onInspect(){},
  }));
  assert(emptyHtml.includes("No results match") && emptyHtml.includes("&lt;missing&gt;"));
  assert(emptyHtml.includes('aria-current="page"') && emptyHtml.includes('aria-label="Next page" disabled'));
  const table = compile("src/red/historyTable.ts");
  assert(table.compareTableValues("Target 2", "target 10", "string") < 0);
  assert.equal(table.compareTableValues(2, 10, "number"), -8);
  assert(table.compareTableValues("2026-01-01", "2025-01-01", "date") > 0);
  const rows = [{...assessment, assessment_number:2}, {...assessment, assessment_number:1}];
  assert.deepEqual(table.sortHistoryRows(rows, {key:"assessment",direction:"asc"}).map(x=>x.assessment_number), [1,2]);
  assert.deepEqual(table.sortHistoryRows(rows, {key:"target",direction:"desc"}), rows);
  assert.deepEqual(table.historyPageNumbers(5,10), [1,"…",4,5,6,"…",10]);
  assert.deepEqual(table.historyPageNumbers(1,1), [1]);
  console.log("T28 Red dashboard API contracts, filters, metrics and history: PASS");
})().catch(error => { console.error(error); process.exitCode = 1; });
