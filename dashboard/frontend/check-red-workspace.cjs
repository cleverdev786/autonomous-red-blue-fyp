"use strict";
const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const path = require("node:path");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function compile(entry) {
  const built = esbuild.buildSync({ entryPoints:[entry], bundle:true, platform:"node",
    format:"cjs", packages:"external", write:false, jsx:"automatic",
    define:{ "import.meta.env.VITE_API_BASE_URL":"undefined" } });
  const mod = { exports:{} };
  new Function("module","exports","require",built.outputFiles[0].text)(
    mod, mod.exports, createRequire(path.resolve("package.json")));
  return mod.exports;
}
const api = compile("src/red/api.ts");
const ui = compile("src/red/AssessmentWorkspace.tsx");
const assessment = { assessment_id:"assessment-t30", target_id:"vulnerable-store",
  mode:"manual", profile:"standard", status:"queued", workflow_complete:false,
  coverage:{ eligible:3, executed:1, completed:1, blocked:1, skipped:1,
    observed_candidate_gaps:1, unresolved_observations:0, coverage_complete:false },
  current_plan_version:"plan-1", current_surface_revision:"surface-1",
  stage_statuses:{ reconnaissance:"succeeded", planning:"succeeded", execution:"ready", verification:"not_started" } };
const finding = { finding_id:"finding-xss", assessment_id:"assessment-t30",
  target_id:"vulnerable-store", status:"suspected", severity:"medium", category:"xss",
  route:"/search?<script>alert(1)</script>", provenance:null, reproduction_scope:null,
  has_evidence:false };
const bundle = { workspace:{ assessment,
  stages:[{ stage:"reconnaissance",status:"succeeded",plan_version:null },
    { stage:"planning",status:"succeeded",plan_version:"plan-1" },
    { stage:"execution",status:"ready",plan_version:"plan-1" },
    { stage:"verification",status:"not_started",plan_version:"plan-1" }],
  plans:[{ plan_version:"plan-1",surface_revision:"surface-1",status:"approved" }],
  candidate_count:3, planned_operation_count:1,
  finding_counts:{ suspected:1,confirmed:0,not_confirmed:0,inconclusive:0 }, coverage_gap_count:1 },
  events:[{ event_id:"event-recon",action:"stage-transition",status:"succeeded",
    stage:"reconnaissance",occurred_at:"2026-10-29T08:00:00Z" }],
  findings:[finding], findingTotal:1,
  coverage:{ assessment_id:"assessment-t30",target_id:"vulnerable-store",
    coverage:assessment.coverage,gaps:[{ gap_id:"gap-auth",status:"open",
      reason:"authentication_required",candidate_id:"candidate-1",test_id:null,
      recommendation:"Authenticated discovery remains outside this release." }],
    warnings:["unauthenticated_only_coverage"] } };

const html = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  { data:bundle,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},
    onCancel(){},token:"operator-token" }));
for (const text of ["Four bounded agents","Recon agent","Planning agent","Execution agent",
  "Verification agent","Last action","Task count","Failure state","Findings &amp; coverage",
  "authentication required","Blue Team handoff is pending"]) assert(html.includes(text), text);
assert(html.includes("Run") && html.includes("Inspect"));
assert(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;") && !html.includes("<script>alert"));
assert(html.includes("Verification requires a completed execution receipt."));
const stale = structuredClone(bundle);
stale.workspace.plans[0].status = "stale";
const staleHtml = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  { data:stale,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},
    onCancel(){},token:"operator-token" }));
assert(staleHtml.includes("Plan is stale") && staleHtml.includes("Run Planning again"));

const autonomous = structuredClone(bundle);
autonomous.workspace.assessment.mode = "autonomous";
autonomous.workspace.assessment.status = "running";
const autoHtml = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  { data:autonomous,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},
    onCancel(){},token:"operator-token" }));
assert(autoHtml.includes("Live assessment timeline") && autoHtml.includes("mode locked") &&
  autoHtml.includes("Stop assessment") && autoHtml.includes("Polling every 3 seconds"));
const source = fs.readFileSync("src/red/AssessmentWorkspace.tsx", "utf8");
const apiSource = fs.readFileSync("src/red/api.ts", "utf8");
const css = fs.readFileSync("src/product.css", "utf8");
assert(source.includes("window.setInterval") && source.includes("window.clearInterval") &&
  apiSource.includes("limit=100"));
assert(css.includes("@media(max-width:760px)") && css.includes("prefers-reduced-motion") &&
  css.includes(":focus-visible"));

const response = data => new Response(JSON.stringify(data),
  { status:200,headers:{"content-type":"application/json"} });
const requested = [];
global.fetch = async url => {
  requested.push(String(url));
  if (String(url).endsWith("/events?offset=0&limit=100")) return response({items:bundle.events,pagination:{offset:0,limit:100,total:1}});
  if (String(url).endsWith("/findings?offset=0&limit=100")) return response({items:bundle.findings,pagination:{offset:0,limit:100,total:1},coverage_gap_count:1});
  if (String(url).endsWith("/coverage")) return response(bundle.coverage);
  if (String(url).endsWith("/assessment-t30")) return response(bundle.workspace);
  throw new Error(`unexpected ${url}`);
};
(async()=>{
  const loaded = await api.loadRedWorkspace("operator-token","assessment-t30");
  assert.equal(loaded.findingTotal,1);
  assert.deepEqual(requested,[
    "/api/red/assessments/assessment-t30",
    "/api/red/assessments/assessment-t30/events?offset=0&limit=100",
    "/api/red/assessments/assessment-t30/findings?offset=0&limit=100",
    "/api/red/assessments/assessment-t30/coverage",
  ]);
  console.log("T30-T33 manual panels, autonomous timeline, findings, gaps and escaping: PASS");
})().catch(error=>{console.error(error);process.exitCode=1;});
