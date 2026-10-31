"use strict";
const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const path = require("node:path");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

function compile(entry, reactOverride) {
  const built = esbuild.buildSync({ entryPoints:[entry], bundle:true, platform:"node",
    format:"cjs", packages:"external", write:false, jsx:"automatic",
    define:{ "import.meta.env.VITE_API_BASE_URL":"undefined" } });
  const mod = { exports:{} };
  new Function("module","exports","require",built.outputFiles[0].text)(
    mod, mod.exports, name => name === "react" && reactOverride ? reactOverride : createRequire(path.resolve("package.json"))(name));
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
  "authentication required","Open reports"]) assert(html.includes(text), text);
assert(html.includes("Run") && html.includes("Inspect"));
assert(html.includes('<h2 id="red-workspace-title">'), "workspace hierarchy must start below the page h1");
assert(html.includes('aria-label="Finding outcomes" tabindex="0"'), "findings overflow must be keyboard reachable");
assert(html.includes("&lt;script&gt;alert(1)&lt;/script&gt;") && !html.includes("<script>alert"));
assert(html.includes("Verification requires a completed execution receipt."));
const stale = structuredClone(bundle);
stale.workspace.plans[0].status = "stale";
const staleHtml = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  { data:stale,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},
    onCancel(){},token:"operator-token" }));
assert(staleHtml.includes("Plan is stale") && staleHtml.includes("Run Planning again"));
const changedSurface = structuredClone(bundle);
changedSurface.workspace.assessment.current_surface_revision = "new-surface";
const changedHtml = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  {data:changedSurface,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},onCancel(){},token:""}));
assert(changedHtml.includes("Execution requires one approved operation on the current plan."));
const multiple = structuredClone(bundle);
multiple.workspace.planned_operation_count = 3;
multiple.workspace.operations = [1,2,3].map(i => ({operation_id:`op-${i}`,plan_version:"plan-1",test_id:`test-${i}`,status:"approved"}));
const multipleHtml = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  {data:multiple,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},onCancel(){},token:""}));
assert(multipleHtml.includes("Registered operation for Execution agent") && !multipleHtml.includes("Execution requires one approved operation"));
multiple.workspace.operations.forEach(item => item.status = "blocked");
const deniedHtml = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  {data:multiple,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},onCancel(){},token:""}));
assert(deniedHtml.includes("Execution requires one approved operation"));
// Poll only after a completed read; terminal records never keep polling.
for (const [refreshing,status,expected] of [[true,"running",0],[false,"running",1],[false,"completed",0]]) {
  const effects = [], timers = [], updates = [];
  let hook = 0;
  const values = [{kind:"ready",data:{...bundle,workspace:{...bundle.workspace,assessment:{...assessment,status}}}},0,null,null,refreshing];
  const controller = compile("src/red/AssessmentWorkspace.tsx", {...React,
    useState: initial => [values[hook++] ?? initial, value => updates.push(value)],
    useRef: value => ({current:value}), useEffect: effect => effects.push(effect)});
  global.window = {setTimeout(fn,delay){timers.push({fn,delay});return 42;},clearTimeout(id){assert.equal(id,42);}};
  controller.AssessmentWorkspace({token:"",assessmentId:"assessment-t30",onClose(){},onChanged(){}});
  const cleanup = effects[1]();
  assert.equal(timers.length, expected);
  if(expected) { assert.equal(timers[0].delay,3000); timers[0].fn(); assert.equal(updates[0](4),5); cleanup(); }
}
delete global.window;
const completed = structuredClone(bundle);
completed.workspace.assessment.mode = "autonomous";
completed.workspace.assessment.status = "completed";
const completedHtml = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
  { data:completed,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},onCancel(){},token:"" }));
assert(completedHtml.includes("Assessment timeline") && !completedHtml.includes("Live assessment timeline"));
assert(!completedHtml.includes("stage-transition"));
assert(completedHtml.includes("Security coverage"));
for (const status of ["queued","running","failed","blocked","cancelled","stale","not_started"]) {
  const state = structuredClone(completed);
  state.workspace.stages[0].status = status;
  const output = renderToStaticMarkup(React.createElement(ui.AssessmentWorkspaceView,
    {data:state,busy:null,commandError:null,onClose(){},onRefresh(){},onRunStage(){},onCancel(){},token:""}));
  assert(output.includes(status.replaceAll("_"," ")));
}
const hash = "a".repeat(64);
const evidenceHtml = renderToStaticMarkup(React.createElement(ui.EvidenceDetail,{detail:{
  finding,operation_id:"op-1",plan_version:"plan-1",test_id:"registered-test",oracle_id:"oracle-1",
  evidence_receipt_ids:["receipt-1"],evidence:[{evidence_id:"evidence-1",receipt_id:"receipt-1",sha256:hash,content_type:"application/json"}]
}}));
for (const value of ["registered-test","receipt-1",hash,"Technical provenance"]) assert(evidenceHtml.includes(value));

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
assert(source.includes("window.setTimeout") && source.includes("window.clearTimeout") &&
  apiSource.includes("limit=100"));
assert(css.includes("@media(max-width:760px)") && css.includes("prefers-reduced-motion") &&
  css.includes(":focus-visible"));

const response = data => new Response(JSON.stringify(data),
  { status:200,headers:{"content-type":"application/json"} });
const requested = [];
global.fetch = async url => {
  requested.push(String(url));
  if (String(url).includes("/findings?offset=100&limit=100&status=suspected")) return response({items:[finding],pagination:{offset:100,limit:100,total:101},coverage_gap_count:1});
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
  const page = await api.loadRedFindingPage("", "assessment-t30", 100, "suspected");
  assert.equal(page.pagination.offset, 100);
  assert.equal(page.items[0].status, "suspected");
  assert(requested.at(-1).endsWith("offset=100&limit=100&status=suspected"));
  let commandBody;
  global.fetch = async (url, options) => {
    if (String(url).endsWith("/csrf")) return response({csrf_token:"test-csrf"});
    commandBody = JSON.parse(options.body);
    return response({assessment_id:"assessment-t30",request_id:"run-test",status:"queued",job_ids:["job-test"]});
  };
  await api.runRedStage("", "assessment-t30", "execution", "run-test", "op-2");
  assert.equal(commandBody.operation_id, "op-2");
  console.log("T30-T33 manual panels, autonomous timeline, findings, gaps and escaping: PASS");
})().catch(error=>{console.error(error);process.exitCode=1;});
