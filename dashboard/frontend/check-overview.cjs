const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { createRequire } = require("node:module");
const path = require("node:path");
const built = esbuild.buildSync({entryPoints:["src/overview/RedOverview.tsx"],bundle:true,
  platform:"node",format:"cjs",packages:"external",write:false,jsx:"automatic",
  define:{"import.meta.env.VITE_API_BASE_URL":"undefined"}});
const mod = {exports:{}};
new Function("module","exports","require",built.outputFiles[0].text)(mod,mod.exports,createRequire(path.resolve("package.json")));
const render = state => renderToStaticMarkup(React.createElement(mod.exports.RedOverviewView,{state,onRetry(){}}));
assert.match(render({kind:"loading"}),/Checking Red assessment data/);
assert.match(render({kind:"error",denied:false}),/Red service unavailable.*Retry Red data/s);
assert.match(render({kind:"error",denied:true}),/Session access required.*Sign in again/s);
const summary = {confirmed_findings:4,tested:2,eligible:3,active_assessments:1,coverage_gaps:1};
const ready = {kind:"ready",summary,targets:[],assessments:[]};
const empty = render(ready);
assert.match(empty,/No registered targets available/);
assert.match(empty,/1 active assessment/);
assert.doesNotMatch(empty,/tools coming later|Browse assessments/);
for (const status of ["running","completed_with_limitations","cancelled","blocked"]) {
  const html = render({...ready,targets:[{target_id:"local-target"}],assessments:[
    {assessment_id:"assessment-example",target_id:"<script>unsafe</script>",mode:"manual",status}]});
  assert(!html.includes("<script>unsafe</script>"));
  assert.match(html,/1 registered target/);
  assert.match(html,/href="\/dashboard\/red-team"/);
}
console.log("Overview compact team cards, unavailable, denied, empty and safe navigation: PASS");
