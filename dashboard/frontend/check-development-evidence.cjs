"use strict";
// Offline server-render contract. Uses Vite's existing esbuild dependency.
const assert = require("node:assert/strict");
const path = require("node:path");
const { createRequire } = require("node:module");
const esbuild = require("esbuild");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");

const built = esbuild.buildSync({
  entryPoints: ["src/App.tsx"], bundle: true, platform: "node", format: "cjs",
  packages: "external", write: false, jsx: "automatic", logLevel: "silent",
  define: { "import.meta.env.VITE_API_BASE_URL": "undefined" },
});
const loaded = { exports: {} };
new Function("module", "exports", "require", built.outputFiles[0].text)(
  loaded, loaded.exports, createRequire(path.join(process.cwd(), "package.json")),
);
const Panel = loaded.exports.DevelopmentEvidencePanel;
assert.equal(typeof Panel, "function");
const evidence = {
  red: { status: "verified_archived_red", red_evidence_verified: true,
    exploit_confirmed: true, registered_test_id: "sqli-login-bypass-001",
    red_run_id: "sql-20261015-r1" },
  blue: { status: "evidence_bound", model_origin: "q8_0_cpu_model",
    model_input_scope: "registered_steps_plus_captured_responses",
    model_decision: { classification: "sql_injection" },
    red_evidence_verified: true, source_analysis_authorized: true,
    registered_test_id: "sqli-login-bypass-001", red_run_id: "sql-20261015-r1" },
  sqli: { status: "verified_archived_patched_replay", registered_replay_verified: true,
    exploit_confirmed: false, test_id: "sqli-login-bypass-001", run_id: "sql-20261015-r2",
    legitimate_login_verified: true, search_file_verified: true },
  phase5: { status: "verified_archived_phase5_replays", replay_count: 2,
    results: {
      xss: { registered_test_id: "xss-reflection-001", run_id: "xss-20261015-r2",
        registered_replay_verified: true, baseline_exploit_confirmed: true,
        patched_exploit_confirmed: false },
      traversal: { registered_test_id: "path-traversal-private-file-001",
        run_id: "trav-20261015-r2", registered_replay_verified: true,
        baseline_exploit_confirmed: true, patched_exploit_confirmed: false },
    },
  },
};
const html = (value) => renderToStaticMarkup(React.createElement(Panel, { evidence: value }));
const verified = html(evidence);
for (const expected of [
  "Verified local-lab exploit", "Verified archived SQLi classification",
  "Verified archival handoff", "Verified exploit prevented",
  "Script marker HTML-escaped", "Private-file request blocked",
  "remains unverified", "not independent research trials",
  "/api/console/assessment/export",
]) assert(verified.includes(expected), expected);
const mismatched = html({ ...evidence, blue: { ...evidence.blue, red_run_id: "wrong-run" } });
assert(!mismatched.includes("Verified exploit prevented"));
assert(mismatched.includes("Not authorized"));
const rejected = html({ ...evidence, phase5: { ...evidence.phase5,
  results: { ...evidence.phase5.results,
    xss: { ...evidence.phase5.results.xss, patched_exploit_confirmed: true } } } });
assert(!rejected.includes("Script marker HTML-escaped"));
const escaped = html({ ...evidence, phase5: { ...evidence.phase5,
  results: { ...evidence.phase5.results,
    xss: { ...evidence.phase5.results.xss, run_id: "<script>alert(1)</script>" } } } });
assert(escaped.includes("&lt;script&gt;alert(1)&lt;/script&gt;"));
assert(!escaped.includes("<script>alert(1)</script>"));
assert(html(null).includes("Loading pinned development evidence"));
const workbench = renderToStaticMarkup(React.createElement(loaded.exports.TrustedPreviewPanel));
assert(workbench.includes("Registered vulnerability workbench"));
assert(workbench.includes("No approved scenarios loaded"));
assert(workbench.includes("Prepare trusted preview"));
assert(workbench.includes("disabled"));
assert(!workbench.includes("Load GGUF"));
assert(workbench.includes("Run offline Red → Blue verification"));
assert(!workbench.includes('href="/"'));
const runtime = renderToStaticMarkup(React.createElement(loaded.exports.OperatorStatusPanel));
assert(runtime.includes("Runtime status"));
assert(runtime.includes("Checking local runtime"));
assert(runtime.includes("Refresh status"));
assert(!runtime.includes("Model process</dt>"));
console.log("Development evidence React render: 5/5 passed; trusted preview and runtime loading contracts passed");
