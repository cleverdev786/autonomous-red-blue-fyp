"use strict";
const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const { createRequire } = require("node:module");
const path = require("node:path");
const built = esbuild.buildSync({ entryPoints: ["src/routes.ts"], bundle: true, platform: "node", format: "cjs", write: false, logLevel: "silent" });
const loaded = { exports: {} };
new Function("module", "exports", "require", built.outputFiles[0].text)(loaded, loaded.exports, createRequire(path.resolve("package.json")));
const { primaryRoutes, resolveRoute, BASE_PATH } = loaded.exports;
assert.equal(primaryRoutes.length, 8);
assert.deepEqual(primaryRoutes.slice(0, 4).map(route => route.title),
  ["Overview", "Red Team", "Blue Team", "Assessments"]);
assert.deepEqual(primaryRoutes.slice(1, 3).map(route => route.path),
  ["/dashboard/red-team", "/dashboard/blue-team"]);
assert.equal(resolveRoute("/dashboard/red-team").section, "Red Team");
assert.equal(resolveRoute("/dashboard/blue-team").section, "Blue Team");
for (const route of primaryRoutes) {
  assert.deepEqual(resolveRoute(route.path), route);
  assert.deepEqual(resolveRoute(route.path + "/"), route);
}
assert.equal(resolveRoute(BASE_PATH).title, "Overview");
assert.equal(resolveRoute("/dashboard/reports/development-evidence").view, "Development Evidence");
assert.equal(resolveRoute("/dashboard/remediation/patch-verification").view, "Patch Verification");
assert.equal(resolveRoute("/dashboard/missing-page").notFound, true);
assert.equal(resolveRoute("/api/console/status").notFound, true);
console.log("MARS route resolver, including Red Team and Blue Team: PASS");
