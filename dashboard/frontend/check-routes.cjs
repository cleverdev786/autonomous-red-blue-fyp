"use strict";
const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const { createRequire } = require("node:module");
const path = require("node:path");
const built = esbuild.buildSync({ entryPoints: ["src/routes.ts"], bundle: true, platform: "node", format: "cjs", write: false, logLevel: "silent" });
const loaded = { exports: {} };
new Function("module", "exports", "require", built.outputFiles[0].text)(loaded, loaded.exports, createRequire(path.resolve("package.json")));
const { primaryRoutes, resolveRoute, BASE_PATH } = loaded.exports;
assert.equal(primaryRoutes.length, 6);
for (const route of primaryRoutes) {
  assert.deepEqual(resolveRoute(route.path), route);
  assert.deepEqual(resolveRoute(route.path + "/"), route);
}
assert.equal(resolveRoute(BASE_PATH).title, "Overview");
assert.equal(resolveRoute("/dashboard/reports/development-evidence").view, "Development Evidence");
assert.equal(resolveRoute("/dashboard/remediation/patch-verification").view, "Patch Verification");
assert.equal(resolveRoute("/dashboard/missing-page").notFound, true);
assert.equal(resolveRoute("/api/console/status").notFound, true);
console.log("M10 native route resolver: 12 checks passed");
