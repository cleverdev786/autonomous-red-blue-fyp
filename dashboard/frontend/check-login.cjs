"use strict";
const assert = require("node:assert/strict");
const esbuild = require("esbuild");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const { createRequire } = require("node:module");
const path = require("node:path");

const built = esbuild.buildSync({
  entryPoints: ["src/LoginScreen.tsx"], bundle: true, platform: "node",
  format: "cjs", write: false, logLevel: "silent", packages: "external", jsx: "automatic",
  define: { "import.meta.env.VITE_API_BASE_URL": "undefined" },
});
const loaded = { exports: {} };
new Function("module", "exports", "require", built.outputFiles[0].text)(
  loaded, loaded.exports, createRequire(path.resolve("package.json")),
);
const html = renderToStaticMarkup(React.createElement(loaded.exports.LoginScreen, {
  checking: false, onSignedIn() {},
}));
for (const text of ["MARS security workspace", "Welcome back", "Username", "Password", "Sign in"]) {
  assert(html.includes(text), `missing login content: ${text}`);
}
assert(/autocomplete="username"/i.test(html) && /autocomplete="current-password"/i.test(html));
assert(!html.includes("19283746"));
console.log("MARS application login form and password privacy: PASS");
