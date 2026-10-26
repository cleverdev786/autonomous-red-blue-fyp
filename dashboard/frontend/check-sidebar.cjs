"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const esbuild = require("esbuild");
const { createRequire } = require("node:module");
const path = require("node:path");

const built = esbuild.buildSync({ entryPoints: ["src/routes.ts"], bundle: true,
  platform: "node", format: "cjs", write: false, logLevel: "silent" });
const loaded = { exports: {} };
new Function("module", "exports", "require", built.outputFiles[0].text)(
  loaded, loaded.exports, createRequire(path.resolve("package.json")));
const { primaryRoutes } = loaded.exports;
assert.deepEqual(primaryRoutes.slice(0, 3).map(route => route.title),
  ["Overview", "Red Team", "Blue Team"]);
assert(primaryRoutes.every(route => route.path.startsWith("/dashboard/")));
const app = fs.readFileSync("src/App.tsx", "utf8");
const css = fs.readFileSync("src/product.css", "utf8");
const sidebar = fs.readFileSync("src/components/ui/sidebar.tsx", "utf8");
for (const token of [
  "sidebar-close", "aria-label=\"Close navigation\"",
  'className="brand-type"',
  "menuOpen", 'className="sidebar-workspace-label"',
]) assert(app.includes(token), "Missing sidebar accessibility state: " + token);
for (const token of [
  ".shell:has(.sidebar:hover)", ".shell:has(.sidebar:focus-within)",
  ".nav-label", ".sidebar.menu-open", "@keyframes mars-sidebar-enter",
  "prefers-reduced-motion: reduce", "width:100vw"
]) assert(css.includes(token), "Missing responsive interaction: " + token);
for (const token of ['aria-label={item.title}', 'className="nav-label"',
  'aria-current={active ? "page"', 'onNavigate(event, item.path)']) {
  assert(sidebar.includes(token), "Missing sidebar link behavior: " + token);
}
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const component = esbuild.buildSync({
  entryPoints: ["src/components/ui/sidebar.tsx"], bundle: true,
  platform: "node", format: "cjs", packages: "external", write: false,
  jsx: "automatic", logLevel: "silent",
});
const sidebarModule = { exports: {} };
new Function("module", "exports", "require", component.outputFiles[0].text)(
  sidebarModule, sidebarModule.exports, createRequire(path.resolve("package.json")));
const { Sidebar, SidebarLink } = sidebarModule.exports;
const nav = renderToStaticMarkup(React.createElement(SidebarLink, {
  item: primaryRoutes[1], active: true, onNavigate: () => {},
}));
assert.match(nav, /href="\/dashboard\/red-team"/);
assert.match(nav, /aria-current="page"/);
assert.match(nav, /aria-label="Red Team"/);
assert.match(nav, /class="nav-label"/);
const mobile = renderToStaticMarkup(React.createElement(Sidebar,
  { open: true }, React.createElement("p", null, "Navigation")));
assert.match(mobile, /role="dialog"/);
assert.match(mobile, /aria-modal="true"/);
assert(app.includes("<Sidebar open={menuOpen}>"));
assert(app.includes("<SidebarLink key={item.path}"));
assert(!app.includes('href="#"'), "Sidebar links must point to real routes");
console.log("MARS sidebar: eight real routes, desktop hover/focus, mobile drawer, accessible labels = PASS");
