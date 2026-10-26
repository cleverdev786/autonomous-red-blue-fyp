"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const css = fs.readFileSync("src/tokens.css", "utf8");
const ui = fs.readFileSync("src/product.css", "utf8");
const app = fs.readFileSync("src/App.tsx", "utf8");
function block(selector) {
  const pattern = new RegExp(selector.replace(/[.*+?^${}()|[\]\\]/g,"\\$&") + "\\s*\\{([^}]*)\\}");
  const match = css.match(pattern);
  assert(match, "Missing theme: " + selector);
  return Object.fromEntries([...match[1].matchAll(/(--[a-z0-9-]+):\s*([^;]+);/g)].map(m => [m[1], m[2].trim()]));
}
const light = block(":root");
const dark = block(':root[data-theme="dark"]');
const required = ["--color-canvas", "--color-sidebar", "--color-surface", "--color-surface-sunken",
  "--color-border", "--color-text", "--color-muted", "--color-action", "--color-action-hover",
  "--color-action-ink", "--color-success", "--color-warning", "--color-danger", "--color-focus", "--color-link"];
for (const key of required) {
  assert(/^#[0-9a-fA-F]{6}$/.test(light[key]), "Light theme missing " + key);
  assert(/^#[0-9a-fA-F]{6}$/.test(dark[key]), "Dark theme missing " + key);
  assert.notEqual(light[key], dark[key], "Unchanged semantic color: " + key);
}
for (const alias of ["--card", "--primary", "--sidebar", "--background", "--foreground",
  "--border", "--ring", "--input", "--muted-foreground", "--accent", "--chart-1",
  "--chart-2", "--chart-3", "--chart-4", "--chart-5"]) {
  assert(light[alias], "Expected MARS-compatible token: " + alias);
}
function luminance(hex) {
  const channels = [1,3,5].map(i => parseInt(hex.slice(i,i+2), 16)/255)
    .map(n => n <= .04045 ? n / 12.92 : ((n + .055) / 1.055) ** 2.4);
  return .2126*channels[0]+.7152*channels[1]+.0722*channels[2];
}
function contrast(a,b) {
  const x=luminance(a),y=luminance(b);
  return (Math.max(x,y)+.05)/(Math.min(x,y)+.05);
}
for (const [mode, colors] of [["light",light],["dark",dark]]) {
  for(const [fg,bg] of [
    ["--color-text","--color-canvas"],
    ["--color-muted","--color-surface"],
    ["--color-action-ink","--color-action"],
    ["--color-danger","--color-surface"],
    ["--color-success","--color-surface"],
    ["--color-warning","--color-surface"],
  ]) assert(contrast(colors[fg],colors[bg]) >= 4.5, mode + " insufficient contrast: " + fg + "/" + bg);
}
assert(ui.includes("background:var(--color-canvas)"), "Shell must use semantic canvas");
assert(ui.includes("background:var(--color-sidebar)"), "Sidebar must use semantic sidebar");
assert(ui.includes("background:var(--color-surface)"), "Cards must use semantic surface");
assert(app.includes('window.localStorage.setItem("mars-theme", theme)'), "Persisted toggle removed");
const brand = fs.readFileSync("src/brand.tsx", "utf8");
assert(brand.includes('fill="#1D5BBD"'), "Brand mark not aligned to MARS cobalt");
assert(!brand.includes("#4F46E5"), "Legacy purple logo survived");
assert(!/var\(--color-surface\)[a-z0-9]/i.test(ui), "Invalid CSS color replacement");
console.log("MARS theme: light/dark semantic roles, security state contrast, and existing persistence PASS");
