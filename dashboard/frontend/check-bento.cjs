"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const css = fs.readFileSync("src/overview/bento.css", "utf8").replace(/\s+/g, " ");
const code = fs.readFileSync("src/overview/MarsBento.tsx", "utf8");
const shell = fs.readFileSync("src/product.css", "utf8");
const entry = fs.readFileSync("src/main.tsx", "utf8");
assert(entry.includes('import "./overview/bento.css";'), "Bento CSS must be bundled");
for (const fragment of [
  "grid-template-areas:", '"a a b c"', '"a a d d"', '"e e f f"',
  '"a a"', '"b c"', '"d d"', '"e e"', '"f f"',
  "grid-template-columns:1fr", "prefers-reduced-motion: reduce",
  "mars-bento--lit", "-webkit-mask-composite:xor", "mask-composite:exclude",
  "pointer: fine", "mars-bento-enter", "mars-bento-log",
  "mars-bento-pulse", "mars-bento-trace",
]) assert(css.includes(fragment) || css.replace(/\s+/g,"").includes(fragment.replace(/\s+/g,"")), "Missing bento CSS: " + fragment);
for (const fragment of [
  "requestAnimationFrame", "cancelAnimationFrame",
  "onPointerMove", "onPointerEnter", "onPointerLeave",
  'setProperty("--mx"', 'setProperty("--my"',
  "aria-labelledby", 'aria-hidden="true"', 'role="list"',
]) assert(code.includes(fragment), "Missing bento behavior: " + fragment);
assert(css.includes(".mars-bento-chips > span {"), "Receipt pills must be distinct");
assert(css.includes("grid-template-columns:repeat(2,minmax(0,1fr))"), "Narrow scope grid must not crowd labels");
assert(shell.includes("border-right:1px solid var(--sidebar-border)"),
  "Missing visible sidebar/main separation");
assert(shell.includes("box-shadow:"),
  "Sidebar needs a deliberate separation treatment");
const path = require("node:path");
const esbuild = require("esbuild");
const React = require("react");
const { renderToStaticMarkup } = require("react-dom/server");
const built = esbuild.buildSync({entryPoints:["src/overview/MarsBento.tsx"],bundle:true,
  platform:"node",format:"cjs",packages:"external",write:false,jsx:"automatic",
  loader:{".css":"empty"},logLevel:"silent"});
const result={exports:{}};
new Function("module","exports","require",built.outputFiles[0].text)(
  result,result.exports,require("node:module").createRequire(path.resolve("package.json")));
const rendered=renderToStaticMarkup(React.createElement(result.exports.MarsBento));
assert.match(rendered,/<section[^>]+aria-labelledby="mars-bento-heading"/);
assert.equal((rendered.match(/class="mars-bento-tile /g)||[]).length,6);
assert.doesNotMatch(rendered,/31 edge regions|SOC 2|9\.2s|p99 latency/i);
console.log("MARS bento: six real-workflow tiles, responsive layout, spotlight, reduced motion and separation PASS");
