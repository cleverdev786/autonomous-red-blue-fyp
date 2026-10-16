"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const { createRequire } = require("node:module");
const path = require("node:path");
const esbuild = require("esbuild");
const React = require("react");
const { renderToStaticMarkup: render } = require("react-dom/server");

const built = esbuild.buildSync({
  entryPoints: ["src/ui.tsx"], bundle: true, platform: "node", format: "cjs",
  packages: "external", write: false, jsx: "automatic",
});
const moduleOut = { exports: {} };
new Function("module", "exports", "require", built.outputFiles[0].text)(
  moduleOut, moduleOut.exports, createRequire(path.resolve("package.json")),
);
const { Notice, EmptyState, LoadingState, ActionButton } = moduleOut.exports;
const show = (component, props) => render(React.createElement(component, props));
assert.match(show(Notice, { title: "Blocked", tone: "danger", children: "No authority" }), /role="alert"/);
assert.match(show(Notice, { title: "Waiting" }), /role="status"/);
assert.match(show(EmptyState, { title: "No runs", description: "Unverified" }), /No runs.*Unverified/);
assert.match(show(LoadingState, { label: "Checking" }), /role="status" aria-live="polite"/);
assert.match(show(ActionButton, { disabled: true, children: "Prepare" }), /disabled="".*Prepare/);
assert.match(show(ActionButton, { variant: "secondary", children: "Refresh" }), /ui-button--secondary/);
const modelBuilt = esbuild.buildSync({
  entryPoints: ["src/system/ModelStatus.tsx"], bundle: true, platform: "node",
  format: "cjs", packages: "external", write: false, jsx: "automatic",
});
const modelExports = { exports: {} };
new Function("module","exports","require",modelBuilt.outputFiles[0].text)(
  modelExports,modelExports.exports,createRequire(path.resolve("package.json")));
const { ModelStatus } = modelExports.exports;
const loadedModel = {
  state:"running",filename:"c08b-nf4-effective-Q8_0.gguf",
  model_name:"mars-q8-development",sha256:"51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304",
  port:18083, concurrency:1,context_tokens:2048, final_research_ready:false,
};
const loadedHtml=show(ModelStatus,{active:loadedModel});
assert.match(loadedHtml,/Currently loaded model/);
assert.match(loadedHtml,/c08b-nf4-effective-Q8_0.gguf/);
assert.match(loadedHtml,/running/);
assert.match(loadedHtml,/mars-q8-development/);
assert.match(loadedHtml,/51b63a132c73a592d954e96b15c1d28176f0cc3e5f05533304e92a6fb40ad304/);
assert.match(loadedHtml,/Not research-qualified/);
const unloadedHtml=show(ModelStatus,{active:{state:"unloaded",final_research_ready:false}});
assert.match(unloadedHtml,/No model loaded/);
assert.doesNotMatch(unloadedHtml,/c08b-nf4-effective-Q8_0.gguf/);
const startingHtml=show(ModelStatus,{active:{...loadedModel,state:"starting"}});
assert.match(startingHtml,/Model startup is in progress/);
const stoppedHtml=show(ModelStatus,{active:{...loadedModel,state:"stopped"}});
assert.match(stoppedHtml,/No model running/);
assert.match(stoppedHtml,/Last session: c08b-nf4-effective-Q8_0.gguf/);
assert.doesNotMatch(stoppedHtml,/Local model inference server is reachable/);
const css = fs.readFileSync("src/tokens.css", "utf8");
for (const key of ["canvas", "surface", "text", "muted", "action", "action-ink",
  "success", "warning", "danger", "focus", "red-path"]) {
  assert(css.includes("--color-" + key + ":"), "Missing semantic token: " + key);
}
const color = name => {
  const match = css.match(new RegExp("--color-" + name + ":\\s*(#[a-fA-F0-9]{6})"));
  assert(match, "Unrecognized color token " + name);
  return match[1];
};
const luminance = hex => {
  const values = [1,3,5].map(n => parseInt(hex.slice(n,n+2),16)/255)
    .map(v => v <= .04045 ? v/12.92 : Math.pow((v+.055)/1.055,2.4));
  return .2126*values[0]+.7152*values[1]+.0722*values[2];
};
const contrast = (a,b) => {
  const x = luminance(color(a)), y = luminance(color(b));
  return (Math.max(x,y)+.05)/(Math.min(x,y)+.05);
};
for (const [fg,bg] of [["text","canvas"],["muted","surface"],["action-ink","action"],["danger","surface"]]) {
  assert(contrast(fg,bg) >= 4.5, "Contrast failure: " + fg + " on " + bg);
}
console.log("M11: six semantic component checks, required tokens, four AA text-contrast pairs passed");
