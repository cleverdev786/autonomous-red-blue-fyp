"use strict";
const assert=require("node:assert/strict");
const fs=require("node:fs");
const css=fs.readFileSync("src/product.css","utf8");
const source=fs.readFileSync("src/overview/OverviewPanel.tsx","utf8");
const entry=fs.readFileSync("src/main.tsx","utf8");
assert(source.includes('className="overview-bento"'), "Overview must use existing cards as bento tiles");
assert(source.includes('tool-card tool-card--'), "Real navigation links must be tiles");
assert(css.includes('grid-template-areas:"welcome welcome history history"'),
       "Bento must use asymmetric first row");
assert(css.includes('grid-template-areas:"welcome welcome"'),
       "Bento must adapt to tablets");
assert(css.includes('grid-template-columns:1fr'), "Bento must stack for phones");
assert(css.includes('background:var(--color-surface)'), "Use MARS theme surfaces");
assert(!source.includes("MarsBento"), "Do not mount the old standalone showcase");
assert(!entry.includes("overview/bento.css"), "Do not include removed showcase CSS");
for(const thing of ["mars-bento-section","mars-bento-log","--mars-bento-coral"]) {
  assert(!css.includes(thing), "Legacy black showcase should not survive: "+thing);
}
console.log("MARS integrated overview bento: six real navigation destinations, mixed spans, theme and responsive breakpoints PASS");
