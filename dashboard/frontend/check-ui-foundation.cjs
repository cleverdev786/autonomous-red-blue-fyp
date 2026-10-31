"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");

const pkg = JSON.parse(fs.readFileSync("package.json", "utf8"));
for (const dependency of ["tailwindcss", "@tailwindcss/vite"]) {
  assert(pkg.devDependencies[dependency], `Missing ${dependency}`);
}
for (const dependency of ["class-variance-authority", "cn", "lucide-react", "radix-ui"]) {
  assert(pkg.dependencies[dependency], `Missing ${dependency}`);
}

const styles = fs.readFileSync("src/styles.css", "utf8");
assert(styles.includes('@import "tailwindcss/utilities" layer(utilities);'));
assert(styles.includes('@custom-variant dark (&:where([data-theme="dark"], [data-theme="dark"] *));'));
assert(!styles.includes('@import "tailwindcss";'), "Preflight must not alter untouched legacy views.");

const vite = fs.readFileSync("vite.config.ts", "utf8");
assert(vite.includes("tailwindcss()"));
const app = fs.readFileSync("src/main.tsx", "utf8");
assert(app.includes("TooltipProvider"));
const ui = fs.readFileSync("src/ui.tsx", "utf8");
assert(ui.includes('import { Button } from "./components/ui/button"'));

for (const component of ["button", "input", "select", "radio-group", "dialog", "dropdown-menu", "table", "alert", "skeleton", "tooltip", "badge"]) {
  assert(fs.existsSync(`src/components/ui/${component}.tsx`), `Missing shadcn ${component}`);
}
console.log("MARS Tailwind v4 and selected shadcn foundation: PASS");
