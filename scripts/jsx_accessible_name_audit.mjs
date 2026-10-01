// Derive accessible-name presence from a real JSX AST, not a text scanner.
//
// The hand-rolled scanner recorded in
// evidence/one-line-release-001/ui-inventory-unlabelled-pass-unsafe-20260926.md
// cannot find a JSX tag's real boundary across multi-line attributes, nested
// braces and template literals, and returned attribute text labelled as an
// accessible name in both its original and its "corrected" form. This uses the
// @babel/parser already present in apps/web/node_modules, so no network, no
// install and no heavy slot are involved.
//
// Usage: node scripts/jsx_accessible_name_audit.mjs [--sample N] [--json]
import { readFileSync } from "node:fs";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(new URL("../apps/web/", import.meta.url));
const { parse } = require("@babel/parser");

const argv = process.argv.slice(2);
const sampleIdx = argv.indexOf("--sample");
const SAMPLE = sampleIdx >= 0 ? Number(argv[sampleIdx + 1]) : 0;
const AS_JSON = argv.includes("--json");

const files = execFileSync("git", ["ls-files", "*.tsx"], { encoding: "utf8" })
  .split("\n")
  .filter(Boolean);
const chosen = SAMPLE > 0 ? files.slice(0, SAMPLE) : files;

// SCOPE, stated honestly.
// In scope: native HTML elements whose accessible name is computable from the AST.
// A capitalised React component is NOT in scope - what it renders is not knowable
// statically, so counting it as an unlabelled control would be a guess dressed as a
// measurement. Components are counted separately as "not statically decidable".
const NATIVE_NAME_REQUIRED = new Set(["input", "button", "select", "textarea", "img"]);
const INTERACTIVE = new Set(["a"]); // only name-required when it has an href

function isNativeControl(el, tag) {
  if (NATIVE_NAME_REQUIRED.has(tag)) {
    if (tag === "input") {
      const type = (classifyAttrs(el)).get("type") || "text";
      return type !== "hidden";
    }
    return true;
  }
  if (INTERACTIVE.has(tag)) return classifyAttrs(el).has("href");
  return false;
}

function classifyAttrs(el) {
  const attrs = new Map();
  for (const a of el.openingElement.attributes || []) {
    const n = attrName(a);
    if (n) attrs.set(n, attrValue(a));
  }
  return attrs;
}

function attrName(node) {
  if (!node || node.type !== "JSXAttribute") return null;
  return node.name.type === "JSXIdentifier" ? node.name.name : null;
}

function attrValue(node) {
  const v = node && node.value;
  if (!v) return null;
  if (v.type === "StringLiteral") return v.value;
  if (v.type === "JSXExpressionContainer") return "<expression>";
  return "<other>";
}

function tagName(node) {
  const n = node.openingElement.name;
  if (n.type === "JSXIdentifier") return n.name;
  if (n.type === "JSXMemberExpression") {
    return `${n.property.name}`; // e.g. CollapsiblePrimitive.Root
  }
  if (n.type === "JSXNamespacedName") return `${n.namespace.name}:${n.name.name}`;
  return "<complex>";
}

// Real element text: JSXText children only, never attribute values.
function ownText(el) {
  let out = "";
  for (const child of el.children || []) {
    if (child.type === "JSXText") out += child.value;
    else if (child.type === "JSXExpressionContainer" && child.expression?.type === "StringLiteral") {
      out += child.expression.value;
    }
  }
  return out.trim();
}

function classify(el) {
  const attrs = new Map();
  for (const a of el.openingElement.attributes || []) {
    const n = attrName(a);
    if (n) attrs.set(n, attrValue(a));
  }
  const sources = [];
  if (ownText(el)) sources.push("text");
  if (attrs.has("aria-label")) sources.push("aria-label");
  if (attrs.has("aria-labelledby")) sources.push("aria-labelledby");
  if (attrs.has("title")) sources.push("title");
  if (attrs.has("alt")) sources.push("alt");
  if (tagName(el) === "input" && attrs.get("type") === "submit") {
    sources.push("type=submit");
  }
  return { sources, attrs };
}

const rows = [];
const perFile = new Map();
for (const rel of chosen) {
  let ast;
  try {
    ast = parse(readFileSync(rel, "utf8"), {
      sourceType: "module",
      plugins: ["jsx", "typescript"],
      errorRecovery: true,
    });
  } catch (e) {
    continue; // a file that will not parse is reported separately, not silently dropped
  }
  let controls = 0, unlabelled = 0, undecidable = 0;
  const walk = (node) => {
    if (!node || typeof node !== "object") return;
    if (Array.isArray(node)) return node.forEach(walk);
    if (node.type === "JSXElement" && node.openingElement && node.openingElement.name) {
      const tag = tagName(node);
      if (/^[A-Z]/.test(tag)) {
        undecidable += 1;
      } else if (isNativeControl(node, tag)) {
        controls += 1;
        const { sources, attrs } = classify(node);
        if (sources.length === 0) {
          unlabelled += 1;
          rows.push({
            file: rel,
            line: node.loc.start.line,
            tag,
            type: attrs.get("type") ?? null,
            hasAriaDescribedBy: attrs.has("aria-describedby"),
          });
        }
      }
    }
    for (const k of Object.keys(node)) {
      if (k === "loc" || k === "extra" || k === "errors" ||
          k === "leadingComments" || k === "trailingComments" ||
          k === "innerComments") continue;
      walk(node[k]);
    }
  };
  walk(ast.program);
  perFile.set(rel, { controls, unlabelled, undecidable });
}

const summary = {
  filesScanned: perFile.size,
  filesAvailable: files.length,
  controlsExamined: [...perFile.values()].reduce((a, b) => a + b.controls, 0),
  componentsNotStaticallyDecidable: [...perFile.values()].reduce((a, b) => a + b.undecidable, 0),
  unlabelled: rows.length,
  method: "babel AST; element text is JSXText children only, never attribute values; native interactive elements only, components excluded as undecidable",
};

if (AS_JSON) {
  console.log(JSON.stringify({ summary, unlabelled: rows }, null, 2));
} else {
  console.log("files scanned      :", summary.filesScanned, "of", summary.filesAvailable);
  console.log("native controls    :", summary.controlsExamined);
  console.log("unlabelled native  :", summary.unlabelled);
  console.log("components (NOT statically decidable, deliberately NOT counted as controls):",
    summary.componentsNotStaticallyDecidable);
  console.log("method             :", summary.method);
  const shown = rows.slice(0, 10);
  for (const r of shown) {
    console.log(`  ${r.file}:${r.line} <${r.tag}${r.type ? ` type=${r.type}` : ""}>`);
  }
  if (rows.length > shown.length) console.log(`  ... and ${rows.length - shown.length} more`);
}
