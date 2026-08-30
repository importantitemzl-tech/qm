import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const html = readFileSync(new URL("../public/index.html", import.meta.url), "utf8");

function slice(from: string, to: string): string {
  const start = html.indexOf(from);
  const end = html.indexOf(to, start);
  assert.ok(start >= 0 && end > start, `could not extract ${from}`);
  return html.slice(start, end);
}

function resolveView(pathname: string, search: string): string {
  const src = [
    slice("const SECTIONS = [", "const DISABLED_VIEWS"),
    slice("const DEFAULT_VIEW = ", ";") + ";",
    slice("function urlToState() {", "let transcriptObserver"),
    "urlToState().view;",
  ].join("\n");
  const context = vm.createContext({
    URLSearchParams,
    API_BASE: "/admin",
    scope: "org",
    location: { pathname, search },
  });
  return vm.runInContext(src, context);
}

function customModelFields(): {
  parseCustomModels(text: string): unknown[];
  formatCustomModels(models: unknown[]): string;
} {
  const source = slice("function parseCustomModels(text) {", "async function loadCustomProviders()");
  const context = vm.createContext({});
  return vm.runInContext(`${source}; ({ parseCustomModels, formatCustomModels })`, context);
}

test("onboarding is a navigable view", () => {
  assert.match(html, /\{ label: "Admin", views: \["onboarding",/);
});

test("/admin/onboarding resolves to the onboarding view", () => {
  assert.equal(resolveView("/admin/onboarding", ""), "onboarding");
});

test("?view=onboarding resolves to the onboarding view", () => {
  assert.equal(resolveView("/admin/", "?view=onboarding"), "onboarding");
});

test("unknown views still fall back to the default view", () => {
  assert.equal(resolveView("/admin/no-such-view", ""), "history");
});

test("custom model fields preserve optional positions, modalities, and pricing", () => {
  const { parseCustomModels, formatCustomModels } = customModelFields();
  const models = [
    {
      id: "vision-model",
      contextWindow: 128000,
      maxTokens: 8192,
      modalities: ["text", "image"],
      input: 1.25,
      output: 4.5,
    },
  ];
  const formatted = formatCustomModels(models);
  assert.equal(formatted, "vision-model |  | 128000 | 8192 | text,image | 1.25 | 4.5");
  assert.deepEqual(JSON.parse(JSON.stringify(parseCustomModels(formatted))), models);
  assert.deepEqual(JSON.parse(JSON.stringify(parseCustomModels("legacy | Legacy | 64000 | 4096"))), [
    { id: "legacy", name: "Legacy", contextWindow: 64000, maxTokens: 4096 },
  ]);
});
