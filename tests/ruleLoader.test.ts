import { describe, it, expect } from "vitest";
import * as path from "path";
import {
  loadRules,
  detectFrameworks,
  applyCompiledRules,
  categoryDedup,
  CompiledRule,
  LoadedRules,
} from "../src/ruleLoader";
import { Finding } from "../src/analyser";

const REPO_ROOT = path.resolve(__dirname, "..");

// Build a minimal CompiledRule by hand — avoids touching JSON loading for
// unit tests of applyCompiledRules' branching behaviour.
function mkRule(overrides: Partial<CompiledRule> & { ruleId: string; patterns: RegExp[] }): CompiledRule {
  return {
    ruleId:   overrides.ruleId,
    severity: overrides.severity ?? "warning",
    message:  overrides.message  ?? "test",
    detail:   overrides.detail   ?? "",
    cves:     overrides.cves     ?? [],
    patterns: overrides.patterns.map((regex) => ({ regex })),
    safeguards:     overrides.safeguards     ?? [],
    safeguardScope: overrides.safeguardScope ?? "line",
    requiresTaint:  overrides.requiresTaint  ?? false,
    framework:      overrides.framework,
  };
}

describe("applyCompiledRules — line-scope safeguards", () => {
  it("skips only the line containing the safeguard", () => {
    const rule = mkRule({
      ruleId: "test-eval",
      patterns: [/eval\(/],
      safeguards: [/sanitize/],
      safeguardScope: "line",
    });
    const src = `eval(userInput);\nsanitize(x); eval(userInput);`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.map((f) => f.line)).toEqual([0]);
  });
});

describe("applyCompiledRules — file-scope safeguards", () => {
  it("suppresses every match in the file when safeguard appears anywhere", () => {
    const rule = mkRule({
      ruleId: "test-helmet",
      patterns: [/app\.use\(/],
      safeguards: [/helmet\(\)/],
      safeguardScope: "file",
    });
    const src = `
      app.use(router);
      app.use(bodyParser.json());
      app.use(helmet());  // safeguard registered once at setup
      app.use(session());
    `;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(0);
  });

  it("still fires on every line if the file-scope safeguard is missing", () => {
    const rule = mkRule({
      ruleId: "test-helmet",
      patterns: [/app\.use\(/],
      safeguards: [/helmet\(\)/],
      safeguardScope: "file",
    });
    const src = `app.use(router);\napp.use(session());`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(2);
  });
});

describe("applyCompiledRules — comment-strip before safeguard check", () => {
  it("does not treat a commented-out safeguard as suppressing the line", () => {
    const rule = mkRule({
      ruleId: "test-eval",
      patterns: [/eval\(/],
      safeguards: [/sanitize/],
      safeguardScope: "line",
    });
    const src = `eval(x); // sanitize(x) — commented out`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(1);
  });
});

describe("applyCompiledRules — requiresTaint window", () => {
  it("fires when a taint source is within the ±10 line window", () => {
    const rule = mkRule({
      ruleId: "test-taint-sink",
      patterns: [/dangerousSink\(/],
      requiresTaint: true,
    });
    const src = `const x = req.body.id;\n${"\n".repeat(5)}dangerousSink(x);`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(1);
  });

  it("does NOT fire when the sink is far from any taint source", () => {
    const rule = mkRule({
      ruleId: "test-taint-sink",
      patterns: [/dangerousSink\(/],
      requiresTaint: true,
    });
    const src = `${"\n".repeat(30)}dangerousSink(literal);`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(0);
  });

  it("still fires without requiresTaint regardless of taint proximity", () => {
    const rule = mkRule({
      ruleId: "test-noisy",
      patterns: [/dangerousSink\(/],
      requiresTaint: false,
    });
    const src = `${"\n".repeat(30)}dangerousSink(literal);`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(1);
  });
});

describe("applyCompiledRules — shieldprompt-ignore comment", () => {
  it("suppresses the specific rule named in the ignore directive", () => {
    const rule = mkRule({ ruleId: "test-eval", patterns: [/eval\(/] });
    const src = `eval(x); // shieldprompt-ignore: test-eval`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(0);
  });

  it("suppresses all rules when the directive has no rule id", () => {
    const rule = mkRule({ ruleId: "test-eval", patterns: [/eval\(/] });
    const src = `eval(x); // shieldprompt-ignore`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(0);
  });

  it("does NOT suppress a different rule", () => {
    const rule = mkRule({ ruleId: "test-eval", patterns: [/eval\(/] });
    const src = `eval(x); // shieldprompt-ignore: some-other-rule`;
    const findings = applyCompiledRules(src, "javascript", 0, [], [rule]);
    expect(findings.length).toBe(1);
  });
});

describe("categoryDedup", () => {
  const mk = (ruleId: string, line: number, framework?: string): Finding & { framework?: string } => ({
    line, col: 0, severity: "warning", ruleId, message: "", detail: "", cves: [], framework,
  });

  it("collapses two SQLi-category findings on the same line", () => {
    const input  = [mk("sql-injection-generic", 5), mk("prisma-sql-injection-raw", 5)];
    const output = categoryDedup(input);
    expect(output.length).toBe(1);
  });

  it("prefers the framework-tagged finding", () => {
    const input  = [mk("sql-injection-generic", 5), mk("prisma-sql-injection-raw", 5, "prisma")];
    const output = categoryDedup(input);
    expect(output.length).toBe(1);
    expect(output[0].framework).toBe("prisma");
  });

  it("leaves same-category findings on DIFFERENT lines alone", () => {
    const input  = [mk("sql-injection-generic", 5), mk("sql-injection-generic", 9)];
    const output = categoryDedup(input);
    expect(output.length).toBe(2);
  });

  it("never hides a finding that doesn't match any known category", () => {
    const input  = [mk("weird-unknown-rule", 5), mk("another-random-rule", 5)];
    const output = categoryDedup(input);
    expect(output.length).toBe(2);
  });

  it("explicit category overrides the ruleId-regex heuristic", () => {
    // Two rules on the same line with ruleIds that DON'T match any
    // CATEGORY_FRAGMENTS regex — they would pass through untouched under
    // the heuristic — but they share an explicit `category`, so dedup
    // should collapse them.
    const a: Finding = {
      line: 5, col: 0, severity: "warning", ruleId: "nextjs-sql-in-server-component",
      message: "", detail: "", cves: [], category: "sql-injection",
    };
    const b: Finding = {
      line: 5, col: 0, severity: "warning", ruleId: "django-raw-sql",
      message: "", detail: "", cves: [], category: "sql-injection",
    };
    const output = categoryDedup([a, b]);
    expect(output.length).toBe(1);
  });

  it("explicit category on one finding collapses with regex-matched category on another", () => {
    // Common migration case: framework rule has been labelled, hardcoded
    // rule hasn't. Dedup should still collapse them.
    const labelled: Finding = {
      line: 5, col: 0, severity: "warning", ruleId: "nextjs-sql-in-server-component",
      message: "", detail: "", cves: [], category: "sql-injection", framework: "nextjs",
    };
    const unlabelled: Finding = {
      line: 5, col: 0, severity: "warning", ruleId: "sql-injection-generic",
      message: "", detail: "", cves: [], // no explicit category → regex matches
    };
    const output = categoryDedup([labelled, unlabelled]);
    expect(output.length).toBe(1);
    expect(output[0].framework).toBe("nextjs");
  });
});

describe("detectFrameworks", () => {
  const fws = [
    { name: "express", detectionDeps: ["express"], detectionImports: ["require(\"express\")", "from 'express'"] },
    { name: "react",   detectionDeps: ["react"],   detectionImports: ["from 'react'"] },
  ];

  it("detects by dependency", () => {
    const active = detectFrameworks(`const a = 1;`, new Set(["express"]), fws);
    expect(active).toContain("express");
  });

  it("detects by import substring when no dep is present", () => {
    const active = detectFrameworks(`import express from 'express'`, new Set(), fws);
    expect(active).toContain("express");
  });

  it("returns empty when nothing matches", () => {
    const active = detectFrameworks(`const a = 1;`, new Set(), fws);
    expect(active).toEqual([]);
  });
});

describe("loadRules — setup rules declare file-scope safeguards in JSON", () => {
  // These are rules where the safeguard (helmet(), csrf_protect, RLS,
  // schema validation) is registered once at setup — so one match anywhere
  // in the file should suppress the rule. Regression guard: if anyone drops
  // `"safeguardScope": "file"` from a rule's JSON, this test flags it before
  // the rule starts over-firing on users.
  const SETUP_RULE_IDS = [
    "drizzle-where-missing",
    "express-no-helmet",
    "fastapi-no-auth-dependency",
    "fastapi-jwt-no-verify",
    "fastify-no-schema-validation",
    "fastify-jwt-no-verify",
    "flask-no-csrf",
    "flask-cookie-no-httponly",
    "nextjs-server-action-no-auth",
    "nextjs-cookie-no-httponly",
    "prisma-findmany-no-where",
    "react-postmessage-no-origin",
    "sqlalchemy-bulk-no-validate",
    "supabase-no-rls",
    "svelte-server-load-no-auth",
    "svelte-form-action-no-validate",
    "svelte-cookie-no-httponly",
  ];

  it("every setup rule compiles with safeguardScope: file", async () => {
    const loaded = await loadRules(REPO_ROOT);
    const compiledById = new Map<string, CompiledRule>();
    for (const rules of loaded.frameworkRules.values()) {
      for (const r of rules) { compiledById.set(r.ruleId, r); }
    }
    const missing: string[] = [];
    const wrongScope: string[] = [];
    for (const id of SETUP_RULE_IDS) {
      const rule = compiledById.get(id);
      if (!rule) { missing.push(id); continue; }
      if (rule.safeguardScope !== "file") { wrongScope.push(id); }
    }
    expect(missing,    `rules not found: ${missing.join(", ")}`).toEqual([]);
    expect(wrongScope, `wrong scope (expected "file"): ${wrongScope.join(", ")}`).toEqual([]);
  });
});

describe("loadRules — integration smoke test against real rules/", () => {
  it("loads all language rule packs without throwing", async () => {
    const loaded: LoadedRules = await loadRules(REPO_ROOT);
    expect(loaded.languageRules.size).toBeGreaterThan(0);
  });

  it("loads at least one framework rule pack", async () => {
    const loaded: LoadedRules = await loadRules(REPO_ROOT);
    expect(loaded.frameworkRules.size).toBeGreaterThan(0);
    expect(loaded.frameworks.length).toBeGreaterThan(0);
  });

  it("compiles TypeScript rules that apply to typescript + javascript", async () => {
    const loaded = await loadRules(REPO_ROOT);
    const tsRules = loaded.languageRules.get("typescript") ?? [];
    const jsRules = loaded.languageRules.get("javascript") ?? [];
    // TS rules alias into JS per LANG_ALIASES, so JS should have at least as many as TS.
    expect(jsRules.length).toBeGreaterThanOrEqual(tsRules.length);
  });
});
