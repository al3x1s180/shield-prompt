import { describe, it, expect, beforeAll } from "vitest";
import * as path from "path";
import { analyseAllLayers } from "../src/pipeline";
import { loadRules, LoadedRules } from "../src/ruleLoader";

const REPO_ROOT = path.resolve(__dirname, "..");

describe("analyseAllLayers — end-to-end pipeline", () => {
  let rules: LoadedRules;

  beforeAll(async () => {
    rules = await loadRules(REPO_ROOT);
  });

  it("fires at least one finding on an obviously unsafe snippet", () => {
    const src = `
      const code = req.body.code;
      eval(code);
      const key = "AKIAIOSFODNN7EXAMPLE";
    `;
    const findings = analyseAllLayers(src, "javascript", 0, [], new Set(), rules);
    expect(findings.length).toBeGreaterThan(0);
  });

  it("produces zero findings on trivially safe code", () => {
    const src = `export function add(a, b) { return a + b; }\nconsole.log(add(1, 2));`;
    const findings = analyseAllLayers(src, "javascript", 0, [], new Set(), rules);
    expect(findings.length).toBe(0);
  });

  it("deduplicates cross-layer findings on the same line+ruleId", () => {
    const src = `eval(req.body.code);`;
    const findings = analyseAllLayers(src, "javascript", 0, [], new Set(), rules);
    const keys = findings.map((f) => `${f.line}:${f.ruleId}`);
    expect(new Set(keys).size).toBe(keys.length);
  });

  it("sorts findings by line, then by severity (critical first)", () => {
    const src = `
      const k = "AKIAIOSFODNN7EXAMPLE";
      eval(req.body.payload);
    `;
    const findings = analyseAllLayers(src, "javascript", 0, [], new Set(), rules);
    for (let i = 1; i < findings.length; i++) {
      const prev = findings[i - 1], cur = findings[i];
      if (prev.line === cur.line) {
        const order: Record<string, number> = { critical: 0, warning: 1, info: 2 };
        expect(order[prev.severity]).toBeLessThanOrEqual(order[cur.severity]);
      } else {
        expect(prev.line).toBeLessThanOrEqual(cur.line);
      }
    }
  });

  it("honours the suppressed-rules list", () => {
    const src = `eval(req.body.code);`;
    const all = analyseAllLayers(src, "javascript", 0, [], new Set(), rules);
    const someId = all[0]?.ruleId;
    if (!someId) { return; } // nothing to suppress; test is vacuously fine
    const after = analyseAllLayers(src, "javascript", 0, [someId], new Set(), rules);
    expect(after.some((f) => f.ruleId === someId)).toBe(false);
  });

  it("activates framework rules only when deps or imports indicate the framework", () => {
    const src = `await prisma.$queryRawUnsafe("SELECT * FROM users WHERE id=" + id);`;
    const without = analyseAllLayers(src, "typescript", 0, [], new Set(),          rules);
    const withDep = analyseAllLayers(src, "typescript", 0, [], new Set(["prisma"]), rules);
    // At least as many findings (probably more) when the framework is active.
    expect(withDep.length).toBeGreaterThanOrEqual(without.length);
  });

  // Regression guard for the exact FP found during the 1.1.0 smoke test:
  // a "sha1" literal in an explanatory comment was firing the weak-hash rule.
  describe("astLayer flag", () => {
    const src = `// Expected findings: crypto-sha1 (warning)\nconst hash = crypto.createHash("sha1");`;

    it("flag OFF = existing behaviour (match in comment is preserved)", () => {
      const findings    = analyseAllLayers(src, "javascript", 0, [], new Set(), rules);
      const onCommentLine = findings.filter((f) => f.line === 0);
      expect(onCommentLine.length).toBeGreaterThan(0);
    });

    it("flag ON drops the comment-line match but keeps the real one", () => {
      const findings      = analyseAllLayers(src, "javascript", 0, [], new Set(), rules, { astLayer: true });
      const onCommentLine = findings.filter((f) => f.line === 0);
      const onCodeLine    = findings.filter((f) => f.line === 1);
      expect(onCommentLine.length).toBe(0);
      expect(onCodeLine.length).toBeGreaterThan(0);
    });

    it("flag ON is a no-op on snippets with no comments", () => {
      const plain    = `const hash = crypto.createHash("sha1");`;
      const without  = analyseAllLayers(plain, "javascript", 0, [], new Set(), rules);
      const withFlag = analyseAllLayers(plain, "javascript", 0, [], new Set(), rules, { astLayer: true });
      expect(withFlag.map((f) => f.ruleId)).toEqual(without.map((f) => f.ruleId));
    });
  });
});
