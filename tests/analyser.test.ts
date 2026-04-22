import { describe, it, expect } from "vitest";
import { analyse, fingerprint } from "../src/analyser";

// Convenience: run the static analyser against a snippet and return the ruleIds.
function run(text: string, languageId = "javascript", deps: string[] = []): string[] {
  return analyse(text, languageId, 0, [], new Set(deps)).map((f) => f.ruleId);
}

// Convenience: does the finding set contain a given ruleId?
function has(ids: string[], target: string): boolean { return ids.includes(target); }

describe("analyse — true positives", () => {
  it("flags eval on tainted input", () => {
    const ids = run(`const code = req.body.code;\neval(code);`);
    expect(ids.some((r) => r.includes("eval"))).toBe(true);
  });

  it("flags a hardcoded AWS access key", () => {
    const ids = run(`const key = "AKIAIOSFODNN7EXAMPLE";`);
    expect(has(ids, "hardcoded-secret")).toBe(true);
  });

  it("flags a Stripe secret key", () => {
    const ids = run(`const s = "sk_live_abcdefghijklmnopqrstuvwxyz";`);
    expect(has(ids, "hardcoded-secret")).toBe(true);
  });

  it("flags dangerouslySetInnerHTML with unsanitised input", () => {
    const ids = run(
      `function C({ html }) { return <div dangerouslySetInnerHTML={{ __html: html }} /> }`,
      "javascriptreact"
    );
    expect(ids.some((r) => r.toLowerCase().includes("html") || r.toLowerCase().includes("xss")))
      .toBe(true);
  });

  it("flags insecure SHA-1 hash usage", () => {
    const ids = run(`crypto.createHash('sha1').update(x).digest();`);
    expect(ids.some((r) => r.toLowerCase().includes("sha1") || r.toLowerCase().includes("weak")))
      .toBe(true);
  });
});

describe("analyse — false-positive traps", () => {
  it("does NOT flag low-entropy mock passwords", () => {
    const ids = run(`const password = "changeme";`);
    expect(has(ids, "hardcoded-secret")).toBe(false);
  });

  it("does NOT flag placeholder secrets", () => {
    const ids = run(`const apiKey = "your_secret";`);
    expect(has(ids, "hardcoded-secret")).toBe(false);
  });

  it("does NOT flag template strings like <YOUR_KEY>", () => {
    const ids = run(`const token = "<YOUR_KEY>";`);
    expect(has(ids, "hardcoded-secret")).toBe(false);
  });

  it("does NOT flag repeated-char strings", () => {
    const ids = run(`const pwd = "aaaaaaaaaaaa";`);
    expect(has(ids, "hardcoded-secret")).toBe(false);
  });

  it("does NOT flag process.env usage", () => {
    const ids = run(`const s = process.env.STRIPE_KEY;`);
    expect(has(ids, "hardcoded-secret")).toBe(false);
  });
});

describe("fingerprint — AI-code heuristic", () => {
  it("returns a result with a confidence field", () => {
    const fp = fingerprint("console.log('hi');");
    expect(fp).toHaveProperty("confidence");
    expect(["low", "medium", "high"]).toContain(fp.confidence);
  });
});
