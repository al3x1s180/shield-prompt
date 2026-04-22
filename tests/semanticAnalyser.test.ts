import { describe, it, expect } from "vitest";
import { semanticAnalyse } from "../src/semanticAnalyser";

function run(text: string, languageId = "javascript"): string[] {
  return semanticAnalyse(text, languageId, 0, []).map((f) => f.ruleId);
}

describe("semanticAnalyse — taint propagation (command injection owned by this layer)", () => {
  it("flags shell exec where the argument comes from req.query via a single assignment", () => {
    const src = `
      const user = req.query.user;
      child_process.exec("ls " + user);
    `;
    const ids = run(src);
    expect(ids).toContain("command-injection");
  });

  it("propagates taint through Array.join into a fetch URL", () => {
    const src = `
      const id = req.params.id;
      const url = ["/api", id].join("/");
      fetch(url);
    `;
    const ids = run(src);
    // SSRF or command-injection style — either is a valid catch.
    expect(ids.length).toBeGreaterThan(0);
  });

  it("flags sql concatenation with tainted input", () => {
    const src = `
      const id = req.body.id;
      db.query("SELECT * FROM users WHERE id=" + id);
    `;
    const ids = run(src);
    expect(ids).toContain("sql-concat");
  });
});

describe("semanticAnalyse — comment-bypass resistance", () => {
  it("does not let a commented-out sanitizer silence command-injection", () => {
    const src = `
      const user = req.query.user;
      // sanitize(user) — commented out, must not count as a safeguard
      child_process.exec("ls " + user);
    `;
    const ids = run(src);
    expect(ids).toContain("command-injection");
  });
});

describe("semanticAnalyse — no false positives on safe patterns", () => {
  it("does NOT flag command-injection when both operands are literals", () => {
    const ids = run(`child_process.exec("ls " + "-la");`);
    expect(ids).not.toContain("command-injection");
  });

  it("does NOT flag sql-concat when the query has no taint source", () => {
    const ids = run(`db.query("SELECT * FROM users WHERE id=" + 42);`);
    expect(ids).not.toContain("sql-concat");
  });
});
