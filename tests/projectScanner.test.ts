import { describe, it, expect, beforeEach, afterEach } from "vitest";
import * as fs from "fs";
import * as os from "os";
import * as path from "path";
import {
  runProjectScan,
  InMemoryScanCache,
  hashRulePack,
  hashDeps,
} from "../src/projectScanner";
import { loadRules, LoadedRules } from "../src/ruleLoader";

const REPO_ROOT = path.resolve(__dirname, "..");

let tmpRoot: string;

beforeEach(() => {
  tmpRoot = fs.mkdtempSync(path.join(os.tmpdir(), "sp-scan-"));
});

afterEach(() => {
  try { fs.rmSync(tmpRoot, { recursive: true, force: true }); }
  catch { /* ignore */ }
});

function writeFile(rel: string, content: string): string {
  const full = path.join(tmpRoot, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, content);
  return full;
}

// Touch a file with an explicit mtime so cache-hit logic is deterministic.
function touch(filePath: string, mtimeMs: number): void {
  const t = mtimeMs / 1000;
  fs.utimesSync(filePath, t, t);
}

describe("runProjectScan — caching", () => {
  let rules: LoadedRules;

  beforeEach(async () => {
    rules = await loadRules(REPO_ROOT);
  });

  it("writes an entry to the cache on first scan (cache miss)", async () => {
    writeFile("a.js", "eval(userInput);\n");
    const cache = new InMemoryScanCache();

    const results = await runProjectScan(tmpRoot, [], rules, { cache });

    expect(results.length).toBe(1);
    expect(cache.size()).toBe(1);
  });

  it("reuses cached findings when mtime, ruleVersion and depsHash are unchanged", async () => {
    const file = writeFile("a.js", "eval(userInput);\n");
    touch(file, 1_700_000_000_000);
    const cache = new InMemoryScanCache();

    const first  = await runProjectScan(tmpRoot, [], rules, { cache });
    // Rewrite the file *contents* but restore the old mtime so the scanner
    // thinks nothing changed — cache hit should return the OLD findings.
    fs.writeFileSync(file, "// totally safe code now\n");
    touch(file, 1_700_000_000_000);
    const second = await runProjectScan(tmpRoot, [], rules, { cache });

    expect(second[0].findings.length).toBe(first[0].findings.length);
    expect(second[0].findings.length).toBeGreaterThan(0); // stale hit — proves cache was used
  });

  it("invalidates the entry when mtime changes", async () => {
    const file = writeFile("a.js", "eval(userInput);\n");
    touch(file, 1_700_000_000_000);
    const cache = new InMemoryScanCache();

    await runProjectScan(tmpRoot, [], rules, { cache });
    // Rewrite to something safe and bump mtime — cache should miss, re-scan,
    // and return the NEW (empty) findings.
    fs.writeFileSync(file, "const x = 1;\n");
    touch(file, 1_700_000_001_000);
    const second = await runProjectScan(tmpRoot, [], rules, { cache });

    expect(second[0].findings.length).toBe(0);
  });

  it("invalidates when ruleVersion changes", async () => {
    writeFile("a.js", "const x = 1;\n");
    const cache = new InMemoryScanCache();

    await runProjectScan(tmpRoot, [], rules, {
      cache, ruleVersion: "v1",
    });
    expect(cache.size()).toBe(1);

    // Inject a different ruleVersion — entry's ruleVersion won't match, so
    // the scanner re-scans and overwrites the cached entry.
    const beforeEntry = cache.get(path.join(tmpRoot, "a.js"));
    await runProjectScan(tmpRoot, [], rules, {
      cache, ruleVersion: "v2",
    });
    const afterEntry = cache.get(path.join(tmpRoot, "a.js"));

    expect(beforeEntry?.ruleVersion).toBe("v1");
    expect(afterEntry?.ruleVersion).toBe("v2");
  });

  it("applies suppression AFTER the cache lookup (cache entries stay valid)", async () => {
    // A file with an obvious rule match — we store full findings in the
    // cache regardless of suppression, then filter on read.
    writeFile("a.js", "eval(userInput);\n");
    const cache = new InMemoryScanCache();

    const first  = await runProjectScan(tmpRoot, [], rules, { cache });
    const firstIds = first[0].findings.map((f) => f.ruleId);
    expect(firstIds.length).toBeGreaterThan(0);

    // Second call — suppress one of the rules we just found. Cache entry
    // should NOT be rewritten (its ruleVersion/depsHash/mtime are unchanged)
    // and the returned findings should be filtered.
    const suppressOne = [firstIds[0]];
    const before = cache.get(path.join(tmpRoot, "a.js"));
    const second = await runProjectScan(tmpRoot, suppressOne, rules, { cache });
    const after  = cache.get(path.join(tmpRoot, "a.js"));

    expect(second[0].findings.map((f) => f.ruleId)).not.toContain(firstIds[0]);
    // Entry object identity-preserved (same findings array length stored)
    expect(after?.findings.length).toBe(before?.findings.length);
  });

  it("prunes cache entries for files that no longer exist under the root", async () => {
    const fileA = writeFile("a.js", "eval(userInput);\n");
    const fileB = writeFile("b.js", "eval(userInput);\n");
    const cache = new InMemoryScanCache();

    await runProjectScan(tmpRoot, [], rules, { cache });
    expect(cache.size()).toBe(2);

    // Delete b.js — next scan should discover only a.js and prune b's entry.
    fs.unlinkSync(fileB);
    await runProjectScan(tmpRoot, [], rules, { cache });

    expect(cache.size()).toBe(1);
    expect(cache.get(fileA)).toBeDefined();
    expect(cache.get(fileB)).toBeUndefined();
  });

  it("leaves entries from other workspaces alone during prune", async () => {
    writeFile("a.js", "eval(userInput);\n");
    const cache = new InMemoryScanCache();
    // Seed an entry keyed to a path OUTSIDE tmpRoot — representing another
    // workspace's cached file. The prune pass must not touch it.
    const foreignKey = "/some/other/workspace/x.js";
    cache.set(foreignKey, { mtimeMs: 1, ruleVersion: "v", depsHash: "d", findings: [] });

    await runProjectScan(tmpRoot, [], rules, { cache });

    expect(cache.get(foreignKey)).toBeDefined();
  });

  it("respects fileLimit", async () => {
    for (let i = 0; i < 5; i++) { writeFile(`file-${i}.js`, "const x = 1;\n"); }
    const cache = new InMemoryScanCache();

    const results = await runProjectScan(tmpRoot, [], rules, {
      cache, fileLimit: 2,
    });

    expect(results.length).toBe(2);
  });
});

describe("hashRulePack / hashDeps", () => {
  it("hashRulePack is stable across calls", async () => {
    const rules = await loadRules(REPO_ROOT);
    expect(hashRulePack(rules)).toBe(hashRulePack(rules));
  });

  it("hashRulePack handles undefined input without throwing", () => {
    expect(hashRulePack(undefined)).toBe("no-rules");
  });

  it("hashDeps is order-independent", () => {
    expect(hashDeps(new Set(["a", "b", "c"]))).toBe(hashDeps(new Set(["c", "a", "b"])));
  });

  it("hashDeps changes when the set changes", () => {
    expect(hashDeps(new Set(["a"]))).not.toBe(hashDeps(new Set(["a", "b"])));
  });
});
