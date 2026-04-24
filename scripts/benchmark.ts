// Standalone benchmark — scans a given directory with the same analysis
// pipeline the VSCode extension uses, and prints a summary. Useful for
// running against real vulnerable apps (DVWA, Juice Shop, WebGoat) without
// launching VSCode.
//
// Usage:
//   npx tsx scripts/benchmark.ts /path/to/repo
//
// Or compile via tsc and: node dist/scripts/benchmark.js /path/to/repo

import * as path from "path";
import { runProjectScan, InMemoryScanCache } from "../src/projectScanner";
import { loadRules } from "../src/ruleLoader";
import { Finding } from "../src/analyser";

interface Summary {
  totalFiles:     number;
  filesScanned:   number;
  filesWithIssue: number;
  totalFindings:  number;
  bySeverity:     Record<string, number>;
  byRuleId:       Record<string, number>;
  byCategory:     Record<string, number>;
  topFiles:       Array<{ file: string; count: number }>;
  elapsedMs:      number;
}

function summarize(
  results: Array<{ file: string; findings: Finding[] }>,
  rootPath: string,
  elapsedMs: number
): Summary {
  const bySeverity: Record<string, number> = {};
  const byRuleId:   Record<string, number> = {};
  const byCategory: Record<string, number> = {};
  let   totalFindings  = 0;
  const fileCounts: Array<{ file: string; count: number }> = [];

  for (const r of results) {
    if (r.findings.length > 0) {
      fileCounts.push({
        file:  path.relative(rootPath, r.file),
        count: r.findings.length,
      });
    }
    for (const f of r.findings) {
      totalFindings++;
      bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
      byRuleId[f.ruleId]     = (byRuleId[f.ruleId]   ?? 0) + 1;
      const cat = f.category ?? categoryFromRuleId(f.ruleId);
      if (cat) byCategory[cat] = (byCategory[cat] ?? 0) + 1;
    }
  }

  fileCounts.sort((a, b) => b.count - a.count);

  return {
    totalFiles:     results.length,
    filesScanned:   results.length,
    filesWithIssue: fileCounts.length,
    totalFindings,
    bySeverity,
    byRuleId,
    byCategory,
    topFiles:       fileCounts.slice(0, 15),
    elapsedMs,
  };
}

function categoryFromRuleId(id: string): string | undefined {
  if (/sql/i.test(id))           return "sql-injection";
  if (/xss|html/i.test(id))      return "xss";
  if (/command|shell|exec/i.test(id)) return "command-injection";
  if (/secret|token|key|password|credential|hardcoded/i.test(id)) return "secret-leak";
  if (/ssrf/i.test(id))          return "ssrf";
  if (/path|traversal/i.test(id)) return "path-traversal";
  if (/deserial|pickle|yaml/i.test(id)) return "deserialization";
  return undefined;
}

function printSummary(s: Summary, target: string): void {
  const line = (s: string): string => `  ${s}`;
  console.log();
  console.log(`ShieldPrompt benchmark — ${target}`);
  console.log("─".repeat(60));
  console.log(line(`files scanned:     ${s.filesScanned}`));
  console.log(line(`files with issue:  ${s.filesWithIssue}`));
  console.log(line(`total findings:    ${s.totalFindings}`));
  console.log(line(`elapsed:           ${s.elapsedMs} ms (${(s.elapsedMs / s.filesScanned).toFixed(1)} ms/file)`));
  console.log();

  console.log("  by severity:");
  for (const [sev, n] of Object.entries(s.bySeverity).sort((a, b) => b[1] - a[1])) {
    console.log(line(`  ${sev.padEnd(10)}${n}`));
  }

  console.log();
  console.log("  by category:");
  for (const [cat, n] of Object.entries(s.byCategory).sort((a, b) => b[1] - a[1])) {
    console.log(line(`  ${cat.padEnd(20)}${n}`));
  }

  console.log();
  console.log("  top findings by rule:");
  const sortedRules = Object.entries(s.byRuleId).sort((a, b) => b[1] - a[1]);
  for (const [rule, n] of sortedRules.slice(0, 15)) {
    console.log(line(`  ${rule.padEnd(40)}${n}`));
  }

  console.log();
  console.log("  files with most findings:");
  for (const { file, count } of s.topFiles) {
    console.log(line(`  ${count.toString().padStart(4)}  ${file}`));
  }
  console.log();
}

async function main(): Promise<void> {
  const target = process.argv[2];
  if (!target) {
    console.error("usage: benchmark <path-to-repo>");
    process.exit(1);
  }
  const rootPath = path.resolve(target);

  const extensionPath = path.resolve(__dirname, "..");
  process.stderr.write(`loading rules from ${extensionPath}... `);
  const rules = await loadRules(extensionPath);
  process.stderr.write(`ok (${rules.languageRules.size} language packs, ${rules.frameworkRules.size} framework packs)\n`);

  process.stderr.write(`scanning ${rootPath}...\n`);
  const cache = new InMemoryScanCache();
  const t0 = Date.now();
  const results = await runProjectScan(rootPath, [], rules, {
    cache,
    fileLimit: 10000,      // large enough for DVWA / Juice Shop
    astLayer: true,
    skipNoisyInTests: true,
  });
  const elapsedMs = Date.now() - t0;

  printSummary(summarize(results, rootPath, elapsedMs), rootPath);
}

void main();
