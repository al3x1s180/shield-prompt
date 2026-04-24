// Targeted DVWA audit — checks whether we catch the canonical vulnerabilities
// in the vulnerabilities/*/source/low.php and medium.php files.
// Ground truth: DVWA labels each folder by vulnerability class.

import * as fs from "fs";
import * as path from "path";
import { loadRules, getLanguageRules, applyCompiledRules } from "../src/ruleLoader";
import { analyseAllLayers } from "../src/pipeline";

interface GroundTruthCase {
  category: string;
  folder:   string;
  files:    string[];
  expectedRuleIds?: string[]; // partial match is fine
}

const CASES: GroundTruthCase[] = [
  { category: "SQL injection",       folder: "sqli",        files: ["low.php", "medium.php"], expectedRuleIds: ["sql-injection", "sql-concat"] },
  { category: "SQL injection blind", folder: "sqli_blind",  files: ["low.php", "medium.php"], expectedRuleIds: ["sql-injection"] },
  { category: "Command injection",   folder: "exec",        files: ["low.php", "medium.php"], expectedRuleIds: ["command-injection"] },
  { category: "File inclusion",      folder: "fi",          files: ["low.php", "medium.php"], expectedRuleIds: ["file-inclusion"] },
  { category: "Reflected XSS",       folder: "xss_r",       files: ["low.php", "medium.php"], expectedRuleIds: ["xss"] },
  { category: "Stored XSS",          folder: "xss_s",       files: ["low.php", "medium.php"], expectedRuleIds: ["xss"] },
  { category: "Upload (path traversal)", folder: "upload",  files: ["low.php", "medium.php"], expectedRuleIds: ["path-traversal", "file-inclusion"] },
  { category: "Open redirect",       folder: "open_redirect", files: ["low.php"],             expectedRuleIds: ["open-redirect"] },
];

async function main(): Promise<void> {
  const dvwaRoot = process.argv[2];
  if (!dvwaRoot) {
    console.error("usage: benchmark-dvwa-ground-truth <path-to-DVWA>");
    process.exit(1);
  }

  const extensionPath = path.resolve(__dirname, "..");
  const rules = await loadRules(extensionPath);

  let caught = 0;
  let total  = 0;

  console.log();
  console.log("DVWA ground-truth audit");
  console.log("─".repeat(72));

  for (const c of CASES) {
    for (const fname of c.files) {
      total++;
      const fullPath = path.join(dvwaRoot, "vulnerabilities", c.folder, "source", fname);
      let text: string;
      try { text = fs.readFileSync(fullPath, "utf8"); }
      catch { console.log(`  ${c.category.padEnd(24)} ${c.folder}/${fname} — FILE MISSING`); continue; }

      const findings = analyseAllLayers(text, "php", 0, [], new Set(), rules, { astLayer: true });
      const ruleIds  = findings.map((f) => f.ruleId);
      const matches  = c.expectedRuleIds
        ? c.expectedRuleIds.some((exp) => ruleIds.some((r) => r.includes(exp)))
        : findings.length > 0;

      if (matches) { caught++; }
      const mark   = matches ? "✓ caught" : "✗ MISSED";
      const idsFmt = ruleIds.length === 0 ? "(no findings)" : ruleIds.slice(0, 4).join(", ");
      console.log(`  ${mark}  ${c.category.padEnd(24)} ${c.folder}/${fname.padEnd(12)} [${idsFmt}]`);
    }
  }

  console.log("─".repeat(72));
  console.log(`  coverage: ${caught}/${total} canonical DVWA low/medium vulns caught (${((caught/total)*100).toFixed(0)}%)`);
  console.log();
}

void main();
