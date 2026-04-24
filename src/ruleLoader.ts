import * as fs from "fs";
import * as path from "path";
import { CVERef, Finding, stripLineComment } from "./analyser";
import { TAINT_SOURCES } from "./semanticAnalyser";

interface RawPattern {
  type: string;
  match: string;
  flags?: string;
  context?: string;
}

interface RawRule {
  ruleId: string;
  severity: "critical" | "warning" | "info";
  message: string;
  detail: string;
  cves?: CVERef[];
  patterns: RawPattern[];
  safeguards?: string[];
  requiresTaint?: boolean;
  safeguardScope?: "line" | "file";
  category?: string;
}

interface RawLanguageFile {
  version: number;
  language: string;
  rules: RawRule[];
}

interface RawFrameworkFile {
  version: number;
  framework: string;
  language: string;
  rules: RawRule[];
}

interface RawFrameworkManifest {
  frameworks: Record<string, {
    detectionDeps: string[];
    detectionImports: string[];
  }>;
}

interface CompiledPattern {
  regex: RegExp;
}

export interface CompiledRule {
  ruleId: string;
  severity: "critical" | "warning" | "info";
  message: string;
  detail: string;
  cves: CVERef[];
  patterns: CompiledPattern[];
  safeguards: RegExp[];
  safeguardScope: "line" | "file";
  requiresTaint: boolean;
  category?: string;
  framework?: string;
}

// `safeguardScope` on each rule is now authoritative and defined in the JSON
// rule packs themselves. Setup-style rules (helmet(), csrf_protect, RLS,
// schema validators registered once) set `"safeguardScope": "file"` so a
// single safeguard match anywhere in the file suppresses the rule; sink-style
// rules default to `"line"` so only the line holding the protection is
// skipped.

export interface FrameworkDetection {
  name: string;
  detectionDeps: string[];
  detectionImports: string[];
}

export interface LoadedRules {
  languageRules: Map<string, CompiledRule[]>;
  frameworkRules: Map<string, CompiledRule[]>;
  frameworks: FrameworkDetection[];
}

// Map canonical language name → VS Code languageIds it applies to.
const LANG_ALIASES: Record<string, string[]> = {
  javascript: ["javascript", "javascriptreact"],
  typescript: ["typescript", "typescriptreact", "javascript", "javascriptreact"],
  python:     ["python"],
  java:       ["java"],
  csharp:     ["csharp"],
  go:         ["go"],
  ruby:       ["ruby"],
  php:        ["php"],
  rust:       ["rust"],
  c:          ["c", "cpp"],
};

function safeRegex(pattern: string, flags = ""): RegExp | null {
  try {
    return new RegExp(pattern, flags);
  } catch {
    return null;
  }
}

function compileRule(raw: RawRule, framework?: string): CompiledRule | null {
  const patterns: CompiledPattern[] = [];
  for (const p of raw.patterns ?? []) {
    if (p.type !== "regex") continue;
    const r = safeRegex(p.match, p.flags ?? "g");
    if (r) patterns.push({ regex: r });
  }
  if (patterns.length === 0) return null;

  const safeguards: RegExp[] = [];
  for (const s of raw.safeguards ?? []) {
    const r = safeRegex(s, "i");
    if (r) safeguards.push(r);
  }

  const safeguardScope: "line" | "file" = raw.safeguardScope ?? "line";

  return {
    ruleId:   raw.ruleId,
    severity: raw.severity,
    message:  raw.message,
    detail:   raw.detail,
    cves:     raw.cves ?? [],
    patterns,
    safeguards,
    safeguardScope,
    requiresTaint: raw.requiresTaint === true,
    category: raw.category,
    framework,
  };
}

async function readJson<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await fs.promises.readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

export async function loadRules(extensionPath: string): Promise<LoadedRules> {
  const rulesDir = path.join(extensionPath, "rules");
  const frameworksDir = path.join(rulesDir, "frameworks");

  const languageRules  = new Map<string, CompiledRule[]>();
  const frameworkRules = new Map<string, CompiledRule[]>();
  const frameworks: FrameworkDetection[] = [];

  // ── Language rules ───────────────────────────────────────────────────────
  for (const lang of Object.keys(LANG_ALIASES)) {
    const file = await readJson<RawLanguageFile>(path.join(rulesDir, `${lang}.json`));
    if (!file || !Array.isArray(file.rules)) continue;

    const compiled: CompiledRule[] = [];
    for (const raw of file.rules) {
      const c = compileRule(raw);
      if (c) compiled.push(c);
    }
    for (const vscodeLang of LANG_ALIASES[lang]) {
      const existing = languageRules.get(vscodeLang) ?? [];
      languageRules.set(vscodeLang, existing.concat(compiled));
    }
  }

  // ── Framework manifest + rules ───────────────────────────────────────────
  const manifest = await readJson<RawFrameworkManifest>(
    path.join(frameworksDir, "manifest-frameworks.json")
  );
  if (manifest && manifest.frameworks) {
    for (const [name, def] of Object.entries(manifest.frameworks)) {
      frameworks.push({
        name,
        detectionDeps:    def.detectionDeps    ?? [],
        detectionImports: def.detectionImports ?? [],
      });

      const file = await readJson<RawFrameworkFile>(
        path.join(frameworksDir, `${name}.json`)
      );
      if (!file || !Array.isArray(file.rules)) continue;

      const compiled: CompiledRule[] = [];
      for (const raw of file.rules) {
        const c = compileRule(raw, name);
        if (c) compiled.push(c);
      }
      frameworkRules.set(name, compiled);
    }
  }

  return { languageRules, frameworkRules, frameworks };
}

// ─── Detection ──────────────────────────────────────────────────────────────

export function detectFrameworks(
  text: string,
  projectDeps: Set<string>,
  frameworks: FrameworkDetection[]
): string[] {
  const active: string[] = [];
  for (const fw of frameworks) {
    const depMatch = fw.detectionDeps.some((d) => {
      const lower = d.toLowerCase();
      if (lower.endsWith("/")) {
        // Namespace prefix — match any dep starting with it.
        for (const p of projectDeps) if (p.startsWith(lower)) return true;
        return false;
      }
      return projectDeps.has(lower);
    });
    if (depMatch) { active.push(fw.name); continue; }

    const importMatch = fw.detectionImports.some((s) => text.includes(s));
    if (importMatch) active.push(fw.name);
  }
  return active;
}

// ─── Application ────────────────────────────────────────────────────────────

export interface JsonFinding extends Finding {
  framework?: string;
}

// ±20 lines — strikes a balance between missing taint flow across short
// helper-variable chains (common in real code: taint source → one or two
// str_replace / trim / intval steps → sink) and over-firing when a sink
// happens to share a file with an unrelated taint source.
const TAINT_WINDOW = 20;

function lineHasTaintSource(line: string): boolean {
  return TAINT_SOURCES.some((re) => re.test(line));
}

export function applyCompiledRules(
  text: string,
  languageId: string,
  startLine: number,
  suppressedRules: string[],
  rules: CompiledRule[],
  skipRuleIds: Set<string> = new Set()
): JsonFinding[] {
  const rawLines  = text.split("\n");
  const codeLines = rawLines.map(stripLineComment);
  const findings: JsonFinding[] = [];
  const seen = new Set<string>();

  // Precompute per-line taint flags once per file — cheap and shared across rules.
  const taintedLines: boolean[] = codeLines.map(lineHasTaintSource);

  for (const rule of rules) {
    if (suppressedRules.includes(rule.ruleId)) continue;
    if (skipRuleIds.has(rule.ruleId)) continue;

    // File-scope safeguard: if the protection is configured anywhere in the
    // file (e.g. `helmet()` in app setup), the rule is satisfied for the
    // whole file — skip it entirely.
    if (rule.safeguardScope === "file" && rule.safeguards.length > 0) {
      const fileHasSafeguard = rule.safeguards.some((rg) =>
        codeLines.some((cl) => rg.test(cl))
      );
      if (fileHasSafeguard) continue;
    }

    for (let i = 0; i < codeLines.length; i++) {
      const rawLine  = rawLines[i];
      const codeLine = codeLines[i];

      // Respect line-level shieldprompt-ignore comments (check raw line so
      // the comment itself is still visible).
      if (rawLine.includes("shieldprompt-ignore")) {
        const m = rawLine.match(/shieldprompt-ignore:\s*([\w-]+)/);
        if (!m || m[1] === rule.ruleId) continue;
      }

      // Line-scope safeguard: only the lines that themselves contain the
      // protection are skipped. Checked against the comment-stripped form so
      // a commented-out sanitizer doesn't silence the rule.
      if (
        rule.safeguardScope === "line" &&
        rule.safeguards.some((rg) => rg.test(codeLine))
      ) {
        continue;
      }

      // Taint gate: rules marked requiresTaint only fire when a known taint
      // source is present within ±TAINT_WINDOW lines of the candidate match.
      if (rule.requiresTaint) {
        const lo = Math.max(0, i - TAINT_WINDOW);
        const hi = Math.min(codeLines.length - 1, i + TAINT_WINDOW);
        let inWindow = false;
        for (let j = lo; j <= hi; j++) {
          if (taintedLines[j]) { inWindow = true; break; }
        }
        if (!inWindow) continue;
      }

      for (const p of rule.patterns) {
        p.regex.lastIndex = 0;
        const match = p.regex.exec(codeLine);
        if (!match) continue;

        const key = `${rule.ruleId}:${i + startLine}:${match.index}`;
        if (seen.has(key)) break;
        seen.add(key);

        findings.push({
          line:     i + startLine,
          col:      match.index ?? 0,
          severity: rule.severity,
          ruleId:   rule.ruleId,
          message:  rule.message,
          detail:   rule.detail,
          cves:     rule.cves,
          framework: rule.framework,
          category:  rule.category,
        });
        break;
      }
    }
  }

  return findings;
}

export function getLanguageRules(
  loaded: LoadedRules,
  languageId: string
): CompiledRule[] {
  return loaded.languageRules.get(languageId) ?? [];
}

export function getFrameworkRules(
  loaded: LoadedRules,
  frameworkNames: string[],
  languageId: string
): CompiledRule[] {
  const out: CompiledRule[] = [];
  for (const name of frameworkNames) {
    const rules = loaded.frameworkRules.get(name);
    if (!rules) continue;
    // Framework rules tag the expected language, but we loaded them
    // language-agnostically — trust the framework detection itself as the
    // language gate, since each framework is language-specific anyway.
    void languageId;
    out.push(...rules);
  }
  return out;
}

// ─── Cross-layer category dedup ─────────────────────────────────────────────
//
// Static, semantic, and JSON rule layers often flag the same underlying issue
// (e.g. an SQL concatenation sink) under different ruleIds. When two or more
// findings on the SAME line clearly map to the same category, keep the most
// specific one so the panel doesn't show near-duplicates. We only dedup
// within a conservative, explicit category list — findings that don't match
// any category are left alone to avoid silently hiding genuine issues.

// NOTE: intentionally no trailing \b — rule IDs like "sql-injection-generic"
// should still match the "sql-injection" category even though the fragment
// is followed by more word characters.
const CATEGORY_FRAGMENTS: Array<[string, RegExp]> = [
  ["sql-injection",        /(sql.*inject|sqli|sql-concat|query.*concat|raw.*query|unsafe.*query)/i],
  ["command-injection",    /(command.*inject|cmd.*inject|shell.*inject|exec.*inject|unsafe.*exec|spawn.*inject)/i],
  ["path-traversal",       /(path.*traversal|dir.*traversal|unsafe.*path)/i],
  ["xss",                  /(xss|dangerously.*html|inner.*html.*inject|unsafe.*html|sanitize.*html)/i],
  ["ssrf",                 /(ssrf|server.*side.*request)/i],
  ["prototype-pollution",  /(prototype.*pollut|__proto__)/i],
  ["deserialization",      /(unsafe.*deserial|pickle.*load|yaml.*load|unsafe.*yaml)/i],
  ["open-redirect",        /(open.*redirect|unsafe.*redirect)/i],
];

// Explicit `category` on a finding wins; fall back to the ruleId-regex
// heuristic for rules that predate the field (hardcoded rules, unlabelled
// JSON rules). This lets us migrate rules to explicit categories
// incrementally without losing dedup coverage.
function findingCategory(f: Finding): string | null {
  if (f.category && f.category.length > 0) return f.category;
  for (const [cat, re] of CATEGORY_FRAGMENTS) {
    if (re.test(f.ruleId)) return cat;
  }
  return null;
}

/**
 * Dedup findings across layers when multiple ruleIds clearly describe the
 * same category on the same line. Prefers framework-tagged findings, then
 * longer (more specific) ruleIds, then first-seen. Findings outside the
 * known category list pass through untouched.
 */
export function categoryDedup<T extends Finding & { framework?: string }>(
  findings: T[]
): T[] {
  type Slot = { idx: number; f: T; cat: string };
  const byKey = new Map<string, Slot>();
  const keep  = new Set<number>();

  // First pass: findings with no known category are always kept.
  const categorized: Slot[] = [];
  findings.forEach((f, idx) => {
    const cat = findingCategory(f);
    if (!cat) { keep.add(idx); return; }
    categorized.push({ idx, f, cat });
  });

  // Second pass: collapse by (line, category).
  for (const slot of categorized) {
    const key = `${slot.f.line}:${slot.cat}`;
    const prev = byKey.get(key);
    if (!prev) { byKey.set(key, slot); continue; }

    const a = prev.f, b = slot.f;
    const aFw = a.framework ? 1 : 0;
    const bFw = b.framework ? 1 : 0;
    if (bFw > aFw) { byKey.set(key, slot); continue; }
    if (bFw < aFw) continue;
    if (b.ruleId.length > a.ruleId.length) { byKey.set(key, slot); continue; }
    // else keep `prev`
  }

  for (const slot of byKey.values()) keep.add(slot.idx);

  const result: T[] = [];
  findings.forEach((f, idx) => { if (keep.has(idx)) result.push(f); });
  return result;
}
