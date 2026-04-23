// Pure analysis pipeline — zero VSCode dependency so it can be unit-tested
// and reused from both the paste handler and the project scanner.

import { analyse, Finding } from "./analyser";
import { semanticAnalyse } from "./semanticAnalyser";
import {
  LoadedRules,
  detectFrameworks,
  applyCompiledRules,
  getLanguageRules,
  getFrameworkRules,
  categoryDedup,
} from "./ruleLoader";
import { filterFindingsInNonCode, isCredentialRule } from "./astLayer";
import { filterFindingsForTestFile } from "./testFileHeuristic";

const SEV_WEIGHT: Record<string, number> = { critical: 0, warning: 1, info: 2 };

function filterBySeverity<T extends Finding>(
  findings: T[],
  minSeverity: "critical" | "warning" | "info"
): T[] {
  const threshold = SEV_WEIGHT[minSeverity] ?? 1;
  return findings.filter((f) => {
    // Credential findings are always kept — leaked secrets are never "too
    // minor to show".
    if (isCredentialRule(f.ruleId)) return true;
    const weight = SEV_WEIGHT[f.severity] ?? 3;
    return weight <= threshold;
  });
}

export interface AnalyseOptions {
  // Drops findings whose match position falls inside a comment or string
  // literal (credential rules exempt). Controlled by shieldprompt.astLayer.
  astLayer?: boolean;
  // When set AND the path matches a test-file pattern, drops all findings
  // except credential rules. Controlled by shieldprompt.skipNoisyInTests.
  filePath?: string;
  skipNoisyInTests?: boolean;
  // Hides findings below the given severity (warning | info). Credential
  // rules are always kept regardless of severity. Default "warning" = show
  // everything. Setting to "critical" = show only critical + credential.
  minSeverity?: "critical" | "warning" | "info";
}

// Runs every layer of analysis (hardcoded static, hardcoded semantic, JSON
// language rules, JSON framework rules), merges with dedup on line+ruleId,
// then collapses cross-layer near-duplicates via categoryDedup.
//
// Hardcoded findings win line+ruleId ties because they're pushed first.
export function analyseAllLayers(
  text: string,
  languageId: string,
  startLine: number,
  suppressed: string[],
  deps: Set<string>,
  rules: LoadedRules | undefined,
  options: AnalyseOptions = {}
): Finding[] {
  const staticFindings   = analyse(text, languageId, startLine, suppressed, deps);
  const semanticFindings = semanticAnalyse(text, languageId, startLine, suppressed);

  const seen   = new Set<string>();
  const merged: Finding[] = [];
  const push = (f: Finding): void => {
    const key = `${f.line}:${f.ruleId}`;
    if (seen.has(key)) return;
    seen.add(key);
    merged.push(f);
  };
  for (const f of staticFindings)   push(f);
  for (const f of semanticFindings) push(f);

  if (rules) {
    const langRules = getLanguageRules(rules, languageId);
    for (const f of applyCompiledRules(text, languageId, startLine, suppressed, langRules)) {
      push(f);
    }
    const activeFrameworks = detectFrameworks(text, deps, rules.frameworks);
    if (activeFrameworks.length > 0) {
      const fwRules = getFrameworkRules(rules, activeFrameworks, languageId);
      for (const f of applyCompiledRules(text, languageId, startLine, suppressed, fwRules)) {
        push(f);
      }
    }
  }

  const deduped = categoryDedup(merged);

  // AST layer: when enabled, drop findings whose position falls inside a
  // comment or inside a string literal. Credential-like rules (hardcoded
  // secrets, tokens, API keys) are exempt from the string filter because
  // those findings are meaningful inside strings by definition. Runs AFTER
  // dedup so cross-layer collapsing is not affected. On any tokenizer error,
  // fall back to the un-filtered list so the layer can never make the
  // pipeline worse than before.
  let final = deduped;
  if (options.astLayer) {
    try {
      final = filterFindingsInNonCode(text, languageId, deduped);
    } catch {
      final = deduped;
    }
  }

  // Test-file skip: for files under test/ spec/ fixtures/ etc., drop
  // behavior-class findings. Credential findings are preserved.
  if (options.skipNoisyInTests && options.filePath) {
    try {
      final = filterFindingsForTestFile(options.filePath, final);
    } catch {
      // keep `final` as-is
    }
  }

  // Severity cap — drops findings below the configured minimum, except
  // credential leaks which are always shown.
  if (options.minSeverity) {
    final = filterBySeverity(final, options.minSeverity);
  }

  final.sort((a, b) =>
    a.line !== b.line ? a.line - b.line : (SEV_WEIGHT[a.severity] ?? 3) - (SEV_WEIGHT[b.severity] ?? 3)
  );
  return final;
}
