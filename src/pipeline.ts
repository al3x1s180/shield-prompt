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
  rules: LoadedRules | undefined
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

  const sevWeight: Record<string, number> = { critical: 0, warning: 1, info: 2 };
  deduped.sort((a, b) =>
    a.line !== b.line ? a.line - b.line : (sevWeight[a.severity] ?? 3) - (sevWeight[b.severity] ?? 3)
  );
  return deduped;
}
