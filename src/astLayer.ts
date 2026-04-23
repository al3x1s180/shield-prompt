// Phase 1 AST layer: a lightweight tokenizer for identifying
// "non-executable" byte ranges in source code — comments and strings.
//
// Why hand-rolled instead of tree-sitter: for the job of "is this byte offset
// inside a comment/string literal?", a ~200-line tokenizer ships with zero
// dependencies, zero bundle bloat, and zero WASM runtime risk.
//
// Phase 1   (1.1.2): comment filtering — drop findings inside comments.
// Phase 1.5 (1.1.3): string-literal filtering — drop findings inside string
//                    literals, UNLESS the rule is credential-like (AWS keys,
//                    JWTs, etc. ARE meaningful inside strings).
//
// This file is self-contained and framework-agnostic.

import { Finding } from "./analyser";

export type Range = [number, number];         // [start, end) byte offsets

export interface TokenizedText {
  comments: Range[];
  strings:  Range[];
}

// ─── Public API ─────────────────────────────────────────────────────────────

// Legacy alias used by callers that only care about comments.
export function commentRanges(text: string, languageId: string): Range[] {
  return tokenize(text, languageId).comments;
}

// Full tokenization — returns both comment and string ranges.
export function tokenize(text: string, languageId: string): TokenizedText {
  const lang = canonicalLang(languageId);
  if (lang === "javascript") return jsTokenize(text);
  if (lang === "python")     return pyTokenize(text);
  return { comments: [], strings: [] };
}

function canonicalLang(id: string): "javascript" | "python" | "other" {
  if (id === "typescript" || id === "javascript" ||
      id === "javascriptreact" || id === "typescriptreact") {
    return "javascript";
  }
  if (id === "python") return "python";
  return "other";
}

// ─── JS / TS ────────────────────────────────────────────────────────────────
function jsTokenize(text: string): TokenizedText {
  const comments: Range[] = [];
  const strings:  Range[] = [];
  const n = text.length;
  let i = 0;

  while (i < n) {
    const c    = text[i];
    const next = i + 1 < n ? text[i + 1] : "";

    if (c === "/" && next === "/") {
      const start = i;
      i += 2;
      while (i < n && text[i] !== "\n") i++;
      comments.push([start, i]);
      continue;
    }

    if (c === "/" && next === "*") {
      const start = i;
      i += 2;
      while (i < n - 1 && !(text[i] === "*" && text[i + 1] === "/")) i++;
      i = Math.min(n, i + 2);
      comments.push([start, i]);
      continue;
    }

    if (c === '"' || c === "'") {
      const quote = c;
      const start = i;
      i++;
      while (i < n && text[i] !== quote && text[i] !== "\n") {
        if (text[i] === "\\") i++;
        i++;
      }
      if (i < n) i++;
      strings.push([start, i]);
      continue;
    }

    if (c === "`") {
      const start = i;
      i++;
      let hasInterpolation = false;
      while (i < n && text[i] !== "`") {
        if (text[i] === "\\") { i++; i++; continue; }
        if (text[i] === "$" && text[i + 1] === "{") {
          hasInterpolation = true;
          // Skip past ${...} so we don't confuse the inner code for template
          // content. Depth-count braces; strings inside interpolation ignored.
          i += 2;
          let depth = 1;
          while (i < n && depth > 0) {
            if (text[i] === "{") depth++;
            else if (text[i] === "}") depth--;
            if (depth === 0) break;
            i++;
          }
        }
        i++;
      }
      if (i < n) i++;
      // Template literals WITH interpolation are part-string, part-code.
      // A finding like SQL injection inside an interpolated template is a
      // real vulnerability, not an FP — so don't mark them as strings here.
      // Only plain template literals (no `${}`) are treated as strings.
      if (!hasInterpolation) strings.push([start, i]);
      continue;
    }

    i++;
  }

  return { comments, strings };
}

// ─── Python ─────────────────────────────────────────────────────────────────
function pyTokenize(text: string): TokenizedText {
  const comments: Range[] = [];
  const strings:  Range[] = [];
  const n = text.length;
  let i = 0;

  while (i < n) {
    const c = text[i];

    if (c === "#") {
      const start = i;
      while (i < n && text[i] !== "\n") i++;
      comments.push([start, i]);
      continue;
    }

    if (c === '"' || c === "'") {
      const quote = c;
      const start = i;
      if (text[i + 1] === quote && text[i + 2] === quote) {
        i += 3;
        while (i < n - 2 && !(text[i] === quote && text[i + 1] === quote && text[i + 2] === quote)) {
          if (text[i] === "\\") i++;
          i++;
        }
        i = Math.min(n, i + 3);
        strings.push([start, i]);
        continue;
      }
      i++;
      while (i < n && text[i] !== quote && text[i] !== "\n") {
        if (text[i] === "\\") i++;
        i++;
      }
      if (i < n) i++;
      strings.push([start, i]);
      continue;
    }

    i++;
  }

  return { comments, strings };
}

// ─── Range lookup ───────────────────────────────────────────────────────────

// Binary search — ranges must be sorted by start offset.
export function isInRange(offset: number, ranges: Range[]): boolean {
  let lo = 0, hi = ranges.length;
  while (lo < hi) {
    const mid       = (lo + hi) >>> 1;
    const [s, e]    = ranges[mid];
    if (offset < s)       hi = mid;
    else if (offset >= e) lo = mid + 1;
    else                  return true;
  }
  return false;
}

// Legacy alias (Phase 1 only used comments).
export const isInComment = isInRange;

function lineColToOffset(text: string, line: number, col: number): number {
  let offset      = 0;
  let currentLine = 0;
  while (currentLine < line && offset < text.length) {
    if (text[offset] === "\n") currentLine++;
    offset++;
  }
  return Math.min(text.length, offset + col);
}

// ─── Credential-rule detection ──────────────────────────────────────────────
// These rules detect hardcoded credentials / secrets / tokens. A match from
// any of these rules is meaningful even when it appears inside a string
// literal — in fact, it's nearly ALWAYS inside a string literal, because that's
// how credentials get committed. So the string filter explicitly exempts them.
const CREDENTIAL_RULE_PATTERNS: RegExp[] = [
  /secret/i,
  /token/i,
  /password/i,
  /api[_-]?key/i,
  /credential/i,
  /private[_-]?key/i,
  /hardcoded/i,
  /^py-(?:.*(?:secret|token|password|key))/i,
];

export function isCredentialRule(ruleId: string): boolean {
  return CREDENTIAL_RULE_PATTERNS.some((re) => re.test(ruleId));
}

// ─── High-level filter ──────────────────────────────────────────────────────

// Drops findings that fall inside a comment or (for non-credential rules)
// inside a string literal. Safe to call on any language — returns input
// unchanged for languages we don't tokenize.
export function filterFindingsInNonCode<T extends Finding>(
  text: string,
  languageId: string,
  findings: T[]
): T[] {
  if (findings.length === 0) return findings;
  const { comments, strings } = tokenize(text, languageId);
  if (comments.length === 0 && strings.length === 0) return findings;

  return findings.filter((f) => {
    const offset = lineColToOffset(text, f.line, f.col ?? 0);
    if (isInRange(offset, comments)) return false;
    // Inside a string: drop UNLESS this rule is credential-like.
    if (isInRange(offset, strings) && !isCredentialRule(f.ruleId)) return false;
    return true;
  });
}

// Kept for backward compatibility; new callers should use filterFindingsInNonCode.
export function filterFindingsInComments<T extends Finding>(
  text: string,
  languageId: string,
  findings: T[]
): T[] {
  if (findings.length === 0) return findings;
  const { comments } = tokenize(text, languageId);
  if (comments.length === 0) return findings;
  return findings.filter((f) => {
    const offset = lineColToOffset(text, f.line, f.col ?? 0);
    return !isInRange(offset, comments);
  });
}
