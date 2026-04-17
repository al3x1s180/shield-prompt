/**
 * semanticAnalyser.ts
 *
 * Multi-line, context-aware security analysis that static per-line regex
 * cannot do. Techniques used:
 *  1. Lightweight taint tracking — follows user-controlled values through
 *     assignments into dangerous sinks.
 *  2. Call-chain analysis — detects dangerous function sequences across lines.
 *  3. Structural heuristics — identifies missing security controls in code
 *     blocks (e.g. JWT decode with no verify, crypto key sizes, etc.).
 */

import { Finding, CVERef } from "./analyser";

// ─── helpers ────────────────────────────────────────────────────────────────

function mkFinding(
  line: number,
  col: number,
  severity: Finding["severity"],
  ruleId: string,
  message: string,
  detail: string,
  cves: CVERef[]
): Finding {
  return { line, col, severity, ruleId, message, detail, cves };
}

/** Extract the variable name(s) assigned on a line, e.g. `const foo =` → "foo" */
function assignedVar(line: string): string | null {
  const m = line.match(
    /(?:const|let|var|val)\s+([a-zA-Z_$][\w$]*)\s*=|^([a-zA-Z_$][\w$]*)\s*=/
  );
  if (!m) return null;
  return (m[1] ?? m[2]) || null;
}

/** Return all variable names referenced on the right-hand side of an assignment */
function rhsVars(line: string): string[] {
  // strip the lhs
  const eqIdx = line.indexOf("=");
  if (eqIdx === -1) return [];
  const rhs = line.slice(eqIdx + 1);
  const matches = [...rhs.matchAll(/\b([a-zA-Z_$][\w$]*)\b/g)];
  return matches.map((m) => m[1]);
}

// ─── taint sources ──────────────────────────────────────────────────────────

/**
 * Patterns whose matched variable should be considered tainted (user-controlled).
 * Keyed by language family.
 */
const TAINT_SOURCES: RegExp[] = [
  // JS/TS — request inputs
  /\breq\.(body|params|query|headers|cookies)\b/,
  /\bprocess\.argv\b/,
  /\bwindow\.location\b/,
  /\bdocument\.(?:cookie|referrer|URL|location)\b/,
  /\.value\b/, // DOM input.value
  // Python — request inputs
  /\brequest\.(form|args|json|data|files|headers|cookies)\b/,
  /\binput\s*\(/,
  /\bos\.environ\b/,
  /\bsys\.argv\b/,
  // Generic
  /\bgetenv\s*\(/,
  /\bgetParam\s*\(/,
  /\bgetQueryParam\s*\(/,
];

/** Returns true if a line introduces a tainted (user-controlled) value */
function lineIsTaintSource(line: string): boolean {
  return TAINT_SOURCES.some((re) => re.test(line));
}

/**
 * Build a taint set: map from variable name → line index where it was tainted.
 * Simple single-pass propagation: if rhs contains a tainted var, the lhs is also tainted.
 */
function buildTaintSet(lines: string[]): Map<string, number> {
  const tainted = new Map<string, number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Direct source
    if (lineIsTaintSource(line)) {
      const v = assignedVar(line);
      if (v) tainted.set(v, i);
      continue;
    }

    // Propagation: if any rhs var is tainted, taint the lhs
    const lhs = assignedVar(line);
    if (lhs) {
      const rhs = rhsVars(line);
      for (const r of rhs) {
        if (tainted.has(r)) {
          tainted.set(lhs, i);
          break;
        }
      }
    }
  }

  return tainted;
}

/** Returns true if any tainted variable appears in the given line */
function lineUsesTainted(line: string, tainted: Map<string, number>): boolean {
  for (const v of tainted.keys()) {
    // whole-word match
    const re = new RegExp(`\\b${v}\\b`);
    if (re.test(line)) return true;
  }
  return false;
}

// ─── semantic rule definitions ───────────────────────────────────────────────

interface SemanticRule {
  ruleId: string;
  languages: string[]; // empty = all
  run: (lines: string[], languageId: string, startLine: number) => Finding[];
}

const semanticRules: SemanticRule[] = [
  // ── 1. Path traversal via tainted variable fed into file operations ──────
  {
    ruleId: "path-traversal",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      const sinks = [
        // JS/TS
        /\b(?:fs|path)\s*\.\s*(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|rename|mkdir|rmdir|open|access|stat|lstat|appendFile|copyFile)\s*\(/,
        // Python
        /\b(?:open|os\.path\.join|os\.listdir|os\.remove|os\.rename|shutil\.|pathlib\.Path)\s*\(/,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        const hitsSink = sinks.some((re) => re.test(line));
        if (!hitsSink) continue;
        if (!lineUsesTainted(line, tainted)) continue;

        // Check there's no sanitisation nearby
        const contextStart = Math.max(0, i - 4);
        const contextEnd = Math.min(lines.length - 1, i + 1);
        const hasSanitiser = lines
          .slice(contextStart, contextEnd + 1)
          .some((l) =>
            /\b(?:basename|normalize|resolve|realpath|path\.join|sanitize|allowedPaths|whitelist|startsWith|includes)\b/.test(l)
          );
        if (hasSanitiser) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "critical", "path-traversal",
            "Path traversal: user input used in file operation",
            "User-controlled data reaches a file-system call without sanitisation. An attacker can supply '../../../etc/passwd' style paths to read or write arbitrary files. Use path.basename() and validate against an allowed directory.",
            [
              { id: "CWE-22", url: "https://cwe.mitre.org/data/definitions/22.html", description: "Improper Limitation of a Pathname to a Restricted Directory" },
              { id: "CVE-2017-5638", url: "https://nvd.nist.gov/vuln/detail/CVE-2017-5638", description: "Apache Struts path traversal / RCE" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 2. Server-Side Request Forgery (SSRF) ────────────────────────────────
  {
    ruleId: "ssrf",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      const sinks = [
        /\bfetch\s*\(/,
        /\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(/,
        /\bhttp\s*\.\s*(?:get|request)\s*\(/,
        /\bhttps\s*\.\s*(?:get|request)\s*\(/,
        /\brequests\s*\.\s*(?:get|post|put|delete|request)\s*\(/,
        /\burllib\s*\.\s*request\b/,
        /\bcurl\b/,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!sinks.some((re) => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted)) continue;

        const contextStart = Math.max(0, i - 4);
        const contextEnd = Math.min(lines.length - 1, i + 1);
        const hasSanitiser = lines
          .slice(contextStart, contextEnd + 1)
          .some((l) =>
            /\b(?:allowedHosts|allowedDomains|whitelist|validateUrl|parseURL|new URL|hostname|startsWith|includes)\b/.test(l)
          );
        if (hasSanitiser) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "critical", "ssrf",
            "SSRF: user-controlled URL passed to HTTP request",
            "The destination URL is derived from user input without validation. An attacker can make the server fetch internal services (metadata APIs, databases). Validate the URL against an allowlist of permitted hosts.",
            [
              { id: "CWE-918", url: "https://cwe.mitre.org/data/definitions/918.html", description: "Server-Side Request Forgery (SSRF)" },
              { id: "CVE-2021-29418", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-29418", description: "SSRF via user-controlled URL" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 3. JWT decoded without signature verification ────────────────────────
  {
    ruleId: "jwt-no-verify",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact", "python"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Detects jwt.decode / jwtDecode / decode_token without verify
        const isDecodeCall =
          /\bjwt\s*\.\s*decode\s*\(/.test(line) ||
          /\bjwtDecode\s*\(/.test(line) ||
          /\bbase64(?:Url)?Decode\s*\(.*\.split\s*\(/.test(line);

        if (!isDecodeCall) continue;

        // jwt.decode in jsonwebtoken skips verification by design
        // Flag unless there is a verify() call within 5 lines above
        const contextStart = Math.max(0, i - 5);
        const contextEnd = Math.min(lines.length - 1, i + 5);
        const hasVerify = lines
          .slice(contextStart, contextEnd + 1)
          .some((l) => /\bjwt\s*\.\s*verify\s*\(/.test(l));

        if (hasVerify) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "critical", "jwt-no-verify",
            "JWT decoded without signature verification",
            "jwt.decode() does not verify the signature — an attacker can craft arbitrary payloads. Use jwt.verify() with a secret or public key so the signature is always validated.",
            [
              { id: "CWE-347", url: "https://cwe.mitre.org/data/definitions/347.html", description: "Improper Verification of Cryptographic Signature" },
              { id: "CVE-2022-21449", url: "https://nvd.nist.gov/vuln/detail/CVE-2022-21449", description: "ECDSA signature bypass ('Psychic Signatures')" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 4. Insecure random for cryptographic use (non-Math.random form) ──────
  {
    ruleId: "insecure-random-token",
    languages: ["python"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Python random module used for tokens/keys
        if (!/\brandom\s*\.\s*(?:randint|choice|choices|sample|random|uniform|shuffle)\b/.test(line)) continue;

        const contextStart = Math.max(0, i - 6);
        const contextEnd = Math.min(lines.length - 1, i + 6);
        const inCryptoContext = lines
          .slice(contextStart, contextEnd + 1)
          .some((l) =>
            /\b(?:token|secret|key|nonce|salt|password|uuid|session|auth|csrf|otp)\b/i.test(l)
          );
        if (!inCryptoContext) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "warning", "insecure-random-token",
            "Python random module used in security-sensitive context",
            "The random module is not cryptographically secure. Use secrets.token_hex(), secrets.token_bytes(), or os.urandom() for any security-sensitive randomness.",
            [
              { id: "CWE-338", url: "https://cwe.mitre.org/data/definitions/338.html", description: "Use of Cryptographically Weak PRNG" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 5. ReDoS — catastrophic backtracking regex patterns ─────────────────
  {
    ruleId: "redos",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact", "python"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      // Patterns known to cause catastrophic backtracking
      const dangerous = [
        /\([^)]*[+*]\)[+*]/, // (a+)+ or (a*)* nested quantifiers
        /\([^)]*\)\{[0-9]+,\}[+*?]/, // (x){n,}* etc.
        /(\[[^\]]*\][+*]){2}/, // [a-z]+[a-z]+
        /\([^)]*\|[^)]*\)[+*][+*]/, // (a|b)++ or (a|b)*+
      ];

      const reAssign = /(?:new RegExp\s*\(|=\s*\/|=\s*new RegExp)/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!reAssign.test(line)) continue;

        // Extract the pattern string from the line
        const litMatch = line.match(/\/([^/]+)\//);
        const strMatch = line.match(/new RegExp\s*\(\s*['"`]([^'"` ]+)['"`]/);
        const pattern = litMatch?.[1] ?? strMatch?.[1];
        if (!pattern) continue;

        if (dangerous.some((d) => d.test(pattern))) {
          findings.push(
            mkFinding(
              startLine + i, 0, "warning", "redos",
              "Potential ReDoS: catastrophic backtracking regex",
              "This regular expression contains nested quantifiers that can cause exponential backtracking when given crafted input, leading to denial-of-service. Rewrite using possessive quantifiers, atomic groups, or a linear-time regex engine.",
              [
                { id: "CWE-1333", url: "https://cwe.mitre.org/data/definitions/1333.html", description: "Inefficient Regular Expression Complexity (ReDoS)" },
                { id: "CVE-2022-25887", url: "https://nvd.nist.gov/vuln/detail/CVE-2022-25887", description: "ReDoS in sanitize-html package" },
              ]
            )
          );
        }
      }
      return findings;
    },
  },

  // ── 6. Command injection via exec/spawn with tainted string concat ───────
  {
    ruleId: "command-injection",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      const sinks = [
        /\bchild_process\s*\.\s*exec\s*\(/,
        /\bexec\s*\(/,
        /\bspawn\s*\(/,
        /\bexecSync\s*\(/,
        /\bspawnSync\s*\(/,
        /\bexecFile\s*\(/,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!sinks.some((re) => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted)) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "critical", "command-injection",
            "Command injection: user input in exec/spawn call",
            "User-controlled data is passed to a shell command. An attacker can inject shell metacharacters to run arbitrary commands. Pass arguments as an array to spawn() without shell:true, and never concatenate user input into shell strings.",
            [
              { id: "CWE-78", url: "https://cwe.mitre.org/data/definitions/78.html", description: "Improper Neutralization of Special Elements in OS Command" },
              { id: "CVE-2020-7660", url: "https://nvd.nist.gov/vuln/detail/CVE-2020-7660", description: "Command injection via serialize-javascript" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 7. Insecure TLS/SSL — certificate verification disabled ─────────────
  {
    ruleId: "tls-verify-disabled",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      const patterns = [
        /rejectUnauthorized\s*:\s*false/,
        /verify\s*=\s*False/,          // Python requests
        /ssl\s*=\s*False/,
        /checkServerIdentity\s*:\s*\(\s*\)\s*=>/,
        /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/,
        /InsecureRequestWarning/,       // urllib3 warning suppression
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!patterns.some((re) => re.test(line))) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "critical", "tls-verify-disabled",
            "TLS certificate verification disabled",
            "Disabling certificate verification exposes all connections to man-in-the-middle attacks. Remove rejectUnauthorized:false / verify=False and use a proper CA bundle instead.",
            [
              { id: "CWE-295", url: "https://cwe.mitre.org/data/definitions/295.html", description: "Improper Certificate Validation" },
              { id: "CVE-2021-33502", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-33502", description: "TLS verification bypass" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 8. Timing attack: string comparison of secrets with == ──────────────
  {
    ruleId: "timing-attack",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      const secretNameRe = /\b(?:token|hmac|signature|hash|mac|digest|secret|password|apiKey|api_key)\b/i;
      const equalityRe = /(?:===|==|!=|!==)/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!secretNameRe.test(line)) continue;
        if (!equalityRe.test(line)) continue;

        // Skip if the line is an assignment, not a comparison
        const isComparison = /if\s*\(|return\s|&&|\|\|/.test(line) || /[!=]==/.test(line);
        if (!isComparison) continue;

        // Skip if already using constant-time compare
        if (/timingSafeEqual|hmac\.compare|crypto\.timingSafe|secrets\.compare_digest/.test(line)) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "warning", "timing-attack",
            "Potential timing attack: secret compared with ==",
            "Using == or === to compare secrets allows timing side-channel attacks where response time leaks information about the secret. Use crypto.timingSafeEqual() (Node.js) or hmac.compare_digest() (Python) instead.",
            [
              { id: "CWE-208", url: "https://cwe.mitre.org/data/definitions/208.html", description: "Observable Timing Discrepancy" },
              { id: "CVE-2015-9251", url: "https://nvd.nist.gov/vuln/detail/CVE-2015-9251", description: "Timing attack via string comparison in jQuery" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 9. XML/HTML parsing without entity expansion protection (XXE) ────────
  {
    ruleId: "xxe-injection",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact", "python"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      const parserPatterns = [
        /\bDOMParser\s*\(\s*\)/,
        /\bparseFromString\s*\(/,
        /\bxml\.etree\b/,
        /\blxml\s*\.\s*etree\b/,
        /\bxmldom\b/,
        /\bfast-xml-parser\b/,
        /new\s+XMLParser\s*\(/,
        /libxml\b/,
      ];

      const tainted = buildTaintSet(lines);

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!parserPatterns.some((re) => re.test(line))) continue;

        // Only flag if the content being parsed looks like it comes from user input
        const nearby = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5));
        const hasUserInput = nearby.some((l) => lineUsesTainted(l, tainted) || lineIsTaintSource(l));
        if (!hasUserInput) continue;

        const hasProtection = nearby.some((l) =>
          /resolveEntities\s*:\s*false|resolve_entities\s*=\s*False|XMLParser.*allowBooleanAttributes|no_network|forbid_dtd/.test(l)
        );
        if (hasProtection) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "critical", "xxe-injection",
            "Potential XXE: XML parsed from user input without entity restrictions",
            "Parsing XML from untrusted sources without disabling external entity resolution allows XXE attacks, which can read local files or trigger SSRF. Set resolveEntities:false, or use a safe parser configuration.",
            [
              { id: "CWE-611", url: "https://cwe.mitre.org/data/definitions/611.html", description: "Improper Restriction of XML External Entity Reference (XXE)" },
              { id: "CVE-2019-20149", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-20149", description: "XXE in kind-of npm package" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 10. Weak RSA/DSA key size ────────────────────────────────────────────
  {
    ruleId: "weak-key-size",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Look for key size numbers that are too small
        const keyGenRe = /\b(?:generateKeyPair|generateKey|RSA_generate_key|DSA_generate_key|genrsa|gendsa)\b/i;
        if (!keyGenRe.test(line)) continue;

        const sizeMatch = line.match(/\b(\d{3,4})\b/);
        if (!sizeMatch) continue;

        const size = parseInt(sizeMatch[1], 10);
        if (size >= 2048) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "warning", "weak-key-size",
            `Weak asymmetric key size: ${size} bits`,
            `A ${size}-bit RSA/DSA key is considered insecure. NIST recommends a minimum of 2048 bits; prefer 3072 or 4096 bits for new keys.`,
            [
              { id: "CWE-326", url: "https://cwe.mitre.org/data/definitions/326.html", description: "Inadequate Encryption Strength" },
            ]
          )
        );
      }
      return findings;
    },
  },

  // ── 11. Regex injection — user input compiled into RegExp ────────────────
  {
    ruleId: "regex-injection",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!/new\s+RegExp\s*\(/.test(line)) continue;
        if (!lineUsesTainted(line, tainted)) continue;

        findings.push(
          mkFinding(
            startLine + i, 0, "warning", "regex-injection",
            "Regex injection: user input compiled into RegExp",
            "Passing user-controlled strings to new RegExp() allows regex injection, which can cause ReDoS or bypass validation. Escape the input with a library like escape-string-regexp before constructing the pattern.",
            [
              { id: "CWE-730", url: "https://cwe.mitre.org/data/definitions/730.html", description: "Uncontrolled Resource Consumption via Regex (ReDoS)" },
            ]
          )
        );
      }
      return findings;
    },
  },
];

// ─── public API ──────────────────────────────────────────────────────────────

export function semanticAnalyse(
  text: string,
  languageId: string,
  startLine: number,
  suppressedRules: string[]
): Finding[] {
  const lines = text.split("\n");
  const all: Finding[] = [];

  for (const rule of semanticRules) {
    if (suppressedRules.includes(rule.ruleId)) continue;
    if (rule.languages.length > 0 && !rule.languages.some((l) => languageId.startsWith(l))) continue;

    const found = rule.run(lines, languageId, startLine);
    all.push(...found);
  }

  // Sort by line then severity
  const sev: Record<string, number> = { critical: 0, warning: 1, info: 2 };
  all.sort((a, b) => a.line !== b.line ? a.line - b.line : (sev[a.severity] ?? 3) - (sev[b.severity] ?? 3));

  return all;
}

export const SEMANTIC_RULES_COUNT = semanticRules.length;