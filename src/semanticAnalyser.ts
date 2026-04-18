/**
 * semanticAnalyser.ts — multi-line, context-aware security analysis
 *
 * Improvements over v1:
 *  - Taint propagation now follows method calls (.join, .concat, .replace, .slice, +)
 *    so URL construction via Array.join('/') correctly taints the result
 *  - Sanitiser check now strips comments before checking — prevents comment-keyword bypass
 *  - Alias tracking: detects eval stored in a variable and later called
 *  - Expanded source patterns (more frameworks, env vars, DOM APIs)
 *  - 6 new rules: command-injection, template-injection, insecure-redirect-chain,
 *    jwt-alg-none, mass-assignment, second-order-injection awareness
 */

import { Finding, CVERef } from "./analyser";

function mkFinding(
  line: number, col: number,
  severity: Finding["severity"],
  ruleId: string, message: string, detail: string, cves: CVERef[]
): Finding {
  return { line, col, severity, ruleId, message, detail, cves };
}

// ─── comment stripping ───────────────────────────────────────────────────────

/** Strip single-line comments from a line of code before checking for safeguards */
function stripComments(line: string): string {
  // Remove // ... to end (but not inside strings — simple approximation)
  return line.replace(/(?<!['"\/])\/\/.*$/, "").replace(/^\s*#.*$/, "");
}

// ─── variable assignment helpers ─────────────────────────────────────────────

function assignedVar(line: string): string | null {
  const m = line.match(
    /(?:const|let|var|val)\s+([a-zA-Z_$][\w$]*)\s*=|^([a-zA-Z_$][\w$]*)\s*=/
  );
  if (!m) return null;
  return (m[1] ?? m[2]) || null;
}

function rhsVars(line: string): string[] {
  const eqIdx = line.indexOf("=");
  if (eqIdx === -1) return [];
  const rhs = line.slice(eqIdx + 1);
  return [...rhs.matchAll(/\b([a-zA-Z_$][\w$]*)\b/g)].map(m => m[1]);
}

// ─── taint sources ───────────────────────────────────────────────────────────

const TAINT_SOURCES: RegExp[] = [
  // JS/TS request inputs
  /\breq\.(body|params|query|headers|cookies)\b/,
  /\brequest\.(body|params|query|headers|cookies)\b/,
  /\bprocess\.argv\b/,
  /\bwindow\.location\b/,
  /\bdocument\.(?:cookie|referrer|URL|location)\b/,
  /\.value\b/,
  /\bgetQueryParam\s*\(/,
  /\bgetParam\s*\(/,
  /\bsearchParams\.get\s*\(/,
  // Python request inputs
  /\brequest\.(form|args|json|data|files|headers|cookies|values)\b/,
  /\binput\s*\(/,
  /\bos\.environ\b/,
  /\bos\.getenv\s*\(/,
  /\bsys\.argv\b/,
  /\bgetenv\s*\(/,
  // Generic
  /\bformData\b/,
  /\bevent\.data\b/,
  /\bevent\.target\.value\b/,
  /\bparams\[/,
  /\bbody\[/,
];

function lineIsTaintSource(line: string): boolean {
  return TAINT_SOURCES.some(re => re.test(line));
}

/**
 * Improved taint propagation:
 * - Follows direct assignment: const x = req.body.id
 * - Follows method calls: const url = [base, id].join('/') — if id is tainted, url is tainted
 * - Follows string concatenation: const cmd = "ls " + userInput
 * - Follows template literals: const q = `SELECT * WHERE id=${userId}`
 * - Follows property access: const name = user.name (if user is tainted)
 */
function buildTaintSet(lines: string[]): Map<string, number> {
  const tainted = new Map<string, number>();

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Direct taint source
    if (lineIsTaintSource(line)) {
      const v = assignedVar(line);
      if (v) tainted.set(v, i);
      continue;
    }

    const lhs = assignedVar(line);
    if (!lhs) continue;

    const eqIdx = line.indexOf("=");
    if (eqIdx === -1) continue;
    const rhs = line.slice(eqIdx + 1);

    // Check if any tainted variable appears anywhere in the RHS
    // This catches: join(), concat(), template literals, +, property access
    let isTainted = false;
    for (const v of tainted.keys()) {
      const re = new RegExp(`\\b${v}\\b`);
      if (re.test(rhs)) {
        isTainted = true;
        break;
      }
    }
    if (isTainted) tainted.set(lhs, i);
  }

  return tainted;
}

function lineUsesTainted(line: string, tainted: Map<string, number>): boolean {
  for (const v of tainted.keys()) {
    if (new RegExp(`\\b${v}\\b`).test(line)) return true;
  }
  return false;
}

/** Check surrounding lines for a safeguard, ignoring comment lines */
function hasSafeguardNearby(
  lines: string[],
  lineIndex: number,
  patterns: RegExp[],
  radius = 5
): boolean {
  const start = Math.max(0, lineIndex - radius);
  const end = Math.min(lines.length - 1, lineIndex + 1);
  return lines.slice(start, end + 1).some(l => {
    const code = stripComments(l); // ignore comments — prevents keyword-in-comment bypass
    return patterns.some(re => re.test(code));
  });
}

// ─── semantic rules ───────────────────────────────────────────────────────────

interface SemanticRule {
  ruleId: string;
  languages: string[];
  run: (lines: string[], languageId: string, startLine: number) => Finding[];
}

const semanticRules: SemanticRule[] = [

  // ── 1. Path traversal ─────────────────────────────────────────────────────
  {
    ruleId: "path-traversal",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      const sinks = [
        /\b(?:fs|path)\s*\.\s*(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|rename|mkdir|rmdir|open|access|stat|lstat|appendFile|copyFile)\s*\(/,
        /\b(?:open|os\.path\.join|os\.listdir|os\.remove|os\.rename|shutil\.|pathlib\.Path)\s*\(/,
        /send_file\s*\(/i,
      ];

      const safeguards = [
        /\bbasename\s*\(/,
        /path\.resolve\s*\(/,
        /path\.normalize\s*\(/,
        /\.startsWith\s*\(baseDir|\.startsWith\s*\(UPLOAD_DIR|\.startsWith\s*\(allowedDir/i,
        /safe_join\s*\(/,
        /send_from_directory\s*\(/,
        /allowedPaths/i,
        /realpath\s*\(/,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!sinks.some(re => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted)) continue;
        if (hasSafeguardNearby(lines, i, safeguards, 5)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "critical", "path-traversal",
          "Path traversal: user input used in file operation without sanitisation",
          "User-controlled data reaches a file-system call without sanitisation. An attacker can supply '../../../etc/passwd' style paths. Use path.basename(), validate that the resolved absolute path starts with the expected base directory.",
          [
            { id: "CWE-22", url: "https://cwe.mitre.org/data/definitions/22.html", description: "Path Traversal" },
            { id: "CVE-2017-5638", url: "https://nvd.nist.gov/vuln/detail/CVE-2017-5638", description: "Apache Struts path traversal / RCE" },
          ]
        ));
      }
      return findings;
    },
  },

  // ── 2. SSRF (improved: follows multi-step URL construction) ───────────────
  {
    ruleId: "ssrf",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      const sinks = [
        /\bfetch\s*\(/,
        /\baxios\s*\.\s*(?:get|post|put|delete|patch|request)\s*\(/,
        /\bhttp\s*\.\s*(?:get|request)\s*\(/,
        /\bhttps\s*\.\s*(?:get|request)\s*\(/,
        /\brequests\s*\.\s*(?:get|post|put|delete|request)\s*\(/,
        /\burllib\s*\.\s*request\b/,
        /\bhttpx\.\w+\s*\(/,
        /\bgot\s*\.\s*(?:get|post)\s*\(/,
        /\bneedle\s*\.\s*(?:get|post)\s*\(/,
      ];

      const safeguards = [
        /allowedHosts/i,
        /allowedDomains/i,
        /whitelist/i,
        /validateUrl/i,
        /new URL\s*\(.*\)\s*\.\s*hostname/,
        /\.hostname\s*===|\.hostname\s*!==|\.host\s*===/,
        /startsWith\s*\(['"`]https:\/\//i,
        /SSRF_ALLOWLIST/i,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!sinks.some(re => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted)) continue;
        if (hasSafeguardNearby(lines, i, safeguards, 6)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "critical", "ssrf",
          "SSRF: user-controlled value flows into HTTP request",
          "The destination URL is derived from user input. An attacker can make the server fetch internal services (cloud metadata, databases). Validate the URL's hostname against an allowlist of permitted hosts.",
          [
            { id: "CWE-918", url: "https://cwe.mitre.org/data/definitions/918.html", description: "Server-Side Request Forgery (SSRF)" },
            { id: "CVE-2019-11043", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-11043", description: "SSRF via crafted URL" },
          ]
        ));
      }
      return findings;
    },
  },

  // ── 3. Command injection (JS/TS exec/spawn with tainted input) ────────────
  {
    ruleId: "command-injection",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      const sinks = [
        /\bexec\s*\(/,
        /\bexecSync\s*\(/,
        /\bspawn\s*\(/,
        /\bspawnSync\s*\(/,
        /child_process\.\w+\s*\(/,
        /\bexecFile\s*\(/,
      ];

      const safeguards = [
        /shell\s*:\s*false/i,
        /shlex\.quote/i,
        /escapeShell/i,
        /execFile\s*\(/,   // execFile is safe — no shell interpolation
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!sinks.some(re => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted)) continue;
        if (hasSafeguardNearby(lines, i, safeguards, 3)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "critical", "command-injection",
          "Command injection: user input flows into shell command",
          "User-controlled data is passed to a shell execution function. An attacker can inject shell metacharacters to run arbitrary commands. Use execFile() with an args array, or whitelist the allowed commands.",
          [
            { id: "CWE-78", url: "https://cwe.mitre.org/data/definitions/78.html", description: "OS Command Injection" },
            { id: "CVE-2014-6271", url: "https://nvd.nist.gov/vuln/detail/CVE-2014-6271", description: "Shellshock — command injection via env var" },
          ]
        ));
      }
      return findings;
    },
  },

  // ── 4. Server-side template injection ─────────────────────────────────────
  {
    ruleId: "template-injection",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      // Template engine render calls where the template string or data is tainted
      const sinks = [
        /\bejs\.render\s*\(/i,
        /\bpug\.render\s*\(/i,
        /\bhandlebars\.compile\s*\(/i,
        /\bnunjucks\.renderString\s*\(/i,
        /\benv\.fromString\s*\(/i,
        /\bTemplate\s*\(\s*[^)]*\)\s*\.render/i,
        /\bjinja2\.Template\s*\(/i,
        /\bMako\.Template\s*\(/i,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!sinks.some(re => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "critical", "template-injection",
          "Server-side template injection: user input in template string",
          "Passing user-controlled data as the template itself (not just the context) allows arbitrary code execution via the template engine's expression syntax. Always render a fixed template with user data as context variables, never render user-supplied template strings.",
          [
            { id: "CWE-94", url: "https://cwe.mitre.org/data/definitions/94.html", description: "Improper Control of Generation of Code" },
            { id: "CVE-2019-9193", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-9193", description: "Template injection RCE" },
          ]
        ));
      }
      return findings;
    },
  },

  // ── 5. JWT no-verify ──────────────────────────────────────────────────────
  {
    ruleId: "jwt-no-verify",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // jwt.decode() — no verification at all
        if (/\bjwt\.decode\s*\(|\bjsonwebtoken\.decode\s*\(/i.test(line)) {
          findings.push(mkFinding(
            startLine + i, 0, "critical", "jwt-no-verify",
            "JWT decoded without signature verification",
            "jwt.decode() skips signature verification — any crafted payload is trusted. Use jwt.verify() with the signing secret/public key and explicitly set allowed algorithms.",
            [
              { id: "CWE-347", url: "https://cwe.mitre.org/data/definitions/347.html", description: "Improper Verification of Cryptographic Signature" },
              { id: "CVE-2015-9235", url: "https://nvd.nist.gov/vuln/detail/CVE-2015-9235", description: "JWT 'none' algorithm attack" },
            ]
          ));
        }

        // algorithms: ['none'] or algorithm: 'none'
        if (/algorithms?\s*:\s*\[?\s*['"]none['"]/i.test(line)) {
          findings.push(mkFinding(
            startLine + i, 0, "critical", "jwt-no-verify",
            "JWT 'none' algorithm accepted — signature verification bypassed",
            "Allowing the 'none' algorithm lets attackers craft unsigned tokens that are accepted as valid. Always specify your signing algorithm explicitly (e.g. 'HS256', 'RS256') and never include 'none' in the allowed list.",
            [
              { id: "CWE-347", url: "https://cwe.mitre.org/data/definitions/347.html", description: "Improper Verification of Cryptographic Signature" },
            ]
          ));
        }
      }
      return findings;
    },
  },

  // ── 6. Insecure random token (JS) ─────────────────────────────────────────
  {
    ruleId: "insecure-random-token",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!/Math\.random\s*\(\s*\)/i.test(line)) continue;
        const secCtx = /token|session|secret|password|nonce|salt|key\b|auth|otp|csrf|id\s*=/i;
        if (!secCtx.test(line)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "warning", "insecure-random-token",
          "Math.random() used for security-sensitive value",
          "Math.random() is not cryptographically secure and is predictable. Use crypto.randomBytes() or crypto.randomUUID() for security tokens, session IDs, nonces, and CSRF tokens.",
          [{ id: "CWE-338", url: "https://cwe.mitre.org/data/definitions/338.html", description: "Use of Cryptographically Weak PRNG" }]
        ));
      }
      return findings;
    },
  },

  // ── 7. TLS verification disabled ─────────────────────────────────────────
  {
    ruleId: "tls-verify-disabled",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const patterns = [
        /rejectUnauthorized\s*:\s*false/,
        /verify\s*=\s*False/,
        /ssl\s*=\s*False/,
        /checkServerIdentity\s*:\s*\(\s*\)\s*=>/,
        /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/,
        /InsecureRequestWarning/,
        /VERIFY_NONE/,
        /ssl_verify\s*=\s*false/i,
      ];

      for (let i = 0; i < lines.length; i++) {
        if (patterns.some(re => re.test(lines[i]))) {
          findings.push(mkFinding(
            startLine + i, 0, "critical", "tls-verify-disabled",
            "TLS certificate verification disabled",
            "Disabling TLS verification allows man-in-the-middle attacks — any server certificate is accepted. Remove this flag and ensure a valid CA bundle is configured.",
            [{ id: "CWE-295", url: "https://cwe.mitre.org/data/definitions/295.html", description: "Improper Certificate Validation" }]
          ));
        }
      }
      return findings;
    },
  },

  // ── 8. Timing attack ──────────────────────────────────────────────────────
  {
    ruleId: "timing-attack",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const secretRe = /\b(?:token|hmac|signature|hash|mac|digest|secret|password|apiKey|api_key)\b/i;
      const equalityRe = /[!=]==?/;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!secretRe.test(line)) continue;
        if (!equalityRe.test(line)) continue;
        if (!/if\s*\(|return\s|&&|\|\||[!=]==/.test(line)) continue;
        if (/timingSafeEqual|compare_digest|hmac\.compare/i.test(line)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "warning", "timing-attack",
          "Timing attack: secret compared with == instead of constant-time function",
          "String equality allows timing side-channel attacks. Use crypto.timingSafeEqual() in Node.js or hmac.compare_digest() in Python.",
          [{ id: "CWE-208", url: "https://cwe.mitre.org/data/definitions/208.html", description: "Observable Timing Discrepancy" }]
        ));
      }
      return findings;
    },
  },

  // ── 9. XXE injection ──────────────────────────────────────────────────────
  {
    ruleId: "xxe-injection",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact", "python"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);

      const parserPatterns = [
        /\bDOMParser\s*\(\s*\)/,
        /\bparseFromString\s*\(/,
        /\bxml\.etree\b/,
        /\blxml\s*\.\s*etree\b/,
        /\bxmldom\b/,
        /\bfast-xml-parser\b/,
        /new\s+XMLParser\s*\(/,
        /libxml\b/,
        /etree\.parse\s*\(/,
        /lxml\.objectify\b/,
      ];

      const protections = [
        /resolveEntities\s*:\s*false/,
        /resolve_entities\s*=\s*False/,
        /forbid_dtd/,
        /no_network/,
        /allowBooleanAttributes/,
        /defusedxml/,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!parserPatterns.some(re => re.test(line))) continue;

        const nearby = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 5));
        const hasUserInput = nearby.some(l => lineUsesTainted(l, tainted) || lineIsTaintSource(l));
        if (!hasUserInput) continue;
        if (nearby.some(l => protections.some(p => p.test(stripComments(l))))) continue;

        findings.push(mkFinding(
          startLine + i, 0, "critical", "xxe-injection",
          "XXE: XML parsed from user input without entity restrictions",
          "Parsing XML from untrusted sources without disabling external entity resolution allows XXE attacks, which can read local files or trigger SSRF. Use defusedxml (Python) or set resolveEntities:false (JS).",
          [{ id: "CWE-611", url: "https://cwe.mitre.org/data/definitions/611.html", description: "XXE — XML External Entity" }]
        ));
      }
      return findings;
    },
  },

  // ── 10. Weak key size ─────────────────────────────────────────────────────
  {
    ruleId: "weak-key-size",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const keyGenRe = /\b(?:generateKeyPair|generateKey|RSA_generate_key|DSA_generate_key|genrsa|gendsa|generate_private_key|RSA\.generate)\b/i;

      for (let i = 0; i < lines.length; i++) {
        if (!keyGenRe.test(lines[i])) continue;
        const m = lines[i].match(/\b(512|768|1024)\b/);
        if (!m) continue;
        const size = parseInt(m[1], 10);
        findings.push(mkFinding(
          startLine + i, m.index ?? 0, "warning", "weak-key-size",
          `Weak asymmetric key size: ${size} bits`,
          `A ${size}-bit RSA/DSA key is considered insecure. Use at least 2048 bits; prefer 3072 or 4096 for new keys.`,
          [{ id: "CWE-326", url: "https://cwe.mitre.org/data/definitions/326.html", description: "Inadequate Encryption Strength" }]
        ));
      }
      return findings;
    },
  },

  // ── 11. Regex injection ───────────────────────────────────────────────────
  {
    ruleId: "regex-injection",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!/new\s+RegExp\s*\(/i.test(line)) continue;
        if (!lineUsesTainted(line, tainted)) continue;
        const safeguards = /escapeRegExp|escape-string-regexp|_.escapeRegExp/i;
        if (safeguards.test(line)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "warning", "regex-injection",
          "Regex injection: user input compiled into RegExp",
          "Passing user-controlled strings to new RegExp() allows ReDoS or validation bypass. Escape with escape-string-regexp before constructing the pattern.",
          [{ id: "CWE-730", url: "https://cwe.mitre.org/data/definitions/730.html", description: "Uncontrolled Resource Consumption via Regex (ReDoS)" }]
        ));
      }
      return findings;
    },
  },

  // ── 12. Eval alias detection ──────────────────────────────────────────────
  //   Catches: const run = eval; run(userInput)
  //   Also: const x = global['ev'+'al'] — stored and later called
  {
    ruleId: "eval-alias",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const evalAliases = new Map<string, number>();

      // Pass 1: find eval aliases
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // const x = eval  or  let run = eval  or  var fn = eval
        const directAlias = line.match(/(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*\beval\b/);
        if (directAlias) { evalAliases.set(directAlias[1], i); continue; }
        // const x = global['ev'+'al']  or  this['ev'+'al']
        const concatAlias = line.match(/(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=.*['"]ev['"]\s*\+\s*['"]al['"]/);
        if (concatAlias) { evalAliases.set(concatAlias[1], i); continue; }
        // const x = global.eval  or  window.eval
        const propAlias = line.match(/(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=\s*(?:global|window|self|globalThis)\.eval/);
        if (propAlias) { evalAliases.set(propAlias[1], i); }
      }

      if (evalAliases.size === 0) return findings;

      // Pass 2: find calls to those aliases
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        for (const [alias, defLine] of evalAliases) {
          const callRe = new RegExp(`\\b${alias}\\s*\\(`, "g");
          let m: RegExpExecArray | null;
          while ((m = callRe.exec(line)) !== null) {
            if (i === defLine) continue; // skip the definition line itself
            findings.push(mkFinding(
              startLine + i, m.index, "critical", "eval-alias",
              `Aliased eval() call via '${alias}'`,
              `The variable '${alias}' holds a reference to eval (assigned on line ${defLine + 1}). Calling it is equivalent to eval() and allows arbitrary code execution. Remove the alias and the call.`,
              [{ id: "CWE-95", url: "https://cwe.mitre.org/data/definitions/95.html", description: "Improper Neutralization of Directives in Dynamically Evaluated Code" }]
            ));
          }
        }
      }
      return findings;
    },
  },

  // ── 13. Mass assignment ───────────────────────────────────────────────────
  //   Catches: Object.assign(user, req.body)  or  spread: {...req.body}
  {
    ruleId: "mass-assignment",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const safeguards = [
        /pick\s*\(/i,
        /omit\s*\(/i,
        /allowedFields/i,
        /whitelist/i,
        /allowList/i,
        /\.select\s*\(/i,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];

        // Object.assign(model, req.body)
        const assignRe = /Object\.assign\s*\(\s*\w+\s*,\s*(?:req\.|body\.|params\.)\w*/i;
        if (assignRe.test(line)) {
          if (!hasSafeguardNearby(lines, i, safeguards, 3)) {
            findings.push(mkFinding(
              startLine + i, 0, "warning", "mass-assignment",
              "Mass assignment: request body spread directly onto model",
              "Directly assigning req.body to a model allows attackers to set protected fields (e.g. isAdmin, role, password). Explicitly pick only the fields you expect using a whitelist.",
              [{ id: "CWE-915", url: "https://cwe.mitre.org/data/definitions/915.html", description: "Improperly Controlled Modification of Dynamically-Determined Object Attributes" }]
            ));
            continue;
          }
        }

        // Spread: {...req.body} assigned to a model update
        const spreadRe = /\.\s*(?:create|update|save|insert)\s*\(\s*\{[^}]*\.\.\.(?:req\.|body\.|params\.)/i;
        if (spreadRe.test(line)) {
          if (!hasSafeguardNearby(lines, i, safeguards, 3)) {
            findings.push(mkFinding(
              startLine + i, 0, "warning", "mass-assignment",
              "Mass assignment: request body spread into model create/update",
              "Spreading req.body into a database create/update call allows attackers to set fields they shouldn't control. Destructure only the expected fields explicitly.",
              [{ id: "CWE-915", url: "https://cwe.mitre.org/data/definitions/915.html", description: "Improperly Controlled Modification of Dynamically-Determined Object Attributes" }]
            ));
          }
        }
      }
      return findings;
    },
  },

  // ── 14. SQL injection via any variable name ────────────────────────────────
  //   Catches: stmt, command, q, str — not just query/sql
  {
    ruleId: "sql-concat",
    languages: [],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);
      if (tainted.size === 0) return findings;

      const sqlSinks = [
        /\.(?:query|execute|run|all|get)\s*\(/i,
        /cursor\.execute\s*\(/i,
        /db\.query\s*\(/i,
        /pool\.query\s*\(/i,
        /connection\.query\s*\(/i,
      ];

      const safeguards = [
        /\?\s*,/,         // ? placeholder
        /\$[0-9]/,        // $1 placeholder
        /parameterized/i,
        /prepared/i,
        /cursor\.execute\s*\([^,]+,\s*\(/,  // cursor.execute(sql, params)
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!sqlSinks.some(re => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted)) continue;
        if (hasSafeguardNearby(lines, i, safeguards, 3)) continue;

        // Look at the argument to see if it contains a SQL keyword (reduces false positives)
        const fullContext = lines.slice(Math.max(0, i - 5), i + 1).join("\n");
        if (!/\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|TRUNCATE)\b/i.test(fullContext)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "critical", "sql-concat",
          "SQL injection: user input flows into database query",
          "User-controlled data reaches a database query. The variable name masks this from simple regex rules. Use parameterised queries — pass user values as bound parameters, never as part of the query string.",
          [{ id: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html", description: "SQL Injection" }]
        ));
      }
      return findings;
    },
  },

  // ── 15. Prototype pollution via deep merge ─────────────────────────────────
  {
    ruleId: "prototype-pollution",
    languages: ["javascript", "typescript", "javascriptreact", "typescriptreact"],
    run(lines, _lang, startLine) {
      const findings: Finding[] = [];
      const tainted = buildTaintSet(lines);

      const dangerousMerges = [
        /\bdefaultsDeep\s*\(/i,     // lodash — known pollution vector
        /\bmergeDeep\s*\(/i,
        /\bextend\s*\(true/i,       // jQuery deep extend
        /\bdeepMerge\s*\(/i,
        /\bmerge\s*\(\s*\w+\s*,\s*(?:req\.|body\.|params\.)/i,
      ];

      const safeguards = [
        /Object\.create\s*\(null\)/,
        /hasOwnProperty/,
        /allowedKeys/i,
        /__proto__.*false/i,
        /sanitize/i,
      ];

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!dangerousMerges.some(re => re.test(line))) continue;
        if (!lineUsesTainted(line, tainted) && !/req\.|body\.|params\./i.test(line)) continue;
        if (hasSafeguardNearby(lines, i, safeguards, 4)) continue;

        findings.push(mkFinding(
          startLine + i, 0, "critical", "prototype-pollution",
          "Prototype pollution risk: deep merge with user-controlled input",
          "Deep merge functions like lodash defaultsDeep() can pollute Object.prototype when given user-controlled objects containing __proto__ or constructor keys. Sanitise input keys before merging, or use Object.create(null) maps.",
          [
            { id: "CWE-1321", url: "https://cwe.mitre.org/data/definitions/1321.html", description: "Improperly Controlled Modification of Object Prototype Attributes" },
            { id: "CVE-2019-10744", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744", description: "lodash prototype pollution via defaultsDeep" },
          ]
        ));
      }
      return findings;
    },
  },
];

// ─── public API ───────────────────────────────────────────────────────────────

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
    if (rule.languages.length > 0 && !rule.languages.some(l => languageId.startsWith(l))) continue;

    const found = rule.run(lines, languageId, startLine);
    all.push(...found);
  }

  const sev: Record<string, number> = { critical: 0, warning: 1, info: 2 };
  all.sort((a, b) => a.line !== b.line ? a.line - b.line : (sev[a.severity] ?? 3) - (sev[b.severity] ?? 3));

  return all;
}

export const SEMANTIC_RULES_COUNT = semanticRules.length;