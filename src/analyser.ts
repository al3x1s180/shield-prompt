export interface Finding {
  line: number;
  col: number;
  severity: "critical" | "warning" | "info";
  ruleId: string;
  message: string;
  detail: string;
  cves: CVERef[];
}

export interface AIFingerprint {
  isAI: boolean;
  confidence: "high" | "medium" | "low";
}

export interface CVERef {
  id: string;         // e.g. "CVE-2021-44228"
  url: string;        // NVD link
  description: string; // short label
}

interface RuleDef {
  ruleId: string;
  severity: "critical" | "warning" | "info";
  languages: string[];
  message: string;
  detail: string;
  cves: CVERef[];
  check: (line: string, lineIndex: number, allLines: string[], languageId: string) => Finding[];
}

const JS_TS = ["javascript", "typescript", "javascriptreact", "typescriptreact"];
const PYTHON = ["python"];
const ALL_LANGUAGES: string[] = [];

function matchesLanguage(ruleLangs: string[], languageId: string): boolean {
  if (ruleLangs.length === 0) {
    return true;
  }
  return ruleLangs.some((lang) => languageId.startsWith(lang));
}

function langList(groups: string[][]): string[] {
  const result: string[] = [];
  for (const g of groups) {
    result.push(...g);
  }
  return result;
}

function shannonEntropy(str: string): number {
  const freq: Record<string, number> = {};
  for (const c of str) {
    freq[c] = (freq[c] || 0) + 1;
  }
  return Object.values(freq).reduce((h, count) => {
    const p = count / str.length;
    return h - p * Math.log2(p);
  }, 0);
}

const SECRET_FALSE_POSITIVES = new Set([
  "success", "failure", "pass", "fail", "passed", "failed", "error",
  "true", "false", "yes", "no", "none", "null", "undefined", "empty",
  "test", "testing", "example", "sample", "placeholder", "changeme",
  "todo", "fixme", "required", "optional", "invalid", "valid", "missing",
  "default", "admin", "user", "guest", "public", "private", "enabled",
  "disabled", "pending", "active", "inactive", "unknown", "loading",
]);

const SECRET_MOCK_PATTERNS = /^(abc123|1234567|12345678|password123|qwerty|asdfgh|aaaaaa+|bbbbbb+|000000+|111111+|test1234|mock.*)$/i;

const rules: RuleDef[] = [
  // eval-external: eval( where arg is not a string literal
  {
    ruleId: "eval-external",
    severity: "critical",
    languages: langList([JS_TS]),
    message: "Dangerous eval() with non-literal argument",
    detail:
      "eval() with dynamic input can execute arbitrary code. Use safer alternatives like JSON.parse() or Function constructors with sanitised input.",
    cves: [
      { id: "CWE-95", url: "https://cwe.mitre.org/data/definitions/95.html", description: "Improper Neutralization of Directives in Dynamically Evaluated Code" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /\beval\s*\(/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const afterParen = line.slice(m.index + m[0].length).trim();
        const isStringLiteral = /^['"`]/.test(afterParen);
        if (!isStringLiteral) {
          findings.push({
            line: lineIndex,
            col: m.index,
            severity: "critical",
            ruleId: "eval-external",
            message: this.message,
            detail: this.detail,
            cves: this.cves,
          });
        }
      }
      return findings;
    },
  },

  // hardcoded-secret — with Shannon entropy and expanded false-positive filtering
  {
    ruleId: "hardcoded-secret",
    severity: "critical",
    languages: ALL_LANGUAGES,
    message: "Hardcoded secret detected",
    detail:
      "Credentials should never be hardcoded. Use environment variables or a secrets manager instead.",
    cves: [
      { id: "CWE-798", url: "https://cwe.mitre.org/data/definitions/798.html", description: "Use of Hard-coded Credentials" },
      { id: "CWE-259", url: "https://cwe.mitre.org/data/definitions/259.html", description: "Use of Hard-coded Password" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re =
        /\b(password|secret|token|api_key|apikey|api_secret|apiSecret|auth|credential|private_key|access_key)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const value = m[2];
        const valueLower = value.toLowerCase();
        if (value.length <= 8) { continue; }
        if (SECRET_FALSE_POSITIVES.has(valueLower)) { continue; }
        if (/^(your_|<|\{|\$|%|__)/.test(value)) { continue; }
        if (SECRET_MOCK_PATTERNS.test(value)) { continue; }
        if (/^(.)\1+$/.test(value)) { continue; }
        if (shannonEntropy(value) <= 2.5) { continue; }
        findings.push({
          line: lineIndex,
          col: m.index,
          severity: "critical",
          ruleId: "hardcoded-secret",
          message: this.message,
          detail: this.detail,
          cves: this.cves,
        });
      }
      return findings;
    },
  },

  // weak-hash-md5
  {
    ruleId: "weak-hash-md5",
    severity: "warning",
    languages: langList([JS_TS, PYTHON]),
    message: "Weak hash algorithm: MD5",
    detail:
      "MD5 is cryptographically broken and should not be used for security purposes. Use SHA-256 or SHA-3 instead.",
    cves: [
      { id: "CVE-2004-2761", url: "https://nvd.nist.gov/vuln/detail/CVE-2004-2761", description: "MD5 collision vulnerability" },
      { id: "CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html", description: "Use of a Broken or Risky Cryptographic Algorithm" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /\bmd5\s*\(|createHash\s*\(\s*['"]md5['"]\s*\)/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        findings.push({
          line: lineIndex,
          col: m.index,
          severity: "warning",
          ruleId: "weak-hash-md5",
          message: this.message,
          detail: this.detail,
          cves: this.cves,
        });
      }
      return findings;
    },
  },

  // weak-hash-sha1
  {
    ruleId: "weak-hash-sha1",
    severity: "warning",
    languages: langList([JS_TS, PYTHON]),
    message: "Weak hash algorithm: SHA-1",
    detail:
      "SHA-1 is deprecated for security use. Use SHA-256 or SHA-3 instead.",
    cves: [
      { id: "CVE-2005-4900", url: "https://nvd.nist.gov/vuln/detail/CVE-2005-4900", description: "SHA-1 collision attack" },
      { id: "CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html", description: "Use of a Broken or Risky Cryptographic Algorithm" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /\bsha1\s*\(|createHash\s*\(\s*['"]sha1['"]\s*\)/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        findings.push({
          line: lineIndex,
          col: m.index,
          severity: "warning",
          ruleId: "weak-hash-sha1",
          message: this.message,
          detail: this.detail,
          cves: this.cves,
        });
      }
      return findings;
    },
  },

  // cors-wildcard
  {
    ruleId: "cors-wildcard",
    severity: "warning",
    languages: langList([JS_TS]),
    message: "CORS origin set to wildcard '*'",
    detail:
      "Allowing all origins with '*' can expose your API to cross-origin attacks. Restrict to known domains.",
    cves: [
      { id: "CWE-942", url: "https://cwe.mitre.org/data/definitions/942.html", description: "Permissive Cross-domain Policy with Untrusted Domains" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /origin\s*[:=]\s*['"`]\*['"`]/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        findings.push({
          line: lineIndex,
          col: m.index,
          severity: "warning",
          ruleId: "cors-wildcard",
          message: this.message,
          detail: this.detail,
          cves: this.cves,
        });
      }
      return findings;
    },
  },

  // shell-injection
  {
    ruleId: "shell-injection",
    severity: "critical",
    languages: PYTHON,
    message: "Potential shell injection via subprocess with shell=True",
    detail:
      "Using shell=True with subprocess allows shell injection attacks. Pass arguments as a list without shell=True.",
    cves: [
      { id: "CWE-78", url: "https://cwe.mitre.org/data/definitions/78.html", description: "Improper Neutralization of Special Elements used in an OS Command" },
      { id: "CVE-2018-1000802", url: "https://nvd.nist.gov/vuln/detail/CVE-2018-1000802", description: "Python subprocess shell injection" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /subprocess\.\w+\s*\(.*shell\s*=\s*True/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        findings.push({
          line: lineIndex,
          col: m.index,
          severity: "critical",
          ruleId: "shell-injection",
          message: this.message,
          detail: this.detail,
          cves: this.cves,
        });
      }
      return findings;
    },
  },

  // pickle-loads
  {
    ruleId: "pickle-loads",
    severity: "critical",
    languages: PYTHON,
    message: "Unsafe pickle.loads() deserialization",
    detail:
      "pickle.loads() can execute arbitrary code during deserialization. Use safer formats like JSON or validate the pickle source.",
    cves: [
      { id: "CWE-502", url: "https://cwe.mitre.org/data/definitions/502.html", description: "Deserialization of Untrusted Data" },
      { id: "CVE-2014-1402", url: "https://nvd.nist.gov/vuln/detail/CVE-2014-1402", description: "Python pickle arbitrary code execution" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /pickle\.loads?\s*\(/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        findings.push({
          line: lineIndex,
          col: m.index,
          severity: "critical",
          ruleId: "pickle-loads",
          message: this.message,
          detail: this.detail,
          cves: this.cves,
        });
      }
      return findings;
    },
  },

  // math-random-crypto — expanded context keywords
  {
    ruleId: "math-random-crypto",
    severity: "warning",
    languages: langList([JS_TS]),
    message: "Math.random() used in security-sensitive context",
    detail:
      "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues() instead.",
    cves: [
      { id: "CWE-338", url: "https://cwe.mitre.org/data/definitions/338.html", description: "Use of Cryptographically Weak PRNG" },
    ],
    check(line, lineIndex, allLines) {
      const findings: Finding[] = [];
      const re = /Math\.random\s*\(\s*\)/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const contextStart = Math.max(0, lineIndex - 5);
        const contextEnd = Math.min(allLines.length - 1, lineIndex + 5);
        let hasCryptoContext = false;
        for (let i = contextStart; i <= contextEnd; i++) {
          if (/\b(crypto|token|secret|key|nonce|salt|password|uuid|id|session|auth|random|seed|iv|cipher)\b/i.test(allLines[i])) {
            hasCryptoContext = true;
            break;
          }
        }
        if (hasCryptoContext) {
          findings.push({
            line: lineIndex,
            col: m.index,
            severity: "warning",
            ruleId: "math-random-crypto",
            message: this.message,
            detail: this.detail,
            cves: this.cves,
          });
        }
      }
      return findings;
    },
  },

  // inner-html — with safe pattern exceptions
  {
    ruleId: "inner-html",
    severity: "warning",
    languages: langList([JS_TS]),
    message: "Unsafe innerHTML assignment",
    detail:
      "Direct innerHTML assignment can lead to XSS attacks. Use textContent, or sanitise HTML with a library like DOMPurify.",
    cves: [
      { id: "CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html", description: "Cross-site Scripting (XSS)" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /\.innerHTML\s*=/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const after = line.slice(m.index + ".innerHTML".length).trim();
        if (after.startsWith("+=")) {
          const rhs = after.slice(2).trim();
          if (/^['"`]/.test(rhs)) { continue; }
        }
        const afterAssign = after.startsWith("+=") ? after.slice(2).trim() : after.slice(1).trim();
        const isSafe =
          /^["'`]\s*["'`]/.test(afterAssign) ||
          /^[A-Z_]{3,}\b/.test(afterAssign) ||
          /\b(DOMPurify\.sanitize|sanitize|escapeHtml|escape)\s*\(/.test(line);
        if (isSafe) { continue; }
        findings.push({
          line: lineIndex,
          col: m.index,
          severity: "warning",
          ruleId: "inner-html",
          message: this.message,
          detail: this.detail,
          cves: this.cves,
        });
      }
      return findings;
    },
  },

  // sql-concat — now requires SQL keyword in the same line
  {
    ruleId: "sql-concat",
    severity: "critical",
    languages: ALL_LANGUAGES,
    message: "Potential SQL injection via string concatenation",
    detail:
      "Building SQL queries with string concatenation is vulnerable to SQL injection. Use parameterised queries or prepared statements.",
    cves: [
      { id: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html", description: "SQL Injection" },
      { id: "CVE-2012-5615", url: "https://nvd.nist.gov/vuln/detail/CVE-2012-5615", description: "MySQL SQL injection via user enumeration" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const hasSqlKeyword = /\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|INTO|VALUES)\b/i.test(line);
      if (!hasSqlKeyword) { return findings; }
      const re = /\b(query|sql)\s*[=:+]\s*.*\+/gi;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: "sql-concat", message: this.message, detail: this.detail, cves: this.cves });
      }
      const reTpl = /\b(query|sql)\s*=\s*`[^`]*\$\{/gi;
      let m2: RegExpExecArray | null;
      while ((m2 = reTpl.exec(line)) !== null) {
        findings.push({ line: lineIndex, col: m2.index, severity: "critical", ruleId: "sql-concat", message: this.message, detail: this.detail, cves: this.cves });
      }
      const reFStr = /\b(query|sql)\s*=\s*f["']/gi;
      let m3: RegExpExecArray | null;
      while ((m3 = reFStr.exec(line)) !== null) {
        findings.push({ line: lineIndex, col: m3.index, severity: "critical", ruleId: "sql-concat", message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    },
  },

  // prototype-pollution
  {
    ruleId: "prototype-pollution",
    severity: "critical",
    languages: langList([JS_TS]),
    message: "Potential prototype pollution",
    detail:
      "Merging or assigning user-controlled objects without validation can pollute Object.prototype. Use Object.create(null) for safe key-value stores or validate keys against a whitelist.",
    cves: [
      { id: "CWE-1321", url: "https://cwe.mitre.org/data/definitions/1321.html", description: "Improperly Controlled Modification of Object Prototype Attributes" },
      { id: "CVE-2019-10744", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744", description: "lodash prototype pollution via defaultsDeep" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /\w+\s*\[\s*\w+\s*\]\s*=/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const hasSafeGuard = /hasOwnProperty|Object\.keys|whitelist|allowedKeys|sanitize/i.test(line);
        if (!hasSafeGuard) {
          findings.push({
            line: lineIndex,
            col: m.index,
            severity: "critical",
            ruleId: "prototype-pollution",
            message: this.message,
            detail: this.detail,
            cves: this.cves,
          });
        }
      }
      return findings;
    },
  },

  // open-redirect
  {
    ruleId: "open-redirect",
    severity: "warning",
    languages: langList([JS_TS]),
    message: "Potential open redirect",
    detail:
      "Redirecting to a URL from user input without validation can be exploited for phishing. Validate the URL against an allowlist of trusted domains.",
    cves: [
      { id: "CWE-601", url: "https://cwe.mitre.org/data/definitions/601.html", description: "URL Redirection to Untrusted Site (Open Redirect)" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /\b(res\.redirect|location\.href|location\.replace|window\.location)\s*[=(]/g;
      let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) {
        const after = line.slice(m.index + m[0].length).trim();
        if (!/^["'`]/.test(after)) {
          findings.push({
            line: lineIndex,
            col: m.index,
            severity: "warning",
            ruleId: "open-redirect",
            message: this.message,
            detail: this.detail,
            cves: this.cves,
          });
        }
      }
      return findings;
    },
  },
];

// Exported so the panel can report the count
export const RULES_COUNT = rules.length;

export function analyse(
  text: string,
  languageId: string,
  startLine: number,
  suppressedRules: string[],
  deps: Set<string> = new Set()
): Finding[] {
  const lines = text.split("\n");
  const findings: Finding[] = [];

  for (const rule of rules) {
    if (suppressedRules.includes(rule.ruleId)) {
      continue;
    }
    if (!matchesLanguage(rule.languages, languageId)) {
      continue;
    }

    // Dependency-aware suppression for Python stdlib rules:
    // subprocess and pickle are Python stdlib — always flag for Python files
    // Only suppress if we have positive evidence the library isn't there
    // (For now, Python stdlib rules always fire for Python files since they're built-in)

    for (let i = 0; i < lines.length; i++) {
      // Inline suppression: shieldprompt-ignore
      const flaggedLine = lines[i];
      if (flaggedLine.includes("shieldprompt-ignore")) {
        const specificMatch = flaggedLine.match(/shieldprompt-ignore:\s*([\w-]+)/);
        if (!specificMatch || specificMatch[1] === rule.ruleId) {
          continue;
        }
      }

      const lineFindings = rule.check(lines[i], i, lines, languageId);
      for (const f of lineFindings) {
        findings.push({
          ...f,
          line: f.line + startLine,
        });
      }
    }
  }

  // Sort by line, then severity weight
  const severityWeight: Record<string, number> = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => {
    if (a.line !== b.line) {
      return a.line - b.line;
    }
    return (severityWeight[a.severity] ?? 3) - (severityWeight[b.severity] ?? 3);
  });

  return findings;
}

export function fingerprint(text: string): AIFingerprint {
  const lines = text.split("\n");
  const nonEmptyLines = lines.filter((l) => l.trim().length > 0);

  if (nonEmptyLines.length === 0) {
    return { isAI: false, confidence: "low" };
  }

  let signals = 0;

  // Signal 1: Comment density > 30%
  const commentLines = nonEmptyLines.filter((l) => {
    const trimmed = l.trim();
    return (
      trimmed.startsWith("//") ||
      trimmed.startsWith("#") ||
      trimmed.startsWith("/*") ||
      trimmed.startsWith("*") ||
      trimmed.startsWith("'''") ||
      trimmed.startsWith('"""')
    );
  });
  if (commentLines.length / nonEmptyLines.length > 0.3) {
    signals++;
  }

  // Signal 2: Comments follow pattern "This [verb] [noun] by [verb]ing"
  const patternRe = /\bthis\s+\w+s?\s+\w+\s+by\s+\w+ing\b/i;
  const matchingComments = commentLines.filter((l) => patternRe.test(l));
  if (matchingComments.length >= 1) {
    signals++;
  }

  // Signal 3: Every function has a try/catch wrapper
  const functionStarts = nonEmptyLines.filter((l) =>
    /\b(function\s+\w+|=>\s*\{|def\s+\w+)/.test(l)
  );
  if (functionStarts.length > 0) {
    const tryCatchCount = nonEmptyLines.filter((l) =>
      /\b(try\s*\{|try\s*:)/.test(l.trim())
    ).length;
    if (tryCatchCount >= functionStarts.length) {
      signals++;
    }
  }

  // Signal 4: Identifier names are unusually long (avg > 14 chars)
  const identifierRe = /\b([a-zA-Z_]\w{2,})\b/g;
  let totalLen = 0;
  let identCount = 0;
  const reserved = new Set([
    "function", "const", "let", "var", "return", "import", "export", "from",
    "class", "extends", "implements", "interface", "type", "this", "new",
    "async", "await", "true", "false", "null", "undefined", "void",
    "typeof", "instanceof", "throw", "catch", "finally", "while", "for",
    "break", "continue", "switch", "case", "default", "else", "try",
    "delete", "yield", "static", "super", "with", "debugger", "enum",
    "def", "self", "None", "True", "False", "lambda", "pass", "raise",
    "except", "finally", "elif", "print", "string", "number", "boolean",
  ]);
  for (const line of nonEmptyLines) {
    let im: RegExpExecArray | null;
    while ((im = identifierRe.exec(line)) !== null) {
      const ident = im[1];
      if (!reserved.has(ident)) {
        totalLen += ident.length;
        identCount++;
      }
    }
  }
  if (identCount > 0 && totalLen / identCount > 14) {
    signals++;
  }

  // Signal 5: Code contains a docstring starting with "This function"
  const fullText = text;
  if (/["']{3}\s*This function|\/\*\*[\s\S]*?This function/.test(fullText)) {
    signals++;
  }

  // Signal 6: ChatGPT-style "// Step N:" comment sequences
  const stepCommentRe = /^\s*(\/\/|#)\s*Step\s+\d+[:.]/im;
  const stepMatches = nonEmptyLines.filter((l) => stepCommentRe.test(l));
  if (stepMatches.length >= 2) {
    signals++;
  }

  if (signals >= 2) {
    return { isAI: true, confidence: "high" };
  }
  if (signals === 1) {
    return { isAI: true, confidence: "medium" };
  }
  return { isAI: false, confidence: "low" };
}