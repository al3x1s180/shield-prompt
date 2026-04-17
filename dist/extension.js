"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __getProtoOf = Object.getPrototypeOf;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => { for (var name in all) __defProp(target, name, { get: all[name], enumerable: true }); };
var __copyProps = (to, from, except, desc) => { if (from && typeof from === "object" || typeof from === "function") for (let key of __getOwnPropNames(from)) if (!__hasOwnProp.call(to, key) && key !== except) __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable }); return to; };
var __toESM = (mod, isNodeMode, target) => (target = mod != null ? __create(__getProtoOf(mod)) : {}, __copyProps(isNodeMode || !mod || !mod.__esModule ? __defProp(target, "default", { value: mod, enumerable: true }) : target, mod));
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

var src_exports = {};
__export(src_exports, { activate: () => activate, deactivate: () => deactivate });
module.exports = __toCommonJS(src_exports);
var vscode = __toESM(require("vscode"));

// ─── PASTE DETECTOR ──────────────────────────────────────────────────────────
function onPaste(callback) {
  const lastChange = { time: 0 };
  let debounceTimer;
  return vscode.workspace.onDidChangeTextDocument((event) => {
    const config = vscode.workspace.getConfiguration("pasteguard");
    if (!config.get("enabled", true)) return;
    if (event.reason === vscode.TextDocumentChangeReason.Undo || event.reason === vscode.TextDocumentChangeReason.Redo) return;
    if (event.document.uri.scheme !== "file" && event.document.uri.scheme !== "untitled") return;
    const minLines = config.get("minLines", 3);
    const now = Date.now();
    const timeSince = now - lastChange.time;
    for (const change of event.contentChanges) {
      const lineCount = change.text.split("\n").length;
      const isMultiLine = lineCount >= minLines;
      const isLargeChunk = change.text.length > 80 && timeSince > 150;
      if (isMultiLine || isLargeChunk) {
        const startLine = change.range.start.line;
        const startChar = change.range.start.character;
        const endLine = startLine + lineCount - 1;
        const lines = change.text.split("\n");
        const endChar = lineCount === 1 ? startChar + lines[0].length : lines[lines.length - 1].length;
        const range = new vscode.Range(startLine, startChar, endLine, endChar);
        if (debounceTimer !== undefined) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => { callback(change.text, event.document, range); debounceTimer = undefined; }, 300);
      }
    }
    lastChange.time = now;
  });
}

// ─── STATIC ANALYSER ─────────────────────────────────────────────────────────
const JS_TS = ["javascript", "typescript", "javascriptreact", "typescriptreact"];
const PYTHON = ["python"];
const ALL_LANGUAGES = [];

function matchesLanguage(ruleLangs, languageId) {
  if (ruleLangs.length === 0) return true;
  return ruleLangs.some((l) => languageId.startsWith(l));
}
function langList(groups) {
  const r = []; for (const g of groups) r.push(...g); return r;
}
function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((h, count) => { const p = count / str.length; return h - p * Math.log2(p); }, 0);
}

const SECRET_FP = new Set(["success","failure","pass","fail","passed","failed","error","true","false","yes","no","none","null","undefined","empty","test","testing","example","sample","placeholder","changeme","todo","fixme","required","optional","invalid","valid","missing","default","admin","user","guest","public","private","enabled","disabled","pending","active","inactive","unknown","loading"]);
const SECRET_MOCK = /^(abc123|1234567|12345678|password123|qwerty|asdfgh|aaaaaa+|bbbbbb+|000000+|111111+|test1234|mock.*)$/i;

const STATIC_RULES = [
  {
    ruleId: "eval-external", severity: "critical", languages: langList([JS_TS]),
    message: "Dangerous eval() with non-literal argument",
    detail: "eval() with dynamic input can execute arbitrary code. Use safer alternatives like JSON.parse() or Function constructors with sanitised input.",
    cves: [{ id: "CWE-95", url: "https://cwe.mitre.org/data/definitions/95.html", description: "Improper Neutralization of Directives in Dynamically Evaluated Code" }],
    check(line, i) {
      const findings = []; const re = /\beval\s*\(/g; let m;
      while ((m = re.exec(line)) !== null) { const after = line.slice(m.index + m[0].length).trim(); if (!/^['"`]/.test(after)) findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves }); }
      return findings;
    }
  },
  {
    ruleId: "hardcoded-secret", severity: "critical", languages: ALL_LANGUAGES,
    message: "Hardcoded secret detected",
    detail: "Credentials should never be hardcoded. Use environment variables or a secrets manager instead.",
    cves: [{ id: "CWE-798", url: "https://cwe.mitre.org/data/definitions/798.html", description: "Use of Hard-coded Credentials" }, { id: "CWE-259", url: "https://cwe.mitre.org/data/definitions/259.html", description: "Use of Hard-coded Password" }],
    check(line, i) {
      const findings = []; const re = /\b(password|secret|token|api_key|apikey|api_secret|apiSecret|auth|credential|private_key|access_key)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi; let m;
      while ((m = re.exec(line)) !== null) {
        const v = m[2], vl = v.toLowerCase();
        if (v.length <= 8 || SECRET_FP.has(vl) || /^(your_|<|\{|\$|%|__)/.test(v) || SECRET_MOCK.test(v) || /^(.)\1+$/.test(v) || shannonEntropy(v) <= 2.5) continue;
        findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "weak-hash-md5", severity: "warning", languages: langList([JS_TS, PYTHON]),
    message: "Weak hash algorithm: MD5",
    detail: "MD5 is cryptographically broken and should not be used for security purposes. Use SHA-256 or SHA-3 instead.",
    cves: [{ id: "CVE-2004-2761", url: "https://nvd.nist.gov/vuln/detail/CVE-2004-2761", description: "MD5 collision vulnerability" }, { id: "CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html", description: "Use of a Broken or Risky Cryptographic Algorithm" }],
    check(line, i) {
      const findings = []; const re = /\bmd5\s*\(|createHash\s*\(\s*['"]md5['"]\s*\)/gi; let m;
      while ((m = re.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      return findings;
    }
  },
  {
    ruleId: "weak-hash-sha1", severity: "warning", languages: langList([JS_TS, PYTHON]),
    message: "Weak hash algorithm: SHA-1",
    detail: "SHA-1 is deprecated for security use. Use SHA-256 or SHA-3 instead.",
    cves: [{ id: "CVE-2005-4900", url: "https://nvd.nist.gov/vuln/detail/CVE-2005-4900", description: "SHA-1 collision attack" }, { id: "CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html", description: "Use of a Broken or Risky Cryptographic Algorithm" }],
    check(line, i) {
      const findings = []; const re = /\bsha1\s*\(|createHash\s*\(\s*['"]sha1['"]\s*\)/gi; let m;
      while ((m = re.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      return findings;
    }
  },
  {
    ruleId: "cors-wildcard", severity: "warning", languages: langList([JS_TS]),
    message: "CORS origin set to wildcard '*'",
    detail: "Allowing all origins with '*' can expose your API to cross-origin attacks. Restrict to known domains.",
    cves: [{ id: "CWE-942", url: "https://cwe.mitre.org/data/definitions/942.html", description: "Permissive Cross-domain Policy with Untrusted Domains" }],
    check(line, i) {
      const findings = []; const re = /origin\s*[:=]\s*['"`]\*['"`]/gi; let m;
      while ((m = re.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      return findings;
    }
  },
  {
    ruleId: "shell-injection", severity: "critical", languages: PYTHON,
    message: "Potential shell injection via subprocess with shell=True",
    detail: "Using shell=True with subprocess allows shell injection attacks. Pass arguments as a list without shell=True.",
    cves: [{ id: "CWE-78", url: "https://cwe.mitre.org/data/definitions/78.html", description: "Improper Neutralization of Special Elements used in an OS Command" }, { id: "CVE-2018-1000802", url: "https://nvd.nist.gov/vuln/detail/CVE-2018-1000802", description: "Python subprocess shell injection" }],
    check(line, i) {
      const findings = []; const re = /subprocess\.\w+\s*\(.*shell\s*=\s*True/gi; let m;
      while ((m = re.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      return findings;
    }
  },
  {
    ruleId: "pickle-loads", severity: "critical", languages: PYTHON,
    message: "Unsafe pickle.loads() deserialization",
    detail: "pickle.loads() can execute arbitrary code during deserialization. Use safer formats like JSON or validate the pickle source.",
    cves: [{ id: "CWE-502", url: "https://cwe.mitre.org/data/definitions/502.html", description: "Deserialization of Untrusted Data" }, { id: "CVE-2014-1402", url: "https://nvd.nist.gov/vuln/detail/CVE-2014-1402", description: "Python pickle arbitrary code execution" }],
    check(line, i) {
      const findings = []; const re = /pickle\.loads?\s*\(/g; let m;
      while ((m = re.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      return findings;
    }
  },
  {
    ruleId: "math-random-crypto", severity: "warning", languages: langList([JS_TS]),
    message: "Math.random() used in security-sensitive context",
    detail: "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.getRandomValues() instead.",
    cves: [{ id: "CWE-338", url: "https://cwe.mitre.org/data/definitions/338.html", description: "Use of Cryptographically Weak PRNG" }],
    check(line, i, allLines) {
      const findings = []; const re = /Math\.random\s*\(\s*\)/g; let m;
      while ((m = re.exec(line)) !== null) {
        const cs = Math.max(0, i - 5), ce = Math.min(allLines.length - 1, i + 5);
        let hit = false;
        for (let x = cs; x <= ce; x++) if (/\b(crypto|token|secret|key|nonce|salt|password|uuid|id|session|auth|random|seed|iv|cipher)\b/i.test(allLines[x])) { hit = true; break; }
        if (hit) findings.push({ line: i, col: m.index, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "inner-html", severity: "warning", languages: langList([JS_TS]),
    message: "Unsafe innerHTML assignment",
    detail: "Direct innerHTML assignment can lead to XSS attacks. Use textContent, or sanitise HTML with a library like DOMPurify.",
    cves: [{ id: "CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html", description: "Cross-site Scripting (XSS)" }],
    check(line, i) {
      const findings = []; const re = /\.innerHTML\s*=/g; let m;
      while ((m = re.exec(line)) !== null) {
        const after = line.slice(m.index + ".innerHTML".length).trim();
        if (after.startsWith("+=")) { const rhs = after.slice(2).trim(); if (/^['"`]/.test(rhs)) continue; }
        const afterAssign = after.startsWith("+=") ? after.slice(2).trim() : after.slice(1).trim();
        if (/^["'`]\s*["'`]/.test(afterAssign) || /^[A-Z_]{3,}\b/.test(afterAssign) || /\b(DOMPurify\.sanitize|sanitize|escapeHtml|escape)\s*\(/.test(line)) continue;
        findings.push({ line: i, col: m.index, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "sql-concat", severity: "critical", languages: ALL_LANGUAGES,
    message: "Potential SQL injection via string concatenation",
    detail: "Building SQL queries with string concatenation is vulnerable to SQL injection. Use parameterised queries or prepared statements.",
    cves: [{ id: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html", description: "SQL Injection" }, { id: "CVE-2012-5615", url: "https://nvd.nist.gov/vuln/detail/CVE-2012-5615", description: "MySQL SQL injection via user enumeration" }],
    check(line, i) {
      const findings = [];
      if (!/\b(SELECT|INSERT|UPDATE|DELETE|FROM|WHERE|JOIN|INTO|VALUES)\b/i.test(line)) return findings;
      const re1 = /\b(query|sql)\s*[=:+]\s*.*\+/gi; let m;
      while ((m = re1.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      const re2 = /\b(query|sql)\s*=\s*`[^`]*\$\{/gi;
      while ((m = re2.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      const re3 = /\b(query|sql)\s*=\s*f["']/gi;
      while ((m = re3.exec(line)) !== null) findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      return findings;
    }
  },
  {
    ruleId: "prototype-pollution", severity: "critical", languages: langList([JS_TS]),
    message: "Potential prototype pollution",
    detail: "Merging or assigning user-controlled objects without validation can pollute Object.prototype. Use Object.create(null) for safe key-value stores or validate keys against a whitelist.",
    cves: [{ id: "CWE-1321", url: "https://cwe.mitre.org/data/definitions/1321.html", description: "Improperly Controlled Modification of Object Prototype Attributes" }, { id: "CVE-2019-10744", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-10744", description: "lodash prototype pollution via defaultsDeep" }],
    check(line, i) {
      const findings = []; const re = /\w+\s*\[\s*\w+\s*\]\s*=/g; let m;
      while ((m = re.exec(line)) !== null) { if (!/hasOwnProperty|Object\.keys|whitelist|allowedKeys|sanitize/i.test(line)) findings.push({ line: i, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves }); }
      return findings;
    }
  },
  {
    ruleId: "open-redirect", severity: "warning", languages: langList([JS_TS]),
    message: "Potential open redirect",
    detail: "Redirecting to a URL from user input without validation can be exploited for phishing. Validate the URL against an allowlist of trusted domains.",
    cves: [{ id: "CWE-601", url: "https://cwe.mitre.org/data/definitions/601.html", description: "URL Redirection to Untrusted Site (Open Redirect)" }],
    check(line, i) {
      const findings = []; const re = /\b(res\.redirect|location\.href|location\.replace|window\.location)\s*[=(]/g; let m;
      while ((m = re.exec(line)) !== null) { const after = line.slice(m.index + m[0].length).trim(); if (!/^["'`]/.test(after)) findings.push({ line: i, col: m.index, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves }); }
      return findings;
    }
  },
];

const STATIC_RULES_COUNT = STATIC_RULES.length;

function analyse(text, languageId, startLine, suppressedRules) {
  const lines = text.split("\n");
  const findings = [];
  for (const rule of STATIC_RULES) {
    if (suppressedRules.includes(rule.ruleId)) continue;
    if (!matchesLanguage(rule.languages, languageId)) continue;
    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.includes("shieldprompt-ignore")) {
        const sm = line.match(/shieldprompt-ignore:\s*([\w-]+)/);
        if (!sm || sm[1] === rule.ruleId) continue;
      }
      const lf = rule.check(lines[i], i, lines, languageId);
      for (const f of lf) findings.push({ ...f, line: f.line + startLine });
    }
  }
  const sw = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => a.line !== b.line ? a.line - b.line : (sw[a.severity] ?? 3) - (sw[b.severity] ?? 3));
  return findings;
}

// ─── SEMANTIC ANALYSER ───────────────────────────────────────────────────────
const TAINT_SOURCES = [
  /\breq\.(body|params|query|headers|cookies)\b/,
  /\bprocess\.argv\b/, /\bwindow\.location\b/,
  /\bdocument\.(?:cookie|referrer|URL|location)\b/, /\.value\b/,
  /\brequest\.(form|args|json|data|files|headers|cookies)\b/,
  /\binput\s*\(/, /\bos\.environ\b/, /\bsys\.argv\b/,
  /\bgetenv\s*\(/, /\bgetParam\s*\(/, /\bgetQueryParam\s*\(/,
];

function assignedVar(line) {
  const m = line.match(/(?:const|let|var|val)\s+([a-zA-Z_$][\w$]*)\s*=|^([a-zA-Z_$][\w$]*)\s*=/);
  if (!m) return null; return (m[1] != null ? m[1] : m[2]) || null;
}
function rhsVars(line) {
  const eq = line.indexOf("="); if (eq === -1) return [];
  return [...line.slice(eq + 1).matchAll(/\b([a-zA-Z_$][\w$]*)\b/g)].map((m) => m[1]);
}
function lineIsTaintSource(line) { return TAINT_SOURCES.some((re) => re.test(line)); }
function buildTaintSet(lines) {
  const tainted = new Map();
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (lineIsTaintSource(line)) { const v = assignedVar(line); if (v) tainted.set(v, i); continue; }
    const lhs = assignedVar(line);
    if (lhs) { for (const r of rhsVars(line)) { if (tainted.has(r)) { tainted.set(lhs, i); break; } } }
  }
  return tainted;
}
function lineUsesTainted(line, tainted) {
  for (const v of tainted.keys()) { if (new RegExp("\\b" + v + "\\b").test(line)) return true; } return false;
}

const SEMANTIC_RULES = [
  {
    ruleId: "path-traversal", languages: [],
    message: "Path traversal: user input used in file operation",
    detail: "User-controlled data reaches a file-system call without sanitisation. An attacker can supply '../../../etc/passwd' style paths. Use path.basename() and validate against an allowed directory.",
    cves: [{ id: "CWE-22", url: "https://cwe.mitre.org/data/definitions/22.html", description: "Improper Limitation of a Pathname to a Restricted Directory" }, { id: "CVE-2017-5638", url: "https://nvd.nist.gov/vuln/detail/CVE-2017-5638", description: "Apache Struts path traversal RCE" }],
    run(lines, _lang, startLine) {
      const findings = []; const tainted = buildTaintSet(lines); if (!tainted.size) return findings;
      const sinks = [/\b(?:fs|path)\s*\.\s*(?:readFile|writeFile|readFileSync|writeFileSync|createReadStream|createWriteStream|unlink|rename|mkdir|rmdir|open|access|stat|appendFile|copyFile)\s*\(/, /\b(?:open|os\.path\.join|os\.listdir|os\.remove|os\.rename|shutil\.|pathlib\.Path)\s*\(/];
      for (let i = 0; i < lines.length; i++) {
        if (!sinks.some((re) => re.test(lines[i]))) continue;
        if (!lineUsesTainted(lines[i], tainted)) continue;
        const ctx = lines.slice(Math.max(0, i - 4), Math.min(lines.length, i + 2));
        if (ctx.some((l) => /\b(?:basename|normalize|resolve|realpath|path\.join|sanitize|allowedPaths|whitelist|startsWith)\b/.test(l))) continue;
        findings.push({ line: startLine + i, col: 0, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "ssrf", languages: [],
    message: "SSRF: user-controlled URL passed to HTTP request",
    detail: "The destination URL is derived from user input without validation. An attacker can make the server fetch internal services. Validate the URL against an allowlist of permitted hosts.",
    cves: [{ id: "CWE-918", url: "https://cwe.mitre.org/data/definitions/918.html", description: "Server-Side Request Forgery (SSRF)" }, { id: "CVE-2021-29418", url: "https://nvd.nist.gov/vuln/detail/CVE-2021-29418", description: "SSRF via user-controlled URL" }],
    run(lines, _lang, startLine) {
      const findings = []; const tainted = buildTaintSet(lines); if (!tainted.size) return findings;
      const sinks = [/\bfetch\s*\(/, /\baxios\s*\.\s*(?:get|post|put|delete|request)\s*\(/, /\bhttps?\s*\.\s*(?:get|request)\s*\(/, /\brequests\s*\.\s*(?:get|post|put|delete|request)\s*\(/, /\burllib\s*\.\s*request\b/, /\bcurl\b/];
      for (let i = 0; i < lines.length; i++) {
        if (!sinks.some((re) => re.test(lines[i]))) continue;
        if (!lineUsesTainted(lines[i], tainted)) continue;
        const ctx = lines.slice(Math.max(0, i - 4), Math.min(lines.length, i + 2));
        if (ctx.some((l) => /\b(?:allowedHosts|allowedDomains|whitelist|validateUrl|new URL|hostname|startsWith)\b/.test(l))) continue;
        findings.push({ line: startLine + i, col: 0, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "jwt-no-verify", languages: ["javascript","typescript","javascriptreact","typescriptreact","python"],
    message: "JWT decoded without signature verification",
    detail: "jwt.decode() does not verify the signature — an attacker can craft arbitrary payloads. Use jwt.verify() with a secret or public key so the signature is always validated.",
    cves: [{ id: "CWE-347", url: "https://cwe.mitre.org/data/definitions/347.html", description: "Improper Verification of Cryptographic Signature" }, { id: "CVE-2022-21449", url: "https://nvd.nist.gov/vuln/detail/CVE-2022-21449", description: "ECDSA signature bypass" }],
    run(lines, _lang, startLine) {
      const findings = [];
      for (let i = 0; i < lines.length; i++) {
        if (!/\bjwt\s*\.\s*decode\s*\(/.test(lines[i]) && !/\bjwtDecode\s*\(/.test(lines[i])) continue;
        const ctx = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 6));
        if (ctx.some((l) => /\bjwt\s*\.\s*verify\s*\(/.test(l))) continue;
        findings.push({ line: startLine + i, col: 0, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "tls-verify-disabled", languages: [],
    message: "TLS certificate verification disabled",
    detail: "Disabling certificate verification exposes all connections to man-in-the-middle attacks. Remove rejectUnauthorized:false / verify=False and use a proper CA bundle.",
    cves: [{ id: "CWE-295", url: "https://cwe.mitre.org/data/definitions/295.html", description: "Improper Certificate Validation" }],
    run(lines, _lang, startLine) {
      const findings = [];
      const patterns = [/rejectUnauthorized\s*:\s*false/, /verify\s*=\s*False/, /ssl\s*=\s*False/, /NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/];
      for (let i = 0; i < lines.length; i++) {
        if (patterns.some((re) => re.test(lines[i]))) findings.push({ line: startLine + i, col: 0, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "timing-attack", languages: [],
    message: "Potential timing attack: secret compared with ==",
    detail: "Using == or === to compare secrets allows timing side-channel attacks. Use crypto.timingSafeEqual() (Node.js) or hmac.compare_digest() (Python) instead.",
    cves: [{ id: "CWE-208", url: "https://cwe.mitre.org/data/definitions/208.html", description: "Observable Timing Discrepancy" }],
    run(lines, _lang, startLine) {
      const findings = [];
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        if (!/\b(?:token|hmac|signature|hash|mac|digest|secret|password|apiKey|api_key)\b/i.test(line)) continue;
        if (!/(?:===|==|!=|!==)/.test(line)) continue;
        if (/timingSafeEqual|hmac\.compare|crypto\.timingSafe|secrets\.compare_digest/.test(line)) continue;
        if (!(/if\s*\(|return\s|&&|\|\|/.test(line) || /[!=]==/.test(line))) continue;
        findings.push({ line: startLine + i, col: 0, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "command-injection", languages: ["javascript","typescript","javascriptreact","typescriptreact"],
    message: "Command injection: user input in exec/spawn call",
    detail: "User-controlled data is passed to a shell command. An attacker can inject shell metacharacters to run arbitrary commands. Use spawn() with an argument array and no shell:true.",
    cves: [{ id: "CWE-78", url: "https://cwe.mitre.org/data/definitions/78.html", description: "Improper Neutralization of Special Elements in OS Command" }, { id: "CVE-2020-7660", url: "https://nvd.nist.gov/vuln/detail/CVE-2020-7660", description: "Command injection via serialize-javascript" }],
    run(lines, _lang, startLine) {
      const findings = []; const tainted = buildTaintSet(lines); if (!tainted.size) return findings;
      const sinks = [/\bchild_process\s*\.\s*exec\s*\(/, /\bexec\s*\(/, /\bspawn\s*\(/, /\bexecSync\s*\(/, /\bspawnSync\s*\(/, /\bexecFile\s*\(/];
      for (let i = 0; i < lines.length; i++) {
        if (!sinks.some((re) => re.test(lines[i]))) continue;
        if (!lineUsesTainted(lines[i], tainted)) continue;
        findings.push({ line: startLine + i, col: 0, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "insecure-random-token", languages: ["python"],
    message: "Python random module used in security-sensitive context",
    detail: "The random module is not cryptographically secure. Use secrets.token_hex(), secrets.token_bytes(), or os.urandom() for any security-sensitive randomness.",
    cves: [{ id: "CWE-338", url: "https://cwe.mitre.org/data/definitions/338.html", description: "Use of Cryptographically Weak PRNG" }],
    run(lines, _lang, startLine) {
      const findings = [];
      for (let i = 0; i < lines.length; i++) {
        if (!/\brandom\s*\.\s*(?:randint|choice|choices|sample|random|uniform|shuffle)\b/.test(lines[i])) continue;
        const ctx = lines.slice(Math.max(0, i - 6), Math.min(lines.length, i + 7));
        if (ctx.some((l) => /\b(?:token|secret|key|nonce|salt|password|uuid|session|auth|csrf|otp)\b/i.test(l))) findings.push({ line: startLine + i, col: 0, severity: "warning", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
  {
    ruleId: "xxe-injection", languages: ["javascript","typescript","javascriptreact","typescriptreact","python"],
    message: "Potential XXE: XML parsed from user input without entity restrictions",
    detail: "Parsing XML from untrusted sources without disabling external entity resolution allows XXE attacks, which can read local files or trigger SSRF. Set resolveEntities:false or use a safe parser config.",
    cves: [{ id: "CWE-611", url: "https://cwe.mitre.org/data/definitions/611.html", description: "Improper Restriction of XML External Entity Reference (XXE)" }, { id: "CVE-2019-20149", url: "https://nvd.nist.gov/vuln/detail/CVE-2019-20149", description: "XXE in kind-of npm package" }],
    run(lines, _lang, startLine) {
      const findings = []; const tainted = buildTaintSet(lines);
      const parsers = [/\bDOMParser\s*\(\s*\)/, /\bparseFromString\s*\(/, /\bxml\.etree\b/, /\blxml\s*\.\s*etree\b/, /\bxmldom\b/, /\bfast-xml-parser\b/, /new\s+XMLParser\s*\(/, /\bET\s*\.\s*fromstring\s*\(/];
      for (let i = 0; i < lines.length; i++) {
        if (!parsers.some((re) => re.test(lines[i]))) continue;
        const nearby = lines.slice(Math.max(0, i - 5), Math.min(lines.length, i + 6));
        if (!nearby.some((l) => lineUsesTainted(l, tainted) || lineIsTaintSource(l))) continue;
        if (nearby.some((l) => /resolveEntities\s*:\s*false|resolve_entities\s*=\s*False|forbid_dtd/.test(l))) continue;
        findings.push({ line: startLine + i, col: 0, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      return findings;
    }
  },
];

const SEMANTIC_RULES_COUNT = SEMANTIC_RULES.length;
const TOTAL_RULES_COUNT = STATIC_RULES_COUNT + SEMANTIC_RULES_COUNT;

function semanticAnalyse(text, languageId, startLine, suppressedRules) {
  const lines = text.split("\n");
  const all = [];
  for (const rule of SEMANTIC_RULES) {
    if (suppressedRules.includes(rule.ruleId)) continue;
    if (rule.languages.length > 0 && !rule.languages.some((l) => languageId.startsWith(l))) continue;
    all.push(...rule.run(lines, languageId, startLine));
  }
  const sw = { critical: 0, warning: 1, info: 2 };
  all.sort((a, b) => a.line !== b.line ? a.line - b.line : (sw[a.severity] ?? 3) - (sw[b.severity] ?? 3));
  return all;
}

// ─── AI FINGERPRINT ──────────────────────────────────────────────────────────
function fingerprint(text) {
  const lines = text.split("\n");
  const nonEmpty = lines.filter((l) => l.trim().length > 0);
  if (!nonEmpty.length) return { isAI: false, confidence: "low" };
  let signals = 0;
  const comments = nonEmpty.filter((l) => { const t = l.trim(); return t.startsWith("//") || t.startsWith("#") || t.startsWith("/*") || t.startsWith("*") || t.startsWith("'''") || t.startsWith('"""'); });
  if (comments.length / nonEmpty.length > 0.3) signals++;
  if (comments.filter((l) => /\bthis\s+\w+s?\s+\w+\s+by\s+\w+ing\b/i.test(l)).length >= 1) signals++;
  const fns = nonEmpty.filter((l) => /\b(function\s+\w+|=>\s*\{|def\s+\w+)/.test(l));
  if (fns.length > 0 && nonEmpty.filter((l) => /\b(try\s*\{|try\s*:)/.test(l.trim())).length >= fns.length) signals++;
  const idRe = /\b([a-zA-Z_]\w{2,})\b/g;
  let tl = 0, cnt = 0;
  const reserved = new Set(["function","const","let","var","return","import","export","from","class","extends","implements","interface","type","this","new","async","await","true","false","null","undefined","void","typeof","instanceof","throw","catch","finally","while","for","break","continue","switch","case","default","else","try","delete","yield","static","super","with","debugger","enum","def","self","None","True","False","lambda","pass","raise","except","elif","print","string","number","boolean"]);
  for (const line of nonEmpty) { let m; while ((m = idRe.exec(line)) !== null) { if (!reserved.has(m[1])) { tl += m[1].length; cnt++; } } }
  if (cnt > 0 && tl / cnt > 14) signals++;
  if (/["']{3}\s*This function|\/\*\*[\s\S]*?This function/.test(text)) signals++;
  if (nonEmpty.filter((l) => /^\s*(\/\/|#)\s*Step\s+\d+[:.]/im.test(l)).length >= 2) signals++;
  if (signals >= 2) return { isAI: true, confidence: "high" };
  if (signals === 1) return { isAI: true, confidence: "medium" };
  return { isAI: false, confidence: "low" };
}

// ─── DECORATIONS ─────────────────────────────────────────────────────────────
let decorState;
function ensureDecorations() {
  if (decorState) return decorState;
  const criticalType = vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorError.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Left, borderWidth: "0 0 2px 0", borderStyle: "wavy", borderColor: new vscode.ThemeColor("editorError.foreground"), backgroundColor: "rgba(255,0,0,0.08)" });
  const warningType = vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorWarning.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Left, borderWidth: "0 0 2px 0", borderStyle: "wavy", borderColor: new vscode.ThemeColor("editorWarning.foreground"), backgroundColor: "rgba(255,165,0,0.08)" });
  const infoType = vscode.window.createTextEditorDecorationType({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorInfo.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Left, borderWidth: "0 0 2px 0", borderStyle: "dashed", borderColor: new vscode.ThemeColor("editorInfo.foreground"), backgroundColor: "rgba(0,120,255,0.05)" });
  decorState = { criticalType, warningType, infoType, activeRanges: new Map() };
  return decorState;
}
function applyDecorations(editor, findings) {
  const s = ensureDecorations(); const crit = [], warn = [], info = [];
  for (const f of findings) {
    if (f.line < 0 || f.line >= editor.document.lineCount) continue;
    const lineRange = editor.document.lineAt(f.line).range;
    const hover = new vscode.MarkdownString("**[" + f.ruleId + "]** " + f.message + "\n\n" + f.detail);
    const dec = { range: lineRange, hoverMessage: hover, renderOptions: { after: { contentText: " " + (f.severity === "critical" ? "\uD83D\uDD34" : f.severity === "warning" ? "\uD83D\DFE1" : "\uD83D\uDD35") + " " + f.ruleId } } };
    s.activeRanges.set(editor.document.uri.toString() + ":" + f.line, lineRange);
    if (f.severity === "critical") crit.push(dec); else if (f.severity === "warning") warn.push(dec); else info.push(dec);
  }
  editor.setDecorations(s.criticalType, crit);
  editor.setDecorations(s.warningType, warn);
  editor.setDecorations(s.infoType, info);
}
function createEditClearListener() {
  return vscode.workspace.onDidChangeTextDocument((event) => {
    if (!decorState) return;
    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document !== event.document) return;
    for (const change of event.contentChanges) {
      for (let line = change.range.start.line; line <= change.range.end.line; line++) {
        if (decorState.activeRanges.has(event.document.uri.toString() + ":" + line)) {
          editor.setDecorations(decorState.criticalType, []);
          editor.setDecorations(decorState.warningType, []);
          editor.setDecorations(decorState.infoType, []);
          return;
        }
      }
    }
  });
}
function disposeDecorations() {
  if (decorState) { decorState.criticalType.dispose(); decorState.warningType.dispose(); decorState.infoType.dispose(); decorState = undefined; }
}

// ─── PANEL ───────────────────────────────────────────────────────────────────
const HIGH_CONF_RULES = new Set(["eval-external","hardcoded-secret","shell-injection","pickle-loads"]);

function escHtml(t) { return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
function sevLabel(s) { return s === "critical" ? "CRIT" : s === "warning" ? "WARN" : "INFO"; }
function confLabel(f) {
  if (f.severity === "critical" && HIGH_CONF_RULES.has(f.ruleId)) return { label: "high confidence", cls: "conf-high" };
  if (f.severity === "warning") return { label: "review", cls: "conf-review" };
  return { label: "medium confidence", cls: "conf-med" };
}
function renderCveBadges(cves) {
  if (!cves || !cves.length) return "";
  const badges = cves.map((c) => '<button class="cve-badge" onclick="openCve(\'' + escHtml(c.url) + '\')" title="' + escHtml(c.description) + '">' + escHtml(c.id) + '</button>').join("");
  return '<div class="cve-row"><span class="cve-label">References</span>' + badges + '</div>';
}

const SHIELD_SVG = '<svg width="20" height="20" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg"><defs><linearGradient id="sg" x1="3" y1="2" x2="21" y2="23" gradientUnits="userSpaceOnUse"><stop offset="0%" stop-color="#60a5fa"/><stop offset="100%" stop-color="#1d4ed8"/></linearGradient></defs><path d="M12 2L3 6.5V12c0 5.25 3.8 9.74 9 10.93C17.2 21.74 21 17.25 21 12V6.5L12 2Z" fill="url(#sg)"/><path d="M8.5 12l2.5 2.5 4.5-4.5" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>';

class PasteGuardPanel {
  constructor() { this.panel = undefined; this.disposables = []; this._currentFindings = []; }

  show(findings, fp) {
    this._currentFindings = findings;
    if (this.panel) { this.panel.webview.html = this.buildHtml(findings, fp); this.panel.reveal(vscode.ViewColumn.Beside, true); return; }
    this.panel = vscode.window.createWebviewPanel("shieldpromptPanel", "ShieldPrompt", { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true }, { enableScripts: true, retainContextWhenHidden: true });
    this.panel.webview.html = this.buildHtml(findings, fp);
    this.panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === "openCve") {
        await vscode.env.openExternal(vscode.Uri.parse(msg.url));
      } else if (msg.type === "ignoreThis") {
        const finding = this._currentFindings[msg.findingIndex];
        if (!finding) return;
        const editor = vscode.window.activeTextEditor;
        if (!editor) return;
        const line = editor.document.lineAt(finding.line);
        await editor.edit((eb) => { eb.replace(line.range, line.text + " // shieldprompt-ignore: " + finding.ruleId); });
        vscode.window.showInformationMessage("ShieldPrompt: Rule " + finding.ruleId + " ignored on line " + (finding.line + 1) + ".");
      }
    }, null, this.disposables);
    this.panel.onDidDispose(() => { this.panel = undefined; this.disposables.forEach((d) => d.dispose()); this.disposables = []; }, null, this.disposables);
  }

  reveal() { if (this.panel) this.panel.reveal(vscode.ViewColumn.Beside, true); }
  dispose() { if (this.panel) this.panel.dispose(); }

  buildHtml(findings, fp) {
    const critN = findings.filter((f) => f.severity === "critical").length;
    const warnN = findings.filter((f) => f.severity === "warning").length;
    const infoN = findings.filter((f) => f.severity === "info").length;
    const total = findings.length;
    const parts = [];
    if (critN) parts.push(critN + " critical");
    if (warnN) parts.push(warnN + " warning" + (warnN > 1 ? "s" : ""));
    if (infoN) parts.push(infoN + " info");
    const summaryText = total === 0 ? "No issues found" : total + " issue" + (total > 1 ? "s" : "") + " found \u2014 " + parts.join(", ");

    const fpBadge = (fp.confidence === "high" || fp.confidence === "medium")
      ? '<div class="ai-badge ' + fp.confidence + '"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>AI-generated code detected (' + fp.confidence + ' confidence)</div>'
      : "";

    const findingsList = findings.map((f, i) => {
      const conf = confLabel(f);
      const cveBadges = renderCveBadges(f.cves);
      return '<div class="finding ' + f.severity + '">' +
        '<div class="finding-header" onclick="toggle(' + i + ')">' +
          '<span class="sev-pill ' + f.severity + '">' + sevLabel(f.severity) + '</span>' +
          '<span class="conf ' + conf.cls + '">' + conf.label + '</span>' +
          '<span class="fl">L' + (f.line + 1) + '</span>' +
          '<span class="fr">' + escHtml(f.ruleId) + '</span>' +
          '<span class="fm">' + escHtml(f.message) + '</span>' +
          '<span class="chevron" id="ch-' + i + '">&#9654;</span>' +
        '</div>' +
        '<div class="finding-detail" id="det-' + i + '" style="display:none">' +
          '<p>' + escHtml(f.detail) + '</p>' +
          cveBadges +
          '<button class="ignore-btn" onclick="ignoreThis(' + i + ')">Ignore on this line</button>' +
        '</div>' +
      '</div>';
    }).join("\n");

    const emptyHtml = '<div class="empty">' +
      '<div class="empty-shield">' + SHIELD_SVG + '</div>' +
      '<p class="empty-title">Code looks clean</p>' +
      '<p class="empty-sub">Checked ' + TOTAL_RULES_COUNT + ' security patterns &mdash; no issues found.</p>' +
    '</div>';

    return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><style>' +
':root{--bg:var(--vscode-editor-background,#1e1e1e);--bg2:var(--vscode-sideBar-background,#252526);--fg:var(--vscode-editor-foreground,#ccc);--fg2:var(--vscode-descriptionForeground,#858585);--border:var(--vscode-panel-border,#333);--crit-fg:#ff6b6b;--crit-bg:rgba(255,107,107,.1);--warn-fg:#ffa500;--warn-bg:rgba(255,165,0,.1);--info-fg:#4fc3f7;--info-bg:rgba(79,195,247,.08);--blue:#3b82f6;--r:6px;--font:var(--vscode-font-family,-apple-system,BlinkMacSystemFont,sans-serif);--mono:var(--vscode-editor-font-family,"Cascadia Code","Fira Code",monospace)}' +
'*{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--font);font-size:var(--vscode-font-size,13px);color:var(--fg);background:var(--bg);padding:14px 16px 28px;line-height:1.5}' +
'.header{display:flex;align-items:center;gap:8px;margin-bottom:14px}.header-title{font-size:15px;font-weight:600;letter-spacing:-.01em}' +
'.ai-badge{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:20px;font-size:12px;font-weight:600;margin-bottom:14px;border:1px solid}' +
'.ai-badge.high{background:var(--crit-bg);border-color:var(--crit-fg);color:var(--crit-fg)}.ai-badge.medium{background:var(--warn-bg);border-color:var(--warn-fg);color:var(--warn-fg)}' +
'.summary{background:var(--bg2);border-left:3px solid var(--blue);border-radius:0 var(--r) var(--r) 0;padding:9px 13px;margin-bottom:14px;font-size:13px}' +
'.finding{border:.5px solid var(--border);border-radius:var(--r);margin-bottom:7px;overflow:hidden}.finding.critical{border-left:3px solid var(--crit-fg)}.finding.warning{border-left:3px solid var(--warn-fg)}.finding.info{border-left:3px solid var(--info-fg)}' +
'.finding-header{display:flex;align-items:center;gap:7px;padding:8px 11px;cursor:pointer;user-select:none}.finding-header:hover{background:rgba(255,255,255,.03)}' +
'.sev-pill{padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;flex-shrink:0}.sev-pill.critical{background:var(--crit-bg);color:var(--crit-fg)}.sev-pill.warning{background:var(--warn-bg);color:var(--warn-fg)}.sev-pill.info{background:var(--info-bg);color:var(--info-fg)}' +
'.conf{font-size:10px;opacity:.6;flex-shrink:0}.fl{font-size:11px;color:var(--fg2);flex-shrink:0;font-family:var(--mono)}.fr{font-size:12px;font-family:var(--mono);opacity:.65;flex-shrink:0}.fm{flex:1;font-size:13px}' +
'.chevron{font-size:10px;opacity:.4;flex-shrink:0;transition:transform .15s}.chevron.open{transform:rotate(90deg)}' +
'.finding-detail{padding:10px 14px 13px;background:var(--bg2);border-top:.5px solid var(--border)}.finding-detail p{margin-bottom:9px;color:var(--fg2);font-size:12px;line-height:1.6}' +
'.cve-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:10px}.cve-label{font-size:11px;color:var(--fg2);flex-shrink:0;margin-right:2px}' +
'.cve-badge{display:inline-flex;align-items:center;padding:2px 8px;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.4);border-radius:4px;color:#60a5fa;font-size:11px;font-family:var(--mono);font-weight:600;cursor:pointer;transition:background .12s,border-color .12s}.cve-badge:hover{background:rgba(59,130,246,.25);border-color:rgba(59,130,246,.75)}' +
'.ignore-btn{padding:4px 11px;background:transparent;color:var(--fg2);border:1px solid var(--border);border-radius:4px;cursor:pointer;font-size:12px;transition:border-color .12s,color .12s}.ignore-btn:hover{border-color:var(--fg);color:var(--fg)}' +
'.empty{text-align:center;padding:52px 20px 44px}.empty-shield{display:flex;justify-content:center;margin-bottom:16px}.empty-shield svg{width:48px;height:48px;opacity:.5}.empty-title{font-size:15px;font-weight:600;margin-bottom:6px}.empty-sub{font-size:12px;color:var(--fg2);opacity:.7}' +
'</style></head><body>' +
'<div class="header">' + SHIELD_SVG + '<span class="header-title">ShieldPrompt</span></div>' +
fpBadge +
'<div class="summary">' + summaryText + '</div>' +
(total === 0 ? emptyHtml : findingsList) +
'<script>' +
'var vscode=acquireVsCodeApi();' +
'function toggle(i){var d=document.getElementById("det-"+i),c=document.getElementById("ch-"+i);if(!d||!c)return;var o=d.style.display!=="none";d.style.display=o?"none":"block";c.classList.toggle("open",!o);}' +
'function ignoreThis(i){vscode.postMessage({type:"ignoreThis",findingIndex:i});}' +
'function openCve(url){vscode.postMessage({type:"openCve",url:url});}' +
'</script></body></html>';
  }
}

// ─── EXTENSION MAIN ──────────────────────────────────────────────────────────
let statusBarItem, panelInstance;
let currentFindings = [];
let currentFingerprint = { isAI: false, confidence: "low" };

function activate(context) {
  panelInstance = new PasteGuardPanel();
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = "pasteguard.openPanel";
  statusBarItem.text = "$(shield) ShieldPrompt: 0 issues";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  context.subscriptions.push(vscode.commands.registerCommand("pasteguard.openPanel", () => { panelInstance.show(currentFindings, currentFingerprint); }));
  context.subscriptions.push(vscode.commands.registerCommand("pasteguard.resetSuppressions", () => { vscode.workspace.getConfiguration("pasteguard").update("suppressedRules", [], vscode.ConfigurationTarget.Workspace); vscode.window.showInformationMessage("ShieldPrompt: All rule suppressions reset."); }));
  context.subscriptions.push(vscode.commands.registerCommand("pasteguard.toggleEnabled", () => { const cfg = vscode.workspace.getConfiguration("pasteguard"); const cur = cfg.get("enabled", true); cfg.update("enabled", !cur, vscode.ConfigurationTarget.Workspace); vscode.window.showInformationMessage("ShieldPrompt: " + (cur ? "Disabled" : "Enabled")); }));

  const pasteDisposable = onPaste((text, document, range) => {
    const config = vscode.workspace.getConfiguration("pasteguard");
    const suppressedRules = config.get("suppressedRules", []);
    const languageId = document.languageId;

    const staticFindings = analyse(text, languageId, range.start.line, suppressedRules);
    const semanticFindings = semanticAnalyse(text, languageId, range.start.line, suppressedRules);

    const seen = new Set(staticFindings.map((f) => f.line + ":" + f.ruleId));
    const merged = [...staticFindings];
    for (const f of semanticFindings) {
      const key = f.line + ":" + f.ruleId;
      if (!seen.has(key)) { merged.push(f); seen.add(key); }
    }
    const sw = { critical: 0, warning: 1, info: 2 };
    merged.sort((a, b) => a.line !== b.line ? a.line - b.line : (sw[a.severity] != null ? sw[a.severity] : 3) - (sw[b.severity] != null ? sw[b.severity] : 3));

    const fp = fingerprint(text);
    currentFindings = merged;
    currentFingerprint = fp;
    updateStatusBar(merged);

    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document === document) applyDecorations(editor, merged);

    // Always open panel so user gets feedback even when code is clean
    panelInstance.show(merged, fp);
  });

  context.subscriptions.push(pasteDisposable);
  context.subscriptions.push(createEditClearListener());
  context.subscriptions.push({ dispose() { panelInstance.dispose(); disposeDecorations(); } });
}

function updateStatusBar(findings) {
  const count = findings.length;
  statusBarItem.text = "$(shield) ShieldPrompt: " + count + " issue" + (count !== 1 ? "s" : "");
  const hasCrit = findings.some((f) => f.severity === "critical");
  const hasWarn = findings.some((f) => f.severity === "warning");
  statusBarItem.backgroundColor = hasCrit
    ? new vscode.ThemeColor("statusBarItem.errorBackground")
    : hasWarn ? new vscode.ThemeColor("statusBarItem.warningBackground") : undefined;
}

function deactivate() {}