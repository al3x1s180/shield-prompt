"use strict";
var __export = (target, all) => { for (var k in all) Object.defineProperty(target, k, { get: all[k], enumerable: true }); };
var __toCommonJS = (mod) => { const m = Object.defineProperty({}, "__esModule", { value: true }); for (const k of Object.getOwnPropertyNames(mod)) Object.defineProperty(m, k, { get: () => mod[k], enumerable: true }); return m; };
var src_exports = {};
__export(src_exports, { activate: () => activate, deactivate: () => deactivate });
module.exports = __toCommonJS(src_exports);

const vscode = require("vscode");
const { loadRules, loadFrameworkRules, loadFrameworkManifest, detectFrameworks, readAllDeps, forceRemoteUpdate } = require("./ruleLoader");
const { runProjectScan, FILE_LIMIT } = require("./projectScanner");

// ─── TAINT HELPERS ──────────────────────────────────────────────────────────
const TAINT_SOURCES = [
  /\breq\.(body|params|query|headers|cookies)\b/,
  /\brequest\.(form|args|json|data|files|headers|cookies)\b/,
  /\bprocess\.argv\b/, /\bwindow\.location\b/,
  /\bdocument\.(?:cookie|referrer|URL|location)\b/, /\.value\b/,
  /\binput\s*\(/, /\bos\.environ\b/, /\bsys\.argv\b/,
  /\bgetenv\s*\(/, /\br\.FormValue\b/, /\br\.URL\.Query\b/,
  /\bRequest\.\w+\b/, /\bHttpContext\.\w+\b/, /\bgetParameter\s*\(/,
  /\$_(?:GET|POST|REQUEST|COOKIE|SERVER)\b/,
  /\b(?:params|cookies)\[/, /\brequest\.params\b/,
];

function assignedVar(line) {
  const m = line.match(/(?:const|let|var|val|my|our)\s+([a-zA-Z_$][\w$]*)\s*=|^([a-zA-Z_$][\w$]*)\s*=/);
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
  if (lineIsTaintSource(line)) return true;
  for (const v of tainted.keys()) { if (new RegExp("\\b" + v + "\\b").test(line)) return true; }
  return false;
}

// ─── ENTROPY ────────────────────────────────────────────────────────────────
function shannonEntropy(str) {
  const freq = {};
  for (const c of str) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((h, count) => { const p = count / str.length; return h - p * Math.log2(p); }, 0);
}

const SECRET_FP = new Set(["success","failure","pass","fail","passed","failed","error","true","false","yes","no","none","null","undefined","empty","test","testing","example","sample","placeholder","changeme","todo","fixme","required","optional","invalid","valid","missing","default","admin","user","guest","public","private","enabled","disabled","pending","active","inactive","unknown","loading"]);
const SECRET_MOCK = /^(abc123|1234567|12345678|password123|qwerty|asdfgh|aaaaaa+|bbbbbb+|000000+|111111+|test1234|mock.*)$/i;

// ─── RULE ENGINE ─────────────────────────────────────────────────────────────
/**
 * Run all rules for a given language against the pasted text.
 * @param {string}   text           - pasted code
 * @param {string}   languageId     - VS Code language ID
 * @param {number}   startLine      - line offset in the document
 * @param {string[]} suppressedRules
 * @param {Map}      rulesMap       - language → rules[] from loader
 * @returns {Array}  findings
 */
function runRules(text, languageId, startLine, suppressedRules, rulesMap) {
  const lines   = text.split("\n");
  const tainted = buildTaintSet(lines);
  const rules   = rulesMap.get(languageId) || [];
  const findings = [];
  // Track ruleId:line to avoid duplicates within this run
  const seen = new Set();

  for (const rule of rules) {
    if (suppressedRules.includes(rule.ruleId)) continue;

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      const findingKey = rule.ruleId + ":" + (startLine + i);
      if (seen.has(findingKey)) continue;

      // Inline suppress
      if (line.includes("shieldprompt-ignore")) {
        const sm = line.match(/shieldprompt-ignore:\s*([\w-]+)/);
        if (!sm || sm[1] === rule.ruleId) continue;
      }

      let matched = false;
      for (const pattern of (rule.patterns || [])) {
        const re = new RegExp(pattern.match, pattern.flags || "g");

        if (pattern.context === "multiline" && pattern.windowLines) {
          // CRITICAL: for multiline patterns, the anchor line (i) must itself
          // match the pattern OR the pattern must match starting within 1 line
          // of i. We test the current line first as a quick anchor check.
          // Then build the full window for safeguard scanning only.
          const anchorRe = new RegExp(pattern.match, (pattern.flags || "g").replace("m", ""));
          const lineMatches = anchorRe.test(line);
          if (!lineMatches) continue; // pattern must hit the current line

          const start = Math.max(0, i - pattern.windowLines);
          const end   = Math.min(lines.length - 1, i + pattern.windowLines);
          const windowText = lines.slice(start, end + 1).join("\n");

          // Safeguard check in full window
          const hasSafeguard = (rule.safeguards || []).some((sg) => new RegExp(sg, "i").test(windowText));
          if (hasSafeguard) continue;

          matched = true;
        } else {
          // Single-line match
          if (!re.test(line)) continue;

          // Taint check
          if (rule.requiresTaint && !lineUsesTainted(line, tainted)) {
            const nearby = lines.slice(Math.max(0, i - 3), Math.min(lines.length, i + 4));
            if (!nearby.some((l) => lineUsesTainted(l, tainted))) continue;
          }

          // Safeguard check in surrounding lines
          const windowStart = Math.max(0, i - 4);
          const windowEnd   = Math.min(lines.length - 1, i + 2);
          const windowText  = lines.slice(windowStart, windowEnd + 1).join("\n");
          const hasSafeguard = (rule.safeguards || []).some((sg) => new RegExp(sg, "i").test(windowText));
          if (hasSafeguard) continue;

          matched = true;
        }

        if (matched) break;
      }

      if (!matched) continue;

      // Context keywords check
      if (rule.contextKeywords && rule.contextKeywords.length > 0) {
        const ctxStart = Math.max(0, i - 6);
        const ctxEnd   = Math.min(lines.length - 1, i + 6);
        const ctxText  = lines.slice(ctxStart, ctxEnd + 1).join("\n");
        const inContext = rule.contextKeywords.some((kw) => new RegExp("\\b" + kw + "\\b", "i").test(ctxText));
        if (!inContext) continue;
      }

      // Entropy check for secrets
      if (rule.entropyCheck) {
        const valMatch = line.match(/[`'""]([^`'""\n]{8,})[`'""]/);
        if (valMatch) {
          const val = valMatch[1];
          const vl  = val.toLowerCase();
          if (val.length <= rule.entropyCheck.minLength) continue;
          if (SECRET_FP.has(vl)) continue;
          if (/^(your_|<|\{|\$|%|__)/.test(val)) continue;
          if (SECRET_MOCK.test(val)) continue;
          if (/^(.)\1+$/.test(val)) continue;
          if (shannonEntropy(val) <= rule.entropyCheck.minEntropy) continue;
        }
      }

      seen.add(findingKey);
      findings.push({
        line:     startLine + i,
        col:      0,
        severity: rule.severity || "warning",
        ruleId:   rule.ruleId,
        message:  rule.message,
        detail:   rule.detail,
        cves:     rule.cves || [],
      });
    }
  }

  const sw = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => a.line !== b.line ? a.line - b.line : (sw[a.severity] ?? 3) - (sw[b.severity] ?? 3));
  return findings;
}

// ─── AI FINGERPRINT ──────────────────────────────────────────────────────────
function fingerprint(text) {
  const lines    = text.split("\n");
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


// ─── INLINE RULE ENGINE ──────────────────────────────────────────────────────
const INLINE_SECRET_SHAPES = [
  { re: /AKIA[A-Z0-9]{16}/, label: "AWS Access Key ID" },
  { re: /(sk|pk)_(live|test)_[A-Za-z0-9]{20,}/, label: "Stripe API key" },
  { re: /whsec_[A-Za-z0-9]{20,}/, label: "Stripe webhook secret" },
  { re: /rk_live_[A-Za-z0-9]{20,}/, label: "Stripe restricted key" },
  { re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/, label: "SendGrid API key" },
  { re: /xox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]{10,}/, label: "Slack token" },
  { re: /ghp_[A-Za-z0-9]{36}/, label: "GitHub personal token" },
  { re: /ghs_[A-Za-z0-9]{36}/, label: "GitHub Actions secret" },
  { re: /gho_[A-Za-z0-9]{36}/, label: "GitHub OAuth token" },
  { re: /github_pat_[A-Za-z0-9_]{59}/, label: "GitHub fine-grained PAT" },
  { re: /AIza[A-Za-z0-9_-]{35}/, label: "Google API key" },
  { re: /ya29\.[A-Za-z0-9_-]{50,}/, label: "Google OAuth token" },
  { re: /SK[a-fA-F0-9]{32}/, label: "Twilio API key" },
  { re: /AC[a-fA-F0-9]{32}/, label: "Twilio Account SID" },
  { re: /EAA[A-Za-z0-9]{50,}/, label: "Facebook access token" },
  { re: /key-[A-Za-z0-9]{32}/, label: "Mailgun API key" },
  { re: /npm_[A-Za-z0-9]{36}/, label: "npm token" },
  { re: /glpat-[A-Za-z0-9_-]{20}/, label: "GitLab personal token" },
  { re: /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/, label: "JWT token" },
];
const INLINE_SECRET_FP = new Set(["success","failure","pass","fail","passed","failed","error","true","false","yes","no","none","null","undefined","empty","test","testing","example","sample","placeholder","changeme","todo","fixme","required","optional","invalid","valid","missing","default","admin","user","guest","public","private","enabled","disabled","pending","active","inactive","unknown","loading","development","production","staging","localhost","notset","insert_here","replace_me","your_secret","my_secret","enter_here"]);
const INLINE_MOCK_RE = /^(abc123|1234567|12345678|password123|qwerty|asdfgh|aaaaaa+|bbbbbb+|000000+|111111+|test1234|mock.*|dummy.*|fake.*|your_.*|my_.*|<.*>|\$\{.*\}|%.*%)$/i;
const INLINE_SECRET_KW = /\b(?:webhookauth|webhook_secret|webhooksecret|webhook_key|signing_key|signingkey|hmac_key|hmac_secret|session_secret|sessionsecret|cookie_secret|stripe_secret|stripe_key|stripekey|twilio_token|twilio_secret|sendgrid_key|sendgrid_secret|mailgun_key|mailgun_secret|github_token|github_secret|gh_token|gitlab_token|slack_token|slack_secret|discord_token|discord_secret|firebase_key|firebase_secret|aws_secret|aws_key|openai_key|openai_secret|anthropic_key|algolia_key|pusher_secret|vault_token|master_key|master_password|db_password|db_pass|database_password|dbpassword|db_secret|mongo_uri|mongodb_uri|redis_url|database_url|db_url)\b/i;
const INLINE_DANGEROUS_ALIAS_SRC = [/\beval\b/,/require\s*\(\s*['"\`]child_process['"\`]\s*\)\s*\.\s*exec\b/,/child_process\s*\.\s*exec\b/,/global\s*\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/,/window\s*\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/];
const INLINE_INSECURE_JS = [
  { ruleId:"insecure-session-secret",severity:"critical",re:/session\s*\(\s*\{[^}]*secret\s*:\s*['"\`][^'"\`]{1,30}['"\`]/i,msg:"Express session with short or hardcoded secret",det:"session() secret should come from an environment variable and be at least 32 random characters.",safeguard:/process\.env\.|config\.|getenv/i},
  { ruleId:"jwt-no-expiry",severity:"warning",re:/jwt\.sign\s*\([^)]*\)/,msg:"JWT signed without expiry (expiresIn missing)",det:"Tokens without expiry are valid forever. Always set expiresIn: '15m' or similar.",safeguard:/expiresIn|exp\s*:|expires_in/i,winAfter:3},
  { ruleId:"cors-no-config",severity:"warning",re:/\bapp\.use\s*\(\s*cors\s*\(\s*\)\s*\)/i,msg:"cors() with no config — allows all origins",det:"cors() with no arguments permits requests from any origin. Configure origin explicitly.",safeguard:/origin\s*:/i},
  { ruleId:"jwt-alg-none",severity:"critical",re:/algorithms?\s*:\s*\[?\s*['"]none['"]/i,msg:"JWT algorithm 'none' — signature verification bypassed",det:"Accepting 'none' allows attackers to forge tokens. Specify your signing algorithm."},
  { ruleId:"deep-merge-unguarded",severity:"warning",re:/(?:defaultsDeep|mergeDeep|deepMerge|extend\s*\(\s*true)\s*\(/i,msg:"Deep merge without prototype pollution guard",det:"Deep merge functions are vulnerable to prototype pollution. Validate or strip __proto__ and constructor keys before merging.",safeguard:/hasOwnProperty|Object\.create\s*\(null\)|sanitize|allowedKeys/i},
];
function inlineSecretOk(val) {
  if (!val || val.length < 9) return false;
  if (INLINE_SECRET_FP.has(val.toLowerCase())) return false;
  if (INLINE_MOCK_RE.test(val)) return false;
  if (/^(.)\1{5,}$/.test(val)) return false;
  if (/^[a-z_]+$/.test(val) && val.length < 16) return false;
  if (shannonEntropy(val) < 2.8) return false;
  return true;
}
function stripCmt(l) { return l.replace(/(?<!['"\/])\/\/.*$/, "").replace(/^\s*#.*$/, ""); }
function codeWin2(lines, i, before, after) { return lines.slice(Math.max(0,i-before),Math.min(lines.length,i+(after||1)+1)).map(stripCmt).join("\n"); }
function runInlineRules(text, languageId, startLine, suppressedRules) {
  const isJS = /^(?:javascript|typescript|javascriptreact|typescriptreact)/.test(languageId);
  const isPY = languageId === "python";
  const lines = text.split("\n");
  const findings = [];
  const seen = new Set();
  function push(li, col, sev, ruleId, msg, det) {
    if (suppressedRules.includes(ruleId)) return;
    const key = ruleId+":"+(startLine+li)+":"+col;
    if (seen.has(key)) return;
    seen.add(key);
    findings.push({ line:startLine+li, col, severity:sev, ruleId, message:msg, detail:det, cves:[] });
  }
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.includes("shieldprompt-ignore")) continue;
    // Value-shape secrets
    for (const {re, label} of INLINE_SECRET_SHAPES) {
      const r2 = new RegExp(re.source, "g"); let m;
      while ((m = r2.exec(line)) !== null)
        push(i, m.index, "critical", "hardcoded-secret", label+" detected in source code", "A "+label+" was found hardcoded. Revoke and rotate this credential immediately, then store it in an environment variable.");
    }
    // Expanded keyword secrets (mid-compound words)
    if (INLINE_SECRET_KW.test(line)) {
      const kre = new RegExp(INLINE_SECRET_KW.source+"\\s*[:=]\\s*[\"'\`]([^\"'\`]+)[\"'\`]","gi"); let m;
      while ((m = kre.exec(line)) !== null) { const v=m[m.length-1]; if(inlineSecretOk(v)) push(i,m.index,"critical","hardcoded-secret","Hardcoded secret or credential detected","Credentials in source code can be extracted by anyone with repo access. Use environment variables or a secrets manager."); }
    }
    // Connection string secrets
    { const r=/(?:mongodb|postgresql|postgres|mysql|mssql|redis|amqp|amqps|smtp|ftp|sftp|ldap|ldaps):\/\/[^:@\s"'\`]*:([^@\s"'\`]{4,})@/gi; let m;
      while((m=r.exec(line))!==null){const p=m[1];if(/^\$\{|^%|^<|password|placeholder|changeme/i.test(p))continue;if(INLINE_SECRET_FP.has(p.toLowerCase()))continue;push(i,m.index,"critical","secret-in-url","Password in connection string","Credentials in URLs are logged by proxies. Extract them to environment variables.");}}
    { const r=/[?&](?:api_?key|token|secret|password|auth|apikey)=([^&"'\`\s]{8,})/gi; let m;
      while((m=r.exec(line))!==null){const v=m[1];if(/^\$\{|^%|^<|placeholder/i.test(v))continue;if(!inlineSecretOk(v))continue;push(i,m.index,"critical","secret-in-url","Secret in URL query parameter","Secrets in URL params are logged in access logs. Use Authorization headers instead.");}}
    // Variable-name-agnostic SQL
    if (isJS||isPY) {
      let m;
      const t=/\`[^\`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|TRUNCATE)\b[^\`]*\$\{/gi; while((m=t.exec(line))!==null) push(i,m.index,"critical","sql-concat","SQL injection: dynamic query in template literal","Use parameterised queries.");
      const f=/f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b[^"']*\{/gi; while((m=f.exec(line))!==null) push(i,m.index,"critical","sql-concat","SQL injection: dynamic query in f-string","Use parameterised queries.");
      const e=/\.(?:execute|query|run|exec)\s*\(\s*["'\`][^"'\`]*["'\`]\s*\+/gi; while((m=e.exec(line))!==null) push(i,m.index,"critical","sql-concat","SQL injection: string concat in database call","Use parameterised queries.");
    }
    // Multi-line SQL
    if ((isJS||isPY) && /\.(?:query|execute|run|exec|all|get|prepare)\s*\(/i.test(line)) {
      const vm=line.match(/\.(?:query|execute|run|exec|all|get|prepare)\s*\(\s*([a-zA-Z_$][\w$]*)/i);
      if(vm){const vn=vm[1];const lb=lines.slice(Math.max(0,i-10),i);const ar=new RegExp("\\b"+vn+"\\b.*\\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\\b","i");const hd=lb.some(l=>ar.test(l)&&/\$\{|\+\s*\w|f["']/. test(l));const hs=/\?\s*,|\$[0-9]|parameterized|prepared|\bparams\s*:/i.test(lb.join("\n"));if(hd&&!hs)push(i,0,"critical","sql-concat","SQL injection: dynamic query variable in database call","A dynamically built SQL variable is passed to a database call. Use parameterised queries.");}
    }
    // Dangerous alias (JS)
    if (isJS) {
      const am=/(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=/.exec(line);
      if(am){const rhs=line.slice(line.indexOf("=")+1);if(INLINE_DANGEROUS_ALIAS_SRC.some(s=>s.test(rhs)))push(i,am.index,"critical","dangerous-alias","'"+am[1]+"' assigned a dangerous function reference","Storing eval or exec in a variable and calling it later bypasses static analysis.");}
      const lb30=lines.slice(Math.max(0,i-30),i);
      for(const prev of lb30){const pm=/(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=/.exec(prev);if(!pm)continue;const rhs=prev.slice(prev.indexOf("=")+1);if(!INLINE_DANGEROUS_ALIAS_SRC.some(s=>s.test(rhs)))continue;const alias=pm[1];const cr=new RegExp("\\b"+alias+"\\s*\\(","g");let m;while((m=cr.exec(line))!==null)push(i,m.index,"critical","dangerous-alias","Call to aliased dangerous function '"+alias+"'","'"+alias+"' was assigned a dangerous function reference earlier. Calling it is equivalent to calling the original dangerous function.");}
    }
    // Insecure defaults (JS)
    if (isJS) {
      for(const def of INLINE_INSECURE_JS){if(!def.re.test(line))continue;if(def.safeguard){const w=codeWin2(lines,i,2,def.winAfter||2);if(def.safeguard.test(w))continue;}push(i,0,def.severity,def.ruleId,def.msg,def.det);}
    }
  }
  const sw={critical:0,warning:1,info:2};
  findings.sort((a,b)=>a.line!==b.line?a.line-b.line:(sw[a.severity]||3)-(sw[b.severity]||3));
  return findings;
}

// ─── PASTE DETECTOR ──────────────────────────────────────────────────────────
function onPaste(callback) {
  const lastChange = { time: 0 };
  let debounceTimer;
  return vscode.workspace.onDidChangeTextDocument((event) => {
    const config = vscode.workspace.getConfiguration("shieldprompt");
    if (!config.get("enabled", true)) return;
    if (event.reason === vscode.TextDocumentChangeReason.Undo || event.reason === vscode.TextDocumentChangeReason.Redo) return;
    if (event.document.uri.scheme !== "file" && event.document.uri.scheme !== "untitled") return;
    const minLines = config.get("minLines", 3);
    const now = Date.now();
    const timeSince = now - lastChange.time;
    for (const change of event.contentChanges) {
      const lineCount = change.text.split("\n").length;
      if (lineCount >= minLines || (change.text.length > 80 && timeSince > 150)) {
        const startLine = change.range.start.line;
        const startChar = change.range.start.character;
        const endLine   = startLine + lineCount - 1;
        const ls        = change.text.split("\n");
        const endChar   = lineCount === 1 ? startChar + ls[0].length : ls[ls.length - 1].length;
        const range     = new vscode.Range(startLine, startChar, endLine, endChar);
        if (debounceTimer !== undefined) clearTimeout(debounceTimer);
        debounceTimer = setTimeout(() => { callback(change.text, event.document, range); debounceTimer = undefined; }, 300);
      }
    }
    lastChange.time = now;
  });
}

// ─── DECORATIONS ─────────────────────────────────────────────────────────────
let decorState;
function ensureDecorations() {
  if (decorState) return decorState;
  const mk = (opts) => vscode.window.createTextEditorDecorationType(opts);
  decorState = {
    criticalType: mk({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorError.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Left, borderWidth: "0 0 2px 0", borderStyle: "wavy", borderColor: new vscode.ThemeColor("editorError.foreground"), backgroundColor: "rgba(255,0,0,0.08)" }),
    warningType:  mk({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorWarning.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Left, borderWidth: "0 0 2px 0", borderStyle: "wavy", borderColor: new vscode.ThemeColor("editorWarning.foreground"), backgroundColor: "rgba(255,165,0,0.08)" }),
    infoType:     mk({ isWholeLine: true, overviewRulerColor: new vscode.ThemeColor("editorInfo.foreground"), overviewRulerLane: vscode.OverviewRulerLane.Left, borderWidth: "0 0 2px 0", borderStyle: "dashed", borderColor: new vscode.ThemeColor("editorInfo.foreground"), backgroundColor: "rgba(0,120,255,0.05)" }),
    activeRanges: new Map(),
  };
  return decorState;
}
function applyDecorations(editor, findings) {
  const s = ensureDecorations(); const crit = [], warn = [], info = [];
  for (const f of findings) {
    if (f.line < 0 || f.line >= editor.document.lineCount) continue;
    const lineRange = editor.document.lineAt(f.line).range;
    const hover     = new vscode.MarkdownString("**[" + f.ruleId + "]** " + f.message + "\n\n" + f.detail);
    const icon      = f.severity === "critical" ? "\uD83D\uDD34" : f.severity === "warning" ? "\uD83D\uDFE1" : "\uD83D\uDD35";
    const dec       = { range: lineRange, hoverMessage: hover, renderOptions: { after: { contentText: " " + icon + " " + f.ruleId } } };
    s.activeRanges.set(editor.document.uri.toString() + ":" + f.line, lineRange);
    if (f.severity === "critical") crit.push(dec); else if (f.severity === "warning") warn.push(dec); else info.push(dec);
  }
  editor.setDecorations(s.criticalType, crit);
  editor.setDecorations(s.warningType,  warn);
  editor.setDecorations(s.infoType,     info);
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
          editor.setDecorations(decorState.warningType,  []);
          editor.setDecorations(decorState.infoType,     []);
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
const HIGH_CONF_RULES = new Set(["eval-external","hardcoded-secret","shell-injection","pickle-loads","deserialization","jndi-injection","buffer-overflow-gets","file-inclusion"]);
const SHIELD_SVG = '<img src="data:image/png;base64,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" width="36" height="24" style="display:inline-block;vertical-align:middle;" />'

function escHtml(t) { return String(t).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"); }
function sevLabel(s) { return s === "critical" ? "CRIT" : s === "warning" ? "WARN" : "INFO"; }
function confLabel(f) {
  if (f.severity === "critical" && HIGH_CONF_RULES.has(f.ruleId)) return { label: "high confidence", cls: "conf-high" };
  if (f.severity === "warning") return { label: "review", cls: "conf-review" };
  return { label: "medium confidence", cls: "conf-med" };
}
function renderCveBadges(cves) {
  if (!cves || !cves.length) return "";
  return '<div class="cve-row"><span class="cve-label">References</span>' +
    cves.map((c) => '<button class="cve-badge" onclick="openCve(\'' + escHtml(c.url) + '\')" title="' + escHtml(c.description) + '">' + escHtml(c.id) + '</button>').join("") +
    '</div>';
}

class ShieldPromptPanel {
  constructor() { this.panel = undefined; this.disposables = []; this._findings = []; this._documentUri = undefined; }

  show(findings, fp, totalRules, documentUri) {
    this._findings = findings;
    if (documentUri) this._documentUri = documentUri;
    if (this.panel) { this.panel.webview.html = this.buildHtml(findings, fp, totalRules); this.panel.reveal(vscode.ViewColumn.Beside, true); return; }
    this.panel = vscode.window.createWebviewPanel("shieldpromptPanel", "ShieldPrompt", { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true }, { enableScripts: true, retainContextWhenHidden: true });
    this.panel.webview.html = this.buildHtml(findings, fp, totalRules);
    this.panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === "openCve") {
        await vscode.env.openExternal(vscode.Uri.parse(msg.url));
      } else if (msg.type === "scanProject") {
        scanPanelInstance.open();
      } else if (msg.type === "rescanActive") {
        (async () => {
          // activeTextEditor is null when the ShieldPrompt webview has focus —
          // resolve the right editor from visibleTextEditors instead.
          let editor = vscode.window.activeTextEditor;
          if (!editor) {
            // Prefer the document we last scanned
            if (this._documentUri) {
              editor = vscode.window.visibleTextEditors.find(
                e => e.document.uri.toString() === this._documentUri.toString()
              );
            }
            // Fall back to any visible file editor (exclude output/git/webview schemes)
            if (!editor) {
              editor = vscode.window.visibleTextEditors.find(
                e => e.document.uri.scheme === "file" || e.document.uri.scheme === "untitled"
              );
            }
          }
          if (!editor) {
            vscode.window.showWarningMessage("ShieldPrompt: No file editor is open. Open a file first, then Re-scan.");
            if (this.panel) this.panel.webview.postMessage({ type: "rescanDone" });
            return;
          }
          const languageId   = editor.document.languageId;
          const config       = vscode.workspace.getConfiguration("shieldprompt");
          const suppressed   = config.get("suppressedRules", []);

          // Strip all shieldprompt-ignore comments from the document before re-scanning
          // so previously ignored lines are re-evaluated fresh. This also restores the
          // file to its original state (no leftover suppression comments).
          const rawText = editor.document.getText();
          const hasIgnoreComments = rawText.includes("shieldprompt-ignore");
          if (hasIgnoreComments) {
            await editor.edit((eb) => {
              const lines = editor.document.getText().split("\n");
              for (let i = 0; i < lines.length; i++) {
                if (lines[i].includes("shieldprompt-ignore")) {
                  const docLine = editor.document.lineAt(i);
                  // Remove just the suppress comment, leaving the original code intact
                  const cleaned = docLine.text.replace(/\s*\/\/\s*shieldprompt-ignore:[^\n]*/g, "").trimEnd();
                  eb.replace(docLine.range, cleaned);
                }
              }
            });
          }

          const text         = editor.document.getText();
          const langFindings = runRules(text, languageId, 0, suppressed, loadedRulesMap);
          const fwFindings   = [];
          if (frameworkManifest) {
            const detected = detectFrameworks(text, cachedDeps, frameworkManifest);
            for (const fwName of detected) {
              const fw = loadedFrameworkMap.get(fwName);
              if (!fw) continue;
              const langOk = !fw.language || languageId.startsWith(fw.language) ||
                (fw.language === "javascript" && ["typescript","javascriptreact","typescriptreact"].includes(languageId)) ||
                (fw.language === "typescript" && ["javascript","javascriptreact","typescriptreact"].includes(languageId));
              if (!langOk) continue;
              const tempMap = new Map([[languageId, fw.rules]]);
              const found = runRules(text, languageId, 0, suppressed, tempMap);
              for (const f of found) { f.framework = fwName; fwFindings.push(f); }
            }
          }
          const seen   = new Set(langFindings.map(f => f.line + ":" + f.ruleId));
          const merged = [...langFindings];
          for (const f of fwFindings) { if (!seen.has(f.line + ":" + f.ruleId)) { merged.push(f); seen.add(f.line + ":" + f.ruleId); } }
          // Inline rules pass
          const inlineFR = runInlineRules(text, languageId, 0, suppressed);
          for (const f of inlineFR) {
            const key = f.line + ":" + f.ruleId + ":" + f.col;
            if (!seen.has(f.line + ":" + f.ruleId)) { seen.add(f.line + ":" + f.ruleId); merged.push(f); }
          }
          const sw = { critical: 0, warning: 1, info: 2 };
          merged.sort((a, b) => a.line !== b.line ? a.line - b.line : (sw[a.severity] ?? 3) - (sw[b.severity] ?? 3));
          const fp = fingerprint(text);
          currentFindings    = merged;
          currentFingerprint = fp;
          updateStatusBar(merged);
          applyDecorations(editor, merged);
          this._findings     = merged;
          this._documentUri  = editor.document.uri;
          // Use postMessage to update the panel in-place rather than replacing .html
          // (replacing .html destroys the webview context and causes a blank panel).
          this.panel.webview.postMessage({
            type: "updateFindings",
            html: this._buildFindingsHtml(merged, fp, totalRulesCount)
          });
          this.panel.webview.postMessage({ type: "rescanDone" });
        })();
      } else if (msg.type === "aiFix") {
        (async () => {
          try {
            const config  = vscode.workspace.getConfiguration("shieldprompt");
            const apiKey  = config.get("aiFixApiKey", "").trim();
            const aiModel = config.get("aiFixModel", "claude-haiku-4-5-20251001").trim();
            const findings = this._findings;
            if (!findings || findings.length === 0) {
              if (this.panel) this.panel.webview.postMessage({ type: "aiFix", text: "No findings to fix.", err: false });
              return;
            }
            // Build a readable summary of all findings
            const findingsSummary = findings.map((f, i) =>
              `[${i+1}] Line ${f.line+1} — ${f.severity.toUpperCase()} — ${f.ruleId}\n    ${f.message}\n    ${f.detail}`
            ).join("\n\n");
            // Try to get the source code for context
            let sourceContext = "";
            const editor = vscode.window.activeTextEditor;
            if (editor) {
              const lines = editor.document.getText().split("\n");
              const flaggedLines = new Set(findings.map(f => f.line));
              const ctxLines = [];
              for (const lineNum of flaggedLines) {
                const start = Math.max(0, lineNum - 2);
                const end   = Math.min(lines.length - 1, lineNum + 2);
                for (let i = start; i <= end; i++) {
                  ctxLines.push(`${i+1}: ${lines[i]}`);
                }
              }
              sourceContext = ctxLines.join("\n");
            }
            const prompt = `You are a security expert. The following security vulnerabilities were detected in code:\n\n${findingsSummary}\n\n${sourceContext ? "Relevant code context:\n```\n" + sourceContext + "\n```\n\n" : ""}For each finding, propose a concise fix in ask/proposal mode — explain what to change and why, but do not rewrite the entire file. Be specific about the line numbers. Format each fix clearly.`;
            if (!apiKey) {
              // No API key — fall back to opening in the default AI chat via clipboard
              await vscode.env.clipboard.writeText(prompt);
              vscode.window.showInformationMessage("ShieldPrompt: Fix prompt copied to clipboard. Paste it into your AI assistant.", "Open Settings").then(sel => {
                if (sel === "Open Settings") vscode.commands.executeCommand("workbench.action.openSettings", "shieldprompt.aiFixApiKey");
              });
              if (this.panel) this.panel.webview.postMessage({ type: "aiFix", text: "No AI API key configured.\n\nThe fix prompt has been copied to your clipboard — paste it into your AI assistant (ChatGPT, Claude, Copilot Chat, etc.).\n\nTo enable automatic AI fixes, add your API key in Settings → ShieldPrompt → AI Fix API Key.", err: true });
              return;
            }
            // Call Anthropic API with user-provided key
            const https = require("https");
            const body  = JSON.stringify({
              model: aiModel,
              max_tokens: 2048,
              messages: [{ role: "user", content: prompt }]
            });
            const result = await new Promise((resolve, reject) => {
              const req = https.request({
                hostname: "api.anthropic.com",
                path: "/v1/messages",
                method: "POST",
                headers: {
                  "Content-Type": "application/json",
                  "x-api-key": apiKey,
                  "anthropic-version": "2023-06-01",
                  "Content-Length": Buffer.byteLength(body)
                }
              }, (res) => {
                let data = "";
                res.on("data", chunk => data += chunk);
                res.on("end", () => {
                  try { resolve(JSON.parse(data)); } catch(e) { reject(new Error("Invalid JSON response")); }
                });
              });
              req.on("error", reject);
              req.write(body);
              req.end();
            });
            if (result.error) throw new Error(result.error.message || "API error");
            const text = result.content && result.content[0] && result.content[0].text
              ? result.content[0].text
              : "No response from AI.";
            if (this.panel) this.panel.webview.postMessage({ type: "aiFix", text, err: false });
          } catch (err) {
            const errMsg = err && err.message ? err.message : String(err);
            if (this.panel) this.panel.webview.postMessage({ type: "aiFix", text: "Error: " + errMsg, err: true });
          }
        })();
      } else if (msg.type === "openSettings") {
        vscode.commands.executeCommand("workbench.action.openSettings", "shieldprompt.aiFixApiKey");
      } else if (msg.type === "ignoreThis") {
        const f = this._findings[msg.findingIndex];
        if (!f) return;

        // Try stored document URI first, then fall back to active editor
        let targetEditor = vscode.window.activeTextEditor;
        if (!targetEditor || (this._documentUri && targetEditor.document.uri.toString() !== this._documentUri.toString())) {
          // Find the right editor from all visible editors
          const editors = vscode.window.visibleTextEditors;
          if (this._documentUri) {
            targetEditor = editors.find((e) => e.document.uri.toString() === this._documentUri.toString());
          }
          // If still not found, try to open the document
          if (!targetEditor && this._documentUri) {
            const doc = await vscode.workspace.openTextDocument(this._documentUri);
            targetEditor = await vscode.window.showTextDocument(doc, vscode.ViewColumn.One, false);
          }
        }

        if (!targetEditor) {
          vscode.window.showWarningMessage("ShieldPrompt: Could not find the source file. Make sure it's open in the editor.");
          return;
        }

        if (f.line >= targetEditor.document.lineCount) {
          vscode.window.showWarningMessage("ShieldPrompt: Line " + (f.line + 1) + " no longer exists in the file.");
          return;
        }

        const line = targetEditor.document.lineAt(f.line);
        const alreadyIgnored = line.text.includes("shieldprompt-ignore");
        if (alreadyIgnored) {
          vscode.window.showInformationMessage("ShieldPrompt: This line is already suppressed.");
          return;
        }

        const success = await targetEditor.edit((eb) => {
          eb.replace(line.range, line.text + " // shieldprompt-ignore: " + f.ruleId);
        });

        if (success) {
          // Remove this finding from the live list and immediately refresh the panel
          // so the red/yellow marker disappears without needing a re-paste or re-scan.
          // The suppression comment stays in the file, so a future paste or Re-scan
          // will correctly skip this rule on this line.
          this._findings = this._findings.filter((_, idx) => idx !== msg.findingIndex);
          currentFindings = this._findings;
          updateStatusBar(this._findings);
          // Reapply decorations with the filtered findings list — this replaces
          // all previous decorations, clearing the ignored line's marker.
          applyDecorations(targetEditor, this._findings);
          // Send updated findings to the existing webview to re-render in-place.
          // We must NOT replace .html — that destroys the webview context and
          // causes a blank panel (acquireVsCodeApi can only be called once).
          if (this.panel) {
            this.panel.webview.postMessage({
              type: "updateFindings",
              html: this._buildFindingsHtml(this._findings, currentFingerprint, totalRulesCount)
            });
          }
          vscode.window.showInformationMessage("ShieldPrompt: \u2713 Ignored — marker cleared. Will re-flag on next paste or Re-scan File.");
        } else {
          vscode.window.showWarningMessage("ShieldPrompt: Could not edit the file. Make sure it is not read-only.");
        }
      }
    }, null, this.disposables);
    this.panel.onDidDispose(() => { this.panel = undefined; this.disposables.forEach((d) => d.dispose()); this.disposables = []; }, null, this.disposables);
  }
  reveal()  { if (this.panel) this.panel.reveal(vscode.ViewColumn.Beside, true); }
  dispose() { if (this.panel) this.panel.dispose(); }

  _buildFindingsHtml(findings, fp, totalRules) {
    // Returns just the inner content fragment for postMessage updates.
    const critN = findings.filter((f) => f.severity === "critical").length;
    const warnN = findings.filter((f) => f.severity === "warning").length;
    const infoN = findings.filter((f) => f.severity === "info").length;
    const total = findings.length;
    const parts = [];
    if (critN) parts.push(critN + " critical");
    if (warnN) parts.push(warnN + " warning" + (warnN > 1 ? "s" : ""));
    if (infoN) parts.push(infoN + " info");
    const summaryText = total === 0 ? "No issues found" : total + " issue" + (total > 1 ? "s" : "") + " — " + parts.join(", ");
    const fpBadge = (fp.confidence === "high" || fp.confidence === "medium")
      ? '<div class="ai-badge ' + fp.confidence + '"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>AI-generated code detected (' + fp.confidence + ' confidence)</div>'
      : "";
    const list = findings.map((f, i) => {
      const conf = confLabel(f);
      const fwBadge = f.framework ? '<span class="fw-badge">' + escHtml(f.framework) + '</span>' : "";
      return '<div class="finding ' + f.severity + '">' +
        '<div class="finding-header" onclick="toggle(' + i + ')">' +
          '<span class="sev-pill ' + f.severity + '">' + sevLabel(f.severity) + '</span>' +
          '<span class="conf ' + conf.cls + '">' + conf.label + '</span>' +
          fwBadge +
          '<span class="fl">L' + (f.line + 1) + '</span>' +
          '<span class="fr">' + escHtml(f.ruleId) + '</span>' +
          '<span class="fm">' + escHtml(f.message) + '</span>' +
          '<span class="chevron" id="ch-' + i + '">&#9654;</span>' +
        '</div>' +
        '<div class="finding-detail" id="det-' + i + '" style="display:none">' +
          '<p>' + escHtml(f.detail) + '</p>' +
          renderCveBadges(f.cves) +
          '<button class="ignore-btn" onclick="ignoreThis(' + i + ')">Ignore on this line</button>' +
        '</div>' +
      '</div>';
    }).join("\n");
    const empty = '<div class="empty"><div class="empty-shield">' + SHIELD_SVG + '</div><p class="empty-title">Code looks clean</p><p class="empty-sub">Checked ' + totalRules + ' security patterns — no issues found.</p></div>';
    const fixBtn = total > 0
      ? '<button class="fix-btn" onclick="requestAiFix()" title="Ask your AI assistant to propose fixes"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>AI Fix Suggestions</button>'
      : '';
    return JSON.stringify({
      summary: summaryText,
      fpBadge,
      findings: total === 0 ? empty : list,
      fixBtn,
    });
  }

  buildHtml(findings, fp, totalRules) {
    const critN = findings.filter((f) => f.severity === "critical").length;
    const warnN = findings.filter((f) => f.severity === "warning").length;
    const infoN = findings.filter((f) => f.severity === "info").length;
    const total = findings.length;
    const parts = [];
    if (critN) parts.push(critN + " critical");
    if (warnN) parts.push(warnN + " warning" + (warnN > 1 ? "s" : ""));
    if (infoN) parts.push(infoN + " info");
    const summaryText = total === 0 ? "No issues found" : total + " issue" + (total > 1 ? "s" : "") + " \u2014 " + parts.join(", ");
    const fpBadge = (fp.confidence === "high" || fp.confidence === "medium")
      ? '<div class="ai-badge ' + fp.confidence + '"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>AI-generated code detected (' + fp.confidence + ' confidence)</div>'
      : "";
    const list = findings.map((f, i) => {
      const conf = confLabel(f);
      const fwBadge = f.framework
        ? '<span class="fw-badge">' + escHtml(f.framework) + '</span>'
        : "";
      return '<div class="finding ' + f.severity + '">' +
        '<div class="finding-header" onclick="toggle(' + i + ')">' +
          '<span class="sev-pill ' + f.severity + '">' + sevLabel(f.severity) + '</span>' +
          '<span class="conf ' + conf.cls + '">' + conf.label + '</span>' +
          fwBadge +
          '<span class="fl">L' + (f.line + 1) + '</span>' +
          '<span class="fr">' + escHtml(f.ruleId) + '</span>' +
          '<span class="fm">' + escHtml(f.message) + '</span>' +
          '<span class="chevron" id="ch-' + i + '">&#9654;</span>' +
        '</div>' +
        '<div class="finding-detail" id="det-' + i + '" style="display:none">' +
          '<p>' + escHtml(f.detail) + '</p>' +
          renderCveBadges(f.cves) +
          '<button class="ignore-btn" onclick="ignoreThis(' + i + ')">Ignore on this line</button>' +
        '</div>' +
      '</div>';
    }).join("\n");
    const empty = '<div class="empty"><div class="empty-shield">' + SHIELD_SVG + '</div><p class="empty-title">Code looks clean</p><p class="empty-sub">Checked ' + totalRules + ' security patterns \u2014 no issues found.</p></div>';
    const CSS = ':root{--bg:var(--vscode-editor-background,#1e1e1e);--bg2:var(--vscode-sideBar-background,#252526);--fg:var(--vscode-editor-foreground,#ccc);--fg2:var(--vscode-descriptionForeground,#858585);--border:var(--vscode-panel-border,#333);--crit-fg:#ff6b6b;--crit-bg:rgba(255,107,107,.1);--warn-fg:#ffa500;--warn-bg:rgba(255,165,0,.1);--info-fg:#4fc3f7;--info-bg:rgba(79,195,247,.08);--blue:#3b82f6;--r:6px;--font:var(--vscode-font-family,-apple-system,BlinkMacSystemFont,sans-serif);--mono:var(--vscode-editor-font-family,"Cascadia Code","Fira Code",monospace)}*{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--font);font-size:var(--vscode-font-size,13px);color:var(--fg);background:var(--bg);padding:14px 16px 28px;line-height:1.5}.header{display:flex;align-items:center;gap:8px;margin-bottom:14px}.header-title{font-size:15px;font-weight:600;letter-spacing:-.01em;flex:1}.scan-project-btn{padding:4px 10px;background:transparent;color:var(--fg2);border:1px solid var(--border);border-radius:4px;cursor:pointer;font-size:11px;white-space:nowrap;transition:border-color .12s,color .12s}.scan-project-btn:hover{border-color:var(--blue);color:var(--blue)}.ai-badge{display:inline-flex;align-items:center;gap:6px;padding:5px 11px;border-radius:20px;font-size:12px;font-weight:600;margin-bottom:14px;border:1px solid}.ai-badge.high{background:var(--crit-bg);border-color:var(--crit-fg);color:var(--crit-fg)}.ai-badge.medium{background:var(--warn-bg);border-color:var(--warn-fg);color:var(--warn-fg)}.summary{background:var(--bg2);border-left:3px solid var(--blue);border-radius:0 var(--r) var(--r) 0;padding:9px 13px;margin-bottom:14px;font-size:13px}.finding{border:.5px solid var(--border);border-radius:var(--r);margin-bottom:7px;overflow:hidden}.finding.critical{border-left:3px solid var(--crit-fg)}.finding.warning{border-left:3px solid var(--warn-fg)}.finding.info{border-left:3px solid var(--info-fg)}.finding-header{display:flex;align-items:center;gap:7px;padding:8px 11px;cursor:pointer;user-select:none}.finding-header:hover{background:rgba(255,255,255,.03)}.sev-pill{padding:2px 7px;border-radius:20px;font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.04em;flex-shrink:0}.sev-pill.critical{background:var(--crit-bg);color:var(--crit-fg)}.sev-pill.warning{background:var(--warn-bg);color:var(--warn-fg)}.sev-pill.info{background:var(--info-bg);color:var(--info-fg)}.conf{font-size:10px;opacity:.6;flex-shrink:0}.fw-badge{font-size:10px;padding:1px 6px;border-radius:4px;background:rgba(139,92,246,.15);border:1px solid rgba(139,92,246,.4);color:#a78bfa;font-family:var(--mono);flex-shrink:0}.fl{font-size:11px;color:var(--fg2);flex-shrink:0;font-family:var(--mono)}.fr{font-size:12px;font-family:var(--mono);opacity:.65;flex-shrink:0}.fm{flex:1;font-size:13px}.chevron{font-size:10px;opacity:.4;flex-shrink:0;transition:transform .15s}.chevron.open{transform:rotate(90deg)}.finding-detail{padding:10px 14px 13px;background:var(--bg2);border-top:.5px solid var(--border)}.finding-detail p{margin-bottom:9px;color:var(--fg2);font-size:12px;line-height:1.6}.cve-row{display:flex;align-items:center;gap:6px;flex-wrap:wrap;margin-bottom:10px}.cve-label{font-size:11px;color:var(--fg2);flex-shrink:0;margin-right:2px}.cve-badge{display:inline-flex;align-items:center;padding:2px 8px;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.4);border-radius:4px;color:#60a5fa;font-size:11px;font-family:var(--mono);font-weight:600;cursor:pointer;transition:background .12s,border-color .12s}.cve-badge:hover{background:rgba(59,130,246,.25);border-color:rgba(59,130,246,.75)}.ignore-btn{padding:4px 11px;background:transparent;color:var(--fg2);border:1px solid var(--border);border-radius:4px;cursor:pointer;font-size:12px;transition:border-color .12s,color .12s}.ignore-btn:hover{border-color:var(--fg);color:var(--fg)}.empty{text-align:center;padding:52px 20px 44px}.empty-shield{display:flex;justify-content:center;margin-bottom:16px}.empty-shield svg{width:48px;height:48px;opacity:.5}.empty-title{font-size:15px;font-weight:600;margin-bottom:6px}.empty-sub{font-size:12px;color:var(--fg2);opacity:.7}.toolbar{display:flex;align-items:center;gap:6px;margin-bottom:12px}.rescan-btn{display:inline-flex;align-items:center;gap:5px;padding:5px 11px;background:rgba(59,130,246,.12);color:#60a5fa;border:1px solid rgba(59,130,246,.4);border-radius:4px;cursor:pointer;font-size:12px;font-weight:500;transition:background .12s,border-color .12s}.rescan-btn:hover{background:rgba(59,130,246,.22);border-color:rgba(59,130,246,.7)}.rescan-btn:disabled{opacity:.4;cursor:default}.fix-btn{display:inline-flex;align-items:center;gap:5px;padding:5px 11px;background:rgba(16,185,129,.1);color:#34d399;border:1px solid rgba(52,211,153,.35);border-radius:4px;cursor:pointer;font-size:12px;font-weight:500;transition:background .12s,border-color .12s}.fix-btn:hover{background:rgba(16,185,129,.2);border-color:rgba(52,211,153,.65)}.fix-btn:disabled{opacity:.4;cursor:default}.ai-fix-panel{margin-top:14px;background:var(--bg2);border:0.5px solid rgba(52,211,153,.3);border-radius:var(--r);overflow:hidden}.ai-fix-header{display:flex;align-items:center;justify-content:space-between;padding:8px 12px;border-bottom:0.5px solid var(--border)}.ai-fix-label{font-size:12px;font-weight:600;color:#34d399}.ai-fix-dismiss{background:transparent;border:none;color:var(--fg2);cursor:pointer;font-size:14px;line-height:1;padding:0 2px}.ai-fix-dismiss:hover{color:var(--fg)}.ai-fix-body{padding:12px;font-size:12px;color:var(--fg2);line-height:1.6;white-space:pre-wrap;font-family:var(--mono)}.ai-fix-loading{padding:14px 12px;font-size:12px;color:var(--fg2);display:flex;align-items:center;gap:8px}.spinner{width:14px;height:14px;border:2px solid var(--border);border-top-color:#34d399;border-radius:50%;animation:spin .7s linear infinite;flex-shrink:0}@keyframes spin{to{transform:rotate(360deg)}}.ai-fix-err{padding:12px;font-size:12px;color:var(--crit-fg)}.no-key-hint{margin-top:6px;font-size:11px;color:var(--fg2);opacity:.7}.no-key-hint a{color:#60a5fa;text-decoration:none}.no-key-hint a:hover{text-decoration:underline}';
    return '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><style>' + CSS + '</style></head><body>' +
      '<div class="header">' + SHIELD_SVG + '<span class="header-title">ShieldPrompt</span>' +
      '<button class="scan-project-btn" onclick="scanProject()" title="Scan entire project"><svg width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" style="display:inline-block;vertical-align:middle;margin-right:5px;margin-top:-1px"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Scan Project</button></div>' +
      '<div class="toolbar">' +
        '<button class="rescan-btn" onclick="rescanActive()" title="Re-scan the active editor file now">' +
          '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/></svg>' +
          'Re-scan File</button>' +
        (total > 0 ? '<button class="fix-btn" onclick="requestAiFix()" title="Ask your AI assistant to propose fixes for all findings">' +
          '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>' +
          'AI Fix Suggestions</button>' : '') +
      '</div>' +
      fpBadge +
      '<div class="summary">' + summaryText + '</div>' +
      '<div id="findings-container">' + (total === 0 ? empty : list) + '</div>' +
      '<div id="ai-fix-panel" style="display:none"></div>' +
      '<script>' +
        'var vscode=acquireVsCodeApi();' +
        'function toggle(i){var d=document.getElementById("det-"+i),c=document.getElementById("ch-"+i);if(!d||!c)return;var o=d.style.display!=="none";d.style.display=o?"none":"block";c.classList.toggle("open",!o);}' +
        'function ignoreThis(i){vscode.postMessage({type:"ignoreThis",findingIndex:i});}' +
        'function openCve(u){vscode.postMessage({type:"openCve",url:u});}' +
        'function scanProject(){vscode.postMessage({type:"scanProject"});}' +
        'function rescanActive(){' +
          'var btn=document.querySelector(".rescan-btn");' +
          'if(btn){btn.disabled=true;btn.textContent="Scanning\u2026";}' +
          'vscode.postMessage({type:"rescanActive"});' +
        '}' +
        'function requestAiFix(){' +
          'var p=document.getElementById("ai-fix-panel");' +
          'p.style.display="block";' +
          'p.innerHTML="<div class=\\"ai-fix-panel\\"><div class=\\"ai-fix-loading\\"><div class=\\"spinner\\"></div>Sending findings to your AI\u2026</div></div>";' +
          'vscode.postMessage({type:"aiFix"});' +
        '}' +
        'function showAiFix(txt,isErr){' +
          'var p=document.getElementById("ai-fix-panel");' +
          'var hdr="<div class=\\"ai-fix-panel\\"><div class=\\"ai-fix-header\\"><span class=\\"ai-fix-label\\">AI Fix Suggestions</span><button class=\\"ai-fix-dismiss\\" onclick=\\"dismissFix()\\">&#x2715;</button></div>";' +
          'if(isErr){' +
            'p.innerHTML=hdr+"<div class=\\"ai-fix-err\\">"+escHtml(txt)+"<div class=\\"no-key-hint\\">Add your API key in <a href=\\"#\\" onclick=\\"openSettings()\\">ShieldPrompt settings</a>.</div></div></div>";' +
          '}else{' +
            'p.innerHTML=hdr+"<div class=\\"ai-fix-body\\">"+escHtml(txt)+"</div></div>";' +
          '}' +
        '}' +
        'function dismissFix(){document.getElementById("ai-fix-panel").style.display="none";}' +
        'function openSettings(){vscode.postMessage({type:"openSettings"});}' +
        'function escHtml(s){return s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/\\n/g,"<br>");}' +
        'window.addEventListener("message",function(e){' +
          'var m=e.data;' +
          'if(m.type==="rescanDone"){' +
            'var btn=document.querySelector(".rescan-btn");' +
            'if(btn){btn.disabled=false;btn.innerHTML=' +
              '"<svg width=\\"12\\" height=\\"12\\" viewBox=\\"0 0 24 24\\" fill=\\"none\\" stroke=\\"currentColor\\" stroke-width=\\"2.2\\" stroke-linecap=\\"round\\" stroke-linejoin=\\"round\\"><polyline points=\\"23 4 23 10 17 10\\"/><polyline points=\\"1 20 1 14 7 14\\"/><path d=\\"M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15\\"/></svg> Re-scan File";}' +
          '}else if(m.type==="aiFix"){showAiFix(m.text,m.err||false);}' +
          'else if(m.type==="updateFindings"){' +
            'try{' +
              'var d=JSON.parse(m.html);' +
              'var s=document.querySelector(".summary");if(s)s.textContent=d.summary;' +
              'var fb=document.querySelector(".ai-badge");' +
              'if(fb)fb.outerHTML=d.fpBadge||"",' +
              'document.querySelector(".ai-badge");' +
              'var fc=document.getElementById("findings-container");if(fc)fc.innerHTML=d.findings;' +
              'var tb=document.querySelector(".toolbar");' +
              'if(tb){var eb=tb.querySelector(".fix-btn");if(eb)eb.remove();if(d.fixBtn){var tmp=document.createElement("div");tmp.innerHTML=d.fixBtn;tb.appendChild(tmp.firstChild);}}' +
            '}catch(e){}' +
          '}' +
        '});' +
      '</script>' +
      '</body></html>';
  }
}

// ─── SCAN PANEL ──────────────────────────────────────────────────────────────
class ScanPanel {
  constructor() { this.panel = undefined; this.disposables = []; this._cancelToken = null; }

  open() {
    if (this.panel) { this.panel.reveal(vscode.ViewColumn.One, false); return; }
    this.panel = vscode.window.createWebviewPanel(
      "shieldpromptScan", "ShieldPrompt: Project Scan",
      { viewColumn: vscode.ViewColumn.One, preserveFocus: false },
      { enableScripts: true, retainContextWhenHidden: true }
    );
    this.panel.webview.html = this._buildIdleHtml();
    this.panel.webview.onDidReceiveMessage(async (msg) => {
      if (msg.type === "startScan") { await this._runScan(); }
      if (msg.type === "cancelScan") { if (this._cancelToken) this._cancelToken.cancelled = true; }
      if (msg.type === "openFile") {
        try {
          const uri  = vscode.Uri.file(msg.filePath);
          const doc  = await vscode.workspace.openTextDocument(uri);
          const ed   = await vscode.window.showTextDocument(doc, vscode.ViewColumn.Two, false);
          const line = Math.max(0, (msg.line || 1) - 1);
          const pos  = new vscode.Position(line, 0);
          ed.selection = new vscode.Selection(pos, pos);
          ed.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
        } catch {}
      }
      if (msg.type === "openCve") {
        await vscode.env.openExternal(vscode.Uri.parse(msg.url));
      }
    }, null, this.disposables);
    this.panel.onDidDispose(() => {
      if (this._cancelToken) this._cancelToken.cancelled = true;
      this.panel = undefined;
      this.disposables.forEach((d) => d.dispose());
      this.disposables = [];
    }, null, this.disposables);
  }

  async _runScan() {
    if (!vscode.workspace.workspaceFolders) {
      vscode.window.showWarningMessage("ShieldPrompt: No workspace folder open to scan.");
      return;
    }
    const rootPath = vscode.workspace.workspaceFolders[0].uri.fsPath;
    const config   = vscode.workspace.getConfiguration("shieldprompt");
    const suppressedRules = config.get("suppressedRules", []);

    this._cancelToken = { cancelled: false };
    const cancelToken = this._cancelToken;

    // Show scanning state immediately
    this._postMessage({ type: "scanStarted" });

    const startTime = Date.now();

    try {
      const result = await runProjectScan(
        rootPath,
        runRules,
        detectFrameworks,
        loadedRulesMap,
        loadedFrameworkMap,
        frameworkManifest,
        cachedDeps,
        suppressedRules,
        (scanned, total, currentFile) => {
          // Relative path for display
          const rel = currentFile.replace(rootPath, "").replace(/^[/\\]/, "");
          this._postMessage({ type: "progress", scanned, total, currentFile: rel });
        },
        cancelToken
      );

      const elapsed = ((Date.now() - startTime) / 1000).toFixed(1);
      this._postMessage({ type: "scanComplete", result: this._serializeResult(result, rootPath), elapsed });
    } catch (err) {
      this._postMessage({ type: "scanError", message: String(err) });
    }
  }

  _serializeResult(result, rootPath) {
    return {
      scanned:       result.scanned,
      totalFound:    result.totalFound,
      limited:       result.limited,
      usedGit:       result.usedGit,
      cancelled:     result.cancelled,
      totalFindings: result.totalFindings,
      fileResults:   result.fileResults.map((fr) => ({
        filePath:    fr.filePath,
        relPath:     fr.filePath.replace(rootPath, "").replace(/^[/\\]/, ""),
        findings:    fr.findings,
      })),
      scannedFiles: result.scannedFiles.map((f) => f.replace(rootPath, "").replace(/^[/\\]/, "")),
    };
  }

  _postMessage(msg) {
    if (this.panel) { try { this.panel.webview.postMessage(msg); } catch {} }
  }

  dispose() {
    if (this._cancelToken) this._cancelToken.cancelled = true;
    if (this.panel) this.panel.dispose();
  }

  _buildIdleHtml() {
    const CSS = this._css();
    return `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><style>${CSS}</style></head><body>
<div class="header">${SHIELD_SVG}<span class="header-title">ShieldPrompt — Project Scan</span></div>
<div class="idle-wrap">
  <div class="idle-icon">${SHIELD_SVG}</div>
  <p class="idle-title">Scan your entire project</p>
  <p class="idle-sub">Runs all ${328} security rules against every file in your workspace.<br>Respects .gitignore &mdash; up to ${FILE_LIMIT} files per scan.</p>
  <button class="scan-btn" onclick="startScan()">&#9654;&nbsp; Start Project Scan</button>
</div>
<script>
var vscode = acquireVsCodeApi();
function startScan() { vscode.postMessage({ type: 'startScan' }); }
function cancelScan() { vscode.postMessage({ type: 'cancelScan' }); }
function openFile(p, l) { vscode.postMessage({ type: 'openFile', filePath: p, line: l }); }
function openCve(u) { vscode.postMessage({ type: 'openCve', url: u }); }
function toggle(id) {
  var d = document.getElementById('det-' + id);
  var c = document.getElementById('ch-' + id);
  if (!d || !c) return;
  var open = d.style.display !== 'none';
  d.style.display = open ? 'none' : 'block';
  c.classList.toggle('open', !open);
}

window.addEventListener('message', function(ev) {
  var msg = ev.data;
  if (msg.type === 'scanStarted') { showScanning(); }
  if (msg.type === 'progress')    { updateProgress(msg.scanned, msg.total, msg.currentFile); }
  if (msg.type === 'scanComplete') { showResults(msg.result, msg.elapsed); }
  if (msg.type === 'scanError')   { showError(msg.message); }
});

function showScanning() {
  document.body.innerHTML = '<div class="header">${SHIELD_SVG}<span class="header-title">ShieldPrompt — Project Scan</span></div>' +
    '<div class="scanning-wrap"><div class="spinner"></div><p class="scanning-title">Scanning project&hellip;</p>' +
    '<p class="scanning-sub" id="prog-sub">Discovering files&hellip;</p>' +
    '<div class="prog-bar-wrap"><div class="prog-bar" id="prog-bar" style="width:0%"></div></div>' +
    '<p class="prog-count" id="prog-count"></p>' +
    '<button class="cancel-btn" onclick="cancelScan()">Cancel</button></div>';
  rebind();
}

function updateProgress(scanned, total, currentFile) {
  var pct = total > 0 ? Math.round((scanned / total) * 100) : 0;
  var bar = document.getElementById('prog-bar');
  var sub = document.getElementById('prog-sub');
  var cnt = document.getElementById('prog-count');
  if (bar) bar.style.width = pct + '%';
  if (sub) sub.textContent = currentFile;
  if (cnt) cnt.textContent = scanned + ' / ' + total + ' files scanned';
}

function showResults(result, elapsed) {
  var critTotal = 0, warnTotal = 0;
  result.fileResults.forEach(function(fr) {
    fr.findings.forEach(function(f) {
      if (f.severity === 'critical') critTotal++;
      else if (f.severity === 'warning') warnTotal++;
    });
  });

  var summaryClass = critTotal > 0 ? 'summary-crit' : warnTotal > 0 ? 'summary-warn' : 'summary-ok';
  var summaryText = result.totalFindings === 0
    ? '&#10003; No issues found across ' + result.scanned + ' files'
    : result.totalFindings + ' issue' + (result.totalFindings !== 1 ? 's' : '') + ' in ' + result.fileResults.length + ' file' + (result.fileResults.length !== 1 ? 's' : '') + ' &mdash; ' + critTotal + ' critical, ' + warnTotal + ' warnings';

  var metaLine = 'Scanned ' + result.scanned + ' files in ' + elapsed + 's';
  if (result.limited) metaLine += ' &mdash; <span class="warn-text">limited to ' + ${FILE_LIMIT} + ' files (found ' + result.totalFound + ' total)</span>';
  if (!result.usedGit) metaLine += ' &mdash; <span class="warn-text">git not detected, .gitignore not applied</span>';
  if (result.cancelled) metaLine += ' &mdash; <span class="warn-text">scan was cancelled</span>';

  var filesHtml = result.fileResults.map(function(fr, fi) {
    var fileCrit = fr.findings.filter(function(f) { return f.severity === 'critical'; }).length;
    var fileWarn = fr.findings.filter(function(f) { return f.severity === 'warning'; }).length;
    var fileLabel = fileCrit > 0 ? (fileCrit + ' crit' + (fileWarn > 0 ? ', ' + fileWarn + ' warn' : '')) : fileWarn + ' warn';
    var findingsHtml = fr.findings.map(function(f, i) {
      var uid = 'f' + fi + '-' + i;
      var icon = f.severity === 'critical' ? '&#128308;' : '&#128993;';
      var fwBadge = f.framework ? '<span class="fw-badge">' + esc(f.framework) + '</span>' : '';
      var cveBadges = (f.cves || []).map(function(c) {
        return '<button class="cve-badge" onclick="openCve(\\'' + esc(c.url) + '\\')" title="' + esc(c.description) + '">' + esc(c.id) + '</button>';
      }).join('');
      var cveRow = cveBadges ? '<div class="cve-row"><span class="cve-label">References</span>' + cveBadges + '</div>' : '';
      return '<div class="finding ' + f.severity + '">' +
        '<div class="finding-header" onclick="toggle(\\'' + uid + '\\')">' +
          icon + ' ' + fwBadge +
          '<span class="fl link" onclick="event.stopPropagation();openFile(\\'' + esc(fr.filePath) + '\\',' + (f.line + 1) + ')">L' + (f.line + 1) + '</span>' +
          '<span class="fr">' + esc(f.ruleId) + '</span>' +
          '<span class="fm">' + esc(f.message) + '</span>' +
          '<span class="chevron" id="ch-' + uid + '">&#9654;</span>' +
        '</div>' +
        '<div class="finding-detail" id="det-' + uid + '" style="display:none">' +
          '<p>' + esc(f.detail) + '</p>' + cveRow +
        '</div></div>';
    }).join('');

    return '<div class="file-block">' +
      '<div class="file-header" onclick="toggleFile(' + fi + ')">' +
        '<span class="file-name">' + esc(fr.relPath) + '</span>' +
        '<span class="file-count ' + (fileCrit > 0 ? 'fc-crit' : 'fc-warn') + '">' + fileLabel + '</span>' +
        '<span class="chevron" id="fch-' + fi + '">&#9654;</span>' +
      '</div>' +
      '<div class="file-findings" id="ff-' + fi + '" style="display:none">' + findingsHtml + '</div>' +
    '</div>';
  }).join('');

  var scannedListHtml = '<div class="scanned-section"><p class="scanned-title" onclick="toggleScanned()">&#9654; Files scanned (' + result.scanned + ')</p>' +
    '<ul class="scanned-list" id="scanned-list" style="display:none">' +
    result.scannedFiles.map(function(f) { return '<li>' + esc(f) + '</li>'; }).join('') +
    '</ul></div>';

  document.body.innerHTML =
    '<div class="header">${SHIELD_SVG}<span class="header-title">ShieldPrompt &mdash; Project Scan</span>' +
    '<button class="rescan-btn" onclick="startScan()">&#9654; Re-scan</button></div>' +
    '<div class="summary-bar ' + summaryClass + '">' + summaryText + '</div>' +
    '<p class="meta">' + metaLine + '</p>' +
    (result.totalFindings === 0
      ? '<div class="empty-scan"><div class="empty-shield">${SHIELD_SVG}</div><p class="empty-title">Project looks clean</p><p class="empty-sub">No security issues detected across ' + result.scanned + ' files.</p></div>'
      : filesHtml) +
    scannedListHtml;
  rebind();
}

function showError(msg) {
  document.body.innerHTML = '<div class="header">${SHIELD_SVG}<span class="header-title">ShieldPrompt &mdash; Project Scan</span></div>' +
    '<div class="error-box">Scan failed: ' + esc(msg) + '</div>' +
    '<button class="scan-btn" onclick="startScan()" style="margin:20px 16px">Try again</button>';
  rebind();
}

function toggleFile(fi) {
  var d = document.getElementById('ff-' + fi);
  var c = document.getElementById('fch-' + fi);
  if (!d || !c) return;
  var open = d.style.display !== 'none';
  d.style.display = open ? 'none' : 'block';
  c.classList.toggle('open', !open);
}

function toggleScanned() {
  var l = document.getElementById('scanned-list');
  if (l) l.style.display = l.style.display === 'none' ? 'block' : 'none';
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;').replace(/'/g,'&#39;');
}

function rebind() {
  // re-attach global functions after innerHTML replace
  window.startScan  = function() { vscode.postMessage({ type: 'startScan' }); showScanning(); };
  window.cancelScan = function() { vscode.postMessage({ type: 'cancelScan' }); };
  window.openFile   = function(p, l) { vscode.postMessage({ type: 'openFile', filePath: p, line: l }); };
  window.openCve    = function(u) { vscode.postMessage({ type: 'openCve', url: u }); };
}
rebind();
</script></body></html>`;
  }

  _css() {
    return ':root{--bg:var(--vscode-editor-background,#1e1e1e);--bg2:var(--vscode-sideBar-background,#252526);--fg:var(--vscode-editor-foreground,#ccc);--fg2:var(--vscode-descriptionForeground,#858585);--border:var(--vscode-panel-border,#333);--crit-fg:#ff6b6b;--crit-bg:rgba(255,107,107,.1);--warn-fg:#ffa500;--warn-bg:rgba(255,165,0,.1);--blue:#3b82f6;--green:#4ade80;--r:6px;--font:var(--vscode-font-family,-apple-system,BlinkMacSystemFont,sans-serif);--mono:var(--vscode-editor-font-family,"Cascadia Code","Fira Code",monospace)}' +
      '*{box-sizing:border-box;margin:0;padding:0}body{font-family:var(--font);font-size:var(--vscode-font-size,13px);color:var(--fg);background:var(--bg);padding:0 0 40px;line-height:1.5}' +
      '.header{display:flex;align-items:center;gap:8px;padding:14px 16px 12px;border-bottom:.5px solid var(--border);margin-bottom:14px;position:sticky;top:0;background:var(--bg);z-index:10}' +
      '.header-title{font-size:15px;font-weight:600;letter-spacing:-.01em;flex:1}' +
      '.rescan-btn{padding:4px 12px;background:var(--blue);color:#fff;border:none;border-radius:4px;cursor:pointer;font-size:12px;opacity:.9}.rescan-btn:hover{opacity:1}' +
      '.idle-wrap{display:flex;flex-direction:column;align-items:center;padding:60px 20px;gap:14px}' +
      '.idle-icon svg{width:52px;height:52px;opacity:.4}' +
      '.idle-title{font-size:16px;font-weight:600}' +
      '.idle-sub{font-size:13px;color:var(--fg2);text-align:center;line-height:1.7;max-width:400px}' +
      '.scan-btn{margin-top:8px;padding:10px 28px;background:var(--blue);color:#fff;border:none;border-radius:6px;cursor:pointer;font-size:14px;font-weight:600;letter-spacing:.01em}.scan-btn:hover{opacity:.9}' +
      '.cancel-btn{margin-top:16px;padding:6px 18px;background:transparent;color:var(--fg2);border:1px solid var(--border);border-radius:4px;cursor:pointer;font-size:12px}.cancel-btn:hover{border-color:var(--fg);color:var(--fg)}' +
      '.scanning-wrap{display:flex;flex-direction:column;align-items:center;padding:60px 20px;gap:12px}' +
      '.spinner{width:36px;height:36px;border:3px solid var(--border);border-top-color:var(--blue);border-radius:50%;animation:spin 0.8s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}' +
      '.scanning-title{font-size:15px;font-weight:600}' +
      '.scanning-sub{font-size:12px;color:var(--fg2);max-width:440px;text-align:center;word-break:break-all}' +
      '.prog-bar-wrap{width:320px;height:6px;background:var(--border);border-radius:3px;overflow:hidden;margin-top:4px}' +
      '.prog-bar{height:100%;background:var(--blue);border-radius:3px;transition:width .2s}' +
      '.prog-count{font-size:11px;color:var(--fg2)}' +
      '.summary-bar{padding:10px 16px;font-size:13px;font-weight:500;border-bottom:.5px solid var(--border);margin-bottom:4px}' +
      '.summary-crit{color:var(--crit-fg);background:var(--crit-bg)}.summary-warn{color:var(--warn-fg);background:var(--warn-bg)}.summary-ok{color:var(--green);background:rgba(74,222,128,.08)}' +
      '.meta{padding:6px 16px 12px;font-size:11px;color:var(--fg2)}.warn-text{color:var(--warn-fg)}' +
      '.file-block{margin:0 12px 8px;border:.5px solid var(--border);border-radius:var(--r);overflow:hidden}' +
      '.file-header{display:flex;align-items:center;gap:8px;padding:9px 12px;cursor:pointer;background:var(--bg2);user-select:none}.file-header:hover{filter:brightness(1.1)}' +
      '.file-name{flex:1;font-family:var(--mono);font-size:12px;word-break:break-all}' +
      '.file-count{font-size:11px;font-weight:600;padding:2px 7px;border-radius:10px;flex-shrink:0}' +
      '.fc-crit{background:var(--crit-bg);color:var(--crit-fg)}.fc-warn{background:var(--warn-bg);color:var(--warn-fg)}' +
      '.file-findings{padding:4px 8px 8px}' +
      '.finding{border:.5px solid var(--border);border-radius:var(--r);margin-bottom:5px;overflow:hidden}' +
      '.finding.critical{border-left:3px solid var(--crit-fg)}.finding.warning{border-left:3px solid var(--warn-fg)}' +
      '.finding-header{display:flex;align-items:center;gap:6px;padding:7px 10px;cursor:pointer;user-select:none;font-size:12px}.finding-header:hover{background:rgba(255,255,255,.03)}' +
      '.fl{font-size:11px;color:var(--blue);flex-shrink:0;font-family:var(--mono)}.fl.link{cursor:pointer;text-decoration:underline;text-underline-offset:2px}.fl.link:hover{opacity:.8}' +
      '.fr{font-size:11px;font-family:var(--mono);opacity:.6;flex-shrink:0}.fm{flex:1;font-size:12px}' +
      '.fw-badge{font-size:10px;padding:1px 5px;border-radius:3px;background:rgba(139,92,246,.15);border:1px solid rgba(139,92,246,.4);color:#a78bfa;font-family:var(--mono);flex-shrink:0}' +
      '.chevron{font-size:9px;opacity:.4;flex-shrink:0;transition:transform .15s;display:inline-block}.chevron.open{transform:rotate(90deg)}' +
      '.finding-detail{padding:8px 12px 10px;background:var(--bg2);border-top:.5px solid var(--border);font-size:12px;color:var(--fg2);line-height:1.6}' +
      '.cve-row{display:flex;align-items:center;gap:5px;flex-wrap:wrap;margin-top:6px}.cve-label{font-size:11px;color:var(--fg2)}' +
      '.cve-badge{padding:2px 7px;background:rgba(59,130,246,.12);border:1px solid rgba(59,130,246,.4);border-radius:3px;color:#60a5fa;font-size:11px;font-family:var(--mono);font-weight:600;cursor:pointer}.cve-badge:hover{background:rgba(59,130,246,.25)}' +
      '.scanned-section{margin:16px 12px 0;border:.5px solid var(--border);border-radius:var(--r);overflow:hidden}' +
      '.scanned-title{padding:8px 12px;font-size:12px;color:var(--fg2);cursor:pointer;background:var(--bg2);user-select:none}.scanned-title:hover{filter:brightness(1.1)}' +
      '.scanned-list{padding:8px 12px;font-size:11px;color:var(--fg2);font-family:var(--mono);line-height:1.8;list-style:none}' +
      '.error-box{margin:20px 16px;padding:12px;background:var(--crit-bg);border:1px solid var(--crit-fg);border-radius:var(--r);color:var(--crit-fg);font-size:12px}' +
      '.empty-scan{display:flex;flex-direction:column;align-items:center;padding:52px 20px;gap:12px}.empty-shield svg{width:48px;height:48px;opacity:.4}.empty-title{font-size:15px;font-weight:600}.empty-sub{font-size:12px;color:var(--fg2)}';
  }
}

// ─── EXTENSION MAIN ──────────────────────────────────────────────────────────
let statusBarItem, panelInstance, scanPanelInstance;
let currentFindings      = [];
let currentFingerprint   = { isAI: false, confidence: "low" };
let loadedRulesMap       = new Map();
let loadedFrameworkMap   = new Map();
let frameworkManifest    = null;
let cachedDeps           = new Set();
let totalRulesCount      = 0;

function activate(context) {
  panelInstance     = new ShieldPromptPanel();
  scanPanelInstance = new ScanPanel();

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = "shieldprompt.openPanel";
  statusBarItem.text    = "$(shield) ShieldPrompt: loading rules\u2026";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Load all rules on startup (async, non-blocking)
  Promise.all([
    loadRules(context.extensionPath, context.globalState),
    loadFrameworkRules(context.extensionPath, context.globalState),
  ]).then(([langMap, fwMap]) => {
    loadedRulesMap     = langMap;
    loadedFrameworkMap = fwMap;
    frameworkManifest  = loadFrameworkManifest(context.extensionPath, context.globalState);

    // Count all rules: language + all framework rules (deduped per framework)
    const langTotal = [...langMap.values()].reduce((s, r) => s + r.length, 0);
    const fwTotal   = [...fwMap.values()].reduce((s, { rules }) => s + rules.length, 0);
    totalRulesCount  = langTotal + fwTotal;
    statusBarItem.text = "$(shield) ShieldPrompt: 0 issues";
  }).catch(() => {
    statusBarItem.text = "$(shield) ShieldPrompt: 0 issues";
  });

  // Pre-read workspace deps once on startup (re-read on each paste in case files changed)
  if (vscode.workspace.workspaceFolders) {
    const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
    readAllDeps(root).then((deps) => { cachedDeps = deps; }).catch(() => {});
  }

  // Commands
  context.subscriptions.push(vscode.commands.registerCommand("shieldprompt.openPanel", () => {
    const uri = vscode.window.activeTextEditor?.document?.uri;
    panelInstance.show(currentFindings, currentFingerprint, totalRulesCount, uri);
  }));
  context.subscriptions.push(vscode.commands.registerCommand("shieldprompt.resetSuppressions", () => {
    vscode.workspace.getConfiguration("shieldprompt").update("suppressedRules", [], vscode.ConfigurationTarget.Workspace);
    vscode.window.showInformationMessage("ShieldPrompt: All suppressions reset.");
  }));
  context.subscriptions.push(vscode.commands.registerCommand("shieldprompt.toggleEnabled", () => {
    const cfg = vscode.workspace.getConfiguration("shieldprompt");
    const cur = cfg.get("enabled", true);
    cfg.update("enabled", !cur, vscode.ConfigurationTarget.Workspace);
    vscode.window.showInformationMessage("ShieldPrompt: " + (cur ? "Disabled" : "Enabled"));
  }));
  context.subscriptions.push(vscode.commands.registerCommand("shieldprompt.checkRuleUpdates", async () => {
    vscode.window.showInformationMessage("ShieldPrompt: Checking for rule updates\u2026");
    await forceRemoteUpdate(context.extensionPath, context.globalState);
    loadedRulesMap     = await loadRules(context.extensionPath, context.globalState);
    loadedFrameworkMap = await loadFrameworkRules(context.extensionPath, context.globalState);
    frameworkManifest  = loadFrameworkManifest(context.extensionPath, context.globalState);
    const langTotal    = [...loadedRulesMap.values()].reduce((s, r) => s + r.length, 0);
    const fwTotal      = [...loadedFrameworkMap.values()].reduce((s, { rules }) => s + rules.length, 0);
    totalRulesCount    = langTotal + fwTotal;
    vscode.window.showInformationMessage("ShieldPrompt: Rules updated (" + totalRulesCount + " rules loaded).");
  }));

  // Paste handler — runs language rules + applicable framework rules
  const pasteDisposable = onPaste((text, document, range) => {
    const config          = vscode.workspace.getConfiguration("shieldprompt");
    const suppressedRules = config.get("suppressedRules", []);
    const languageId      = document.languageId;

    // Refresh deps in background (fast, cached by OS)
    if (vscode.workspace.workspaceFolders) {
      const root = vscode.workspace.workspaceFolders[0].uri.fsPath;
      readAllDeps(root).then((deps) => { cachedDeps = deps; }).catch(() => {});
    }

    // Detect frameworks using imports in pasted text + cached deps
    const detectedFrameworks = frameworkManifest
      ? detectFrameworks(text, cachedDeps, frameworkManifest)
      : new Set();

    // Run language rules
    const langFindings = runRules(text, languageId, range.start.line, suppressedRules, loadedRulesMap);

    // Run framework rules for each detected framework
    const fwFindings = [];
    for (const fwName of detectedFrameworks) {
      const fw = loadedFrameworkMap.get(fwName);
      if (!fw) continue;

      // Build a temporary single-language rules map and reuse runRules engine
      const tempMap = new Map();
      // Framework rules apply if they match the current language OR if languageId starts with fw.language
      const langMatches = !fw.language ||
        languageId.startsWith(fw.language) ||
        (fw.language === "javascript" && ["typescript","javascriptreact","typescriptreact"].includes(languageId)) ||
        (fw.language === "typescript" && ["javascript","javascriptreact","typescriptreact"].includes(languageId));

      if (langMatches) {
        tempMap.set(languageId, fw.rules);
        const found = runRules(text, languageId, range.start.line, suppressedRules, tempMap);
        for (const f of found) {
          f.framework = fwName; // tag with framework name for display
          fwFindings.push(f);
        }
      }
    }

    // Merge and deduplicate by line:ruleId — also suppress language-level rule
    // when a more specific framework rule fires for the same vulnerability class on the same line
    const FRAMEWORK_SUPERSEDES = {
      "express-cors-wildcard":   "cors-wildcard",
      "express-sql-injection":   "sql-injection",
      "express-ssrf":            "ssrf",
      "express-open-redirect":   "open-redirect",
      "express-xss-response":    "xss-innerhtml",
      "fastapi-sql-injection":   "sql-injection",
      "fastapi-ssrf":            "ssrf",
      "fastapi-open-redirect":   "open-redirect",
      "flask-sql-injection":     "sql-injection",
      "flask-ssrf":              "ssrf",
      "flask-open-redirect":     "open-redirect",
      "django-sql-raw":          "sql-injection",
      "nextjs-ssrf-fetch":       "ssrf",
      "nextjs-redirect-open-redirect": "open-redirect",
    };

    const seen    = new Set(langFindings.map((f) => f.line + ":" + f.ruleId));
    // Also track which vulnerability classes are covered per line
    const coveredVulnOnLine = new Map();
    for (const f of langFindings) {
      const key = f.line + ":" + f.ruleId;
      coveredVulnOnLine.set(key, true);
    }

    const merged  = [...langFindings];
    for (const f of fwFindings) {
      const key = f.line + ":" + f.ruleId;
      if (seen.has(key)) continue;
      // Check if a more specific framework rule supersedes a language rule already in merged
      const superseded = FRAMEWORK_SUPERSEDES[f.ruleId];
      if (superseded) {
        // Remove the language-level finding for the same line if present
        const langKey = f.line + ":" + superseded;
        const idx = merged.findIndex((m) => m.line === f.line && m.ruleId === superseded);
        if (idx !== -1) merged.splice(idx, 1);
      }
      merged.push(f);
      seen.add(key);
    }

    // Run inline rules (value-shape secrets, conn strings, SQL multi-line, aliases, insecure defaults)
    const inlineFindings = runInlineRules(text, languageId, range.start.line, suppressedRules);
    for (const f of inlineFindings) {
      const key = f.line + ":" + f.ruleId + ":" + f.col;
      if (!seen.has(key)) { seen.add(key); merged.push(f); }
    }

    const sw = { critical: 0, warning: 1, info: 2 };
    merged.sort((a, b) => a.line !== b.line ? a.line - b.line : (sw[a.severity] ?? 3) - (sw[b.severity] ?? 3));

    const fp = fingerprint(text);
    currentFindings    = merged;
    currentFingerprint = fp;
    updateStatusBar(merged);

    const editor = vscode.window.activeTextEditor;
    if (editor && editor.document === document) applyDecorations(editor, merged);
    panelInstance.show(merged, fp, totalRulesCount, document.uri);
  });

  context.subscriptions.push(vscode.commands.registerCommand("shieldprompt.scanProject", () => {
    scanPanelInstance.open();
  }));

  context.subscriptions.push(pasteDisposable);
  context.subscriptions.push(createEditClearListener());
  context.subscriptions.push({ dispose() { panelInstance.dispose(); scanPanelInstance.dispose(); disposeDecorations(); } });
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