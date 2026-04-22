export interface Finding {
  line: number;
  col: number;
  severity: "critical" | "warning" | "info";
  ruleId: string;
  message: string;
  detail: string;
  cves: CVERef[];
  framework?: string;
  // Vulnerability taxonomy used for cross-layer dedup. Optional because
  // hardcoded rules predate this field; ruleLoader.categoryDedup falls back
  // to a ruleId-regex heuristic when `category` is absent.
  category?: string;
}

export interface AIFingerprint {
  isAI: boolean;
  confidence: "high" | "medium" | "low";
}

export interface CVERef {
  id: string;
  url: string;
  description: string;
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

const JS_TS   = ["javascript", "typescript", "javascriptreact", "typescriptreact"];
const PYTHON  = ["python"];
const ALL_LANGUAGES: string[] = [];

function matchesLanguage(ruleLangs: string[], languageId: string): boolean {
  if (ruleLangs.length === 0) return true;
  return ruleLangs.some((l) => languageId.startsWith(l));
}
function langList(groups: string[][]): string[] { return groups.flat(); }

// ─── entropy ──────────────────────────────────────────────────────────────────
function shannonEntropy(s: string): number {
  const freq: Record<string, number> = {};
  for (const c of s) freq[c] = (freq[c] || 0) + 1;
  return Object.values(freq).reduce((h, n) => {
    const p = n / s.length; return h - p * Math.log2(p);
  }, 0);
}

// ─── comment stripping ────────────────────────────────────────────────────────
export function stripLineComment(line: string): string {
  return line.replace(/(?<!['"\/])\/\/.*$/, "").replace(/^\s*#.*$/, "");
}

// ─── window helper ────────────────────────────────────────────────────────────
function codeWindow(lines: string[], i: number, before: number, after = 1): string {
  return lines
    .slice(Math.max(0, i - before), Math.min(lines.length, i + after + 1))
    .map(stripLineComment).join("\n");
}

// ─── secret helpers ───────────────────────────────────────────────────────────

const SECRET_FALSE_POSITIVES = new Set([
  "success","failure","pass","fail","passed","failed","error","true","false",
  "yes","no","none","null","undefined","empty","test","testing","example",
  "sample","placeholder","changeme","todo","fixme","required","optional",
  "invalid","valid","missing","default","admin","user","guest","public",
  "private","enabled","disabled","pending","active","inactive","unknown",
  "loading","development","production","staging","localhost","notset",
  "insert_here","replace_me","your_secret","my_secret","enter_here",
]);

const SECRET_MOCK_RE = /^(abc123|1234567|12345678|password123|qwerty|asdfgh|aaaaaa+|bbbbbb+|000000+|111111+|test1234|mock.*|dummy.*|fake.*|your_.*|my_.*|<.*>|\$\{.*\}|%.*%)$/i;

// (1) EXPANDED keyword list
const SECRET_KEYWORD_RE = /\b(?:password|passwd|pwd|pass|secret|secret_key|secret_token|token|access_token|auth_token|bearer_token|id_token|refresh_token|api_key|apikey|api_secret|apisecret|auth|auth_key|auth_secret|authorization|credential|credentials|private_key|privatekey|priv_key|privkey|signing_key|signingkey|sign_key|encryption_key|encryptionkey|encrypt_key|symmetric_key|master_key|root_key|secret_phrase|hmac_key|hmac_secret|client_secret|clientsecret|consumer_secret|consumersecret|app_secret|appsecret|application_secret|jwt_secret|jwtsecret|session_secret|sessionsecret|cookie_secret|webhook_secret|webhooksecret|webhook_key|webhookauth|oauth_secret|oauthsecret|oauth_token|access_key|accesskey|access_key_id|secret_access_key|db_password|db_pass|database_password|database_pass|dbpass|dbpassword|db_secret|database_secret|mongo_uri|mongodb_uri|redis_url|database_url|db_url|stripe_secret|stripe_key|stripe_sk|stripekey|stripesecret|twilio_token|twilio_secret|twilio_auth|sendgrid_key|sendgrid_api|sendgrid_secret|mailgun_key|mailgun_api|mailgun_secret|github_token|github_secret|github_key|gh_token|gitlab_token|gitlab_secret|slack_token|slack_secret|slack_signing|slack_bot_token|discord_token|discord_secret|discord_bot_token|firebase_key|firebase_secret|firebase_token|aws_secret|aws_key|aws_access|aws_token|gcp_key|google_key|google_secret|google_api_key|azure_secret|azure_key|azure_token|cloudflare_token|cloudflare_key|cloudflare_secret|npm_token|npm_secret|sentry_dsn|datadog_key|newrelic_key|newrelic_license|openai_key|openai_secret|anthropic_key|cohere_key|algolia_key|algolia_secret|algolia_api|pusher_key|pusher_secret|pusher_app_secret|vault_token|vault_secret|encryption_password|master_password|SECRET_KEY|API_KEY|AUTH_TOKEN|ACCESS_TOKEN|REFRESH_TOKEN|PRIVATE_KEY|SIGNING_KEY|ENCRYPTION_KEY|JWT_SECRET|SESSION_SECRET|DATABASE_URL|MONGO_URI|REDIS_URL|CONNECTION_STRING|WEBHOOK_SECRET|CLIENT_SECRET|CONSUMER_SECRET|APP_SECRET)\b/i;

// (1) VALUE-SHAPE patterns — known real API key formats
const SECRET_VALUE_SHAPES: Array<{ re: RegExp; label: string }> = [
  { re: /AKIA[A-Z0-9]{16}/,                              label: "AWS Access Key ID"          },
  { re: /(sk|pk)_(live|test)_[A-Za-z0-9]{20,}/,         label: "Stripe API key"             },
  { re: /whsec_[A-Za-z0-9]{20,}/,                        label: "Stripe webhook secret"      },
  { re: /rk_live_[A-Za-z0-9]{20,}/,                      label: "Stripe restricted key"      },
  { re: /SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}/,     label: "SendGrid API key"           },
  { re: /xox[baprs]-[0-9A-Za-z]{10,}-[0-9A-Za-z]{10,}/, label: "Slack token"                },
  { re: /ghp_[A-Za-z0-9]{36}/,                           label: "GitHub personal token"      },
  { re: /ghs_[A-Za-z0-9]{36}/,                           label: "GitHub Actions secret"      },
  { re: /gho_[A-Za-z0-9]{36}/,                           label: "GitHub OAuth token"         },
  { re: /github_pat_[A-Za-z0-9_]{59}/,                   label: "GitHub fine-grained PAT"    },
  { re: /AIza[A-Za-z0-9_-]{35}/,                         label: "Google API key"             },
  { re: /ya29\.[A-Za-z0-9_-]{50,}/,                      label: "Google OAuth access token"  },
  { re: /SK[a-fA-F0-9]{32}/,                             label: "Twilio API key"             },
  { re: /AC[a-fA-F0-9]{32}/,                             label: "Twilio Account SID"         },
  { re: /EAA[A-Za-z0-9]{50,}/,                           label: "Facebook access token"      },
  { re: /key-[A-Za-z0-9]{32}/,                           label: "Mailgun API key"            },
  { re: /npm_[A-Za-z0-9]{36}/,                           label: "npm token"                  },
  { re: /glpat-[A-Za-z0-9_-]{20}/,                       label: "GitLab personal token"      },
];

const JWT_RE = /eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/;

function isLikelyRealSecret(value: string): boolean {
  if (value.length < 9) return false;
  if (SECRET_FALSE_POSITIVES.has(value.toLowerCase())) return false;
  if (SECRET_MOCK_RE.test(value)) return false;
  if (/^(.)\1{5,}$/.test(value)) return false;
  if (/^[a-z_]+$/.test(value) && value.length < 16) return false;
  if (shannonEntropy(value) < 2.8) return false;
  return true;
}

// ─── SQL helpers ──────────────────────────────────────────────────────────────
const SQL_KEYWORD_RE = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|TRUNCATE|CREATE|REPLACE)\b/i;
const SQL_SINK_RE    = /\.(?:query|execute|run|exec|all|get|prepare)\s*\(/i;
const SQL_PARAM_RE   = /\?\s*,|\$[0-9]|parameterized|prepared|\bparams\s*:/i;

// ─── dangerous alias sources ──────────────────────────────────────────────────
const DANGEROUS_ALIAS_SOURCES = [
  /\beval\b/,
  /require\s*\(\s*['"`]child_process['"`]\s*\)\s*\.\s*exec\b/,
  /child_process\s*\.\s*exec\b/,
  /\bFunction\b(?!\s*\()/,
  /document\s*\.\s*write\b/,
  /global\s*\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/,
  /window\s*\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/,
];

// ─── insecure defaults ────────────────────────────────────────────────────────
interface InsecureDefault {
  re: RegExp; ruleId: string; message: string; detail: string;
  severity: "critical" | "warning" | "info";
  safeguard?: RegExp; windowBefore?: number; windowAfter?: number;
}

const JS_INSECURE_DEFAULTS: InsecureDefault[] = [
  { ruleId: "insecure-session-secret", severity: "critical",
    re: /session\s*\(\s*\{[^}]*secret\s*:\s*['"`][^'"`]{1,30}['"`]/i,
    message: "Express session with short or hardcoded secret",
    detail: "session() secret should come from an environment variable and be at least 32 random characters.",
    safeguard: /process\.env\.|config\.|getenv/i },
  { ruleId: "jwt-no-expiry", severity: "warning",
    re: /jwt\.sign\s*\([^)]*\)/,
    message: "JWT signed without expiry (expiresIn missing)",
    detail: "Tokens without expiry are valid forever. Always set expiresIn: '15m' or similar.",
    safeguard: /expiresIn|exp\s*:|expires_in/i, windowAfter: 3 },
  { ruleId: "cors-no-config", severity: "warning",
    re: /\bapp\.use\s*\(\s*cors\s*\(\s*\)\s*\)/i,
    message: "cors() with no config — allows all origins",
    detail: "cors() with no arguments permits requests from any origin. Configure origin, methods, and credentials explicitly.",
    safeguard: /origin\s*:/i },
  { ruleId: "jwt-alg-none", severity: "critical",
    re: /algorithms?\s*:\s*\[?\s*['"]none['"]/i,
    message: "JWT algorithm set to 'none' — signature verification bypassed",
    detail: "Accepting 'none' allows attackers to forge tokens. Explicitly specify your signing algorithm and reject 'none'." },
  { ruleId: "debug-enabled", severity: "warning",
    re: /\bdebug\s*:\s*true\b|DEBUG\s*=\s*(?:true|1|['"]true['"])/i,
    message: "Debug mode enabled — must not reach production",
    detail: "Debug mode exposes stack traces and internal state to end users. Disable in production.",
    safeguard: /process\.env\.NODE_ENV\s*===?\s*['"]development['"]/i },
  { ruleId: "deep-merge-unguarded", severity: "warning",
    re: /(?:defaultsDeep|mergeDeep|deepMerge|extend\s*\(\s*true)\s*\(/i,
    message: "Deep merge without prototype pollution guard",
    detail: "Deep merge functions are vulnerable to prototype pollution. Strip __proto__ and constructor keys before merging.",
    safeguard: /hasOwnProperty|Object\.create\s*\(null\)|sanitize|allowedKeys/i },
];

const PYTHON_INSECURE_DEFAULTS: InsecureDefault[] = [
  { ruleId: "flask-debug-enabled", severity: "critical",
    re: /app\.run\s*\([^)]*debug\s*=\s*True/i,
    message: "Flask running with debug=True",
    detail: "Flask debug mode enables an interactive browser debugger — an unauthenticated attacker can execute arbitrary Python. Never deploy with debug=True." },
  { ruleId: "django-hardcoded-secret", severity: "critical",
    re: /SECRET_KEY\s*=\s*['"][^'"]{9,}['"]/,
    message: "Django SECRET_KEY hardcoded in settings",
    detail: "Move SECRET_KEY to an environment variable: SECRET_KEY = os.environ['DJANGO_SECRET_KEY'].",
    safeguard: /os\.environ|os\.getenv|config\./i },
  { ruleId: "django-allowed-hosts-wildcard", severity: "warning",
    re: /ALLOWED_HOSTS\s*=\s*\[\s*['"][*]['"]|ALLOWED_HOSTS\s*=\s*\[''\]/,
    message: "Django ALLOWED_HOSTS set to wildcard",
    detail: "ALLOWED_HOSTS = ['*'] disables host header validation. Restrict to your actual domain(s)." },
  { ruleId: "python-cors-wildcard", severity: "warning",
    re: /CORS_ORIGIN_ALLOW_ALL\s*=\s*True|CORS_ALLOW_ALL_ORIGINS\s*=\s*True/,
    message: "CORS configured to allow all origins",
    detail: "Explicitly list permitted origins in CORS_ALLOWED_ORIGINS." },
];

// ─── rules ────────────────────────────────────────────────────────────────────

const rules: RuleDef[] = [

  // ══ 1. HARDCODED SECRETS — expanded keywords + value shapes ══════════════
  {
    ruleId: "hardcoded-secret", severity: "critical", languages: ALL_LANGUAGES,
    message: "Hardcoded secret or credential detected",
    detail: "Credentials in source code can be extracted by anyone with repo access. Use environment variables or a secrets manager.",
    cves: [
      { id: "CWE-798", url: "https://cwe.mitre.org/data/definitions/798.html", description: "Use of Hard-coded Credentials" },
      { id: "CWE-259", url: "https://cwe.mitre.org/data/definitions/259.html", description: "Use of Hard-coded Password" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const reported = new Set<number>();

      // A. Keyword + quoted value
      const kwRe = new RegExp(SECRET_KEYWORD_RE.source + "\\s*[:=]\\s*[\"'`]([^\"'`]+)[\"'`]", "gi");
      let m: RegExpExecArray | null;
      while ((m = kwRe.exec(line)) !== null) {
        const val = m[m.length - 1];
        if (isLikelyRealSecret(val) && !reported.has(m.index)) {
          reported.add(m.index);
          findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
        }
      }

      // B. Value-shape detection (known API key formats — zero FP risk)
      for (const { re, label } of SECRET_VALUE_SHAPES) {
        const re2 = new RegExp(re.source, "g");
        while ((m = re2.exec(line)) !== null) {
          if (!reported.has(m.index)) {
            reported.add(m.index);
            findings.push({
              line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId,
              message: `${label} detected in source code`,
              detail: `A ${label} was found hardcoded. Revoke and rotate this credential immediately, then store it in an environment variable or secrets manager.`,
              cves: this.cves,
            });
          }
        }
      }

      // C. Hardcoded JWT
      if (JWT_RE.test(line)) {
        const jm = JWT_RE.exec(line);
        if (jm && !reported.has(jm.index)) {
          reported.add(jm.index);
          findings.push({ line: lineIndex, col: jm.index, severity: "critical", ruleId: this.ruleId, message: "Hardcoded JWT token found in source", detail: "JWTs carry auth state. Remove it and use short-lived tokens from your auth provider.", cves: this.cves });
        }
      }

      // D. Bearer token literal
      const bRe = /Bearer\s+[A-Za-z0-9\-._~+/]{20,}/g;
      while ((m = bRe.exec(line)) !== null) {
        if (!reported.has(m.index)) { reported.add(m.index); findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: "Hardcoded Bearer token", detail: "Store tokens in environment variables, never in source.", cves: this.cves }); }
      }

      return findings;
    },
  },

  // ══ 4. SECRETS IN CONNECTION STRINGS / URLS ══════════════════════════════
  {
    ruleId: "secret-in-url", severity: "critical", languages: ALL_LANGUAGES,
    message: "Password or secret embedded in connection string or URL",
    detail: "Credentials in URLs are logged by proxies and load balancers. Extract them to environment variables.",
    cves: [
      { id: "CWE-312", url: "https://cwe.mitre.org/data/definitions/312.html", description: "Cleartext Storage of Sensitive Information" },
      { id: "CWE-798", url: "https://cwe.mitre.org/data/definitions/798.html", description: "Use of Hard-coded Credentials" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      // Protocol://user:PASSWORD@host
      const connRe = /(?:mongodb|postgresql|postgres|mysql|mssql|redis|amqp|amqps|smtp|ftp|sftp|ldap|ldaps):\/\/[^:@\s]*:([^@\s]{4,})@/gi;
      let m: RegExpExecArray | null;
      while ((m = connRe.exec(line)) !== null) {
        const pwd = m[1];
        if (/^\$\{|^%|^<|password|placeholder|changeme/i.test(pwd)) continue;
        if (SECRET_FALSE_POSITIVES.has(pwd.toLowerCase())) continue;
        findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }
      // ?api_key=VALUE in URL strings
      const urlRe = /['"` ][^'"` ]*[?&](?:api_?key|token|secret|password|auth|apikey)=([^&'"` \s]{8,})/gi;
      while ((m = urlRe.exec(line)) !== null) {
        const val = m[1];
        if (/^\$\{|^%|^<|placeholder/i.test(val)) continue;
        if (!isLikelyRealSecret(val)) continue;
        findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: "Secret in URL query parameter", detail: "Secrets in URL params are logged in access logs. Use Authorization headers instead.", cves: this.cves });
      }
      return findings;
    },
  },

  // ══ 2+3. SQL INJECTION — variable-name-agnostic + multi-line window ═══════
  {
    ruleId: "sql-concat", severity: "critical", languages: ALL_LANGUAGES,
    message: "SQL injection: dynamic query built via concatenation or template literal",
    detail: "Building SQL from user-controlled data allows injection regardless of variable name. Use parameterised queries.",
    cves: [{ id: "CWE-89", url: "https://cwe.mitre.org/data/definitions/89.html", description: "SQL Injection" }],
    check(line, lineIndex, allLines) {
      const findings: Finding[] = [];
      if (SQL_PARAM_RE.test(line)) return findings;

      // A. SQL keyword in template literal with interpolation
      const tplRe = /`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER|TRUNCATE)\b[^`]*\$\{/gi;
      let m: RegExpExecArray | null;
      while ((m = tplRe.exec(line)) !== null) findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });

      // B. SQL keyword in string + concatenation
      const catRe = /["'`][^"'`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b[^"'`]*["'`]\s*\+/gi;
      while ((m = catRe.exec(line)) !== null) {
        if (!findings.some(f => f.col === m!.index)) findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }

      // C. Python f-string with SQL keyword
      const fRe = /f["'][^"']*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b[^"']*\{/gi;
      while ((m = fRe.exec(line)) !== null) {
        if (!findings.some(f => f.col === m!.index)) findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }

      // D. .execute/.query with string concat — ANY variable name
      const exRe = /\.(?:execute|query|run|exec)\s*\(\s*["'`][^"'`]*["'`]\s*\+/gi;
      while ((m = exRe.exec(line)) !== null) {
        if (!findings.some(f => f.col === m!.index)) findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves });
      }

      // E. MULTI-LINE: var assigned SQL, then passed to sink within 8 lines
      if (SQL_SINK_RE.test(line) && !findings.length) {
        const varM = line.match(/\.(?:query|execute|run|exec|all|get|prepare)\s*\(\s*([a-zA-Z_$][\w$]*)/);
        if (varM) {
          const varName = varM[1];
          const lookback = allLines.slice(Math.max(0, lineIndex - 8), lineIndex);
          const assignRe = new RegExp(`\\b${varName}\\b.*\\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\\b`, "i");
          const hasDangerAssign = lookback.some(l => assignRe.test(l) && /\$\{|\+\s*\w|f["']/.test(l));
          if (hasDangerAssign && !SQL_PARAM_RE.test(lookback.join("\n"))) {
            findings.push({ line: lineIndex, col: 0, severity: "critical", ruleId: this.ruleId, message: "SQL injection: dynamic query variable passed to database call", detail: "A variable containing a dynamically built SQL string is passed to a database call. Use parameterised queries.", cves: this.cves });
          }
        }
      }
      return findings;
    },
  },

  // ══ 5. DANGEROUS FUNCTION ALIASING ═══════════════════════════════════════
  {
    ruleId: "dangerous-alias", severity: "critical", languages: langList([JS_TS]),
    message: "Dangerous function stored in variable — obfuscated code execution risk",
    detail: "Storing eval, exec, or Function in a variable and calling it later bypasses static analysis. This pattern is strongly associated with intentional obfuscation.",
    cves: [{ id: "CWE-95", url: "https://cwe.mitre.org/data/definitions/95.html", description: "Code Injection" }],
    check(line, lineIndex, allLines) {
      const findings: Finding[] = [];
      // Detect alias assignment on this line
      const am = /(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=/.exec(line);
      if (am) {
        const rhs = line.slice(line.indexOf("=") + 1);
        if (DANGEROUS_ALIAS_SOURCES.some(s => s.test(rhs))) {
          findings.push({ line: lineIndex, col: am.index, severity: "critical", ruleId: this.ruleId, message: `'${am[1]}' assigned a dangerous function reference`, detail: this.detail, cves: this.cves });
        }
      }
      // Detect calls to aliases defined in the previous 30 lines
      const lookback = allLines.slice(Math.max(0, lineIndex - 30), lineIndex);
      for (const prev of lookback) {
        const pm = /(?:const|let|var)\s+([a-zA-Z_$][\w$]*)\s*=/.exec(prev);
        if (!pm) continue;
        const rhs = prev.slice(prev.indexOf("=") + 1);
        if (!DANGEROUS_ALIAS_SOURCES.some(s => s.test(rhs))) continue;
        const alias = pm[1];
        const callRe = new RegExp(`\\b${alias}\\s*\\(`, "g");
        let m: RegExpExecArray | null;
        while ((m = callRe.exec(line)) !== null) {
          if (!findings.some(f => f.col === m!.index)) {
            findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: `Call to aliased dangerous function '${alias}'`, detail: `'${alias}' was assigned a dangerous function reference earlier in this block. Calling it is equivalent to calling the original dangerous function.`, cves: this.cves });
          }
        }
      }
      return findings;
    },
  },

  // ══ 6. INSECURE DEFAULTS — JS/TS ═════════════════════════════════════════
  {
    ruleId: "insecure-default", severity: "warning", languages: langList([JS_TS]),
    message: "Insecure default configuration detected",
    detail: "Web framework defaults often favour ease-of-use over security. Explicitly configure security-relevant options.",
    cves: [{ id: "CWE-1188", url: "https://cwe.mitre.org/data/definitions/1188.html", description: "Insecure Default Initialization of Resource" }],
    check(line, lineIndex, allLines) {
      const findings: Finding[] = [];
      for (const def of JS_INSECURE_DEFAULTS) {
        if (!def.re.test(line)) continue;
        if (def.safeguard) {
          const win = codeWindow(allLines, lineIndex, def.windowBefore ?? 2, def.windowAfter ?? 2);
          if (def.safeguard.test(win)) continue;
        }
        findings.push({ line: lineIndex, col: 0, severity: def.severity, ruleId: def.ruleId, message: def.message, detail: def.detail, cves: this.cves });
      }
      return findings;
    },
  },

  // ══ 6. INSECURE DEFAULTS — Python ════════════════════════════════════════
  {
    ruleId: "insecure-default", severity: "warning", languages: langList([PYTHON]),
    message: "Insecure default configuration detected",
    detail: "Web framework defaults often favour ease-of-use over security.",
    cves: [{ id: "CWE-1188", url: "https://cwe.mitre.org/data/definitions/1188.html", description: "Insecure Default Initialization of Resource" }],
    check(line, lineIndex, allLines) {
      const findings: Finding[] = [];
      for (const def of PYTHON_INSECURE_DEFAULTS) {
        if (!def.re.test(line)) continue;
        if (def.safeguard) {
          const win = codeWindow(allLines, lineIndex, def.windowBefore ?? 2, def.windowAfter ?? 2);
          if (def.safeguard.test(win)) continue;
        }
        findings.push({ line: lineIndex, col: 0, severity: def.severity, ruleId: def.ruleId, message: def.message, detail: def.detail, cves: this.cves });
      }
      return findings;
    },
  },

  // ══ 7. PYTHON-SPECIFIC DANGEROUS PATTERNS ════════════════════════════════
  {
    ruleId: "python-dangerous", severity: "critical", languages: langList([PYTHON]),
    message: "Dangerous Python function called with potentially untrusted input",
    detail: "Several Python built-ins allow arbitrary code execution when called with untrusted input.",
    cves: [
      { id: "CWE-78",  url: "https://cwe.mitre.org/data/definitions/78.html",  description: "OS Command Injection" },
      { id: "CWE-95",  url: "https://cwe.mitre.org/data/definitions/95.html",  description: "Code Injection" },
      { id: "CWE-502", url: "https://cwe.mitre.org/data/definitions/502.html", description: "Deserialization of Untrusted Data" },
    ],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const patterns: Array<{ re: RegExp; msg: string; det: string; sev: "critical"|"warning"; needsTaint?: boolean; safeguard?: RegExp }> = [
        { re: /\beval\s*\(/,           msg: "eval() allows arbitrary code execution",        det: "Use ast.literal_eval() for safe literal parsing.",            sev: "critical" },
        { re: /\bexec\s*\(/,           msg: "exec() allows arbitrary code execution",        det: "Never pass user-controlled data to exec().",                  sev: "critical" },
        { re: /\b__import__\s*\(/,     msg: "Dynamic __import__() — arbitrary module load",  det: "Use an explicit allowlist of permitted module names.",         sev: "critical" },
        { re: /\bgetattr\s*\([^)]*(?:request\.|form\.|args\.)/i, msg: "getattr() with user-controlled attribute", det: "Validate the attribute name against an allowlist.", sev: "critical", needsTaint: true },
        { re: /\bcompile\s*\([^)]*(?:request\.|form\.|args\.)/i, msg: "compile() with user-controlled code string", det: "compile() + exec/eval on user input is code injection.", sev: "critical", needsTaint: true },
        { re: /subprocess\.\w+\s*\([^)]*shell\s*=\s*True/i, msg: "subprocess shell=True — command injection", det: "Use a list of arguments with shell=False.", sev: "critical", safeguard: /shlex\.quote|shell\s*=\s*False/i },
        { re: /\bos\.system\s*\(/,     msg: "os.system() executes shell commands",          det: "Use subprocess.run() with a list and shell=False.",            sev: "critical" },
        { re: /\bos\.popen\s*\(/,      msg: "os.popen() executes shell commands",           det: "Use subprocess.run(capture_output=True).",                    sev: "critical" },
        { re: /\bopen\s*\([^)]*(?:request\.|form\.|args\.)/i, msg: "open() with user-controlled filename", det: "Use os.path.basename() and validate against an allowed directory.", sev: "critical", needsTaint: true },
        { re: /\btempfile\.mktemp\s*\(/, msg: "tempfile.mktemp() — TOCTOU race condition", det: "Use tempfile.mkstemp() or NamedTemporaryFile().",              sev: "warning" },
        { re: /\bpickle\.loads?\s*\(|cPickle\.loads?\s*\(/, msg: "pickle.loads() — arbitrary code on deserialization", det: "Never deserialize untrusted data with pickle. Use JSON.", sev: "critical" },
        { re: /\byaml\.load\s*\(/,     msg: "yaml.load() without SafeLoader — code execution risk", det: "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).", sev: "critical", safeguard: /safe_load|SafeLoader/i },
        { re: /\bmarshal\.loads?\s*\(/, msg: "marshal.loads() is unsafe with untrusted data", det: "Use JSON instead.",                                          sev: "critical" },
        { re: /\bshelve\.open\s*\(/,   msg: "shelve uses pickle internally",               det: "Use JSON-backed storage instead.",                            sev: "critical" },
        { re: /\bdill\.loads?\s*\(|\bjoblib\.load\s*\(/, msg: "Unsafe deserialization via dill/joblib", det: "dill and joblib use pickle and can execute arbitrary code.", sev: "critical" },
        { re: /\bhashlib\.md5\s*\(|\bhashlib\.new\s*\(\s*['"]md5['"]/i, msg: "MD5 is cryptographically broken", det: "Use hashlib.sha256() or hashlib.sha3_256().", sev: "warning" },
        { re: /\bhashlib\.sha1\s*\(|\bhashlib\.new\s*\(\s*['"]sha1['"]/i, msg: "SHA-1 is deprecated for security use", det: "Use hashlib.sha256() or hashlib.sha3_256().", sev: "warning" },
        { re: /\bassert\s+(?:is_admin|authenticated|has_permission|check_auth|verify|is_valid|logged_in)/i, msg: "Security check using assert — stripped by -O flag", det: "Python's -O flag disables assert. Use explicit if/raise instead.", sev: "warning" },
        { re: /requests\.\w+\s*\([^)]*verify\s*=\s*False/i, msg: "TLS verification disabled in requests", det: "verify=False allows MITM attacks. Remove this flag.", sev: "critical" },
        { re: /\bxml\.etree|minidom\.parseString|lxml\.etree/i, msg: "XML parsed without XXE protection", det: "Use defusedxml instead of standard library parsers.", sev: "critical", safeguard: /defusedxml/i },
        { re: /\brandom\.(?:random|randint|choice|randrange)\s*\([^)]*(?:token|secret|key|auth|otp|nonce|salt|session)/i, msg: "random module used for security-sensitive value", det: "Use secrets.token_urlsafe() or os.urandom() for security tokens.", sev: "warning" },
        { re: /\bAES\.MODE_ECB|modes\.ECB/i, msg: "ECB cipher mode leaks data patterns", det: "Use AES-GCM for authenticated encryption.", sev: "warning" },
        { re: /\bDjangoJSONEncoder/i, msg: "Verify DjangoJSONEncoder output is not exposed to untrusted clients", det: "DjangoJSONEncoder serialises model instances; ensure sensitive fields are excluded before returning to clients.", sev: "warning" },
      ];
      for (const { re, msg, det, sev, needsTaint, safeguard } of patterns) {
        const m = re.exec(line);
        if (!m) continue;
        if (safeguard && safeguard.test(line)) continue;
        if (needsTaint && !/request\.|form\.|args\.|input\s*\(|os\.environ|sys\.argv/i.test(line)) continue;
        findings.push({ line: lineIndex, col: m.index, severity: sev, ruleId: `py-${re.source.replace(/[^a-z]/gi,"").slice(0,18)}`, message: msg, detail: det, cves: this.cves });
      }
      return findings;
    },
  },

  // ══ EXISTING RULES (carried forward) ════════════════════════════════════

  { ruleId: "eval-external", severity: "critical", languages: langList([JS_TS]),
    message: "Dangerous eval() with non-literal argument",
    detail: "eval() with dynamic input executes arbitrary code. Use JSON.parse() for data or a proper sandbox.",
    cves: [{ id: "CWE-95", url: "https://cwe.mitre.org/data/definitions/95.html", description: "Code Injection" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      const re = /\beval\s*\(/g; let m: RegExpExecArray | null;
      while ((m = re.exec(line)) !== null) { const a = line.slice(m.index+m[0].length).trim(); if (!/^['"`]/.test(a)) findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: this.message, detail: this.detail, cves: this.cves }); }
      const re2 = /(?:global|window|this|self)\s*\[\s*['"]ev['"]\s*\+\s*['"]al['"]\s*\]/g;
      while ((m = re2.exec(line)) !== null) findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: "Obfuscated eval via string concatenation", detail: "Assembling 'eval' from parts bypasses static analysis — strong indicator of intentional obfuscation.", cves: this.cves });
      const re3 = /\b(?:setTimeout|setInterval)\s*\(\s*(?!function|=>|\()['"`]/g;
      while ((m = re3.exec(line)) !== null) findings.push({ line: lineIndex, col: m.index, severity: "critical", ruleId: this.ruleId, message: "Code execution via setTimeout/setInterval string", detail: "Passing a string invokes eval internally. Use a function reference.", cves: this.cves });
      return findings;
    } },

  { ruleId: "shell-injection", severity: "critical", languages: langList([PYTHON]),
    message: "Shell injection: subprocess shell=True or os.system()",
    detail: "shell=True enables injection. Use subprocess with a list and shell=False.",
    cves: [{ id: "CWE-78", url: "https://cwe.mitre.org/data/definitions/78.html", description: "OS Command Injection" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/shlex\.quote|shell\s*=\s*False/i.test(line)) return findings;
      for (const re of [/subprocess\.\w+\s*\(.*shell\s*=\s*True/i,/os\.system\s*\(/i,/os\.popen\s*\(/i,/commands\.(?:getoutput|getstatusoutput)\s*\(/i]) { const m=re.exec(line); if(m) findings.push({line:lineIndex,col:m.index,severity:"critical",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves}); }
      return findings;
    } },

  { ruleId: "pickle-loads", severity: "critical", languages: langList([PYTHON]),
    message: "Unsafe deserialization: pickle/marshal/shelve",
    detail: "pickle.loads() executes arbitrary code on deserialization. Use JSON.",
    cves: [{ id: "CWE-502", url: "https://cwe.mitre.org/data/definitions/502.html", description: "Deserialization of Untrusted Data" }],
    check(line, lineIndex) {
      const findings: Finding[] = []; const re=/pickle\.loads?\s*\(|cPickle\.loads?\s*\(|_pickle\.loads?\s*\(|marshal\.loads?\s*\(|shelve\.open\s*\(/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"critical",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "weak-hash-md5", severity: "warning", languages: langList([JS_TS,PYTHON]),
    message: "Weak hash algorithm: MD5",
    detail: "MD5 is cryptographically broken. Use SHA-256 or SHA-3.",
    cves: [{ id: "CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html", description: "Broken Cryptographic Algorithm" }],
    check(line, lineIndex) {
      const findings: Finding[] = []; const re=/\bmd5\s*\(|createHash\s*\(\s*['"]md5['"]\s*\)|hashlib\.md5\s*\(/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "weak-hash-sha1", severity: "warning", languages: langList([JS_TS,PYTHON]),
    message: "Weak hash algorithm: SHA-1",
    detail: "SHA-1 is deprecated. Use SHA-256 or SHA-3.",
    cves: [{ id: "CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html", description: "Broken Cryptographic Algorithm" }],
    check(line, lineIndex) {
      const findings: Finding[] = []; const re=/\bsha1\s*\(|createHash\s*\(\s*['"]sha1['"]\s*\)|hashlib\.sha1\s*\(/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "cors-wildcard", severity: "warning", languages: langList([JS_TS]),
    message: "CORS origin set to wildcard '*'",
    detail: "Allowing all origins exposes your API to cross-origin attacks. Restrict to known domains.",
    cves: [{ id: "CWE-942", url: "https://cwe.mitre.org/data/definitions/942.html", description: "Permissive Cross-domain Policy" }],
    check(line, lineIndex) {
      const findings: Finding[] = []; const re=/origin\s*[:=]\s*['"`]\*['"`]|Access-Control-Allow-Origin['"]\s*:\s*['"]\*/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "math-random-crypto", severity: "warning", languages: langList([JS_TS]),
    message: "Math.random() used for security-sensitive value",
    detail: "Math.random() is not cryptographically secure. Use crypto.randomBytes() or crypto.randomUUID().",
    cves: [{ id: "CWE-338", url: "https://cwe.mitre.org/data/definitions/338.html", description: "Weak PRNG" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (!/Math\.random\s*\(\s*\)/i.test(line)) return findings;
      if (!/token|session|secret|password|nonce|salt|\bkey\b|auth|otp|csrf|uuid/i.test(line)) return findings;
      const m=/Math\.random\s*\(\s*\)/i.exec(line); if(m) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "inner-html", severity: "warning", languages: langList([JS_TS]),
    message: "Unsafe innerHTML/outerHTML assignment",
    detail: "Assigning user-controlled content to innerHTML enables XSS. Use textContent or DOMPurify.",
    cves: [{ id: "CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html", description: "XSS" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/DOMPurify\.sanitize|sanitizeHtml\(|textContent/i.test(line)) return findings;
      const re=/\.(?:innerHTML|outerHTML)\s*=(?!=)|document\.write\s*\(|\.insertAdjacentHTML\s*\(/g; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "prototype-pollution", severity: "critical", languages: langList([JS_TS]),
    message: "Potential prototype pollution via dynamic key assignment",
    detail: "User-controlled keys assigned to objects without validation can pollute Object.prototype.",
    cves: [{ id: "CWE-1321", url: "https://cwe.mitre.org/data/definitions/1321.html", description: "Prototype Pollution" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/hasOwnProperty|Object\.create\(null\)|allowedKeys|whitelist|sanitize/i.test(line)) return findings;
      const re=/\w+\s*\[\s*\w+\s*\]\s*=(?!=)/g; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"critical",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "open-redirect", severity: "warning", languages: langList([JS_TS]),
    message: "Potential open redirect via user-controlled URL",
    detail: "Redirecting to a user-supplied URL enables phishing. Validate against an allowlist.",
    cves: [{ id: "CWE-601", url: "https://cwe.mitre.org/data/definitions/601.html", description: "Open Redirect" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/allowedDomains|allowedHosts|whitelist|validateUrl/i.test(line)) return findings;
      const re=/\b(?:res\.redirect|location\.href|location\.replace|window\.location|location\.assign)\s*[=(]/g; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) { const a=line.slice(m.index+m[0].length).trim(); if(!/^["'`]/.test(a)) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves}); }
      return findings;
    } },

  { ruleId: "tls-verify-disabled", severity: "critical", languages: ALL_LANGUAGES,
    message: "TLS certificate verification disabled",
    detail: "Disabling TLS verification allows MITM attacks.",
    cves: [{ id: "CWE-295", url: "https://cwe.mitre.org/data/definitions/295.html", description: "Improper Certificate Validation" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      for (const re of [/rejectUnauthorized\s*:\s*false/i,/verify\s*=\s*False/,/ssl\s*=\s*False/,/NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*['"]?0['"]?/,/InsecureRequestWarning/,/VERIFY_NONE/,/ssl_verify\s*=\s*false/i]) { const m=re.exec(line); if(m) findings.push({line:lineIndex,col:m.index,severity:"critical",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves}); }
      return findings;
    } },

  { ruleId: "ecb-mode", severity: "warning", languages: ALL_LANGUAGES,
    message: "ECB cipher mode leaks data patterns",
    detail: "AES-ECB encrypts identical blocks identically. Use AES-GCM.",
    cves: [{ id: "CWE-327", url: "https://cwe.mitre.org/data/definitions/327.html", description: "Broken Cryptographic Algorithm" }],
    check(line, lineIndex) {
      const findings: Finding[] = []; const re=/\bECB\b|aes-\d+-ecb|AES\.MODE_ECB|modes\.ECB/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "hardcoded-iv", severity: "warning", languages: ALL_LANGUAGES,
    message: "Hardcoded or static IV/nonce",
    detail: "Reusing an IV allows plaintext recovery. Generate a unique random IV per encryption.",
    cves: [{ id: "CWE-329", url: "https://cwe.mitre.org/data/definitions/329.html", description: "Static IV" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/crypto\.randomBytes\(|getRandomValues\(|os\.urandom\(|secrets\.token_bytes\(/i.test(line)) return findings;
      for (const re of [/\b(?:iv|nonce|IV)\s*=\s*(?:Buffer\.from\s*\(\s*)?["'][0-9a-fA-F\x00-\xff]{8,}["']/,/\b(?:iv|nonce)\s*=\s*(?:Buffer\.alloc|Buffer\.from)\s*\(\s*\d+\s*,\s*0\s*\)/i,/\b(?:iv|nonce|IV)\s*=\s*b["'][\\x0-9a-fA-F]{8,}["']/,/\b(?:iv|nonce)\s*=\s*bytes\s*\(\s*\d+\s*\)/i]) { const m=re.exec(line); if(m) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves}); }
      return findings;
    } },

  { ruleId: "jwt-no-verify", severity: "critical", languages: langList([JS_TS]),
    message: "JWT decoded without signature verification",
    detail: "jwt.decode() skips verification. Use jwt.verify() with the signing secret.",
    cves: [{ id: "CWE-347", url: "https://cwe.mitre.org/data/definitions/347.html", description: "Improper Verification of Cryptographic Signature" }],
    check(line, lineIndex) {
      const findings: Finding[] = []; const re=/jwt\.decode\s*\(|jsonwebtoken\.decode\s*\(/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"critical",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      const re2=/algorithms?\s*:\s*\[?\s*['"]none['"]/gi;
      while((m=re2.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"critical",ruleId:this.ruleId,message:"JWT 'none' algorithm — verification bypassed",detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "timing-attack", severity: "warning", languages: ALL_LANGUAGES,
    message: "Timing attack: secret compared with == instead of constant-time compare",
    detail: "String equality leaks secret content via timing. Use crypto.timingSafeEqual() or hmac.compare_digest().",
    cves: [{ id: "CWE-208", url: "https://cwe.mitre.org/data/definitions/208.html", description: "Observable Timing Discrepancy" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/timingSafeEqual|compare_digest|hmac\.compare/i.test(line)) return findings;
      if (!/\b(?:token|hmac|signature|hash|mac|digest|secret|password|apiKey|api_key)\b/i.test(line)) return findings;
      if (!/[!=]==?/.test(line) || !/if\s*\(|return\s|&&|\|\||[!=]==/.test(line)) return findings;
      const m=/[!=]==?/.exec(line); if(m) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "insecure-random-token", severity: "warning", languages: langList([PYTHON]),
    message: "Insecure PRNG for security token",
    detail: "random module is not cryptographically secure. Use secrets.token_urlsafe() or os.urandom().",
    cves: [{ id: "CWE-338", url: "https://cwe.mitre.org/data/definitions/338.html", description: "Weak PRNG" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (!/token|session|secret|password|nonce|salt|\bkey\b|auth|otp/i.test(line)) return findings;
      const re=/\brandom\.(?:random|randint|choice|randrange|uniform)\s*\(/g; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "localstorage-sensitive", severity: "warning", languages: langList([JS_TS]),
    message: "Sensitive data in localStorage/sessionStorage",
    detail: "localStorage is accessible to any JS on the page. Use HttpOnly cookies instead.",
    cves: [{ id: "CWE-922", url: "https://cwe.mitre.org/data/definitions/922.html", description: "Insecure Storage" }],
    check(line, lineIndex) {
      const findings: Finding[] = []; const re=/(?:localStorage|sessionStorage)\.setItem\s*\([^)]*(?:token|password|secret|key|auth|jwt|credential)/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"warning",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "log-injection", severity: "info", languages: ALL_LANGUAGES,
    message: "Log injection: user input written to logs",
    detail: "Logging raw user input allows log forging. Strip newlines before logging.",
    cves: [{ id: "CWE-117", url: "https://cwe.mitre.org/data/definitions/117.html", description: "Log Injection" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/replace.*\\n|re\.sub|sanitize/i.test(line)) return findings;
      const logRe=/(?:console\.(?:log|warn|error|info)|logger\.\w+|logging\.\w+)\s*\(/i;
      if (!logRe.test(line) || !/req\.|body\.|params\.|query\.|request\.\w+|args\.|form\.\w+/i.test(line)) return findings;
      const m=logRe.exec(line); if(m) findings.push({line:lineIndex,col:m.index,severity:"info",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "react-dangerous-html", severity: "critical", languages: langList([JS_TS]),
    message: "dangerouslySetInnerHTML with user-controlled content",
    detail: "Sanitise with DOMPurify.sanitize() before passing to dangerouslySetInnerHTML.",
    cves: [{ id: "CWE-79", url: "https://cwe.mitre.org/data/definitions/79.html", description: "XSS" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (/DOMPurify\.sanitize|sanitize\(|sanitizeHtml\(/i.test(line)) return findings;
      const re=/dangerouslySetInnerHTML\s*=\s*\{|__html\s*:/gi; let m:RegExpExecArray|null;
      while((m=re.exec(line))!==null) findings.push({line:lineIndex,col:m.index,severity:"critical",ruleId:this.ruleId,message:this.message,detail:this.detail,cves:this.cves});
      return findings;
    } },

  { ruleId: "weak-key-size", severity: "warning", languages: ALL_LANGUAGES,
    message: "Weak asymmetric key size (< 2048 bits)",
    detail: "Keys < 2048 bits can be factored. Use at least 2048; prefer 3072 or 4096.",
    cves: [{ id: "CWE-326", url: "https://cwe.mitre.org/data/definitions/326.html", description: "Inadequate Encryption Strength" }],
    check(line, lineIndex) {
      const findings: Finding[] = [];
      if (!/\b(?:generateKeyPair|generateKey|RSA_generate_key|generate_private_key|RSA\.generate)\b/i.test(line)) return findings;
      const sm=line.match(/\b(512|768|1024)\b/); if(!sm) return findings;
      findings.push({line:lineIndex,col:sm.index??0,severity:"warning",ruleId:this.ruleId,message:`Weak key size: ${sm[1]} bits`,detail:this.detail,cves:this.cves});
      return findings;
    } },
];

export const RULES_COUNT = rules.length;

export function analyse(
  text: string, languageId: string, startLine: number,
  suppressedRules: string[], _deps: Set<string> = new Set()
): Finding[] {
  const lines    = text.split("\n");
  const findings: Finding[] = [];
  const seen     = new Set<string>();

  for (const rule of rules) {
    if (suppressedRules.includes(rule.ruleId)) continue;
    if (!matchesLanguage(rule.languages, languageId)) continue;
    for (let i = 0; i < lines.length; i++) {
      const fl = lines[i];
      if (fl.includes("shieldprompt-ignore")) {
        const sm = fl.match(/shieldprompt-ignore:\s*([\w-]+)/);
        if (!sm || sm[1] === rule.ruleId) continue;
      }
      for (const f of rule.check(lines[i], i, lines, languageId)) {
        const key = `${f.ruleId}:${f.line + startLine}:${f.col}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({ ...f, line: f.line + startLine });
      }
    }
  }

  const sw: Record<string, number> = { critical: 0, warning: 1, info: 2 };
  findings.sort((a, b) => a.line !== b.line ? a.line - b.line : (sw[a.severity] ?? 3) - (sw[b.severity] ?? 3));
  return findings;
}

export function fingerprint(text: string): AIFingerprint {
  const lines    = text.split("\n");
  const nonEmpty = lines.filter(l => l.trim());
  if (!nonEmpty.length) return { isAI: false, confidence: "low" };
  let signals = 0;
  const comments = nonEmpty.filter(l => { const t=l.trim(); return t.startsWith("//")||t.startsWith("#")||t.startsWith("/*")||t.startsWith("*")||t.startsWith("'''")||t.startsWith('"""'); });
  if (comments.length / nonEmpty.length > 0.3) signals++;
  if (comments.some(l => /\bthis\s+\w+s?\s+\w+\s+by\s+\w+ing\b/i.test(l))) signals++;
  const funcs = nonEmpty.filter(l => /\b(function\s+\w+|=>\s*\{|def\s+\w+)/.test(l));
  if (funcs.length > 0 && nonEmpty.filter(l => /\b(try\s*\{|try\s*:)/.test(l.trim())).length >= funcs.length) signals++;
  if (/["']{3}\s*This function|\/\*\*[\s\S]*?This function/.test(text)) signals++;
  if (nonEmpty.filter(l => /^\s*(\/\/|#)\s*Step\s+\d+[:.]/im.test(l)).length >= 2) signals++;
  if (/(Here's|Here is) (the|a|an) (implementation|function|code|example|solution)/i.test(text)) signals++;
  if (signals >= 2) return { isAI: true, confidence: "high" };
  if (signals === 1) return { isAI: true, confidence: "medium" };
  return { isAI: false, confidence: "low" };
}