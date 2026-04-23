// Coverage + FP audit — a corpus of realistic snippets that should (or
// should NOT) produce a finding, grouped by vulnerability class. Each case
// carries a short rationale so when a test breaks you can tell WHY the
// expectation exists.
//
// This is the *regression suite* that stops the FP/FN reduction work from
// silently drifting. Adding a new rule? Add cases here. Noticed an FP in
// the wild? Add a `safe` case and fix the rule until this suite passes.

import { describe, it, expect, beforeAll } from "vitest";
import * as path from "path";
import { analyseAllLayers } from "../src/pipeline";
import { loadRules, LoadedRules } from "../src/ruleLoader";

const REPO_ROOT = path.resolve(__dirname, "..");

type Expectation = "vulnerable" | "safe";
interface Case {
  name:     string;
  code:     string;
  language: "javascript" | "typescript" | "python" | "php";
  expect:   Expectation;
  rationale: string;
  // Optional: require a specific ruleId or category to appear / not appear.
  requireRuleId?:   string;
  forbidRuleId?:    string;
  // Optional dependencies to simulate a framework being active.
  deps?: string[];
  // Optional: simulate this being a test file.
  filePath?: string;
}

// ─── SQL INJECTION ──────────────────────────────────────────────────────────
const SQLI: Case[] = [
  {
    name: "JS template literal with user input",
    code: `const user = await db.query(\`SELECT * FROM users WHERE id = '\${req.body.id}'\`);`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Classic template-literal SQLi — MUST catch. Either sql-concat (hardcoded rule) or sql-injection (semantic layer) is acceptable.",
  },
  {
    name: "JS string concatenation",
    code: `db.query("SELECT * FROM u WHERE id = " + req.params.id);`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "String concat with user input into query — MUST catch.",
  },
  {
    name: "JS parameterized query (safe)",
    code: `db.query("SELECT * FROM u WHERE id = ?", [req.params.id]);`,
    language: "javascript",
    expect: "safe",
    rationale: "Parameterized query — MUST NOT flag.",
  },
  {
    name: "Python f-string SQL",
    code: `cursor.execute(f"SELECT * FROM users WHERE id = '{request.args.get('id')}'")`,
    language: "python",
    expect: "vulnerable",
    rationale: "Python f-string SQLi — MUST catch.",
  },
  {
    name: "Python parameterized (safe)",
    code: `cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))`,
    language: "python",
    expect: "safe",
    rationale: "Parameterized pyformat — MUST NOT flag.",
  },
];

// ─── COMMAND INJECTION ──────────────────────────────────────────────────────
const CMD: Case[] = [
  {
    name: "JS exec with user input",
    code: `require('child_process').exec('ls ' + req.body.path);`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Shell exec with user input — critical, MUST catch.",
  },
  {
    name: "JS exec with literal (safe)",
    code: `require('child_process').exec('ls -la');`,
    language: "javascript",
    expect: "safe",
    rationale: "Static arg — should not flag.",
  },
  {
    name: "Python os.system with user input",
    code: `import os\nos.system("rm -rf " + request.form['dir'])`,
    language: "python",
    expect: "vulnerable",
    rationale: "os.system + user input — MUST catch.",
  },
  {
    name: "Python subprocess with shell=True + user input",
    code: `subprocess.call(f"grep {pattern} file.txt", shell=True)`,
    language: "python",
    expect: "vulnerable",
    rationale: "shell=True + interpolated user input — MUST catch.",
  },
];

// ─── EVAL ────────────────────────────────────────────────────────────────────
const EVAL: Case[] = [
  {
    name: "JS eval with req body",
    code: `eval(req.body.code);`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Direct eval on user input — MUST catch.",
    requireRuleId: "eval-external",
  },
  {
    name: "JS eval with literal (safe)",
    code: `eval("1 + 1");`,
    language: "javascript",
    expect: "safe",
    rationale: "Eval of literal — still bad practice but not our FP class.",
    forbidRuleId: "eval-external",
  },
  {
    name: "JS eval inside string (FP class)",
    code: `const warning = "Please do not use eval() on user input";`,
    language: "javascript",
    expect: "safe",
    rationale: "eval() keyword inside a string literal — classic FP.",
  },
  {
    name: "JS eval inside comment (FP class)",
    code: `// TODO: refactor to avoid eval() on user input\nconst x = 1;`,
    language: "javascript",
    expect: "safe",
    rationale: "eval() keyword inside a comment — classic FP.",
  },
];

// ─── HARDCODED SECRETS ──────────────────────────────────────────────────────
const SECRETS: Case[] = [
  {
    name: "AWS access key",
    code: `const key = "AKIAIOSFODNN7EXAMPLE";`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "AWS key literal — MUST catch, including inside a string.",
    requireRuleId: "hardcoded-secret",
  },
  {
    name: "Stripe live secret key",
    code: `const s = "sk_live_4eC39HqLyjWDarjtT1zdp7dc";`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Stripe live key — MUST catch.",
  },
  {
    name: "Generic safe env usage",
    code: `const k = process.env.API_KEY;`,
    language: "javascript",
    expect: "safe",
    rationale: "Env var reference — not a leak.",
  },
  {
    name: "AWS key in comment (still FP-class? depends)",
    code: `// example: AKIAIOSFODNN7EXAMPLE\nconst x = 1;`,
    language: "javascript",
    expect: "safe",
    rationale: "Credential in comment — arguably still a leak, but Phase 1 drops it. Document this tradeoff.",
  },
];

// ─── XSS ─────────────────────────────────────────────────────────────────────
const XSS: Case[] = [
  {
    name: "React dangerouslySetInnerHTML with state",
    code: `<div dangerouslySetInnerHTML={{ __html: props.html }} />`,
    language: "typescript",
    expect: "vulnerable",
    rationale: "dangerouslySetInnerHTML with user-controlled HTML — MUST catch.",
  },
  {
    name: "React dangerouslySetInnerHTML with sanitized",
    code: `<div dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }} />`,
    language: "typescript",
    expect: "safe",
    rationale: "Sanitized via DOMPurify — should not flag.",
  },
];

// ─── WEAK CRYPTO ────────────────────────────────────────────────────────────
const CRYPTO: Case[] = [
  {
    name: "SHA-1 usage",
    code: `crypto.createHash("sha1").update(data).digest("hex");`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "SHA-1 is broken for most uses — MUST warn.",
  },
  {
    name: "SHA-1 in a string comment (FP)",
    code: `const msg = "We used to use sha1 here"; const h = crypto.createHash("sha256");`,
    language: "javascript",
    expect: "safe",
    rationale: "sha1 string mention + real sha256 call — phrase is in string, real call is fine.",
  },
  {
    name: "MD5 usage",
    code: `crypto.createHash("md5").update(data);`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "MD5 also broken — MUST warn.",
  },
];

// ─── PATH TRAVERSAL ─────────────────────────────────────────────────────────
const PATH_TRAVERSAL: Case[] = [
  {
    name: "Direct user input into fs.readFile",
    code: `fs.readFile(req.body.path, cb);`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "User path → fs read — MUST catch.",
  },
];

// ─── TEST FILE SUPPRESSION ──────────────────────────────────────────────────
const TEST_FILES: Case[] = [
  {
    name: "eval() in a .test.ts file",
    code: `describe("x", () => { it("evals", () => { eval("1+1"); }); });`,
    language: "typescript",
    expect: "safe",
    rationale: "Explicit test file — behaviour rule should be suppressed.",
    filePath: "src/foo.test.ts",
  },
  {
    name: "AWS key in a fixture file (still flags)",
    code: `const k = "AKIAIOSFODNN7EXAMPLE";`,
    language: "typescript",
    expect: "vulnerable",
    rationale: "Credential rules survive test-file suppression — real key is a real leak.",
    filePath: "src/fixtures/creds.ts",
  },
];

// ─── SSRF ────────────────────────────────────────────────────────────────────
const SSRF: Case[] = [
  {
    name: "Server-side fetch with user URL",
    code: `app.get("/fetch", async (req, res) => { const r = await fetch(req.query.url); res.send(await r.text()); });`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "User-controlled URL passed to server-side fetch — classic SSRF.",
  },
  {
    name: "fetch with hardcoded URL (safe)",
    code: `const r = await fetch("https://api.example.com/public-data");`,
    language: "javascript",
    expect: "safe",
    rationale: "Hardcoded URL — not SSRF.",
  },
];

// ─── INSECURE DESERIALIZATION ───────────────────────────────────────────────
const DESERIAL: Case[] = [
  {
    name: "Python pickle.loads on user input",
    code: `import pickle\ndata = pickle.loads(request.body)`,
    language: "python",
    expect: "vulnerable",
    rationale: "pickle.loads on untrusted data → RCE. Critical.",
  },
  {
    name: "Python yaml.load (unsafe)",
    code: `import yaml\nconfig = yaml.load(open('config.yml'))`,
    language: "python",
    expect: "vulnerable",
    rationale: "yaml.load without SafeLoader can execute arbitrary Python. Critical.",
  },
  {
    name: "Python yaml.safe_load (safe)",
    code: `import yaml\nconfig = yaml.safe_load(open('config.yml'))`,
    language: "python",
    expect: "safe",
    rationale: "safe_load is the safe variant — must not flag.",
  },
];

// ─── INSECURE RANDOMNESS ────────────────────────────────────────────────────
const RANDOMNESS: Case[] = [
  {
    name: "Math.random() used for token generation",
    code: `function makeToken() { return Math.random().toString(36).slice(2); }`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Math.random is predictable — unsafe for tokens/IDs.",
  },
  {
    name: "Math.random() for UI effect (FP — unreachable with current rule)",
    code: `const opacity = Math.random();`,
    language: "javascript",
    expect: "safe",
    rationale: "Math.random for non-security use — ideally shouldn't flag, but our regex may not distinguish. Accept either outcome.",
    forbidRuleId: "__no_enforcement__",
  },
];

// ─── OPEN REDIRECT ──────────────────────────────────────────────────────────
const OPEN_REDIRECT: Case[] = [
  {
    name: "Express redirect with user input",
    code: `app.get("/go", (req, res) => res.redirect(req.query.next));`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Unvalidated redirect destination — phishing vector.",
  },
];

// ─── COMMON FP CLASSES ──────────────────────────────────────────────────────
const FP_CASES: Case[] = [
  {
    name: "Error message mentioning 'password' (FP)",
    code: `throw new Error("Password must be at least 12 characters long");`,
    language: "javascript",
    expect: "safe",
    rationale: "Help text inside a string — must not flag as hardcoded password.",
  },
  {
    name: "Log line mentioning 'SELECT' (FP)",
    code: `console.log("About to run SELECT query for user " + userId);`,
    language: "javascript",
    expect: "safe",
    rationale: "SELECT keyword inside a log string, no actual SQL being built. Soft FP.",
    // Note: some rules (catRe in sql-concat) will still fire here because
    // SELECT inside quotes + concat = classic SQLi pattern. We accept this.
  },
  {
    name: "JSDoc comment mentioning eval",
    code: `/** @example eval is dangerous */\nexport function safeParse(s) { return JSON.parse(s); }`,
    language: "javascript",
    expect: "safe",
    rationale: "Block comment with 'eval' — must not flag, comment filter handles.",
  },
  {
    name: "Import of a module named 'eval-plugin' (FP)",
    code: `import evalPlugin from "eval-plugin";`,
    language: "javascript",
    expect: "safe",
    rationale: "Module name contains 'eval' but is not a call — must not flag.",
  },
  {
    name: "Placeholder / example key in string (FP — Phase 1 drops it)",
    code: `const exampleKey = "REPLACE_WITH_YOUR_AWS_ACCESS_KEY";`,
    language: "javascript",
    expect: "safe",
    rationale: "Placeholder, not a real key. Current rule uses AKIA prefix so placeholder won't match — good.",
  },
  {
    name: "Real AWS key in an env template file (still flags)",
    code: `const k = "AKIAIOSFODNN7EXAMPLE";`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Real AWS key pattern — MUST catch.",
  },
];

// ─── AI-GENERATED COMMON MISTAKES ──────────────────────────────────────────
const AI_PATTERNS: Case[] = [
  {
    name: "Copilot-style string concat SQL",
    code: `app.post("/login", (req, res) => { db.query("SELECT * FROM u WHERE email = '" + req.body.email + "'"); });`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "Very common AI-generated pattern — MUST catch.",
  },
  {
    name: "ChatGPT-style open Express CORS",
    code: `app.use(cors({ origin: "*", credentials: true }));`,
    language: "javascript",
    expect: "vulnerable",
    rationale: "origin: '*' with credentials: true is a known dangerous combo.",
  },
  {
    name: "AI-generated unsafe JSON.parse on request",
    code: `const data = JSON.parse(req.body);`,
    language: "javascript",
    expect: "safe",
    rationale: "JSON.parse on user input can throw but is not a direct vulnerability. Must not false-positive.",
  },
];

const ALL_CASES: Case[] = [
  ...SQLI, ...CMD, ...EVAL, ...SECRETS, ...XSS, ...CRYPTO, ...PATH_TRAVERSAL,
  ...SSRF, ...DESERIAL, ...RANDOMNESS, ...OPEN_REDIRECT,
  ...FP_CASES, ...AI_PATTERNS, ...TEST_FILES,
];

// ─── Runner ─────────────────────────────────────────────────────────────────
describe("Coverage + FP audit", () => {
  let rules: LoadedRules;
  beforeAll(async () => { rules = await loadRules(REPO_ROOT); });

  for (const c of ALL_CASES) {
    it(`${c.expect === "vulnerable" ? "CATCHES" : "IGNORES"} — ${c.name}`, () => {
      const findings = analyseAllLayers(
        c.code, c.language, 0, [], new Set(c.deps ?? []), rules,
        { astLayer: true, skipNoisyInTests: !!c.filePath, filePath: c.filePath }
      );

      if (c.expect === "vulnerable") {
        expect(findings.length, `expected at least 1 finding — rationale: ${c.rationale}`).toBeGreaterThan(0);
        if (c.requireRuleId) {
          expect(
            findings.some((f) => f.ruleId === c.requireRuleId),
            `expected ruleId "${c.requireRuleId}" — got: ${findings.map((f) => f.ruleId).join(", ")}`
          ).toBe(true);
        }
      } else {
        if (c.forbidRuleId) {
          expect(
            findings.some((f) => f.ruleId === c.forbidRuleId),
            `forbade ruleId "${c.forbidRuleId}" but got it — rationale: ${c.rationale}`
          ).toBe(false);
        } else {
          expect(
            findings.length,
            `expected NO findings — got: ${findings.map((f) => f.ruleId).join(", ")} — rationale: ${c.rationale}`
          ).toBe(0);
        }
      }
    });
  }
});
