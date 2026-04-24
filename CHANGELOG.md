# Changelog

## 1.1.7

### Coverage (real-world benchmark)
- **DVWA ground-truth audit**: baseline was 1/15 (7%) canonical vulnerabilities caught. After rule cleanup on PHP + taint-source widening + taint-window tuning, it's now **11/15 (73%)**. The 4 remaining misses are genuine cross-file vulnerabilities (source file has taint, sink is in a different file) — out of scope for per-file analysis.
- **Taint window raised from ±10 lines to ±20.** Real code often has 3-4 intermediate helper operations between user-input assignment and the sink (`trim`, `str_replace`, `intval`, etc.). The wider window catches these without measurable FP increase on the fixture corpus.
- **Taint sources expanded**: added PHP superglobals (`$_GET/POST/REQUEST/COOKIE/FILES/SERVER/SESSION`, `php://input`), Ruby (`params[:`, `request.params`), Go (`r.FormValue`, `r.URL.Query`), Java servlets (`request.getParameter`). Previously, PHP rules with `requiresTaint: true` never fired because no PHP source was recognised.
- **PHP rule cleanup** — sql-injection, xss, command-injection, file-inclusion, path-traversal patterns now recognise PHP-style string interpolation (`"SELECT ... $var"`) and concatenation through intermediate variables (`$foo = $_GET[...]; exec("cmd " . $foo)`), not just direct `$_GET` in sink.
- **Coverage audit corpus grew from 42 to 60 cases** (18 new PHP cases).

### Project scan UX
- **Clickable findings**: every finding row in the Scan Project panel now opens the file at the exact line and column of the match, in a side editor.
- **Severity filter**: `All / Critical only / Warnings only` pill buttons.
- **File search**: live filter by path substring.
- **Collapsible per-file groups** with expand/collapse-all controls.
- **Stat cards** at the top showing critical / warnings / files-scanned.
- File rows now sort by critical count (descending), then total findings.

### Tooling
- New `scripts/benchmark.ts` — scans any local directory with the same pipeline, prints summary (totals by severity, category, top files). Run with `npx tsx scripts/benchmark.ts <path>`.
- New `scripts/benchmark-dvwa-ground-truth.ts` — targeted audit against DVWA's known-vulnerable canonical files.
- `tsx` added as dev dependency (for benchmark script execution).

## 1.1.2

### Fixes (reduce false positives without hurting detection)
- **Findings inside comments are no longer reported.** A rule regex matching a keyword (e.g. `sha1`, `eval`) inside an explanatory comment used to fire on every scan. The new AST layer tokenizes the source, identifies comment byte ranges (respecting strings and template literals), and drops any finding whose position falls inside one. Enabled by default via `shieldprompt.astLayer` — set to `false` to restore pre-1.1.2 behaviour.
- **Findings inside string literals are dropped too, except for credential rules.** Matches like `"please don't use eval()"` or `"avoid SELECT * FROM users with string concat"` no longer false-positive. Credential-style rules (AWS/Stripe keys, JWT tokens, hardcoded secrets) are explicitly exempt because their findings live *inside* strings by definition.
- **Template literals with `${}` interpolation are correctly treated as part-code**, so SQL injection via `` db.query(`SELECT * FROM u WHERE id = ${req.body.id}`) `` is still detected.
- **`dangerous-alias` no longer misfires on strings** that happen to contain the word `eval`. Rule now strips string literals from the RHS before checking.
- **Test / fixture / mock files skip noisy rules by default.** Paths matching `__tests__/`, `test/`, `spec/`, `fixtures/`, `*.test.*`, `*_test.py`, `conftest.py`, etc. suppress behaviour-class findings but keep credential leak detection. Controlled by `shieldprompt.skipNoisyInTests`.

### New settings
- `shieldprompt.astLayer` (default `true`) — comment + string filtering.
- `shieldprompt.skipNoisyInTests` (default `true`) — test-file FP reduction.
- `shieldprompt.minSeverity` (`"warning"` | `"critical"`, default `"warning"`) — hide `warning`-severity findings to further reduce noise. Credential leaks are always shown regardless.

### Infrastructure
- **Coverage + FP audit suite** — 42 fixture cases covering SQL injection, command injection, eval, hardcoded secrets, XSS, weak crypto, path traversal, SSRF, insecure deserialization, open redirect, insecure randomness, plus 10+ intentional FP scenarios (help strings mentioning `eval`, log lines mentioning `SELECT`, JSDoc comments, etc.). Serves as a regression net for future rule changes.
- Test suite grew to 142 tests across 8 files.

## 1.1.0

### Security
- **AI Fix API key is now stored in the OS keychain** (macOS Keychain, Windows Credential Manager, Linux libsecret) via VSCode's SecretStorage, instead of plaintext in `settings.json`. Existing plaintext keys are migrated once on first launch and then wiped from every `ConfigurationTarget` scope.
- New command `ShieldPrompt: Set AI Fix API key` — prompts for the key via a masked input.
- New command `ShieldPrompt: Clear AI Fix API key` — removes the stored key from the keychain.

### Project scan
- **Per-file mtime cache** persists across sessions in `workspaceState`. Repeat project scans reuse cached findings when the file's mtime, the rule-pack version, and the workspace's dependency set are all unchanged.
- Cache entries for files that no longer exist (deleted, renamed, or dropped out of the file cap) are pruned on each scan.
- Default file limit raised from 200 to 1000.
- New setting `shieldprompt.projectScanFileLimit` — override the cap.
- New command `ShieldPrompt: Clear project scan cache`.

### Detection quality
- Rules with setup-registered safeguards (e.g. `helmet()`, CSRF middleware, RLS policies, schema validation) now declare `"safeguardScope": "file"` in their JSON. One match anywhere in the file suppresses every finding from that rule, reducing false positives on the lines where the protected sink is called.
- Rules tied to a well-known vulnerability class now declare an explicit `"category"` field (e.g. `"sql-injection"`, `"xss"`, `"ssrf"`). Cross-layer dedup uses this to collapse near-duplicate findings on the same line without relying on ruleId regex heuristics.
- `requiresTaint: true` rules only fire when a taint source is within ±10 lines of the sink, cutting FPs on sinks that happen to share a file with unrelated user input.
- Safeguard matching now strips line comments before checking, so a commented-out safeguard no longer suppresses a live sink on the same line.
- Fixed `CATEGORY_FRAGMENTS` regex bug that was silently skipping cross-layer dedup for rule IDs with trailing suffixes (e.g. `sql-injection-generic`).

### Infrastructure
- Vitest test suite added (58 tests across analyser, semanticAnalyser, ruleLoader, pipeline, and projectScanner).
- Analysis pipeline extracted into `src/pipeline.ts` — zero VSCode dependency, fully unit-testable.
