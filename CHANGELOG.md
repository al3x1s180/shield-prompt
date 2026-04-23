# Changelog

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
