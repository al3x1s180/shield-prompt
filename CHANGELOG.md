# Changelog

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
