# ShieldPrompt

**Security analysis for AI-generated code — fires the moment you paste, not while you type.**

Most developers using AI assistants follow the same workflow: ask for code, review it quickly, paste it in. ShieldPrompt fits into that exact moment. The instant you paste, it silently analyses the code, highlights any vulnerable lines directly in the editor, and opens a findings panel explaining what's wrong and how to fix it — all before you've had time to run anything.

---

## How it works

ShieldPrompt runs two analysis layers on every paste:

**Static analysis** matches known dangerous patterns on individual lines — fast, zero false positives on exact matches, covers the most common vulnerability classes across JavaScript, TypeScript, Python, and more.

**Semantic analysis** goes further. It builds a taint map across the entire pasted block, tracking user-controlled values as they flow through variable assignments, helper function calls, and into dangerous sinks — even when source and sink are separated by many lines. It also checks for structural problems: auth routes missing rate-limit middleware, upload handlers missing validation, truncated hash values used as identifiers.

Neither layer sends your code anywhere. Everything runs locally inside VS Code.

---

## Why this instead of other security tools

Most security linters are designed for CI pipelines and whole-project scans. They require accounts, CLIs, language servers, or external services to work. ShieldPrompt has none of those dependencies — it installs as a single extension with no setup, works offline, and fires only on paste so it never slows your editor while you type.

It also detects whether pasted code was AI-generated, and labels findings accordingly — useful context when reviewing code from a model you don't fully trust.

---

## Using it

Install the extension. Paste any block of code into a supported file. That's it.

If ShieldPrompt finds issues, a panel opens beside your editor listing each finding with its severity, the affected line, the rule that fired, and a plain-English explanation of the risk and the fix. Clicking a finding expands its detail. CVE and CWE references are clickable links.

The panel has four actions:

**Re-scan File** — runs a full analysis of the entire active file, not just the last paste. Before scanning it strips any existing ignore comments so previously suppressed lines are re-evaluated from scratch. Useful after you've made fixes and want a clean read.

**AI Fix Suggestions** — sends all current findings, along with the relevant lines of code for context, to the Anthropic API and displays fix proposals inline in the panel. If you haven't added an API key under `shieldprompt.aiFixApiKey`, it falls back to copying a ready-made prompt to your clipboard so you can paste it into any AI assistant manually.

**Scan Project** — runs the full rule set against every file in the workspace and shows results grouped by file. Respects `.gitignore`.

**Ignore on this line** — available on each individual finding. Adds a `// shieldprompt-ignore: <rule-id>` comment to that line and removes the gutter marker. The suppression is per-line and per-rule, so it won't hide other findings on the same line. Re-scan File will clear these comments and re-evaluate everything fresh.

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `shieldprompt.enabled` | `true` | Enable or disable analysis on paste |
| `shieldprompt.minLines` | `3` | Minimum pasted lines to trigger analysis |
| `shieldprompt.suppressedRules` | `[]` | Rule IDs to suppress across the whole workspace |
| `shieldprompt.aiFixApiKey` | `""` | Anthropic API key for AI Fix Suggestions |
| `shieldprompt.aiFixModel` | `claude-haiku-4-5-20251001` | Model used for AI Fix Suggestions |

---

## Commands

- `ShieldPrompt: Open panel` — Reopen the findings panel
- `ShieldPrompt: Toggle on/off` — Disable temporarily without uninstalling
- `ShieldPrompt: Reset suppressed rules` — Clear all workspace-level suppressions
- `ShieldPrompt: Scan Project` — Run analysis across the full project
- `ShieldPrompt: Check for rule updates` — Pull the latest rule definitions

---

## Privacy

All analysis runs locally inside the extension host process. Your code is never transmitted anywhere unless you use AI Fix Suggestions with an API key configured, in which case the flagged code context is sent to the Anthropic API. No account is required for any other feature. No telemetry.

---

## License

MIT