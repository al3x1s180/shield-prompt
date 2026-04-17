# ShieldPrompt

**Detects security vulnerabilities in AI-generated code the moment you paste it.**

ShieldPrompt fires on paste — not on every keystroke. It catches the exact patterns that ChatGPT, Claude, and Copilot produce at high rates and shows you exactly what's wrong inline.

---

## Why ShieldPrompt instead of Snyk or SonarLint?

| | ShieldPrompt | Snyk | SonarLint |
|---|---|---|---|
| Fires on paste only | ✅ | ❌ scans whole file | ❌ scans on type |
| Zero auth / login required | ✅ | ❌ requires account | ❌ requires account |
| Works offline | ✅ | ❌ | Partial |
| No CLI dependency | ✅ | ❌ requires Snyk CLI | ❌ |
| AI-generation detection | ✅ | ❌ | ❌ |
| Tuned for LLM hallucinations | ✅ | ❌ general rules | ❌ general rules |

---

## How it works

1. **Paste** AI-generated code into any file
2. **ShieldPrompt detects** it was pasted (not typed) and analyses it instantly
3. **Flagged lines** get highlighted with coloured gutter markers
4. **The panel** opens showing exactly what's wrong, why it's dangerous, and the CVE if one exists

---

## Security rules

ShieldPrompt catches the vulnerability classes that LLMs produce at highest rates:

| Rule | Severity | Languages |
|---|---|---|
| `eval()` on dynamic input | Critical | JS, TS |
| Hardcoded secrets / API keys | Critical | All |
| SQL injection via string concat | Critical | All |
| `subprocess` with `shell=True` | Critical | Python |
| `pickle.loads()` deserialization | Critical | Python |
| Weak hash: MD5, SHA-1 | Warning | JS, TS, Python |
| CORS wildcard `*` | Warning | JS, TS |
| `Math.random()` for crypto | Warning | JS, TS |
| Unsafe `innerHTML` assignment | Warning | JS, TS |

---

## Settings

| Setting | Default | Description |
|---|---|---|
| `pasteguard.enabled` | `true` | Enable/disable ShieldPrompt |
| `pasteguard.minLines` | `3` | Minimum pasted lines to trigger analysis |
| `pasteguard.suppressedRules` | `[]` | Rule IDs to suppress per workspace |
| `pasteguard.ignoreCompletions` | `false` | Skip Copilot-style injections |

---

## Commands

- `ShieldPrompt: Open panel` — Open the findings panel
- `ShieldPrompt: Reset suppressed rules` — Clear all workspace suppressions
- `ShieldPrompt: Toggle on/off` — Enable or disable without uninstalling

---

## Privacy

All analysis runs entirely locally. Your code never leaves your machine. No telemetry is collected without opt-in.

---

## License

MIT
