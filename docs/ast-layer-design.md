# AST Layer — Design Sketch

**Status:** design only. Not implemented.
**Goal:** reduce regex false positives on the two patterns regex demonstrably can't judge: taint flow across statements, and scope/ownership of identifiers.

---

## What regex gets wrong today

The current analyser is four layers of regex + line-window heuristics:

1. Hardcoded static (analyser.ts) — literal patterns per language
2. Hardcoded semantic (semanticAnalyser.ts) — `TAINT_SOURCES` regex over a ±10-line window
3. JSON language rules (ruleLoader.ts)
4. JSON framework rules (same engine)

The ±10-line taint window is a proxy for "does a tainted value reach this sink". It works for tight snippets and breaks for realistic code:

```ts
// FP: sink is within 10 lines of taint source, but the taint is reassigned to a sanitised value first.
const raw = req.body.q;
const q   = z.string().parse(raw);        // sanitisation
// … 3 lines …
db.query(q);                              // flagged as taint sink — false positive

// FN: sink > 10 lines away from source.
async function handleUpload(req) {
  const raw = req.body.path;
  await saveMetadata(raw);
  // 15 lines of unrelated work
  fs.readFile(raw);                       // not flagged — false negative
}
```

Regex also can't tell `user.query()` (user-defined method) from `db.query()` (Knex/Prisma sink). Rule IDs can collide across identically-named methods on different objects.

---

## Scope of this layer

**In scope:**
- JS/TS, Python. Same two languages the current semantic layer covers.
- Taint flow across variable assignments within a single file.
- Identifier scoping (is `query` a method on our `db` import, or unrelated?).

**Out of scope:**
- Cross-file / cross-module taint propagation. That's a data-flow analyser, an order of magnitude bigger.
- Full type inference. We don't need types — only reaching-definition analysis and import resolution.
- Replacing regex rules. The AST layer sits *alongside* the existing layers as a fifth layer and either:
  - upgrades a regex finding's confidence (kept), or
  - suppresses it when AST proves the taint path is broken.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│ pipeline.ts — analyseAllLayers()                            │
│                                                             │
│   Layer 1: static regex                                     │
│   Layer 2: semantic regex (±10-line taint)                  │
│   Layer 3: JSON language rules                              │
│   Layer 4: JSON framework rules                             │
│        │                                                    │
│        ▼                                                    │
│   Layer 5 (NEW): AST verifier                               │
│        • parse once per file                                │
│        • for each taint-sensitive finding:                  │
│            - resolve sink's receiver → import source        │
│            - walk reaching definitions of the arg           │
│            - check each def against a sanitiser set         │
│        • if AST proves safe: drop the finding               │
│        • if AST proves unsafe: bump confidence to critical  │
│                                                             │
│   categoryDedup → sort → return                             │
└─────────────────────────────────────────────────────────────┘
```

Key property: AST layer is a *filter*, not a source. If parsing fails or the file is a language we don't support, we keep the regex findings unchanged. Zero regression risk.

---

## Parser choice

Two viable options; pick one.

**Option A: `@typescript-eslint/parser`** (for JS/TS)
- Pros: battle-tested, handles JSX/TSX, modern syntax, ESM/CJS both.
- Pros: ESLint rules can be lifted wholesale if we ever want them.
- Cons: ~3 MB bundled. Matters for extension cold-start.
- Cons: JS/TS only — need a second parser for Python.

**Option B: `tree-sitter` with `tree-sitter-typescript` + `tree-sitter-python`**
- Pros: one parser infrastructure, multi-language. Query DSL for tree patterns.
- Pros: incremental re-parse on edits — cheap to run on every paste.
- Pros: ~800 KB bundled per grammar, but WASM builds exist.
- Cons: API is more verbose — no ready-made ESLint-style AST helpers.
- Cons: grammar updates lag the language spec slightly.

**Recommendation: tree-sitter.** The multi-language story is clean, the incremental parse fits the paste-handler path, and bundle size is manageable with lazy loading (only parse when a taint-sensitive rule fires).

---

## Data flow — reaching definitions per variable

For each variable reference in a sink argument, we need the set of assignments that can reach it. Formally: classic reaching-definitions dataflow, intraprocedural.

Simplified algorithm for our case:

```
sink = db.query(q)
       ^^^^^^^^  identify sink via ruleId → sink spec
              ^  resolve argument to identifier `q`

defs_of(q) =
  walk backwards from sink, collecting AST nodes that assign to `q`
  respecting block scope and conditional branches (join at phi nodes)

for each def in defs_of(q):
  if def is a taint source (req.body, params, form, stdin, etc):
    → tainted
  if def is a sanitiser call (z.parse, escape, pathlib.Path, etc):
    → clean
  if def is a copy from another variable:
    → recurse into defs_of(other)

final verdict = any(tainted) && !all(clean)
```

We don't need full SSA — a simple "walk backwards within the function body" is sufficient for this scope. Accept imprecision on loop-carried dependencies; they're rare in paste-analysis snippets.

---

## Sanitiser registry

A small JSON file mapping well-known sanitisation calls per language:

```jsonc
{
  "javascript": {
    "sanitisers": [
      { "match": "z.{method}", "methods": ["parse", "safeParse"] },
      { "match": "DOMPurify.sanitize" },
      { "match": "validator.escape" }
    ],
    "taintSources": [
      { "object": "req", "property": "body" },
      { "object": "req", "property": "query" },
      { "object": "req", "property": "params" }
    ]
  },
  "python": {
    "sanitisers": [
      { "match": "bleach.clean" },
      { "match": "html.escape" },
      { "match": "{schema}.load", "types": ["marshmallow.Schema"] }
    ],
    "taintSources": [
      { "object": "request", "property": "form" },
      { "object": "request", "property": "args" },
      { "object": "request", "property": "json" }
    ]
  }
}
```

Kept deliberately sparse — err on "suspicious" for unknown calls. Registry grows as FPs surface.

---

## Sink annotation on rules

Extend `CompiledRule` with an optional AST hint so the filter knows what to verify:

```ts
interface CompiledRule {
  // …existing fields
  ast?: {
    sinkArg: number | "all";   // which argument position holds the tainted value
    receiver?: string;         // optional expected receiver type/module
  };
}
```

Only rules with `ast` metadata get AST verification. Everything else passes through regex-only.

Example annotation on `sqlalchemy-raw-text-injection`:
```json
{
  "ruleId": "sqlalchemy-raw-text-injection",
  "patterns": [ ... ],
  "ast": { "sinkArg": 0, "receiver": "sqlalchemy.text" }
}
```

---

## Performance budget

On paste-handler path, the user is waiting. Budget: **50 ms P95 for AST work on a typical paste** (≤200 lines).

- Parse cost: tree-sitter parses ~20 MB/s. A 200-line paste ≈ 10 KB → sub-ms.
- Query cost: dominated by reaching-definitions walks. One walk per taint-sensitive finding. Cap at 10 findings per file → ≤50 ms of AST work.
- Lazy-load the grammar on first use — keeps extension activation cold-start untouched.

On project-scan path, already off the interactive path, budget is 500 ms per file average. Plenty of room.

---

## Integration with the existing cache

The project scan cache (#4) already keys on `{mtime, ruleVersion, depsHash}`. AST verification would bump `ruleVersion` on upgrade (since the registry + annotations are part of rule pack), so cache invalidation works without further plumbing.

---

## Phased rollout

**Phase 1 (1–2 weeks).** Spike with tree-sitter-typescript on a single rule: `eval(userInput)` in JS. Implement reaching-definitions in one file. Measure FP reduction on a fixture corpus.

**Phase 2 (2–3 weeks).** Expand to ~5 rules per language. Add Python grammar. Ship behind a `shieldprompt.astLayer` flag, default off. Collect telemetry on verdict flips.

**Phase 3 (2–4 weeks).** Enable by default if FP reduction ≥ 30% and no regression on taint-positive tests. Annotate the full JSON rule pack with `ast` metadata over time.

**Kill switches:**
- Per-user config flag to disable AST layer
- Per-rule opt-out via `"ast": false` in JSON
- Graceful fallback on parse error (drop to regex verdict)

---

## Test strategy

Fixtures directory: `tests/fixtures/ast/`. Each fixture a small file with a `// expected: <finding-or-none>` comment. The test runner:

1. Feeds the fixture through `analyseAllLayers`
2. Compares findings to the expected annotation
3. Reports both FP (flagged but expected clean) and FN (expected finding missed)

Start with the motivating examples from the top of this doc. Grow the corpus to ~50 fixtures covering the common FP patterns people report.

---

## Open questions

1. **Flow sensitivity** — do we model `if (isSafe(x)) { db.query(x); }` as clean on the true branch? Increases complexity; probably skip in Phase 1.
2. **Await / async** — taint flows through Promise resolutions. Need to handle `const x = await req.json()` as tainted.
3. **Destructuring** — `const { id } = req.body` should propagate taint to `id`. Tree-sitter query can identify this pattern.
4. **Type-erasure** — `as unknown as string` is a common unsafe cast. Worth flagging as a taint boundary? Probably out of scope for AST layer; belongs in a separate rule.

---

## What this is *not*

- Not a replacement for regex rules. Regex catches patterns AST can't (credential shapes, magic strings, config snippets).
- Not a full SAST tool. Semgrep, CodeQL, Snyk do that at 100× the complexity. Our niche is the paste-handler — fast, local, approximate.
- Not a formal verifier. AST layer reduces FPs; it does not prove absence of vulnerability.
