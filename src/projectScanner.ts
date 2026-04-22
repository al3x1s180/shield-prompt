import * as fs from "fs";
import * as path from "path";
import * as cp from "child_process";
import * as crypto from "crypto";
import { Finding } from "./analyser";
import { LoadedRules } from "./ruleLoader";
import { analyseAllLayers } from "./pipeline";

const EXT_TO_LANG: Record<string, string> = {
  ".js":   "javascript",
  ".jsx":  "javascriptreact",
  ".ts":   "typescript",
  ".tsx":  "typescriptreact",
  ".py":   "python",
  ".java": "java",
  ".cs":   "csharp",
  ".go":   "go",
  ".rb":   "ruby",
  ".php":  "php",
  ".rs":   "rust",
  ".c":    "c",
  ".h":    "c",
  ".cpp":  "cpp",
  ".cc":   "cpp",
};

const SUPPORTED_EXTENSIONS = new Set(Object.keys(EXT_TO_LANG));

const ALWAYS_SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt",
  "vendor", "venv", ".venv", "__pycache__", ".pytest_cache", "target",
  "bin", "obj", ".gradle", "coverage", ".nyc_output", ".turbo",
  "storybook-static", ".svelte-kit",
]);

const DEFAULT_FILE_LIMIT = 1000;
const BATCH_SIZE = 10;

export interface ScanCacheEntry {
  mtimeMs: number;
  ruleVersion: string;
  depsHash: string;
  findings: Finding[];
}

export interface ScanCache {
  get(key: string): ScanCacheEntry | undefined;
  set(key: string, entry: ScanCacheEntry): void | Promise<void>;
  keys(): string[];
  delete(key: string): void | Promise<void>;
}

export class InMemoryScanCache implements ScanCache {
  private readonly store = new Map<string, ScanCacheEntry>();
  get(key: string): ScanCacheEntry | undefined { return this.store.get(key); }
  set(key: string, entry: ScanCacheEntry): void { this.store.set(key, entry); }
  keys(): string[] { return [...this.store.keys()]; }
  delete(key: string): void { this.store.delete(key); }
  clear(): void { this.store.clear(); }
  size(): number { return this.store.size; }
}

export interface ProjectScanOptions {
  cache?: ScanCache;
  ruleVersion?: string;
  fileLimit?: number;
  deps?: Set<string>;
  onProgress?: (scanned: number, total: number, cached: number) => void;
}

export interface ProjectScanResult {
  file: string;
  findings: Finding[];
}

// Derives a stable hash over the loaded rules' structure so that rule-pack
// changes (extension upgrade, rule edits) invalidate cached findings.
export function hashRulePack(rules: LoadedRules | undefined): string {
  if (!rules) return "no-rules";
  const parts: string[] = [];
  const collect = (scope: string, map: Map<string, unknown[]>): void => {
    const keys = [...map.keys()].sort();
    for (const k of keys) {
      const arr = map.get(k) as Array<{ ruleId: string; severity: string; patterns: unknown[]; safeguards: unknown[]; safeguardScope?: string; requiresTaint?: boolean; category?: string }>;
      for (const r of arr) {
        parts.push(
          `${scope}|${k}|${r.ruleId}|${r.severity}|${r.patterns.length}|${r.safeguards.length}|${r.safeguardScope ?? ""}|${r.requiresTaint ?? ""}|${r.category ?? ""}`
        );
      }
    }
  };
  collect("lang", rules.languageRules as Map<string, unknown[]>);
  collect("fw",   rules.frameworkRules as Map<string, unknown[]>);
  return crypto.createHash("sha256").update(parts.join("\n")).digest("hex").slice(0, 16);
}

export function hashDeps(deps: Set<string>): string {
  const sorted = [...deps].sort().join(",");
  return crypto.createHash("sha256").update(sorted).digest("hex").slice(0, 16);
}

function getGitFiles(rootPath: string): Promise<string[] | null> {
  return new Promise((resolve) => {
    cp.exec(
      "git ls-files --cached --others --exclude-standard",
      { cwd: rootPath, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout) => {
        if (err) { resolve(null); return; }
        const files = stdout
          .split("\n")
          .map((f) => f.trim())
          .filter((f) => f.length > 0)
          .map((f) => path.join(rootPath, f))
          .filter((f) => SUPPORTED_EXTENSIONS.has(path.extname(f).toLowerCase()));
        resolve(files);
      }
    );
  });
}

function walkDir(dirPath: string, results: string[] = []): string[] {
  let entries: fs.Dirent[];
  try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); }
  catch { return results; }

  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".env") continue;
    if (entry.isDirectory()) {
      if (ALWAYS_SKIP_DIRS.has(entry.name)) continue;
      walkDir(path.join(dirPath, entry.name), results);
    } else if (entry.isFile()) {
      if (SUPPORTED_EXTENSIONS.has(path.extname(entry.name).toLowerCase())) {
        results.push(path.join(dirPath, entry.name));
      }
    }
  }
  return results;
}

async function discoverFiles(rootPath: string, fileLimit: number): Promise<string[]> {
  const gitFiles = await getGitFiles(rootPath);
  const files = gitFiles ?? walkDir(rootPath);
  return files.slice(0, fileLimit);
}

async function scanOne(
  filePath: string,
  deps: Set<string>,
  rules: LoadedRules | undefined
): Promise<Finding[]> {
  let text: string;
  try { text = await fs.promises.readFile(filePath, "utf8"); }
  catch { return []; }

  const languageId = EXT_TO_LANG[path.extname(filePath).toLowerCase()] ?? "plaintext";
  // Pass an empty suppressed list here — suppression is applied in
  // runProjectScan after the cache lookup so cached entries stay valid when
  // the user toggles a suppressed rule.
  return analyseAllLayers(text, languageId, 0, [], deps, rules);
}

export async function runProjectScan(
  rootPath: string,
  suppressed: string[],
  rules?: LoadedRules,
  options: ProjectScanOptions = {}
): Promise<ProjectScanResult[]> {
  const fileLimit   = options.fileLimit ?? DEFAULT_FILE_LIMIT;
  const cache       = options.cache;
  const ruleVersion = options.ruleVersion ?? hashRulePack(rules);

  const files        = await discoverFiles(rootPath, fileLimit);
  const deps         = options.deps ?? new Set<string>();
  const depsHash     = hashDeps(deps);

  // Prune stale entries for files that no longer live under rootPath — handles
  // deletes, renames, and files that dropped out of the cap. We scope the prune
  // to this workspace by key prefix so we don't touch other projects' entries.
  if (cache) {
    const rootPrefix = rootPath.endsWith(path.sep) ? rootPath : rootPath + path.sep;
    const liveSet    = new Set(files);
    for (const key of cache.keys()) {
      if (key !== rootPath && !key.startsWith(rootPrefix)) continue; // belongs to a different workspace
      if (!liveSet.has(key)) { await cache.delete(key); }
    }
  }
  const suppressSet  = new Set(suppressed);
  const applySuppress = (findings: Finding[]): Finding[] =>
    suppressSet.size === 0 ? findings : findings.filter((f) => !suppressSet.has(f.ruleId));

  const results: ProjectScanResult[] = [];
  let cachedHits = 0;
  const total = files.length;

  for (let i = 0; i < files.length; i += BATCH_SIZE) {
    const batch = files.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(batch.map(async (filePath): Promise<ProjectScanResult> => {
      let mtimeMs = 0;
      try {
        const stats = await fs.promises.stat(filePath);
        mtimeMs = stats.mtimeMs;
      } catch {
        return { file: filePath, findings: [] };
      }

      const entry = cache?.get(filePath);
      if (
        entry &&
        entry.mtimeMs === mtimeMs &&
        entry.ruleVersion === ruleVersion &&
        entry.depsHash === depsHash
      ) {
        cachedHits++;
        return { file: filePath, findings: applySuppress(entry.findings) };
      }

      const findings = await scanOne(filePath, deps, rules);
      if (cache) {
        await cache.set(filePath, { mtimeMs, ruleVersion, depsHash, findings });
      }
      return { file: filePath, findings: applySuppress(findings) };
    }));
    for (const r of batchResults) results.push(r);
    options.onProgress?.(results.length, total, cachedHits);
  }

  return results;
}
