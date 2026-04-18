"use strict";

/**
 * projectScanner.js
 *
 * Scans all eligible files in the workspace against the loaded rules.
 * - Respects .gitignore via git ls-files when available
 * - Falls back to manual extension-based glob when git is not available
 * - Hard limit of 200 files with clear feedback
 * - Runs files in parallel batches for speed
 * - Reports progress as files complete
 */

const fs      = require("fs");
const path    = require("path");
const cp      = require("child_process");

// Language ID map — file extension → VS Code languageId
const EXT_TO_LANG = {
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

// Directories to always skip even if git is not available
const ALWAYS_SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", "out", ".next", ".nuxt",
  "vendor", "venv", ".venv", "__pycache__", ".pytest_cache", "target",
  "bin", "obj", ".gradle", "coverage", ".nyc_output", ".turbo",
  "storybook-static", ".svelte-kit", "public/build",
]);

const FILE_LIMIT = 200;

// ─── FILE DISCOVERY ──────────────────────────────────────────────────────────

/**
 * Try to get tracked + untracked (non-ignored) files from git.
 * Returns null if git is not available.
 */
function getGitFiles(rootPath) {
  return new Promise((resolve) => {
    // git ls-files lists tracked files; --others --exclude-standard adds untracked non-ignored
    const cmd = "git ls-files --cached --others --exclude-standard";
    cp.exec(cmd, { cwd: rootPath, maxBuffer: 10 * 1024 * 1024 }, (err, stdout) => {
      if (err) { resolve(null); return; }
      const files = stdout
        .split("\n")
        .map((f) => f.trim())
        .filter((f) => f.length > 0)
        .map((f) => path.join(rootPath, f))
        .filter((f) => {
          const ext = path.extname(f).toLowerCase();
          return SUPPORTED_EXTENSIONS.has(ext);
        });
      resolve(files);
    });
  });
}

/**
 * Fallback: walk the directory tree manually, skipping ALWAYS_SKIP_DIRS.
 */
function walkDir(dirPath, results = []) {
  let entries;
  try { entries = fs.readdirSync(dirPath, { withFileTypes: true }); }
  catch { return results; }

  for (const entry of entries) {
    if (entry.name.startsWith(".") && entry.name !== ".env") continue;
    if (entry.isDirectory()) {
      if (ALWAYS_SKIP_DIRS.has(entry.name)) continue;
      walkDir(path.join(dirPath, entry.name), results);
    } else if (entry.isFile()) {
      const ext = path.extname(entry.name).toLowerCase();
      if (SUPPORTED_EXTENSIONS.has(ext)) {
        results.push(path.join(dirPath, entry.name));
      }
    }
  }
  return results;
}

/**
 * Discover all scannable files in the workspace.
 * Returns { files: string[], usedGit: boolean, totalFound: number, limited: boolean }
 */
async function discoverFiles(rootPath) {
  let files = await getGitFiles(rootPath);
  const usedGit = files !== null;

  if (!usedGit) {
    files = walkDir(rootPath);
  }

  const totalFound = files.length;
  const limited    = totalFound > FILE_LIMIT;
  if (limited) files = files.slice(0, FILE_LIMIT);

  return { files, usedGit, totalFound, limited };
}

// ─── FILE SCANNER ────────────────────────────────────────────────────────────

/**
 * Scan a single file and return findings tagged with filePath and languageId.
 */
function scanFile(filePath, runRulesFn, detectFrameworksFn, loadedRulesMap, loadedFrameworkMap, frameworkManifest, cachedDeps, suppressedRules) {
  let text;
  try { text = fs.readFileSync(filePath, "utf8"); }
  catch { return []; }

  // Skip very large files (>500KB) to avoid slowness
  if (text.length > 512000) return [];

  const ext      = path.extname(filePath).toLowerCase();
  const languageId = EXT_TO_LANG[ext] || "plaintext";
  if (languageId === "plaintext") return [];

  // Language rules
  const langFindings = runRulesFn(text, languageId, 0, suppressedRules, loadedRulesMap);

  // Framework rules
  const fwFindings = [];
  if (frameworkManifest) {
    const detected = detectFrameworksFn(text, cachedDeps, frameworkManifest);
    for (const fwName of detected) {
      const fw = loadedFrameworkMap.get(fwName);
      if (!fw) continue;
      const langMatches = !fw.language ||
        languageId.startsWith(fw.language) ||
        (fw.language === "javascript" && ["typescript","javascriptreact","typescriptreact"].includes(languageId)) ||
        (fw.language === "typescript" && ["javascript","javascriptreact","typescriptreact"].includes(languageId));
      if (!langMatches) continue;
      const tempMap = new Map([[languageId, fw.rules]]);
      const found = runRulesFn(text, languageId, 0, suppressedRules, tempMap);
      for (const f of found) { f.framework = fwName; fwFindings.push(f); }
    }
  }

  // Merge + deduplicate
  const seen   = new Set(langFindings.map((f) => f.line + ":" + f.ruleId));
  const merged = [...langFindings];
  for (const f of fwFindings) {
    const key = f.line + ":" + f.ruleId;
    if (!seen.has(key)) { merged.push(f); seen.add(key); }
  }

  // Tag each finding with file info
  return merged.map((f) => ({ ...f, filePath, languageId }));
}

// ─── MAIN SCAN ───────────────────────────────────────────────────────────────

const BATCH_SIZE = 10; // files processed in parallel per batch

/**
 * Run a full project scan.
 *
 * @param {string}   rootPath
 * @param {Function} runRulesFn
 * @param {Function} detectFrameworksFn
 * @param {Map}      loadedRulesMap
 * @param {Map}      loadedFrameworkMap
 * @param {object}   frameworkManifest
 * @param {Set}      cachedDeps
 * @param {string[]} suppressedRules
 * @param {Function} onProgress  - called with (scannedCount, totalFiles, currentFile)
 * @param {object}   cancelToken - { cancelled: boolean }
 * @returns {Promise<ScanResult>}
 */
async function runProjectScan(
  rootPath,
  runRulesFn,
  detectFrameworksFn,
  loadedRulesMap,
  loadedFrameworkMap,
  frameworkManifest,
  cachedDeps,
  suppressedRules,
  onProgress,
  cancelToken
) {
  const discovery = await discoverFiles(rootPath);
  const { files, usedGit, totalFound, limited } = discovery;

  const allFindings = []; // { filePath, languageId, findings[] }
  let scanned = 0;

  // Process in batches
  for (let i = 0; i < files.length; i += BATCH_SIZE) {
    if (cancelToken.cancelled) break;

    const batch = files.slice(i, i + BATCH_SIZE);
    const batchResults = await Promise.all(
      batch.map((filePath) =>
        new Promise((resolve) => {
          // Use setImmediate to yield to event loop between files
          setImmediate(() => {
            const findings = scanFile(
              filePath, runRulesFn, detectFrameworksFn,
              loadedRulesMap, loadedFrameworkMap, frameworkManifest,
              cachedDeps, suppressedRules
            );
            resolve({ filePath, findings });
          });
        })
      )
    );

    for (const { filePath, findings } of batchResults) {
      scanned++;
      if (findings.length > 0) {
        allFindings.push({ filePath, findings });
      }
      if (onProgress) onProgress(scanned, files.length, filePath);
    }
  }

  // Sort files by finding count descending (worst files first)
  allFindings.sort((a, b) => b.findings.length - a.findings.length);

  return {
    scanned,
    totalFound,
    limited,
    usedGit,
    cancelled: cancelToken.cancelled,
    fileResults: allFindings,
    totalFindings: allFindings.reduce((s, f) => s + f.findings.length, 0),
    scannedFiles: files,
  };
}

module.exports = { runProjectScan, EXT_TO_LANG, FILE_LIMIT };