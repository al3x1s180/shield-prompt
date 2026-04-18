"use strict";

/**
 * ruleLoader.js
 *
 * Loads security rules from:
 *  1. Bundled JSON files (always available, used as fallback)
 *  2. Remote GitHub Pages URL (fetched once per day, cached in globalState)
 *
 * Supports both language rules and framework-specific rules.
 * Framework detection uses Option C: import scanning + dependency file scanning.
 */

const fs    = require("fs");
const path  = require("path");
const https = require("https");

const REMOTE_BASE           = "https://al3x1s180.github.io/shield-prompt/rules";
const CACHE_KEY             = "shieldprompt.rulesCache";
const CACHE_DATE_KEY        = "shieldprompt.rulesCacheDate";
const FRAMEWORK_CACHE_KEY   = "shieldprompt.frameworkRulesCache";
const CHECK_INTERVAL        = 24 * 60 * 60 * 1000; // 24 hours

// Language ID → rules file name
const LANGUAGE_MAP = {
  "javascript":       "javascript",
  "javascriptreact":  "javascript",
  "typescript":       "typescript",
  "typescriptreact":  "typescript",
  "python":           "python",
  "java":             "java",
  "csharp":           "csharp",
  "go":               "go",
  "ruby":             "ruby",
  "php":              "php",
  "rust":             "rust",
  "c":                "c",
  "cpp":              "c",
};

// ─── HTTP FETCH ──────────────────────────────────────────────────────────────

function fetchUrl(url, timeoutMs = 8000) {
  return new Promise((resolve) => {
    const req = https.get(url, { timeout: timeoutMs }, (res) => {
      if (res.statusCode !== 200) { res.resume(); resolve(null); return; }
      const chunks = [];
      res.on("data", (c) => chunks.push(c));
      res.on("end",  () => resolve(Buffer.concat(chunks).toString("utf8")));
      res.on("error", () => resolve(null));
    });
    req.on("timeout", () => { req.destroy(); resolve(null); });
    req.on("error",   () => resolve(null));
  });
}

// ─── BUNDLED FILE LOADERS ────────────────────────────────────────────────────

function loadBundled(extensionPath, lang) {
  try {
    const raw = fs.readFileSync(path.join(extensionPath, "rules", lang + ".json"), "utf8");
    return JSON.parse(raw);
  } catch { return null; }
}

function loadBundledManifest(extensionPath) {
  try {
    const raw = fs.readFileSync(path.join(extensionPath, "rules", "manifest.json"), "utf8");
    return JSON.parse(raw);
  } catch { return null; }
}

function loadBundledFramework(extensionPath, frameworkName) {
  try {
    const raw = fs.readFileSync(path.join(extensionPath, "rules", "frameworks", frameworkName + ".json"), "utf8");
    return JSON.parse(raw);
  } catch { return null; }
}

function loadBundledFrameworkManifest(extensionPath) {
  try {
    const raw = fs.readFileSync(path.join(extensionPath, "rules", "frameworks", "manifest-frameworks.json"), "utf8");
    return JSON.parse(raw);
  } catch { return null; }
}

// ─── DEPENDENCY READER ───────────────────────────────────────────────────────

/**
 * Read all dependency files and return a Set of lowercase dependency names.
 * Covers: package.json, requirements.txt, pyproject.toml, Pipfile
 */
async function readAllDeps(workspaceRoot) {
  const deps = new Set();

  // package.json
  try {
    const raw = fs.readFileSync(path.join(workspaceRoot, "package.json"), "utf8");
    const pkg = JSON.parse(raw);
    const all = { ...pkg.dependencies, ...pkg.devDependencies, ...pkg.peerDependencies };
    for (const name of Object.keys(all)) deps.add(name.toLowerCase());
  } catch {}

  // requirements.txt
  try {
    const lines = fs.readFileSync(path.join(workspaceRoot, "requirements.txt"), "utf8").split("\n");
    for (const line of lines) {
      const name = line.split(/[>=<!;\s]/)[0].trim().toLowerCase();
      if (name && !name.startsWith("#")) deps.add(name);
    }
  } catch {}

  // pyproject.toml — parse [project] dependencies and [tool.poetry.dependencies]
  try {
    const raw = fs.readFileSync(path.join(workspaceRoot, "pyproject.toml"), "utf8");
    // Match lines like: package = "^1.0" or "package>=1.0" in arrays
    const matches = raw.matchAll(/^\s*["']?([\w][\w\-\.]+)["']?\s*[=>{]/gm);
    for (const m of matches) {
      const name = m[1].toLowerCase();
      if (name && !["python", "requires-python"].includes(name)) deps.add(name);
    }
    // Also match dependency strings in arrays: "fastapi>=0.100"
    const arrayMatches = raw.matchAll(/["']([\w][\w\-\.]+)(?:[>=<!][^"']*)?["']/g);
    for (const m of arrayMatches) deps.add(m[1].toLowerCase());
  } catch {}

  // Pipfile — parse [packages] and [dev-packages] sections
  try {
    const raw = fs.readFileSync(path.join(workspaceRoot, "Pipfile"), "utf8");
    let inPackages = false;
    for (const line of raw.split("\n")) {
      const trimmed = line.trim();
      if (trimmed === "[packages]" || trimmed === "[dev-packages]") { inPackages = true; continue; }
      if (trimmed.startsWith("[")) { inPackages = false; continue; }
      if (inPackages && trimmed && !trimmed.startsWith("#")) {
        const name = trimmed.split(/[=\s]/)[0].trim().toLowerCase();
        if (name) deps.add(name);
      }
    }
  } catch {}

  return deps;
}

// ─── FRAMEWORK DETECTION (OPTION C) ─────────────────────────────────────────

/**
 * Detect which frameworks are present using:
 *  (a) Import scanning of the pasted text
 *  (b) Dependency file scanning
 *
 * Returns a Set of detected framework names.
 */
function detectFrameworksFromImports(text, frameworkManifest) {
  const detected = new Set();
  if (!frameworkManifest || !frameworkManifest.frameworks) return detected;

  for (const [name, meta] of Object.entries(frameworkManifest.frameworks)) {
    for (const importSig of (meta.detectionImports || [])) {
      if (text.includes(importSig)) {
        detected.add(name);
        break;
      }
    }
  }
  return detected;
}

function detectFrameworksFromDeps(deps, frameworkManifest) {
  const detected = new Set();
  if (!frameworkManifest || !frameworkManifest.frameworks) return detected;

  for (const [name, meta] of Object.entries(frameworkManifest.frameworks)) {
    for (const dep of (meta.detectionDeps || [])) {
      if (deps.has(dep.toLowerCase())) {
        detected.add(name);
        break;
      }
    }
  }
  return detected;
}

/**
 * Combined detection — union of import-based and dep-based detection.
 */
function detectFrameworks(text, deps, frameworkManifest) {
  const fromImports = detectFrameworksFromImports(text, frameworkManifest);
  const fromDeps    = detectFrameworksFromDeps(deps, frameworkManifest);
  return new Set([...fromImports, ...fromDeps]);
}

// ─── REMOTE UPDATE ───────────────────────────────────────────────────────────

async function tryRemoteUpdate(extensionPath, globalState, currentCache, currentFrameworkCache) {
  try {
    // Language rules update
    const manifestRaw = await fetchUrl(REMOTE_BASE + "/manifest.json");
    if (manifestRaw) {
      const remoteManifest   = JSON.parse(manifestRaw);
      const bundledManifest  = loadBundledManifest(extensionPath) || { languages: {} };
      const newCache         = { ...currentCache };
      let   updated          = false;

      for (const [lang, remoteVersion] of Object.entries(remoteManifest.languages || {})) {
        const cachedVersion  = currentCache[lang]?.version   ?? 0;
        const bundledVersion = loadBundled(extensionPath, lang)?.version ?? 0;
        const currentVersion = Math.max(cachedVersion, bundledVersion);

        if (remoteVersion > currentVersion) {
          const raw = await fetchUrl(REMOTE_BASE + "/" + lang + ".json");
          if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed.rules) && typeof parsed.version === "number") {
              newCache[lang] = parsed;
              updated = true;
            }
          }
        }
      }
      if (updated) await globalState.update(CACHE_KEY, newCache);
      await globalState.update(CACHE_DATE_KEY, Date.now());
    }

    // Framework rules update
    const fwManifestRaw = await fetchUrl(REMOTE_BASE + "/frameworks/manifest-frameworks.json");
    if (fwManifestRaw) {
      const remoteFwManifest = JSON.parse(fwManifestRaw);
      const newFwCache       = { ...currentFrameworkCache };
      let   fwUpdated        = false;

      for (const [fw, meta] of Object.entries(remoteFwManifest.frameworks || {})) {
        const remoteVersion  = meta.version ?? 0;
        const cachedVersion  = currentFrameworkCache[fw]?.version   ?? 0;
        const bundledVersion = loadBundledFramework(extensionPath, fw)?.version ?? 0;
        const currentVersion = Math.max(cachedVersion, bundledVersion);

        if (remoteVersion > currentVersion) {
          const raw = await fetchUrl(REMOTE_BASE + "/frameworks/" + fw + ".json");
          if (raw) {
            const parsed = JSON.parse(raw);
            if (Array.isArray(parsed.rules) && typeof parsed.version === "number") {
              newFwCache[fw] = parsed;
              fwUpdated = true;
            }
          }
        }
      }
      if (fwUpdated) await globalState.update(FRAMEWORK_CACHE_KEY, newFwCache);
    }

  } catch {
    // Silently ignore all remote errors
  }
}

// ─── PUBLIC API ──────────────────────────────────────────────────────────────

/**
 * Load all language rules.
 * Returns Map<languageId, rule[]>
 */
async function loadRules(extensionPath, globalState) {
  const lastCheck   = globalState.get(CACHE_DATE_KEY, 0);
  const shouldFetch = (Date.now() - lastCheck) > CHECK_INTERVAL;
  let   cache       = globalState.get(CACHE_KEY, {});
  const fwCache     = globalState.get(FRAMEWORK_CACHE_KEY, {});

  if (shouldFetch) {
    await tryRemoteUpdate(extensionPath, globalState, cache, fwCache);
    cache = globalState.get(CACHE_KEY, {});
  }

  const rulesMap = new Map();
  for (const [langId, langFile] of Object.entries(LANGUAGE_MAP)) {
    const ruleSet = cache[langFile] || loadBundled(extensionPath, langFile);
    if (ruleSet && Array.isArray(ruleSet.rules)) {
      rulesMap.set(langId, ruleSet.rules);
    }
  }
  return rulesMap;
}

/**
 * Load framework rules for detected frameworks.
 * Returns Map<frameworkName, { rules: rule[], language: string }>
 */
async function loadFrameworkRules(extensionPath, globalState) {
  const fwCache         = globalState.get(FRAMEWORK_CACHE_KEY, {});
  const bundledFwManifest = loadBundledFrameworkManifest(extensionPath);
  const frameworkMap    = new Map();

  const allFrameworks = Object.keys(bundledFwManifest?.frameworks || {});
  for (const fw of allFrameworks) {
    const ruleSet = fwCache[fw] || loadBundledFramework(extensionPath, fw);
    if (ruleSet && Array.isArray(ruleSet.rules)) {
      frameworkMap.set(fw, { rules: ruleSet.rules, language: ruleSet.language, framework: fw });
    }
  }
  return frameworkMap;
}

/**
 * Load the framework manifest (for detection metadata).
 */
function loadFrameworkManifest(extensionPath, globalState) {
  // Try to get a cached version, fall back to bundled
  return loadBundledFrameworkManifest(extensionPath);
}

/**
 * Force an immediate remote update (used by the "Check for rule updates" command).
 */
async function forceRemoteUpdate(extensionPath, globalState) {
  const cache   = globalState.get(CACHE_KEY, {});
  const fwCache = globalState.get(FRAMEWORK_CACHE_KEY, {});
  await tryRemoteUpdate(extensionPath, globalState, cache, fwCache);
}

module.exports = {
  loadRules,
  loadFrameworkRules,
  loadFrameworkManifest,
  detectFrameworks,
  readAllDeps,
  forceRemoteUpdate,
  LANGUAGE_MAP,
};