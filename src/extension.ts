import * as vscode from "vscode";
import * as path from "path";
import { onPaste } from "./detector";
import { fingerprint, Finding, AIFingerprint } from "./analyser";
import { ShieldPromptPanel, AI_FIX_API_KEY_SECRET } from "./panel";
import {
  applyDecorations,
  createEditClearListener,
  disposeDecorationTypes,
} from "./decorations";
import { readProjectDeps } from "./depReader";
import { runProjectScan, ScanCache, ScanCacheEntry, hashRulePack } from "./projectScanner";
import { loadRules, LoadedRules } from "./ruleLoader";
import { analyseAllLayers } from "./pipeline";

let statusBarItem: vscode.StatusBarItem;
let panel: ShieldPromptPanel;
let currentFindings: Finding[] = [];
let currentFingerprint: AIFingerprint = { isAI: false, confidence: "low" };
let loadedRules: LoadedRules | undefined;
let projectScanCache: WorkspaceStateCache | undefined;

const SCAN_CACHE_PREFIX = "shieldprompt.scanCache.v1:";

// Wraps vscode.Memento (context.workspaceState) so the project scanner can
// persist per-file findings across sessions. Keys are prefixed so we can
// enumerate and clear them without trampling other workspaceState entries.
class WorkspaceStateCache implements ScanCache {
  constructor(private readonly memento: vscode.Memento) {}
  get(key: string): ScanCacheEntry | undefined {
    return this.memento.get<ScanCacheEntry>(SCAN_CACHE_PREFIX + key);
  }
  async set(key: string, entry: ScanCacheEntry): Promise<void> {
    await this.memento.update(SCAN_CACHE_PREFIX + key, entry);
  }
  keys(): string[] {
    return this.memento.keys()
      .filter((k) => k.startsWith(SCAN_CACHE_PREFIX))
      .map((k) => k.slice(SCAN_CACHE_PREFIX.length));
  }
  async delete(key: string): Promise<void> {
    await this.memento.update(SCAN_CACHE_PREFIX + key, undefined);
  }
  async clear(): Promise<void> {
    const keys = this.memento.keys().filter((k) => k.startsWith(SCAN_CACHE_PREFIX));
    for (const k of keys) { await this.memento.update(k, undefined); }
  }
}
// Tracks the last document scanned so we can re-scan even when the webview
// is focused (which makes vscode.window.activeTextEditor undefined).
let lastScannedDocument: vscode.TextDocument | undefined;

function findEditorFor(doc: vscode.TextDocument): vscode.TextEditor | undefined {
  return vscode.window.visibleTextEditors.find((e) => e.document === doc);
}

function resolveScanTarget(): vscode.TextEditor | undefined {
  const active = vscode.window.activeTextEditor;
  if (active && active.document.uri.scheme !== "output") { return active; }
  if (lastScannedDocument) {
    const tracked = findEditorFor(lastScannedDocument);
    if (tracked) { return tracked; }
  }
  return undefined;
}

// Standalone rescan function so it can be called from both the
// panel callback and the command, without circular reference issues.
async function runRescan(): Promise<void> {
  const editor = resolveScanTarget();
  if (!editor) {
    vscode.window.showWarningMessage("ShieldPrompt: No active file to scan.");
    return;
  }
  lastScannedDocument = editor.document;
  const text       = editor.document.getText();
  const languageId = editor.document.languageId;
  const config     = vscode.workspace.getConfiguration("shieldprompt");
  const suppressed = config.get<string[]>("suppressedRules", []);

  const projectDeps      = await readProjectDeps();
  const astLayer         = config.get<boolean>("astLayer", true);
  const skipNoisyInTests = config.get<boolean>("skipNoisyInTests", true);
  const minSeverity      = config.get<"critical" | "warning">("minSeverity", "warning");
  const merged = analyseAllLayers(
    text, languageId, 0, suppressed, projectDeps.dependencies, loadedRules,
    { astLayer, skipNoisyInTests, minSeverity, filePath: editor.document.uri.fsPath }
  );

  const fp           = fingerprint(text);
  currentFindings    = merged;
  currentFingerprint = fp;
  updateStatusBar(merged);
  applyDecorations(editor, merged);
  panel.show(merged, fp);
}

export function activate(context: vscode.ExtensionContext): void {

  // Load JSON rule packs (language rules + framework rules) once at startup.
  // This is best-effort: if rules/ is missing the extension still runs with
  // the hardcoded rule set.
  void loadRules(context.extensionPath).then((rules) => {
    loadedRules = rules;
  }).catch(() => { /* silent — hardcoded rules still work */ });

  projectScanCache = new WorkspaceStateCache(context.workspaceState);

  // One-shot migration: move any legacy plaintext API key from settings.json
  // into the OS keychain via SecretStorage, then wipe the plaintext value.
  void migrateLegacyApiKey(context);

  panel = new ShieldPromptPanel(
    // onIgnore — called when user dismisses a finding from the panel
    (remainingFindings) => {
      currentFindings = remainingFindings;
      updateStatusBar(remainingFindings);
      // Refresh gutter/inline decorations so the ignored line is no longer
      // highlighted. Re-scan File will bring the finding back from source.
      if (lastScannedDocument) {
        const editor = findEditorFor(lastScannedDocument);
        if (editor) { applyDecorations(editor, remainingFindings); }
      }
    },
    // onRescan — called when user clicks Re-scan File in the panel
    () => { void runRescan(); },
    // onScanProject — called when user clicks Scan Project in the panel
    () => { void vscode.commands.executeCommand("shieldprompt.scanProject"); },
    // extensionUri — needed to load icon.png in the webview
    context.extensionUri,
    // secrets — backs the AI Fix API key (OS keychain-backed storage)
    context.secrets
  );

  // ── Status bar ──────────────────────────────────────────────────────────────
  statusBarItem = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Left, 100);
  statusBarItem.command = "shieldprompt.openPanel";
  statusBarItem.text    = "$(shield) ShieldPrompt: 0 issues";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // ── Commands ─────────────────────────────────────────────────────────────────

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.openPanel", () => {
      panel.show(currentFindings, currentFingerprint);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.resetSuppressions", () => {
      vscode.workspace.getConfiguration("shieldprompt")
        .update("suppressedRules", [], vscode.ConfigurationTarget.Workspace);
      vscode.window.showInformationMessage("ShieldPrompt: All rule suppressions have been reset.");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.toggleEnabled", () => {
      const config  = vscode.workspace.getConfiguration("shieldprompt");
      const current = config.get<boolean>("enabled", true);
      config.update("enabled", !current, vscode.ConfigurationTarget.Workspace);
      vscode.window.showInformationMessage(`ShieldPrompt: ${!current ? "Enabled" : "Disabled"}`);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.checkRuleUpdates", () => {
      vscode.window.showInformationMessage("ShieldPrompt: Rules are built-in and always up to date.");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.rescanFile", () => {
      void runRescan();
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.setAiFixApiKey", async () => {
      const key = await vscode.window.showInputBox({
        prompt: "Anthropic API key for ShieldPrompt AI Fix Suggestions",
        placeHolder: "sk-ant-…",
        password: true,
        ignoreFocusOut: true,
      });
      if (key === undefined) { return; } // user cancelled
      const trimmed = key.trim();
      if (!trimmed) {
        vscode.window.showWarningMessage("ShieldPrompt: No key entered — nothing saved.");
        return;
      }
      await context.secrets.store(AI_FIX_API_KEY_SECRET, trimmed);
      vscode.window.showInformationMessage("ShieldPrompt: AI Fix API key saved to the OS keychain.");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.clearAiFixApiKey", async () => {
      await context.secrets.delete(AI_FIX_API_KEY_SECRET);
      vscode.window.showInformationMessage("ShieldPrompt: AI Fix API key cleared.");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.clearProjectScanCache", async () => {
      await projectScanCache?.clear();
      vscode.window.showInformationMessage("ShieldPrompt: Project scan cache cleared.");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.scanProject", async () => {
      const folders = vscode.workspace.workspaceFolders;
      if (!folders) {
        vscode.window.showWarningMessage("ShieldPrompt: No workspace folder open.");
        return;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "ShieldPrompt: Scanning project…",
          cancellable: false,
        },
        async () => {
          const config     = vscode.workspace.getConfiguration("shieldprompt");
          const suppressed = config.get<string[]>("suppressedRules", []);
          const fileLimit        = config.get<number>("projectScanFileLimit", 1000);
          const astLayer         = config.get<boolean>("astLayer", true);
          const skipNoisyInTests = config.get<boolean>("skipNoisyInTests", true);
          const minSeverity      = config.get<"critical" | "warning">("minSeverity", "warning");
          const rootPath         = folders[0].uri.fsPath;
          const projectDeps      = await readProjectDeps();

          const results = await runProjectScan(rootPath, suppressed, loadedRules, {
            cache: projectScanCache,
            ruleVersion: hashRulePack(loadedRules),
            fileLimit,
            deps: projectDeps.dependencies,
            astLayer,
            skipNoisyInTests,
            minSeverity,
          });

          const scanPanel = vscode.window.createWebviewPanel(
            "shieldpromptProjectScan",
            "ShieldPrompt — Project Scan",
            vscode.ViewColumn.One,
            { enableScripts: true, localResourceRoots: [context.extensionUri] }
          );

          const totalFindings  = results.reduce((sum, r) => sum + r.findings.length, 0);
          const totalCritical  = results.reduce((sum, r) => sum + r.findings.filter((f) => f.severity === "critical").length, 0);
          const totalWarnings  = results.reduce((sum, r) => sum + r.findings.filter((f) => f.severity === "warning").length, 0);
          const filesWithIssues = results.filter((r) => r.findings.length > 0)
            .sort((a, b) => {
              const aCrit = a.findings.filter((f) => f.severity === "critical").length;
              const bCrit = b.findings.filter((f) => f.severity === "critical").length;
              if (aCrit !== bCrit) return bCrit - aCrit;
              return b.findings.length - a.findings.length;
            });
          const totalScanned   = results.length;

          const summaryText  = totalFindings === 0
            ? "No issues found across project"
            : `${totalFindings} issue${totalFindings === 1 ? "" : "s"} across ${filesWithIssues.length} file${filesWithIssues.length === 1 ? "" : "s"}`;

          const logoUri = scanPanel.webview.asWebviewUri(
            vscode.Uri.joinPath(context.extensionUri, "icon.png")
          ).toString();

          // Encode findings as JSON payload the webview can render + filter
          // client-side. Only the fields needed for rendering / open-file.
          const payload = filesWithIssues.map((r) => ({
            file:    r.file,
            relPath: path.relative(rootPath, r.file).replace(/\\/g, "/"),
            crit:    r.findings.filter((f) => f.severity === "critical").length,
            warn:    r.findings.filter((f) => f.severity === "warning").length,
            findings: r.findings.map((f) => ({
              line:     f.line,
              col:      f.col,
              severity: f.severity,
              ruleId:   f.ruleId,
              message:  f.message,
              framework: (f as Finding & { framework?: string }).framework,
            })),
          }));

          const scannedList = results.map((r) =>
            `<li>${escHtml(path.relative(rootPath, r.file).replace(/\\/g, "/"))}</li>`
          ).join("\n");

          scanPanel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  :root {
    --bg: var(--vscode-editor-background,#1e1e1e);
    --bg2: var(--vscode-sideBar-background,#252526);
    --bg3: var(--vscode-editorWidget-background,#2a2a2b);
    --fg: var(--vscode-editor-foreground,#ccc);
    --fg2: var(--vscode-descriptionForeground,#858585);
    --border: var(--vscode-panel-border,#333);
    --mono: var(--vscode-editor-font-family,'Cascadia Code',monospace);
    --radius: 6px;
    --accent: #3b82f6;
  }
  * { box-sizing: border-box; margin:0; padding:0; }
  body { font-family: var(--vscode-font-family,sans-serif); background: var(--bg); color: var(--fg); padding: 16px 20px 32px; font-size: 13px; }

  .header { display:flex; align-items:center; gap:10px; margin-bottom:14px; }
  .header-title { font-size:15px; font-weight:600; }
  .rescan-btn {
    margin-left:auto; padding: 5px 14px; border-radius: var(--radius);
    background: var(--accent); color: white; border: none; cursor: pointer; font-size: 12px; font-weight: 600;
  }
  .rescan-btn:hover { opacity: 0.85; }

  /* Stat cards row */
  .stats { display:grid; grid-template-columns: 1fr 1fr 1fr; gap:8px; margin-bottom:14px; }
  .stat-card {
    padding: 10px 12px; background: var(--bg2); border-radius: var(--radius);
    border: 0.5px solid var(--border);
  }
  .stat-num  { font-size:18px; font-weight:700; line-height:1.1; }
  .stat-num.crit { color:#ff6b6b; }
  .stat-num.warn { color:#ffa500; }
  .stat-num.ok   { color:#22c55e; }
  .stat-label { font-size:11px; color:var(--fg2); margin-top:2px; letter-spacing:0.02em; }

  /* Filter bar */
  .filter-bar { display:flex; gap:8px; align-items:center; margin-bottom:12px; flex-wrap: wrap; }
  .filter-btn {
    padding: 4px 10px; border-radius: 999px; cursor:pointer;
    background: var(--bg2); border: 0.5px solid var(--border);
    color: var(--fg); font-size: 11px; font-weight: 600;
  }
  .filter-btn:hover { background: var(--bg3); }
  .filter-btn.active { background: var(--accent); color: white; border-color: var(--accent); }
  .search-input {
    flex:1; min-width: 140px; max-width: 320px;
    padding: 5px 10px; font-size:12px; background: var(--bg2);
    color: var(--fg); border: 0.5px solid var(--border); border-radius: var(--radius);
    outline: none;
  }
  .search-input:focus { border-color: var(--accent); }

  /* File rows — collapsible */
  .file-row {
    background:var(--bg2); border-radius:var(--radius); margin-bottom:6px;
    border: 0.5px solid var(--border); overflow:hidden;
  }
  .file-header {
    display:flex; align-items:center; gap:8px;
    padding:10px 14px; cursor:pointer; user-select:none;
  }
  .file-header:hover { background: var(--bg3); }
  .file-path { font-family:var(--mono); font-size:12px; flex:1; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .badge { padding:2px 9px; border-radius:20px; font-size:11px; font-weight:700; flex-shrink:0; }
  .badge.crit { background:rgba(255,107,107,0.15); color:#ff6b6b; }
  .badge.warn { background:rgba(255,165,0,0.15);   color:#ffa500; }
  .chevron { font-size:10px; opacity:0.5; flex-shrink:0; transition: transform 0.15s; }
  .file-row.open .chevron { transform: rotate(90deg); }
  .file-findings {
    display: none;
    border-top: 0.5px solid var(--border);
    padding: 4px 0;
  }
  .file-row.open .file-findings { display: block; }
  .finding-row {
    display:flex; align-items:flex-start; gap:10px;
    padding: 7px 14px 7px 24px; cursor:pointer; font-size: 12px;
  }
  .finding-row:hover { background: var(--bg3); }
  .sev-dot {
    display:inline-block; width:8px; height:8px; border-radius:50%;
    flex-shrink:0; margin-top:5px;
  }
  .sev-dot.critical { background: #ff6b6b; }
  .sev-dot.warning  { background: #ffa500; }
  .finding-main { flex:1; min-width:0; }
  .finding-message { color: var(--fg); }
  .finding-meta    { color: var(--fg2); font-size: 11px; margin-top: 2px; font-family: var(--mono); }
  .finding-meta .ruleid { color: var(--fg); opacity:0.75; }
  .finding-meta .fw     { margin-left:6px; padding: 0 6px; background: rgba(100,100,255,0.15); color:#9090ff; border-radius: 4px; font-size:10px; }

  .empty { color:var(--fg2); font-size:13px; padding: 16px 4px; }
  details { margin-top:16px; }
  details summary { cursor:pointer; color:var(--fg2); font-size:12px; padding:6px 0; }
  details ul { padding: 8px 0 0 20px; font-family:var(--mono); font-size:11px; color:var(--fg2); line-height:1.8; }
</style>
</head>
<body>
  <div class="header">
    <img src="${logoUri}" width="24" height="24" style="border-radius:4px;" />
    <span class="header-title">ShieldPrompt — Project Scan</span>
    <button class="rescan-btn" onclick="rescan()">▶ Re-scan</button>
  </div>

  <div class="stats">
    <div class="stat-card"><div class="stat-num ${totalCritical > 0 ? "crit" : "ok"}">${totalCritical}</div><div class="stat-label">CRITICAL</div></div>
    <div class="stat-card"><div class="stat-num ${totalWarnings > 0 ? "warn" : "ok"}">${totalWarnings}</div><div class="stat-label">WARNINGS</div></div>
    <div class="stat-card"><div class="stat-num">${totalScanned}</div><div class="stat-label">FILES SCANNED</div></div>
  </div>

  <div style="font-size:12px; color:var(--fg2); margin-bottom:14px;">${escHtml(summaryText)}</div>

  ${filesWithIssues.length === 0 ? `<div class="empty">No issues found in any scanned file.</div>` : `
  <div class="filter-bar">
    <button class="filter-btn active" data-filter="all">All</button>
    <button class="filter-btn" data-filter="critical">Critical only</button>
    <button class="filter-btn" data-filter="warning">Warnings only</button>
    <input class="search-input" type="text" placeholder="Filter by file path…" id="search"/>
    <button class="filter-btn" onclick="expandAll(true)">Expand all</button>
    <button class="filter-btn" onclick="expandAll(false)">Collapse all</button>
  </div>
  <div id="file-list"></div>
  `}

  <details>
    <summary>▶ Files scanned (${totalScanned})</summary>
    <ul>${scannedList}</ul>
  </details>

  <script>
    const vscode = acquireVsCodeApi();
    const files  = ${JSON.stringify(payload)};
    let currentFilter = "all";
    let currentSearch = "";

    function escHtml(s) {
      return String(s).replace(/[&<>"']/g, (c) => ({ "&":"&amp;","<":"&lt;",">":"&gt;","\\"":"&quot;","'":"&#39;" }[c]));
    }

    function rescan()   { vscode.postMessage({ type: 'rescan' }); }
    function openFile(file, line, col) {
      vscode.postMessage({ type: 'openFile', file, line, col });
    }

    function renderFindings(findings) {
      return findings.map((f, i) => {
        const fwBadge = f.framework ? '<span class="fw">' + escHtml(f.framework) + '</span>' : '';
        return (
          '<div class="finding-row" data-idx="' + i + '" data-sev="' + f.severity + '">' +
            '<span class="sev-dot ' + f.severity + '"></span>' +
            '<div class="finding-main">' +
              '<div class="finding-message">' + escHtml(f.message || f.ruleId) + '</div>' +
              '<div class="finding-meta">line ' + (f.line + 1) + ' · <span class="ruleid">' + escHtml(f.ruleId) + '</span>' + fwBadge + '</div>' +
            '</div>' +
          '</div>'
        );
      }).join('');
    }

    function render() {
      const filtered = files.filter((f) => {
        if (currentSearch && !f.relPath.toLowerCase().includes(currentSearch.toLowerCase())) return false;
        if (currentFilter === "critical") return f.crit > 0;
        if (currentFilter === "warning")  return f.warn > 0;
        return true;
      });

      if (filtered.length === 0) {
        document.getElementById("file-list").innerHTML = '<div class="empty">No files match the current filter.</div>';
        return;
      }

      document.getElementById("file-list").innerHTML = filtered.map((f, i) => {
        const vis = f.findings.filter((x) => {
          if (currentFilter === "critical") return x.severity === "critical";
          if (currentFilter === "warning")  return x.severity === "warning";
          return true;
        });
        const badges = [
          f.crit > 0 ? '<span class="badge crit">' + f.crit + ' crit</span>' : '',
          f.warn > 0 ? '<span class="badge warn">' + f.warn + ' warn</span>' : '',
        ].filter(Boolean).join('');
        return (
          '<div class="file-row" data-file="' + escHtml(f.file) + '">' +
            '<div class="file-header" onclick="toggleFile(this.parentElement)">' +
              '<span class="file-path">' + escHtml(f.relPath) + '</span>' +
              badges +
              '<span class="chevron">▶</span>' +
            '</div>' +
            '<div class="file-findings" data-findings=\\'' + JSON.stringify(vis).replace(/'/g, "&#39;") + '\\'>' +
              renderFindings(vis) +
            '</div>' +
          '</div>'
        );
      }).join('');

      // Wire per-finding click handlers
      for (const row of document.querySelectorAll(".file-row")) {
        const fileAttr = row.getAttribute("data-file");
        row.querySelectorAll(".finding-row").forEach((fr) => {
          fr.addEventListener("click", (e) => {
            e.stopPropagation();
            const idx = parseInt(fr.getAttribute("data-idx"), 10);
            const data = JSON.parse(fr.parentElement.getAttribute("data-findings").replace(/&#39;/g, "'"));
            const f = data[idx];
            openFile(fileAttr, f.line, f.col || 0);
          });
        });
      }
    }

    function toggleFile(row) {
      row.classList.toggle("open");
    }

    function expandAll(open) {
      for (const row of document.querySelectorAll(".file-row")) {
        if (open) row.classList.add("open"); else row.classList.remove("open");
      }
    }

    document.querySelectorAll(".filter-btn[data-filter]").forEach((btn) => {
      btn.addEventListener("click", () => {
        document.querySelectorAll(".filter-btn[data-filter]").forEach((b) => b.classList.remove("active"));
        btn.classList.add("active");
        currentFilter = btn.getAttribute("data-filter");
        render();
      });
    });
    const searchInput = document.getElementById("search");
    if (searchInput) {
      searchInput.addEventListener("input", (e) => {
        currentSearch = e.target.value;
        render();
      });
    }

    render();
  </script>
</body>
</html>`;

          scanPanel.webview.onDidReceiveMessage(async (msg) => {
            if (msg.type === "rescan") {
              void vscode.commands.executeCommand("shieldprompt.scanProject");
              scanPanel.dispose();
            } else if (msg.type === "openFile" && typeof msg.file === "string") {
              try {
                const uri    = vscode.Uri.file(msg.file);
                const doc    = await vscode.workspace.openTextDocument(uri);
                const line   = Math.max(0, Number(msg.line) || 0);
                const col    = Math.max(0, Number(msg.col)  || 0);
                const pos    = new vscode.Position(line, col);
                const editor = await vscode.window.showTextDocument(doc, { viewColumn: vscode.ViewColumn.Beside, selection: new vscode.Range(pos, pos) });
                editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
              } catch {
                vscode.window.showErrorMessage(`ShieldPrompt: Could not open ${msg.file}`);
              }
            }
          });
        }
      );
    })
  );

  // ── Paste handler ────────────────────────────────────────────────────────────
  const pasteDisposable = onPaste((text, document, range) => {
    const config     = vscode.workspace.getConfiguration("shieldprompt");
    const languageId = document.languageId;
    lastScannedDocument = document;

    void readProjectDeps().then((projectDeps) => {
      const suppressed       = config.get<string[]>("suppressedRules", []);
      const astLayer         = config.get<boolean>("astLayer", true);
      const skipNoisyInTests = config.get<boolean>("skipNoisyInTests", true);
      const minSeverity      = config.get<"critical" | "warning">("minSeverity", "warning");
      const merged = analyseAllLayers(
        text, languageId, range.start.line, suppressed, projectDeps.dependencies, loadedRules,
        { astLayer, skipNoisyInTests, minSeverity, filePath: document.uri.fsPath }
      );

      const fp           = fingerprint(text);
      currentFindings    = merged;
      currentFingerprint = fp;
      updateStatusBar(merged);

      const editor = vscode.window.activeTextEditor;
      if (editor && editor.document === document) {
        applyDecorations(editor, merged);
      }

      if (merged.length > 0) { panel.show(merged, fp); }
    });
  });

  context.subscriptions.push(pasteDisposable);
  context.subscriptions.push(createEditClearListener());
  context.subscriptions.push({
    dispose(): void { panel.dispose(); disposeDecorationTypes(); },
  });
}

function updateStatusBar(findings: Finding[]): void {
  const count       = findings.length;
  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasWarning  = findings.some((f) => f.severity === "warning");

  statusBarItem.text = `$(shield) ShieldPrompt: ${count} issue${count !== 1 ? "s" : ""}`;

  if (hasCritical) {
    statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.errorBackground");
  } else if (hasWarning) {
    statusBarItem.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
  } else {
    statusBarItem.backgroundColor = undefined;
  }
}

function escHtml(text: string): string {
  return text.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

// Legacy migration: pre-1.0.3 stored the Anthropic key in settings.json under
// `shieldprompt.aiFixApiKey` (plaintext, syncable, world-readable to other
// extensions). Move any existing value into SecretStorage and wipe the
// plaintext setting. Runs once per install; silently no-ops afterwards.
async function migrateLegacyApiKey(context: vscode.ExtensionContext): Promise<void> {
  try {
    const config = vscode.workspace.getConfiguration("shieldprompt");
    const legacy = (config.get<string>("aiFixApiKey", "") ?? "").trim();
    if (!legacy) { return; }

    const existing = await context.secrets.get(AI_FIX_API_KEY_SECRET);
    if (!existing) { await context.secrets.store(AI_FIX_API_KEY_SECRET, legacy); }

    // Wipe from every scope where it might live. Each update() can throw if
    // the scope has no value — swallow and keep going.
    const scopes: vscode.ConfigurationTarget[] = [
      vscode.ConfigurationTarget.Global,
      vscode.ConfigurationTarget.Workspace,
      vscode.ConfigurationTarget.WorkspaceFolder,
    ];
    for (const scope of scopes) {
      try { await config.update("aiFixApiKey", undefined, scope); } catch { /* ignore */ }
    }

    vscode.window.showInformationMessage(
      "ShieldPrompt: your AI Fix API key has been moved from settings.json to the OS keychain."
    );
  } catch {
    // Migration is best-effort. If it fails the user can re-enter via the
    // "Set AI Fix API key" command.
  }
}

export function deactivate(): void {
  // Cleanup handled by disposables
}