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

  const projectDeps = await readProjectDeps();
  const merged = analyseAllLayers(
    text, languageId, 0, suppressed, projectDeps.dependencies, loadedRules
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
          const fileLimit  = config.get<number>("projectScanFileLimit", 1000);
          const rootPath   = folders[0].uri.fsPath;
          const projectDeps = await readProjectDeps();

          const results = await runProjectScan(rootPath, suppressed, loadedRules, {
            cache: projectScanCache,
            ruleVersion: hashRulePack(loadedRules),
            fileLimit,
            deps: projectDeps.dependencies,
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
          const filesWithIssues = results.filter((r) => r.findings.length > 0);
          const totalScanned   = results.length;

          const summaryColor = totalCritical > 0 ? "#ff6b6b" : totalWarnings > 0 ? "#ffa500" : "#22c55e";
          const summaryText  = totalFindings === 0
            ? "✅ No issues found across project"
            : `${totalFindings} issue${totalFindings > 1 ? "s" : ""} in ${filesWithIssues.length} file${filesWithIssues.length > 1 ? "s" : ""} — ${totalCritical} critical, ${totalWarnings} warnings`;

          const logoUri = scanPanel.webview.asWebviewUri(
            vscode.Uri.joinPath(context.extensionUri, "icon.png")
          ).toString();

          const fileRows = filesWithIssues.map((r) => {
            const relPath = path.relative(rootPath, r.file).replace(/\\/g, "/");
            const crit    = r.findings.filter((f) => f.severity === "critical").length;
            const warn    = r.findings.filter((f) => f.severity === "warning").length;
            const badge   = crit > 0
              ? `<span class="badge crit">${crit} crit</span>`
              : `<span class="badge warn">${warn} warn</span>`;
            return `<div class="file-row"><span class="file-path">${escHtml(relPath)}</span>${badge}<span class="arrow">▶</span></div>`;
          }).join("\n");

          const scannedList = results.map((r) => {
            const relPath = path.relative(rootPath, r.file).replace(/\\/g, "/");
            return `<li>${escHtml(relPath)}</li>`;
          }).join("\n");

          scanPanel.webview.html = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<style>
  :root {
    --bg: var(--vscode-editor-background,#1e1e1e);
    --bg2: var(--vscode-sideBar-background,#252526);
    --fg: var(--vscode-editor-foreground,#ccc);
    --fg2: var(--vscode-descriptionForeground,#858585);
    --border: var(--vscode-panel-border,#333);
    --mono: var(--vscode-editor-font-family,'Cascadia Code',monospace);
    --radius: 6px;
  }
  * { box-sizing: border-box; margin:0; padding:0; }
  body { font-family: var(--vscode-font-family,sans-serif); background: var(--bg); color: var(--fg); padding: 16px 20px 32px; font-size: 13px; }
  .header { display:flex; align-items:center; gap:10px; margin-bottom:16px; }
  .header-title { font-size:15px; font-weight:600; }
  .rescan-btn {
    margin-left:auto; padding: 5px 14px; border-radius: var(--radius);
    background: #3b82f6; color: white; border: none; cursor: pointer; font-size: 12px; font-weight: 600;
  }
  .rescan-btn:hover { opacity: 0.85; }
  .summary { font-size:14px; font-weight:600; color:${summaryColor}; margin-bottom:4px; }
  .sub { font-size:12px; color:var(--fg2); margin-bottom:16px; }
  .file-row {
    display:flex; align-items:center; gap:8px;
    padding:10px 14px; background:var(--bg2);
    border-radius:var(--radius); margin-bottom:6px;
    border: 0.5px solid var(--border);
  }
  .file-path { font-family:var(--mono); font-size:12px; flex:1; }
  .badge { padding:2px 9px; border-radius:20px; font-size:11px; font-weight:700; flex-shrink:0; }
  .badge.crit { background:rgba(255,107,107,0.15); color:#ff6b6b; }
  .badge.warn { background:rgba(255,165,0,0.15);   color:#ffa500; }
  .arrow { font-size:10px; opacity:0.4; flex-shrink:0; }
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
  <div class="summary">${summaryText}</div>
  <div class="sub">Scanned ${totalScanned} file${totalScanned !== 1 ? "s" : ""}</div>
  ${fileRows || `<div style="color:var(--fg2);font-size:13px;padding-top:8px;">No issues found ✅</div>`}
  <details>
    <summary>▶ Files scanned (${totalScanned})</summary>
    <ul>${scannedList}</ul>
  </details>
  <script>
    var vscode = acquireVsCodeApi();
    function rescan() { vscode.postMessage({ type: 'rescan' }); }
  </script>
</body>
</html>`;

          scanPanel.webview.onDidReceiveMessage((msg) => {
            if (msg.type === "rescan") {
              void vscode.commands.executeCommand("shieldprompt.scanProject");
              scanPanel.dispose();
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
      const suppressed = config.get<string[]>("suppressedRules", []);
      const merged = analyseAllLayers(
        text, languageId, range.start.line, suppressed, projectDeps.dependencies, loadedRules
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