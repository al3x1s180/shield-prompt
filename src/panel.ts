import * as vscode from "vscode";
import * as https from "https";
import { Finding, AIFingerprint, CVERef, RULES_COUNT } from "./analyser";
import { SEMANTIC_RULES_COUNT } from "./semanticAnalyser";

interface IgnoreMessage  { type: "ignoreThis"; findingIndex: number; }
interface OpenCveMessage { type: "openCve"; url: string; }
interface RescanMessage  { type: "rescanFile"; }
interface AiFixMessage   { type: "aiFixSuggestions"; }
interface CloseAiMessage { type: "closeAiFix"; }
interface ScanProjMsg    { type: "scanProject"; }

type WebviewMessage =
  | IgnoreMessage | OpenCveMessage | RescanMessage
  | AiFixMessage  | CloseAiMessage | ScanProjMsg;

const HIGH_CONFIDENCE_RULES = new Set([
  "eval-external", "hardcoded-secret", "shell-injection", "pickle-loads",
]);

function confidenceLabel(f: Finding): { label: string; cls: string } {
  if (f.severity === "critical" && HIGH_CONFIDENCE_RULES.has(f.ruleId)) {
    return { label: "high confidence", cls: "conf-high" };
  }
  if (f.severity === "warning") { return { label: "review", cls: "conf-review" }; }
  return { label: "medium confidence", cls: "conf-med" };
}

function renderCveBadges(cves: CVERef[]): string {
  if (!cves || cves.length === 0) { return ""; }
  return cves.map((c) =>
    `<button class="cve-badge" onclick="openCve('${escapeHtml(c.url)}')" title="${escapeHtml(c.description)}">${escapeHtml(c.id)}</button>`
  ).join(" ");
}

function renderFrameworkBadge(framework?: string): string {
  if (!framework) { return ""; }
  return `<span class="fw-badge">${escapeHtml(framework)}</span>`;
}

export const AI_FIX_API_KEY_SECRET = "shieldprompt.aiFixApiKey";

export class ShieldPromptPanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];
  private _currentFindings: Finding[] = [];
  private _currentFp: AIFingerprint = { isAI: false, confidence: "low" };
  private _onIgnore?: (findings: Finding[]) => void;
  private _onRescan?: () => void;
  private _onScanProject?: () => void;
  private _extensionUri: vscode.Uri | undefined;
  private _secrets: vscode.SecretStorage | undefined;

  public constructor(
    onIgnore?: (findings: Finding[]) => void,
    onRescan?: () => void,
    onScanProject?: () => void,
    extensionUri?: vscode.Uri,
    secrets?: vscode.SecretStorage
  ) {
    this._onIgnore      = onIgnore;
    this._onRescan      = onRescan;
    this._onScanProject = onScanProject;
    this._extensionUri  = extensionUri;
    this._secrets       = secrets;
  }

  public show(findings: Finding[], fp: AIFingerprint): void {
    this._currentFindings = findings;
    this._currentFp       = fp;

    if (this.panel) {
      this.panel.webview.html = this.buildHtml(findings, fp);
      // Reveal without a column argument so the panel stays in the column
      // it's already in — passing ViewColumn.Beside when the panel itself
      // is focused would shove it into a fresh column beside itself.
      this.panel.reveal(undefined, true);
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      "shieldpromptPanel",
      "ShieldPrompt",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: this._extensionUri ? [this._extensionUri] : undefined,
      }
    );

    this.panel.webview.html = this.buildHtml(findings, fp);

    this.panel.webview.onDidReceiveMessage(async (message: WebviewMessage) => {

      if (message.type === "openCve") {
        await vscode.env.openExternal(vscode.Uri.parse(message.url));

      } else if (message.type === "ignoreThis") {
        // Hide the finding from the panel only — the file is left untouched.
        // Re-scan File or pasting the same code again will bring it back.
        if (!this._currentFindings[message.findingIndex]) { return; }
        this._currentFindings = this._currentFindings.filter((_, i) => i !== message.findingIndex);
        if (this.panel) {
          this.panel.webview.html = this.buildHtml(this._currentFindings, this._currentFp);
        }
        this._onIgnore?.(this._currentFindings);

      } else if (message.type === "rescanFile") {
        this._onRescan?.();

      } else if (message.type === "scanProject") {
        this._onScanProject?.();

      } else if (message.type === "aiFixSuggestions") {
        await this.handleAiFix();

      } else if (message.type === "closeAiFix") {
        if (this.panel) {
          this.panel.webview.html = this.buildHtml(this._currentFindings, this._currentFp);
        }
      }
    }, null, this.disposables);

    this.panel.onDidDispose(() => {
      this.panel = undefined;
      this.disposables.forEach((d) => d.dispose());
      this.disposables = [];
    }, null, this.disposables);
  }

  private async handleAiFix(): Promise<void> {
    const config   = vscode.workspace.getConfiguration("shieldprompt");
    const model    = config.get<string>("aiFixModel", "claude-haiku-4-5-20251001");
    const apiKey   = (await this._secrets?.get(AI_FIX_API_KEY_SECRET))?.trim() ?? "";
    const findings = this._currentFindings;
    if (findings.length === 0) { return; }

    const editor    = vscode.window.activeTextEditor;
    const codeLines = editor ? editor.document.getText().split("\n") : [];

    const findingContext = findings.map((f) => {
      const lineNum = f.line + 1;
      const snippet = codeLines.slice(Math.max(0, f.line - 1), f.line + 3).join("\n");
      return `Line ${lineNum} [${f.ruleId}]: ${f.message}\nCode:\n${snippet}`;
    }).join("\n\n");

    const prompt = `You are a security expert. The following security vulnerabilities were found in code. For each finding, provide a concise fix with corrected code where applicable.\n\n${findingContext}\n\nProvide fixes in order, referencing the line number. Be concise and practical.`;

    if (!apiKey) {
      // No key — copy prompt to clipboard, offer to set key inline.
      await vscode.env.clipboard.writeText(prompt);
      const setAction = "Set API Key…";
      void vscode.window
        .showInformationMessage(
          "ShieldPrompt: No API key set — fix prompt copied to clipboard.",
          setAction
        )
        .then((choice) => {
          if (choice === setAction) {
            void vscode.commands.executeCommand("shieldprompt.setAiFixApiKey");
          }
        });
      const fallback =
        "No Anthropic API key configured.\n\n" +
        "The fix prompt has been copied to your clipboard.\n" +
        "Paste it into any AI assistant (ChatGPT, Claude, Gemini…) to get fix suggestions.\n\n" +
        "To enable AI fixes directly here, run the command:\n" +
        "  “ShieldPrompt: Set AI Fix API key”\n" +
        "(Cmd/Ctrl+Shift+P) — your key is stored in the OS keychain.";
      if (this.panel) {
        this.panel.webview.html = this.buildHtml(findings, this._currentFp, { aiFixText: fallback });
      }
      return;
    }

    // Show loading state
    if (this.panel) {
      this.panel.webview.html = this.buildHtml(findings, this._currentFp, { loading: true });
    }

    try {
      const text = await callAnthropic(apiKey, model, prompt);
      if (this.panel) {
        this.panel.webview.html = this.buildHtml(findings, this._currentFp, { aiFixText: text });
      }
    } catch (err) {
      vscode.window.showErrorMessage(`ShieldPrompt: AI fix failed — ${String(err)}`);
      if (this.panel) {
        this.panel.webview.html = this.buildHtml(findings, this._currentFp);
      }
    }
  }

  public reveal(): void {
    if (this.panel) { this.panel.reveal(vscode.ViewColumn.Beside, true); }
  }

  public dispose(): void {
    if (this.panel) { this.panel.dispose(); }
  }

  private getLogoUri(): string {
    if (this._extensionUri && this.panel) {
      const logoPath = vscode.Uri.joinPath(this._extensionUri, "icon.png");
      return this.panel.webview.asWebviewUri(logoPath).toString();
    }
    return "";
  }

  private buildHtml(
    findings: Finding[],
    fp: AIFingerprint,
    opts: { loading?: boolean; aiFixText?: string } = {}
  ): string {
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const warningCount  = findings.filter((f) => f.severity === "warning").length;
    const infoCount     = findings.filter((f) => f.severity === "info").length;
    const total         = findings.length;

    const summaryParts: string[] = [];
    if (criticalCount > 0) { summaryParts.push(`${criticalCount} critical`); }
    if (warningCount  > 0) { summaryParts.push(`${warningCount} warning${warningCount > 1 ? "s" : ""}`); }
    if (infoCount     > 0) { summaryParts.push(`${infoCount} info`); }

    const summaryText = total === 0
      ? "No issues found ✅"
      : `${total} issue${total > 1 ? "s" : ""} — ${summaryParts.join(", ")}`;

    const fpBadge = fp.confidence === "high" || fp.confidence === "medium"
      ? `<div class="ai-badge ${fp.confidence}">
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>
          AI-generated code detected (${fp.confidence} confidence)
        </div>`
      : "";

    const rulesCount = RULES_COUNT + SEMANTIC_RULES_COUNT;
    const logoUri    = this.getLogoUri();
    const logoHtml   = logoUri
      ? `<img src="${logoUri}" width="26" height="26" style="border-radius:4px;flex-shrink:0;" />`
      : `<svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M12 2L3 6.5V12c0 5 3.8 9.7 9 10.9C17.2 21.7 21 17 21 12V6.5L12 2Z" fill="#3b82f6"/><path d="M9 12l2 2 4-4" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>`;

    const maxVisible      = opts.aiFixText || opts.loading ? 3 : findings.length;
    const visibleFindings = findings.slice(0, maxVisible);
    const hiddenCount     = findings.length - visibleFindings.length;

    const findingsList = visibleFindings.map((f, i) => {
      const conf      = confidenceLabel(f);
      const cveBadges = renderCveBadges(f.cves ?? []);
      const fwBadge   = renderFrameworkBadge(f.framework);
      return `
      <div class="finding ${f.severity}">
        <div class="finding-header" onclick="toggle(${i})">
          <span class="sev-pill ${f.severity}">${severityLabel(f.severity)}</span>
          <span class="confidence ${conf.cls}">${conf.label}</span>
          ${fwBadge}
          <span class="finding-line">L${f.line + 1}</span>
          <span class="finding-rule">${escapeHtml(f.ruleId)}</span>
          <span class="finding-msg">${escapeHtml(f.message)}</span>
          <span class="chevron" id="chevron-${i}">▶</span>
        </div>
        <div class="finding-detail" id="detail-${i}" style="display:none;">
          <p>${escapeHtml(f.detail)}</p>
          ${cveBadges ? `<div class="cve-row"><span class="cve-label">References:</span>${cveBadges}</div>` : ""}
          <button class="ignore-btn" onclick="ignoreThis(${i})">Ignore on this line</button>
        </div>
      </div>`;
    }).join("\n");

    const hiddenBanner = hiddenCount > 0
      ? `<div class="hidden-banner">+ ${hiddenCount} more finding${hiddenCount > 1 ? "s" : ""}</div>`
      : "";

    let aiFixPanel = "";
    if (opts.loading) {
      aiFixPanel = `
        <div class="ai-fix-panel">
          <div class="ai-fix-header">
            <span class="ai-fix-title">⇒ AI Fix Suggestions</span>
          </div>
          <div class="ai-fix-loading">Analysing findings…</div>
        </div>`;
    } else if (opts.aiFixText) {
      aiFixPanel = `
        <div class="ai-fix-panel">
          <div class="ai-fix-header">
            <span class="ai-fix-title">⇒ AI Fix Suggestions</span>
            <button class="ai-fix-close" onclick="closeAiFix()">✕</button>
          </div>
          <pre class="ai-fix-body">${escapeHtml(opts.aiFixText)}</pre>
        </div>`;
    }

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg:      var(--vscode-editor-background, #1e1e1e);
      --bg2:     var(--vscode-sideBar-background, #252526);
      --fg:      var(--vscode-editor-foreground, #cccccc);
      --fg2:     var(--vscode-descriptionForeground, #858585);
      --border:  var(--vscode-panel-border, #333333);
      --crit-fg: #ff6b6b;
      --crit-bg: rgba(255,107,107,0.1);
      --warn-fg: #ffa500;
      --warn-bg: rgba(255,165,0,0.1);
      --info-fg: #4fc3f7;
      --info-bg: rgba(79,195,247,0.08);
      --blue:    #3b82f6;
      --green:   #22c55e;
      --radius:  6px;
      --font:    var(--vscode-font-family, -apple-system, BlinkMacSystemFont, sans-serif);
      --mono:    var(--vscode-editor-font-family, 'Cascadia Code', 'Fira Code', monospace);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--font);
      font-size: var(--vscode-font-size, 13px);
      color: var(--fg);
      background: var(--bg);
      padding: 14px 16px 24px;
      line-height: 1.5;
    }
    .header { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
    .header-title { font-size: 15px; font-weight: 600; letter-spacing: -0.01em; }
    .header-actions { margin-left: auto; }
    .btn {
      display: inline-flex; align-items: center; gap: 5px;
      padding: 5px 12px; border-radius: var(--radius);
      font-size: 12px; font-weight: 500; cursor: pointer;
      border: 1px solid; transition: opacity 0.12s;
    }
    .btn:hover { opacity: 0.82; }
    .btn-rescan { background: transparent; color: #60a5fa; border-color: rgba(96,165,250,0.5); }
    .btn-ai     { background: rgba(34,197,94,0.12); color: var(--green); border-color: rgba(34,197,94,0.5); }
    .btn-scan   { background: transparent; color: var(--fg2); border-color: var(--border); font-size: 11px; }
    .action-row { display: flex; gap: 8px; margin-bottom: 12px; }
    .ai-badge {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 5px 11px; border-radius: 20px;
      font-size: 12px; font-weight: 600; margin-bottom: 12px; border: 1px solid;
    }
    .ai-badge.high   { background: var(--crit-bg); border-color: var(--crit-fg); color: var(--crit-fg); }
    .ai-badge.medium { background: var(--warn-bg); border-color: var(--warn-fg); color: var(--warn-fg); }
    .summary {
      background: var(--bg2); border-left: 3px solid var(--blue);
      border-radius: 0 var(--radius) var(--radius) 0;
      padding: 9px 13px; margin-bottom: 12px; font-size: 13px;
    }
    .finding { border: 0.5px solid var(--border); border-radius: var(--radius); margin-bottom: 6px; overflow: hidden; }
    .finding.critical { border-left: 3px solid var(--crit-fg); }
    .finding.warning  { border-left: 3px solid var(--warn-fg); }
    .finding.info     { border-left: 3px solid var(--info-fg); }
    .finding-header {
      display: flex; align-items: center; gap: 7px;
      padding: 8px 11px; cursor: pointer; user-select: none;
    }
    .finding-header:hover { background: rgba(255,255,255,0.03); }
    .sev-pill {
      padding: 2px 7px; border-radius: 20px; font-size: 10px;
      font-weight: 700; text-transform: uppercase; letter-spacing: 0.04em; flex-shrink: 0;
    }
    .sev-pill.critical { background: var(--crit-bg); color: var(--crit-fg); }
    .sev-pill.warning  { background: var(--warn-bg); color: var(--warn-fg); }
    .sev-pill.info     { background: var(--info-bg); color: var(--info-fg); }
    .confidence  { font-size: 10px; opacity: 0.6; flex-shrink: 0; }
    .fw-badge {
      padding: 1px 7px; border-radius: 4px; font-size: 10px; font-weight: 600;
      background: rgba(139,92,246,0.2); color: #a78bfa;
      border: 1px solid rgba(139,92,246,0.4); flex-shrink: 0;
    }
    .finding-line { font-size: 11px; color: var(--fg2); flex-shrink: 0; font-family: var(--mono); }
    .finding-rule { font-size: 11px; font-family: var(--mono); opacity: 0.55; flex-shrink: 0; }
    .finding-msg  { flex: 1; font-size: 13px; }
    .chevron { font-size: 10px; opacity: 0.4; flex-shrink: 0; transition: transform 0.15s; }
    .chevron.open { transform: rotate(90deg); }
    .finding-detail { padding: 10px 14px 13px; background: var(--bg2); border-top: 0.5px solid var(--border); }
    .finding-detail p { margin-bottom: 9px; color: var(--fg2); font-size: 12px; line-height: 1.6; }
    .cve-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; margin-bottom: 10px; }
    .cve-label { font-size: 11px; color: var(--fg2); flex-shrink: 0; }
    .cve-badge {
      display: inline-flex; align-items: center; padding: 2px 8px;
      background: rgba(59,130,246,0.12); border: 1px solid rgba(59,130,246,0.4);
      border-radius: 4px; color: #60a5fa; font-size: 11px;
      font-family: var(--mono); font-weight: 600; cursor: pointer;
      transition: background 0.12s, border-color 0.12s;
    }
    .cve-badge:hover { background: rgba(59,130,246,0.22); border-color: rgba(59,130,246,0.7); }
    .ignore-btn {
      padding: 4px 11px; background: transparent; color: var(--fg2);
      border: 1px solid var(--border); border-radius: 4px; cursor: pointer; font-size: 12px;
      transition: border-color 0.12s, color 0.12s;
    }
    .ignore-btn:hover { border-color: var(--fg); color: var(--fg); }
    .hidden-banner { font-size: 12px; color: var(--fg2); padding: 6px 2px; opacity: 0.7; }
    .ai-fix-panel {
      margin-top: 14px; border: 1px solid rgba(34,197,94,0.3);
      border-radius: var(--radius); background: rgba(34,197,94,0.04); overflow: hidden;
    }
    .ai-fix-header {
      display: flex; align-items: center; justify-content: space-between;
      padding: 8px 12px; border-bottom: 1px solid rgba(34,197,94,0.2);
    }
    .ai-fix-title { font-size: 13px; font-weight: 600; color: var(--green); }
    .ai-fix-close {
      background: transparent; border: none; color: var(--fg2);
      cursor: pointer; font-size: 14px; padding: 0 4px;
    }
    .ai-fix-close:hover { color: var(--fg); }
    .ai-fix-body {
      padding: 14px; font-family: var(--mono); font-size: 12px;
      line-height: 1.7; white-space: pre-wrap; color: var(--fg);
      max-height: 420px; overflow-y: auto;
    }
    .ai-fix-loading { padding: 20px; text-align: center; color: var(--fg2); font-size: 13px; }
    .empty { text-align: center; padding: 44px 20px; color: var(--fg2); }
    .empty-icon { font-size: 36px; margin-bottom: 10px; }
    .empty p { font-size: 14px; }
    .empty-sub { font-size: 12px; opacity: 0.5; margin-top: 6px; }
  </style>
</head>
<body>
  <div class="header">
    ${logoHtml}
    <span class="header-title">ShieldPrompt</span>
    <div class="header-actions">
      <button class="btn btn-scan" onclick="scanProject()">● Scan Project</button>
    </div>
  </div>

  <div class="action-row">
    <button class="btn btn-rescan" onclick="rescanFile()">↺ Re-scan File</button>
    <button class="btn btn-ai"     onclick="aiFixSuggestions()">⇒ AI Fix Suggestions</button>
  </div>

  ${fpBadge}
  <div class="summary">${summaryText}</div>

  ${findings.length === 0
    ? `<div class="empty"><div class="empty-icon">✅</div><p>Pasted code looks clean.</p><p class="empty-sub">Checked ${rulesCount} security patterns. No false alarms.</p></div>`
    : findingsList + hiddenBanner
  }

  ${aiFixPanel}

  <script>
    var vscode = acquireVsCodeApi();
    function toggle(idx) {
      var detail  = document.getElementById('detail-'  + idx);
      var chevron = document.getElementById('chevron-' + idx);
      if (!detail || !chevron) { return; }
      var open = detail.style.display !== 'none';
      detail.style.display = open ? 'none' : 'block';
      chevron.classList.toggle('open', !open);
    }
    function ignoreThis(idx)    { vscode.postMessage({ type: 'ignoreThis',       findingIndex: idx }); }
    function openCve(url)       { vscode.postMessage({ type: 'openCve',          url: url }); }
    function rescanFile()       { vscode.postMessage({ type: 'rescanFile'       }); }
    function aiFixSuggestions() { vscode.postMessage({ type: 'aiFixSuggestions' }); }
    function closeAiFix()       { vscode.postMessage({ type: 'closeAiFix'       }); }
    function scanProject()      { vscode.postMessage({ type: 'scanProject'      }); }
  </script>
</body>
</html>`;
  }
}

function severityLabel(severity: "critical" | "warning" | "info"): string {
  switch (severity) {
    case "critical": return "CRIT";
    case "warning":  return "WARN";
    case "info":     return "INFO";
  }
}

function escapeHtml(text: string): string {
  return text
    .replace(/&/g,  "&amp;")
    .replace(/</g,  "&lt;")
    .replace(/>/g,  "&gt;")
    .replace(/"/g,  "&quot;");
}

function callAnthropic(apiKey: string, model: string, prompt: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      model,
      max_tokens: 1500,
      messages: [{ role: "user", content: prompt }],
    });

    const req = https.request(
      {
        method: "POST",
        hostname: "api.anthropic.com",
        path: "/v1/messages",
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(body),
          "x-api-key": apiKey,
          "anthropic-version": "2023-06-01",
        },
      },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (c: Buffer) => chunks.push(c));
        res.on("end", () => {
          const raw = Buffer.concat(chunks).toString("utf8");
          const status = res.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            reject(new Error(`API error ${status}: ${raw.slice(0, 200)}`));
            return;
          }
          try {
            const data = JSON.parse(raw) as { content?: Array<{ type: string; text: string }> };
            const text = (data.content ?? [])
              .filter((b) => b.type === "text")
              .map((b) => b.text)
              .join("\n");
            resolve(text);
          } catch (e) {
            reject(new Error(`Invalid JSON response: ${String(e)}`));
          }
        });
      }
    );

    req.on("error", reject);
    req.write(body);
    req.end();
  });
}