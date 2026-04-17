import * as vscode from "vscode";
import { Finding, AIFingerprint, CVERef, RULES_COUNT } from "./analyser";
import { SEMANTIC_RULES_COUNT } from "./semanticAnalyser";

interface IgnoreMessage {
  type: "ignoreThis";
  findingIndex: number;
}

interface OpenCveMessage {
  type: "openCve";
  url: string;
}

type WebviewMessage = IgnoreMessage | OpenCveMessage;

const HIGH_CONFIDENCE_RULES = new Set([
  "eval-external",
  "hardcoded-secret",
  "shell-injection",
  "pickle-loads",
]);

function confidenceLabel(f: Finding): { label: string; cls: string } {
  if (f.severity === "critical" && HIGH_CONFIDENCE_RULES.has(f.ruleId)) {
    return { label: "high confidence", cls: "conf-high" };
  }
  if (f.severity === "warning") {
    return { label: "review", cls: "conf-review" };
  }
  return { label: "medium confidence", cls: "conf-med" };
}

function renderCveBadges(cves: CVERef[]): string {
  if (!cves || cves.length === 0) { return ""; }
  return cves
    .map(
      (c) =>
        `<button class="cve-badge" onclick="openCve('${escapeHtml(c.url)}')" title="${escapeHtml(c.description)}">${escapeHtml(c.id)}</button>`
    )
    .join(" ");
}

export class PasteGuardPanel {
  private panel: vscode.WebviewPanel | undefined;
  private disposables: vscode.Disposable[] = [];
  private _currentFindings: Finding[] = [];

  public show(findings: Finding[], fp: AIFingerprint): void {
    this._currentFindings = findings;

    if (this.panel) {
      this.panel.webview.html = this.buildHtml(findings, fp);
      this.panel.reveal(vscode.ViewColumn.Beside, true);
      return;
    }

    this.panel = vscode.window.createWebviewPanel(
      "pasteguardPanel",
      "PasteGuard",
      { viewColumn: vscode.ViewColumn.Beside, preserveFocus: true },
      { enableScripts: true, retainContextWhenHidden: true }
    );

    this.panel.webview.html = this.buildHtml(findings, fp);

    this.panel.webview.onDidReceiveMessage(
      async (message: WebviewMessage) => {
        if (message.type === "openCve") {
          await vscode.env.openExternal(vscode.Uri.parse(message.url));
        } else if (message.type === "ignoreThis") {
          const finding = this._currentFindings[message.findingIndex];
          if (!finding) { return; }
          const editor = vscode.window.activeTextEditor;
          if (!editor) { return; }
          const line = editor.document.lineAt(finding.line);
          const newText = `${line.text} // shieldprompt-ignore: ${finding.ruleId}`;
          await editor.edit((eb) => { eb.replace(line.range, newText); });
          vscode.window.showInformationMessage(
            `ShieldPrompt: Rule ${finding.ruleId} ignored on line ${finding.line + 1}.`
          );
        }
      },
      null,
      this.disposables
    );

    this.panel.onDidDispose(
      () => {
        this.panel = undefined;
        this.disposables.forEach((d) => d.dispose());
        this.disposables = [];
      },
      null,
      this.disposables
    );
  }

  public reveal(): void {
    if (this.panel) { this.panel.reveal(vscode.ViewColumn.Beside, true); }
  }

  public dispose(): void {
    if (this.panel) { this.panel.dispose(); }
  }

  private buildHtml(findings: Finding[], fp: AIFingerprint): string {
    const criticalCount = findings.filter((f) => f.severity === "critical").length;
    const warningCount = findings.filter((f) => f.severity === "warning").length;
    const infoCount = findings.filter((f) => f.severity === "info").length;
    const total = findings.length;

    const summaryParts: string[] = [];
    if (criticalCount > 0) { summaryParts.push(`${criticalCount} critical`); }
    if (warningCount > 0) { summaryParts.push(`${warningCount} warning${warningCount > 1 ? "s" : ""}`); }
    if (infoCount > 0) { summaryParts.push(`${infoCount} info`); }

    const summaryText =
      total === 0
        ? "No issues found ✅"
        : `${total} issue${total > 1 ? "s" : ""} found (${summaryParts.join(", ")})`;

    const fpBadge =
      fp.confidence === "high" || fp.confidence === "medium"
        ? `<div class="ai-badge ${fp.confidence}">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/><circle cx="12" cy="16" r="1"/></svg>
            AI-generated code detected (${fp.confidence} confidence)
          </div>`
        : "";

    const rulesCount = RULES_COUNT + SEMANTIC_RULES_COUNT;

    const findingsList = findings
      .map((f, i) => {
        const conf = confidenceLabel(f);
        const cveBadges = renderCveBadges(f.cves);
        return `
      <div class="finding ${f.severity}">
        <div class="finding-header" onclick="toggle(${i})">
          <span class="sev-pill ${f.severity}">${severityLabel(f.severity)}</span>
          <span class="confidence ${conf.cls}">${conf.label}</span>
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
      })
      .join("\n");

    // Polished SVG shield icon
    const shieldSvg = `<svg width="18" height="18" viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">
      <path d="M12 2L3 6.5V12c0 5 3.8 9.7 9 10.9C17.2 21.7 21 17 21 12V6.5L12 2Z" fill="url(#sg)" stroke="none"/>
      <path d="M9 12l2 2 4-4" stroke="white" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>
      <defs>
        <linearGradient id="sg" x1="3" y1="2" x2="21" y2="23" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stop-color="#3b82f6"/>
          <stop offset="100%" stop-color="#1d4ed8"/>
        </linearGradient>
      </defs>
    </svg>`;

    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <style>
    :root {
      --bg: var(--vscode-editor-background, #1e1e1e);
      --bg2: var(--vscode-sideBar-background, #252526);
      --fg: var(--vscode-editor-foreground, #cccccc);
      --fg2: var(--vscode-descriptionForeground, #858585);
      --border: var(--vscode-panel-border, #333333);
      --crit-fg: #ff6b6b;
      --crit-bg: rgba(255,107,107,0.1);
      --warn-fg: #ffa500;
      --warn-bg: rgba(255,165,0,0.1);
      --info-fg: #4fc3f7;
      --info-bg: rgba(79,195,247,0.08);
      --blue: #3b82f6;
      --radius: 6px;
      --font: var(--vscode-font-family, -apple-system, BlinkMacSystemFont, sans-serif);
      --mono: var(--vscode-editor-font-family, 'Cascadia Code', 'Fira Code', monospace);
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
    .header { display: flex; align-items: center; gap: 8px; margin-bottom: 14px; }
    .header-icon { display: flex; align-items: center; flex-shrink: 0; }
    .header-title { font-size: 15px; font-weight: 600; letter-spacing: -0.01em; }
    .header-sub { font-size: 12px; color: var(--fg2); margin-left: auto; }
    .ai-badge {
      display: inline-flex; align-items: center; gap: 6px;
      padding: 5px 11px; border-radius: 20px;
      font-size: 12px; font-weight: 600;
      margin-bottom: 14px; border: 1px solid;
    }
    .ai-badge.high { background: var(--crit-bg); border-color: var(--crit-fg); color: var(--crit-fg); }
    .ai-badge.medium { background: var(--warn-bg); border-color: var(--warn-fg); color: var(--warn-fg); }
    .summary {
      background: var(--bg2);
      border-left: 3px solid var(--blue);
      border-radius: 0 var(--radius) var(--radius) 0;
      padding: 9px 13px;
      margin-bottom: 14px;
      font-size: 13px;
    }
    .finding {
      border: 0.5px solid var(--border);
      border-radius: var(--radius);
      margin-bottom: 7px;
      overflow: hidden;
    }
    .finding.critical { border-left: 3px solid var(--crit-fg); }
    .finding.warning  { border-left: 3px solid var(--warn-fg); }
    .finding.info     { border-left: 3px solid var(--info-fg); }
    .finding-header {
      display: flex; align-items: center; gap: 7px;
      padding: 8px 11px; cursor: pointer; user-select: none;
    }
    .finding-header:hover { background: rgba(255,255,255,0.03); }
    .sev-pill {
      padding: 2px 7px; border-radius: 20px;
      font-size: 10px; font-weight: 700; text-transform: uppercase;
      letter-spacing: 0.04em; flex-shrink: 0;
    }
    .sev-pill.critical { background: var(--crit-bg); color: var(--crit-fg); }
    .sev-pill.warning  { background: var(--warn-bg); color: var(--warn-fg); }
    .sev-pill.info     { background: var(--info-bg); color: var(--info-fg); }
    .confidence { font-size: 10px; opacity: 0.6; flex-shrink: 0; }
    .finding-line { font-size: 11px; color: var(--fg2); flex-shrink: 0; font-family: var(--mono); }
    .finding-rule { font-size: 12px; font-family: var(--mono); opacity: 0.65; flex-shrink: 0; }
    .finding-msg  { flex: 1; font-size: 13px; }
    .chevron { font-size: 10px; opacity: 0.4; flex-shrink: 0; transition: transform 0.15s; }
    .chevron.open { transform: rotate(90deg); }
    .finding-detail {
      padding: 10px 14px 13px;
      background: var(--bg2);
      border-top: 0.5px solid var(--border);
    }
    .finding-detail p { margin-bottom: 9px; color: var(--fg2); font-size: 12px; line-height: 1.6; }
    .cve-row {
      display: flex; align-items: center; gap: 6px;
      flex-wrap: wrap; margin-bottom: 10px;
    }
    .cve-label { font-size: 11px; color: var(--fg2); flex-shrink: 0; }
    .cve-badge {
      display: inline-flex; align-items: center;
      padding: 2px 8px;
      background: rgba(59,130,246,0.12);
      border: 1px solid rgba(59,130,246,0.4);
      border-radius: 4px;
      color: #60a5fa;
      font-size: 11px;
      font-family: var(--mono);
      font-weight: 600;
      cursor: pointer;
      transition: background 0.12s, border-color 0.12s;
    }
    .cve-badge:hover {
      background: rgba(59,130,246,0.22);
      border-color: rgba(59,130,246,0.7);
    }
    .ignore-btn {
      padding: 4px 11px;
      background: transparent;
      color: var(--fg2);
      border: 1px solid var(--border);
      border-radius: 4px;
      cursor: pointer;
      font-size: 12px;
      transition: border-color 0.12s, color 0.12s;
    }
    .ignore-btn:hover { border-color: var(--fg); color: var(--fg); }
    .empty { text-align: center; padding: 44px 20px; color: var(--fg2); }
    .empty-icon { font-size: 36px; margin-bottom: 10px; }
    .empty p { font-size: 14px; }
    .empty-sub { font-size: 12px; opacity: 0.5; margin-top: 6px; }
  </style>
</head>
<body>
  <div class="header">
    <span class="header-icon">${shieldSvg}</span>
    <span class="header-title">ShieldPrompt</span>
    <span class="header-sub" id="trust-signal">Fires on paste only — never slows your editor</span>
  </div>
  ${fpBadge}
  <div class="summary">${summaryText}</div>
  ${
    findings.length === 0
      ? `<div class="empty"><div class="empty-icon">✅</div><p>Pasted code looks clean.</p><p class="empty-sub">Checked ${rulesCount} security patterns. No false alarms.</p></div>`
      : findingsList
  }
  <script>
    var vscode = acquireVsCodeApi();

    function toggle(idx) {
      var detail = document.getElementById('detail-' + idx);
      var chevron = document.getElementById('chevron-' + idx);
      if (!detail || !chevron) return;
      var open = detail.style.display !== 'none';
      detail.style.display = open ? 'none' : 'block';
      chevron.classList.toggle('open', !open);
    }

    function ignoreThis(idx) {
      vscode.postMessage({ type: 'ignoreThis', findingIndex: idx });
    }

    function openCve(url) {
      vscode.postMessage({ type: 'openCve', url: url });
    }

    var signals = [
      'Fires on paste only \u2014 never slows your editor',
      'Zero login required \u2014 works instantly',
      'No CLI dependency \u2014 pure local analysis',
      'Your code never leaves your machine'
    ];
    var sigIdx = 0;
    setInterval(function() {
      sigIdx = (sigIdx + 1) % signals.length;
      var el = document.getElementById('trust-signal');
      if (el) el.textContent = signals[sigIdx];
    }, 4000);
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
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}