import * as vscode from "vscode";
import { onPaste } from "./detector";
import { analyse, fingerprint, Finding, AIFingerprint } from "./analyser";
import { semanticAnalyse } from "./semanticAnalyser";
import { ShieldPromptPanel } from "./panel";
import {
  applyDecorations,
  clearDecorations,
  createEditClearListener,
  disposeDecorationTypes,
} from "./decorations";
import { readProjectDeps } from "./depReader";

let statusBarItem: vscode.StatusBarItem;
let panel: ShieldPromptPanel;
let currentFindings: Finding[] = [];
let currentFingerprint: AIFingerprint = { isAI: false, confidence: "low" };

export function activate(context: vscode.ExtensionContext): void {
  panel = new ShieldPromptPanel((remainingFindings) => {
    currentFindings = remainingFindings;
    updateStatusBar(remainingFindings);
  });

  // Status bar
  statusBarItem = vscode.window.createStatusBarItem(
    vscode.StatusBarAlignment.Left,
    100
  );
  statusBarItem.command = "shieldprompt.openPanel";
  statusBarItem.text = "$(shield) ShieldPrompt: 0 issues";
  statusBarItem.show();
  context.subscriptions.push(statusBarItem);

  // Commands
  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.openPanel", () => {
      panel.show(currentFindings, currentFingerprint);
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.resetSuppressions", () => {
      const config = vscode.workspace.getConfiguration("shieldprompt");
      config.update("suppressedRules", [], vscode.ConfigurationTarget.Workspace);
      vscode.window.showInformationMessage("ShieldPrompt: All rule suppressions have been reset.");
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("shieldprompt.toggleEnabled", () => {
      const config = vscode.workspace.getConfiguration("shieldprompt");
      const current = config.get<boolean>("enabled", true);
      config.update("enabled", !current, vscode.ConfigurationTarget.Workspace);
      vscode.window.showInformationMessage(
        `ShieldPrompt: ${!current ? "Enabled" : "Disabled"}`
      );
    })
  );

  // Paste detection — async to support dependency reading
  const pasteDisposable = onPaste((text, document, range) => {
    const config = vscode.workspace.getConfiguration("shieldprompt");
    const languageId = document.languageId;

    // Read deps and analyse asynchronously
    void readProjectDeps().then((projectDeps) => {
      const suppressedRules = config.get<string[]>("suppressedRules", []);

      // Static regex-based findings
      const staticFindings = analyse(text, languageId, range.start.line, suppressedRules, projectDeps.dependencies);

      // Semantic multi-line findings (taint tracking, call chains, structural checks)
      const semanticFindings = semanticAnalyse(text, languageId, range.start.line, suppressedRules);

      // Merge, deduplicate by line+ruleId
      const seen = new Set(staticFindings.map((f) => `${f.line}:${f.ruleId}`));
      const merged = [...staticFindings];
      for (const f of semanticFindings) {
        if (!seen.has(`${f.line}:${f.ruleId}`)) {
          merged.push(f);
          seen.add(`${f.line}:${f.ruleId}`);
        }
      }
      // Sort by line then severity
      const sevWeight: Record<string, number> = { critical: 0, warning: 1, info: 2 };
      merged.sort((a, b) => a.line !== b.line ? a.line - b.line : (sevWeight[a.severity] ?? 3) - (sevWeight[b.severity] ?? 3));

      const fp = fingerprint(text);

      currentFindings = merged;
      currentFingerprint = fp;

      updateStatusBar(merged);

      const editor = vscode.window.activeTextEditor;
      if (editor && editor.document === document) {
        applyDecorations(editor, merged);
      }

      if (merged.length > 0) {
        panel.show(merged, fp);
      }
    });
  });
  context.subscriptions.push(pasteDisposable);

  // Clear decorations when user edits flagged lines
  context.subscriptions.push(createEditClearListener());

  // Cleanup on deactivate
  context.subscriptions.push({
    dispose(): void {
      panel.dispose();
      disposeDecorationTypes();
    },
  });
}

function updateStatusBar(findings: Finding[]): void {
  const count = findings.length;
  statusBarItem.text = `$(shield) ShieldPrompt: ${count} issue${count !== 1 ? "s" : ""}`;

  const hasCritical = findings.some((f) => f.severity === "critical");
  const hasWarning = findings.some((f) => f.severity === "warning");

  if (hasCritical) {
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.errorBackground"
    );
  } else if (hasWarning) {
    statusBarItem.backgroundColor = new vscode.ThemeColor(
      "statusBarItem.warningBackground"
    );
  } else {
    statusBarItem.backgroundColor = undefined;
  }
}

export function deactivate(): void {
  // Cleanup handled by disposables
}