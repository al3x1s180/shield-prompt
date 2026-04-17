import * as vscode from "vscode";
import { Finding } from "./analyser";

interface DecorationState {
  criticalType: vscode.TextEditorDecorationType;
  warningType: vscode.TextEditorDecorationType;
  infoType: vscode.TextEditorDecorationType;
  activeRanges: Map<string, vscode.Range>;
}

let state: DecorationState | undefined;

function ensureDecorationTypes(): DecorationState {
  if (state) {
    return state;
  }

  const criticalType = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    gutterIconPath: undefined,
    gutterIconSize: "contain",
    overviewRulerColor: new vscode.ThemeColor("editorError.foreground"),
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    borderWidth: "0 0 2px 0",
    borderStyle: "wavy",
    borderColor: new vscode.ThemeColor("editorError.foreground"),
    backgroundColor: "rgba(255, 0, 0, 0.08)",
    after: {
      margin: "0 0 0 1em",
      color: new vscode.ThemeColor("editorError.foreground"),
    },
  });

  const warningType = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    overviewRulerColor: new vscode.ThemeColor("editorWarning.foreground"),
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    borderWidth: "0 0 2px 0",
    borderStyle: "wavy",
    borderColor: new vscode.ThemeColor("editorWarning.foreground"),
    backgroundColor: "rgba(255, 165, 0, 0.08)",
    after: {
      margin: "0 0 0 1em",
      color: new vscode.ThemeColor("editorWarning.foreground"),
    },
  });

  const infoType = vscode.window.createTextEditorDecorationType({
    isWholeLine: true,
    overviewRulerColor: new vscode.ThemeColor("editorInfo.foreground"),
    overviewRulerLane: vscode.OverviewRulerLane.Left,
    borderWidth: "0 0 2px 0",
    borderStyle: "dashed",
    borderColor: new vscode.ThemeColor("editorInfo.foreground"),
    backgroundColor: "rgba(0, 120, 255, 0.05)",
    after: {
      margin: "0 0 0 1em",
      color: new vscode.ThemeColor("editorInfo.foreground"),
    },
  });

  state = {
    criticalType,
    warningType,
    infoType,
    activeRanges: new Map(),
  };

  return state;
}

function severityToType(
  severity: "critical" | "warning" | "info",
  s: DecorationState
): vscode.TextEditorDecorationType {
  switch (severity) {
    case "critical":
      return s.criticalType;
    case "warning":
      return s.warningType;
    case "info":
      return s.infoType;
  }
}

export function applyDecorations(
  editor: vscode.TextEditor,
  findings: Finding[]
): void {
  const s = ensureDecorationTypes();

  const critical: vscode.DecorationOptions[] = [];
  const warning: vscode.DecorationOptions[] = [];
  const info: vscode.DecorationOptions[] = [];

  for (const f of findings) {
    const line = f.line;
    if (line < 0 || line >= editor.document.lineCount) {
      continue;
    }

    const lineRange = editor.document.lineAt(line).range;
    const hoverMessage = new vscode.MarkdownString(
      `**[${f.ruleId}]** ${f.message}\n\n${f.detail}`
    );

    const decoration: vscode.DecorationOptions = {
      range: lineRange,
      hoverMessage,
      renderOptions: {
        after: {
          contentText: ` ⚠ ${f.ruleId}`,
        },
      },
    };

    // Track active ranges for later clearing
    const key = `${editor.document.uri.toString()}:${line}`;
    s.activeRanges.set(key, lineRange);

    switch (f.severity) {
      case "critical":
        decoration.renderOptions = {
          after: { contentText: ` 🔴 ${f.ruleId}` },
        };
        critical.push(decoration);
        break;
      case "warning":
        decoration.renderOptions = {
          after: { contentText: ` 🟡 ${f.ruleId}` },
        };
        warning.push(decoration);
        break;
      case "info":
        decoration.renderOptions = {
          after: { contentText: ` 🔵 ${f.ruleId}` },
        };
        info.push(decoration);
        break;
    }
  }

  editor.setDecorations(s.criticalType, critical);
  editor.setDecorations(s.warningType, warning);
  editor.setDecorations(s.infoType, info);
}

export function clearDecorations(
  editor: vscode.TextEditor,
  range: vscode.Range
): void {
  const s = ensureDecorationTypes();

  // Clear all decorations on lines within the given range
  for (let line = range.start.line; line <= range.end.line; line++) {
    const key = `${editor.document.uri.toString()}:${line}`;
    s.activeRanges.delete(key);
  }

  // Re-apply only remaining decorations — for simplicity, just clear all on this editor
  editor.setDecorations(s.criticalType, []);
  editor.setDecorations(s.warningType, []);
  editor.setDecorations(s.infoType, []);
}

export function clearAllDecorations(editor: vscode.TextEditor): void {
  const s = ensureDecorationTypes();
  editor.setDecorations(s.criticalType, []);
  editor.setDecorations(s.warningType, []);
  editor.setDecorations(s.infoType, []);
  s.activeRanges.clear();
}

export function disposeDecorationTypes(): void {
  if (state) {
    state.criticalType.dispose();
    state.warningType.dispose();
    state.infoType.dispose();
    state = undefined;
  }
}

export function createEditClearListener(): vscode.Disposable {
  return vscode.workspace.onDidChangeTextDocument((event) => {
    if (!state) {
      return;
    }

    const editor = vscode.window.activeTextEditor;
    if (!editor || editor.document !== event.document) {
      return;
    }

    // If any edited line has an active decoration, clear decorations on that range
    for (const change of event.contentChanges) {
      for (
        let line = change.range.start.line;
        line <= change.range.end.line;
        line++
      ) {
        const key = `${event.document.uri.toString()}:${line}`;
        if (state.activeRanges.has(key)) {
          clearDecorations(editor, change.range);
          return;
        }
      }
    }
  });
}
