import * as vscode from "vscode";

interface ChangeTimestamp {
  time: number;
}

let suppressCount = 0;

export function suppressNextPaste(): void {
  suppressCount++;
}

export type PasteCallback = (
  text: string,
  document: vscode.TextDocument,
  range: vscode.Range
) => void;

export function onPaste(callback: PasteCallback): vscode.Disposable {
  const lastChange: ChangeTimestamp = { time: 0 };
  let debounceTimer: ReturnType<typeof setTimeout> | undefined;

  const disposable = vscode.workspace.onDidChangeTextDocument((event) => {
    if (suppressCount > 0) {
      suppressCount--;
      return;
    }

    const config = vscode.workspace.getConfiguration("pasteguard");
    const enabled = config.get<boolean>("enabled", true);
    if (!enabled) {
      return;
    }

    // Ignore undo/redo
    if (
      event.reason === vscode.TextDocumentChangeReason.Undo ||
      event.reason === vscode.TextDocumentChangeReason.Redo
    ) {
      return;
    }

    // Ignore non-file documents (output channels, etc.)
    if (event.document.uri.scheme !== "file" && event.document.uri.scheme !== "untitled") {
      return;
    }

    const minLines = config.get<number>("minLines", 3);
    const now = Date.now();
    const timeSinceLastChange = now - lastChange.time;

    for (const change of event.contentChanges) {
      const lineCount = change.text.split("\n").length;
      const isMultiLine = lineCount >= minLines;
      const isLargeChunk = change.text.length > 80 && timeSinceLastChange > 150;

      if (isMultiLine || isLargeChunk) {
        const pastedText = change.text;
        const startLine = change.range.start.line;
        const startChar = change.range.start.character;
        const endLine = startLine + lineCount - 1;
        const lines = pastedText.split("\n");
        const endChar =
          lineCount === 1
            ? startChar + lines[0].length
            : lines[lines.length - 1].length;
        const range = new vscode.Range(startLine, startChar, endLine, endChar);

        // Debounce 300ms
        if (debounceTimer !== undefined) {
          clearTimeout(debounceTimer);
        }

        debounceTimer = setTimeout(() => {
          callback(pastedText, event.document, range);
          debounceTimer = undefined;
        }, 300);
      }
    }

    lastChange.time = now;
  });

  return disposable;
}
