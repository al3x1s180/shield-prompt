import * as vscode from "vscode";

export interface ProjectDeps {
  hasPackageJson: boolean;
  dependencies: Set<string>;
}

export async function readProjectDeps(): Promise<ProjectDeps> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders) {
    return { hasPackageJson: false, dependencies: new Set() };
  }

  const root = folders[0].uri;
  const deps = new Set<string>();

  // Try package.json
  try {
    const pkgUri = vscode.Uri.joinPath(root, "package.json");
    const raw = await vscode.workspace.fs.readFile(pkgUri);
    const pkg = JSON.parse(Buffer.from(raw).toString("utf8")) as Record<string, Record<string, string>>;
    const allDeps: Record<string, string> = {
      ...pkg["dependencies"],
      ...pkg["devDependencies"],
      ...pkg["peerDependencies"],
    };
    for (const name of Object.keys(allDeps)) {
      deps.add(name.toLowerCase());
    }
    return { hasPackageJson: true, dependencies: deps };
  } catch {
    // no package.json — that's fine
  }

  // Try requirements.txt for Python
  try {
    const reqUri = vscode.Uri.joinPath(root, "requirements.txt");
    const raw = await vscode.workspace.fs.readFile(reqUri);
    const lines = Buffer.from(raw).toString("utf8").split("\n");
    for (const line of lines) {
      const name = line.split(/[>=<!]/)[0].trim().toLowerCase();
      if (name) {
        deps.add(name);
      }
    }
  } catch {
    // no requirements.txt
  }

  return { hasPackageJson: false, dependencies: deps };
}
