import * as vscode from "vscode";
import { execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";

// scans never run longer than this (ms); stops a hung/huge scan wedging things
const SCAN_TIMEOUT_MS = 120_000;
// cap on captured output, guards against a runaway process eating memory
const MAX_OUTPUT_BYTES = 32 * 1024 * 1024;

// shape of `xsec scan --json`
interface XsecFinding {
  rule_id: string;
  severity: "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";
  message: string;
  file: string;
  line: number;
  column: number;
  engine: string;
  fix: string | null;
  snippet: string | null;
}

interface XsecResult {
  files_scanned: number;
  errors: string[];
  findings: XsecFinding[];
}

// rules the auto-fixer can rewrite (so we can offer a Quick Fix)
const FIXABLE = new Set(["PY-YAML-LOAD", "PY-WEAK-HASH", "PY-FLASK-DEBUG"]);

const SUPPORTED_LANGS = new Set(["python", "javascript", "typescript", "java"]);

let diagnostics: vscode.DiagnosticCollection;
let output: vscode.OutputChannel;
let status: vscode.StatusBarItem;

export function activate(context: vscode.ExtensionContext): void {
  diagnostics = vscode.languages.createDiagnosticCollection("xsec");
  output = vscode.window.createOutputChannel("XSEC");
  status = vscode.window.createStatusBarItem(vscode.StatusBarAlignment.Right, 100);
  status.command = "xsec.scanFile";
  context.subscriptions.push(diagnostics, output, status);
  setStatusIdle();

  context.subscriptions.push(
    vscode.commands.registerCommand("xsec.scanWorkspace", scanWorkspace),
    vscode.commands.registerCommand("xsec.scanFile", () => {
      const ed = vscode.window.activeTextEditor;
      if (ed) void scanDocument(ed.document);
    }),
    vscode.commands.registerCommand("xsec.fixFile", () => fixActiveFile(false)),
    vscode.commands.registerCommand("xsec.fixFileUnsafe", () => fixActiveFile(true))
  );

  // scan on save
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument((doc) => {
      if (cfg().get<boolean>("scanOnSave", true) && SUPPORTED_LANGS.has(doc.languageId)) {
        void scanDocument(doc);
      }
    })
  );

  context.subscriptions.push(
    vscode.workspace.onDidCloseTextDocument((doc) => {
      if (doc.isUntitled) diagnostics.delete(doc.uri);
    })
  );

  context.subscriptions.push(
    vscode.languages.registerCodeActionsProvider(
      [...SUPPORTED_LANGS].map((language) => ({ language })),
      new XsecFixProvider(),
      { providedCodeActionKinds: [vscode.CodeActionKind.QuickFix] }
    )
  );

  // if the user grants trust later, scan the open file then
  context.subscriptions.push(
    vscode.workspace.onDidGrantWorkspaceTrust(() => {
      const ed = vscode.window.activeTextEditor;
      if (ed) void scanDocument(ed.document);
    })
  );

  // scan whatever is already open
  if (vscode.window.activeTextEditor) {
    void scanDocument(vscode.window.activeTextEditor.document);
  }
}

export function deactivate(): void {
  diagnostics?.dispose();
}

// --- status bar -------------------------------------------------------------

function setStatusIdle(): void {
  if (!vscode.workspace.isTrusted) {
    status.text = "$(shield) XSEC: untrusted";
    status.tooltip = "Trust this folder to enable XSEC scanning.";
  } else {
    status.text = "$(shield) XSEC";
    status.tooltip = "XSEC ready — click to scan the current file.";
  }
  status.backgroundColor = undefined;
  status.show();
}

function setStatusScanning(): void {
  status.text = "$(sync~spin) XSEC: scanning…";
  status.tooltip = "XSEC is scanning…";
  status.show();
}

function setStatusResult(count: number): void {
  if (count === 0) {
    status.text = "$(shield) XSEC: clean";
    status.tooltip = "No findings in this file.";
    status.backgroundColor = undefined;
  } else {
    status.text = `$(shield) XSEC: ${count}`;
    status.tooltip = `${count} finding(s) — click to re-scan.`;
    status.backgroundColor = new vscode.ThemeColor("statusBarItem.warningBackground");
  }
  status.show();
}

function cfg(): vscode.WorkspaceConfiguration {
  return vscode.workspace.getConfiguration("xsec");
}

function isOn(): boolean {
  // never run in a folder the user hasn't trusted: we execute a program here
  if (!vscode.workspace.isTrusted) return false;
  return cfg().get<boolean>("enable", true);
}

function autofixOn(): boolean {
  return cfg().get<boolean>("enableAutofix", true);
}

// Resolve the configured executable and make sure it's something we can run.
// Returns null (and tells the user) if it's missing or not a real file, so we
// never hand an arbitrary string to the OS.
function resolveExecutable(): string | null {
  const exe = cfg().get<string>("executable", "xsec").trim();
  if (!exe) return null;

  // a bare command name (e.g. "xsec") is resolved via PATH by the OS - fine
  const looksLikePath = exe.includes("/") || exe.includes("\\");
  if (!looksLikePath) return exe;

  // an absolute/relative path must actually exist as a file before we run it
  try {
    const stat = fs.statSync(exe);
    if (!stat.isFile()) {
      showError(new Error(`xsec.executable is not a file: ${exe}`));
      return null;
    }
  } catch {
    showError(new Error(`xsec.executable not found: ${exe}`));
    return null;
  }
  return exe;
}

function baseArgs(): string[] {
  const args = ["--json", "--min-severity", cfg().get<string>("minSeverity", "LOW")];
  if (cfg().get<boolean>("enableAI", false)) args.push("--ai");
  args.push(...cfg().get<string[]>("extraArgs", []));
  return args;
}

function workspaceCwd(target: vscode.Uri): string {
  return (
    vscode.workspace.getWorkspaceFolder(target)?.uri.fsPath ??
    path.dirname(target.fsPath)
  );
}

function runXsec(scanArgs: string[], cwd: string): Promise<XsecResult> {
  const exe = resolveExecutable();
  if (!exe) return Promise.reject(new Error("xsec executable not available"));

  return new Promise((resolve, reject) => {
    execFile(
      exe,
      ["scan", ...scanArgs],
      {
        cwd,
        maxBuffer: MAX_OUTPUT_BYTES,
        timeout: SCAN_TIMEOUT_MS,
        // never go through a shell: args are passed as a list, so a file or
        // path containing shell metacharacters can't be interpreted as a command
        shell: false,
        // don't let the scanned project inject env (e.g. PYTHON* hooks); pass a
        // minimal, explicit environment plus the API key if AI is enabled
        env: childEnv(),
        windowsHide: true,
      },
      (err, stdout, stderr) => {
        // we don't pass --fail-on, so a missing binary is the real failure
        if (err && (err as NodeJS.ErrnoException).code === "ENOENT") {
          reject(new Error(`xsec not found (set "xsec.executable"): ${exe}`));
          return;
        }
        if (!stdout) {
          reject(new Error(stderr || (err ? err.message : "no output from xsec")));
          return;
        }
        try {
          resolve(JSON.parse(stdout) as XsecResult);
        } catch (e) {
          reject(new Error(`could not parse xsec output: ${(e as Error).message}`));
        }
      }
    );
  });
}

// A trimmed environment for the child process. We keep PATH/HOME (needed to
// find and run the tool) and pass ANTHROPIC_API_KEY only when AI is enabled,
// rather than leaking the whole parent environment.
function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    PATH: process.env.PATH,
    HOME: process.env.HOME,
  };
  if (cfg().get<boolean>("enableAI", false) && process.env.ANTHROPIC_API_KEY) {
    env.ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;
  }
  return env;
}

async function scanDocument(doc: vscode.TextDocument): Promise<void> {
  if (!isOn() || doc.uri.scheme !== "file") {
    setStatusIdle();
    return;
  }
  setStatusScanning();
  try {
    const result = await runXsec([...baseArgs(), doc.uri.fsPath], workspaceCwd(doc.uri));
    diagnostics.set(doc.uri, result.findings.map((f) => toDiagnostic(f, doc)));
    reportErrors(result);
    setStatusResult(result.findings.length);
  } catch (e) {
    setStatusIdle();
    showError(e);
  }
}

async function scanWorkspace(): Promise<void> {
  if (!isOn()) {
    vscode.window.showInformationMessage("XSEC is turned off (setting: xsec.enable).");
    return;
  }
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    vscode.window.showWarningMessage("XSEC: open a folder to scan.");
    return;
  }
  await vscode.window.withProgress(
    { location: vscode.ProgressLocation.Notification, title: "XSEC: scanning workspace…" },
    async () => {
      try {
        const result = await runXsec([...baseArgs(), folder.uri.fsPath], folder.uri.fsPath);
        diagnostics.clear();
        const byFile = new Map<string, XsecFinding[]>();
        for (const f of result.findings) {
          const list = byFile.get(f.file) ?? [];
          list.push(f);
          byFile.set(f.file, list);
        }
        for (const [file, findings] of byFile) {
          const uri = vscode.Uri.file(path.resolve(folder.uri.fsPath, file));
          diagnostics.set(uri, findings.map((f) => toDiagnostic(f)));
        }
        reportErrors(result);
        vscode.window.showInformationMessage(
          `XSEC: ${result.findings.length} finding(s) across ${result.files_scanned} file(s).`
        );
      } catch (e) {
        showError(e);
      }
    }
  );
}

async function fixActiveFile(unsafe: boolean): Promise<void> {
  // auto-fix edits files, so it needs both trust and the autofix toggle
  if (!isOn()) {
    vscode.window.showInformationMessage("XSEC is off, or this folder isn't trusted.");
    return;
  }
  if (!autofixOn()) {
    vscode.window.showInformationMessage("XSEC auto-fix is turned off (setting: xsec.enableAutofix).");
    return;
  }
  const ed = vscode.window.activeTextEditor;
  if (!ed) return;
  const doc = ed.document;
  if (doc.isDirty) await doc.save(); // fix rewrites the file on disk

  const exe = resolveExecutable();
  if (!exe) return;
  const args = ["scan", doc.uri.fsPath, "--fix"];
  if (unsafe) args.push("--unsafe-fixes");

  await new Promise<void>((resolve) => {
    execFile(
      exe,
      args,
      {
        cwd: workspaceCwd(doc.uri),
        timeout: SCAN_TIMEOUT_MS,
        maxBuffer: MAX_OUTPUT_BYTES,
        shell: false,
        env: childEnv(),
        windowsHide: true,
      },
      (err, _out, stderr) => {
        if (err && (err as NodeJS.ErrnoException).code === "ENOENT") {
          showError(new Error(`xsec not found: ${exe}`));
        } else if (err && stderr) {
          output.appendLine(stderr);
        }
        resolve();
      }
    );
  });

  // reload from disk (xsec changed it) and re-scan
  await vscode.commands.executeCommand("workbench.action.files.revert");
  await scanDocument(doc);
  vscode.window.showInformationMessage("XSEC: applied auto-fixes.");
}

function severityOf(f: XsecFinding): vscode.DiagnosticSeverity {
  switch (f.severity) {
    case "CRITICAL":
    case "HIGH":
      return vscode.DiagnosticSeverity.Error;
    case "MEDIUM":
      return vscode.DiagnosticSeverity.Warning;
    case "LOW":
      return vscode.DiagnosticSeverity.Information;
    default:
      return vscode.DiagnosticSeverity.Hint;
  }
}

function toDiagnostic(f: XsecFinding, doc?: vscode.TextDocument): vscode.Diagnostic {
  const lineIdx = Math.max(f.line - 1, 0);
  let range: vscode.Range;
  if (doc && lineIdx < doc.lineCount) {
    // underline from the first non-space char to end of line
    const textLine = doc.lineAt(lineIdx);
    const start = Math.max(f.column, textLine.firstNonWhitespaceCharacterIndex);
    range = new vscode.Range(lineIdx, start, lineIdx, textLine.range.end.character);
  } else {
    range = new vscode.Range(lineIdx, Math.max(f.column, 0), lineIdx, 500);
  }

  const diag = new vscode.Diagnostic(range, formatMessage(f), severityOf(f));
  diag.source = `xsec/${f.engine}`;
  diag.code = f.rule_id;
  return diag;
}

function formatMessage(f: XsecFinding): string {
  return f.fix ? `${f.message}\n→ ${f.fix}` : f.message;
}

class XsecFixProvider implements vscode.CodeActionProvider {
  provideCodeActions(
    _doc: vscode.TextDocument,
    _range: vscode.Range,
    context: vscode.CodeActionContext
  ): vscode.CodeAction[] {
    if (!autofixOn()) return [];
    const fixable = context.diagnostics.filter(
      (d) => typeof d.code === "string" && FIXABLE.has(d.code)
    );
    if (fixable.length === 0) return [];

    const action = new vscode.CodeAction(
      "XSEC: auto-fix this file",
      vscode.CodeActionKind.QuickFix
    );
    action.command = { command: "xsec.fixFile", title: "XSEC: auto-fix this file" };
    action.diagnostics = fixable;
    return [action];
  }
}

function reportErrors(result: XsecResult): void {
  for (const e of result.errors) output.appendLine(`! ${e}`);
}

function showError(e: unknown): void {
  const msg = e instanceof Error ? e.message : String(e);
  output.appendLine(`ERROR: ${msg}`);
  vscode.window.showErrorMessage(`XSEC: ${msg}`);
}
