<p align="center">
  <img src="https://raw.githubusercontent.com/LEXES7/XSEC/main/assets/icon.png" width="120" alt="XSEC logo">
</p>

<h1 align="center">XSEC — AI Code Security</h1>

<p align="center">
  <b>Catch and auto-fix security vulnerabilities in AI-written code — live, as you type.</b>
</p>

---

AI assistants write code that *runs*, not code that's *safe*. They reach for
`eval`, `shell=True`, `innerHTML`, hardcoded keys, and outdated packages because
those are the shortest path to "it works." **XSEC flags exactly those mistakes
right in your editor** — with red squiggles, clear explanations, and one-click
fixes.

![XSEC in action](https://raw.githubusercontent.com/LEXES7/XSEC/main/assets/banner.png)

## Why XSEC

- 🛡️ **Finds real vulnerabilities** — command/SQL injection, unsafe
  deserialization, weak crypto, hardcoded secrets, XSS sinks, and more.
- 🔧 **Fixes them for you** — safe one-click refactors (e.g. `yaml.load` →
  `yaml.safe_load`), with risky ones gated behind an explicit opt-in.
- 🌐 **Multi-language** — Python, JavaScript/TypeScript, and Java out of the box.
- 🤖 **Optional AI review** — let Claude reason about deeper logic flaws, in any
  language. Off by default; your code stays local unless you turn it on.
- 📦 **Dependency scanning** — checks your packages against known CVEs (OSV).
- 🔒 **Private & safe by design** — runs locally, respects Workspace Trust, and
  never sends code anywhere unless you explicitly enable AI review.

## How it works

The extension drives the [`xsec` CLI](https://github.com/LEXES7/XSEC)
(`xsec scan --json`) and renders results as editor diagnostics. The CLI is the
single source of truth — no analysis logic is duplicated here, so the editor and
your CI pipeline always agree.

## Requirements

Install the `xsec` CLI (Python 3.10+):

```bash
pip install -e /path/to/XSEC          # core
pip install -e "/path/to/XSEC[ai,deps]"   # + AI review + dependency scanning
xsec --version
```

If it lives in a virtualenv, point the extension at it with the
**`xsec.executable`** setting (e.g. `/path/to/.venv/bin/xsec`).

## Features

- **Scan on save** — every save of a `.py` / `.js` / `.ts` / `.jsx` / `.tsx` /
  `.java` file re-scans it; findings appear as squiggles.
- **Status bar** — a shield in the status bar shows live state: *scanning…*,
  *clean*, or the number of findings. Click it to re-scan.
- **Quick Fix** — auto-fixable findings offer a 💡 lightbulb that runs the fixer.
- **Commands** (`Cmd/Ctrl-Shift-P`):
  - `XSEC: Scan Workspace`
  - `XSEC: Scan Current File`
  - `XSEC: Auto-fix Current File (safe)` / `(include risky)`

## Settings

| Setting | Default | Purpose |
| --- | --- | --- |
| `xsec.enable` | `true` | Master on/off switch. |
| `xsec.executable` | `xsec` | Path to the CLI *(machine-scoped for safety)*. |
| `xsec.scanOnSave` | `true` | Scan files automatically on save. |
| `xsec.minSeverity` | `LOW` | Hide findings below this severity. |
| `xsec.enableAI` | `false` | Send code to Claude for AI review (needs `ANTHROPIC_API_KEY`). |
| `xsec.enableAutofix` | `true` | Allow XSEC to rewrite files via the fix action. |
| `xsec.extraArgs` | `[]` | Extra args appended to every scan *(machine-scoped)*. |

## Privacy & security

XSEC runs a program on your code, so it treats that responsibly:

- **Workspace Trust** — it does nothing in folders you haven't trusted, so a
  malicious repo can't make it run.
- **Machine-scoped executable** — a project's `.vscode/settings.json` cannot
  redirect `xsec.executable`, blocking the classic "repo ships a malware binary"
  attack.
- **Local by default** — nothing leaves your machine unless you enable
  `xsec.enableAI` (which uploads file contents to Anthropic's API) or run a
  dependency scan (which sends package names/versions to OSV).

## Develop

```bash
cd vscode-extension
npm install
npm run compile        # or: npm run watch
```

Then press **F5** in VS Code to launch an Extension Development Host.

---

<p align="center"><sub>Part of the <a href="https://github.com/LEXES7/XSEC">XSEC</a> project · MIT licensed</sub></p>
