# Security

XSEC is a security tool, so it's held to its own standard. This document
describes its threat model, the protections built in, and how to report issues.

## Reporting a vulnerability

Please report security issues **privately**, not in public GitHub issues:

- Use **GitHub → Security → Report a vulnerability** (private advisories), or
- email the maintainer.

Include steps to reproduce and the affected version. We aim to acknowledge
reports promptly and will credit reporters who wish to be named.

## Threat model

The defining fact about XSEC: **it reads code it did not write.** A scanned
repository may be hostile or simply broken, so XSEC treats its *own input* as an
attack surface. The goals:

1. Scanning a malicious repo must not let it run code, read files outside the
   tree, hang the scanner, or exhaust memory.
2. The tool must not leak the user's secrets (API keys) or send code anywhere
   without explicit opt-in.
3. The editor integration must not let a project silently execute a binary.

## Protections

### Processing untrusted code (`xsec/safety.py`, `xsec/discovery.py`)

- **File-size cap** — files larger than 5 MB are skipped, so a giant file can't
  exhaust memory.
- **Line-length cap** — lines longer than 5,000 chars are truncated before any
  regex runs; this is the primary defense against catastrophic backtracking
  (ReDoS). All bundled rules are also benchmarked against adversarial input.
- **No symlink following** — discovery uses `os.walk(followlinks=False)` and
  skips symlinked files, so a repo can't redirect a scan to `/etc` or your home
  directory, or create a traversal cycle.
- **Binary skipping** — files with NUL bytes are skipped.
- **File-count cap** — discovery stops after 50,000 files.
- **Graceful degradation** — unreadable/oversized/binary files are skipped
  quietly rather than crashing the scan.

### Network & secrets

- **Opt-in network only.** The core scan is fully offline. Network access
  happens only with `--ai` (sends file contents to the chosen AI provider) or
  `--deps` (sends package names/versions to OSV). Both are off by default.
- **TLS always verified** — HTTPS requests verify certificates, using the
  `certifi` bundle when available. Verification is never disabled.
- **Encrypted key storage** — `xsec key set` stores API keys in the OS keyring
  (macOS Keychain / Windows Credential Manager / Linux Secret Service),
  encrypted at rest. Keys are read into memory only at request time and are
  never written to a plaintext file or shell history.
- **Minimal egress** — only the file under review (truncated) and your prompt
  are sent to AI providers; nothing else from your environment.

### VS Code extension

- **Workspace Trust** — the extension does nothing in untrusted folders, so
  opening a malicious repo cannot trigger it.
- **Machine-scoped executable** — `xsec.executable` and `xsec.extraArgs` can
  only be set in user settings, never by a project's `.vscode/settings.json`.
  This blocks the classic "repo ships a malware binary and repoints the tool"
  attack.
- **No shell** — the CLI is invoked via `execFile` with an argument array
  (`shell: false`), so filenames with shell metacharacters can't be interpreted
  as commands.
- **Trimmed environment** — the child process receives only `PATH`/`HOME` (plus
  the API key when AI is enabled), not the full parent environment.
- **Timeouts and output caps** — a hung or runaway scan can't wedge the editor.

## What XSEC does *not* claim

No software is "unhackable," and XSEC doesn't pretend otherwise. It closes the
well-known attack classes for a tool of this kind; it does not sandbox the
scanned code at the OS level. For maximum isolation when scanning untrusted
code, run XSEC in a container or VM.

## Handling of findings

Scan results can themselves be sensitive (they describe vulnerabilities and may
include code snippets). Reports written with `--html`, `--json`, or `--sarif`
are plain files — store and share them with the same care as the source code.
The example files under `examples/` are **intentionally vulnerable** test
fixtures and contain only fake, clearly-labeled credentials.

## Supported versions

XSEC is pre-1.0; security fixes are applied to the latest `main`.
