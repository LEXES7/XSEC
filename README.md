# XSEC

A vulnerability scanner aimed at **AI-written code**. LLMs are great at
producing code that runs and terrible at producing code that's safe — they
reach for `shell=True`, `eval`, `verify=False`, and hardcoded keys because
those are the shortest path to "it works". XSEC hunts for exactly those
patterns.

## Engines

XSEC is built around pluggable engines that all emit the same `Finding` shape:

| Engine | Status | What it does |
| ------ | ------ | ------------ |
| **SAST** | ✅ working | AST + regex static analysis for Python (injection, unsafe deserialization, weak crypto, hardcoded secrets, …) |
| **Auto-refactor** | ✅ working | Rewrites unsafe code in place, safely (see below) |
| **AI review** | ✅ working | Opt-in Claude review — semantic, cross-language, structured output |
| **Dependency scan** | 🚧 planned | Checks declared dependencies against known CVEs |

## Install

```bash
pip install -e .          # core (SAST)
pip install -e ".[ai]"    # + AI review engine (anthropic SDK)
pip install -e ".[dev]"   # + pytest
```

## Usage

```bash
xsec scan path/to/code
xsec scan examples/vulnerable.py          # try the bundled sample
xsec scan . --min-severity MEDIUM         # hide low-severity noise
xsec scan . --json                        # machine-readable output
xsec scan . --sarif                       # GitHub code scanning format
xsec scan . --html report.html            # self-contained visual report
xsec scan . --fail-on HIGH                # non-zero exit for CI gating
```

The `--html` report is a single file with no external dependencies — open it
in any browser to click through findings, severity cards, code snippets, and
fix guidance. Great for eyeballing a scan or sharing results.

### Auto-refactor (the headline feature)

XSEC doesn't just report — it can **rewrite the unsafe code for you**, safely:

```bash
xsec scan . --fix                # apply only semantics-preserving fixes
xsec scan . --fix --unsafe-fixes # also apply fixes that may change behavior
```

Fixes are AST-precise (never blind text replace) and every patched file is
re-parsed before being written — if a fix would break the file, it's discarded.

| Fix | Confidence | Applied by |
| --- | --- | --- |
| `yaml.load` → `yaml.safe_load` | safe | `--fix` |
| `hashlib.md5/sha1` → `hashlib.sha256` | risky (digest changes) | `--unsafe-fixes` |
| `debug=True` → `debug=False` | risky | `--unsafe-fixes` |

Issues with no safe mechanical fix (`eval`, `os.system`, `shell=True`,
`pickle`, hardcoded secrets) are reported with remediation guidance instead.

### AI review (opt-in, cross-language)

Rule-based SAST only finds patterns someone wrote a rule for. The AI engine
reads code like a reviewer — catching broken auth, logic flaws, and unsafe
data flows in **any** language. It's off by default; XSEC stays free and
offline unless you ask for it.

```bash
export ANTHROPIC_API_KEY=sk-...
xsec scan . --ai                              # adds Claude review on top of SAST
xsec scan . --ai --ai-model claude-sonnet-4-6 # cheaper for large trees
```

Defaults to `claude-opus-4-8` (most capable — a missed vuln is expensive; drop
to Sonnet via `--ai-model` when scanning big trees). Uses **adaptive thinking**
with `effort: high`, **structured JSON output** (`output_config.format`), and
prompt caching. Per-file API errors are reported without aborting the scan. If
the key or `anthropic` package is missing, the engine is skipped with a note
and the rest of the scan still runs.

## Develop

```bash
pip install -e ".[dev]"
pytest
```

## Layout

```
xsec/
  cli.py            CLI entry point and orchestration
  models.py         Finding / Severity / ScanResult
  discovery.py      file walking + ignore rules
  engines/          sast (done), ai_review + deps (planned)
  rules/python.py   the actual SAST rule definitions
  report/console.py terminal + JSON output
```

## Roadmap

- [x] SAST engine + console/JSON report + CI exit codes
- [x] Auto-refactor engine (`--fix`, safe/risky confidence, re-parse guard)
- [x] SARIF output for GitHub code scanning
- [x] AI review engine (Claude) — opt-in, semantic, cross-language
- [x] HTML report (self-contained, visual)
- [ ] Dependency / CVE scan
- [ ] Dataflow / taint tracking (source → sink)
- [ ] Config file (`.xsec.toml`): suppressions, per-path rules, baseline
- [ ] More languages: JS/TS, then Java
