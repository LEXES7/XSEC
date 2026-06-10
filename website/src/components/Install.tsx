import { useState } from "react";

const COMMANDS = [
  { id: "core", cmd: "pip install xsec" },
  { id: "scan", cmd: "xsec scan . --fix" },
  { id: "full", cmd: "xsec scan . --ai --deps --ai-fix" },
];

const EXTRAS = [
  ["[ai]", "Claude review"],
  ["[treesitter]", "syntax-aware JS/Java"],
  ["[deps]", "CVE scan"],
  ["[secure]", "keyring storage"],
];

export default function Install() {
  const [copied, setCopied] = useState<string | null>(null);

  const copy = async (id: string, cmd: string) => {
    try {
      await navigator.clipboard.writeText(cmd);
      setCopied(id);
      setTimeout(() => setCopied(null), 1600);
    } catch {
      /* clipboard unavailable; nothing to break */
    }
  };

  return (
    <section className="section" id="install">
      <p className="section-eyebrow">05 // deploy the shield</p>
      <h2 className="section-title">Sixty seconds to a safer repo.</h2>
      <p className="section-sub">Python 3.10+. Offline core; add only the capabilities you want.</p>

      <div className="install-cmds">
        {COMMANDS.map(({ id, cmd }) => (
          <div className="install-cmd" key={id}>
            <code>{cmd}</code>
            <button
              className={`copy-btn${copied === id ? " copied" : ""}`}
              onClick={() => copy(id, cmd)}
              aria-label={`Copy: ${cmd}`}
            >
              {copied === id ? "copied" : "copy"}
            </button>
          </div>
        ))}
      </div>

      <div className="install-extras">
        {EXTRAS.map(([extra, label]) => (
          <span className="extra-chip" key={extra}>
            + <code>{extra}</code> {label}
          </span>
        ))}
      </div>

      <div className="ide-strip">
        <h3>Also lives in your editor &amp; CI</h3>
        <p>
          VS Code extension with inline squiggles and one-click fix · SARIF for GitHub code
          scanning · <code>--fail-on HIGH</code> exit codes for CI gates · <code>.xsec.toml</code>{" "}
          config · baselines for legacy repos · <code># xsec: ignore[RULE]</code> inline
          suppressions.
        </p>
      </div>
    </section>
  );
}
