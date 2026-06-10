/* The typing terminal demo: starts when scrolled into view, loops forever. */

import { useEffect, useRef } from "react";
import { prefersReducedMotion } from "../lib/motion";

type Line = { type: "cmd"; text: string } | { type: "out"; html: string };

const SCRIPT: Line[] = [
  { type: "cmd", text: "xsec scan . --ai-fix" },
  { type: "out", html: '<span class="t-dim">discovering files… 42 scanned · 4 engines</span>' },
  { type: "out", html: "" },
  { type: "out", html: '<span class="t-crit">CRITICAL</span>  app/config.py:8   <span class="t-cyan">PY-SECRET-AWS</span>  hardcoded AWS access key' },
  { type: "out", html: '<span class="t-high">HIGH</span>      app/db.py:23      <span class="t-cyan">PY-SQL-INJECTION</span>  SQL built from runtime values' },
  { type: "out", html: '<span class="t-high">HIGH</span>      app/loader.py:14  <span class="t-cyan">PY-YAML-LOAD</span>  yaml.load without safe Loader' },
  { type: "out", html: '<span class="t-med">MEDIUM</span>    web/ui.js:31      <span class="t-cyan">JS-INNERHTML</span>  DOM XSS sink' },
  { type: "out", html: "" },
  { type: "out", html: '<span class="t-dim">AI fix: asking the model to rewrite affected files…</span>' },
  { type: "out", html: '<span class="t-ok">✓</span> app/db.py — verified: finding gone, none introduced' },
  { type: "out", html: '<span class="t-del">-    cur.execute(f"SELECT * FROM users WHERE id = {uid}")</span>' },
  { type: "out", html: '<span class="t-add">+    cur.execute("SELECT * FROM users WHERE id = ?", (uid,))</span>' },
  { type: "out", html: '<span class="t-ok">✓</span> app/loader.py — verified' },
  { type: "out", html: '<span class="t-del">-    data = yaml.load(payload)</span>' },
  { type: "out", html: '<span class="t-add">+    data = yaml.safe_load(payload)</span>' },
  { type: "out", html: "" },
  { type: "out", html: '<span class="t-ok">shield restored:</span> 2 fixed · 2 reported with remediation' },
];

const PROMPT = '<span class="t-prompt">➜  myapp</span> <span class="t-dim">git:(main)</span> ';

export default function Terminal() {
  const bodyRef = useRef<HTMLPreElement>(null);
  const started = useRef(false);

  useEffect(() => {
    const body = bodyRef.current;
    if (!body) return;

    if (prefersReducedMotion()) {
      body.innerHTML =
        PROMPT + `<span class="t-cmd">${SCRIPT[0].type === "cmd" ? SCRIPT[0].text : ""}</span>\n` +
        SCRIPT.slice(1).map((l) => (l.type === "out" ? l.html : "")).join("\n");
      return;
    }

    let timer: ReturnType<typeof setTimeout>;
    let lineIdx = 0;
    let charIdx = 0;
    let rendered = "";

    const show = (html: string) => {
      body.innerHTML = html + '<span class="t-cursor"></span>';
    };

    const step = () => {
      const line = SCRIPT[lineIdx];
      if (!line) {
        timer = setTimeout(() => {
          lineIdx = 0; charIdx = 0; rendered = "";
          show(PROMPT);
          timer = setTimeout(step, 900);
        }, 6500);
        return;
      }
      if (line.type === "cmd") {
        if (charIdx === 0) rendered += PROMPT;
        if (charIdx < line.text.length) {
          const typed = line.text.slice(0, ++charIdx);
          show(rendered + `<span class="t-cmd">${typed}</span>`);
          timer = setTimeout(step, 38 + Math.random() * 50);
          return;
        }
        rendered += `<span class="t-cmd">${line.text}</span>\n`;
        charIdx = 0;
        lineIdx++;
        show(rendered);
        timer = setTimeout(step, 700);
        return;
      }
      rendered += line.html + "\n";
      lineIdx++;
      show(rendered);
      const pause = line.html === "" ? 350 : line.html.includes("asking the model") ? 1200 : 240;
      timer = setTimeout(step, pause);
    };

    const observer = new IntersectionObserver(
      (entries) => {
        if (entries[0].isIntersecting && !started.current) {
          started.current = true;
          show(PROMPT);
          timer = setTimeout(step, 600);
        }
      },
      { threshold: 0.35 }
    );
    observer.observe(body);

    return () => {
      observer.disconnect();
      clearTimeout(timer);
    };
  }, []);

  return (
    <section className="section" id="terminal">
      <p className="section-eyebrow">04 // live fire</p>
      <h2 className="section-title">One command. Watch it work.</h2>
      <div className="terminal-wrap">
        <div className="terminal" role="img" aria-label="Animated terminal demo of an xsec scan finding and fixing vulnerabilities">
          <div className="terminal-bar">
            <span className="t-dot" style={{ background: "#ff5f57" }} />
            <span className="t-dot" style={{ background: "#febc2e" }} />
            <span className="t-dot" style={{ background: "#28c840" }} />
            <span className="terminal-title">xsec — zsh</span>
          </div>
          <pre className="terminal-body" ref={bodyRef} />
        </div>
      </div>
    </section>
  );
}
