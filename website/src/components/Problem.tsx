/* Pinned scrollytelling: as the user scrolls through ~3 viewport heights,
   a scan beam sweeps the editor, vulnerable lines get flagged one by one,
   and the copy on the left advances through the story. */

import { useGSAP } from "@gsap/react";
import { Fragment, useRef } from "react";
import { gsap, prefersReducedMotion } from "../lib/motion";

interface CodeLine {
  n: number;
  html: string;
  flag?: { tag: string; crit?: boolean };
}

const CODE: CodeLine[] = [
  { n: 1, html: '<span class="tok-kw">import</span> yaml, sqlite3' },
  { n: 2, html: "" },
  { n: 3, html: 'AWS_KEY = <span class="tok-str">"AKIA…REDACTED"</span>', flag: { tag: "PY-SECRET-AWS", crit: true } },
  { n: 4, html: "" },
  { n: 5, html: '<span class="tok-kw">def</span> <span class="tok-fn">get_user</span>(uid):' },
  { n: 6, html: '    q = <span class="tok-str">f"SELECT * FROM users</span>' },
  { n: 7, html: '<span class="tok-str">         WHERE id = {uid}"</span>' },
  { n: 8, html: "    cur.<span class=\"tok-fn\">execute</span>(q)", flag: { tag: "PY-SQL-INJECTION" } },
  { n: 9, html: "" },
  { n: 10, html: '<span class="tok-kw">def</span> <span class="tok-fn">load_cfg</span>(raw):' },
  { n: 11, html: "    <span class=\"tok-kw\">return</span> yaml.<span class=\"tok-fn\">load</span>(raw)", flag: { tag: "PY-YAML-LOAD" } },
];

const STEPS = [
  {
    title: "It looks fine. It runs.",
    body: "The demo works, the tests pass, the PR is green. This is exactly the code AI assistants ship every day.",
    sev: null as string | null,
  },
  {
    title: "A key, hardcoded.",
    body: "One paste from a config into source and your AWS account is in git history forever. XSEC's provider-anchored patterns catch it on save.",
    sev: "crit",
  },
  {
    title: "SQL built from an f-string.",
    body: "The classic. uid arrives from a request and lands in the query. XSEC's AST rules see the f-string reach execute() — comments and lookalikes don't fool it.",
    sev: "high",
  },
  {
    title: "And the quiet one.",
    body: "yaml.load without a safe loader can construct arbitrary objects. This one XSEC doesn't just find — it fixes it for you.",
    sev: "high",
  },
];

export default function Problem() {
  const root = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      if (prefersReducedMotion()) {
        gsap.set(".problem-step", { position: "static", opacity: 1 });
        gsap.set(".flag-tag", { opacity: 1, x: 0 });
        return;
      }

      gsap.set(".problem-step:first-child", { opacity: 1 });

      const tl = gsap.timeline({
        defaults: { ease: "none" },
        scrollTrigger: {
          trigger: root.current,
          start: "top top",
          end: "+=320%",
          scrub: 0.6,
          pin: true,
        },
      });

      const lines = gsap.utils.toArray<HTMLElement>(".code-line");
      const flagged = gsap.utils.toArray<HTMLElement>(".code-line[data-flag]");
      const beamTravel = () => {
        const body = document.querySelector(".editor-body") as HTMLElement;
        return body ? body.offsetHeight - 46 : 300;
      };

      // 0 → editor lines materialize
      tl.from(lines, { opacity: 0, x: -16, stagger: 0.05, duration: 0.5 }, 0);

      // beam sweeps down the editor across the whole timeline
      tl.set(".scanbeam", { opacity: 1 }, 0.55);
      tl.to(".scanbeam", { y: beamTravel, duration: 2.7 }, 0.55);
      tl.to(".scanbeam", { opacity: 0, duration: 0.15 }, 3.25);

      // step copy crossfades; findings pop as the beam passes them
      const stepEls = gsap.utils.toArray<HTMLElement>(".problem-step");
      const beats = [0.9, 1.8, 2.7]; // when findings 1..3 fire on the timeline
      beats.forEach((at, i) => {
        tl.to(stepEls[i], { opacity: 0, y: -14, duration: 0.18 }, at - 0.18);
        tl.fromTo(stepEls[i + 1], { opacity: 0, y: 14 }, { opacity: 1, y: 0, duration: 0.18 }, at);
        const line = flagged[i];
        if (line) {
          tl.to(line, {
            backgroundColor: line.dataset.flag === "crit"
              ? "rgba(255,63,216,0.10)"
              : "rgba(255,92,122,0.10)",
            duration: 0.12,
          }, at);
          tl.to(line.querySelector(".flag-tag"), { opacity: 1, x: 0, duration: 0.16 }, at + 0.05);
        }
      });

      // hold a beat at the end so the last step breathes
      tl.to({}, { duration: 0.4 });
    },
    { scope: root }
  );

  return (
    <section className="problem" id="problem" ref={root}>
      <div className="problem-stage">
        <div className="problem-copy">
          <p className="section-eyebrow">01 // the threat</p>
          <h2 className="section-title">Shipped in seconds. Exploitable for years.</h2>
          <div className="problem-steps">
            {STEPS.map((s, i) => (
              <div className="problem-step" key={i}>
                <h3>
                  {s.sev === "crit" && <span className="sev sev-crit">CRITICAL</span>}
                  {s.sev === "high" && <span className="sev sev-high">HIGH</span>}
                  {s.title}
                </h3>
                <p>{s.body}</p>
              </div>
            ))}
          </div>
        </div>

        <div className="editor" aria-label="Code editor showing vulnerabilities being detected">
          <div className="editor-bar">
            <span className="editor-dot" style={{ background: "#ff5f57" }} />
            <span className="editor-dot" style={{ background: "#febc2e" }} />
            <span className="editor-dot" style={{ background: "#28c840" }} />
            <span style={{ marginLeft: 10 }}>api/users.py — written by your assistant</span>
          </div>
          <div className="editor-body">
            <div className="scanbeam" aria-hidden="true" />
            {CODE.map((line) => (
              <Fragment key={line.n}>
                <div
                  className={`code-line${line.flag ? " flagged" : ""}${line.flag?.crit ? " flag-crit" : ""}`}
                  {...(line.flag ? { "data-flag": line.flag.crit ? "crit" : "high" } : {})}
                >
                  <span className="code-ln">{line.n}</span>
                  <span className="code-text" dangerouslySetInnerHTML={{ __html: line.html || " " }} />
                  {line.flag && <span className="flag-tag" style={{ opacity: 0 }}>{line.flag.tag}</span>}
                </div>
              </Fragment>
            ))}
          </div>
        </div>
      </div>
    </section>
  );
}
