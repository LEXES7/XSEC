/* Horizontal scroll-jacked section: the four gates of the fix loop slide
   past while the page scrolls vertically, ending on a live-flipping diff. */

import { useGSAP } from "@gsap/react";
import { useRef } from "react";
import { gsap, prefersReducedMotion } from "../lib/motion";

export default function FixLoop() {
  const root = useRef<HTMLElement>(null);
  const track = useRef<HTMLDivElement>(null);

  useGSAP(
    () => {
      if (prefersReducedMotion()) return;
      const el = track.current!;
      const distance = () => el.scrollWidth - window.innerWidth;

      const tl = gsap.timeline({
        scrollTrigger: {
          trigger: root.current,
          start: "top top",
          end: () => `+=${distance() + window.innerHeight * 0.4}`,
          scrub: 0.7,
          pin: true,
          invalidateOnRefresh: true,
        },
        defaults: { ease: "none" },
      });

      tl.to(el, { x: () => -distance() }, 0);
      tl.to(".fixloop-progress-fill", { width: "100%" }, 0);

      // the diff flips red→green as the last card arrives
      tl.fromTo(".dl-add", { opacity: 0.15 }, { opacity: 1, stagger: 0.04, duration: 0.12 }, 0.78);
      tl.to(".dl-del", { opacity: 0.28, duration: 0.12 }, 0.78);

      gsap.from(".gate", {
        opacity: 0,
        y: 40,
        stagger: 0.08,
        duration: 0.6,
        ease: "power2.out",
        scrollTrigger: { trigger: root.current, start: "top 70%" },
      });
    },
    { scope: root }
  );

  return (
    <section className="fixloop" id="fixloop" ref={root}>
      <div className="fixloop-head">
        <p className="section-eyebrow">02 // the fix loop</p>
        <h2 className="section-title">The model proposes. The scanner disposes.</h2>
        <p className="section-sub">
          <code>--ai-fix</code> rewrites your code — but nothing touches disk until
          every gate passes.
        </p>
      </div>

      <div className="fixloop-viewport">
        <div className="fixloop-track" ref={track}>
          <div className="gate">
            <span className="gate-num">GATE 01</span>
            <h3>SCAN</h3>
            <p>
              Four engines sweep the tree — AST analysis for Python, tree-sitter for
              JS/TS/Java, AI review, dependency CVEs — and agree on one finding format.
            </p>
          </div>

          <div className="gate">
            <span className="gate-num">GATE 02</span>
            <h3>REWRITE</h3>
            <p>
              The AI receives the file and its findings, and returns a corrected
              version. Whole-file, behavior-preserving, secrets moved to the
              environment.
            </p>
          </div>

          <div className="gate gate-verify">
            <span className="gate-num">GATE 03</span>
            <h3>VERIFY</h3>
            <p>The rewrite is interrogated before it earns a write:</p>
            <ul>
              <li>parses cleanly</li>
              <li>sane size — no truncation, no hallucinated rewrite</li>
              <li>re-scan proves the finding is <strong>gone</strong></li>
              <li>zero new findings introduced</li>
            </ul>
          </div>

          <div className="gate gate-diff">
            <span className="gate-num">GATE 04</span>
            <h3>WRITE</h3>
            <pre>
              <span className="dl-meta">@@ api/users.py @@</span>
              <span className="dl-del">- cur.execute(f"SELECT * FROM users WHERE id = {"{uid}"}")</span>
              <span className="dl-add">+ cur.execute("SELECT * FROM users WHERE id = ?", (uid,))</span>
              <span className="dl-meta">@@ api/config.py @@</span>
              <span className="dl-del">- AWS_KEY = "AKIA…REDACTED"</span>
              <span className="dl-add">+ AWS_KEY = os.environ["AWS_ACCESS_KEY_ID"]</span>
              <span className="dl-meta">@@ api/loader.py @@</span>
              <span className="dl-del">- return yaml.load(raw)</span>
              <span className="dl-add">+ return yaml.safe_load(raw)</span>
            </pre>
            <p>Only then does the diff hit your disk — shown in full, line by line.</p>
          </div>
        </div>
        <div className="fixloop-progress" aria-hidden="true">
          <div className="fixloop-progress-fill" />
        </div>
      </div>
    </section>
  );
}
