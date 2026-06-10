/* Engine cards with pointer-tracking 3D tilt + glow. */

import { useGSAP } from "@gsap/react";
import { useRef } from "react";
import type { MouseEvent } from "react";
import { gsap, prefersReducedMotion } from "../lib/motion";

const ENGINES = [
  {
    icon: "⌖",
    name: "SAST",
    tag: "offline",
    body: "AST analysis for Python, tree-sitter syntax awareness for JS/TS/Java. SQL injection, command injection, deserialization, XXE, JWT bypass, weak crypto — without comment/string false positives.",
  },
  {
    icon: "◉",
    name: "AI REVIEW",
    tag: "opt-in",
    body: "Reads code like a senior reviewer: broken auth, logic flaws, unsafe data flow — any language. Claude for best quality, or free via Groq/OpenRouter. Concurrent and content-hash cached.",
  },
  {
    icon: "⟁",
    name: "AUTO-FIX",
    tag: "offline*",
    body: "AST-precise mechanical rewrites, plus AI rewrites that must survive the verification gauntlet before they touch disk. Safe fixes by default; behavior-changing ones behind a flag.",
  },
  {
    icon: "⛁",
    name: "DEPS / CVE",
    tag: "opt-in",
    body: "Manifests and lockfiles — package-lock.json, poetry.lock, uv.lock — against the OSV database. Every pinned transitive dependency, only names + versions ever leave your machine.",
  },
  {
    icon: "⌗",
    name: "SECRETS",
    tag: "offline",
    body: "Provider-anchored patterns for AWS, GitHub, Stripe, Slack, Google, Anthropic and OpenAI keys. High precision, placeholder-aware, shared across every supported language.",
  },
  {
    icon: "⛨",
    name: "HARDENED CORE",
    tag: "offline",
    body: "XSEC treats scanned code as hostile: size limits, no symlink following, ReDoS-resistant rules, binary skipping. Fully offline unless you explicitly opt a network engine in.",
  },
];

function tilt(e: MouseEvent<HTMLDivElement>) {
  const card = e.currentTarget;
  const r = card.getBoundingClientRect();
  const px = (e.clientX - r.left) / r.width;
  const py = (e.clientY - r.top) / r.height;
  card.style.setProperty("--mx", `${px * 100}%`);
  card.style.setProperty("--my", `${py * 100}%`);
  card.style.transform =
    `perspective(900px) rotateY(${(px - 0.5) * 10}deg) rotateX(${(0.5 - py) * 8}deg) translateY(-4px)`;
}

function untilt(e: MouseEvent<HTMLDivElement>) {
  e.currentTarget.style.transform = "perspective(900px) rotateY(0deg) rotateX(0deg)";
}

export default function Engines() {
  const root = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      if (prefersReducedMotion()) return;
      gsap.from(".engine-card", {
        opacity: 0,
        y: 48,
        stagger: 0.09,
        duration: 0.7,
        ease: "power3.out",
        scrollTrigger: { trigger: root.current, start: "top 72%", once: true },
      });
    },
    { scope: root }
  );

  return (
    <section className="section" id="engines" ref={root}>
      <p className="section-eyebrow">03 // the arsenal</p>
      <h2 className="section-title">Six layers. One finding format.</h2>
      <p className="section-sub">
        Every engine emits the same <code>Finding</code> — so the console, JSON, SARIF,
        HTML report and the VS Code extension all work identically.
      </p>
      <div className="engines-grid">
        {ENGINES.map((e) => (
          <div className="engine-card" key={e.name} onMouseMove={tilt} onMouseLeave={untilt}>
            <div className="glow" aria-hidden="true" />
            <div className="engine-icon">{e.icon}</div>
            <h3>{e.name}</h3>
            <p>{e.body}</p>
            <span className={`engine-tagline ${e.tag.startsWith("opt") ? "tg-optin" : "tg-offline"}`}>
              {e.tag}
            </span>
          </div>
        ))}
      </div>
      <p className="section-sub" style={{ fontSize: "0.8rem", marginTop: 18 }}>
        * mechanical fixes are offline; <code>--ai-fix</code> uses your chosen AI provider.
      </p>
    </section>
  );
}
