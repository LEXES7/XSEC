import { useGSAP } from "@gsap/react";
import { lazy, Suspense, useRef } from "react";
import { gsap, prefersReducedMotion, scrollToSection } from "../lib/motion";

const HeroScene = lazy(() => import("./HeroScene"));

/* split a line into per-character spans, keeping words unbreakable */
function Chars({ text }: { text: string }) {
  return (
    <>
      {text.split(" ").map((word, w) => (
        <span className="word" key={w}>
          {word.split("").map((ch, i) => (
            <span className="char" key={i}>{ch}</span>
          ))}
          {w < text.split(" ").length - 1 ? " " : ""}
        </span>
      ))}
    </>
  );
}

export default function Hero({ booted }: { booted: boolean }) {
  const root = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      if (!booted || prefersReducedMotion()) return;
      const tl = gsap.timeline({ defaults: { ease: "power3.out" } });
      tl.from(".hero-title .char", {
        yPercent: 120,
        opacity: 0,
        rotateX: -45,
        stagger: 0.022,
        duration: 0.9,
      })
        .from(".hero-eyebrow", { opacity: 0, y: 14, duration: 0.5 }, 0.15)
        .from(".hero-sub", { opacity: 0, y: 22, duration: 0.7 }, "-=0.5")
        .from(".hero-actions .btn", { opacity: 0, y: 18, stagger: 0.1, duration: 0.5 }, "-=0.4")
        .from(".scroll-cue", { opacity: 0, duration: 0.6 }, "-=0.2");

      // content gently recedes as you scroll into the story
      gsap.to(".hero-content", {
        opacity: 0,
        y: -90,
        scale: 0.96,
        ease: "none",
        scrollTrigger: {
          trigger: root.current,
          start: "top top",
          end: "85% top",
          scrub: true,
        },
      });
    },
    { scope: root, dependencies: [booted] }
  );

  return (
    <header className="hero" ref={root} id="top">
      {!prefersReducedMotion() && (
        <Suspense fallback={null}>
          <HeroScene />
        </Suspense>
      )}
      <div className="hero-content">
        <p className="hero-eyebrow">// security scanner for the AI coding era</p>
        <h1 className="hero-title" aria-label="Hunt the vulns your AI assistant left behind">
          <Chars text="HUNT THE VULNS" />
          <span className="hero-title-sub">
            <Chars text="your AI assistant left behind" />
          </span>
        </h1>
        <p className="hero-sub">
          AI writes code that <em>runs</em> — not code that's <em>safe</em>.
          XSEC finds the <code>eval</code>, the <code>shell=True</code>, the hardcoded
          key, the injectable query… <strong>and rewrites them for you, verified.</strong>
        </p>
        <div className="hero-actions">
          <button className="btn btn-primary" onClick={() => scrollToSection("#install")}>
            ⌁ Install XSEC
          </button>
          <a
            className="btn btn-ghost"
            href="https://github.com/LEXES7/XSEC"
            target="_blank"
            rel="noopener noreferrer"
          >
            View source ↗
          </a>
        </div>
      </div>
      <div className="scroll-cue">scroll</div>
    </header>
  );
}
