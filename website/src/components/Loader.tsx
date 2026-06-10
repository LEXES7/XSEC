import { useEffect, useRef } from "react";
import { gsap, prefersReducedMotion } from "../lib/motion";

const BOOT_LINES = [
  "LOADING RULE PACKS …",
  "ARMING ENGINES: SAST · AI · DEPS · FIX",
  "CALIBRATING SCAN BEAM …",
  "SHIELD ONLINE",
];

export default function Loader({ onDone }: { onDone: () => void }) {
  const rootRef = useRef<HTMLDivElement>(null);
  const fillRef = useRef<HTMLDivElement>(null);
  const lineRef = useRef<HTMLParagraphElement>(null);

  useEffect(() => {
    if (prefersReducedMotion()) {
      onDone();
      return;
    }
    const tl = gsap.timeline({
      onComplete: () => {
        gsap.to(rootRef.current, {
          opacity: 0,
          duration: 0.5,
          ease: "power2.inOut",
          onComplete: onDone,
        });
      },
    });
    tl.to(fillRef.current, { width: "100%", duration: 1.7, ease: "power2.inOut" }, 0);
    BOOT_LINES.forEach((text, i) => {
      tl.call(() => {
        if (lineRef.current) lineRef.current.textContent = text;
      }, [], i * 0.42);
    });
    return () => {
      tl.kill();
    };
  }, [onDone]);

  return (
    <div className="loader" ref={rootRef} role="status" aria-label="Loading XSEC">
      <img className="loader-logo" src="./assets/icon.png" alt="" />
      <div className="loader-bar">
        <div className="loader-fill" ref={fillRef} />
      </div>
      <p className="loader-line" ref={lineRef}>BOOTING XSEC …</p>
    </div>
  );
}
