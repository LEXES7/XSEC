import { useGSAP } from "@gsap/react";
import { useRef } from "react";
import { gsap, prefersReducedMotion } from "../lib/motion";

const STATS: Array<{ value: number; suffix: string; label: string }> = [
  { value: 4, suffix: "", label: "scan engines" },
  { value: 40, suffix: "+", label: "security rules" },
  { value: 194, suffix: "", label: "tests guarding the scanner" },
  { value: 1, suffix: "", label: "command to scan & fix" },
];

export default function Stats() {
  const root = useRef<HTMLElement>(null);

  useGSAP(
    () => {
      if (prefersReducedMotion()) return;
      gsap.utils.toArray<HTMLElement>(".stat-num").forEach((el) => {
        const target = Number(el.dataset.value || 0);
        const suffix = el.dataset.suffix || "";
        const counter = { v: 0 };
        gsap.to(counter, {
          v: target,
          duration: 1.6,
          ease: "power2.out",
          scrollTrigger: { trigger: el, start: "top 85%", once: true },
          onUpdate: () => {
            el.textContent = `${Math.round(counter.v)}${suffix}`;
          },
        });
      });
    },
    { scope: root }
  );

  return (
    <section className="stats" ref={root}>
      {STATS.map((s) => (
        <div className="stat" key={s.label}>
          <span className="stat-num" data-value={s.value} data-suffix={s.suffix}>
            {s.value}{s.suffix}
          </span>
          <span className="stat-label">{s.label}</span>
        </div>
      ))}
    </section>
  );
}
