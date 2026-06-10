/* One place that owns smooth scrolling (Lenis) and its GSAP wiring. */

import gsap from "gsap";
import { ScrollTrigger } from "gsap/ScrollTrigger";
import Lenis from "lenis";

gsap.registerPlugin(ScrollTrigger);

export const prefersReducedMotion = () =>
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

let lenis: Lenis | null = null;

export function initSmoothScroll(): Lenis | null {
  if (prefersReducedMotion()) return null;
  if (lenis) return lenis;

  lenis = new Lenis({ lerp: 0.1, smoothWheel: true });
  lenis.on("scroll", ScrollTrigger.update);
  gsap.ticker.add((time) => lenis!.raf(time * 1000));
  gsap.ticker.lagSmoothing(0);
  return lenis;
}

export function scrollToSection(selector: string): void {
  const target = document.querySelector(selector);
  if (!target) return;
  if (lenis) {
    lenis.scrollTo(target as HTMLElement, { offset: -70 });
  } else {
    (target as HTMLElement).scrollIntoView({ behavior: "smooth" });
  }
}

export { gsap, ScrollTrigger };
