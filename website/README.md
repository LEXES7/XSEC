# XSEC product site

Vite + React + TypeScript webapp: Three.js (react-three-fiber) 3D hero,
GSAP ScrollTrigger pinned scroll scenes, Lenis smooth scrolling.

```bash
npm install
npm run dev        # local dev server
npm run build      # static build in dist/ (relative base — works on Pages)
npm run preview    # serve the production build
```

Honors `prefers-reduced-motion`: the 3D scene and pinned animations are
skipped and all content renders statically.

Deployed automatically to GitHub Pages on every push to `main` that touches
`website/` — see `.github/workflows/deploy-site.yml`.
