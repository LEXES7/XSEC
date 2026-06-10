/* XSEC site: starfield, terminal demo, copy buttons.
   No dependencies; respects prefers-reduced-motion. */

"use strict";

const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/* ------------------------- starfield ------------------------- */

(function starfield() {
  const canvas = document.getElementById("starfield");
  const ctx = canvas.getContext("2d");
  let stars = [];

  function resize() {
    canvas.width = window.innerWidth;
    canvas.height = window.innerHeight;
    const count = Math.min(220, Math.floor((canvas.width * canvas.height) / 9000));
    stars = Array.from({ length: count }, () => ({
      x: Math.random() * canvas.width,
      y: Math.random() * canvas.height,
      r: Math.random() * 1.3 + 0.2,
      v: Math.random() * 0.05 + 0.01,           // drift speed
      tw: Math.random() * Math.PI * 2,           // twinkle phase
      hue: Math.random() < 0.12 ? "0,240,255" : "207,227,239",
    }));
  }

  function frame(t) {
    ctx.clearRect(0, 0, canvas.width, canvas.height);
    for (const s of stars) {
      const alpha = 0.35 + 0.55 * Math.abs(Math.sin(s.tw + t / 1600));
      ctx.fillStyle = `rgba(${s.hue},${alpha})`;
      ctx.beginPath();
      ctx.arc(s.x, s.y, s.r, 0, Math.PI * 2);
      ctx.fill();
      s.y += s.v;                                // slow downward drift
      if (s.y > canvas.height + 2) s.y = -2;
    }
    requestAnimationFrame(frame);
  }

  window.addEventListener("resize", resize);
  resize();
  if (reducedMotion) {
    frame(0); // a single static render
  } else {
    requestAnimationFrame(frame);
  }
})();

/* ------------------------- terminal demo ------------------------- */

const SCRIPT = [
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

(function terminal() {
  const body = document.getElementById("termBody");
  if (!body) return;

  const PROMPT = '<span class="t-prompt">➜  myapp</span> <span class="t-dim">git:(main)</span> ';

  if (reducedMotion) {
    body.innerHTML =
      PROMPT + '<span class="t-cmd">' + SCRIPT[0].text + "</span>\n" +
      SCRIPT.slice(1).map((l) => l.html).join("\n");
    return;
  }

  let lineIdx = 0;
  let charIdx = 0;
  let rendered = "";

  function showCursor(html) {
    body.innerHTML = html + '<span class="cursor"></span>';
  }

  function step() {
    const line = SCRIPT[lineIdx];

    if (!line) {
      // loop: hold the finished screen, then start over
      setTimeout(() => {
        lineIdx = 0; charIdx = 0; rendered = "";
        showCursor(PROMPT);
        setTimeout(step, 900);
      }, 6500);
      return;
    }

    if (line.type === "cmd") {
      if (charIdx === 0) rendered += PROMPT;
      if (charIdx < line.text.length) {
        const typed = line.text.slice(0, ++charIdx);
        showCursor(rendered + '<span class="t-cmd">' + typed + "</span>");
        setTimeout(step, 38 + Math.random() * 50);
        return;
      }
      rendered += '<span class="t-cmd">' + line.text + "</span>\n";
      charIdx = 0;
      lineIdx++;
      showCursor(rendered);
      setTimeout(step, 700);
      return;
    }

    rendered += line.html + "\n";
    lineIdx++;
    showCursor(rendered);
    // findings appear quickly; pauses around the AI-fix beats
    const pause = line.html === "" ? 350 : line.html.includes("asking the model") ? 1200 : 240;
    setTimeout(step, pause);
  }

  showCursor(PROMPT);
  setTimeout(step, 800);
})();

/* ------------------------- copy buttons ------------------------- */

document.querySelectorAll(".copy-btn").forEach((btn) => {
  btn.addEventListener("click", async () => {
    const code = document.getElementById(btn.dataset.copy);
    try {
      await navigator.clipboard.writeText(code.textContent.trim());
      btn.textContent = "copied";
      btn.classList.add("copied");
      setTimeout(() => {
        btn.textContent = "copy";
        btn.classList.remove("copied");
      }, 1600);
    } catch {
      /* clipboard unavailable (http, old browser): select the text instead */
      const range = document.createRange();
      range.selectNodeContents(code);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
  });
});
