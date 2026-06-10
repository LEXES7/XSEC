import { useEffect, useState } from "react";
import Engines from "./components/Engines";
import FixLoop from "./components/FixLoop";
import Footer from "./components/Footer";
import Hero from "./components/Hero";
import Install from "./components/Install";
import Loader from "./components/Loader";
import Nav from "./components/Nav";
import Problem from "./components/Problem";
import Stats from "./components/Stats";
import Terminal from "./components/Terminal";
import { initSmoothScroll, ScrollTrigger } from "./lib/motion";

export default function App() {
  const [booted, setBooted] = useState(false);

  useEffect(() => {
    initSmoothScroll();
  }, []);

  useEffect(() => {
    // the loader changes layout when it leaves; recalc pinned scenes
    if (booted) {
      document.body.classList.remove("locked");
      ScrollTrigger.refresh();
    } else {
      document.body.classList.add("locked");
    }
  }, [booted]);

  return (
    <>
      {!booted && <Loader onDone={() => setBooted(true)} />}
      <div className="noise" aria-hidden="true" />
      <div className="vignette" aria-hidden="true" />
      <Nav />
      <main>
        <Hero booted={booted} />
        <Problem />
        <FixLoop />
        <Stats />
        <Engines />
        <Terminal />
        <Install />
      </main>
      <Footer />
    </>
  );
}
