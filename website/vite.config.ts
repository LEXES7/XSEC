import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [react()],
  // relative base so the build works on GitHub Pages, a subpath, or file://
  base: "./",
  build: {
    chunkSizeWarningLimit: 1200,
  },
});
