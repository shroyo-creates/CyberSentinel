import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// This React app is only used for the /dashboard page. It is built to
// ../static/dashboard with FIXED (non-hashed) filenames (app.js / app.css)
// so the Flask template (templates/dashboard.html) can reference them
// directly without reading a Vite manifest file.
export default defineConfig({
  plugins: [react()],
  base: "/static/dashboard/",
  build: {
    outDir: "../static/dashboard",
    emptyOutDir: true,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: "app.[ext]",
      },
    },
  },
  server: {
    // During `npm run dev` (http://localhost:5173), proxy API calls to
    // the Flask dev server so the React app can be developed with hot
    // reload while still talking to the real backend.
    proxy: {
      "/api": "http://localhost:5000",
    },
  },
});
