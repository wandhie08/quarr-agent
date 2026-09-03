import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Build to dist/; served by FastAPI. Dev proxies /api and /ws to the backend.
export default defineConfig({
  plugins: [react()],
  build: { outDir: "dist", emptyOutDir: true },
  server: {
    proxy: {
      "/api": "http://127.0.0.1:8000",
      "/ws": { target: "ws://127.0.0.1:8000", ws: true },
    },
  },
});
