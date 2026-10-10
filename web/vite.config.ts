import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Built into the Python package, served by `osint ui` (Starlette).
// `npm run dev` proxies the API to a running `osint ui --no-open` on port 8765.
export default defineConfig({
  plugins: [react()],
  base: "/",
  build: {
    outDir: "../src/osint/ui/static",
    emptyOutDir: true,
    chunkSizeWarningLimit: 1500,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:8765",
      "/capture": "http://127.0.0.1:8765",
      "/document": "http://127.0.0.1:8765",
      "/report": "http://127.0.0.1:8765",
      "/files": "http://127.0.0.1:8765",
    },
  },
});
