import { defineConfig } from "vite";
import preact from "@preact/preset-vite";

// The backend serves the page at "/" and its files at "/static/<name>" (one path segment), all under
// Home Assistant's ingress path, so everything is relative: a flat build into app/static, and the
// page itself points at "static/<file>"; files loaded from a script or stylesheet stay relative to it.
// `npm run dev` proxies the API to a local backend (dev/README.md, on :8098).
export default defineConfig({
  base: "./",
  plugins: [preact()],
  build: {
    outDir: "../app/static",
    emptyOutDir: true,
    assetsDir: "",
    target: "es2022",
    assetsInlineLimit: 0,
    reportCompressedSize: true,
  },
  experimental: {
    renderBuiltUrl(filename, { hostType }) {
      return hostType === "html" ? "static/" + filename : { relative: true };
    },
  },
  server: {
    port: 5176,
    proxy: Object.fromEntries(["/api", "/download", "/decoded"].map((p) => [p, "http://127.0.0.1:8098"])),
  },
});
