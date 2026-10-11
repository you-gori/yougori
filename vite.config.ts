import path from "node:path"
import { readFileSync } from "node:fs"
import react from "@vitejs/plugin-react"
import tailwindcss from "@tailwindcss/vite"
import { defineConfig } from "vite"

const host = process.env.TAURI_DEV_HOST
const testAdapter = process.env.VITE_YOUGORI_TEST_ADAPTER === "1"

export default defineConfig({
  // Browser fixtures and the real desktop dev server must not invalidate each
  // other's optimized dependencies when both are running.
  cacheDir: testAdapter ? process.env.YOUGORI_E2E_CACHE || "node_modules/.vite-tests" : "node_modules/.vite",
  // Discover lazy workspace/dialog dependencies before browser tests interact.
  // Otherwise the first open can trigger an optimizer reload and lose a draft.
  optimizeDeps: testAdapter ? { entries: ["index.html", "src/**/*.{ts,tsx}", "!src/**/*.test.{ts,tsx}"] } : undefined,
  plugins: [{
    name: "yougori-startup-styles",
    transformIndexHtml(html) {
      const css = readFileSync(path.resolve(__dirname, "src/startup.css"), "utf8")
      return html.replace("<!-- yougori-startup-styles -->", `<style>${css}</style>`)
    },
  }, react(), tailwindcss()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "./src") },
  },
  clearScreen: false,
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host ? { protocol: "ws", host, port: 1421 } : undefined,
    // Native builds and runtime caches can contain hundreds of thousands of
    // files. Watching them can starve startup/module requests after a build.
    watch: { ignored: ["**/src-tauri/**", "**/target/**", "**/build/**", "**/artifacts/**", "**/test-results*/**", "**/playwright-report/**"] },
    warmup: testAdapter ? { clientFiles: ["./src/main.tsx", "./src/components/guest-workspace.tsx", "./src/components/dialogs/create-environment-dialog.tsx"] } : undefined,
  },
  build: {
    // noVNC uses standards-based module features supported by current Tauri
    // WebViews, including top-level await for WebCodecs capability detection.
    target: "esnext",
    modulePreload: { polyfill: false },
    minify: "esbuild",
    sourcemap: false,
    rollupOptions: {
      output: {
        onlyExplicitManualChunks: true,
        manualChunks(id) {
          const moduleId = id.replaceAll("\\", "/")
          if (moduleId.includes("/node_modules/@novnc/novnc/")) return "vnc-runtime"
          if (
            moduleId.includes("/node_modules/react/")
            || moduleId.includes("/node_modules/react-dom/")
            || moduleId.includes("/node_modules/scheduler/")
          ) return "react-runtime"
          return undefined
        },
      },
    },
  },
})
