import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: "./e2e",
  fullyParallel: true,
  workers: 2,
  globalSetup: "./e2e/global-setup.ts",
  retries: 0,
  reporter: [["line"], ["json", { outputFile: "artifacts/e2e-results.json" }]],
  use: {
    baseURL: "http://127.0.0.1:1422",
    // Feature tests start after onboarding. The first-launch instruction tests
    // explicitly use an empty profile and still exercise the automatic guide.
    storageState: { cookies: [], origins: [{ origin: "http://127.0.0.1:1422", localStorage: [{ name: "yougori.instructions.seen.v1", value: "1" }] }] },
    screenshot: "off",
    trace: "off",
    video: "off",
  },
  webServer: {
    // Never reuse or stop a developer's live Tauri/Vite session on port 1420.
    command: "npx vite --host 127.0.0.1 --port 1422 --strictPort",
    env: { VITE_YOUGORI_TEST_ADAPTER: "1", YOUGORI_E2E_CACHE: "node_modules/.vite-tests-main" },
    url: "http://127.0.0.1:1422",
    reuseExistingServer: false,
  },
  projects: [
    {
      name: "desktop-chrome",
      // Installed Chrome keeps itself patched; Playwright's bundled Chromium lags
      // behind and runs unsandboxed unless chromiumSandbox is set.
      use: { ...devices["Desktop Chrome"], channel: process.env.PLAYWRIGHT_BROWSER_CHANNEL || "chrome", launchOptions: { chromiumSandbox: true }, viewport: { width: 1440, height: 920 } },
    },
  ],
})
