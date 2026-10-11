import { defineConfig, devices } from "@playwright/test"

export default defineConfig({
  testDir: "./e2e",
  testMatch: ["environment-graph.spec.ts", "host-terminal.spec.ts", "instructions.spec.ts", "startup.spec.ts", "neocloud.spec.ts"],
  fullyParallel: true,
  workers: 2,
  globalSetup: "./e2e/global-setup.ts",
  reporter: "line",
  use: {
    ...devices["Desktop Chrome"],
    channel: process.env.PLAYWRIGHT_BROWSER_CHANNEL || "chromium",
    viewport: { width: 1280, height: 1000 },
    baseURL: "http://127.0.0.1:1421",
    // Existing feature tests represent returning users. First-launch tests
    // explicitly override this with a fresh profile.
    storageState: { cookies: [], origins: [{ origin: "http://127.0.0.1:1421", localStorage: [{ name: "yougori.instructions.seen.v1", value: "1" }] }] },
    screenshot: "off",
    trace: "off",
    video: "off",
  },
  webServer: {
    command: "npx vite --host 127.0.0.1 --port 1421 --strictPort",
    env: { VITE_YOUGORI_TEST_ADAPTER: "1", YOUGORI_E2E_CACHE: "node_modules/.vite-tests-graph" },
    url: "http://127.0.0.1:1421",
    reuseExistingServer: false,
  },
})
