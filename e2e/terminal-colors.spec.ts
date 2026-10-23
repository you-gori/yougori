import { test, expect, type Locator, type Page } from "@playwright/test"
import seed from "../src/data/seed.json" with { type: "json" }
import type { PlatformState } from "../src/types/platform"

async function checkColors(page: Page, terminal: Locator) {
  // The browser adapter echoes these bytes through the same base64/read path
  // as a PTY. Check real xterm rendering, including program-selected RGB.
  const output = "\x1b[31mRED\x1b[0m \x1b[93mYELLOW\x1b[0m \x1b[96mCYAN\x1b[0m \x1b[38;5;208mORANGE\x1b[0m \x1b[38;2;123;210;156mRGB\x1b[0m PLAIN"
  await page.evaluate(text => navigator.clipboard.writeText(text), output)
  await terminal.locator(".xterm-helper-textarea").focus()
  await page.keyboard.press("Control+Shift+V")
  const screen = terminal.locator(".xterm-screen")
  for (const [word, color] of [["RED", "rgb(197, 15, 31)"], ["YELLOW", "rgb(249, 241, 165)"], ["CYAN", "rgb(97, 214, 214)"], ["ORANGE", "rgb(255, 135, 0)"], ["RGB", "rgb(123, 210, 156)"], ["PLAIN", "rgb(204, 204, 204)"]]) {
    await expect(screen.getByText(word, { exact: true })).toHaveCSS("color", color)
  }
  await expect(screen).not.toContainText("[38;2;")
}

test.beforeEach(async ({ context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"])
})

test("container terminal renders the same colours and preserves program output", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  state.environments = [{
    id: "env-colors", name: "Terminal colours", kind: "container", provider: "yougoriOci", status: "running",
    runtime: "alpine:latest", description: "", createdAt: "2026-01-01T00:00:00Z",
    networkAccess: false, gpuAccess: false, cpuUsage: 0, memoryUsageGb: 0, storageDeltaGb: 0, networkRxMbps: 0,
    resourcePolicy: { cpu: { min: 0.1, preferred: 0.25, max: 0.5, current: 0 }, memoryGb: { min: 0.125, preferred: 0.25, max: 0.5, current: 0 }, priority: "normal", dynamic: false },
  }]
  await page.addInitScript(value => localStorage.setItem("yougori.platform.v1", JSON.stringify(value)), state)
  await page.goto("/?environment=env-colors")
  const terminal = page.getByRole("tabpanel")
  await expect(terminal.locator(".xterm-screen")).toContainText("Yougori test terminal")
  await checkColors(page, terminal)
})
