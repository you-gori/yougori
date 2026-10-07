import { chromium, expect, type FullConfig } from "@playwright/test"

// Warm a clean, disposable browser context before timed interaction tests.
// This waits on actual app readiness, not a sleep, and captures no images.
export default async function setup(config: FullConfig) {
  const use = config.projects[0]!.use
  const browser = await chromium.launch({ channel: use.channel })
  try {
    const page = await browser.newPage()
    page.on("pageerror", error => console.error("Startup error:", error.message))
    page.on("console", message => { if (message.type() === "error") console.error("Startup:", message.text()) })
    await page.goto(use.baseURL!, { timeout: 90_000 })
    // Navigation now completes at the lightweight loading document, before
    // Vite finishes compiling the dynamically loaded application on a cold run.
    await expect(page.getByRole("group", { name: "Dashboard actions" })).toBeVisible({ timeout: 90_000 })
    await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 30_000 })
  } finally {
    await browser.close()
  }
}
