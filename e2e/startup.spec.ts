import { expect, test } from "@playwright/test"

test("shows a styled loading screen before the main app module arrives", async ({ page }) => {
  let release!: () => void
  const held = new Promise<void>(resolve => { release = resolve })
  await page.route("**/src/bootstrap.tsx*", async route => { await held; await route.continue() })
  try {
    await page.goto("/", { waitUntil: "domcontentloaded" })
    const loading = page.getByRole("main", { name: "Loading Yougori" })
    await expect(loading).toBeVisible()
    await expect(loading.locator(".startup-brand")).toHaveText("Yougori")
    await expect(loading).toHaveCSS("display", "grid")
    await expect(loading.locator(".startup-track")).toBeVisible()
  } finally { release() }
  await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
})

test("reports a failed app module instead of leaving an endless loading animation", async ({ page }) => {
  await page.route("**/src/bootstrap.tsx*", route => route.abort())
  await page.goto("/")
  await expect(page.getByRole("alert")).toContainText("Yougori couldn’t load")
  await expect(page.locator(".startup-screen")).toHaveAttribute("aria-busy", "false")
  await expect(page.locator(".startup-track")).toHaveCount(0)
})
