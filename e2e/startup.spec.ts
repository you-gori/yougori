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


test("waits for CLI startup before exposing environments", async ({ page }) => {
  await page.addInitScript(() => {
    Object.assign(window, { cliStartupGate: new Promise<void>(resolve => { Object.assign(window, { releaseCliStartup: resolve }) }) })
  })
  await page.route("**/src/api/host-terminal-api.ts*", async route => {
    const response = await route.fetch()
    await route.fulfill({ response, body: (await response.text()) + `
const startupOriginal = hostTerminalApi.terminal; hostTerminalApi.terminal = async request => { if (request.action === "create") await window.cliStartupGate; return startupOriginal(request); };` })
  })
  await page.goto("/")
  await expect(page.getByRole("status")).toHaveText("Starting the CLI…")
  await expect(page.locator("[data-environment-canvas]")).toHaveCount(0)
  await page.evaluate(() => (window as unknown as { releaseCliStartup(): void }).releaseCliStartup())
  await expect(page.locator("[data-environment-canvas]")).toBeVisible()
  const state = await page.evaluate(async () => { const path = "/src/api/platform-api.ts"; return (await import(path)).platformApi.getState() })
  expect(state.cliEnvironmentId).toBeFalsy()
  const sessions = await page.evaluate(async () => { const path = "/src/api/host-terminal-api.ts"; return (await (await import(path)).hostTerminalApi.info()).sessions })
  expect(sessions).toHaveLength(1)
  expect(sessions[0].cwd).toContain("Yougori\\Workspace")
})

test("CLI startup failure shows an actionable error", async ({ page }) => {
  await page.route("**/src/api/host-terminal-api.ts*", async route => {
    const response = await route.fetch()
    await route.fulfill({ response, body: (await response.text()) + `
hostTerminalApi.terminal = async () => { throw new Error("CLI boot failed"); };` })
  })
  await page.goto("/")
  await expect(page.getByRole("alert")).toContainText("CLI boot failed")
  await expect(page.getByRole("button", { name: "Try again" })).toBeVisible()
  await expect(page.locator("[data-environment-canvas]")).toHaveCount(0)
  await page.getByRole("button", { name: "Open Yougori" }).click()
  await expect(page.locator("[data-environment-canvas]")).toBeVisible()
})
