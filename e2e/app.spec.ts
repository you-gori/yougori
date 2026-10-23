import { expect, test } from "@playwright/test"

test.beforeEach(async ({ page }) => {
  await page.goto("/")
  // Navigation first loads the startup document; wait for the actual app.
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 30_000 })
})

test("first launch is empty and does not invent running environments or GPU availability", async ({ page }) => {
  await expect(page.getByText("Your workspace starts here", { exact: true })).toBeVisible()
  await expect(page.locator("[data-environment-id]")).toHaveCount(0)
  for (const name of ["Instructions", "Create my personal vault MCP", "Run a local model", "Settings", "Add sandbox"]) {
    await expect(page.getByRole("button", { name, exact: true })).toBeVisible()
  }
  await expect(page.getByText("Unavailable", { exact: true })).toBeVisible()
})

test("storage reclamation is reachable and browser preview does not invent freed bytes", async ({ page }) => {
  const action = page.getByRole("button", { name: "Reclaim space", exact: true })
  await action.click()
  const notification = page.getByRole("dialog", { name: "Storage cleanup complete", exact: true })
  await expect(notification).toBeVisible()
  await expect(notification.getByRole("paragraph")).toHaveText("No additional disk space was reclaimed. Storage reclamation requires the desktop runtime.")
  await expect(action).toBeEnabled()
  await expect(page.getByText("Your workspace starts here", { exact: true })).toBeVisible()
})

test("unimplemented computer branches cannot be selected or created", async ({ page }) => {
  await page.getByRole("button", { name: "Add sandbox", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(dialog).toBeVisible()
  await expect(dialog.getByRole("radio", { name: /Computer branch/ })).toHaveCount(0)
  await expect(dialog.getByRole("radio", { name: "Container", exact: true })).toBeChecked()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(page.getByText("Your workspace starts here", { exact: true })).toBeVisible()
})

test("theme changes persist after reloading the application", async ({ page }) => {
  const openAppearance = async () => {
    await page.getByRole("button", { name: "Theme", exact: true }).click()
    return page.getByRole("dialog", { name: "Appearance", exact: true })
  }
  let appearance = await openAppearance()
  await appearance.getByRole("button", { name: "Dark", exact: true }).click()
  await expect(appearance.getByRole("button", { name: "Dark", exact: true })).toHaveAttribute("aria-pressed", "true")
  await appearance.getByRole("button", { name: "Close", exact: true }).click()
  await expect(page.locator("html")).toHaveClass(/dark/)
  await page.reload()
  appearance = await openAppearance()
  await expect(appearance.getByRole("button", { name: "Dark", exact: true })).toHaveAttribute("aria-pressed", "true")
  await appearance.getByRole("button", { name: "Light", exact: true }).click()
  await appearance.getByRole("button", { name: "Close", exact: true }).click()
  await expect(page.locator("html")).not.toHaveClass(/dark/)
  await page.reload()
  appearance = await openAppearance()
  await expect(appearance.getByRole("button", { name: "Light", exact: true })).toHaveAttribute("aria-pressed", "true")
  await expect(page.locator("html")).not.toHaveClass(/dark/)
})

test("cloud connection remains opt-in and cancellation creates no node", async ({ page }) => {
  await page.getByRole("button", { name: "Add sandbox", exact: true }).click()
  await page.locator(".creation-type").filter({ hasText: /^Cloud environment$/ }).click()
  const dialog = page.getByRole("dialog")
  await expect(dialog).toBeVisible()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(dialog).toBeHidden()
  await expect(page.getByText("Your workspace starts here", { exact: true })).toBeVisible()
})

test("dashboard actions remain reachable without horizontal overflow at compact width", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 })
  for (const name of ["Instructions", "Create my personal vault MCP", "Run a local model", "Settings", "Add sandbox"]) {
    await expect(page.getByRole("button", { name, exact: true })).toBeVisible()
  }
  const width = await page.evaluate(() => ({ viewport: window.innerWidth, document: document.documentElement.scrollWidth }))
  expect(width.document).toBeLessThanOrEqual(width.viewport)
})
