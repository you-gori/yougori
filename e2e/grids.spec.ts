import { test, expect } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

test("My computer, My setups and Hub are the sections, and no other page of grids is left to send anyone to", async ({ page }) => {
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  // My computer is the page itself; Hub opens over it from the header, beside Settings.
  await expect(page.getByRole("heading", { level: 1 })).toContainText("My computer.")
  const actions = page.getByRole("group", { name: "Dashboard actions", exact: true })
  await expect(actions.getByRole("button")).toHaveText([/^Hub/, /^Settings/])
  await actions.getByRole("button", { name: "Hub", exact: true }).click()
  const hub = page.getByRole("dialog", { name: "Hub", exact: true })
  await expect(hub).toBeVisible()
  await expect(hub.getByRole("button", { name: "All grids", exact: true })).toHaveCount(0)
})

// The grid pages and their transports were retired; existing links still navigate, to the
// setup configuration popup over My computer.
for (const address of ["/?page=grid", "/?grid=sandbox", "/?page=grids", "/?recipe=neo-grid"]) {
  test(`Legacy address ${address} opens My setups`, async ({ page }) => {
    await page.goto(address)
    await expect(page.getByRole("dialog", { name: "Setup configuration", exact: true })).toBeVisible({ timeout: 60000 })
    await expect(page.getByRole("region", { name: /^(Neo Grid|Sandbox Grid|Access Grid) workspace$/ })).toHaveCount(0)
  })
}
