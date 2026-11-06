import { test, expect } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

test("My computer, My setups and Hub are the sections, and no other page of grids is left to send anyone to", async ({ page }) => {
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  const sections = page.getByRole("navigation", { name: "Sections" })
  await expect(sections.getByRole("button")).toHaveText([/^My computer/, /^My setups/, /^Hub/])
  await sections.getByRole("button", { name: "My setups", exact: true }).click()
  const setups = page.getByRole("region", { name: "My setups" })
  await expect(setups).toBeVisible()
  await expect(setups.getByRole("button", { name: "All grids", exact: true })).toHaveCount(0)
})

// The grid pages and their transports were retired; existing links still navigate.
for (const address of ["/?page=grid", "/?grid=sandbox", "/?page=grids", "/?recipe=neo-grid"]) {
  test(`Legacy address ${address} opens My setups`, async ({ page }) => {
    await page.goto(address)
    await expect(page.getByRole("region", { name: "My setups", exact: true })).toBeVisible({ timeout: 60000 })
    await expect(page.getByRole("region", { name: /^(Neo Grid|Sandbox Grid|Access Grid) workspace$/ })).toHaveCount(0)
  })
}
