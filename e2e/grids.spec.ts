import { test, expect, type Page } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

/** Replaces the one call path every grid speaks through, and records what it is asked.
 *
 *  Nothing here starts a worker, a desk or a hub: every answer is made up in the page. The
 *  research grid is never created at all, which is what the Grids area does on a real computer
 *  too, so no part of this test comes near Swarm Mining. */
async function mockGrids(page: Page) {
  await page.evaluate(async () => {
    const wirePath = "/src/api/grids/wire.ts"
    const gridPath = "/src/api/grid-api.ts"
    const wire = await import(wirePath) as typeof import("@/api/grids/wire")
    const { gridApi } = await import(gridPath) as typeof import("@/api/grid-api")
    const calls: Array<{ command: string; args: Record<string, unknown> }> = []
    const state: { hub: Record<string, unknown> | null } = { hub: null }
    Object.assign(window, { __grids: { calls, state } })
    const hub = (name: string, address: string) => ({
      id: "g1", name, address, port: 7460, url: `https://${address}:7460/v1`, fingerprint: "AB:CD", createdAt: "",
      computers: { total: 1, capable: 1, online: 1 },
      plans: [{ id: "p1", model: "hf.co/acme/assistant", quant: null, percent: 100, rules: "always on", computers: 1, target: 1, ready: 1, scope: { kind: "all" }, names: [] }],
      planWarning: null,
      members: [{ id: "m1", name: "Design laptop", platform: "windows", joinedAt: "", capable: true, excluded: false, planId: "p1", jobs: 0, online: true, lastSeenSeconds: 1, address: "192.168.1.30", appVersion: "1.0.21", running: 0, models: [] }],
      queue: { waiting: 0, running: 0 }, harnesses: [],
    })
    gridApi.status = async () => ({ hub: state.hub, hubError: null, member: null, memberError: null }) as never
    wire.setTransport(async (command: string, args: Record<string, unknown>, browser: () => unknown) => {
      calls.push({ command, args })
      if (command === "grid_suggested_address") return "192.168.1.20" as never
      if (command === "grid_create") {
        state.hub = hub(String(args.name), String(args.address))
        return { hub: state.hub, hubError: null, member: null, memberError: null } as never
      }
      // Ordering a model and giving a computer's share are part of creating a grid, so the
      // fixture answers them the way a hub does: with a plain acknowledgement.
      if (command === "grid_plan_add" || command === "desks_member_share") return { ok: true } as never
      // Everything else answers as it does with no desktop app, so nothing else changes here.
      return browser() as never
    })
  })
}

const calls = (page: Page) => page.evaluate(() => (window as unknown as { __grids: { calls: Array<{ command: string; args: Record<string, unknown> }> } }).__grids.calls)

async function openGrids(page: Page) {
  page.on("pageerror", error => { console.log(`PAGEERROR ${error.message}\n${error.stack ?? ""}`) })
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  await mockGrids(page)
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Grids", exact: true }).click()
  await expect(page.getByRole("region", { name: "Grids workspace" })).toBeVisible()
}

test("One Grids entry replaces the four, and each grid still opens its own workspace from the same place", async ({ page }) => {
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  const sections = page.getByRole("navigation", { name: "Sections" })
  await expect(sections.getByRole("button", { name: "Grids", exact: true })).toBeVisible()
  for (const [name, workspace] of [
    ["Neo Grid", "Neo Grid workspace"],
    ["Sandbox Grid", "Sandbox Grid workspace"],
    ["Swarm Mining", "Swarm Mining workspace"],
  ] as const) {
    await sections.getByRole("button", { name, exact: true }).click()
    await expect(page.getByRole("region", { name: workspace })).toBeVisible()
  }
  // And the one entry goes back to the list of them all.
  await sections.getByRole("button", { name: "Grids", exact: true }).click()
  await expect(page.getByRole("region", { name: "Grids workspace" })).toBeVisible()
})

test("An old address still opens the grid it named", async ({ page }) => {
  await page.goto("/?page=grid")
  await expect(page.getByRole("region", { name: "Neo Grid workspace" })).toBeVisible({ timeout: 60000 })
  await page.goto("/?grid=sandbox")
  await expect(page.getByRole("region", { name: "Sandbox Grid workspace" })).toBeVisible({ timeout: 60000 })
})

test("Create a grid asks what it is for first, then only that purpose's questions, and Escape closes it", async ({ page }) => {
  await openGrids(page)
  await page.getByRole("button", { name: "Create a grid", exact: true }).click()
  const wizard = page.getByRole("dialog", { name: "Create a grid" })
  await expect(wizard).toContainText("What is this grid for?")
  await expect(wizard.getByRole("button", { name: "Next" })).toBeDisabled()
  await wizard.getByRole("checkbox", { name: /Serving models/ }).click()
  await wizard.getByRole("button", { name: "Next" }).click()
  await wizard.getByLabel("Name").fill("Acme")
  await wizard.getByRole("button", { name: "Next" }).click()
  await expect(wizard.getByLabel("This computer's address on your network")).toHaveValue("192.168.1.20")
  await wizard.getByRole("button", { name: "Next" }).click()
  await wizard.getByLabel("Password", { exact: true }).fill("correct horse battery")
  await wizard.getByLabel("Password again").fill("correct horse battery")
  await wizard.getByRole("button", { name: "Next" }).click()
  await expect(wizard).toContainText("Which model?")
  await expect(wizard).not.toContainText("Who uses a desk?")
  // Back walks out of the wizard question by question, and nothing was created.
  for (let step = 0; step < 5; step += 1) await wizard.getByRole("button", { name: "Back" }).click()
  await expect(wizard).toContainText("What is this grid for?")
  await page.keyboard.press("Escape")
  await expect(wizard).toBeHidden()
  expect((await calls(page)).some(call => call.command === "grid_create")).toBe(false)
})

test("The dry run says where everything is, nothing is created until the last word, and a public link must be agreed to", async ({ page }) => {
  await openGrids(page)
  await page.getByRole("button", { name: "Create a grid", exact: true }).click()
  const wizard = page.getByRole("dialog", { name: "Create a grid" })
  await wizard.getByRole("checkbox", { name: /Serving models/ }).click()
  await wizard.getByRole("button", { name: "Next" }).click()
  await wizard.getByLabel("Name").fill("Acme")
  await wizard.getByRole("button", { name: "Next" }).click()
  await expect(wizard.getByLabel("This computer's address on your network")).toHaveValue("192.168.1.20")
  await wizard.getByRole("radio", { name: /Anywhere, through Cloudflare/ }).click()
  await wizard.getByRole("button", { name: "Next" }).click()
  await wizard.getByLabel("Password", { exact: true }).fill("correct horse battery")
  await wizard.getByLabel("Password again").fill("correct horse battery")
  await wizard.getByRole("button", { name: "Next" }).click()
  await wizard.getByLabel(/^Model/).fill("acme/assistant")
  for (let step = 0; step < 7; step += 1) await wizard.getByRole("button", { name: "Next" }).click()

  const summary = wizard.getByRole("region", { name: "What would happen" })
  await expect(summary).toContainText("Records")
  await expect(summary).toContainText("mints the key and keeps it in this computer's credential store")
  await expect(summary).toContainText("Through a quick public link")
  await expect(summary).toContainText("Administrators")
  await expect(summary).toContainText("Approvers")
  await expect(summary).toContainText("Computers")
  await expect(summary).toContainText("One model plan: acme/assistant")
  expect((await calls(page)).some(call => call.command === "grid_create")).toBe(false)

  const create = wizard.getByRole("button", { name: "Create the grid" })
  await expect(create).toBeDisabled()
  await summary.getByRole("checkbox").first().click()
  await create.click()
  await expect(wizard).toBeHidden()
  const made = (await calls(page)).find(call => call.command === "grid_create")
  expect(made?.args).toEqual({ name: "Acme", address: "192.168.1.20", password: "correct horse battery", tunnel: "quick" })
  // The summary named one model plan, so the grid is left with that plan in it. A sentence
  // somebody agreed to has to describe something that then happens.
  const ordered = (await calls(page)).find(call => call.command === "grid_plan_add")
  expect(ordered?.args).toEqual({ model: "acme/assistant", scope: "remaining", percent: 100, computers: null, quant: null })
  const order = (await calls(page)).map(call => call.command)
  expect(order.indexOf("grid_create")).toBeLessThan(order.indexOf("grid_plan_add"))
})

test("One grid's status shows only the panels its capabilities allow", async ({ page }) => {
  await openGrids(page)
  await page.evaluate(async () => {
    const wirePath = "/src/api/grids/wire.ts"
    const wire = await import(wirePath) as typeof import("@/api/grids/wire")
    await wire.call("grid_create", { name: "Acme", address: "192.168.1.20", password: "correct horse battery", tunnel: null })
  })
  const workspace = page.getByRole("region", { name: "Grids workspace" })
  await expect(workspace.getByRole("button", { name: "Status" })).toBeVisible({ timeout: 15000 })
  await workspace.getByRole("button", { name: "Status" }).click()
  await expect(workspace.getByRole("region", { name: "This grid" })).toContainText("Acme")
  await expect(workspace.getByRole("region", { name: "Models" })).toContainText("hf.co/acme/assistant")
  await expect(workspace.getByRole("region", { name: "Computers" })).toContainText("Design laptop")
  await expect(workspace.getByRole("region", { name: "Credentials" })).toBeHidden()
  await expect(workspace.getByRole("region", { name: "Desks" })).toBeHidden()
  // What a person reads is a sentence, never where a file is or what a realm is called inside.
  await expect(workspace).toContainText("holds this grid's key")
  await expect(workspace).not.toContainText(".db")
})
