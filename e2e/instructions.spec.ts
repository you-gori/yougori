import { expect, test, type Page } from "@playwright/test"
import seed from "../src/data/seed.json" with { type: "json" }
import { overviewSteps } from "../src/lib/instructions-tour"
import { instructionGuides } from "../src/lib/instruction-guides"
import { defaultOciImage } from "../src/data/oci-images"
import { tourWebsitePage } from "../src/lib/tour-website-page"
import type { PlatformState } from "../src/types/platform"

test.use({ actionTimeout: 15000 })
test.beforeEach(({ page }) => { page.on("pageerror", error => console.error("Browser error:", error.message)) })

test.describe("first-launch instructions", () => {
  test.use({ storageState: { cookies: [], origins: [] } })

  test("automatically welcomes a new user once, with two-stage Skip and manual replay", async ({ page }) => {
    test.setTimeout(120_000)
    await page.goto("/")
    await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
    await step(page, "welcome")
    await expect(page.locator('[data-tour-preview]')).toBeVisible()
    await expect(page.getByRole('checkbox', { name: 'Select Tutorial preview', exact: true })).toBeDisabled()
    await expect(page.getByRole('checkbox', { name: 'Select all shown environments', exact: true })).toHaveCount(0)
    await next(page, "stats")
    await guide(page).getByRole("button", { name: "Skip to hands-on", exact: true }).click()
    await step(page, "create-open")
    await expect(guide(page).locator(".tour-meta")).toContainText("Hands-on")
    await expect(guide(page).getByRole("button", { name: "Skip to hands-on", exact: true })).toHaveCount(0)
    await expect(page.locator('[data-tour-preview]')).toHaveCount(0)
    await expect(page.locator('[data-environment-id]')).toHaveCount(0)
    await guide(page).getByRole("button", { name: "Skip", exact: true }).click()
    await expect(guide(page)).toHaveCount(0)
    await page.reload()
    await expect(page.locator("[data-environment-canvas]")).toBeVisible()
    await expect(guide(page)).toHaveCount(0)
    await page.getByRole("button", { name: "Instructions", exact: true }).click()
    await page.getByRole("button", { name: "Replay walkthrough", exact: true }).click()
    await step(page, "welcome")
  })

  test("does not restart automatically if the app closes during the guide", async ({ page }) => {
    test.setTimeout(120_000)
    await page.goto("/")
    await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
    await step(page, "welcome")
    await page.reload()
    await expect(page.locator("[data-environment-canvas]")).toBeVisible()
    await expect(guide(page)).toHaveCount(0)
    await page.getByRole("button", { name: "Instructions", exact: true }).click()
    await page.getByRole("button", { name: "Replay walkthrough", exact: true }).click()
    await step(page, "welcome")
  })
})

test("Instructions launches highlighted walkthroughs, keeps completion, and replays the original tour", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1"))
  await page.goto("/")
  await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  const panel = page.getByRole("dialog", { name: "Instructions", exact: true })
  await expect(panel).toBeVisible()
  await expect(panel.getByRole("button", { name: "Set up Yougori", exact: true })).toBeVisible()
  await expect(panel.getByRole("button", { name: "Change the theme", exact: true })).toBeVisible()
  await expect(panel.getByRole("button", { expanded: true })).toHaveCount(0)
  expect(instructionGuides).toHaveLength(19)
  await panel.getByRole("button", { name: "Set up Yougori", exact: true }).click()
  await panel.getByRole("button", { name: "Start walkthrough", exact: true }).click()
  const topic = page.locator('[data-instruction-topic="settings"]')
  await expect(topic).toHaveAttribute("data-instruction-step", "1")
  await expect(page.locator('[data-topic-highlight]')).toHaveCount(1)
  await page.getByRole("button", { name: "Settings", exact: true }).click()
  await topic.getByRole("button", { name: "Next", exact: true }).click()
  await expect(topic).toHaveAttribute("data-instruction-step", "2")
  await expect(page.locator('[data-instruction="settings-dialog"]')).toBeVisible()
  await topic.getByRole("button", { name: "Next", exact: true }).click()
  await topic.getByRole("button", { name: "Finish walkthrough", exact: true }).click()
  await expect(topic).toHaveCount(0)
  await page.getByRole("dialog", { name: "Settings", exact: true }).getByRole("button", { name: "Close", exact: true }).click()
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  await expect(panel).toContainText("1 of 19 walkthroughs complete")
  await panel.getByRole("button", { name: "Close", exact: true }).click()
  await page.reload()
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  await expect(panel).toContainText("1 of 19 walkthroughs complete")
  await panel.getByRole("button", { name: "Replay walkthrough", exact: true }).click()
  await step(page, "welcome")
  await guide(page).getByRole("button", { name: "Skip to hands-on", exact: true }).click()
  await guide(page).getByRole("button", { name: "Skip", exact: true }).click()
})

test("container walkthrough follows the real creation form without creating a workload", async ({ page }) => {
  await page.goto("/")
  await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  const panel = page.getByRole("dialog", { name: "Instructions", exact: true })
  await panel.getByRole("button", { name: "Create a container", exact: true }).click()
  await panel.getByRole("button", { name: "Start walkthrough", exact: true }).click()
  const topic = page.locator('[data-instruction-topic="container"]')
  await expect(topic).toHaveAttribute("data-instruction-step", "1")
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  await expect(page.locator("[data-create-environment]")).toBeVisible()
  await topic.getByRole("button", { name: "Next", exact: true }).click()
  await expect(topic).toHaveAttribute("data-instruction-step", "2")
  await expect(page.locator('[data-instruction-kind="container"]')).toBeVisible()
  await topic.getByRole("button", { name: "Next", exact: true }).click()
  await expect(page.locator('[data-tour="create-submit"]')).toBeVisible()
  await topic.getByRole("button", { name: "Finish walkthrough", exact: true }).click()
  await expect(topic).toHaveCount(0)
  await page.locator("[data-create-environment]").getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(page.locator("[data-environment-id]")).toHaveCount(0)
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  await expect(panel).toContainText("1 of 19 walkthroughs complete")
})

test("creation walkthroughs point to each real environment type", async ({ page }) => {
  await page.goto("/")
  await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
  const cases = [
    ["Create a GPU container", "gpu", "gpu"],
    ["Create a MicroVM", "microvm", "microVm"],
    ["Create a full VM", "vm", "fullVm"],
    ["Connect a cloud environment", "cloud", "cloud"],
    ["Import a shared environment", "shared", "shared"],
    ["Rent a GPU with Neocloud", "runpod", "neocloud"],
  ] as const
  for (const [title, id, kind] of cases) {
    await page.getByRole("button", { name: "Instructions", exact: true }).click()
    const panel = page.getByRole("dialog", { name: "Instructions", exact: true })
    await panel.getByRole("button", { name: title, exact: true }).click()
    await panel.getByRole("button", { name: "Start walkthrough", exact: true }).click()
    const topic = page.locator(`[data-instruction-topic="${id}"]`)
    await expect(page.locator("[data-topic-highlight]")).toHaveCount(1)
    await page.getByRole("button", { name: "New environment", exact: true }).click()
    await expect(page.locator("[data-create-environment]")).toBeVisible()
    await topic.getByRole("button", { name: "Next", exact: true }).click()
    await expect(page.locator(`[data-instruction-kind="${kind}"]`)).toBeVisible()
    await page.locator(`[data-instruction-kind="${kind}"]`).click()
    await topic.getByRole("button", { name: "Next", exact: true }).click()
    await expect(page.locator("[data-create-environment]")).toBeVisible()
    await topic.getByRole("button", { name: "Exit", exact: true }).click()
    await page.locator("[data-create-environment]").getByRole("button", { name: "Close", exact: true }).click()
    await expect(page.locator("[data-create-environment]")).toHaveCount(0)
  }
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  await expect(page.getByRole("dialog", { name: "Instructions", exact: true })).toContainText("0 of 19 walkthroughs complete")
})

test("service, model, vault and theme walkthroughs stay open inside their dialogs", async ({ page }) => {
  await page.goto("/")
  await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
  const cases = [
    ["Create a public access setup", "public", '[aria-label="Add or manage saved domain setups"]', "public-presets-dialog"],
    ["Run a Hugging Face model", "model", '[data-instruction="model-trigger"]', "model-dialog"],
    ["Use Personal Vault MCP", "vault", '[aria-label="Personal Vault MCP"]', "vault-dialog"],
    ["Change the theme", "theme", '[data-tour="theme"]', "theme-dialog"],
  ] as const
  for (const [title, id, trigger, dialog] of cases) {
    await page.getByRole("button", { name: "Instructions", exact: true }).click()
    const panel = page.getByRole("dialog", { name: "Instructions", exact: true })
    await panel.getByRole("button", { name: title, exact: true }).click()
    await panel.getByRole("button", { name: "Start walkthrough", exact: true }).click()
    const topic = page.locator(`[data-instruction-topic="${id}"]`)
    // List and Nodes retain separate controls; use the active view's control.
    await page.locator(`${trigger}:visible`).first().click()
    await expect(page.locator(`[data-instruction="${dialog}"]`)).toBeVisible()
    await topic.getByRole("button", { name: "Next", exact: true }).click()
    await expect(page.locator(`[data-instruction="${dialog}"]`)).toBeVisible()
    await topic.getByRole("button", { name: "Exit", exact: true }).click()
    await page.locator(`[data-instruction="${dialog}"]`).getByRole("button", { name: "Close", exact: true }).first().click()
  }
})

// All operations in these tests use the browser fixture adapter. No host
// container, download, SSH session, public tunnel or native window is created.
async function openGuide(page: Page, environments?: PlatformState["environments"]) {
  test.setTimeout(Math.max(test.info().timeout, 120_000))
  const state = structuredClone(seed) as PlatformState
  if (environments) state.environments = environments
  Object.assign(state.host, { totalCpu: 8, totalMemoryGb: 16, totalStorageGb: 1024, usedStorageGb: 128 })
  await page.addInitScript(state => {
    if (!localStorage.getItem("yougori.platform.v1")) localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
  }, state)
  await page.goto("/")
  await expect(page.locator("[data-environment-canvas]")).toBeVisible({ timeout: 60000 })
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  await page.getByRole("button", { name: "Replay walkthrough", exact: true }).click()
  await step(page, "welcome")
}
const guide = (page: Page) => page.locator(".tour-card")
async function step(page: Page, value: string) {
  await expect(page.locator("[data-tour-step]")).toHaveAttribute("data-tour-step", value, { timeout: 15000 })
  await expect(guide(page)).toBeVisible()
}
async function next(page: Page, value: string) {
  await guide(page).getByRole("button", { name: "Next", exact: true }).click()
  await step(page, value)
}
async function practice(page: Page) {
  for (const expected of [...overviewSteps.slice(1), "create-open"]) await next(page, expected)
}
async function checkPlacement(page: Page) {
  await expect.poll(async () => {
    const box = await guide(page).boundingBox(), viewport = page.viewportSize()!
    return { inside: !!box && box.x >= 11 && box.y >= 11 && box.x + box.width <= viewport.width - 11 && box.y + box.height <= viewport.height - 11, box, viewport }
  }).toMatchObject({ inside: true })
  await expect.poll(() => page.locator("[data-tour-highlight]").count()).toBeGreaterThan(0)
}
async function mockWindowOpening(page: Page, failFirst = false) {
  await page.evaluate(async failFirst => {
    const path = "/src/api/platform-api.ts", { platformApi } = await import(path)
    let failed = !failFirst
    platformApi.openEnvironmentWindow = async (id: string) => {
      if (!failed) { failed = true; throw new Error("Fixture: window launch failed; retry safely") }
      window.open(`/?environment=${encodeURIComponent(id)}`, "_blank")
      return true
    }
  }, failFirst)
}

test("Instructions is left of reclaim space; overview highlights controls without creating or connecting anything", async ({ page }) => {
  await openGuide(page)
  await expect(page).toHaveTitle("Yougori")
  await expect(page.getByRole("banner").getByText("Yougori", { exact: true })).toBeVisible()
  const instructions = (await page.locator('[data-tour="instructions"]').boundingBox())!
  const backup = (await page.locator('button[data-instruction="reclaim"]').boundingBox())!
  expect(instructions.x + instructions.width).toBeLessThan(backup.x)
  const initial = await page.evaluate(() => localStorage.getItem("yougori.platform.v1"))
  await expect(page.locator('[data-tour-preview]')).toHaveCount(1)
  await expect(page.locator('.workspace-empty')).toHaveCount(0)
  for (const expected of overviewSteps.slice(1)) {
    await next(page, expected); await checkPlacement(page)
    if (expected === "service-ports") {
      await expect(guide(page).getByRole("heading", { name: "Add a service port", exact: true })).toBeVisible()
      await expect(guide(page)).toContainText("Guest TCP port")
      await expect(guide(page)).toContainText("Adding a port does not start your app or publish it")
      await expect(page.locator('[data-tour-preview] [data-tour="node-port"]')).toBeVisible()
      await expect(guide(page)).not.toContainText("PORT appears after you create")
    }
  }
  await guide(page).getByRole("button", { name: "Back", exact: true }).click()
  await step(page, "environment-types")
  expect(await page.evaluate(() => localStorage.getItem("yougori.platform.v1"))).toBe(initial)
  await guide(page).getByRole("button", { name: "Skip to hands-on", exact: true }).click()
  await step(page, "create-open")
  await expect(page.locator('[data-tour-preview]')).toHaveCount(0)
  expect(await page.evaluate(() => localStorage.getItem("yougori.platform.v1"))).toBe(initial)
  await guide(page).getByRole("button", { name: "Skip", exact: true }).click()
  await expect(guide(page)).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Instructions", exact: true })).toBeFocused()
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  await expect(page.locator("[data-create-environment]")).toBeVisible({ timeout: 15000 })
})

test("guide remains readable in both themes, follows resize, supports keyboard and Escape", async ({ page }) => {
  await openGuide(page)
  for (const width of [360, 768, 1440]) {
    await page.setViewportSize({ width, height: 800 })
    await checkPlacement(page)
    await page.evaluate(() => document.documentElement.classList.toggle("dark"))
    await checkPlacement(page)
  }
  await page.keyboard.press("Tab")
  await expect(guide(page).getByRole("button", { name: "Skip to hands-on", exact: true })).toBeFocused()
  await page.keyboard.press("Tab")
  await expect(guide(page).getByRole("button", { name: "Next", exact: true })).toBeFocused()
  await page.keyboard.press("Enter")
  await step(page, "stats")
  await page.keyboard.down("Escape")
  await step(page, "create-open")
  await page.keyboard.down("Escape") // Holding the same key must not skip hands-on.
  await step(page, "create-open")
  await page.keyboard.up("Escape")
  await page.keyboard.press("Escape")
  await expect(guide(page)).toHaveCount(0)
})

test("interactive walkthrough creates, connects, opens, installs, runs Hello World and publishes a free link", async ({ page, context }) => {
  test.setTimeout(180_000)
  const errors: string[] = []
  context.on("page", p => p.on("pageerror", e => { console.error("Guest window error:", e.stack); errors.push(e.message) }))
  page.on("pageerror", e => errors.push(e.message))
  await openGuide(page)
  await practice(page)
  await expect(page.locator('[data-tour-preview]')).toHaveCount(0)
  await expect(guide(page).getByRole("button", { name: "Next", exact: true })).toBeDisabled()
  await page.locator('[data-tour="new-environment"]').click()
  await step(page, "create-type")
  await expect(page.getByRole("radio", { name: "Container", exact: true })).toBeChecked()
  for (const name of ["MicroVM", "VM"]) await expect(page.getByRole("radio", { name, exact: true })).toBeDisabled()
  await expect(page.getByRole("switch", { name: "GPU access", exact: true })).toBeDisabled()
  await next(page, "create-name")
  await expect(guide(page).getByRole("button", { name: "Next", exact: true })).toBeDisabled()
  await page.locator('[data-tour="create-name"] input').fill("First container")
  await next(page, "create-image")
  await expect(page.locator('[data-tour="create-image"] button').first()).toBeDisabled()
  await expect(page.locator('[data-tour="create-image"]')).toContainText(defaultOciImage.value)
  await expect(page.getByRole("textbox", { name: "Startup command (optional)" })).toBeDisabled()
  await next(page, "create-resources")
  await checkPlacement(page)
  await next(page, "create-submit")
  // An early rejection is reported after closing; retry is explicit.
  await page.evaluate(async () => {
    const path = "/src/api/platform-api.ts", { platformApi } = await import(path)
    const original = platformApi.createEnvironment
    platformApi.createEnvironment = async () => {
      platformApi.createEnvironment = original
      throw new Error("Fixture image download failed; please retry")
    }
  })
  await page.locator('[data-tour="create-submit"]').click()
  await expect(page.locator('[data-create-environment]')).toHaveCount(0)
  await expect(page.locator('[data-slot="toast-description"]').filter({ hasText: "Fixture image download failed" })).toBeVisible()
  // Let the transient error toast expire before retrying the button beneath it.
  // Hovering that position would pause the toast's dismissal timer.
  await page.mouse.move(0, 0)
  await expect(page.locator('[data-slot="toast-description"]').filter({ hasText: "Fixture image download failed" })).toBeHidden({ timeout: 15000 })
  await step(page, "create-submit")
  await guide(page).getByRole("button", { name: "Reopen form", exact: true }).click()
  await step(page, "create-type")
  await expect(page.getByRole("switch", { name: "GPU access", exact: true })).toBeDisabled()
  await next(page, "create-name")
  await page.locator('[data-tour="create-name"] input').fill("First container")
  await next(page, "create-image")
  await next(page, "create-resources")
  await next(page, "create-submit")
  await page.evaluate(async () => {
    const path = "/src/api/platform-api.ts", { platformApi } = await import(path)
    const original = platformApi.createEnvironment
    platformApi.createEnvironment = async (request: Parameters<typeof original>[0]) => {
      const pending = await original(request)
      pending.environments[0].status = "provisioning"
      localStorage.setItem("yougori.platform.v1", JSON.stringify(pending))
      await new Promise(resolve => window.addEventListener("finish-tutorial-creation", resolve, { once: true }))
      platformApi.createEnvironment = original
      pending.environments[0].status = "stopped"
      localStorage.setItem("yougori.platform.v1", JSON.stringify(pending))
      return pending
    }
  })
  await page.locator('[data-tour="create-submit"]').click()
  await expect(page.locator('[data-create-environment]')).toHaveCount(0)
  await expect(guide(page).getByRole("heading", { name: "Creating your container", exact: true })).toBeVisible()
  await expect(guide(page).getByRole("button", { name: "Reopen form", exact: true })).toHaveCount(0)
  await expect(page.locator('[data-environment-id]')).toHaveAttribute("aria-busy", "true")
  await page.evaluate(() => window.dispatchEvent(new Event("finish-tutorial-creation")))
  await step(page, "created")
  const environment = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])
  expect(environment.name).toBe("First container")
  expect(environment.runtime).toBe(defaultOciImage.value)
  expect(environment.networkAccess).toBe(true)
  await next(page, "internet-connect")
  const internet = page.getByRole("switch", { name: "Internet access for First container", exact: true })
  await expect(internet).toBeChecked()
  await expect(guide(page).getByRole("button", { name: "Next", exact: true })).toBeEnabled()
  await internet.click()
  await expect(internet).not.toBeChecked()
  await expect(guide(page).getByRole("button", { name: "Next", exact: true })).toBeDisabled()
  await internet.click()
  await expect(internet).toBeChecked()
  await expect(guide(page).getByRole("button", { name: "Next", exact: true })).toBeEnabled()
  await next(page, "start")
  await mockWindowOpening(page, true)
  await page.locator(`[data-environment-id="${environment.id}"] [data-tour="node-launch"]`).click()
  await step(page, "start")
  await expect(page.getByText("Fixture: window launch failed; retry safely").first()).toBeVisible()
  const firstOpening = context.waitForEvent("page")
  // The failed window left the workload running. Follow the guide's terminal icon; Start has correctly changed to Stop.
  await page.locator(`[data-environment-id="${environment.id}"] [data-tour="node-open"]`).click()
  const first = await firstOpening
  await step(first, "terminal")
  await expect(page.locator(".tour-away")).toBeVisible()
  await expect(page.locator(".tour-card")).toHaveCount(0)
  await next(first, "tabs")
  await next(first, "install")
  await expect(first.locator('[data-tour="install-tools"]')).toBeEnabled()
  await first.evaluate(async () => {
    const path = "/src/api/workspace-api.ts", { workspaceApi } = await import(path)
    const original = workspaceApi.terminal
    const writes: string[] = []; Object.assign(window, { tutorialWrites: writes })
    workspaceApi.terminal = (...args: Parameters<typeof original>) => { if (args[2] === "write") writes.push(atob(args[3]?.data ?? "")); return original(...args) }
  })
  await first.locator('[data-tour="install-tools"]').click()
  await first.getByRole("menuitem", { name: "Install Codex", exact: true }).click()
  await step(first, "install-running")
  await expect(first.getByRole("tab", { selected: true })).toContainText("Install Codex")
  expect(await first.evaluate(() => (window as unknown as { tutorialWrites: string[] }).tutorialWrites)).toEqual(["exec sh '/tmp/yougori-install.codex/install.sh'\r"])
  await next(first, "new-terminal")
  await first.locator('[data-tour="new-terminal"]').click()
  await step(first, "run-codex")
  await next(first, "new-window")
  await mockWindowOpening(first)
  const secondOpening = context.waitForEvent("page")
  await first.locator('[data-tour="new-window"]').click()
  const second = await secondOpening
  await step(second, "window-switcher")
  await expect(first.locator(".tour-card")).toHaveCount(0)
  await next(second, "environment-switcher")
  await second.evaluate(async () => {
    const path = "/src/api/platform-api.ts", { platformApi } = await import(path)
    const commands: { id: string; command: string }[] = []
    Object.assign(window, { websiteCommands: commands })
    platformApi.executeEnvironmentCommand = async (id: string, command: string) => {
      commands.push({ id, command })
      return { exitCode: 1, stdout: "", stderr: "Fixture package download failed" }
    }
  })
  await next(second, "demo-start")
  await expect(guide(second)).toContainText("no folders or PC files")
  await expect(guide(second).getByRole("alert")).toContainText("Fixture package download failed")
  await expect(guide(second).getByRole("button", { name: "Copy command", exact: true })).toHaveCount(0)
  expect(await second.evaluate(() => (window as unknown as { websiteCommands: { id: string }[] }).websiteCommands.map(item => item.id))).toEqual([environment.id])
  await step(second, "demo-start")
  await second.evaluate(async () => {
    const path = "/src/api/platform-api.ts", { platformApi } = await import(path)
    const run = JSON.parse(localStorage.getItem("yougori.instructions.v1")!).run
    platformApi.executeEnvironmentCommand = async (id: string, command: string) => {
      (window as unknown as { websiteCommands: { id: string; command: string }[] }).websiteCommands.push({ id, command })
      return { exitCode: 0, stdout: `yougori-hello-${run}\n`, stderr: "" }
    }
  })
  await guide(second).getByRole("button", { name: "Retry website setup", exact: true }).click()
  await step(second, "demo-return")
  expect(await second.evaluate(() => (window as unknown as { websiteCommands: { id: string }[] }).websiteCommands.map(item => item.id))).toEqual([environment.id, environment.id])
  await guide(second).getByRole("button", { name: "Continue on main window", exact: true }).click()
  await step(page, "demo-port-open")
  await expect(second.locator(".tour-card")).toHaveCount(0)
  await expect(second.locator(".tour-away")).toContainText("main Yougori window")
  await page.bringToFront()
  await page.locator(`[data-environment-id="${environment.id}"] [data-tour="node-port"]`).click()
  await step(page, "demo-port-add")
  const portForm = page.locator("[data-add-service-port]")
  await portForm.getByRole("textbox", { name: "Guest TCP port" }).fill("8080")
  await portForm.getByRole("button", { name: "Add port", exact: true }).click()
  await expect(portForm.getByRole("alert")).toContainText("Use port 3000")
  await portForm.getByRole("button", { name: "3000", exact: true }).click()
  await portForm.getByRole("button", { name: "Add port", exact: true }).click()
  await step(page, "demo-publish")
  const options = page.locator("[data-service-options]")
  await expect(guide(page).getByRole("button", { name: "Next", exact: true })).toBeDisabled()
  await options.getByRole("button", { name: "Connect local network", exact: true }).click()
  await expect(options.getByRole("alert")).toContainText("Quick link — no account")
  await options.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await expect(options.getByRole("radio", { name: "Quick link — no account", exact: true })).toBeChecked()
  await page.evaluate(async () => {
    const path = "/src/api/platform-api.ts", { platformApi } = await import(path)
    const workspacePath = "/src/api/workspace-api.ts", { workspaceApi } = await import(workspacePath)
    const run = JSON.parse(localStorage.getItem("yougori.instructions.v1")!).run
    const checks = { ready: false, publications: 0 }
    Object.assign(window, { demoChecks: checks })
    platformApi.executeEnvironmentCommand = async () => ({ exitCode: checks.ready ? 0 : 1, stdout: checks.ready ? `yougori-hello-${run}\n` : "", stderr: "" })
    const publish = workspaceApi.publish
    workspaceApi.publish = (...args: Parameters<typeof publish>) => {
      checks.publications++
      if (checks.publications === 1) throw new Error("Fixture Cloudflare unavailable; retry")
      return publish(...args)
    }
  })
  await options.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(options.getByRole("alert")).toContainText("Hello World is not ready")
  expect(await page.evaluate(() => (window as unknown as { demoChecks: { publications: number } }).demoChecks.publications)).toBe(0)
  await page.evaluate(() => { (window as unknown as { demoChecks: { ready: boolean } }).demoChecks.ready = true })
  await options.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(options.getByRole("alert")).toContainText("Fixture Cloudflare unavailable")
  await step(page, "demo-publish")
  await options.getByRole("button", { name: "Publish service", exact: true }).click()
  await step(page, "demo-link")
  // The URL below is the fixture adapter, never a live external tunnel.
  await context.route("https://test-tunnel.example.test/", route => route.fulfill({ contentType: "text/html", body: "<h1>Hello World!</h1>" }))
  const visiting = context.waitForEvent("page")
  await options.getByRole("button", { name: "https://test-tunnel.example.test", exact: true }).click()
  const website = await visiting
  await expect(website.getByRole("heading", { name: "Hello World!", exact: true })).toBeVisible()
  await step(page, "demo-visit")
  await options.getByRole("button", { name: "Disconnect cloudflare from port 3000", exact: true }).click()
  await expect(options.getByRole("button", { name: "https://test-tunnel.example.test", exact: true })).toHaveCount(0)
  await next(page, "done")
  await guide(page).getByRole("button", { name: "Finish", exact: true }).click()
  await expect(guide(page)).toHaveCount(0)
  await expect(page.getByRole("dialog", { name: "Instructions", exact: true })).toBeVisible()
  await expect(page.locator('[data-tour-preview]')).toHaveCount(0)
  await expect(page.locator(".tour-away")).toHaveCount(0)
  expect(await second.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])).toMatchObject({ name: "First container", status: "running", networkAccess: true })
  expect(await page.evaluate(id => JSON.parse(localStorage.getItem("yougori.workspace.v1")!)[id].publications, environment.id)).toEqual([])
  expect(errors).toEqual([])
})

test("Skip inside the creation dialog keeps its draft and restores normal modal controls", async ({ page }) => {
  await openGuide(page)
  await practice(page)
  await page.locator('[data-tour="new-environment"]').click()
  await step(page, "create-type")
  await expect(page.getByRole("switch", { name: "GPU access", exact: true })).toBeDisabled()
  await next(page, "create-name")
  await page.locator('[data-tour="create-name"] input').fill("Keep my draft")
  await guide(page).getByRole("button", { name: "Skip", exact: true }).click()
  await expect(guide(page)).toHaveCount(0)
  await expect(page.locator('[data-tour="create-name"] input')).toHaveValue("Keep my draft")
  await expect(page.getByRole("switch", { name: "GPU access", exact: true })).toBeEnabled()
  await expect(page.locator('[data-tour="create-image"] button').first()).toBeEnabled()
  await page.locator('[data-create-environment]').getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(page.locator('[data-create-environment]')).toHaveCount(0)
})

async function openWebsitePortGuide(page: Page) {
  await openGuide(page, [{ id: "env-demo", name: "Hello demo", kind: "container", provider: "yougoriOci", status: "running", runtime: "alpine:latest", description: "", createdAt: "2026-01-01T00:00:00Z", networkAccess: true, gpuAccess: false, cpuUsage: 0, memoryUsageGb: 0, storageDeltaGb: 0, networkRxMbps: 0, resourcePolicy: { cpu: { min: 1, preferred: 1, max: 2, current: 1 }, memoryGb: { min: 0.5, preferred: 1, max: 2, current: 1 }, priority: "normal", dynamic: true } }])
  await page.evaluate(async () => {
    const path = "/src/lib/instructions-tour.ts", { changeTour } = await import(path)
    changeTour({ step: "demo-port-open", environmentId: "env-demo" })
  })
  await page.locator('[data-tour="node-port"]').click()
  await step(page, "demo-port-add")
}

test("automatic website setup touches only the tutorial container and cannot resume a skipped guide", async ({ page }) => {
  await openWebsitePortGuide(page)
  await page.evaluate(async () => {
    const tourPath = "/src/lib/instructions-tour.ts", { changeTour } = await import(tourPath)
    const apiPath = "/src/api/platform-api.ts", { platformApi } = await import(apiPath)
    const original = JSON.parse(localStorage.getItem("yougori.platform.v1")!)
    original.environments.push({ ...original.environments[0], id: "env-unrelated", name: "Existing project" })
    localStorage.setItem("yougori.platform.v1", JSON.stringify(original))
    const calls: string[] = []
    Object.assign(window, { automaticWebsiteCalls: calls })
    const run = JSON.parse(localStorage.getItem("yougori.instructions.v1")!).run
    platformApi.executeEnvironmentCommand = id => {
      calls.push(id)
      return new Promise(resolve => Object.assign(window, { finishWebsiteBuild: () => resolve({ exitCode: 0, stdout: `yougori-hello-${run}`, stderr: "" }) }))
    }
    changeTour({ step: "demo-start" })
  })
  await step(page, "demo-start")
  await expect.poll(() => page.evaluate(() => (window as unknown as { automaticWebsiteCalls: string[] }).automaticWebsiteCalls)).toEqual(["env-demo"])
  await expect(guide(page).getByRole("button", { name: "Building website…", exact: true })).toBeDisabled()
  await guide(page).getByRole("button", { name: "Skip", exact: true }).click()
  await page.evaluate(() => (window as unknown as { finishWebsiteBuild: () => void }).finishWebsiteBuild())
  await expect(guide(page)).toHaveCount(0)
  await expect(page.locator('[data-tour-preview]')).toHaveCount(0)
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.instructions.v1")!))).toMatchObject({ active: false, step: "demo-start" })
  expect(await page.evaluate(() => (window as unknown as { automaticWebsiteCalls: string[] }).automaticWebsiteCalls)).toEqual(["env-demo"])
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments.map((env: { id: string }) => env.id))).toEqual(["env-demo", "env-unrelated"])
})

test("Hello World website fits desktop and mobile and its links work without external assets", async ({ page }) => {
  const requests: string[] = []
  page.on("request", request => requests.push(request.url()))
  await page.setContent(tourWebsitePage("yougori-hello-design-review"))
  for (const width of [1440, 768, 390, 320]) {
    await page.setViewportSize({ width, height: 900 })
    await expect(page.getByRole("heading", { name: "Hello World!", exact: true })).toBeVisible()
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  }
  await page.getByRole("link", { name: "See how it works" }).click()
  await expect(page.locator("#how-it-works")).toBeInViewport()
  expect(requests).toEqual([])
})

test("website tutorial port draft survives Skip and closing the form returns to PORT", async ({ page }) => {
  await openWebsitePortGuide(page)
  const dialog = page.locator("[data-add-service-port]")
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await step(page, "demo-port-open")
  await page.locator('[data-tour="node-port"]').click()
  await step(page, "demo-port-add")
  await dialog.getByRole("textbox", { name: "Guest TCP port" }).fill("3000")
  await guide(page).getByRole("button", { name: "Skip", exact: true }).click()
  await expect(guide(page)).toHaveCount(0)
  await expect(dialog.getByRole("textbox", { name: "Guest TCP port" })).toHaveValue("3000")
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(dialog).toHaveCount(0)
  expect(await page.evaluate(() => localStorage.getItem("yougori.workspace.manual.v2"))).toBeNull()
})

test("Skip during the website preflight cancels publication and keeps normal dialog controls", async ({ page }) => {
  await openWebsitePortGuide(page)
  const portForm = page.locator("[data-add-service-port]")
  await portForm.getByRole("button", { name: "3000", exact: true }).click()
  await portForm.getByRole("button", { name: "Add port", exact: true }).click()
  await step(page, "demo-publish")
  const options = page.locator("[data-service-options]")
  await options.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await page.evaluate(async () => {
    const path = "/src/api/platform-api.ts", { platformApi } = await import(path)
    const workspacePath = "/src/api/workspace-api.ts", { workspaceApi } = await import(workspacePath)
    const run = JSON.parse(localStorage.getItem("yougori.instructions.v1")!).run
    platformApi.executeEnvironmentCommand = () => new Promise(resolve => Object.assign(window, { finishDemoCheck: () => resolve({ exitCode: 0, stdout: `yougori-hello-${run}`, stderr: "" }) }))
    Object.assign(window, { demoPublished: false })
    workspaceApi.publish = () => { Object.assign(window, { demoPublished: true }); throw new Error("Publishing must not run after Skip") }
  })
  await options.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect.poll(() => page.evaluate(() => typeof (window as unknown as { finishDemoCheck?: () => void }).finishDemoCheck)).toBe("function")
  await guide(page).getByRole("button", { name: "Skip", exact: true }).click()
  await page.evaluate(() => (window as unknown as { finishDemoCheck: () => void }).finishDemoCheck())
  await expect(guide(page)).toHaveCount(0)
  await expect(options.getByRole("button", { name: "Publish service", exact: true })).toBeEnabled()
  expect(await page.evaluate(() => (window as unknown as { demoPublished: boolean }).demoPublished)).toBe(false)
  await options.getByRole("button", { name: "Done", exact: true }).click()
  await expect(options).toHaveCount(0)
})
