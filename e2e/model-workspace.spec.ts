import { test, expect, type Locator } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

/** Every visible descendant must sit inside the popup horizontally; returns offenders. */
async function escapees(popup: Locator) {
  return popup.evaluate(root => {
    const bounds = root.getBoundingClientRect()
    const out: string[] = []
    for (const element of Array.from(root.querySelectorAll<HTMLElement>("*"))) {
      const rect = element.getBoundingClientRect()
      const style = getComputedStyle(element)
      if (rect.width < 3 || rect.height < 3 || style.visibility === "hidden" || element.closest(".sr-only")) continue
      if (rect.left < bounds.left - 1 || rect.right > bounds.right + 1) out.push(`${element.tagName.toLowerCase()}.${element.className} ${Math.round(rect.left)}-${Math.round(rect.right)} vs ${Math.round(bounds.left)}-${Math.round(bounds.right)}`)
    }
    return out.slice(0, 8)
  })
}

for (const width of [1440, 760]) {
  test(`run-a-local-model and the model library stay inside their popups at ${width}px`, async ({ page }) => {
    await page.setViewportSize({ width, height: 900 })
    await page.goto("/")
    await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
    await page.evaluate(async () => {
      const path = "/src/api/model-registry-api.ts"
      const { registryApi } = await import(path)
      registryApi.list = async () => ({ storage: { configured: true }, models: [
        { id: "m1", name: "Very long European open-weights instruction model name that used to be cut off", ref: "yougori.com/models/very-long-european-open-weights-instruction-model-2026-10", visibility: "public", description: "A long description of the model.", license: "Apache-2.0", downloads: 3, canDownload: true, owned: false, version: { source: "upload", inferenceAvailable: true } },
        { id: "m2", name: "Tiny model", ref: "yougori.com/models/tiny", visibility: "api-only", description: "", license: "MIT", downloads: 0, canDownload: false, owned: false },
      ] })
    })
    await page.getByRole("button", { name: "Run a local model", exact: true }).click()
    const popup = page.locator('[data-instruction="model-dialog"]')
    await expect(popup).toBeVisible()

    expect(await popup.evaluate(el => el.scrollWidth <= el.clientWidth + 1), "popup scrolls sideways").toBe(true)
    expect(await escapees(popup), "elements outside the run-model popup").toEqual([])

    const input = await popup.locator("#model-folder").boundingBox()
    const choose = await popup.getByRole("button", { name: "Choose model folder" }).boundingBox()
    expect(input && choose, "local weights row rendered").toBeTruthy()
    const sameLine = Math.abs(input!.y - choose!.y) < 8
    const gap = sameLine ? choose!.x - (input!.x + input!.width) : choose!.y - (input!.y + input!.height)
    expect(gap, "input and Choose model folder must not touch").toBeGreaterThanOrEqual(6)

    await popup.getByRole("button", { name: "Model library", exact: true }).click()
    const library = page.getByRole("dialog", { name: "Model library" })
    await expect(library).toBeVisible()
    await library.getByRole("button", { name: /Very long European/ }).click()
    expect(await library.evaluate(el => el.scrollWidth <= el.clientWidth + 1), "library scrolls sideways").toBe(true)
    expect(await escapees(library), "elements outside the library popup").toEqual([])
    const clipped = await library.locator(".model-library-name, .model-library-detail-head strong, .model-library-detail-head code").evaluateAll(nodes => nodes.filter(node => node.scrollWidth > node.clientWidth + 1).map(node => node.textContent))
    expect(clipped, "library text cut off").toEqual([])
    const header = await library.locator(".model-dialog-header").boundingBox()
    const title = await library.getByRole("heading", { name: "Model library" }).boundingBox()
    expect(title!.x - header!.x, "library title must not touch the edge").toBeGreaterThanOrEqual(16)
  })
}
