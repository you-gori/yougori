import { test, expect } from "@playwright/test"

test("Neocloud guides a GPU pod from template to a priced review", async ({ page }) => {
  const errors: string[] = []
  page.on("pageerror", error => errors.push(error.message))
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 30000 })
  await page.evaluate(async () => {
    const path = "/src/api/runpod-api.ts"
    const { runpodApi } = await import(path)
    const account = { email: "test@example.com", balance: 10, spendPerHour: 0, spendLimit: 80 }
    runpodApi.status = async () => ({ installed: true, connected: true, account })
    runpodApi.resources = async () => ({ pods: [], endpoints: [] })
    runpodApi.template = async (id: string) => ({ id, name: "Runpod Pytorch 2.8.0", image: "runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404", kind: "gpu", containerDiskGb: 30, volumeGb: 50, mountPath: "/workspace", own: false, official: true, ports: [{ port: 8888, kind: "http", name: "Jupyter Notebook" }], readme: "PyTorch with Jupyter" })
    runpodApi.catalog = async () => ({
      checkedAt: new Date().toISOString(), account, issues: [], registries: [], volumes: [],
      locations: [{ id: "US-KS-2", country: "United States" }],
      gpus: [
        { id: "NVIDIA H100 80GB HBM3", name: "H100 SXM", vramGb: 80, securePrice: 2.69, communityPrice: 1.99, available: true, stock: "low", locations: [{ id: "US-KS-2", stock: "low" }], amd: false },
        { id: "NVIDIA A40", name: "A40", vramGb: 48, securePrice: 0.49, communityPrice: null, available: false, stock: "none", locations: [], amd: false },
      ],
      templates: [{ id: "runpod-torch-v280", name: "Runpod Pytorch 2.8.0", image: "runpod/pytorch:1.0.2-cu1281-torch280-ubuntu2404", kind: "gpu", containerDiskGb: 30, volumeGb: 50, mountPath: "/workspace", own: false, official: true }],
    })
  })
  await page.getByRole("button", { name: "Add sandbox", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await dialog.getByText("Neocloud", { exact: true }).click()
  await expect(dialog.getByText("$10.00")).toBeVisible()
  await dialog.getByRole("button", { name: "Create a GPU pod" }).click()
  await dialog.getByRole("button", { name: "Start from PyTorch 2.8.0" }).click()
  await dialog.getByRole("button", { name: "Continue" }).click()
  await expect(dialog.getByRole("button", { name: "Choose A40" })).toHaveCount(0)
  await dialog.getByRole("button", { name: "Choose H100 SXM" }).click()
  await dialog.getByRole("button", { name: "Continue" }).click()
  await expect(dialog.getByLabel("Volume size")).toHaveValue("50")
  await dialog.getByRole("button", { name: "Continue" }).click()
  await expect(dialog.getByText("$2.69", { exact: true }).first()).toBeVisible()
  await expect(dialog.getByRole("button", { name: /Create pod/ })).toBeDisabled()
  await page.setViewportSize({ width: 650, height: 900 })
  expect(await dialog.evaluate(el => el.scrollWidth <= el.clientWidth + 1)).toBe(true)
  expect(errors).toEqual([])
})
