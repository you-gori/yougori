// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { GridHostingBox } from "./grid-hosting-box"
const gridSettings = vi.hoisted(() => vi.fn())
vi.mock("@/api/sandbox-vm-api", async original => ({ ...(await original<typeof import("@/api/sandbox-vm-api")>()), sandboxVmApi: { gridSettings } }))
beforeEach(() => vi.stubGlobal("PointerEvent", MouseEvent))
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.unstubAllGlobals() })

it("reads saved state, toggles the actual VM settings and allows all grids off", async () => {
  gridSettings.mockResolvedValueOnce({ installed: true, enabled: ["gpu", "sandbox"] })
    .mockResolvedValueOnce({ installed: true, enabled: ["sandbox"] })
    .mockResolvedValueOnce({ installed: true, enabled: [] })
  render(<GridHostingBox sandbox="vm-a" disabled={false} />)
  expect(await screen.findByRole("switch", { name: "GPU Grid" })).toBeChecked()
  fireEvent.click(screen.getByRole("switch", { name: "GPU Grid" }))
  await waitFor(() => expect(screen.getByRole("switch", { name: "GPU Grid" })).not.toBeChecked())
  expect(gridSettings).toHaveBeenLastCalledWith("vm-a", ["sandbox"])
  fireEvent.click(screen.getByRole("switch", { name: "Sandbox Grid" }))
  await waitFor(() => expect(screen.getByRole("switch", { name: "Sandbox Grid" })).not.toBeChecked())
  expect(gridSettings).toHaveBeenLastCalledWith("vm-a", [])
})

it("keeps confirmed state on failure and never labels failed settings as saved", async () => {
  gridSettings.mockResolvedValueOnce({ installed: false, enabled: [] }).mockRejectedValueOnce(new Error("VM stopped"))
  render(<GridHostingBox sandbox="vm-a" disabled={false} />)
  fireEvent.click(await screen.findByRole("switch", { name: "Sandbox Grid" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("VM stopped")
  expect(screen.getByRole("switch", { name: "Sandbox Grid" })).not.toBeChecked()
  expect(screen.queryByText("Grid settings saved in this VM.")).toBeNull()
})
