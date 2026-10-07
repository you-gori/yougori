// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelGpuOptimizer } from "./model-gpu-optimizer"
const { optimizer } = vi.hoisted(() => ({ optimizer: vi.fn() }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { optimizer } }))
beforeEach(() => { vi.stubGlobal("PointerEvent", MouseEvent) })
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.unstubAllGlobals() })
const status = { supported:true,enabled:true,pinned:false,resident:false,loading:false,active:0,pending:2,idleTimeoutSeconds:120,allocatedBytes:0 }
it("shows on-demand state and saves pinning without stopping the environment", async () => {
  optimizer.mockResolvedValue(status)
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByText(/On demand.*2 waiting/)).toBeVisible()
  fireEvent.click(screen.getByRole("switch", { name:"Keep this model loaded" }))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{pinned:true}))
  fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value:"30"}})
  fireEvent.click(screen.getByRole("button",{name:"Save"}))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{idleTimeoutSeconds:30}))
})
it("leaves legacy runners usable and rejects invalid idle timeouts in the controls", async () => {
  optimizer.mockResolvedValue(status)
  render(<ModelGpuOptimizer environmentId="env-one" />)
  await screen.findByLabelText("Unload after idle seconds")
  fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value:"0"}})
  expect(screen.getByRole("button",{name:"Save"})).toBeDisabled()
})
