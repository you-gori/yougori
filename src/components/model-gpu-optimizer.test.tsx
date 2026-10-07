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
  fireEvent.click(screen.getByRole("switch", { name:"Prevent automatic model switching" }))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{pinned:true}))
  fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value:"30"}})
  fireEvent.click(screen.getByRole("button",{name:"Save"}))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{idleTimeoutSeconds:30}))
})
it("saves keep-loaded mode and rejects invalid idle timeouts", async () => {
  optimizer.mockResolvedValue(status)
  render(<ModelGpuOptimizer environmentId="env-one" />)
  await screen.findByLabelText("Unload after idle seconds")
  fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value:"0"}})
  fireEvent.click(screen.getByRole("button",{name:"Save"}))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{idleTimeoutSeconds:0}))
  await waitFor(() => expect(screen.getByRole("button",{name:"Save"})).toBeEnabled())
  for (const value of ["", "-1", "1", "9", "3601", "10.5"]) {
    fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value}})
    expect(screen.getByRole("button",{name:"Save"})).toBeDisabled()
  }
})
it("explains residency until the next requested model", async () => {
  optimizer.mockResolvedValue({...status,idleTimeoutSeconds:0})
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByText(/current model stays loaded until another model needs the GPU/)).toBeVisible()
})
