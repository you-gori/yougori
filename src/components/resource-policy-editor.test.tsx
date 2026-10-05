// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { useImperativeHandle, type ReactNode, type Ref } from "react"
import { ResourcePolicyEditor } from "./resource-policy-editor"
import type { SectionSave } from "@/lib/resource-controls"
import type { Environment } from "@/types/platform"

const save = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
const saveStartup = vi.hoisted(() => vi.fn().mockResolvedValue(undefined))
vi.mock("./configuration-help", () => ({ ConfigurationHelp: ({ children }: { children: ReactNode }) => <div>{children}</div> }))
const host = vi.hoisted(() => ({ os: "macOS 15.0", totalCpu: 8, totalMemoryGb: 16 }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { host, environments: [] }, updateResourcePolicy: save, updateContainerStartupCommand: saveStartup }) }))
// Sections report edits to Save changes through their handles.
const sections = vi.hoisted(() => ({
  storage: { changed: false, problem: null as string | null, save: vi.fn() },
  name: { changed: false, problem: null as string | null, save: vi.fn() },
}))
function FakeSection({ saveRef, section }: { saveRef?: Ref<SectionSave>; section: typeof sections.storage }) {
  useImperativeHandle(saveRef, () => ({ changed: () => section.changed, problem: () => section.problem, save: section.save }))
  return null
}
vi.mock("./storage-allocation-editor", () => ({ StorageAllocationEditor: ({ saveRef }: { saveRef?: Ref<SectionSave> }) => <FakeSection saveRef={saveRef} section={sections.storage} /> }))
vi.mock("./environment-name-editor", () => ({ EnvironmentNameEditor: ({ saveRef }: { saveRef?: Ref<SectionSave> }) => <FakeSection saveRef={saveRef} section={sections.name} /> }))
afterEach(() => {
  cleanup(); save.mockClear(); saveStartup.mockReset(); saveStartup.mockResolvedValue(undefined); host.os = "macOS 15.0"
  for (const section of [sections.storage, sections.name]) { section.changed = false; section.problem = null; section.save.mockReset() }
})

const environment = {
  id: "mac-test", name: "Test VM", kind: "fullVm", status: "running",
  resourcePolicy: {
    cpu: { min: 1, preferred: 2, max: 4, current: 2 },
    memoryGb: { min: 1, preferred: 2, max: 4, current: 2 },
    dynamic: true, priority: "normal",
  },
} as Environment

it("explains Mac VM restart requirements without promising live dynamic allocation", () => {
  render(<ResourcePolicyEditor environment={environment} />)
  expect(screen.getByText(/VM changes apply after shutdown and restart/).textContent).toContain("VM changes apply after shutdown and restart")
  expect(screen.queryByText(/Live memory changes require/)).toBeNull()
})

it("does not apply the Mac VM limitation to Windows or Mac containers", () => {
  const { rerender } = render(<ResourcePolicyEditor environment={{ ...environment, kind: "container" }} />)
  expect(screen.queryByText(/VM changes apply after shutdown and restart/)).toBeNull()
  host.os = "Windows 11"
  rerender(<ResourcePolicyEditor environment={environment} />)
  expect(screen.queryByText(/VM changes apply after shutdown and restart/)).toBeNull()
  expect(screen.getByText(/Live memory changes require/)).toBeTruthy()
})

it("converts legacy ranges to fixed allocations and validates typed values", async () => {
  render(<ResourcePolicyEditor environment={environment} />)
  expect(screen.getAllByRole("slider")).toHaveLength(2)
  expect(screen.queryByText("Exact values")).toBeNull()
  const memory = screen.getByRole("spinbutton", { name: "Memory value" })
  fireEvent.change(memory, { target: { value: "" } })
  expect((screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(memory, { target: { value: "3.125" } })
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  await waitFor(() => expect(save).toHaveBeenCalledWith(environment.id, expect.objectContaining({
    cpu: { min: 2, preferred: 2, max: 2, current: 2 },
    memoryGb: { min: 3.125, preferred: 3.125, max: 3.125, current: 2 },
  })))
})

it("keeps model resource controls at two CPUs and four GB", async () => {
  render(<ResourcePolicyEditor environment={{ ...environment, kind: "container", description: "Hugging Face · google/gemma-4-12B" }} />)
  fireEvent.change(screen.getByRole("spinbutton", { name: "CPU value" }), { target: { value: "1" } })
  fireEvent.change(screen.getByRole("spinbutton", { name: "Memory value" }), { target: { value: "2" } })
  expect((screen.getByRole("button", { name: "Save changes" }) as HTMLButtonElement).disabled).toBe(true)
  fireEvent.change(screen.getByRole("spinbutton", { name: "CPU value" }), { target: { value: "2" } })
  fireEvent.change(screen.getByRole("spinbutton", { name: "Memory value" }), { target: { value: "4" } })
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  await waitFor(() => expect(save).toHaveBeenCalledWith(environment.id, expect.objectContaining({
    cpu: expect.objectContaining({ min: 2, preferred: 2, max: 2 }),
    memoryGb: expect.objectContaining({ min: 4, preferred: 4, max: 4 }),
  })))
})

it("Save changes also stores the container startup command from the same configuration", async () => {
  const container = { ...environment, kind: "container", status: "stopped", containerCommand: "sleep 1" } as Environment
  const saved = vi.fn()
  render(<ResourcePolicyEditor environment={container} startupDraft="  exec npm start  " onStartupSaved={saved} />)
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  await waitFor(() => expect(saveStartup).toHaveBeenCalledExactlyOnceWith(container.id, "  exec npm start  "))
  expect(save).not.toHaveBeenCalled()
  expect(saved).toHaveBeenCalledOnce()
  expect((await screen.findByRole("status")).textContent).toBe("Changes saved.")
})

it("a running container's new startup command blocks the whole save and stays a draft", async () => {
  const container = { ...environment, kind: "container", status: "running", containerCommand: "" } as Environment
  const saved = vi.fn()
  render(<ResourcePolicyEditor environment={container} startupDraft="exec server" onStartupSaved={saved} />)
  fireEvent.change(screen.getByRole("spinbutton", { name: "Memory value" }), { target: { value: "3" } })
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  expect((await screen.findByRole("alert")).textContent).toContain("Stop the container")
  expect(save).not.toHaveBeenCalled()
  expect(saveStartup).not.toHaveBeenCalled()
  expect(saved).not.toHaveBeenCalled()
})

it("a startup command the backend rejects is reported and kept as a draft", async () => {
  const container = { ...environment, kind: "container", status: "stopped", containerCommand: "" } as Environment
  saveStartup.mockRejectedValue(new Error("Finish the pending Factory reset before changing the startup command"))
  const saved = vi.fn()
  render(<ResourcePolicyEditor environment={container} startupDraft="exec server" onStartupSaved={saved} />)
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  expect((await screen.findByRole("alert")).textContent).toContain("Factory reset")
  expect(saved).not.toHaveBeenCalled()
})

it("an unchanged startup draft does not send a startup update", async () => {
  const container = { ...environment, kind: "container", status: "stopped", containerCommand: "exec server" } as Environment
  render(<ResourcePolicyEditor environment={container} startupDraft="exec server" />)
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  await waitFor(() => expect(save).toHaveBeenCalledOnce())
  expect(saveStartup).not.toHaveBeenCalled()
})

it("Save changes stores the VM name, resources and storage together in order", async () => {
  const order: string[] = []
  sections.name.changed = true; sections.name.save.mockImplementation(async () => { order.push("name") })
  sections.storage.changed = true; sections.storage.save.mockImplementation(async () => { order.push("storage") })
  save.mockImplementationOnce(async () => { order.push("resources") })
  render(<ResourcePolicyEditor environment={{ ...environment, status: "stopped" }} />)
  fireEvent.change(screen.getByRole("spinbutton", { name: "Memory value" }), { target: { value: "3" } })
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  expect(await screen.findByText("Changes saved.")).toBeTruthy()
  expect(order).toEqual(["name", "resources", "storage"])
})

it("a blocked section stops Save changes before anything is stored", async () => {
  sections.storage.changed = true
  sections.storage.problem = "Stop this environment before expanding storage."
  render(<ResourcePolicyEditor environment={environment} />)
  fireEvent.change(screen.getByRole("spinbutton", { name: "Memory value" }), { target: { value: "3" } })
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  expect((await screen.findByRole("alert")).textContent).toBe("Stop this environment before expanding storage.")
  expect(save).not.toHaveBeenCalled()
  expect(sections.storage.save).not.toHaveBeenCalled()
})

it("an unchanged section is neither checked nor saved", async () => {
  sections.storage.problem = "Stop this environment before expanding storage."
  render(<ResourcePolicyEditor environment={environment} />)
  fireEvent.click(screen.getByRole("button", { name: "Save changes" }))
  await waitFor(() => expect(save).toHaveBeenCalledOnce())
  expect(sections.storage.save).not.toHaveBeenCalled()
})
