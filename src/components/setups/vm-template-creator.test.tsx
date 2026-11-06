// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { SandboxVmContext } from "@/components/sandbox-vm/sandbox-vm-context"
import { VmTemplateCreator } from "./vm-template-creator"
const api = vi.hoisted(() => ({ run: vi.fn(), folder: vi.fn(), open: vi.fn(), openConsole: vi.fn() }))
vi.mock("@/api/platform-api", () => ({ run: api.run }))
vi.mock("@/api/hub-api", () => ({ hubApi: api }))
vi.mock("./builder-context", () => ({ useSetupBuilder: () => ({ open: api.open }) }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
function show() {
  return render(<SandboxVmContext value={{ error: "", refresh: vi.fn(), status: {
    sandboxes: [{ sandbox: "exe-website", state: "running", phase: "ready", boot: 1, revocation: null },
      { sandbox: "exe-models", state: "running", phase: "ready", boot: 1, revocation: null }], workspaces: [],
  } }}><VmTemplateCreator selected={["exe-website"]} open onClose={vi.fn()} /></SandboxVmContext>)
}
it("uses the VM feed, reviews source and saves only the reviewed selection", async () => {
  const preview = { digest: "reviewed-source", files: ["app.py"], omitted: ["Private answers"],
    sandboxes: [{id:"exe-website",name:"website",files:1,connections:["models"]}],
    questions: [{id:"vm1_password",question:"Admin password",type:"secret"}],
  }
  api.run.mockResolvedValueOnce(preview).mockResolvedValueOnce({folder:"C:/templates/site"})
  api.folder.mockResolvedValue("C:/templates/site")
  show()
  expect(screen.getByRole("checkbox", {name:/exe-website/})).toBeChecked()
  fireEvent.click(screen.getByRole("checkbox", {name:/exe-models/}))
  fireEvent.click(screen.getByRole("button",{name:"Review template"}))
  expect(await screen.findByText("Admin password · private answer")).toBeVisible()
  expect(screen.getByText("Connects to: models")).toBeVisible()
  fireEvent.click(screen.getByRole("button",{name:"Save template…"}))
  await waitFor(()=>expect(api.run).toHaveBeenLastCalledWith("sandbox_vm", {action:"template",params:{operation:"export",sandboxes:["exe-website","exe-models"],name:"my-template",digest:"reviewed-source",folder:"C:/templates/site"}},expect.any(Function)))
  fireEvent.click(await screen.findByRole("button",{name:"Run template"}))
  expect(api.open).toHaveBeenCalledWith({mode:"run",folder:"C:/templates/site"})
})
it("invalidates a review after a selection change and exposes engine errors", async () => {
  api.run.mockRejectedValue(new Error("No setup declaration in this VM"))
  show()
  fireEvent.click(screen.getByRole("button",{name:"Review template"}))
  expect(await screen.findByRole("alert")).toHaveTextContent("No setup declaration")
  expect(screen.queryByRole("button",{name:"Save template…"})).toBeNull()
})

it("offers VM creation instead of an unusable review form when the inventory is empty", () => {
  const refresh = vi.fn()
  const create = vi.fn()
  render(<SandboxVmContext value={{ error: "", refresh, status: { sandboxes: [], workspaces: [] } }}>
    <VmTemplateCreator open onClose={vi.fn()} onCreateVm={create} />
  </SandboxVmContext>)
  expect(screen.getByRole("heading", { name: "No Sandbox VMs available to select" })).toBeVisible()
  expect(screen.getByText(/Standalone model environments do not appear/)).toBeVisible()
  expect(screen.queryByRole("textbox", { name: "Template name" })).toBeNull()
  expect(screen.queryByRole("button", { name: "Review template" })).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Refresh VM list" }))
  expect(refresh).toHaveBeenCalledTimes(2)
  fireEvent.click(screen.getByRole("button", { name: "Create Sandbox VM" }))
  expect(create).toHaveBeenCalledOnce()
  expect(api.run).not.toHaveBeenCalled()
})

it("shows inventory failures as errors rather than saying there are no VMs", () => {
  const refresh = vi.fn()
  render(<SandboxVmContext value={{ error: "Engine unavailable", refresh, status: null }}>
    <VmTemplateCreator open onClose={vi.fn()} onCreateVm={vi.fn()} />
  </SandboxVmContext>)
  expect(screen.getByRole("alert")).toHaveTextContent("Engine unavailable")
  expect(screen.queryByRole("heading", { name: "No Sandbox VMs available to select" })).toBeNull()
  expect(screen.queryByRole("button", { name: "Create Sandbox VM" })).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Retry loading VMs" }))
  expect(refresh).toHaveBeenCalledTimes(2)
})

it("keeps real VMs selected in a mixed selection and explicitly excludes unavailable IDs", async () => {
  api.run.mockResolvedValue({ digest: "d", files: [], omitted: [], questions: [], sandboxes: [] })
  render(<SandboxVmContext value={{ error: "", refresh: vi.fn(), status: {
    sandboxes: [{ sandbox: "exe-website", state: "running", phase: "ready", boot: 1, revocation: null }], workspaces: [],
  } }}><VmTemplateCreator selected={["env-local-model", "exe-website"]} open onClose={vi.fn()} /></SandboxVmContext>)
  expect(screen.getByRole("status", { name: "Selected environments not included" })).toHaveTextContent("env-local-model")
  expect(screen.getByRole("checkbox", { name: /exe-website/ })).toBeChecked()
  expect(screen.getByRole("button", { name: "Review template" })).toBeEnabled()
  fireEvent.click(screen.getByRole("button", { name: "Review template" }))
  await waitFor(() => expect(api.run).toHaveBeenCalledWith("sandbox_vm", {
    action: "template", params: { operation: "preview", sandboxes: ["exe-website"], name: "my-template" },
  }, expect.any(Function)))
})

it("explains a disabled review and never sends only stale IDs to capture", () => {
  render(<SandboxVmContext value={{ error: "", refresh: vi.fn(), status: {
    sandboxes: [{ sandbox: "exe-website", state: "running", phase: "ready", boot: 1, revocation: null }], workspaces: [],
  } }}><VmTemplateCreator selected={["exe-missing"]} open onClose={vi.fn()} /></SandboxVmContext>)
  expect(screen.getByText("Select at least one Sandbox VM to continue.")).toBeVisible()
  expect(screen.getByRole("button", { name: "Review template" })).toBeDisabled()
  fireEvent.click(screen.getByRole("checkbox", { name: /exe-website/ }))
  fireEvent.change(screen.getByRole("textbox", { name: "Template name" }), { target: { value: "My Template" } })
  expect(screen.getByText(/Use a name starting with a lowercase letter/)).toBeVisible()
  expect(screen.getByRole("button", { name: "Review template" })).toBeDisabled()
  fireEvent.change(screen.getByRole("textbox", { name: "Template name" }), { target: { value: "my-template" } })
  expect(screen.getByRole("button", { name: "Review template" })).toBeEnabled()
  expect(api.run).not.toHaveBeenCalled()
})
