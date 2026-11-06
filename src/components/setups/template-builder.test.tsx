// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { CapabilityDescriptor, SetupDraft } from "@/api/setups/types"

const api = vi.hoisted(() => ({
  capabilities: vi.fn(), validate: vi.fn(), plan: vi.fn(), apply: vi.fn(), list: vi.fn(), get: vi.fn(), operation: vi.fn(), cancel: vi.fn(), action: vi.fn(), reviewRemoval: vi.fn(),
}))
const catalogue = vi.hoisted(() => {
  const capability = (over: Partial<CapabilityDescriptor>): CapabilityDescriptor => ({
    id: "x", version: 1, group: "grid_workers", name: "X", summary: "A capability.", examples: [], resourceKinds: [], requires: [], conflicts: [],
    aliases: [], permissions: [], actions: [], widget: "toggle", status: "shipped", profiles: [], requiresWaivedFor: [], ...over,
  })
  return [
    capability({ id: "grid.local_only", name: "Run on this computer only", conflicts: ["grid.create"], examples: ["One sandbox for yourself"] }),
    capability({ id: "grid.create", name: "Create a grid", conflicts: ["grid.local_only"], aliases: ["gpu"], permissions: ["enroll_computers"] }),
    capability({ id: "models.team", group: "ai_models", name: "AI team", requires: [["grid.create", "grid.local_only"]] }),
    capability({ id: "web.site", group: "website_api", name: "Website" }),
    capability({ id: "people.team", group: "people_access", name: "Team members" }),
    capability({ id: "data.volume", group: "files_data", name: "Persistent volumes" }),
    capability({ id: "run.schedule", group: "automation_recovery", name: "Schedules", status: "planned" }),
  ]
})
vi.mock("@/api/setups/setups-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/setups-api")>()), setupsApi: api }))
vi.mock("@/api/setups/catalogue", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/catalogue")>()), CATALOGUE: catalogue }))
const platformState = vi.hoisted(() => ({ value: null as unknown }))
vi.mock("@/context/platform-context", () => ({ usePlatformOptional: () => platformState.value }))
const hubDetail = vi.hoisted(() => vi.fn())
vi.mock("@/api/hub-api", async importOriginal => {
  const original = await importOriginal<typeof import("@/api/hub-api")>()
  return { ...original, hubApi: { ...original.hubApi, detail: hubDetail } }
})
const dialog = vi.hoisted(() => ({ open: vi.fn() }))
vi.mock("@tauri-apps/plugin-dialog", () => dialog)

import { SetupUnavailableError } from "@/api/setups/setups-api"
import { setupFeed } from "@/api/setups/progress"
import { TemplateBuilder } from "./template-builder"
import type { BuilderIntent } from "./setup-intent"

const available = catalogue.filter(one => one.status !== "planned").map(one => ({ id: one.id, availability: "available" as const }))

beforeEach(() => {
  // A Hub address without a version is pinned to the version the Hub has now.
  hubDetail.mockResolvedValue({ latestVersion: "1.0.0", version: { version: "1.0.0" } })
  api.capabilities.mockResolvedValue([...available, { id: "run.schedule", availability: "planned" }])
  api.validate.mockResolvedValue({ manifest: "format_version: 2\nname: Acme\n", diagnostics: [] })
  api.list.mockRejectedValue(new SetupUnavailableError("setup_list"))
})
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.restoreAllMocks(); platformState.value = null })

function open(intent: BuilderIntent = { mode: "create" }) {
  const onClose = vi.fn()
  const onShowSetups = vi.fn()
  render(<TemplateBuilder intent={intent} open onClose={onClose} onShowSetups={onShowSetups} />)
  return { onClose, onShowSetups }
}

async function toCapabilities(user = userEvent.setup({ delay: null })) {
  await user.type(screen.getByLabelText("Template name"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what it can do" })
  return user
}

it("shows all six groups on the main screen, Grid & workers first, with nothing behind an Advanced panel", async () => {
  open()
  await toCapabilities()
  const groups = screen.getAllByRole("heading", { level: 4 }).map(heading => heading.querySelector("span")?.textContent)
  expect(groups).toEqual(["Grid & workers", "AI tools & models", "Website & API", "People & access", "Files & data", "Automation & recovery"])
  expect(screen.queryByText(/Advanced/i)).toBeNull()
  const card = screen.getByRole("article", { name: "Run on this computer only" })
  expect(within(card).getByText("A capability.")).toBeInTheDocument()
  expect(within(card).getByText(/For example: One sandbox for yourself/)).toBeInTheDocument()
  expect(within(card).getByText("Available")).toBeInTheDocument()
})

it("never lets a planned capability be turned on, and says so in words", async () => {
  open()
  const user = await toCapabilities()
  const planned = screen.getByRole("article", { name: "Schedules" })
  expect(within(planned).getByText("Planned")).toBeInTheDocument()
  expect(within(planned).getByText(/can't be turned on/)).toBeInTheDocument()
  const box = within(planned).getByRole("checkbox", { name: "Schedules" })
  expect(box).toBeDisabled()
  await user.click(box)
  expect(box).not.toBeChecked()
  await user.click(screen.getByRole("button", { name: "Next" }))
  expect(api.validate).not.toHaveBeenCalledWith({ draft: expect.objectContaining({ capabilities: expect.objectContaining({ "run.schedule": expect.anything() }) }) })
})

it("works by keyboard alone: type, Enter, Tab to a card, Space to choose it", async () => {
  const user = userEvent.setup({ delay: null })
  open()
  await waitFor(() => expect(screen.getByRole("heading", { name: "How do you want to start?" })).toHaveFocus())
  await user.tab()
  expect(screen.getByLabelText("Template name")).toHaveFocus()
  await user.keyboard("Acme{Enter}")
  await waitFor(() => expect(screen.getByRole("heading", { name: "Choose what it can do" })).toHaveFocus())
  await user.tab() // Capabilities
  await user.tab() // Source
  await user.tab() // Find a capability
  expect(screen.getByRole("searchbox", { name: "Find a capability" })).toHaveFocus()
  await user.keyboard("gpu")
  expect(screen.queryByRole("article", { name: "Website" })).toBeNull()
  // Nothing stands between the search and the cards: no starter recipe is offered for a word.
  await user.tab()
  const create = screen.getByRole("checkbox", { name: "Create a grid" })
  expect(create).toHaveFocus()
  await user.keyboard(" ")
  expect(create).toBeChecked()
  // The author's controls follow it: Tab reaches the chosen mode, Space picks another.
  await user.tab()
  expect(screen.getByRole("radio", { name: /On by default/ })).toHaveFocus()
  await user.tab()
  expect(screen.getByRole("checkbox", { name: "They can change its settings" })).toHaveFocus()
  await user.keyboard(" ")
  expect(screen.getByRole("checkbox", { name: "They can change its settings" })).not.toBeChecked()
})

it("explains what a selection still needs and adds it only when asked", async () => {
  const user = await toCapabilities((open(), userEvent.setup({ delay: null })))
  await user.click(screen.getByRole("checkbox", { name: "AI team" }))
  const card = screen.getByRole("article", { name: "AI team" })
  expect(within(card).getByRole("note")).toHaveTextContent("AI team also needs one of Create a grid or Run on this computer only.")
  expect(screen.getByText(/AI team also needs Create a grid or Run on this computer only\. Add it, or turn AI team off\./)).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  await user.click(within(card).getByRole("button", { name: "Add Create a grid" }))
  expect(screen.getByRole("checkbox", { name: "Create a grid" })).toBeChecked()
  // Choosing one of two that clash makes the other unavailable, with the reason.
  expect(screen.getByRole("checkbox", { name: "Run on this computer only" })).toBeDisabled()
  expect(within(screen.getByRole("article", { name: "Run on this computer only" })).getByText(/Can't be used with Create a grid/)).toBeInTheDocument()
  // A grid brings one more question, and only then can it go on.
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  await user.click(screen.getByRole("radio", { name: /Neo Grid/ }))
  expect(screen.getByRole("button", { name: "Next" })).toBeEnabled()
})

it("Back keeps answers, Cancel asks before throwing a draft away, and Back from the first step closes", async () => {
  const user = userEvent.setup({ delay: null })
  const { onClose } = open()
  await toCapabilities(user)
  await user.click(screen.getByRole("button", { name: "Back" }))
  expect(await screen.findByLabelText("Template name")).toHaveValue("Acme")
  // Going back puts focus on that step's heading, so it is read out again.
  await waitFor(() => expect(screen.getByRole("heading", { name: "How do you want to start?" })).toHaveFocus())
  await user.click(screen.getByRole("button", { name: "Cancel" }))
  const confirm = screen.getByRole("group", { name: "Discard this draft?" })
  await waitFor(() => expect(within(confirm).getByRole("button", { name: "Keep editing" })).toHaveFocus())
  expect(onClose).not.toHaveBeenCalled()
  await user.click(within(confirm).getByRole("button", { name: "Keep editing" }))
  await waitFor(() => expect(screen.getByRole("button", { name: "Cancel" })).toHaveFocus())
  await user.click(screen.getByRole("button", { name: "Cancel" }))
  await user.click(screen.getByRole("button", { name: "Discard" }))
  expect(onClose).toHaveBeenCalledTimes(1)

  cleanup()
  const fresh = open()
  await user.click(await screen.findByRole("button", { name: "Back" }))
  expect(fresh.onClose).toHaveBeenCalledTimes(1)
})

it("shows the engine's source and sends a problem's Go to link to its field", async () => {
  api.validate.mockResolvedValue({
    manifest: "format_version: 2\nname: Acme\ncapabilities:\n  grid.create: required\n",
    diagnostics: [{ code: "grid_name_missing", severity: "error", retryable: false, message: "The grid needs a name.", field: "capabilities.grid.create" }],
  })
  const user = await toCapabilities((open(), userEvent.setup({ delay: null })))
  await user.click(screen.getByRole("button", { name: "Source" }))
  expect(await screen.findByLabelText("yougori-template.yaml")).toHaveValue("format_version: 2\nname: Acme\ncapabilities:\n  grid.create: required\n")
  expect(screen.getByText("The grid needs a name.")).toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Go to Create a grid" }))
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Create a grid" })).toHaveFocus())
})

it("says plainly when this build can't check or create setups, and still lets people look", async () => {
  api.capabilities.mockRejectedValue(new SetupUnavailableError("setup_capabilities"))
  api.validate.mockRejectedValue(new SetupUnavailableError("setup_validate"))
  open()
  expect(await screen.findByText(/can't check or create setups yet/)).toBeInTheDocument()
  await toCapabilities()
  expect(within(screen.getByRole("article", { name: "Create a grid" })).getByText("Not checked")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Source" }))
  expect(await screen.findByText(/once this build of Yougori can check drafts/)).toBeInTheDocument()
})

it("runs a Hub template from start to readiness, keeping secrets out of everything but the apply", async () => {
  const user = userEvent.setup({ delay: null })
  const read: SetupDraft = {
    name: "Sandbox Grid", recipe: "sandbox-grid",
    capabilities: {
      "grid.create": { selected: true, mode: "required", runnerEditable: true, settings: {} },
      "web.site": { selected: false, mode: "optional", runnerEditable: true, settings: {} },
    },
    questions: [
      { id: "grid_name", label: "Grid name", kind: "text", capability: "grid.create" },
      { id: "admin.password", label: "Administrator password", kind: "secret", step: "admin" },
    ],
  }
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], draft: read })
  api.plan.mockResolvedValue({
    setupId: "s-new", digest: "d1", baseRevision: 0, headline: "Creates Sandbox Grid on this computer.",
    resources: [{ resourceId: "company", label: "Company grid", kind: "grid", owned: true, action: "create" }], notes: ["Nothing is downloaded."],
  })
  api.apply.mockResolvedValue({ operationId: "op-77", setupId: "s-new" })
  api.list.mockResolvedValue([{ setupId: "s-new", name: "Office desks", source: { kind: "installed_setup", setupId: "x" }, state: "running", createdAt: 1, currentOperation: { operationId: "op-77", setupId: "s-new" } }])
  api.operation.mockResolvedValue({ operation: { operationId: "op-77", setupId: "s-new" }, state: "completed", nextCursor: 2, events: [
    { cursor: 1, at: 1, step: "grid", message: "Created the company grid" },
    { cursor: 2, at: 2, step: "ready", message: "Checked that it answers" },
  ] })
  api.get.mockResolvedValue({ summary: {}, revision: 1, resources: [], capabilities: [{ id: "grid.create", health: "ready" }, { id: "web.site", health: "needs_sign_in", detail: "Sign in to Cloudflare to publish it." }] })

  const { onShowSetups } = open({ mode: "run", hubRef: "hub/ana/desks" })
  expect(screen.getByRole("radio", { name: /A template from the Hub/ })).toBeChecked()
  expect(screen.getByLabelText("Hub address")).toHaveValue("hub/ana/desks")
  const name = screen.getByLabelText("Name for this setup")
  await user.clear(name)
  await user.type(name, "Office desks")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  expect(api.validate).toHaveBeenCalledWith({ source: { kind: "hub", publisher: "ana", name: "desks", version: "1.0.0" } })
  // A required capability can't be removed by the person running it.
  expect(screen.getByRole("checkbox", { name: "Create a grid" })).toBeDisabled()
  expect(screen.getByText("Required by this template.")).toBeInTheDocument()
  expect(screen.queryByRole("article", { name: "Team members" })).toBeNull()

  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Compute, storage and limits" })
  await user.type(screen.getByLabelText("Grid name"), "acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Administrator" })
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  await user.type(screen.getByLabelText("Administrator password"), "correct horse battery")
  await user.type(screen.getByLabelText("Administrator password again"), "correct horse battery")
  await user.click(screen.getByRole("button", { name: "Next" }))

  expect(await screen.findByText("Creates Sandbox Grid on this computer.")).toBeInTheDocument()
  expect(screen.getByRole("rowheader", { name: "Company grid" })).toBeInTheDocument()
  expect(screen.getByText("Owned by this setup")).toBeInTheDocument()
  const planned = api.plan.mock.calls[0]![0]
  expect(JSON.stringify(planned)).not.toContain("correct horse")
  expect(planned).toMatchObject({
    name: "Office desks",
    source: { kind: "hub", publisher: "ana", name: "desks", version: "1.0.0" },
    answers: [{ field: "capabilities.grid.create", value: true }, { field: "capabilities.web.site", value: false }, { field: "grid_name", value: "acme" }],
    bindings: [{ field: "admin.password", secretRef: "apply:admin.password" }],
  })

  await user.click(screen.getByRole("button", { name: "Set it up" }))
  expect(api.apply).toHaveBeenCalledWith(expect.objectContaining({ setupId: "s-new", digest: "d1", baseRevision: 0 }), expect.stringMatching(/^op-/), { "admin.password": "correct horse battery" }, [])
  expect(await screen.findByText("Created the company grid")).toBeInTheDocument()
  expect(await screen.findByText("Finished")).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Back" })).toBeNull()
  await user.click(screen.getByRole("button", { name: "See what's ready" }))
  const readiness = await screen.findByRole("list", { name: "Readiness" })
  expect(within(readiness).getByText("Ready")).toBeInTheDocument()
  expect(within(readiness).getByText("Needs sign-in")).toBeInTheDocument()
  expect(within(readiness).getByText("Sign in to Cloudflare to publish it.")).toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Open setup configuration" }))
  expect(onShowSetups).toHaveBeenCalledWith("s-new")
})

it("offers a storage drive for a new setup, lists only drives sandboxes can go on, and sends the chosen one", async () => {
  const user = userEvent.setup({ delay: null })
  // This computer's drives: two take sandboxes; a removable, a read-only and a nearly-full one can't.
  platformState.value = { state: { host: { storageDrives: [
    { path: "C:\\", name: "System", fileSystem: "NTFS", totalGb: 200, freeGb: 120, readOnly: false, removable: false },
    { path: "D:\\", name: "Data", fileSystem: "NTFS", totalGb: 1000, freeGb: 900, readOnly: false, removable: false },
    { path: "E:\\", name: "USB", fileSystem: "exFAT", totalGb: 64, freeGb: 50, readOnly: false, removable: true },
    { path: "F:\\", name: "Disc", fileSystem: "UDF", totalGb: 25, freeGb: 20, readOnly: true, removable: false },
    { path: "G:\\", name: "Scratch", fileSystem: "NTFS", totalGb: 20, freeGb: 5, readOnly: false, removable: false },
  ] } } }
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], draft: {
    name: "Sandbox Grid", recipe: "sandbox-grid",
    capabilities: { "grid.create": { selected: true, mode: "required", runnerEditable: true, settings: {} } },
    questions: [{ id: "grid_name", label: "Grid name", kind: "text", capability: "grid.create" }],
  } })
  api.plan.mockResolvedValue({ setupId: "s-drive", digest: "dd", baseRevision: 0, headline: "Creates it on D:." })

  open({ mode: "run", hubRef: "hub/ana/desks@1.0.0" })
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Compute, storage and limits" })

  const select = screen.getByLabelText("Where should its sandboxes be stored?") as HTMLSelectElement
  const options = within(select).getAllByRole("option").map(option => option.textContent)
  // The usual drive is the default; only the two eligible drives are offered, with free space.
  expect(select.value).toBe("")
  expect(options[0]).toBe("The usual drive")
  expect(options).toContain("C: · 120 GB free")
  expect(options).toContain("D: · 900 GB free")
  expect(options.some(label => label?.startsWith("E:"))).toBe(false)
  expect(options.some(label => label?.startsWith("F:"))).toBe(false)
  expect(options.some(label => label?.startsWith("G:"))).toBe(false)

  await user.selectOptions(select, "D:\\")
  await user.type(screen.getByLabelText("Grid name"), "acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await waitFor(() => expect(api.plan).toHaveBeenCalled())
  expect(api.plan.mock.calls.at(-1)![0]).toMatchObject({ storageDrive: "D:\\" })
})

it("doesn't ask where to store a change, and never sends a drive for one", async () => {
  const user = userEvent.setup({ delay: null })
  platformState.value = { state: { host: { storageDrives: [
    { path: "C:\\", name: "System", fileSystem: "NTFS", totalGb: 200, freeGb: 120, readOnly: false, removable: false },
    { path: "D:\\", name: "Data", fileSystem: "NTFS", totalGb: 1000, freeGb: 900, readOnly: false, removable: false },
  ] } } }
  api.get.mockResolvedValue({ summary: { setupId: "s1", name: "Acme", source: { kind: "hub", publisher: "yougori", name: "sandbox-grid", version: "1.0.0" }, state: "running", createdAt: 1 }, revision: 3, resources: [], capabilities: [], actions: [] })
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], draft: {
    name: "Acme", recipe: "sandbox-grid",
    capabilities: { "grid.create": { selected: true, mode: "required", runnerEditable: true, settings: {} } },
    questions: [{ id: "grid_name", label: "Grid name", kind: "text", capability: "grid.create" }],
    answers: { grid_name: "acme" },
  } })
  api.plan.mockResolvedValue({ setupId: "s1", digest: "d1", baseRevision: 3, headline: "No change." })

  open({ mode: "configure", setupId: "s1", setupName: "Acme" })
  await screen.findByRole("heading", { name: "Change what it can do" })
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Compute, storage and limits" })
  // A change keeps the drive it is on, so it is never asked where to store the sandboxes.
  expect(screen.queryByLabelText("Where should its sandboxes be stored?")).toBeNull()
  await user.click(screen.getByRole("button", { name: "Next" }))
  await waitFor(() => expect(api.plan).toHaveBeenCalled())
  for (const call of api.plan.mock.calls) expect(call[0]).not.toHaveProperty("storageDrive")
})

it("asks for a new review when the one shown expired, and starts nothing", async () => {
  const user = userEvent.setup({ delay: null })
  api.validate.mockResolvedValue({ manifest: "", diagnostics: [], draft: { name: "Neo", recipe: "neo-grid", capabilities: {} } })
  api.plan.mockResolvedValue({ setupId: "s2", digest: "d2", baseRevision: 0, headline: "Creates Neo." })
  const { SetupCommandError } = await import("@/api/setups/setups-api")
  api.apply.mockRejectedValueOnce(new SetupCommandError("Expired.", { code: "plan_expired" }))
  open({ mode: "run", hubRef: "hub/ana/neo@1.0.0" })
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  await user.click(screen.getByRole("button", { name: "Next" }))
  await user.click(await screen.findByRole("button", { name: "Set it up" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("This review expired before it was applied, so nothing was changed. A fresh review is below")
  await waitFor(() => expect(api.plan).toHaveBeenCalledTimes(2))
  expect(api.apply).toHaveBeenCalledTimes(1)
  // The second click is a new operation, not a replay of the refused one.
  api.apply.mockResolvedValueOnce({ operationId: "op-2", setupId: "s2" })
  await user.click(await screen.findByRole("button", { name: "Set it up" }))
  expect(api.apply.mock.calls[1]![1]).not.toBe(api.apply.mock.calls[0]![1])
})

it("saves the files a template carries beside its two, such as the cloud model gateway, into the same folder", async () => {
  const user = userEvent.setup({ delay: null })
  const hub = await import("@/api/hub-api")
  const save = vi.spyOn(hub.hubApi, "saveTemplateDraft").mockResolvedValue({ folder: "D:/templates/acme", name: "acme", written: ["yougori-template.yaml", "yougori.yaml", "model-gateway.py", "README.md"], keptReadme: false })
  dialog.open.mockResolvedValue("D:/templates/acme")
  api.validate.mockResolvedValue({ manifest: "format_version: 2\nname: acme\n", project: "format_version: 2\nproject: acme\n", files: { "model-gateway.py": "print('gateway')\n" }, diagnostics: [] })
  open()
  await toCapabilities(user)
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Your template" })
  const saveButton = await screen.findByRole("button", { name: "Save to a folder…" })
  await waitFor(() => expect(saveButton).toBeEnabled())
  await user.click(saveButton)
  await waitFor(() => expect(save).toHaveBeenCalledWith({ folder: "D:/templates/acme", template: "format_version: 2\nname: acme\n", project: "format_version: 2\nproject: acme\n", files: { "model-gateway.py": "print('gateway')\n" } }))
  expect(await screen.findByText(/Saved to/)).toHaveTextContent("model-gateway.py")
  save.mockRestore()
})

it("saves the template into a chosen folder, then checks it and publishes it through the console", async () => {
  const user = userEvent.setup({ delay: null })
  const hub = await import("@/api/hub-api")
  const save = vi.spyOn(hub.hubApi, "saveTemplateDraft").mockResolvedValue({ folder: "D:/templates/acme", name: "acme", written: ["yougori-template.yaml", "yougori.yaml", "README.md"], keptReadme: false })
  const consoleOpen = vi.spyOn(hub.hubApi, "openConsole").mockResolvedValue({ opened: true, command: "yougori template publish D:/templates/acme" })
  dialog.open.mockResolvedValue("D:/templates/acme")
  api.validate.mockResolvedValue({ manifest: "format_version: 2\nname: acme\n", project: "format_version: 2\nproject: acme\n", diagnostics: [] })
  open()
  await toCapabilities(user)
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Your template" })
  const saveButton = await screen.findByRole("button", { name: "Save to a folder…" })
  await waitFor(() => expect(saveButton).toBeEnabled())
  await user.click(saveButton)
  await waitFor(() => expect(save).toHaveBeenCalledWith({ folder: "D:/templates/acme", template: "format_version: 2\nname: acme\n", project: "format_version: 2\nproject: acme\n" }))
  expect(await screen.findByText(/Saved to/)).toHaveTextContent("Saved to D:/templates/acme: yougori-template.yaml, yougori.yaml, README.md.")
  await user.click(screen.getByRole("button", { name: "Check it" }))
  await waitFor(() => expect(api.validate).toHaveBeenLastCalledWith({ source: { kind: "local_folder", path: "D:/templates/acme" } }))
  expect(await screen.findByText("The check found no problems.")).toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Publish…" }))
  await waitFor(() => expect(consoleOpen).toHaveBeenCalledWith("publishTemplate", "D:/templates/acme"))
  expect(await screen.findByText(/asks before anything is published/)).toBeInTheDocument()
})

it("does not offer saving before this build can write the source, and saves nothing when no folder is chosen", async () => {
  const user = userEvent.setup({ delay: null })
  const hub = await import("@/api/hub-api")
  const save = vi.spyOn(hub.hubApi, "saveTemplateDraft")
  api.validate.mockRejectedValue(new SetupUnavailableError("setup_validate"))
  open()
  await toCapabilities(user)
  await user.click(screen.getByRole("button", { name: "Next" }))
  expect(await screen.findByRole("button", { name: "Save to a folder…" })).toBeDisabled()
  expect(screen.getByText(/Saving needs the source, which this build of Yougori can't write yet/)).toBeInTheDocument()

  cleanup()
  api.validate.mockResolvedValue({ manifest: "format_version: 2\nname: acme\n", diagnostics: [] })
  dialog.open.mockResolvedValue(null)
  open()
  await toCapabilities(user)
  await user.click(screen.getByRole("button", { name: "Next" }))
  const saveButton = await screen.findByRole("button", { name: "Save to a folder…" })
  await waitFor(() => expect(saveButton).toBeEnabled())
  await user.click(saveButton)
  await waitFor(() => expect(dialog.open).toHaveBeenCalled())
  expect(save).not.toHaveBeenCalled()
})

it("never offers to add what can't be used here, and never lets it through", async () => {
  catalogue.push(
    { ...catalogue[0]!, id: "run.job", group: "automation_recovery", name: "Run as a job", conflicts: [], examples: [], aliases: [] },
    { ...catalogue[0]!, id: "run.retries", group: "automation_recovery", name: "Retries", conflicts: [], examples: [], aliases: [], requires: [["run.job"]] },
  )
  api.capabilities.mockResolvedValue([...available, { id: "run.retries", availability: "available" }, { id: "run.job", availability: "unsupported", reason: "Jobs run only in Swarm setups here." }])
  try {
    const user = await toCapabilities((open(), userEvent.setup({ delay: null })))
    await user.click(screen.getByRole("checkbox", { name: "Retries" }))
    const card = screen.getByRole("article", { name: "Retries" })
    expect(within(card).getByRole("note")).toHaveTextContent("None of them can be used here")
    expect(within(card).queryByRole("button", { name: /^Add/ })).toBeNull()
    expect(screen.getByRole("checkbox", { name: "Run as a job" })).toBeDisabled()
    expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  } finally {
    catalogue.splice(-2, 2)
  }
})

it("turns nothing on until this computer has been checked, and asks again after a failed check", async () => {
  api.capabilities.mockRejectedValueOnce(new Error("The engine is busy."))
  open()
  await toCapabilities()
  expect(within(screen.getByRole("article", { name: "Create a grid" })).getByText("Not checked")).toBeInTheDocument()
  expect(screen.getByRole("checkbox", { name: "Create a grid" })).toBeDisabled()
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Create a grid" })).toBeEnabled(), { timeout: 4000 })
  expect(api.capabilities).toHaveBeenCalledTimes(2)
}, 10000)

it("chooses a capability a search led to only once it is known to work here, and opens on its group", async () => {
  const user = userEvent.setup({ delay: null })
  open({ mode: "create", capability: "grid.create", group: "grid_workers" })
  await toCapabilities(user)
  await waitFor(() => expect(screen.getByRole("checkbox", { name: "Create a grid" })).toBeChecked())
  await waitFor(() => expect(screen.getByRole("heading", { name: /^Grid & workers/ })).toHaveFocus())
  cleanup()
  open({ mode: "create", capability: "run.schedule" })
  await toCapabilities(user)
  expect(screen.getByRole("checkbox", { name: "Schedules" })).not.toBeChecked()
})

it("stops before the review when a template asks for something this computer can't do", async () => {
  api.capabilities.mockResolvedValue([...available.filter(one => one.id !== "web.site"), { id: "web.site", availability: "unsupported", reason: "Publishing needs a network driver." }])
  api.validate.mockResolvedValue({ manifest: "", diagnostics: [], draft: { name: "Neo", recipe: "neo-grid", capabilities: { "web.site": { selected: true, mode: "required", runnerEditable: true, settings: {} } } } })
  const user = userEvent.setup({ delay: null })
  open({ mode: "run", hubRef: "hub/ana/neo@1.0.0" })
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  expect(await screen.findByText(/Website can't be used here: Publishing needs a network driver\. Turn it off to go on\./)).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  expect(api.plan).not.toHaveBeenCalled()
})

it("sends only the secrets of questions still asked", async () => {
  const user = userEvent.setup({ delay: null })
  api.validate.mockResolvedValue({ manifest: "", diagnostics: [], draft: {
    name: "Site", recipe: "neo-grid",
    capabilities: { "web.site": { selected: true, mode: "default", runnerEditable: true, settings: {} } },
    questions: [{ id: "token", label: "Publishing token", kind: "secret", capability: "web.site", step: "people" }],
  } })
  api.plan.mockResolvedValue({ setupId: "s9", digest: "d9", baseRevision: 0 })
  api.apply.mockResolvedValue({ operationId: "op-9", setupId: "s9" })
  open({ mode: "run", hubRef: "hub/ana/neo@1.0.0" })
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  await user.click(screen.getByRole("button", { name: "Next" }))
  await user.type(await screen.findByLabelText("Publishing token"), "do-not-send")
  await user.click(screen.getByRole("button", { name: "Back" }))
  await user.click(await screen.findByRole("checkbox", { name: "Website" }))
  await user.click(screen.getByRole("button", { name: "Next" }))
  await user.click(await screen.findByRole("button", { name: "Set it up" }))
  await waitFor(() => expect(api.apply).toHaveBeenCalled())
  expect(api.apply.mock.calls[0]![2]).toEqual({})
  expect(JSON.stringify(api.plan.mock.calls)).not.toContain("do-not-send")
  expect(api.plan.mock.calls.at(-1)![0].bindings).toEqual([])
})

it("keeps edited source when the engine can't read it, and only takes it once it can", async () => {
  const user = userEvent.setup({ delay: null })
  open()
  await toCapabilities(user)
  await user.click(screen.getByRole("button", { name: "Source" }))
  const editor = await screen.findByLabelText("yougori-template.yaml")
  await user.clear(editor)
  await user.type(editor, "name: broken: [[")
  api.validate.mockResolvedValueOnce({ manifest: "format_version: 2\nname: Acme\n", diagnostics: [{ code: "invalid_yaml", severity: "error", retryable: false, message: "The file is not valid YAML." }], draft: null })
  await user.click(screen.getByRole("button", { name: "Use this source" }))
  expect(await screen.findByText(/couldn't read this source. Your edits are kept/)).toBeInTheDocument()
  expect(screen.getByLabelText("yougori-template.yaml")).toHaveValue("name: broken: [")
  expect(screen.getByText("The file is not valid YAML.")).toBeInTheDocument()
})

it("sends the same operation id again only when the same plan is retried", async () => {
  const user = userEvent.setup({ delay: null })
  const { SetupCommandError } = await import("@/api/setups/setups-api")
  api.validate.mockResolvedValue({ manifest: "", diagnostics: [], draft: { name: "Neo", recipe: "neo-grid", capabilities: {} } })
  api.plan.mockResolvedValue({ setupId: "s2", digest: "d2", baseRevision: 0 })
  api.apply.mockRejectedValueOnce(new SetupCommandError("The engine restarted.", { code: "engine_restarting", retryable: true }))
    .mockResolvedValueOnce({ operationId: "op-x", setupId: "s2" })
  open({ mode: "run", hubRef: "hub/ana/neo@1.0.0" })
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  await user.click(screen.getByRole("button", { name: "Next" }))
  await user.click(await screen.findByRole("button", { name: "Set it up" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("The engine restarted.")
  await user.click(screen.getByRole("button", { name: "Set it up" }))
  await waitFor(() => expect(api.apply).toHaveBeenCalledTimes(2))
  expect(api.apply.mock.calls[1]![1]).toBe(api.apply.mock.calls[0]![1])
})

it("says so when an installed setup can't be read, instead of showing an empty one", async () => {
  api.validate.mockRejectedValue(new Error("The setup's record is damaged."))
  open({ mode: "configure", setupId: "s1", setupName: "Acme" })
  expect(await screen.findByRole("alert")).toHaveTextContent("The setup's record is damaged. Nothing was changed.")
  expect(screen.queryByRole("checkbox", { name: "Create a grid" })).toBeNull()
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  // Nothing was edited, so Cancel closes without asking.
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
  expect(screen.queryByRole("group", { name: "Discard this draft?" })).toBeNull()
})

it("asks for each consent unticked, and sends only the ones ticked", async () => {
  const user = userEvent.setup({ delay: null })
  api.validate.mockResolvedValue({ manifest: "", diagnostics: [], draft: { name: "Neo", recipe: "neo-grid", capabilities: {} } })
  api.plan.mockResolvedValue({ setupId: "s3", digest: "d3", baseRevision: 0, consents: [
    { id: "copy-claude", message: "Copy your Claude Code sign-in from this computer into the app sandbox." },
    { id: "copy-codex", message: "Copy your Codex sign-in from this computer into the app sandbox." },
  ] })
  api.apply.mockResolvedValue({ operationId: "op-3", setupId: "s3" })
  open({ mode: "run", hubRef: "hub/ana/neo@1.0.0" })
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  await user.click(screen.getByRole("button", { name: "Next" }))
  const claude = await screen.findByRole("checkbox", { name: /Copy your Claude Code sign-in/ })
  const codex = screen.getByRole("checkbox", { name: /Copy your Codex sign-in/ })
  expect(claude).not.toBeChecked()
  expect(codex).not.toBeChecked()
  await user.click(claude)
  await user.click(screen.getByRole("button", { name: "Set it up" }))
  await waitFor(() => expect(api.apply).toHaveBeenCalled())
  expect(api.apply.mock.calls[0]![3]).toEqual(["copy-claude"])
})

it("updates a setup to a newer version by planning that version against the setup's own choices", async () => {
  const user = userEvent.setup({ delay: null })
  const installed: SetupDraft = { name: "Acme", capabilities: { "grid.local_only": { selected: true, mode: "required", runnerEditable: true, settings: {} } } }
  api.validate.mockResolvedValue({ manifest: "format_version: 2\nname: acme\n", diagnostics: [], draft: installed })
  api.plan.mockResolvedValue({ setupId: "s1", digest: "d1", baseRevision: 3 })
  api.apply.mockResolvedValue({ operationId: "op-1", setupId: "s1" })
  open({ mode: "configure", setupId: "s1", setupName: "Acme", update: { publisher: "acme", name: "shop", version: "2.0.0" } })
  expect(await screen.findByRole("heading", { name: "Update Acme to 2.0.0" })).toBeInTheDocument()
  // The installed setup is what is read; the new version is what is planned.
  await waitFor(() => expect(api.validate).toHaveBeenCalledWith({ source: { kind: "installed_setup", setupId: "s1" } }))
  for (let step = 0; step < 6 && !screen.queryByRole("button", { name: "Update to 2.0.0" }); step++) {
    const next = screen.queryByRole("button", { name: "Next" })
    if (!next) break
    await user.click(next)
  }
  const updateButton = await screen.findByRole("button", { name: "Update to 2.0.0" })
  await waitFor(() => expect(api.plan).toHaveBeenCalled())
  const asked = api.plan.mock.calls.at(-1)![0]
  expect(asked.source).toEqual({ kind: "hub", publisher: "acme", name: "shop", version: "2.0.0" })
  expect(asked.existingSetup).toBe("s1")
  // Nothing was changed here, so the engine's merge keeps every choice the setup has.
  expect(asked.answers).toEqual([])
  await user.click(updateButton)
  await waitFor(() => expect(api.apply).toHaveBeenCalled())
})

it("picks a folder for a folder binding, says what the setup may do with it, and asks again on the review", async () => {
  const user = userEvent.setup({ delay: null })
  const read: SetupDraft = {
    name: "Dev Workspace", recipe: null,
    capabilities: { "data.volume": { selected: true, mode: "required", runnerEditable: true, settings: {} } },
    questions: [
      {
        id: "project", label: "Which folder holds your project?", kind: "folder", binding: "folder", required: true,
        group: "files_data", help: "Yougori keeps this folder and the sandbox's copy of it in step, both ways.",
        access: "The sandbox keeps its own copy of this folder and the two are kept in step both ways. A file changed in both places keeps both copies; nothing is replaced silently. You agree to this again before anything is created.",
      },
      { id: "reference", label: "A folder the sandbox may read", kind: "folder", binding: "folder", group: "files_data", access: "The sandbox can read this folder. It is never changed." },
    ],
  }
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], draft: read })
  api.plan.mockResolvedValue({
    setupId: "s-dev", digest: "d2", baseRevision: 0, headline: "Creates Dev Workspace on this computer.",
    resources: [{ resourceId: "dev", label: "Sandbox", kind: "environment", owned: true, action: "create" }],
    consents: [{ id: "write_folder:dev/project", message: "Let setup-s-dev-dev change files in /home/sam/code, the folder you chose for project. Changes travel both ways; a file changed in both places keeps both copies." }],
  })
  api.apply.mockResolvedValue({ operationId: "op-9", setupId: "s-dev" })
  api.operation.mockResolvedValue({ operation: { operationId: "op-9", setupId: "s-dev" }, state: "completed", nextCursor: 1, events: [] })
  api.get.mockResolvedValue({ summary: {}, revision: 1, resources: [], capabilities: [] })

  open({ mode: "run", hubRef: "hub/ana/desks@1.0.0" })
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what to include" })
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "People, connections and access" })

  // Both folders are asked with a picker, each saying what the setup may do with it.
  const folders = screen.getByRole("region", { name: "Folders on this computer" })
  expect(within(folders).getByText(/kept in step both ways/)).toBeInTheDocument()
  expect(within(folders).getByText("The sandbox can read this folder. It is never changed.")).toBeInTheDocument()
  expect(screen.getByLabelText(/Which folder holds your project/)).toHaveValue("")
  // Nothing can be planned until the required folder is chosen.
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()

  // A relative path is refused here, as the planner refuses it, and nothing is answered.
  dialog.open.mockResolvedValueOnce("code/app")
  await user.click(within(folders).getAllByRole("button", { name: "Choose folder" })[0]!)
  expect(await screen.findByText(/not a full path/)).toBeInTheDocument()
  expect(screen.getByLabelText(/Which folder holds your project/)).toHaveValue("")

  dialog.open.mockResolvedValueOnce("/home/sam/code")
  await user.click(within(folders).getAllByRole("button", { name: "Choose folder" })[0]!)
  await waitFor(() => expect(screen.getByLabelText(/Which folder holds your project/)).toHaveValue("/home/sam/code"))
  await user.click(screen.getByRole("button", { name: "Next" }))

  // The folder travels to the planner as its binding's answer, by the binding's id.
  expect(await screen.findByText("Creates Dev Workspace on this computer.")).toBeInTheDocument()
  const planned = api.plan.mock.calls[0]![0]
  expect(planned.answers).toContainEqual({ field: "project", value: "/home/sam/code" })
  expect(planned.answers).not.toContainEqual(expect.objectContaining({ field: "reference" }))

  // The writable folder is agreed to on the review, unticked until the person ticks it, and only
  // then does it travel with the apply.
  const consent = screen.getByRole("checkbox", { name: /change files in .home.sam.code/ })
  expect(consent).not.toBeChecked()
  await user.click(screen.getByRole("button", { name: "Set it up" }))
  expect(api.apply).toHaveBeenCalledWith(expect.anything(), expect.stringMatching(/^op-/), {}, [])
  api.apply.mockClear()
})

it("reveals a capability's settings when its card's Configure is pressed, and hides them again", async () => {
  const user = userEvent.setup({ delay: null })
  // An installed setup with one selected capability that has a setting of its own.
  api.validate.mockResolvedValue({ manifest: "format_version: 2\nname: Acme\n", diagnostics: [], draft: {
    name: "Acme", recipe: "neo-grid",
    capabilities: { "grid.create": { selected: true, mode: "required", runnerEditable: true, settings: {} } },
    questions: [{ id: "grid_name", label: "Grid name", kind: "text", capability: "grid.create" }],
  } })
  api.get.mockResolvedValue({ summary: {}, revision: 1, resources: [], capabilities: [{ id: "grid.create", health: "ready" }] })
  open({ mode: "configure", setupId: "s1", setupName: "Acme" })

  const card = await screen.findByRole("article", { name: "Create a grid" })
  const configure = within(card).getByRole("button", { name: "Configure" })
  // Settings are hidden until Configure is pressed.
  expect(configure).toHaveAttribute("aria-expanded", "false")
  expect(within(card).queryByLabelText("Grid name")).toBeNull()
  await user.click(configure)
  // Now the capability's own setting is shown, and the button says Done.
  expect(within(card).getByRole("button", { name: "Done" })).toHaveAttribute("aria-expanded", "true")
  expect(within(card).getByLabelText("Grid name")).toBeInTheDocument()
  // Pressing Done closes it again.
  await user.click(within(card).getByRole("button", { name: "Done" }))
  expect(within(card).getByRole("button", { name: "Configure" })).toHaveAttribute("aria-expanded", "false")
  expect(within(card).queryByLabelText("Grid name")).toBeNull()
})

it("imports a Compose file: converts it to a draft, shows what it carried over, and sends the compose source", async () => {
  const user = userEvent.setup({ delay: null })
  // Choosing the Compose file converts it at once and the engine returns the draft plus its notes.
  dialog.open.mockResolvedValue("/home/sam/docker-compose.yml")
  api.validate.mockResolvedValue({
    manifest: "format_version: 2\nname: shop\n", project: "format_version: 2\nproject: shop\n", diagnostics: [],
    draft: { name: "shop", capabilities: {} },
    notes: ["Imported 2 services from the Compose file.", "Choose what this setup can do next; the import did not pick any capabilities for you."],
  })
  open()
  await user.type(screen.getByLabelText("Template name"), "shop")
  await user.click(screen.getByRole("radio", { name: /Import a Compose file/ }))
  await user.click(screen.getByRole("button", { name: "Choose a file" }))

  // The compose source goes to validate — never a local_folder with the file path.
  await waitFor(() => expect(api.validate).toHaveBeenCalledWith({ source: { kind: "compose", path: "/home/sam/docker-compose.yml" } }))
  // Its notes are shown before Continue, so the person sees what came over.
  const notes = await screen.findByRole("list", { name: "What the import brought over" })
  expect(within(notes).getByText(/Imported 2 services/)).toBeInTheDocument()
  expect(within(notes).getByText(/did not pick any capabilities/)).toBeInTheDocument()

  // Continuing reaches the capability screen with the imported draft (no extra folder read).
  await user.click(screen.getByRole("button", { name: "Next" }))
  expect(await screen.findByRole("heading", { name: "Choose what it can do" })).toBeInTheDocument()
})

it("creates a template from an existing setup: lists it, reads it, and sends its installed-setup source", async () => {
  const user = userEvent.setup({ delay: null })
  // A setup exists on this computer, so the "Use an existing setup" picker can offer it.
  api.list.mockResolvedValue([{ setupId: "setup-7", name: "Office desks", source: { kind: "installed_setup", setupId: "x" }, state: "running", createdAt: 1 }])
  api.validate.mockResolvedValue({
    manifest: "format_version: 2\nname: Office desks\n", project: "format_version: 2\nproject: office\n", diagnostics: [],
    draft: { name: "Office desks", capabilities: {} },
  })
  await setupFeed.refresh()
  open()
  await user.type(screen.getByLabelText("Template name"), "my-desks")
  await user.click(screen.getByRole("radio", { name: /Use an existing setup/ }))
  // The existing setup is listed; choose it.
  await user.click(await screen.findByRole("radio", { name: "Office desks" }))
  await user.click(screen.getByRole("button", { name: "Next" }))
  // It is read from its installed-setup source into a draft, reaching the capability screen.
  await waitFor(() => expect(api.validate).toHaveBeenCalledWith({ source: { kind: "installed_setup", setupId: "setup-7" } }))
  expect(await screen.findByRole("heading", { name: "Choose what it can do" })).toBeInTheDocument()
})

it("starts from selected sandboxes: captures them, shows what was left out, and sends the environments source", async () => {
  const user = userEvent.setup({ delay: null })
  platformState.value = { state: { cliEnvironmentId: "env-cli", environments: [{ id: "env-web", name: "web" }, { id: "env-db", name: "db" }] } }
  api.validate.mockResolvedValue({
    manifest: "format_version: 2\nname: web\n", project: "format_version: 2\nproject: web\n", diagnostics: [],
    draft: { name: "web", capabilities: {} },
    notes: ["web was not running, so its variables and signed-in tools could not be read.", "The names of variables and signed-in tools are not read here. To include them, run yougori template capture, which reads them from a running sandbox."],
  })
  open()
  await user.type(screen.getByLabelText("Template name"), "from-sandboxes")
  await user.click(screen.getByRole("radio", { name: /Use environments on this computer/ }))
  await user.click(await screen.findByRole("checkbox", { name: "web" }))
  // Reading what would be captured sends the environments source and shows its left-out notes.
  await user.click(screen.getByRole("button", { name: "See what would be captured" }))
  await waitFor(() => expect(api.validate).toHaveBeenCalledWith({ source: { kind: "environments", environments: ["env-web"] } }))
  const notes = await screen.findByRole("list", { name: "What the import brought over" })
  expect(within(notes).getByText(/not read here/)).toBeInTheDocument()
  expect(within(notes).getByText(/was not running/)).toBeInTheDocument()
  // Continuing reaches the capability screen with the captured draft.
  await user.click(screen.getByRole("button", { name: "Next" }))
  expect(await screen.findByRole("heading", { name: "Choose what it can do" })).toBeInTheDocument()
})

it("opens on adding capabilities, with imports beside it and no starter recipe anywhere", async () => {
  const user = userEvent.setup({ delay: null })
  open()
  // Adding capabilities comes first and is already chosen; everything else is an import.
  const options = screen.getAllByRole("radio").map(radio => radio.closest("label")?.querySelector(".grid-choice-label")?.textContent)
  expect(options).toEqual(["Add capabilities", "Import a Hub template", "Import a project folder", "Import a Compose file", "Use an existing setup", "Use environments on this computer"])
  expect(screen.getByRole("radio", { name: /Add capabilities/ })).toBeChecked()
  expect(screen.queryByText(/recipe/i)).toBeNull()
  await user.type(screen.getByLabelText("Template name"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  // Straight onto the six shared groups, with nothing read from anywhere first.
  await screen.findByRole("heading", { name: "Choose what it can do" })
  expect(screen.getAllByRole("heading", { level: 4 })).toHaveLength(6)
  expect(api.validate).not.toHaveBeenCalledWith(expect.objectContaining({ source: expect.anything() }))
})

it("asks which kind of grid only while a grid is chosen, in the generator's words, and sends the answer as the draft's recipe", async () => {
  const user = await toCapabilities((open(), userEvent.setup({ delay: null })))
  expect(screen.queryByRole("group", { name: "Which kind of grid?" })).toBeNull()
  await user.click(screen.getByRole("checkbox", { name: "Create a grid" }))
  const kinds = screen.getByRole("group", { name: "Which kind of grid?" })
  expect(within(kinds).getAllByRole("radio").map(radio => radio.closest("label")?.textContent)).toEqual([
    "Sandbox GridA private workspace for each person, on your computers.",
    "Neo GridServe models across your computers, behind one private API.",
    "Access GridOne place for the credentials your people's agents use.",
    "Swarm Mining GridA private security review of source you own, by an agent in an offline sandbox.",
  ])
  // Without an answer nothing goes on, and the reason is the generator's own.
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  expect(screen.getByText(/A grid needs to say which kind it is/)).toBeInTheDocument()
  await user.click(within(kinds).getByRole("radio", { name: /Sandbox Grid/ }))
  expect(screen.getByRole("button", { name: "Next" })).toBeEnabled()
  await waitFor(() => expect(api.validate).toHaveBeenLastCalledWith({ draft: expect.objectContaining({ recipe: "sandbox-grid" }) }))
  // A grid no longer chosen takes its kind with it, so the answer never travels on its own.
  await user.click(screen.getByRole("checkbox", { name: "Create a grid" }))
  expect(screen.queryByRole("group", { name: "Which kind of grid?" })).toBeNull()
  await waitFor(() => expect(api.validate).toHaveBeenLastCalledWith({ draft: expect.objectContaining({ recipe: null }) }))
})

it("sends the engine's problem about the kind of grid to that question", async () => {
  api.validate.mockResolvedValue({ manifest: "", diagnostics: [{ code: "draft_needs_recipe", severity: "error", retryable: false, message: "A grid needs one of the grid recipes: Sandbox Grid, Neo Grid or Access Grid. Choose one first.", field: "recipe" }] })
  const user = await toCapabilities((open(), userEvent.setup({ delay: null })))
  await user.click(screen.getByRole("checkbox", { name: "Create a grid" }))
  const problems = await screen.findByRole("list", { name: "About the whole template" })
  await user.click(within(problems).getByRole("button", { name: "Go to the kind of grid" }))
  await waitFor(() => expect(screen.getByRole("group", { name: "Which kind of grid?" })).toHaveFocus())
})

it("offers the capabilities of the kind of grid a template's source names, and not to a template of no kind", async () => {
  catalogue.push({ ...catalogue[0]!, id: "people.workspaces", group: "people_access", name: "Workspaces for people", conflicts: [], examples: [], aliases: [], profiles: ["sandbox_grid"] })
  api.capabilities.mockResolvedValue([...available, { id: "people.workspaces", availability: "available" }])
  try {
    const user = userEvent.setup({ delay: null })
    api.validate.mockResolvedValue({ manifest: "", diagnostics: [], draft: { name: "Desks", recipe: "sandbox-grid", capabilities: { "grid.create": { selected: true, mode: "required", runnerEditable: true, settings: {} }, "people.workspaces": { selected: false, mode: "optional", runnerEditable: true, settings: {} } } } })
    open({ mode: "run", hubRef: "hub/ana/desks@1.0.0" })
    await user.type(screen.getByLabelText("Name for this setup"), "Desks")
    await user.click(screen.getByRole("button", { name: "Next" }))
    const card = await screen.findByRole("article", { name: "Workspaces for people" })
    expect(within(card).getByText("Available")).toBeInTheDocument()
    expect(within(card).getByRole("checkbox")).toBeEnabled()

    cleanup()
    api.validate.mockResolvedValue({ manifest: "", diagnostics: [], draft: { name: "Plain", capabilities: { "people.workspaces": { selected: false, mode: "optional", runnerEditable: true, settings: {} } } } })
    open({ mode: "run", hubRef: "hub/ana/plain@1.0.0" })
    await user.type(screen.getByLabelText("Name for this setup"), "Plain")
    await user.click(screen.getByRole("button", { name: "Next" }))
    const other = await screen.findByRole("article", { name: "Workspaces for people" })
    expect(within(other).getByText("Unsupported here")).toBeInTheDocument()
    expect(within(other).getByText(/Works in Sandbox Grid setups for now/)).toBeInTheDocument()
    expect(within(other).getByRole("checkbox")).toBeDisabled()
  } finally {
    catalogue.pop()
  }
})

it("says what the engine added for you, by name, while the choices still need it", async () => {
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], added: ["grid.local_only"] })
  const user = await toCapabilities((open(), userEvent.setup({ delay: null })))
  await user.click(screen.getByRole("checkbox", { name: "AI team" }))
  expect(await screen.findByText(/^Added for you \(needed by your choices\): Run on this computer only\./)).toBeInTheDocument()
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], added: [] })
  await user.click(screen.getByRole("button", { name: "Add Run on this computer only" }))
  await waitFor(() => expect(screen.queryByText(/Added for you/)).toBeNull())
})

it("reviews a preselected inference template before creating any workloads", async () => {
  const user = userEvent.setup({ delay: null })
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], draft: { name: "inference-solver", capabilities: {} } })
  open({ mode: "run", folder: "C:/templates/inference-solver" })
  expect(screen.getByRole("radio", { name: /A template folder on this computer/ })).toBeChecked()
  expect(screen.getByText("C:/templates/inference-solver")).toBeInTheDocument()
  await user.type(screen.getByLabelText("Name for this setup"), "My inference")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await waitFor(() => expect(api.validate).toHaveBeenCalledWith({ source: { kind: "local_folder", path: "C:/templates/inference-solver" } }))
  expect(await screen.findByRole("heading", { name: "Choose what to include" })).toBeInTheDocument()
})

it("runs a template from a folder on this computer, sending that folder as its source", async () => {
  const user = userEvent.setup({ delay: null })
  dialog.open.mockResolvedValue("D:/templates/acme")
  api.validate.mockResolvedValue({ manifest: "format_version: 2\n", diagnostics: [], draft: { name: "acme", capabilities: {} } })
  open({ mode: "run" })
  expect(screen.getByRole("radio", { name: /A template from the Hub/ })).toBeChecked()
  await user.click(screen.getByRole("radio", { name: /A template folder on this computer/ }))
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  await user.click(screen.getByRole("button", { name: "Choose a folder" }))
  expect(await screen.findByText("D:/templates/acme")).toBeInTheDocument()
  await user.type(screen.getByLabelText("Name for this setup"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await waitFor(() => expect(api.validate).toHaveBeenCalledWith({ source: { kind: "local_folder", path: "D:/templates/acme" } }))
  expect(await screen.findByRole("heading", { name: "Choose what to include" })).toBeInTheDocument()
})


it("preselects environments passed from Configure selection", async () => {
  platformState.value = { state: { environments: [{ id: "env-web", name: "web" }, { id: "env-db", name: "db" }] } }
  open({ mode: "create", entry: "environments", environments: ["env-db"] })
  expect(await screen.findByRole("checkbox", { name: "db" })).toBeChecked()
  expect(screen.getByRole("checkbox", { name: "web" })).not.toBeChecked()
})
