// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { readFileSync } from "node:fs"
import { cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { CapabilityDescriptor } from "@/api/setups/types"
import type { HubDetail, HubSummary } from "@/api/hub-api"

/** A keyboard-only walk through the setups screens (plan scenario U02): every step is reached
 *  with Tab, Enter, Space, arrow keys and Escape alone; focus lands somewhere sensible after every
 *  move and comes back where it was after Back, Cancel or closing; every control has a name; and
 *  progress is read out without a screen reader being flooded. */

const setups = vi.hoisted(() => ({
  capabilities: vi.fn(), validate: vi.fn(), plan: vi.fn(), apply: vi.fn(), list: vi.fn(), get: vi.fn(), operation: vi.fn(), cancel: vi.fn(), action: vi.fn(),
  reviewRemoval: vi.fn(), reviewRepair: vi.fn(), permissions: vi.fn().mockResolvedValue({ setupId: "s-1", known: false, reason: "" }),
}))
const hub = vi.hoisted(() => ({
  list: vi.fn(), detail: vi.fn(), file: vi.fn(), star: vi.fn(), instances: vi.fn(), openConsole: vi.fn(), folder: vi.fn(), saveTemplateDraft: vi.fn(),
  builtins: vi.fn(() => Promise.resolve([])),
  pageUrl: () => "https://yougori.com/hub/ana/desks",
}))
const catalogue = vi.hoisted(() => [
  { id: "grid.create", version: 1, group: "grid_workers", name: "Create a grid", summary: "Start a grid.", examples: [], resourceKinds: ["grid"], requires: [], conflicts: [], aliases: [], permissions: [], actions: [], widget: "toggle", status: "shipped", profiles: [], requiresWaivedFor: [] },
  { id: "web.site", version: 1, group: "website_api", name: "Website", summary: "A site.", examples: [], resourceKinds: ["service_publication"], requires: [], conflicts: [], aliases: [], permissions: [], actions: [], widget: "toggle", status: "shipped", profiles: [], requiresWaivedFor: [] },
] as CapabilityDescriptor[])
vi.mock("@/api/setups/setups-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/setups-api")>()), setupsApi: setups }))
vi.mock("@/api/setups/catalogue", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/catalogue")>()), CATALOGUE: catalogue }))
vi.mock("@/api/hub-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/hub-api")>()), hubApi: hub }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn(() => Promise.resolve()) } }))
vi.mock("@/components/ui/toast", () => ({ toastManager: { add: vi.fn() } }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { host: { hostname: "Studio PC" } } }), usePlatformOptional: () => null }))
vi.mock("@/components/use-workspace-actions", async () => {
  const { createContext } = await import("react")
  return {
    useWorkspaceActions: () => ({ grid: null, workers: [], desks: null, refreshGrid: vi.fn(), refreshDesks: vi.fn(), refreshSwarm: vi.fn() }),
    WorkspaceActionsContext: createContext(null),
  }
})

import { setupFeed } from "@/api/setups/progress"
import { HubPage } from "@/pages/hub-page"
import { SetupsPage } from "@/pages/setups-page"
import { SetupBuilderProvider } from "./setup-builder-provider"

const at = 1760000000
const item: HubSummary = {
  ref: "ana/desks", publisher: "ana", name: "desks", kind: "template", title: "Office desks", summary: "Desks for a team.", topics: [], license: "MIT",
  verified: true, latestVersion: "2.0.0", createdAt: at, updatedAt: at, counts: { clones: 1, clonesWeek: 0, stars: 0, forks: 0, versions: 1 }, forkedFrom: null, format: 2,
}
const detail: HubDetail = {
  ...item, state: "active", removed: null, starred: false, mine: false,
  versions: [{ version: "2.0.0", createdAt: at, digest: "a".repeat(64), verified: true, fileCount: 1, bytes: 10, clones: 1, changelog: null }],
  version: { version: "2.0.0", createdAt: at, digest: "a".repeat(64), verified: true, fileCount: 1, bytes: 10, readme: null, changelog: null, files: [], review: { format: 2 }, notices: [] },
}

/** Presses Tab until `target` has focus, as a keyboard user would, and fails if it never does. */
async function tabTo(user: ReturnType<typeof userEvent.setup>, target: HTMLElement, limit = 80) {
  for (let presses = 0; presses < limit; presses += 1) {
    if (document.activeElement === target) return
    await user.tab()
  }
  expect(document.activeElement, `Tab never reached ${target.outerHTML.slice(0, 120)}`).toBe(target)
}

/** Every control in `root` has a name a screen reader can say. */
function everyControlNamed(root: HTMLElement) {
  for (const role of ["button", "checkbox", "radio", "textbox", "combobox", "searchbox", "tab", "spinbutton"]) {
    for (const control of within(root).queryAllByRole(role)) expect(control, `${role} without a name: ${control.outerHTML.slice(0, 120)}`).toHaveAccessibleName()
  }
}

beforeEach(() => {
  hub.list.mockResolvedValue({ items: [item], total: 1, page: 1, pageSize: 24 })
  hub.detail.mockResolvedValue(detail)
  hub.instances.mockResolvedValue([])
  setups.capabilities.mockResolvedValue(catalogue.map(one => ({ id: one.id, availability: "available" })))
  setups.validate.mockResolvedValue({ valid: true, manifest: "format_version: 2\nname: desks\n", diagnostics: [], draft: {
    name: "", capabilities: { "grid.create": { selected: true, mode: "required", runnerEditable: true, settings: {} }, "web.site": { selected: true, mode: "default", runnerEditable: true, settings: {} } },
  } })
  setups.plan.mockResolvedValue({ setupId: "s-1", digest: "d-1", baseRevision: 0, headline: "Creates Office desks.", review: { totals: { environments: 1, cpu: 2, memoryGb: 4, storageGb: 20, gpu: "none" }, pcAccess: [], creates: [] } })
  setups.apply.mockResolvedValue({ operationId: "op-1", setupId: "s-1" })
  setups.list.mockResolvedValue([{ setupId: "s-1", name: "Acme desks", source: { kind: "hub", publisher: "ana", name: "desks", version: "2.0.0" }, state: "creating", createdAt: at, currentOperation: { operationId: "op-1", setupId: "s-1" } }])
  setups.get.mockResolvedValue({ summary: {}, revision: 1, resources: [], capabilities: [{ id: "grid.create", health: "starting" }], actions: [] })
  setups.operation.mockResolvedValue({ operation: { operationId: "op-1", setupId: "s-1" }, state: "applying", nextCursor: 2, events: [
    { cursor: 1, at, step: "grid", message: "Creating the company grid" },
    { cursor: 2, at, step: "desks", message: "Making the first desk" },
  ] })
})
afterEach(() => { cleanup(); vi.clearAllMocks() })

it("runs a Hub template from its page to its progress by keyboard alone, and focus comes back to Run", async () => {
  const user = userEvent.setup({ delay: null })
  render(<SetupBuilderProvider><HubPage /></SetupBuilderProvider>)
  const row = await screen.findByRole("button", { name: /Office desks/ })
  await tabTo(user, row)
  await user.keyboard("{Enter}")
  const run = await screen.findByRole("button", { name: /Run on this computer/ })
  await tabTo(user, run)
  await user.keyboard("{Enter}")

  const dialog = await screen.findByRole("dialog", { name: "Run a template" })
  await waitFor(() => expect(within(dialog).getByRole("heading", { name: "Choose what to set up" })).toHaveFocus())
  expect(within(dialog).getByRole("radio", { name: /A template from the Hub/ })).toBeChecked()
  expect(within(dialog).getByLabelText("Hub address")).toHaveValue("hub/ana/desks@2.0.0")
  everyControlNamed(dialog)
  await tabTo(user, within(dialog).getByLabelText("Name for this setup"))
  await user.keyboard("Acme desks{Enter}")

  await waitFor(() => expect(within(dialog).getByRole("heading", { name: "Choose what to include" })).toHaveFocus())
  expect(setups.validate).toHaveBeenCalledWith({ source: { kind: "hub", publisher: "ana", name: "desks", version: "2.0.0" } })
  everyControlNamed(dialog)
  const website = within(dialog).getByRole("checkbox", { name: "Website" })
  await tabTo(user, website)
  await user.keyboard(" ")
  expect(website).not.toBeChecked()
  await tabTo(user, within(dialog).getByRole("button", { name: "Next" }))
  await user.keyboard("{Enter}")

  await waitFor(() => expect(within(dialog).getByRole("heading", { name: "What will happen" })).toHaveFocus())
  expect(await within(dialog).findByText("Creates Office desks.")).toBeInTheDocument()
  expect(within(dialog).getByText("4 GB")).toBeInTheDocument()
  everyControlNamed(dialog)
  await tabTo(user, within(dialog).getByRole("button", { name: "Set it up" }))
  await user.keyboard("{Enter}")

  await waitFor(() => expect(within(dialog).getByRole("heading", { name: "Setting it up" })).toHaveFocus())
  expect(await within(dialog).findByText("Making the first desk")).toBeInTheDocument()
  // The state and the count are read out; each step's own line is not, so a long setup is not
  // read out line by line.
  const live = within(dialog).getAllByRole("status")
  expect(live.some(region => /Working/.test(region.textContent ?? ""))).toBe(true)
  expect(live.some(region => /Making the first desk/.test(region.textContent ?? ""))).toBe(false)
  expect(within(dialog).queryByRole("button", { name: "Back" })).toBeNull()
  everyControlNamed(dialog)

  await user.keyboard("{Escape}")
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Run a template" })).toBeNull())
  await waitFor(() => expect(screen.getByRole("button", { name: /Run on this computer/ })).toHaveFocus())
  expect(hub.openConsole).not.toHaveBeenCalled()
})

it("Close and Escape before anything starts close the template creator, and give focus back to what opened it", async () => {
  // Create template makes a template from Sandbox VMs (VmTemplateCreator); running and changing
  // setups keep the template builder.
  const user = userEvent.setup({ delay: null })
  render(<SetupBuilderProvider><HubPage /></SetupBuilderProvider>)
  const create = await screen.findByRole("button", { name: /Create template/ })
  await tabTo(user, create)
  await user.keyboard("{Enter}")
  const dialog = await screen.findByRole("dialog", { name: "Create template from VMs" })
  // The footer's Close (the header also has an icon-only one).
  await tabTo(user, within(dialog).getByText("Close", { selector: "button" }))
  await user.keyboard("{Enter}")
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Create template from VMs" })).toBeNull())
  await waitFor(() => expect(screen.getByRole("button", { name: /Create template/ })).toHaveFocus())

  await user.keyboard("{Enter}")
  await screen.findByRole("dialog", { name: "Create template from VMs" })
  await user.keyboard("{Escape}")
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Create template from VMs" })).toBeNull())
  await waitFor(() => expect(screen.getByRole("button", { name: /Create template/ })).toHaveFocus())
})

it("walks My setups into a setup and back by keyboard, and only the open setup reads its progress out", async () => {
  const user = userEvent.setup({ delay: null })
  setups.list.mockResolvedValue([
    { setupId: "s-1", name: "Acme desks", source: { kind: "installed_setup", setupId: "x" }, state: "updating", createdAt: at, currentOperation: { operationId: "op-1", setupId: "s-1" } },
    { setupId: "s-2", name: "Model lab", source: { kind: "installed_setup", setupId: "y" }, state: "updating", createdAt: at, currentOperation: { operationId: "op-2", setupId: "s-2" } },
  ])
  setups.operation.mockImplementation(async (id: string) => ({ operation: { operationId: id, setupId: id === "op-1" ? "s-1" : "s-2" }, state: "applying", nextCursor: 1, events: [{ cursor: 1, at, step: "x", message: `Working on ${id}` }] }))
  await setupFeed.refresh()
  render(<SetupBuilderProvider><SetupsPage /></SetupBuilderProvider>)
  const page = await screen.findByRole("region", { name: "My setups" })
  await within(page).findByText("Working on op-2")
  everyControlNamed(page)
  // Two setups moving at once: neither card's progress is a live region.
  expect(within(page).queryAllByRole("status").filter(region => /Working/.test(region.textContent ?? ""))).toHaveLength(0)

  const open = within(page).getByRole("button", { name: "Open Acme desks" })
  await tabTo(user, open)
  await user.keyboard("{Enter}")
  await waitFor(() => expect(screen.getByRole("heading", { level: 2, name: "Acme desks" })).toHaveFocus())
  // The setup being looked at reads its progress out.
  expect(screen.getAllByRole("status").some(region => /Working/.test(region.textContent ?? ""))).toBe(true)
  const overview = screen.getByRole("tab", { name: "Overview" })
  await tabTo(user, overview)
  await user.keyboard("{ArrowRight}")
  expect(screen.getByRole("tab", { name: "Workers" })).toHaveFocus()
  await user.keyboard("{End}")
  expect(screen.getByRole("tab", { name: "Settings" })).toHaveFocus()
  expect(screen.getByRole("tabpanel")).toHaveAccessibleName("Settings")
  everyControlNamed(screen.getByRole("region", { name: "My setups" }))
  await tabTo(user, screen.getByRole("button", { name: "All setups" }), 120)
  await user.keyboard("{Enter}")
  await waitFor(() => expect(screen.getByRole("button", { name: "Open Acme desks" })).toHaveFocus())
})

it("stops every moving mark when someone has asked for less motion", () => {
  const css = readFileSync("src/components/setups/setups.css", "utf8")
  const reduced = css.slice(css.indexOf("@media (prefers-reduced-motion: reduce)"))
  expect(reduced).toContain('.setup-state[data-tone="busy"] .setup-state-mark { animation: none; }')
  expect(reduced).toContain(".setup-card { transition: none; }")
  // Every animation and transition in the file has its reduced-motion counterpart.
  const animated = [...css.matchAll(/^([^@{}\n][^{}\n]*)\{[^}]*\banimation:/gm)].map(match => match[1]!.trim())
  for (const selector of animated) expect(reduced).toContain(`${selector} { animation: none; }`)
})
