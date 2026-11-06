// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { CapabilityDescriptor, OperationProgress, SetupDetailView, SetupSummary } from "@/api/setups/types"

const api = vi.hoisted(() => ({
  capabilities: vi.fn(), validate: vi.fn(), plan: vi.fn(), apply: vi.fn(), list: vi.fn(), get: vi.fn(), operation: vi.fn(), cancel: vi.fn(), action: vi.fn(), reviewRemoval: vi.fn(), reviewRepair: vi.fn(), permissions: vi.fn(),
  resourceAction: vi.fn(), reviewResourceAction: vi.fn(), reviewAdoption: vi.fn(),
}))
const catalogue = vi.hoisted(() => [
  { id: "grid.create", name: "Create a grid", group: "grid_workers", resourceKinds: ["grid", "compute_pool"] },
  { id: "web.site", name: "Website", group: "website_api", resourceKinds: ["service_publication"] },
] as Partial<CapabilityDescriptor>[])

vi.mock("@/api/setups/setups-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/setups-api")>()), setupsApi: api }))
vi.mock("@/api/setups/catalogue", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/catalogue")>()), CATALOGUE: catalogue }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { host: { hostname: "Studio PC" } } }), usePlatformOptional: () => null }))
vi.mock("@/components/use-workspace-actions", async () => {
  const { createContext } = await import("react")
  return {
    useWorkspaceActions: () => ({ grid: null, workers: [], desks: null, refreshGrid: vi.fn(), refreshDesks: vi.fn(), refreshSwarm: vi.fn() }),
    WorkspaceActionsContext: createContext(null),
  }
})
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn(() => Promise.resolve()) } }))
const hubDetail = vi.hoisted(() => vi.fn())
vi.mock("@/api/hub-api", async importOriginal => {
  const original = await importOriginal<typeof import("@/api/hub-api")>()
  return { ...original, hubApi: { ...original.hubApi, detail: hubDetail } }
})
vi.mock("@/components/setups/template-builder", () => ({
  TemplateBuilder: ({ intent, onClose }: { intent: unknown; onClose(): void }) => <div role="dialog" aria-label="Builder">
    <span>{JSON.stringify(intent)}</span><button type="button" onClick={onClose}>Close builder</button>
  </div>,
}))
// Create template opens the code-authored VM template creator, not the capability builder.
vi.mock("@/components/setups/vm-template-creator", () => ({
  VmTemplateCreator: ({ onClose }: { onClose(): void }) => <div role="dialog" aria-label="Create template from VMs">
    <button type="button" onClick={onClose}>Close creator</button>
  </div>,
}))

import { setupFeed } from "@/api/setups/progress"
import { WorkspaceActionsContext } from "@/components/use-workspace-actions"
import { SetupUnavailableError } from "@/api/setups/setups-api"
import { SetupsPage } from "./setups-page"

const summary = (over: Partial<SetupSummary> = {}): SetupSummary => ({
  setupId: "s1", name: "Acme desks", source: { kind: "hub", publisher: "yougori", name: "sandbox-grid", version: "1.0.0" }, state: "running", createdAt: 1, ...over,
})
const detail = (over: Partial<SetupDetailView> = {}): SetupDetailView => ({
  summary: summary(), revision: 4, resources: [],
  capabilities: [{ id: "grid.create", health: "ready" }, { id: "web.site", health: "needs_sign_in", detail: "Sign in to Cloudflare to publish it." }],
  actions: ["stop", "remove"], outputs: [{ key: "public_url", label: "Address", value: "https://desks.example.com" }], ...over,
})

async function show(highlight: string | null = null, workspace: Record<string, unknown> | null = null) {
  await setupFeed.refresh()
  const page = <SetupsPage highlight={highlight} />
  render(workspace ? <WorkspaceActionsContext.Provider value={workspace as never}>{page}</WorkspaceActionsContext.Provider> : page)
}

beforeEach(() => {
  api.list.mockResolvedValue([summary(), summary({ setupId: "s2", name: "Model lab", state: "stopped", source: { kind: "local_folder", path: "lab" } })])
  api.get.mockImplementation(async (id: string) => id === "s1" ? detail() : detail({ summary: summary({ setupId: "s2" }), revision: 2, capabilities: [], actions: ["start", "remove"], outputs: [] }))
  api.action.mockResolvedValue({ operationId: "op-9", setupId: "s1" })
  api.permissions.mockResolvedValue({ setupId: "s1", known: true, version: "1.0.0", permissions: [], downloads: [], secrets: [], pcAccess: [], costs: [] })
  // The Hub has nothing newer unless a test says so.
  hubDetail.mockResolvedValue({ state: "active", latestVersion: "1.0.0", version: { version: "1.0.0" } })
})
afterEach(() => { cleanup(); vi.clearAllMocks() })

it("lists each setup with its state in words, readiness by capability, and what can be done next", async () => {
  await show()
  const acme = await screen.findByRole("article", { name: "Acme desks" })
  expect(within(acme).getByText("Running")).toBeInTheDocument()
  expect(within(acme).getByText("From hub/yougori/sandbox-grid@1.0.0")).toBeInTheDocument()
  const readiness = within(acme).getByRole("list", { name: "Readiness of Acme desks" })
  expect(within(readiness).getByText("Create a grid")).toBeInTheDocument()
  expect(within(readiness).getByText("Ready")).toBeInTheDocument()
  expect(within(readiness).getByText("Needs sign-in")).toBeInTheDocument()
  expect(within(readiness).getByText("Sign in to Cloudflare to publish it.")).toBeInTheDocument()
  expect(within(acme).getByRole("button", { name: "https://desks.example.com" })).toBeInTheDocument()
  for (const name of ["Configure", "Add capability", "Stop", "Remove…"]) expect(within(acme).getByRole("button", { name })).toBeInTheDocument()
  expect(within(acme).queryByRole("button", { name: "Start" })).toBeNull()
  const lab = screen.getByRole("article", { name: "Model lab" })
  expect(within(lab).getByText("Stopped")).toBeInTheDocument()
  expect(within(lab).getByRole("button", { name: "Start" })).toBeInTheDocument()
})

it("starts and stops at once with the revision it read, and removes only after its review", async () => {
  const user = userEvent.setup({ delay: null })
  api.reviewRemoval.mockResolvedValue({ setupId: "s1", digest: "rm-1", baseRevision: 4, headline: "Removes Acme desks.", retained: ["The desks volume and its files"], resources: [{ resourceId: "pool", label: "Desk pool", kind: "workspace_pool", owned: true, action: "remove" }] })
  api.apply.mockResolvedValue({ operationId: "op-rm", setupId: "s1" })
  await show()
  const acme = await screen.findByRole("article", { name: "Acme desks" })
  await user.click(within(acme).getByRole("button", { name: "Stop" }))
  await waitFor(() => expect(api.action).toHaveBeenCalledWith("s1", "stop", { expectedRevision: 4, operationId: expect.stringMatching(/^op-/) }))

  await user.click(within(acme).getByRole("button", { name: "Remove…" }))
  const review = await within(acme).findByRole("region", { name: "Remove Acme desks" })
  expect(api.reviewRemoval).toHaveBeenCalledWith("s1", 4)
  expect(within(review).getByText("Removes Acme desks.")).toBeInTheDocument()
  expect(within(review).getByText("The desks volume and its files")).toBeInTheDocument()
  expect(api.apply).not.toHaveBeenCalled()
  await user.click(within(review).getByRole("button", { name: "Keep it" }))
  await waitFor(() => expect(within(acme).getByRole("button", { name: "Remove…" })).toHaveFocus())
  expect(api.apply).not.toHaveBeenCalled()

  await user.click(within(acme).getByRole("button", { name: "Remove…" }))
  await user.click(await within(acme).findByRole("button", { name: "Remove Acme desks" }))
  await waitFor(() => expect(api.apply).toHaveBeenCalledWith(expect.objectContaining({ setupId: "s1", digest: "rm-1", baseRevision: 4 }), expect.stringMatching(/^op-/), undefined, []))
})

it("shows each part's last check in the parts table, and says when a part was not healthy then", async () => {
  const user = userEvent.setup({ delay: null })
  const at = 1_793_037_600 // a fixed second; the table shows its local time
  api.get.mockImplementation(async (id: string) => id === "s1" ? detail({
    resources: [
      { resourceId: "site", label: "Website", kind: "service_publication", owned: true, observed: "running", lastCheckedAt: at, lastHealthyAt: at },
      { resourceId: "data", label: "Desk data", kind: "volume", owned: true, observed: "present", drift: "Changed outside Yougori.", lastCheckedAt: at, lastHealthyAt: null },
      { resourceId: "new", label: "Fresh pool", kind: "workspace_pool", owned: true, observed: "unknown" },
    ],
  }) : detail({ summary: summary({ setupId: "s2" }), revision: 2, capabilities: [], actions: ["start", "remove"], outputs: [] }))
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  await user.click(within(tabs).getByRole("tab", { name: "Settings" }))
  const made = within(screen.getByRole("tabpanel")).getByRole("table", { name: "Resources of Acme desks" })
  const shown = new Date(at * 1000).toLocaleTimeString(undefined, { timeStyle: "short" })
  // A part checked and found well shows only the time; a part checked but not well says so; a part
  // never checked shows a dash.
  const site = within(made).getByRole("rowheader", { name: /Website/ }).closest("tr")!
  expect(within(site).getByText(`Checked ${shown}`)).toBeInTheDocument()
  expect(within(site).queryByText(/not healthy when last checked/)).toBeNull()
  const data = within(made).getByRole("rowheader", { name: /Desk data/ }).closest("tr")!
  expect(within(data).getByText(/not healthy when last checked/)).toBeInTheDocument()
  const fresh = within(made).getByRole("rowheader", { name: /Fresh pool/ }).closest("tr")!
  expect(within(fresh).queryByText(/Checked/)).toBeNull()
})

it("offers Repair only when a part is missing or drifted, reviews first, and applies the reviewed digest", async () => {
  const user = userEvent.setup({ delay: null })
  // Acme has a part the engine last saw missing, and another that drifted; both are what repair puts right.
  api.get.mockImplementation(async (id: string) => id === "s1" ? detail({
    resources: [
      { resourceId: "pool", label: "Desk pool", kind: "workspace_pool", owned: true, observed: "missing" },
      { resourceId: "vol", label: "Desk data", kind: "volume", owned: true, observed: "present", drift: "Changed outside Yougori." },
    ],
  }) : detail({ summary: summary({ setupId: "s2" }), revision: 2, capabilities: [], actions: ["start", "remove"], outputs: [] }))
  api.reviewRepair.mockResolvedValue({ setupId: "s1", digest: "rp-1", baseRevision: 4, intent: "repair", headline: "Puts the missing desk pool back.", resources: [{ resourceId: "pool", label: "Desk pool", kind: "workspace_pool", owned: true, action: "create" }] })
  api.apply.mockResolvedValue({ operationId: "op-rp", setupId: "s1" })
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  // The overview offers a way in, since parts are out of place.
  expect(within(screen.getByRole("tabpanel")).getByText(/Some parts are missing or have drifted/)).toBeInTheDocument()
  await user.click(within(tabs).getByRole("tab", { name: "Settings" }))
  const settings = screen.getByRole("tabpanel")

  await user.click(within(settings).getByRole("button", { name: "Repair…" }))
  const review = await within(settings).findByRole("region", { name: "Repair Acme desks" })
  expect(api.reviewRepair).toHaveBeenCalledWith("s1", 4)
  expect(within(review).getByText("Puts the missing desk pool back.")).toBeInTheDocument()
  expect(within(review).getByText("Desk pool")).toBeInTheDocument()
  expect(api.apply).not.toHaveBeenCalled()
  // Not now closes the review and changes nothing.
  await user.click(within(review).getByRole("button", { name: "Not now" }))
  await waitFor(() => expect(within(settings).getByRole("button", { name: "Repair…" })).toHaveFocus())
  expect(api.apply).not.toHaveBeenCalled()

  await user.click(within(settings).getByRole("button", { name: "Repair…" }))
  await user.click(await within(settings).findByRole("button", { name: "Repair Acme desks" }))
  await waitFor(() => expect(api.apply).toHaveBeenCalledWith(expect.objectContaining({ setupId: "s1", digest: "rp-1", baseRevision: 4 }), expect.stringMatching(/^op-/), undefined, []))
})

it("shows the change running on a setup from the shared feed, and asks before cancelling it", async () => {
  const user = userEvent.setup({ delay: null })
  api.list.mockResolvedValue([summary({ state: "updating", currentOperation: { operationId: "op-1", setupId: "s1" } })])
  api.operation.mockResolvedValue({ operation: { operationId: "op-1", setupId: "s1" }, state: "applying", nextCursor: 1, events: [{ cursor: 1, at: 1, step: "storage", message: "Reserving storage" }] } satisfies OperationProgress)
  api.cancel.mockResolvedValue({})
  await show()
  const acme = await screen.findByRole("article", { name: "Acme desks" })
  expect(within(acme).getByText("Updating")).toBeInTheDocument()
  expect(within(acme).getByText("Reserving storage")).toBeInTheDocument()
  expect(within(acme).getByRole("button", { name: "Configure" })).toBeDisabled()
  await user.click(within(acme).getByRole("button", { name: "Cancel" }))
  expect(api.cancel).not.toHaveBeenCalled()
  await user.click(within(acme).getByRole("button", { name: "Cancel the change" }))
  await waitFor(() => expect(api.cancel).toHaveBeenCalledWith("op-1"))
})

it("with nothing set up offers Run a template and Create template, and says plainly when this build has no setups", async () => {
  const user = userEvent.setup({ delay: null })
  api.list.mockRejectedValue(new SetupUnavailableError("setup_list"))
  await show()
  expect(await screen.findByText("Nothing set up yet")).toBeInTheDocument()
  expect(screen.getByRole("note")).toHaveTextContent("aren't available in this build of Yougori yet. Your sandboxes work as before.")
  // The two ways in are in the header and again in the empty space: run something published, or
  // make a template by adding capabilities or importing. Nothing names a grid or a recipe.
  const runs = screen.getAllByRole("button", { name: /Run a template/ })
  expect(runs).toHaveLength(2)
  await user.click(runs[1]!)
  expect(await screen.findByRole("dialog", { name: "Builder" })).toHaveTextContent('{"mode":"run"}')
  await user.click(screen.getByRole("button", { name: "Close builder" }))
  await user.click(screen.getAllByRole("button", { name: /Create template/ })[1]!)
  expect(await screen.findByRole("dialog", { name: "Create template from VMs" })).toBeInTheDocument()
  expect(screen.queryByRole("dialog", { name: "Builder" })).toBeNull()
  await user.click(screen.getByRole("button", { name: "Close creator" }))
  await user.click(runs[0]!)
  expect(await screen.findByRole("dialog", { name: "Builder" })).toHaveTextContent('{"mode":"run"}')
  expect(screen.queryByRole("button", { name: /grid|recipe/i })).toBeNull()
})

it("says once, plainly, that the engine isn't answering while the feed waits longer between tries", async () => {
  api.list.mockRejectedValue(new Error("The engine did not answer."))
  for (let attempt = 0; attempt < 6; attempt += 1) await setupFeed.refresh().catch(() => undefined)
  render(<SetupsPage />)
  const said = await screen.findByText(/^Yougori's engine isn't answering\. Trying again in/)
  expect(said).toHaveAttribute("role", "status")
  expect(screen.queryByText(/Yougori couldn't read your setups/)).toBeNull()
})

it("opens a linked setup straight into its own view, where Settings has Configure and Add capability", async () => {
  const user = userEvent.setup({ delay: null })
  await show("s2")
  const heading = await screen.findByRole("heading", { level: 2, name: "Model lab" })
  await waitFor(() => expect(heading).toHaveFocus())
  const tabs = screen.getByRole("tablist", { name: "Model lab sections" })
  expect(within(tabs).getAllByRole("tab").map(tab => tab.textContent)).toEqual(["Overview", "Activity", "Settings"])
  await user.click(within(tabs).getByRole("tab", { name: "Settings" }))
  await user.click(screen.getByRole("button", { name: "Add capability" }))
  expect(await screen.findByRole("dialog", { name: "Builder" })).toHaveTextContent('{"mode":"configure","setupId":"s2","setupName":"Model lab","addCapability":true}')
})

it("the Settings tab reads what a setup is allowed to do: permissions, downloads, a secret by its question, folders and costs", async () => {
  const user = userEvent.setup({ delay: null })
  api.permissions.mockResolvedValue({
    setupId: "s1", known: true, version: "1.0.0",
    permissions: ["Run containers on this computer.", "Open a public web address for this setup."],
    downloads: [{ kind: "image", name: "node:24" }],
    secrets: [{ resource: "web", variable: "OPENAI_API_KEY", source: "the question api_key" }],
    pcAccess: [{ environment: "web", path: "/home/sam/data", readOnly: true }],
    costs: ["Cloud GPU: about $2 an hour while it runs."],
  })
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  await user.click(within(tabs).getByRole("tab", { name: "Settings" }))
  const section = await screen.findByRole("region", { name: "What it is allowed to do" })
  expect(api.permissions).toHaveBeenCalledWith("s1")
  expect(within(section).getByText("Run containers on this computer.")).toBeInTheDocument()
  expect(within(section).getByText(/node:24/)).toBeInTheDocument()
  // The secret is named by its question and its variable, never a value.
  expect(within(section).getByText(/web: OPENAI_API_KEY — from the question api_key/)).toBeInTheDocument()
  expect(within(section).getByText(/\/home\/sam\/data \(read only\)/)).toBeInTheDocument()
  expect(within(section).getByText(/Cloud GPU: about \$2 an hour/)).toBeInTheDocument()
})

it("the Settings tab shows the plain reason when a setup's permissions can't be read again", async () => {
  const user = userEvent.setup({ delay: null })
  api.permissions.mockResolvedValue({ setupId: "s1", known: false, reason: "This grid was set up before templates, so Yougori has no template to read its permissions from." })
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  await user.click(within(tabs).getByRole("tab", { name: "Settings" }))
  const section = await screen.findByRole("region", { name: "What it is allowed to do" })
  expect(within(section).getByText(/set up before templates/)).toBeInTheDocument()
  // No lists are shown when the permissions aren't known.
  expect(within(section).queryByRole("list")).toBeNull()
})

it("a capability tab shows its own parts from what the engine sent: a published address, with its link", async () => {
  const user = userEvent.setup({ delay: null })
  api.get.mockImplementation(async (id: string) => id === "s1" ? detail({
    resources: [{ resourceId: "web", kind: "service_publication", owned: true, label: "Website", observed: "running", exposure: { to: "web", port: 3000, access: "domain" } }],
    outputs: [{ key: "public_url", label: "Website", value: "https://shop.example.com" }],
  }) : detail())
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  await user.click(within(tabs).getByRole("tab", { name: "Website & API" }))
  const panel = screen.getByRole("tabpanel")
  // The group's own content names the published address, its port, how it is reached, and its link.
  expect(within(panel).getByRole("list", { name: "Published addresses" })).toBeInTheDocument()
  expect(within(panel).getByText(/web on port 3000, reached your own domain/)).toBeInTheDocument()
  expect(within(panel).getByRole("link", { name: "https://shop.example.com" })).toHaveAttribute("href", "https://shop.example.com")
})

it("follows the template's declared views: a history view brings Activity forward, and a storage view shows the Data tab", async () => {
  const user = userEvent.setup({ delay: null })
  // The template declares `logs` (bring Activity forward) and `storage` (show the Data tab), even
  // though no files_data capability is on. A view the desktop can't draw a tab for is ignored.
  api.get.mockImplementation(async (id: string) => id === "s1" ? detail({
    views: ["logs", "storage", "dashboard"],
    resources: [{ resourceId: "vol", label: "Desk data", kind: "volume", owned: true, observed: "present", retainedData: true }],
  }) : detail({ summary: summary({ setupId: "s2" }), revision: 2, capabilities: [], actions: ["start", "remove"], outputs: [] }))
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  // Activity sits right after Overview; Data appears from the storage view, Automation (where its
  // sandboxes' logs are read) from the logs view; the unknown view adds nothing.
  expect(within(tabs).getAllByRole("tab").map(tab => tab.textContent)).toEqual(["Overview", "Activity", "Workers", "Website & API", "Data", "Automation", "Settings"])
  await user.click(within(tabs).getByRole("tab", { name: "Data" }))
  // The Data tab lists the volume even though no files_data capability is on.
  const stored = within(screen.getByRole("tabpanel")).getByRole("list", { name: "Stored data" })
  expect(within(stored).getByText("Desk data")).toBeInTheDocument()
})

it("gives a setup a tab for each kind of capability it has, moves between tabs by arrow key, and goes back to the list", async () => {
  const user = userEvent.setup({ delay: null })
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  expect(within(tabs).getAllByRole("tab").map(tab => tab.textContent)).toEqual(["Overview", "Workers", "Website & API", "Activity", "Settings"])
  const overview = within(tabs).getByRole("tab", { name: "Overview" })
  expect(overview).toHaveAttribute("aria-selected", "true")
  expect(screen.getByRole("tabpanel")).toHaveAccessibleName("Overview")
  overview.focus()
  await user.keyboard("{ArrowRight}")
  const workers = within(tabs).getByRole("tab", { name: "Workers" })
  expect(workers).toHaveFocus()
  expect(workers).toHaveAttribute("aria-selected", "true")
  expect(within(screen.getByRole("tabpanel")).getByText("Create a grid")).toBeInTheDocument()
  expect(within(screen.getByRole("tabpanel")).queryByText("Website")).toBeNull()
  await user.keyboard("{End}")
  expect(within(tabs).getByRole("tab", { name: "Settings" })).toHaveFocus()
  expect(within(screen.getByRole("tabpanel")).getByRole("button", { name: "Remove…" })).toBeInTheDocument()
  // Nothing is out of place here, so repair is not offered.
  expect(within(screen.getByRole("tabpanel")).queryByRole("button", { name: "Repair…" })).toBeNull()
  await user.click(screen.getByRole("button", { name: "All setups" }))
  await waitFor(() => expect(screen.getByRole("button", { name: "Open Acme desks" })).toHaveFocus())
})

it("shows a setup's recent changes in Activity, with what happened in the one chosen", async () => {
  const user = userEvent.setup({ delay: null })
  api.get.mockImplementation(async (id: string) => id === "s1"
    ? detail({ operations: [
      { operationId: "op-new", kind: "stop", state: "completed", createdAt: 1_760_000_100 },
      { operationId: "op-old", kind: "create", state: "failed", createdAt: 1_760_000_000, error: { code: "operation_cancelled", message: "Cancelled.", severity: "error", retryable: true } },
    ] })
    : detail({ summary: summary({ setupId: "s2" }), capabilities: [], actions: [] }))
  api.operation.mockImplementation(async (id: string) => ({ operation: { operationId: id, setupId: "s1" }, state: id === "op-new" ? "completed" : "failed", nextCursor: 1, events: [{ cursor: 1, at: 1, step: "x", message: id === "op-new" ? "Stopped the desks" : "Started creating" }] }))
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  await user.click(screen.getByRole("tab", { name: "Activity" }))
  const changes = screen.getByRole("list", { name: "Recent changes" })
  const rows = within(changes).getAllByRole("button")
  expect(rows[0]).toHaveTextContent(/^StopFinished/)
  expect(rows[1]).toHaveTextContent(/^Set upCancelled/)
  expect(await screen.findByText("Stopped the desks")).toBeInTheDocument()
  await user.click(rows[1]!)
  expect(await screen.findByText("Started creating")).toBeInTheDocument()
})

it("carries out a capability's next actions: the Yougori sign-in opens, other sign-ins say where, logs open Activity", async () => {
  const user = userEvent.setup({ delay: null })
  const openNetwork = vi.fn()
  api.list.mockResolvedValue([summary()])
  api.get.mockImplementation(async (id: string) => detail({
    summary: summary({ setupId: id }),
    capabilities: [
      { id: "grid.create", health: "needs_sign_in", nextActions: [{ kind: "sign_in", provider: "yougori" }] },
      { id: "web.site", health: "degraded", nextActions: [{ kind: "sign_in", provider: "Cloudflare" }, { kind: "view_logs" }] },
    ],
  }))
  await show(null, { openNetwork })
  const acme = await screen.findByRole("article", { name: "Acme desks" })
  await user.click(within(acme).getByRole("button", { name: "Sign in to yougori: Create a grid" }))
  expect(openNetwork).toHaveBeenCalledTimes(1)
  await user.click(within(acme).getByRole("button", { name: "Sign in to Cloudflare: Website" }))
  expect(within(acme).getByText(/Sign in to Cloudflare from the environment that uses it/)).toBeInTheDocument()
  await user.click(within(acme).getByRole("button", { name: "Open its logs: Website" }))
  expect(await screen.findByRole("tab", { name: "Activity" })).toHaveAttribute("aria-selected", "true")
})

it("says where a computer is added to a grid, and gives a grid made from a template no page of its own", async () => {
  const user = userEvent.setup({ delay: null })
  api.list.mockResolvedValue([summary({ profile: "access_grid" })])
  api.get.mockResolvedValue(detail({ capabilities: [{ id: "grid.create", health: "waiting_for_computer", nextActions: [{ kind: "add_computer" }] }] }))
  await show()
  const acme = await screen.findByRole("article", { name: "Acme desks" })
  await user.click(within(acme).getByRole("button", { name: "Add a computer: Create a grid" }))
  expect(within(acme).getByRole("status")).toHaveTextContent("Add a computer to the setup that uses it from its own configuration under My setups.")
  // The branded grid pages are gone: a setup of a grid profile has the same tabs as any other.
  await user.click(within(acme).getByRole("button", { name: "Open Acme desks" }))
  const tabs = await screen.findByRole("tablist", { name: "Acme desks sections" })
  expect(within(tabs).getAllByRole("tab").map(tab => tab.textContent)).toEqual(["Overview", "Workers", "Activity", "Settings"])
  expect(screen.queryByRole("tab", { name: "Access Grid" })).toBeNull()
})

it("keeps a failed change in sight after the engine lets go of it, and retries that same operation", async () => {
  const user = userEvent.setup({ delay: null })
  api.list.mockResolvedValue([summary({ state: "creating" })])
  api.get.mockResolvedValue(detail({
    actions: ["remove"],
    operations: [{ operationId: "op-f", kind: "create", state: "failed", createdAt: 1, error: { code: "pull_failed", message: "The image could not be downloaded.", severity: "error", retryable: true, nextActions: [{ kind: "retry" }] } }],
  }))
  await show()
  const acme = await screen.findByRole("article", { name: "Acme desks" })
  expect(within(acme).getByText("Stopped part way")).toBeInTheDocument()
  expect(within(acme).queryByText("Being set up")).toBeNull()
  expect(within(acme).getByText("The last change did not finish")).toBeInTheDocument()
  expect(within(acme).getByRole("alert")).toHaveTextContent("The image could not be downloaded.")
  await user.click(within(acme).getByRole("button", { name: "Try again" }))
  await waitFor(() => expect(api.action).toHaveBeenCalledWith("s1", "retry", { operationId: "op-f" }))
})

it("starts with one operation id, sends it again on a retryable failure, and makes a new one after", async () => {
  const user = userEvent.setup({ delay: null })
  const { SetupCommandError } = await import("@/api/setups/setups-api")
  api.action.mockRejectedValueOnce(new SetupCommandError("Try again in a moment.", { code: "setups_starting", retryable: true }))
    .mockResolvedValueOnce({ operationId: "op-ok", setupId: "s2" })
    .mockResolvedValueOnce({ operationId: "op-ok2", setupId: "s2" })
  await show()
  const lab = await screen.findByRole("article", { name: "Model lab" })
  await user.click(within(lab).getByRole("button", { name: "Start" }))
  expect(await within(lab).findByRole("alert")).toHaveTextContent("Try again in a moment.")
  await user.click(within(lab).getByRole("button", { name: "Start" }))
  await waitFor(() => expect(api.action).toHaveBeenCalledTimes(2))
  const first = api.action.mock.calls[0]![2].operationId
  expect(api.action.mock.calls[1]![2].operationId).toBe(first)
  await user.click(within(lab).getByRole("button", { name: "Start" }))
  await waitFor(() => expect(api.action).toHaveBeenCalledTimes(3))
  expect(api.action.mock.calls[2]![2].operationId).not.toBe(first)
})

it("draws a setup's parts on its overview, and opens one part's controls from there", async () => {
  const user = userEvent.setup({ delay: null })
  api.list.mockResolvedValue([summary()])
  api.get.mockResolvedValue(detail({ resources: [
    { resourceId: "db", kind: "volume", owned: true, label: "Database", placement: "This computer" },
    { resourceId: "site", kind: "service_publication", owned: true, label: "Site", dependsOn: ["db"], placement: "This computer", actions: ["logs"] },
  ] }))
  await show()
  await user.click(await screen.findByRole("button", { name: "Open Acme desks" }))
  const diagram = await screen.findByRole("group", { name: /How it fits together: 2 parts/ })
  await user.click(within(diagram).getByRole("button", { name: /^Site:/ }))
  await user.click(within(screen.getByRole("region", { name: "Site controls" })).getByRole("button", { name: "Logs" }))
  expect(screen.getByRole("tab", { name: "Activity" })).toHaveAttribute("aria-selected", "true")
})

it("puts a removal's notes first, where its dates and what happens to data are read before anything else", async () => {
  const user = userEvent.setup({ delay: null })
  api.reviewRemoval.mockResolvedValue({ setupId: "s1", digest: "rm-2", baseRevision: 4, intent: "remove", headline: "Remove this setup: 2 steps.", notes: ["Removing pauses the Sandbox Grid Acme for three days, until 29 October 2026."], resources: [{ resourceId: "pool", label: "Desk pool", kind: "workspace_pool", owned: true, action: "remove" }] })
  await show()
  const acme = await screen.findByRole("article", { name: "Acme desks" })
  await user.click(within(acme).getByRole("button", { name: "Remove…" }))
  const notes = await within(acme).findByRole("list", { name: "Before you remove it" })
  expect(notes).toHaveTextContent("until 29 October 2026")
  const review = within(acme).getByRole("region", { name: "What will happen" })
  expect(notes.compareDocumentPosition(within(review).getByText("Desk pool")) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
})

it("offers the newest version of a setup's Hub template, and opens the update with the setup's choices", async () => {
  const user = userEvent.setup({ delay: null })
  hubDetail.mockResolvedValue({ state: "active", latestVersion: "1.2.0", version: { version: "1.2.0" } })
  await show("s1")
  await screen.findByRole("heading", { level: 2, name: "Acme desks" })
  const offer = await screen.findByRole("button", { name: "Update to 1.2.0" })
  expect(screen.getByText(/keeps the choices you made/)).toBeInTheDocument()
  expect(hubDetail).toHaveBeenCalledWith("yougori", "sandbox-grid")
  await user.click(offer)
  expect(await screen.findByRole("dialog", { name: "Builder" })).toHaveTextContent('{"mode":"configure","setupId":"s1","setupName":"Acme desks","update":{"publisher":"yougori","name":"sandbox-grid","version":"1.2.0"}}')
})

it("offers no update for a removed template, an older one, or a setup not made from the Hub", async () => {
  hubDetail.mockResolvedValue({ state: "removed", latestVersion: "9.0.0", version: null })
  await show("s1")
  await screen.findByRole("heading", { level: 2, name: "Acme desks" })
  await waitFor(() => expect(hubDetail).toHaveBeenCalled())
  expect(screen.queryByRole("button", { name: /^Update to/ })).toBeNull()
  cleanup()
  await show("s2")
  await screen.findByRole("heading", { level: 2, name: "Model lab" })
  expect(screen.queryByRole("button", { name: /^Update to/ })).toBeNull()
})
