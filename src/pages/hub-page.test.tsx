// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { HubDetail, HubInstance, HubReview, HubSummary } from "@/api/hub-api"
import { SetupBuilderContext } from "@/components/setups/builder-context"
import { SetupBuilderProvider } from "@/components/setups/setup-builder-provider"
import { SandboxVmContext } from "@/components/sandbox-vm/sandbox-vm-context"
import { Dialog, DialogPopup, DialogTitle } from "@/components/ui/dialog"

const api = vi.hoisted(() => ({
  builtins: vi.fn(), list: vi.fn(), detail: vi.fn(), file: vi.fn(), star: vi.fn(), instances: vi.fn(), openConsole: vi.fn(), folder: vi.fn(),
  pageUrl: (item: { publisher: string; name: string }) => `https://yougori.com/hub/${item.publisher}/${item.name}`,
}))
const toasts = vi.hoisted(() => [] as { title: string; description?: string; type?: string }[])
vi.mock("@/api/hub-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/hub-api")>()), hubApi: api }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn(() => Promise.resolve()) } }))
vi.mock("@/components/ui/toast", () => ({ toastManager: { add: (toast: { title: string }) => { toasts.push(toast) } } }))
vi.mock("@/api/setups/catalogue", async importOriginal => ({
  ...(await importOriginal<typeof import("@/api/setups/catalogue")>()),
  CATALOGUE: [{ id: "grid.create", group: "grid_workers", name: "Create a grid", aliases: [], examples: [], requires: [], conflicts: [] }],
}))
vi.mock("@/components/setups/template-builder", () => ({
  TemplateBuilder: ({ intent, onClose }: { intent: unknown; onClose(): void }) => <div role="dialog" aria-label="Builder">
    <span>{JSON.stringify(intent)}</span><button type="button" onClick={onClose}>Close builder</button>
  </div>,
}))

import { HubPage } from "./hub-page"

const at = 1760000000
const summary = (over: Partial<HubSummary> = {}): HubSummary => ({
  ref: "ana/my-api", publisher: "ana", name: "my-api", kind: "template", title: "My API", summary: "A private model API website.",
  topics: ["ai"], license: "MIT", verified: false, latestVersion: "1.0.0", createdAt: at, updatedAt: at,
  counts: { clones: 12, clonesWeek: 3, stars: 4, forks: 1, versions: 1 }, forkedFrom: null, ...over,
})
const detail = (over: Partial<HubDetail> = {}): HubDetail => ({
  ...summary(), state: "active", removed: null, starred: false, mine: false,
  versions: [{ version: "1.0.0", createdAt: at, digest: "a".repeat(64), verified: false, fileCount: 2, bytes: 300, clones: 12, changelog: "First version." }],
  version: {
    version: "1.0.0", createdAt: at, digest: "a".repeat(64), verified: false, fileCount: 2, bytes: 300, changelog: "First version.",
    readme: "# My API\n\n![Verified](https://evil.example/badge.svg)\n\n<img src=x onerror=alert(1)>",
    files: [{ path: "README.md", bytes: 100, sha256: "b".repeat(64), text: true }, { path: "my file.txt", bytes: 5, sha256: "c".repeat(64), text: true }],
    review: { environments: [{ name: "web", type: "container", image: "node:24", cpu: 2, memoryGb: 4, ports: [3000], tools: ["codex"] }], inputs: [{ id: "key", question: "OpenAI API key", type: "secret", secret: true }] },
    notices: [],
  },
  ...over,
})

beforeEach(() => {
  api.builtins.mockResolvedValue([])
  api.list.mockResolvedValue({ items: [summary({ verified: true, ref: "yougori/hello-site", publisher: "yougori", name: "hello-site", title: "Hello site" }), summary()], total: 2, page: 1, pageSize: 24 })
  api.detail.mockResolvedValue(detail())
  api.openConsole.mockResolvedValue({ opened: true, command: "yougori run hub/ana/my-api@1.0.0" })
  api.instances.mockResolvedValue([])
})
afterEach(() => { cleanup(); vi.clearAllMocks(); toasts.length = 0 })

it("opens the shipped inference template in the shared builder without starting a workload", async () => {
  const open = vi.fn()
  api.builtins.mockResolvedValue([{ id: "inference-solver", title: "Create my inference", folder: "C:/templates/inference-solver" }])
  render(<SetupBuilderContext.Provider value={{ open }}><HubPage /></SetupBuilderContext.Provider>)
  fireEvent.click(await screen.findByRole("button", { name: "Create my inference" }))
  expect(open).toHaveBeenCalledWith({ mode: "run", folder: "C:/templates/inference-solver" })
  expect(api.openConsole).not.toHaveBeenCalled()
})

it("lists Hub items with the Verified badge on owner uploads and on publishers who hold collateral", async () => {
  api.list.mockResolvedValueOnce({ items: [
    summary({ verified: true, ref: "yougori/hello-site", publisher: "yougori", name: "hello-site", title: "Hello site" }), summary(),
    summary({ collateral: true, ref: "ben/shop", publisher: "ben", name: "shop", title: "Shop" }),
  ], total: 3, page: 1, pageSize: 24 })
  render(<HubPage />)
  const rows = await screen.findAllByRole("button", { name: /clones/ })
  expect(rows).toHaveLength(3)
  expect(within(rows[0]!).getByText("Verified")).toHaveAttribute("title", "Uploaded by Yougori")
  expect(within(rows[1]!).queryByText("Verified")).toBeNull()
  expect(within(rows[2]!).getByText("Verified")).toHaveAttribute("title", "The publisher holds $100 collateral, lost if they publish harmful code")
  expect(screen.getByText(/Yougori checks only its own uploads/)).toHaveTextContent("Verified means uploaded by Yougori, or by a publisher who holds $100 collateral")
  fireEvent.click(screen.getByRole("button", { name: "Tools" }))
  await waitFor(() => expect(api.list).toHaveBeenLastCalledWith(expect.objectContaining({ kind: "tool" })))
})

it("shows the warning on an unverified item, never renders README images or HTML, and runs it through a console", async () => {
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByRole("note")).toHaveTextContent("Not checked by Yougori. Community templates can contain harmful code, including viruses.")
  const readme = screen.getByRole("article", { name: "README" })
  expect(readme.querySelector("img")).toBeNull()
  expect(readme).toHaveTextContent("[image: Verified]")
  expect(readme).toHaveTextContent("<img src=x onerror=alert(1)>")
  fireEvent.click(screen.getByRole("button", { name: /Run on this computer/ }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("run", "hub/ana/my-api@1.0.0"))
  expect(toasts.at(-1)?.description).toContain("Review what it does there before you confirm")
  fireEvent.click(screen.getByRole("button", { name: "What it creates" }))
  expect(screen.getByText("node:24")).toBeInTheDocument()
  expect(screen.getByText(/OpenAI API key · kept secret, never uploaded/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Files 2" }))
  expect(screen.getByRole("button", { name: "README.md" })).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "my file.txt" })).toBeNull()
})

it("a malformed review and a very long file cannot break the item page", async () => {
  const base = detail()
  const review = { environments: "web", warnings: "careful", public: [{ environment: "web", port: 3000, access: 5 }], tools: [{ name: "x", downloads: "https://a.example" }], totals: [] } as unknown as HubReview
  api.detail.mockResolvedValueOnce({ ...base, version: { ...base.version!, review } })
  api.file.mockResolvedValueOnce({ path: "README.md", bytes: 60_000, sha256: "b".repeat(64), text: true, content: "line\n".repeat(12_000) })
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  fireEvent.click(await screen.findByRole("button", { name: "What it creates" }))
  expect(screen.getByText("web, port 3000: you choose when it runs")).toBeInTheDocument()
  expect(screen.getByRole("note")).toHaveTextContent("Not checked by Yougori.")
  fireEvent.click(screen.getByRole("button", { name: "Files 2" }))
  fireEvent.click(screen.getByRole("button", { name: "README.md" }))
  await waitFor(() => expect(screen.getByRole("list", { name: "Contents of README.md" }).children).toHaveLength(5000))
  expect(screen.getByText(/Showing the first 5,000 of 12,000 lines/)).toBeInTheDocument()
})

it("a collateral publisher's item is Verified, and still says Yougori has not checked its files", async () => {
  api.detail.mockResolvedValueOnce(detail({ collateral: true }))
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByText("Verified", { selector: ".hub-detail-title *" })).toHaveClass("hub-verified-large")
  expect(screen.getByText("Verified: ana holds $100 collateral.")).toBeInTheDocument()
  expect(screen.getByRole("note")).toHaveTextContent("Not checked by Yougori. Community templates can contain harmful code, including viruses. Read the files first and run only what you trust. Its publisher holds $100 collateral, which they lose if Yougori removes their work for harmful code.")
})

it("a verified item has no warning; a removed one says why and cannot run", async () => {
  api.detail.mockResolvedValueOnce(detail({ verified: true }))
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[0]!)
  expect(await screen.findByText("Verified", { selector: ".hub-detail-title *" })).toBeInTheDocument()
  expect(screen.getByText("Verified: uploaded by Yougori.")).toBeInTheDocument()
  expect(screen.queryByRole("note")).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Back" }))
  api.detail.mockResolvedValueOnce(detail({ state: "removed", removed: { reason: "harmful", message: "Removed by Yougori: harmful code.", at }, versions: [], version: null }))
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByRole("alert")).toHaveTextContent("Removed by Yougori: harmful code. It can no longer be downloaded or run.")
  expect(screen.queryByRole("button", { name: /Run on this computer/ })).toBeNull()
})

it("lists templates on this computer and removes one only after a confirmation", async () => {
  const instance: HubInstance = {
    schema: 1, name: "my-api", ref: "ana/my-api", source: "hub", state: "incomplete", version: "1.0.0", updatedAt: at,
    failed: { part: "tools", message: "Codex did not install in my-api-paid.", next: "yougori template run hub/ana/my-api --name my-api" },
    public: { web: "https://quick.example.trycloudflare.com" }, steps: [{ title: "Sign in to Codex", command: "yougori codex --environment my-api-paid" }],
  }
  api.instances.mockResolvedValue([instance])
  render(<HubPage />)
  fireEvent.click(screen.getByRole("button", { name: "On this computer" }))
  expect(await screen.findByText("Not finished")).toBeInTheDocument()
  expect(screen.getByRole("alert")).toHaveTextContent("Codex did not install in my-api-paid.")
  expect(screen.getByText("https://quick.example.trycloudflare.com")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Remove…" }))
  expect(api.openConsole).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Remove" }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("remove", "my-api"))
  fireEvent.click(screen.getByRole("button", { name: "Status" }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("status", "my-api"))
})

it("a run whose window was closed reads as not finished and continues through a console", async () => {
  const now = Math.floor(Date.now() / 1000)
  const base: HubInstance = { schema: 1, name: "shop", ref: "ana/shop", source: "hub", state: "creating", version: "1.0.0", next: "yougori template continue shop" }
  api.instances.mockResolvedValue([{ ...base, updatedAt: now - 600 }, { ...base, name: "blog", ref: "ana/blog", updatedAt: now - 5, next: "yougori template continue blog" }])
  render(<HubPage />)
  fireEvent.click(screen.getByRole("button", { name: "On this computer" }))
  const [stale, live] = await screen.findAllByText(/^(shop|blog)$/, { selector: "strong" })
  const card = (node: HTMLElement) => node.closest(".hub-instance") as HTMLElement
  expect(within(card(stale!)).getByText("Not finished")).toBeInTheDocument()
  expect(within(card(stale!)).getByRole("alert")).toHaveTextContent("This run stopped before it finished")
  expect(within(card(stale!)).getByRole("alert")).toHaveTextContent("yougori template continue shop")
  expect(within(card(live!)).getByText("Being created")).toBeInTheDocument()
  expect(within(card(live!)).queryByRole("button", { name: "Continue" })).toBeNull()
  fireEvent.click(within(card(stale!)).getByRole("button", { name: "Continue" }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("continue", "shop"))
})

it("publishes a chosen folder through the CLI, and does nothing when no folder is chosen", async () => {
  api.folder.mockResolvedValueOnce(null).mockResolvedValueOnce("C:\\Users\\me\\hello-site")
  render(<HubPage />)
  fireEvent.click(screen.getByRole("button", { name: "Publish" }))
  fireEvent.click(screen.getByRole("button", { name: /Publish a template folder/ }))
  await waitFor(() => expect(api.folder).toHaveBeenCalledTimes(1))
  expect(api.openConsole).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: /Publish a template folder/ }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("publishTemplate", "C:\\Users\\me\\hello-site"))
})

it("tells people to sign in when starring needs an account", async () => {
  api.star.mockRejectedValueOnce(new Error("Sign in first"))
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  fireEvent.click(await screen.findByRole("button", { name: /^Star/ }))
  await waitFor(() => expect(toasts.at(-1)?.description).toBe("Sign in to the Yougori Network first: run yougori login, then try again."))
})

it("keeps Create template without redundant run and publish header actions", async () => {
  render(<HubPage />)
  const actions = screen.getAllByRole("button").filter(button => button.closest(".page-actions"))
  expect(actions.map(button => button.textContent)).toEqual(["Create template", "Open yougori.com/hub"])
  fireEvent.click(screen.getByRole("button", { name: /Create template/ }))
  expect(await screen.findByRole("dialog", { name: "Create template from VMs" })).toHaveTextContent("setup declarations")
  fireEvent.click(screen.getAllByRole("button", { name: "Close" })[0]!)
  await waitFor(() => expect(screen.queryByRole("dialog", { name: "Create template from VMs" })).toBeNull())
  expect(screen.queryByRole("button", { name: "Run a template" })).toBeNull()
  expect(screen.queryByRole("button", { name: "Publish a template" })).toBeNull()
})

it("opens the current VM selection from the Hub popup using the shared builder", async () => {
  const refresh = vi.fn().mockResolvedValue(undefined)
  render(<SandboxVmContext value={{ error: "", refresh, status: {
    sandboxes: [
      { sandbox: "exe-web", phase: "ready", state: "running", boot: 1, revocation: null },
      { sandbox: "exe-models", phase: "ended", state: "stopped", boot: 1, revocation: null },
      { sandbox: "exe-importer", phase: "ended", state: "stopped", boot: 1, revocation: null },
    ],
    workspaces: [{ sandbox: "exe-models", sandbox_running: false, folder: "C:/projects/models", imported_at: "today", files: 1, excluded: 0, skipped: 0, state: { state: "imported" } }],
  } }}><SetupBuilderProvider><Dialog open><DialogPopup><DialogTitle>Hub</DialogTitle><HubPage /></DialogPopup></Dialog></SetupBuilderProvider></SandboxVmContext>)
  fireEvent.click(screen.getByRole("button", { name: "Create template" }))
  const picker = await screen.findByRole("dialog", { name: "Create template from VMs" })
  expect(picker).toBeVisible()
  expect(refresh).toHaveBeenCalledOnce()
  expect(within(picker).getAllByRole("checkbox")).toHaveLength(2)
  expect(within(picker).getByRole("button", { name: "Review template" })).toBeDisabled()
  fireEvent.click(within(picker).getByRole("checkbox", { name: /exe-web/ }))
  fireEvent.click(within(picker).getByRole("checkbox", { name: /models/ }))
  expect(within(picker).getByText(/2 of 2 VMs selected/)).toBeVisible()
  expect(within(picker).getByRole("button", { name: "Review template" })).toBeEnabled()
  expect(within(picker).queryByText("exe-importer")).toBeNull()
})

it("searches templates without offering the removed capability wizard", async () => {
  render(<HubPage />)
  fireEvent.change(screen.getByRole("searchbox", { name: "Search the Hub" }), { target: { value: "backup" } })
  expect(screen.queryByRole("region", { name: "Capabilities" })).toBeNull()
  // The old grid names find nothing here now; the Hub's own search still runs on them.
  fireEvent.change(screen.getByRole("searchbox", { name: "Search the Hub" }), { target: { value: "Sandbox Grid" } })
  await waitFor(() => expect(screen.queryByRole("region", { name: "Capabilities" })).toBeNull())
})

it("runs a format 2 template here, on that exact version, with no console window", async () => {
  const base = detail()
  api.detail.mockResolvedValueOnce({ ...base, format: 2, version: { ...base.version!, review: { ...base.version!.review, format: 2 } as HubReview } })
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  fireEvent.click(await screen.findByRole("button", { name: /Run on this computer/ }))
  expect(await screen.findByRole("dialog", { name: "Builder" })).toHaveTextContent('{"mode":"run","hubRef":"hub/ana/my-api@1.0.0"}')
  expect(api.openConsole).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Close builder" }))
  expect(screen.queryByRole("button", { name: "Make my own from it" })).toBeNull()
})

it("keeps an older template on the console path, and says why", async () => {
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByText(/older format, so Run opens a console window/)).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Make my own from it" })).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: /Run on this computer/ }))
  await waitFor(() => expect(api.openConsole).toHaveBeenCalledWith("run", "hub/ana/my-api@1.0.0"))
  expect(screen.queryByRole("dialog", { name: "Builder" })).toBeNull()
})

it("reads a format 2 review: requirements before Run, capabilities in their groups, and the parts it sets up", async () => {
  const base = detail()
  const review = {
    format: 2,
    environments: [{ name: "web", type: "container", image: "node:24", cpu: 2, memoryGb: 4 }],
    capabilities: [{ id: "grid.create", selection: "required", locked: true }, { id: "future.thing", selection: "optional" }],
    resources: [{ id: "company", kind: "grid", summary: "The company grid" }, { id: "desks", kind: "workspace_pool", dependsOn: ["company"], when: { input: "mode", equals: "shared" } }],
    requires: { yougori: ">=1.2.0", platforms: ["linux", "windows"], gpu: "nvidia" },
    aliases: ["desks", "secret alias"],
  } as unknown as HubReview
  api.detail.mockResolvedValueOnce({ ...base, subtitle: "Desks for a team", tags: ["grids", "workspaces", "unknown"], version: { ...base.version!, review } })
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByText("Desks for a team")).toBeInTheDocument()
  expect(screen.getByText("Workspaces", { selector: ".hub-tag" })).toBeInTheDocument()
  expect(screen.queryByText("unknown")).toBeNull()
  const needs = screen.getByText(/Yougori 1\.2\.0 or newer · runs on Linux, Windows · an NVIDIA GPU/)
  const run = screen.getByRole("button", { name: /Run on this computer/ })
  expect(needs.compareDocumentPosition(run) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  fireEvent.click(screen.getByRole("button", { name: "What it creates" }))
  expect(screen.getByRole("heading", { name: "Grid & workers" })).toBeInTheDocument()
  expect(screen.getByText("Create a grid").closest("li")).toHaveTextContent("Create a grid · Required · settings fixed by the author")
  expect(screen.getByRole("heading", { name: "Not known to this version of Yougori" })).toBeInTheDocument()
  expect(screen.getByText("future.thing").closest("li")).toHaveTextContent("future.thing · Optional")
  expect(screen.getByRole("rowheader", { name: "company" })).toBeInTheDocument()
  expect(screen.getByRole("row", { name: /desks workspace pool company/ })).toHaveTextContent('{"input":"mode","equals":"shared"}')
  expect(screen.getByText("node:24")).toBeInTheDocument()
  expect(screen.queryByText(/secret alias/)).toBeNull()
  expect(screen.queryByText(/newer than this app understands/)).toBeNull()
})

it("says when a review format is newer than it understands, and still lists every grant it can read", async () => {
  const base = detail()
  const review = { format: 3, environments: [{ name: "web", image: "node:24", pcAccess: [{ path: "x" }] }], inputs: [{ id: "key", question: "API key", secret: true }], somethingNew: { a: 1 } } as unknown as HubReview
  api.detail.mockResolvedValueOnce({ ...base, version: { ...base.version!, review } })
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  fireEvent.click(await screen.findByRole("button", { name: "What it creates" }))
  expect(screen.getByText(/This review format is newer than this app understands/)).toBeInTheDocument()
  expect(screen.getByText("node:24")).toBeInTheDocument()
  expect(within(screen.getByRole("row", { name: /^web/ })).getByText("1", { selector: ".hub-flag" })).toBeInTheDocument()
  expect(screen.getByText(/API key · kept secret, never uploaded/)).toBeInTheDocument()
})

it("shows a format 2 item's subtitle and tags in the list", async () => {
  api.list.mockResolvedValueOnce({ items: [summary({ subtitle: "Desks for a team", tags: ["workspaces"] } as Partial<HubSummary>)], total: 1, page: 1, pageSize: 24 })
  render(<HubPage />)
  const row = (await screen.findAllByRole("button", { name: /clones/ }))[0]!
  expect(within(row).getByText("Desks for a team")).toBeInTheDocument()
  expect(within(row).getByText("Workspaces")).toBeInTheDocument()
})

it("says what a template needs in plain words, and leaves out platform ids it doesn't know", async () => {
  const base = detail()
  const review = { format: 2, requires: { yougori: "1.2.0", platforms: ["linux-x86_64", "windows-arm64", "plan9", "linux-aarch64"], gpu: "optional" } } as unknown as HubReview
  api.detail.mockResolvedValueOnce({ ...base, version: { ...base.version!, review } })
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect((await screen.findByText("Needs")).closest("p")).toHaveTextContent("Needs Yougori 1.2.0 or newer · runs on Linux (x86-64), Windows (Arm), Linux (Arm) · a GPU if you have one")
  expect(screen.queryByText(/plan9/)).toBeNull()
})

it("treats a review format that isn't a number as newer than it understands", async () => {
  const base = detail()
  api.detail.mockResolvedValueOnce({ ...base, version: { ...base.version!, review: { format: "two", environments: [{ name: "web", image: "node:24" }] } as unknown as HubReview } })
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  fireEvent.click(await screen.findByRole("button", { name: "What it creates" }))
  expect(screen.getByText(/newer than this app understands/)).toBeInTheDocument()
  expect(screen.getByText("node:24")).toBeInTheDocument()
})

it("shows each list card's platforms and minimum version in plain words, and nothing when unknown", async () => {
  api.list.mockResolvedValueOnce({ items: [
    summary({ ref: "ana/web", name: "web", title: "Web", requires: { yougori: "1.2.0", platforms: ["linux-x86_64", "windows-arm64"], gpu: "nvidia" } } as Partial<HubSummary>),
    summary({ ref: "ana/plain", name: "plain", title: "Plain" }),
  ], total: 2, page: 1, pageSize: 24 })
  render(<HubPage />)
  const rows = await screen.findAllByRole("button", { name: /clones/ })
  // The card with metadata names its platforms and minimum version; the plain id it doesn't know is
  // left out, never shown raw.
  expect(within(rows[0]!).getByText(/Needs/)).toHaveTextContent("Needs Yougori 1.2.0 or newer · runs on Linux (x86-64), Windows (Arm) · an NVIDIA GPU")
  // The older card without a `requires` shows no requirements line at all.
  expect(within(rows[1]!).queryByText(/Needs/)).toBeNull()
})

it("shows a forked template's lineage, and says when its original is gone", async () => {
  // A fork names what it came from.
  api.detail.mockResolvedValueOnce(detail({ forkedFrom: { ref: "yougori/hello-site", available: true } }))
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByText(/Forked from yougori\/hello-site/)).toBeInTheDocument()
  expect(screen.queryByText(/no longer on the Hub/)).toBeNull()
  cleanup()
  // When the original has been removed, the lineage says so rather than linking to nothing.
  api.detail.mockResolvedValueOnce(detail({ forkedFrom: { ref: "yougori/hello-site", available: false } }))
  render(<HubPage />)
  fireEvent.click((await screen.findAllByRole("button", { name: /clones/ }))[1]!)
  expect(await screen.findByText(/Forked from yougori\/hello-site \(no longer on the Hub\)/)).toBeInTheDocument()
})

it("keeps the Hub list and the detail usable at 200% text, with no fixed-height text containers", async () => {
  // jsdom has no layout, so clipping can't be measured directly; instead we scale the root font and
  // check the text containers carry no fixed pixel height that would clip larger text. Controls stay
  // present and operable at the larger size.
  document.documentElement.style.fontSize = "200%"
  try {
    api.detail.mockResolvedValueOnce(detail({ forkedFrom: null }))
    const { container } = render(<HubPage />)
    const rows = await screen.findAllByRole("button", { name: /clones/ })
    expect(rows.length).toBeGreaterThan(0)
    // No text-bearing element pins its own height in pixels (which would clip scaled text).
    for (const node of container.querySelectorAll(".hub-row, .hub-row-title, .hub-row-summary, .hub-row-subtitle, .hub-row-requires, .hub-tag")) {
      const style = (node as HTMLElement).style
      expect(style.height === "" || !style.height.endsWith("px")).toBe(true)
      expect(style.maxHeight === "" || !style.maxHeight.endsWith("px")).toBe(true)
    }
    // The detail opens and its actions are still reachable at the larger text size.
    fireEvent.click(rows[1]!)
    expect(await screen.findByRole("button", { name: /Run on this computer/ })).toBeInTheDocument()
  } finally {
    document.documentElement.style.fontSize = ""
  }
})
