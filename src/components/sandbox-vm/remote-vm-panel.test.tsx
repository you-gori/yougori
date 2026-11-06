// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import { RemoteVmPanel } from "./remote-vm-panel"

const api = vi.hoisted(() => ({ remoteStatus: vi.fn(), remoteHistory: vi.fn(), remoteArchive: vi.fn(), remoteLaunch: vi.fn(), remoteTrust: vi.fn(), remoteStop: vi.fn(), remoteReconcile: vi.fn(), remoteStart: vi.fn(), remoteOutcome: vi.fn(), remoteCancel: vi.fn() }))
const getState = vi.hoisted(() => vi.fn())
vi.mock("@/api/platform-api", () => ({ platformApi: { getState } }))
vi.mock("@/api/sandbox-vm-api", async original => ({ ...await original<typeof import("@/api/sandbox-vm-api")>(), sandboxVmApi: api }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
const run = { run: "r1", parent: "exe-parent", connection: "env-owned", host: "server.example", port: 22, phase: "ready", detail: null, observation: null, billing: "externally_managed", server_power_changed: false }
const parents = [{ sandbox: "exe-parent", phase: "ready" as const, state: "running", boot: 1, revocation: null }]
const setup = () => {
  getState.mockResolvedValue({ environments: [{ id: "env-owned", name: "My server", provider: "cloudSsh" }, { id: "local", name: "Local container", provider: "yougoriOci" }] })
  api.remoteStatus.mockResolvedValue({ runs: [] })
}
it("uses a real saved SSH connection and ready parent, with an explicit first-use fingerprint", async () => {
  setup(); const user = userEvent.setup(); render(<RemoteVmPanel parents={parents} />)
  expect(api.remoteStatus).not.toHaveBeenCalled()
  await user.click(screen.getByText("Remote VM sandboxes"))
  await screen.findByRole("option", { name: "My server" })
  expect(screen.queryByRole("option", { name: "Local container" })).not.toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Launch remote VM" })).toBeDisabled()
  await user.selectOptions(screen.getByLabelText("SSH connection"), "env-owned")
  await user.selectOptions(screen.getByLabelText("Parent VM on this computer"), "exe-parent")
  await user.type(screen.getByLabelText("Server engine endpoint"), "/run/engine.sock")
  await user.type(screen.getByLabelText("Server engine SHA-256"), "a".repeat(64))
  await user.type(screen.getByLabelText("Verified SSH fingerprint"), "SHA256:checked")
  await user.click(screen.getByRole("button", { name: "Launch remote VM" }))
  await waitFor(() => expect(api.remoteLaunch).toHaveBeenCalledWith({ connection: "env-owned", parent: "exe-parent", program: "/opt/yougori/yougori-engine", endpoint: "/run/engine.sock", engine_sha256: "a".repeat(64), accept_host_key: "SHA256:checked", memory_mib: 1024 }))
})
it("confirms a selected key for cleanup without creating a replacement parent or workload", async () => {
  setup(); const user = userEvent.setup(); render(<RemoteVmPanel parents={[]} />)
  await user.click(screen.getByText("Remote VM sandboxes"))
  await screen.findByRole("option", { name: "My server" })
  const confirm = screen.getByRole("button", { name: "Confirm server key" })
  expect(confirm).toBeDisabled()
  await user.selectOptions(screen.getByLabelText("SSH connection"), "env-owned")
  await user.type(screen.getByLabelText("Verified SSH fingerprint"), "SHA256:rotated")
  await user.click(confirm)
  expect(api.remoteTrust).toHaveBeenCalledWith("env-owned", "SHA256:rotated")
  expect(api.remoteLaunch).not.toHaveBeenCalled()
  expect(screen.getByRole("button", { name: "Launch remote VM" })).toBeDisabled()
})
it("clears submitted input and refuses to replay an uncertain start", async () => {
  setup(); api.remoteStatus.mockResolvedValue({ runs: [run] }); api.remoteStart.mockRejectedValue(new Error("Outcome uncertain"))
  const user = userEvent.setup(); render(<RemoteVmPanel parents={parents} />)
  await user.click(screen.getByText("Remote VM sandboxes"))
  await user.type(await screen.findByLabelText("Guest shell script"), "echo private-value")
  await user.click(screen.getByRole("button", { name: "Run script once" }))
  await screen.findByText(/It has not been repeated/)
  expect(api.remoteStart).toHaveBeenCalledTimes(1)
  expect(screen.getByLabelText("Guest shell script")).toHaveValue("")
  expect(screen.getByRole("button", { name: "Run script once" })).toBeDisabled()
})
it("keeps unconfirmed cleanup visible and reconciles only that recorded run", async () => {
  setup(); api.remoteStatus.mockResolvedValue({ runs: [{ ...run, phase: "unconfirmed", detail: "Native end proof unavailable." }] })
  const user = userEvent.setup(); render(<RemoteVmPanel parents={[]} />)
  await user.click(screen.getByText("Remote VM sandboxes"))
  await user.click(await screen.findByRole("button", { name: "Reconcile cleanup" }))
  expect(api.remoteReconcile).toHaveBeenCalledWith("r1")
  expect(api.remoteStop).not.toHaveBeenCalled()
  expect(screen.queryByLabelText("Guest shell script")).not.toBeInTheDocument()
})
it("archives only ended runs and retains a paginated, read-only history", async () => {
  setup()
  const ended = { ...run, phase: "ended" }
  api.remoteStatus.mockResolvedValue({ runs: [], archived_count: 1 }).mockResolvedValueOnce({ runs: [ended], archived_count: 0 })
  api.remoteHistory.mockResolvedValue({ runs: [{ ...ended, archived: true }], archived_count: 101, next_after: "page-one" })
  const user = userEvent.setup(); render(<RemoteVmPanel parents={[]} />)
  await user.click(screen.getByText("Remote VM sandboxes"))
  await user.click(await screen.findByRole("button", { name: "Archive ended run" }))
  expect(api.remoteArchive).toHaveBeenCalledWith("r1")
  await user.click(await screen.findByRole("button", { name: "Show archived runs (1)" }))
  await screen.findByText(/original identity and cleanup proof retained/)
  expect(screen.queryByRole("button", { name: "Archive ended run" })).not.toBeInTheDocument()
  expect(screen.queryByLabelText("Guest shell script")).not.toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Next page" }))
  await waitFor(() => expect(api.remoteHistory).toHaveBeenCalledWith("page-one"))
  expect(api.remoteStart).not.toHaveBeenCalled()
})
