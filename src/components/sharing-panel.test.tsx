// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { SharingPanel } from "./sharing-panel"
import { remoteAccessApi } from "@/api/remote-access-api"

const { refresh } = vi.hoisted(() => ({ refresh: vi.fn() }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ refreshPlatform: refresh, state: { environments: [] } }) }))
vi.mock("@/api/remote-access-api", () => ({ remoteAccessApi: { list: vi.fn(), create: vi.fn(), connect: vi.fn(), start: vi.fn(), stop: vi.fn(), remove: vi.fn() } }))
// Typing without per-key timers keeps these interaction tests fast under a loaded full-suite run.
vi.mock("./cloudflare-account-fields", () => ({ CloudflareAccountFields: ({ presets, onSelectPreset }: { presets: { id: string; hostname: string }[]; onSelectPreset(id: string): void }) => <div>Tunnel settings{presets.map(p => <button key={p.id} type="button" onClick={() => onSelectPreset(p.id)}>{`Use ${p.hostname}`}</button>)}</div> }))
afterEach(cleanup)
beforeEach(() => {
  vi.clearAllMocks()
  vi.mocked(remoteAccessApi.list).mockResolvedValue({ grants: [], url: null, port: null, audit: [] })
})

it("requires explicit PC folder consent and never offers unrestricted PC control", async () => {
  const user = userEvent.setup({ delay: null })
  render(<SharingPanel environmentId="my-pc" />)
  await user.click(screen.getByRole("button", { name: "Share My PC via Tunnel" }))
  await user.click(screen.getByRole("button", { name: "Add person" }))
  expect(screen.getByRole("radio", { name: /View Only/ })).toHaveAttribute("aria-checked", "true")
  expect(screen.queryByRole("radio", { name: /Full Control/ })).not.toBeInTheDocument()
  await user.type(screen.getByLabelText("Username"), "teammate")
  await user.type(screen.getByLabelText("Share password"), "a private password")
  await user.type(screen.getByLabelText("PC folder"), "C:/Projects/example")
  expect(screen.getByRole("button", { name: "Add recipient" })).toBeDisabled()
  await user.click(screen.getByRole("checkbox", { name: /I allow this recipient/ }))
  await user.click(screen.getByRole("button", { name: "Add recipient" }))
  await waitFor(() => expect(remoteAccessApi.create).toHaveBeenCalledWith(expect.objectContaining({ targetId: "my-pc", permission: "view", folder: "C:/Projects/example", confirmPcFiles: true })))
  expect(remoteAccessApi.start).not.toHaveBeenCalled()
})

it("reuses an active tunnel instead of offering another start", async () => {
  vi.mocked(remoteAccessApi.list).mockResolvedValue({ grants: [{ id: "share-test", targetId: "my-pc", username: "teammate", permission: "view", folder: "C:/Projects", expiresAt: null, status: "online", link: "https://example.trycloudflare.com/share/share-test", connectedUsers: 0 }], url: "https://example.trycloudflare.com", port: 1234, audit: [] })
  const user = userEvent.setup({ delay: null })
  render(<SharingPanel environmentId="my-pc" />)
  await user.click(screen.getByRole("button", { name: "Share My PC via Tunnel" }))
  expect(await screen.findByText("https://example.trycloudflare.com/share/share-test")).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Enable tunnel" })).not.toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Disconnect Remote Users" }))
  await waitFor(() => expect(remoteAccessApi.stop).toHaveBeenCalledOnce())
})

it("connects with share credentials and preserves whitespace in the password", async () => {
  const user = userEvent.setup({ delay: null })
  render(<SharingPanel />)
  await user.click(screen.getByRole("button", { name: "Connect to Shared Environment" }))
  await user.type(screen.getByLabelText("Link"), "https://example.trycloudflare.com/share/share-test")
  await user.type(screen.getByLabelText("Username"), "teammate")
  await user.type(screen.getByLabelText("Password"), " private password ")
  await user.click(screen.getByRole("button", { name: "Connect" }))
  await waitFor(() => expect(refresh).toHaveBeenCalledOnce())
  expect(remoteAccessApi.connect).toHaveBeenCalledWith("https://example.trycloudflare.com/share/share-test", "teammate", " private password ", undefined)
})


it("reconnects the selected node and keeps failed credentials editable for retry", async () => {
  const user = userEvent.setup({ delay: null })
  const connected = vi.fn()
  vi.mocked(remoteAccessApi.connect).mockRejectedValueOnce(new Error("Wrong credentials")).mockResolvedValueOnce({} as never)
  render(<SharingPanel reconnectEnvironmentId="env-original" onConnected={connected} />)
  await user.click(screen.getByRole("button", { name: "Connect to Shared Environment" }))
  expect(screen.getByText("Reconnect shared environment")).toBeInTheDocument()
  await user.type(screen.getByLabelText("Link"), "https://new.trycloudflare.com/share/share-new")
  await user.type(screen.getByLabelText("Username"), "recipient")
  await user.type(screen.getByLabelText("Password"), " private password ")
  await user.click(screen.getByRole("button", { name: "Connect" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Wrong credentials")
  expect(refresh).not.toHaveBeenCalled()
  expect(connected).not.toHaveBeenCalled()
  expect(screen.getByLabelText("Password")).toHaveValue(" private password ")
  await user.click(screen.getByRole("button", { name: "Connect" }))
  await waitFor(() => expect(connected).toHaveBeenCalledOnce())
  expect(refresh).toHaveBeenCalledOnce()
  expect(remoteAccessApi.connect).toHaveBeenLastCalledWith("https://new.trycloudflare.com/share/share-new", "recipient", " private password ", "env-original")
})

it("turns the link on with a domain saved for another app", async () => {
  const id = "3f1c2b8e-4a5d-4e6f-9a7b-1c2d3e4f5a6b"
  localStorage.setItem("yougori.public-access-presets.v1", JSON.stringify([{ id, credentialEnvironmentId: "public-presets", port: 5281, hostname: "crm.prompx.com", hostPort: 5281 }]))
  vi.mocked(remoteAccessApi.list).mockResolvedValue({ grants: [{ id: "share-test", targetId: "my-pc", username: "teammate", permission: "view", folder: "C:/Projects", expiresAt: null, status: "offline", link: null, connectedUsers: 0 }], url: null, port: null, audit: [] })
  const user = userEvent.setup({ delay: null })
  render(<SharingPanel environmentId="my-pc" />)
  await user.click(screen.getByRole("button", { name: "Share My PC via Tunnel" }))
  expect(await screen.findByText("Waiting for link")).toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Use crm.prompx.com" }))
  await user.click(screen.getByRole("button", { name: "Enable tunnel" }))
  await waitFor(() => expect(remoteAccessApi.start).toHaveBeenCalledWith({ hostname: "crm.prompx.com", presetId: id, presetSourceEnvironmentId: "public-presets", presetPort: 5281, remember: false, routesReviewed: true }, 5281))
  localStorage.clear()
})

it("says so when the link is on but its token could not be kept", async () => {
  const id = "3f1c2b8e-4a5d-4e6f-9a7b-1c2d3e4f5a6b"
  localStorage.setItem("yougori.public-access-presets.v1", JSON.stringify([{ id, credentialEnvironmentId: "public-presets", port: 5281, hostname: "crm.prompx.com", hostPort: 5281 }]))
  vi.mocked(remoteAccessApi.list).mockResolvedValue({ grants: [{ id: "share-test", targetId: "my-pc", username: "teammate", permission: "view", folder: "C:/Projects", expiresAt: null, status: "offline", link: null, connectedUsers: 0 }], url: null, port: null, audit: [] })
  vi.mocked(remoteAccessApi.start).mockResolvedValue({ url: "https://crm.prompx.com", port: 5281, warning: "Connected, but credentials could not be saved in the OS vault." })
  const user = userEvent.setup({ delay: null })
  render(<SharingPanel environmentId="my-pc" />)
  await user.click(screen.getByRole("button", { name: "Share My PC via Tunnel" }))
  await user.click(await screen.findByRole("button", { name: "Use crm.prompx.com" }))
  await user.click(screen.getByRole("button", { name: "Enable tunnel" }))
  expect(await screen.findByText("Link is on. Connected, but credentials could not be saved in the OS vault.")).toBeInTheDocument()
  localStorage.clear()
})

it("removes people whose access was revoked or expired", async () => {
  const grant = (id: string, username: string, status: "revoked" | "expired" | "online") => ({ id, targetId: "my-pc", username, permission: "view" as const, folder: "C:/Projects", expiresAt: null, status, link: null, connectedUsers: 0 })
  vi.mocked(remoteAccessApi.list).mockResolvedValue({ grants: [grant("share-a", "alice", "revoked"), grant("share-b", "bob", "expired"), grant("share-c", "carol", "online")], url: null, port: null, audit: [] })
  vi.mocked(remoteAccessApi.remove).mockResolvedValue(undefined)
  const user = userEvent.setup({ delay: null })
  render(<SharingPanel environmentId="my-pc" />)
  await user.click(screen.getByRole("button", { name: "Share My PC via Tunnel" }))
  expect(await screen.findByText("alice")).toBeInTheDocument()
  expect(screen.getAllByRole("button", { name: "Remove" })).toHaveLength(2)
  await user.click(screen.getAllByRole("button", { name: "Remove" })[0]!)
  await waitFor(() => expect(remoteAccessApi.remove).toHaveBeenCalledWith("share-a"))
  await user.click(screen.getByRole("button", { name: "Clear ended" }))
  await waitFor(() => expect(remoteAccessApi.remove).toHaveBeenCalledWith("share-b"))
  expect(remoteAccessApi.remove).not.toHaveBeenCalledWith("share-c")
})
