// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { open } from "@tauri-apps/plugin-dialog"
import { SandboxGridAdmin } from "./sandbox-grid-admin"
import { desksApi, type EnterpriseStatus } from "@/api/desks-api"
vi.mock("@/api/desks-api", () => ({ desksApi: { manage: vi.fn() } }))
vi.mock("@tauri-apps/plugin-dialog", () => ({ open: vi.fn() }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn() } }))
const state: EnterpriseStatus = {
  id: "grid-test", name: "Company", actor: "owner", adminRole: "administrator",
  people: [{ id: "person-1", username: "ada.lovelace", name: "Ada Lovelace", adminRole: "user", roleId: null, createdAt: 0, lastLoginAt: null, desks: [] }],
  desks: [], members: [],
  enterprise: { images: [{ id: "image-1", name: "Research tools", version: "1", description: "Prepared", applications: ["Python"], spec: { kind: "vm", cpu: 2, memoryGb: 4, diskGb: 40, gpu: false, image: "https://images.example.test/research.qcow2" }, sha256: "a".repeat(64), createdAt: 0 }], roles: [{ id: "role-1", name: "Research Kazakhstan", description: "Research team", imageId: "image-1", access: "restricted", createdAt: 0 }], connections: [], audit: [], computerLimit: null },
}
beforeEach(() => { vi.mocked(desksApi.manage).mockImplementation(async () => structuredClone(state)) })
afterEach(() => { cleanup(); vi.resetAllMocks() })

it("changes a person's administrative permission and workspace role from the Permissions tab", async () => {
  render(<SandboxGridAdmin onChanged={vi.fn().mockResolvedValue(undefined)} />)
  const permission = await screen.findByLabelText("Administrative permission for Ada Lovelace")
  fireEvent.change(permission, { target: { value: "administrator" } })
  await waitFor(() => expect(desksApi.manage).toHaveBeenCalledWith({ action: "personUpdate", id: "person-1", adminRole: "administrator" }))
  fireEvent.change(screen.getByLabelText("Workspace role for Ada Lovelace"), { target: { value: "role-1" } })
  await waitFor(() => expect(desksApi.manage).toHaveBeenCalledWith({ action: "personUpdate", id: "person-1", roleId: "role-1" }))
  expect(screen.queryByLabelText("Username")).not.toBeInTheDocument()
})
it("shows the hub's refusal and keeps the panel usable", async () => {
  vi.mocked(desksApi.manage).mockImplementation(async request => { if (request.action !== "status") throw new Error("Your administrator role does not allow this operation"); return structuredClone(state) })
  render(<SandboxGridAdmin onChanged={vi.fn().mockResolvedValue(undefined)} />)
  fireEvent.change(await screen.findByLabelText("Administrative permission for Ada Lovelace"), { target: { value: "operator" } })
  expect(await screen.findByRole("alert")).toHaveTextContent("does not allow")
  expect(screen.getByLabelText("Administrative permission for Ada Lovelace")).toBeEnabled()
})
it("makes an auditor's view read-only and still names the company workspace providers", async () => {
  vi.mocked(desksApi.manage).mockResolvedValue({ ...structuredClone(state), actor: "person-auditor", adminRole: "auditor" })
  render(<SandboxGridAdmin onChanged={vi.fn().mockResolvedValue(undefined)} />)
  expect(await screen.findByText("auditor")).toBeInTheDocument()
  expect(screen.getByLabelText("Administrative permission for Ada Lovelace")).toBeDisabled()
  fireEvent.click(screen.getByRole("tab", { name: "Images" }))
  expect(screen.queryByRole("button", { name: "Publish image" })).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole("tab", { name: "Company workspaces" }))
  expect(screen.getByText(/Citrix, Azure Virtual Desktop, Windows 365 or Omnissa Horizon/)).toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Add workspace" })).not.toBeInTheDocument()
})
it("defaults new roles to restricted access and says what that does and does not stop", async () => {
  render(<SandboxGridAdmin onChanged={vi.fn().mockResolvedValue(undefined)} />)
  await screen.findByLabelText("Administrative permission for Ada Lovelace")
  fireEvent.click(screen.getByRole("tab", { name: "Workspace roles" }))
  expect(screen.getByLabelText("Data access")).toHaveValue("restricted")
  expect(screen.getByText(/can still be photographed/)).toBeInTheDocument()
})
it("imports a prepared disk on the owner computer without asking for a checksum", async () => {
  vi.mocked(open).mockResolvedValue("C:/Prepared/research.qcow2")
  render(<SandboxGridAdmin onChanged={vi.fn().mockResolvedValue(undefined)} />)
  await screen.findByLabelText("Administrative permission for Ada Lovelace")
  fireEvent.click(screen.getByRole("tab", { name: "Images" }))
  fireEvent.change(screen.getByLabelText("Source"), { target: { value: "file" } })
  fireEvent.change(screen.getByLabelText("Image name"), { target: { value: "Research local" } })
  expect(screen.queryByLabelText("SHA-256 checksum")).not.toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Publish image" })).toBeDisabled()
  fireEvent.click(screen.getByRole("button", { name: "Choose disk image" }))
  await screen.findByText("C:/Prepared/research.qcow2")
  fireEvent.click(screen.getByRole("button", { name: "Publish image" }))
  await waitFor(() => expect(desksApi.manage).toHaveBeenCalledWith(expect.objectContaining({ action: "imageImport", path: "C:/Prepared/research.qcow2", name: "Research local" })))
})
it("remote administrators publish reachable URLs instead of hub filesystem paths", async () => {
  vi.mocked(desksApi.manage).mockResolvedValue({ ...structuredClone(state), actor: "person-admin" })
  render(<SandboxGridAdmin onChanged={vi.fn().mockResolvedValue(undefined)} />)
  await screen.findByLabelText("Administrative permission for Ada Lovelace")
  fireEvent.click(screen.getByRole("tab", { name: "Images" }))
  expect(screen.queryByLabelText("Source")).not.toBeInTheDocument()
  expect(screen.getByLabelText(/Download URL/)).toBeInTheDocument()
})
