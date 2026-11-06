// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import type { HostAccessView } from "@/api/sandbox-vm-api"

const hostAccess = vi.hoisted(() => vi.fn())
vi.mock("@/api/sandbox-vm-api", async importOriginal => ({
  ...await importOriginal<typeof import("@/api/sandbox-vm-api")>(), sandboxVmApi: { hostAccess },
}))
import { HostAccessBox } from "./host-access-box"

afterEach(() => { cleanup(); hostAccess.mockReset() })
const initial: HostAccessView = {
  policy: { treeVisible: false, askForAccess: false }, requests: [], grants: [],
  endpoint: "http://host.yougori/", maxFileBytes: 8 << 20,
}

it("keeps seeing names separate from allowing requests", async () => {
  const user = userEvent.setup()
  hostAccess.mockResolvedValue(initial)
  render(<HostAccessBox sandbox="vm-owner" />)
  await user.click(await screen.findByRole("switch", { name: "See computer file tree" }))
  expect(hostAccess).toHaveBeenCalledWith("vm-owner", "policy", {
    policy: { treeVisible: true, askForAccess: false },
  })
  await user.click(screen.getByRole("switch", { name: "Ask for file access" }))
  expect(hostAccess).toHaveBeenCalledWith("vm-owner", "policy", {
    policy: { treeVisible: false, askForAccess: true },
  })
})

it("shows the exact path and allows narrowing read-write to a one-time read", async () => {
  const user = userEvent.setup()
  hostAccess.mockResolvedValue({ ...initial, policy: { treeVisible: false, askForAccess: true },
    requests: [{ id: "request-a", sandbox: "vm-owner", path: "C:/Projects/notes.txt", mode: "read_write", state: "pending", grant: null }],
  })
  render(<HostAccessBox sandbox="vm-owner" />)
  expect(await screen.findByText("C:/Projects/notes.txt")).toBeVisible()
  await user.selectOptions(screen.getByRole("combobox"), "read")
  await user.click(screen.getByRole("button", { name: "Allow once" }))
  expect(hostAccess).toHaveBeenCalledWith("vm-owner", "approve", { request: "request-a", mode: "read", duration: "once" })
})

it("never widens a read request and can revoke persistent access", async () => {
  const user = userEvent.setup()
  hostAccess.mockResolvedValue({ ...initial,
    requests: [{ id: "request-a", sandbox: "vm-owner", path: "C:/Projects", mode: "read", state: "pending", grant: null }],
    grants: [{ id: "grant-a", sandbox: "vm-owner", path: "C:/Other", folder: true, mode: "read_write", duration: "always" }],
  })
  render(<HostAccessBox sandbox="vm-owner" />)
  await screen.findByRole("combobox")
  expect(screen.queryByRole("option", { name: "Read & write" })).not.toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Always allow" }))
  expect(hostAccess).toHaveBeenCalledWith("vm-owner", "approve", { request: "request-a", mode: "read", duration: "always" })
  await user.click(screen.getByRole("button", { name: "Revoke" }))
  expect(hostAccess).toHaveBeenCalledWith("vm-owner", "revoke", { grant: "grant-a" })
})

it("surfaces a refused approval without inventing a grant", async () => {
  const user = userEvent.setup()
  hostAccess.mockResolvedValue({ ...initial, requests: [{ id: "r", path: "C:/missing", mode: "read", state: "pending" }] })
  render(<HostAccessBox sandbox="vm-owner" />)
  const allow = await screen.findByRole("button", { name: "Allow once" })
  hostAccess.mockRejectedValue(new Error("The requested path does not exist."))
  await user.click(allow)
  expect(await screen.findByRole("alert")).toHaveTextContent("The requested path does not exist.")
  expect(screen.queryByRole("button", { name: "Revoke" })).not.toBeInTheDocument()
})
