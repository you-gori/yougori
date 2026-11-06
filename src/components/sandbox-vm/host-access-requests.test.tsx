// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, waitFor } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
const api = vi.hoisted(() => ({ status: vi.fn(), hostAccess: vi.fn() }))
vi.mock("@/api/sandbox-vm-api", async original => ({
  ...await original<typeof import("@/api/sandbox-vm-api")>(), sandboxVmApi: api,
}))
import { HostAccessRequests } from "./host-access-requests"

afterEach(() => {
  cleanup(); vi.clearAllMocks()
  Reflect.deleteProperty(window, "__TAURI_INTERNALS__")
})

it("asks on any app page and closing grants no permission", async () => {
  Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} })
  api.status.mockResolvedValue({ sandboxes: [{ sandbox: "vm-requester", phase: "ready" }] })
  api.hostAccess.mockResolvedValue({ policy: { treeVisible: false, askForAccess: true },
    requests: [{ id: "r", sandbox: "vm-requester", path: "C:/Work/notes.txt", mode: "read", state: "pending" }], grants: [],
  })
  render(<HostAccessRequests />)
  expect(await screen.findByRole("dialog")).toHaveTextContent("vm-requester")
  expect(await screen.findByText("C:/Work/notes.txt")).toBeVisible()
  await userEvent.keyboard("{Escape}")
  await waitFor(() => expect(screen.queryByRole("dialog")).not.toBeInTheDocument())
  expect(screen.getByRole("button", { name: /Review 1 file request/ })).toBeVisible()
  expect(api.hostAccess.mock.calls.every(call => call.length === 1)).toBe(true)
})

it("does not query a native VM service in the browser preview", () => {
  render(<HostAccessRequests />)
  expect(api.status).not.toHaveBeenCalled()
  expect(screen.queryByRole("dialog")).not.toBeInTheDocument()
})
