// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { ResourceView } from "@/api/setups/types"

const api = vi.hoisted(() => ({
  capabilities: vi.fn(), validate: vi.fn(), plan: vi.fn(), apply: vi.fn(), list: vi.fn(), get: vi.fn(), operation: vi.fn(), cancel: vi.fn(), action: vi.fn(), reviewRemoval: vi.fn(),
  resourceAction: vi.fn(), reviewResourceAction: vi.fn(), reviewAdoption: vi.fn(),
}))
vi.mock("@/api/setups/setups-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/setups-api")>()), setupsApi: api }))

import { SetupCommandError } from "@/api/setups/setups-api"
import { SetupDiagram } from "./setup-diagram"

const part = (resourceId: string, over: Partial<ResourceView> = {}): ResourceView => ({ resourceId, kind: "environment", owned: true, label: resourceId, ...over })
const parts: ResourceView[] = [
  part("db", { kind: "volume", label: "Database", placement: "This computer", observed: "running", retainedData: true }),
  part("app", { label: "App", dependsOn: ["db", "models"], placement: "This computer", observed: "running", actions: ["start", "stop", "remove", "logs"] }),
  part("models", { kind: "model_service", label: "Shared models", owned: false, borrowedFrom: "Neo Grid", placement: "Office PC 2", actions: ["start", "detach"] }),
  part("link", { kind: "connection", label: "App to models", connection: { from: "app", to: "models", ports: [8080], direction: "one_way" } }),
]

beforeEach(() => {
  api.list.mockResolvedValue([])
  api.resourceAction.mockResolvedValue({ operationId: "op-1", setupId: "s1" })
  api.reviewResourceAction.mockResolvedValue({ setupId: "s1", digest: "dt", baseRevision: 3, headline: "Detaches Shared models." })
  api.apply.mockResolvedValue({ operationId: "op-2", setupId: "s1" })
})
afterEach(() => { cleanup(); vi.clearAllMocks() })

const picture = () => screen.getByRole("group", { name: /How it fits together/ })

function show(resources = parts) {
  const onLogs = vi.fn()
  render(<SetupDiagram setupId="s1" resources={resources} revision={3} onLogs={onLogs} />)
  return onLogs
}

it("names every part and connection in words, owned and borrowed alike, and says the same as a list", () => {
  show()
  const diagram = screen.getByRole("group", { name: /How it fits together: 3 parts and 1 connection/ })
  expect(within(diagram).getByRole("button", { name: "App: sandbox, on This computer, owned by this setup, running, needs Database and Shared models" })).toBeInTheDocument()
  expect(within(diagram).getByRole("button", { name: /^Shared models: model, on Office PC 2, borrowed from Neo Grid, never removed by this setup/ })).toBeInTheDocument()
  expect(within(diagram).getByRole("button", { name: "App to models: App can reach Shared models on port 8080" })).toBeInTheDocument()
  // Owned and borrowed differ in shape and words, never in colour alone.
  expect(diagram.querySelector('[data-item="db"]')).toHaveAttribute("data-owned")
  expect(diagram.querySelector('[data-item="models"]')).not.toHaveAttribute("data-owned")
  expect(within(diagram).getByText("Model · Borrowed")).toBeInTheDocument()
  expect(screen.getByText("borrowed, never removed by it")).toBeInTheDocument()
  expect(screen.getByText(/needs: waits for that part/)).toBeInTheDocument()
  expect(screen.getByText(/connects: may reach it, on the ports shown/)).toBeInTheDocument()
  const list = screen.getByRole("list", { name: "Parts" })
  expect(within(list).getAllByRole("button")).toHaveLength(3)
  expect(within(screen.getByRole("list", { name: "Connections" })).getByRole("button", { name: /on port 8080/ })).toBeInTheDocument()
})

it("moves between parts with the arrow keys, opens one with Enter, and gives focus back on Escape", async () => {
  const user = userEvent.setup({ delay: null })
  show()
  const diagram = screen.getByRole("group", { name: /How it fits together/ })
  const tabbable = within(diagram).getAllByRole("button").filter(button => button.getAttribute("tabindex") === "0")
  expect(tabbable).toHaveLength(1)
  await user.tab()
  expect(within(diagram).getByRole("button", { name: /^Database:/ })).toHaveFocus()
  await user.keyboard("{ArrowRight}")
  await waitFor(() => expect(within(diagram).getByRole("button", { name: /^App:/ })).toHaveFocus())
  await user.keyboard("{Enter}")
  const controls = await screen.findByRole("region", { name: "App controls" })
  await waitFor(() => expect(within(controls).getByRole("heading", { name: /App/ })).toHaveFocus())
  expect(within(diagram).getByRole("button", { name: /^App:/ })).toHaveAttribute("aria-expanded", "true")
  await user.keyboard("{Escape}")
  expect(screen.queryByRole("region", { name: "App controls" })).toBeNull()
  await waitFor(() => expect(within(diagram).getByRole("button", { name: /^App:/ })).toHaveFocus())
})

it("offers an owned part what the engine allows, and acts on that one part", async () => {
  const user = userEvent.setup({ delay: null })
  const onLogs = show()
  await user.click(within(picture()).getByRole("button", { name: /^App:/ }))
  const controls = screen.getByRole("region", { name: "App controls" })
  expect(within(controls).getAllByRole("button").map(button => button.textContent)).toEqual(["Start", "Stop", "Remove…", "Logs", "Close"])
  await user.click(within(controls).getByRole("button", { name: "Stop" }))
  await waitFor(() => expect(api.resourceAction).toHaveBeenCalledWith("s1", "app", "stop", { expectedRevision: 3, operationId: expect.stringMatching(/^op-/) }))
  await user.click(within(controls).getByRole("button", { name: "Logs" }))
  expect(onLogs).toHaveBeenCalled()
})

it("offers a borrowed part only Detach, whatever else is listed, and detaches only after its review", async () => {
  const user = userEvent.setup({ delay: null })
  show()
  await user.click(within(picture()).getByRole("button", { name: /^Shared models:/ }))
  const controls = screen.getByRole("region", { name: "Shared models controls" })
  expect(within(controls).queryByRole("button", { name: "Start" })).toBeNull()
  expect(within(controls).getByText("Borrowed from Neo Grid, never removed by this setup")).toBeInTheDocument()
  await user.click(within(controls).getByRole("button", { name: "Detach…" }))
  expect(await within(controls).findByText("Detaches Shared models.")).toBeInTheDocument()
  expect(within(controls).getByText(/Only this setup's use of Shared models ends/)).toBeInTheDocument()
  expect(api.reviewResourceAction).toHaveBeenCalledWith("s1", "models", "detach", 3)
  expect(api.apply).not.toHaveBeenCalled()
  await user.click(within(controls).getByRole("button", { name: "Detach Shared models" }))
  await waitFor(() => expect(api.apply).toHaveBeenCalledWith(expect.objectContaining({ digest: "dt" }), expect.stringMatching(/^op-/), undefined, []))
})

it("says so plainly when acting on one part isn't in this build, and changes nothing", async () => {
  const user = userEvent.setup({ delay: null })
  api.resourceAction.mockRejectedValueOnce(new SetupCommandError("This setup action is not one Yougori knows.", { code: "invalid_request" }))
  show([part("db", { kind: "volume", label: "Database" }), part("app", { label: "App", actions: ["start"] })])
  await user.click(within(picture()).getByRole("button", { name: /^Database:/ }))
  expect(screen.getByText(/can't act on one part on its own yet/)).toBeInTheDocument()
  expect(within(screen.getByRole("region", { name: "Database controls" })).queryByRole("button", { name: "Start" })).toBeNull()
  await user.click(within(picture()).getByRole("button", { name: /^App:/ }))
  await user.click(within(screen.getByRole("region", { name: "App controls" })).getByRole("button", { name: "Start" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("This isn't in this build of Yougori yet. Nothing was changed.")
})

it("draws nothing for a setup with no parts recorded", () => {
  show([])
  expect(screen.queryByRole("group", { name: /How it fits together/ })).toBeNull()
})
