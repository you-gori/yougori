// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { ReactNode } from "react"
import type { GraphEnvironment } from "./graph-capabilities"
import { EnvironmentList, EnvironmentListRow } from "./environment-list"

const { platform } = vi.hoisted(() => ({ platform: { state: { host: { gpuUsagePercent: 42 as number | null } }, environmentActions: {} as Record<string, string>, setEnvironmentStatus: vi.fn(), deleteEnvironment: vi.fn() } }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => platform }))
vi.mock("@/components/environment-node-menu", () => ({ EnvironmentNodeMenu: ({ children }: { children: ReactNode }) => children }))
beforeEach(() => { localStorage.clear(); platform.state.host.gpuUsagePercent = 42 })
afterEach(() => { cleanup(); vi.clearAllMocks() })

function environment(id: string, changes: Partial<GraphEnvironment> = {}): GraphEnvironment {
  return { id, name: id, kind: "container", provider: "yougoriOci", status: "running", runtime: "alpine", description: "", createdAt: "2026-10-06T00:00:00Z", cpuUsage: 0, memoryUsageGb: 0, storageDeltaGb: 0, networkRxMbps: 0,
    resourcePolicy: { cpu: { min: 1, preferred: 1, max: 1, current: 1 }, memoryGb: { min: 1, preferred: 1, max: 1, current: 1 }, priority: "normal", dynamic: false }, ...changes }
}
function show(environments: GraphEnvironment[], connect = vi.fn()) {
  const items = environments.map(environment => ({ id: environment.id, data: { environment } }))
  const view = render(<EnvironmentList items={items} connections={[{ id: "connection", sourceId: "gpu", targetId: "cpu", direction: "oneWay", active: true }]} colors={{}} onConnect={connect}>
    {item => <EnvironmentListRow key={item.id} environment={item.data.environment} accent="#888" canLink busy={false} fileStatus={null} dropHint="" status={<span>{item.data.environment.status}</span>} access={null} services={null} actions={null} onConfigure={() => undefined} onDoubleClick={() => undefined} />}
  </EnvironmentList>)
  return { ...view, row: (id: string) => within(view.container.querySelector(`[data-environment-id="${id}"]`) as HTMLElement), connect }
}

it("shows running local GPU telemetry as shared and never assigns it to CPU or cloud nodes", () => {
  const view = show([environment("gpu", { provider: "yougoriCuda", gpuAccess: true }), environment("cpu"), environment("remote", { kind: "cloud", gpuAccess: true })])
  expect(screen.getByRole("columnheader", { name: "GPU" })).toBeInTheDocument()
  expect(view.row("gpu").getByText("Running")).toBeInTheDocument()
  expect(view.row("gpu").getByText("42% shared")).toBeInTheDocument()
  expect(view.row("gpu").getByRole("meter", { name: "GPU on this computer use" })).toHaveAttribute("aria-valuenow", "42")
  expect(view.row("cpu").queryByRole("meter", { name: "GPU on this computer use" })).toBeNull()
  expect(view.row("remote").queryByRole("meter", { name: "GPU on this computer use" })).toBeNull()
  expect(view.row("remote").getByText("Enabled")).toBeInTheDocument()
})

it("does not display a busy PC's GPU usage for a stopped container or fabricate missing readings", () => {
  platform.state.host.gpuUsagePercent = null
  const view = show([environment("gpu", { provider: "yougoriCuda", gpuAccess: true, status: "stopped" }), environment("unknown", { provider: "yougoriCuda", gpuAccess: true })])
  expect(view.row("gpu").getByText("Not running")).toBeInTheDocument()
  expect(view.row("gpu").queryByRole("meter", { name: "GPU on this computer use" })).toBeNull()
  expect(view.row("unknown").getByText("Usage unavailable")).toBeInTheDocument()
  expect(view.row("unknown").queryByRole("meter", { name: "GPU on this computer use" })).toBeNull()
})

it("renames private connections and keeps saved sorting and connection actions", () => {
  localStorage.setItem("yougori.environment-list.v1", JSON.stringify({ sort: "links", descending: false }))
  const view = show([environment("gpu"), environment("cpu")])
  expect(screen.getByRole("columnheader", { name: "Connections" })).toHaveAttribute("aria-sort", "ascending")
  expect(screen.queryByRole("columnheader", { name: "Links" })).toBeNull()
  fireEvent.click(view.row("gpu").getByRole("button", { name: "Connection to cpu, active" }))
  expect(view.connect).toHaveBeenLastCalledWith("gpu", "cpu")
  fireEvent.click(view.row("gpu").getByRole("button", { name: "Connect gpu to another environment" }))
  expect(view.connect).toHaveBeenLastCalledWith("gpu")
  fireEvent.click(view.row("gpu").getByRole("button", { name: "Show details for gpu" }))
  expect(screen.getByRole("region", { name: "Connections of gpu" })).toBeInTheDocument()
})

it("deletes the selected environments one at a time after confirming, leaving busy ones alone", async () => {
  platform.environmentActions = { busy: "stopping" }
  const order: string[] = []
  platform.deleteEnvironment.mockImplementation(async (id: string) => { order.push(id) })
  show([environment("one"), environment("two", { status: "stopped" }), environment("busy"), environment("making", { status: "provisioning" })])
  fireEvent.click(screen.getByRole("checkbox", { name: "Select all shown environments" }))
  const bar = within(screen.getByRole("group", { name: "Selected environments" }))
  expect(bar.getByText("4 selected")).toBeInTheDocument()
  fireEvent.click(bar.getByRole("button", { name: "Delete 2" }))
  const dialog = within(await screen.findByRole("alertdialog"))
  expect(dialog.getByText("Delete 2 environments?")).toBeInTheDocument()
  expect(dialog.getByText(/2 selected are busy and stay/)).toBeInTheDocument()
  expect(platform.deleteEnvironment).not.toHaveBeenCalled()
  fireEvent.click(dialog.getByRole("button", { name: "Delete 2 nodes" }))
  await waitFor(() => expect(order).toEqual(["one", "two"]))
  await waitFor(() => expect(screen.getByText("2 selected")).toBeInTheDocument())
  platform.environmentActions = {}
})


it("configures a mixed selection without passing VM IDs to old lifecycle or delete commands", async () => {
  const selected = vi.fn()
  const envs = [environment("regular"), environment("vm-one", { kind: "fullVm", runtime: "sandbox-vm://vm-one" })]
  render(<EnvironmentList items={envs.map(environment => ({ id: environment.id, data: { environment } }))} connections={[]} colors={{}} onConnect={vi.fn()} onConfigureSelection={selected}>
    {item => <EnvironmentListRow key={item.id} environment={item.data.environment} managedExternally={item.id === "vm-one"} metricsAvailable={item.id !== "vm-one"} accent="#888" canLink={false} busy={false} fileStatus={null} dropHint="" status={null} access={null} services={null} actions={null} onConfigure={vi.fn()} onDoubleClick={vi.fn()} />}
  </EnvironmentList>)
  fireEvent.click(screen.getByRole("checkbox", { name: "Select all shown environments" }))
  const bar = within(screen.getByRole("group", { name: "Selected environments" }))
  expect(bar.getByText("2 selected")).toBeInTheDocument()
  fireEvent.click(bar.getByRole("button", { name: "Configure" }))
  expect(selected).toHaveBeenCalledWith(["regular", "vm-one"])
  fireEvent.click(bar.getByRole("button", { name: "Stop 1" }))
  await waitFor(() => expect(platform.setEnvironmentStatus).toHaveBeenCalledExactlyOnceWith("regular", "stopped"))
  expect(bar.getByRole("button", { name: "Delete 1" })).toBeInTheDocument()
  expect(within(document.querySelector('[data-environment-id="vm-one"]') as HTMLElement).queryByRole("meter")).toBeNull()
})

it("opens the picker for selected VMs and mixed selections instead of silently disabling it", () => {
  const create = vi.fn()
  const envs = [environment("vm-a", { runtime: "sandbox-vm://vm-a" }), environment("vm-b", { runtime: "sandbox-vm://vm-b" }), environment("model")]
  render(<EnvironmentList items={envs.map(environment => ({ id: environment.id, data: { environment } }))} connections={[]} colors={{}} onConnect={vi.fn()} onCreateTemplate={create}>
    {item => <EnvironmentListRow environment={item.data.environment} accent="#888" canLink={false} busy={false} fileStatus={null} dropHint="" status={null} access={null} services={null} actions={null} onConfigure={vi.fn()} onDoubleClick={vi.fn()} />}
  </EnvironmentList>)
  fireEvent.click(screen.getByRole("checkbox", { name: "Select vm-a" }))
  fireEvent.click(screen.getByRole("checkbox", { name: "Select vm-b" }))
  fireEvent.click(screen.getByRole("button", { name: "Create template" }))
  expect(create).toHaveBeenCalledExactlyOnceWith(["vm-a", "vm-b"])
  fireEvent.click(screen.getByRole("checkbox", { name: "Select model" }))
  expect(screen.getByRole("button", { name: "Create template" })).toBeEnabled()
  fireEvent.click(screen.getByRole("button", { name: "Create template" }))
  expect(create).toHaveBeenLastCalledWith(["model", "vm-a", "vm-b"])
})
