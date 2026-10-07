// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { ReactNode } from "react"
import type { GraphEnvironment } from "./graph-capabilities"
import { EnvironmentList, EnvironmentListRow } from "./environment-list"

const { platform } = vi.hoisted(() => ({ platform: { state: { host: { gpuUsagePercent: 42 as number | null } }, environmentActions: {}, setEnvironmentStatus: vi.fn() } }))
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
