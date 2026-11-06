// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import type { ReactNode } from "react"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { sandboxVmEnvironments } from "./sandbox-vm/sandbox-vm-environments"
const open = vi.hoisted(() => vi.fn())
vi.mock("@/components/setups/builder-context", () => ({ useSetupBuilder: () => ({ open }) }))
vi.mock("@/api/setups/progress", () => ({ useSetupFeed: () => ({
  setups: [{ setupId: "ours", name: "My API" }, { setupId: "other", name: "Other setup" }],
  details: { ours: { resources: [], outputs: [{ value: "vm-one" }] }, other: { resources: [{ resourceId: "not-selected" }] } },
}) }))
vi.mock("./sandbox-vm/sandbox-vm-panel", () => ({ SandboxVmPanel: ({ sandbox }: { sandbox: string }) => <p>Controls for {sandbox}</p> }))
vi.mock("./environment-detail-sheet", () => ({ EnvironmentDetailSheet: ({ environmentId, setupActions, onOpenChange, onOpenEnvironment }: {
  environmentId: string; setupActions?: ReactNode; onOpenChange(open: boolean): void; onOpenEnvironment(id: string): void
}) => <section aria-label="Environment settings"><p>Settings for {environmentId}</p>{setupActions}<button onClick={() => onOpenEnvironment(environmentId)}>Open environment</button><button onClick={() => onOpenChange(false)}>Close settings</button></section> }))
import { SandboxConfiguration } from "./sandbox-configuration"
const vm = () => sandboxVmEnvironments({ sandboxes: [{ sandbox: "vm-one", phase: "ready", state: "running", boot: 1, revocation: null }], workspaces: [] })[0]!
const local = (id: string) => ({ ...vm(), id, name: id, runtime: "ubuntu:24.04", kind: "container" as const, provider: "yougoriOci" as const })
afterEach(() => { cleanup(); vi.clearAllMocks() })
it("shows only the selected VM's controls and its associated setup configuration", () => {
  const environments = sandboxVmEnvironments({ sandboxes: [{ sandbox: "vm-one", phase: "ready", state: "running", boot: 1, revocation: null }], workspaces: [] })
  const close = vi.fn()
  render(<SandboxConfiguration environments={environments} onClose={close} onConfigureEnvironment={vi.fn()} onOpenEnvironment={vi.fn()} />)
  expect(screen.getByText("Controls for vm-one")).toBeVisible()
  expect(screen.getByText("My API")).toBeInTheDocument()
  expect(screen.queryByText("Other setup")).toBeNull()
  expect(screen.getByRole("button", { name: "Create template" })).toBeVisible()
  fireEvent.click(screen.getByRole("button", { name: /Configure setup/ }))
  expect(open).toHaveBeenCalledExactlyOnceWith({ mode: "configure", setupId: "ours", setupName: "My API" })
  expect(close).toHaveBeenCalledOnce()
})

it("opens a single environment's actual settings directly and keeps template actions there", async () => {
  const close = vi.fn(), openEnvironment = vi.fn(), configure = vi.fn()
  render(<SandboxConfiguration environments={[local("model")]} onClose={close} onConfigureEnvironment={configure} onOpenEnvironment={openEnvironment} />)
  expect(await screen.findByText("Settings for model")).toBeVisible()
  expect(screen.queryByRole("button", { name: "Open environment settings" })).toBeNull()
  expect(configure).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Open environment" }))
  expect(close).toHaveBeenCalledOnce()
  expect(openEnvironment).toHaveBeenCalledExactlyOnceWith("model")
})

it("captures the selected VM from its actual settings", async () => {
  const close = vi.fn()
  render(<SandboxConfiguration environments={[vm()]} onClose={close} onConfigureEnvironment={vi.fn()} onOpenEnvironment={vi.fn()} />)
  fireEvent.click(await screen.findByRole("button", { name: "Create template" }))
  expect(open).toHaveBeenCalledExactlyOnceWith({ mode: "create", entry: "environments", environments: ["vm-one"] })
  expect(close).toHaveBeenCalledOnce()
})

it("keeps individual settings without exporting non-VM environments", () => {
  const close = vi.fn(), configure = vi.fn()
  render(<SandboxConfiguration environments={[local("web"), local("api")]} onClose={close} onConfigureEnvironment={configure} onOpenEnvironment={vi.fn()} />)
  expect(screen.getByRole("dialog", { name: "Configure environments" })).toBeVisible()
  fireEvent.click(screen.getByRole("button", { name: "Configure api" }))
  expect(configure).toHaveBeenCalledExactlyOnceWith("api")
  expect(close).toHaveBeenCalledOnce()
  expect(screen.queryByRole("button", { name: "Create template" })).toBeNull()
})

it("does not offer unsupported template capture for a mixed VM selection", () => {
  render(<SandboxConfiguration environments={[vm(), local("web")]} onClose={vi.fn()} onConfigureEnvironment={vi.fn()} onOpenEnvironment={vi.fn()} />)
  expect(screen.queryByRole("button", { name: "Create template" })).toBeNull()
  expect(screen.getByRole("button", { name: "Configure web" })).toBeVisible()
  fireEvent.click(screen.getByText(vm().name))
  expect(screen.getByText("Controls for vm-one")).toBeVisible()
})

it("shows no popup for an empty selection", () => {
  render(<SandboxConfiguration environments={[]} onClose={vi.fn()} onConfigureEnvironment={vi.fn()} onOpenEnvironment={vi.fn()} />)
  expect(screen.queryByRole("dialog")).toBeNull()
})
