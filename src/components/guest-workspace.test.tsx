// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import type { Environment, PlatformState } from "@/types/platform"
import { GuestWorkspace } from "./guest-workspace"

const platform = vi.hoisted(() => ({ state: null as unknown as PlatformState }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: platform.state, environmentActions: {}, openEnvironmentWindow: vi.fn(), setEnvironmentStatus: vi.fn() }) }))
vi.mock("@/components/remote-workspace", () => ({ RemoteWorkspace: ({ environment, onClose }: { environment: Environment; onClose(): void }) => <div>Remote view {environment.name}<button type="button" onClick={onClose}>Close remote workspace</button></div> }))
vi.mock("@/components/guest-desktop", () => ({ GuestScene: ({ environment }: { environment: Environment }) => <div>Terminal view {environment.name}</div> }))
vi.mock("@/components/model-environment-actions", () => ({ ModelEnvironmentActions: () => null }))
vi.mock("@/components/environment-changes", () => ({ EnvironmentChanges: () => null }))
vi.mock("@/components/guest-app-launcher", () => ({ GuestAppLauncher: () => null }))
vi.mock("@/components/connection-skills-dialog", () => ({ ConnectionSkillsDialog: () => null }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { titleWindow: vi.fn(async () => undefined), windows: vi.fn(async () => []), focusWindow: vi.fn() } }))
vi.mock("@/lib/instructions-tour", () => ({ ownsTour: () => false, useInstructionsTour: () => null, prepareTourWindow: vi.fn(), tourTerminalOpened: vi.fn(), tourWindowFailed: vi.fn() }))
afterEach(cleanup)
// jsdom has no layout; the workspace scrolls the selected tab into view.
Element.prototype.scrollIntoView = () => undefined

const environment = (id: string, extra: Partial<Environment> = {}) => ({ id, name: id, kind: "container", status: "running", runtime: "builtin", ...extra }) as Environment

it("opens a shared tunnel as a tab without closing existing terminals", () => {
  platform.state = { environments: [environment("Alpha"), environment("Remote", { kind: "cloud", runtime: "shared://tunnel/owner/share-1" })], connections: [] } as unknown as PlatformState
  const close = vi.fn()
  const view = render(<GuestWorkspace embedded initialEnvironmentId="Alpha" onClose={close} />)
  expect(screen.getByText("Terminal view Alpha")).toBeInTheDocument()
  view.rerender(<GuestWorkspace embedded initialEnvironmentId="Remote" onClose={close} />)
  expect(screen.getByText("Remote view Remote")).toBeInTheDocument()
  // The local terminal stays mounted behind its tab and can be selected again.
  expect(screen.getByText("Terminal view Alpha")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("tab", { name: "Alpha · Terminal 1" }))
  expect(screen.getByRole("tab", { name: "Alpha · Terminal 1" })).toHaveAttribute("aria-selected", "true")
  fireEvent.click(screen.getByRole("tab", { name: "Remote · Shared 1" }))
  fireEvent.click(screen.getByRole("button", { name: "Close remote workspace" }))
  expect(screen.queryByText("Remote view Remote")).not.toBeInTheDocument()
  expect(screen.getByRole("tab", { name: "Alpha · Terminal 1" })).toHaveAttribute("aria-selected", "true")
  expect(screen.getByText("Terminal view Alpha")).toBeInTheDocument()
  expect(close).not.toHaveBeenCalled()
})

it("closes the window when its only remote tab closes", () => {
  platform.state = { environments: [environment("Remote", { kind: "cloud", runtime: "shared://tunnel/owner/share-1" })], connections: [] } as unknown as PlatformState
  const close = vi.fn()
  render(<GuestWorkspace initialEnvironmentId="Remote" onClose={close} />)
  fireEvent.click(screen.getByRole("button", { name: "Close remote workspace" }))
  expect(close).toHaveBeenCalledOnce()
})
