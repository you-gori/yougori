// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import type { Environment } from "@/types/platform"
import { remoteAccessApi } from "@/api/remote-access-api"
import { RemoteWorkspace } from "./remote-workspace"

vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ setEnvironmentStatus: vi.fn(), environmentActions: {}, refreshPlatform: vi.fn() }) }))
vi.mock("@/components/remote-display", () => ({ RemoteDisplay: () => null }))
vi.mock("@/components/guest-terminal", () => ({ GuestTerminal: () => null }))
vi.mock("@/components/guest-logs", () => ({ GuestLogs: () => null }))
vi.mock("@/components/sharing-panel", () => ({ SharingPanel: () => null }))
afterEach(() => { cleanup(); vi.restoreAllMocks() })

const desk = { id: "env-desk", name: "Design desk", status: "running", runtime: "shared://desk/one" } as unknown as Environment

it("says once that a desk is restricted, and offers one place to put files into it", async () => {
  vi.spyOn(remoteAccessApi, "inspect").mockResolvedValue({ name: "Design desk", permission: "control", restricted: true, uploads: true, files: true, desktop: true, commands: false, apps: false, installers: false, internet: false, power: false })
  render(<RemoteWorkspace environment={desk} onClose={() => {}} />)
  await waitFor(() => expect(screen.getAllByText(/^Restricted workspace/)).toHaveLength(1))
  // Two upload sections would each keep their own half-finished upload.
  expect(screen.getAllByRole("region", { name: "Upload into workspace" })).toHaveLength(1)
  // A sentence about the workspace is a sentence, not a boxed-off panel.
  expect(screen.getByText(/^Restricted workspace/).className).not.toMatch(/\bborder\b/)
})
