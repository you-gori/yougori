// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
vi.mock("@/components/remote-access-status", () => ({ RemoteAccessStatus: () => null }))
vi.mock("@/components/dialogs/preferences-dialog", () => ({ PreferencesDialog: () => null }))
vi.mock("@/components/release-update", () => ({ ReleaseUpdateNotice: () => null }))
vi.mock("@/components/environment-download-status", () => ({ EnvironmentDownloadStatus: () => null }))
vi.mock("@/components/shared/window-controls", () => ({ WindowControls: () => null }))
vi.mock("@/lib/instructions-tour", () => ({ startFirstLaunchInstructions: () => undefined }))
import { AppShell } from "./app-shell"
afterEach(cleanup)
it("has one workspace with no sidebar or section tabs and a Hub popup button", () => {
  const open = vi.fn()
  render(<AppShell onOpenHub={open}><p>Workspace</p></AppShell>)
  expect(document.querySelector("aside")).toBeNull()
  expect(screen.queryByRole("navigation")).toBeNull()
  expect(screen.queryByRole("tab")).toBeNull()
  expect(screen.queryByRole("button", { name: "My setups" })).toBeNull()
  expect(screen.getByRole("main")).toHaveTextContent("Workspace")
  const hub = screen.getByRole("button", { name: "Hub" })
  expect(hub).toHaveAttribute("aria-haspopup", "dialog")
  fireEvent.click(hub)
  expect(open).toHaveBeenCalledOnce()
})
