// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { DeskPortal } from "./desk-portal"
import { desksApi, type DeskLogin } from "@/api/desks-api"
import { DesktopOnlyError, NotAllowedError } from "@/api/grids/errors"

vi.mock("@/api/desks-api", () => ({ desksApi: { refreshDesk: vi.fn(), manage: vi.fn() } }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn() } }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ openEnvironmentWindow: vi.fn(), refreshPlatform: vi.fn() }) }))
afterEach(() => { cleanup(); vi.resetAllMocks() })

const login = { personId: "person-1", username: "ada.lovelace", name: "Ada Lovelace", company: "Acme", desks: [], connections: [], adminRole: null, mfa: false } as unknown as DeskLogin

it("shows the sentence a refusal carries, and never the name of the thing that was thrown", async () => {
  // Every refusal off the grids wire is a named Error, so String() would prefix the sentence
  // with the class name and the person would read "DesktopOnlyError: ..." instead.
  for (const thrown of [
    new DesktopOnlyError("Open Yougori Desktop to use your desks on this computer", "desk_refresh", "r-1"),
    new NotAllowedError("manageWorkspaces", [], "desk_refresh", "r-2"),
  ]) {
    vi.mocked(desksApi.refreshDesk).mockRejectedValue(thrown)
    render(<DeskPortal login={login} onSignOut={() => {}} />)
    const said = await screen.findByRole("alert")
    expect(said).toHaveTextContent(thrown.message)
    expect(said.textContent).not.toContain("Error")
    cleanup()
  }
})
