// @vitest-environment jsdom
import { cleanup, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { remoteAccessApi } from "@/api/remote-access-api"
import { RemoteDisplay } from "./remote-display"

vi.mock("@/api/remote-access-api", () => ({ remoteAccessApi: { desktop: vi.fn() } }))
vi.mock("@novnc/novnc", () => ({ default: class { constructor() { throw new Error("Display viewer failed") } } }))
afterEach(() => { cleanup(); vi.resetAllMocks() })

it("closes the remote display session when the viewer cannot start", async () => {
  vi.mocked(remoteAccessApi.desktop).mockImplementation(async (_environment, params) => params.action === "create" ? { displayId: "display-1", password: "secret" } : {})
  render(<RemoteDisplay environmentId="remote" />)
  await waitFor(() => expect(screen.getByRole("status").textContent).toContain("Display viewer failed"))
  expect(remoteAccessApi.desktop).toHaveBeenCalledWith("remote", { action: "close", displayId: "display-1" })
})
