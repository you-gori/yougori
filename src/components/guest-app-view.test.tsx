// @vitest-environment jsdom
import { act, cleanup, render, screen } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { guestAppsApi } from "@/api/guest-apps-api"
import { GuestAppView } from "./guest-app-view"

vi.mock("@/api/guest-apps-api", () => ({ guestAppsApi: { status: vi.fn(), view: vi.fn(), stop: vi.fn() } }))
vi.mock("@/components/guest-desktop", () => ({ VncDesktop: ({ websocketUrl }: { websocketUrl: string }) => <div>Display {websocketUrl}</div> }))
const app = { id: "app-1", name: "Editor", state: "running", message: "" }
beforeEach(() => { vi.useFakeTimers() })
afterEach(() => { cleanup(); vi.useRealTimers(); vi.resetAllMocks() })

it("keeps polling after a transient status failure instead of stopping for good", async () => {
  vi.mocked(guestAppsApi.status).mockRejectedValueOnce(new Error("Connection reset.")).mockResolvedValue({ apps: [app] } as never)
  vi.mocked(guestAppsApi.view).mockResolvedValue({ websocketUrl: "ws://127.0.0.1:5900/app" } as never)
  render(<GuestAppView environmentId="env" sessionId="app-1" active />)
  await act(async () => { await Promise.resolve() })
  expect(screen.getByText(/Connection reset\. Retrying/)).toBeTruthy()
  await act(async () => { await vi.advanceTimersByTimeAsync(5000) })
  expect(screen.getByText("Display ws://127.0.0.1:5900/app")).toBeTruthy()
  expect(screen.queryByText(/Retrying/)).toBeNull()
})

it("reports a closed session without retrying", async () => {
  vi.mocked(guestAppsApi.status).mockResolvedValue({ apps: [] } as never)
  render(<GuestAppView environmentId="env" sessionId="app-1" active />)
  await act(async () => { await Promise.resolve() })
  expect(screen.getByText(/This app session has closed/)).toBeTruthy()
  await act(async () => { await vi.advanceTimersByTimeAsync(60_000) })
  expect(guestAppsApi.status).toHaveBeenCalledOnce()
})
