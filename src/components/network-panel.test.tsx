// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelNetworkPanel, NetworkPanel } from "./network-panel"
import type { NetworkStatus } from "@/api/market-api"

const mocks = vi.hoisted(() => ({ status: vi.fn(), signIn: vi.fn(), signOut: vi.fn(), share: vi.fn(), unshare: vi.fn(), listen: vi.fn(), openUrl: vi.fn() }))
vi.mock("@/api/market-api", () => ({ marketApi: mocks }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: mocks.openUrl } }))
let current: NetworkStatus
let event: (status: NetworkStatus) => void
const stop = vi.fn()
beforeEach(() => {
  current = { website: "https://yougori.com", signedIn: false, account: null, login: null, shares: [] }
  mocks.status.mockImplementation(async () => current)
  mocks.listen.mockImplementation(async (callback: typeof event) => { event = callback; return stop })
})
afterEach(() => { cleanup(); vi.resetAllMocks() })
const account = { email: "provider@example.com", wallet: null, creditMicros: 2000000, earningsMicros: 1000000, availableMicros: 3000000 }

it("shows browser approval, receives a CLI sign-in event, and unsubscribes on close", async () => {
  const view = render(<NetworkPanel />)
  expect(mocks.status).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Neo Grid" }))
  await waitFor(() => expect(mocks.listen).toHaveBeenCalledOnce())
  mocks.signIn.mockImplementation(async () => { current = { ...current, login: { userCode: "ABCD-EFGH", verificationUrl: "https://yougori.com/device", verificationUrlComplete: "https://yougori.com/device?code=ABCD-EFGH", expiresIn: 600, error: null } }; return current })
  fireEvent.click(await screen.findByRole("button", { name: "Sign in" }))
  expect(await screen.findByText("ABCD-EFGH")).toBeVisible()
  fireEvent.click(screen.getByRole("button", { name: "Open browser" }))
  await waitFor(() => expect(mocks.openUrl).toHaveBeenCalledWith("https://yougori.com/device?code=ABCD-EFGH"))
  current = { ...current, signedIn: true, account, login: null }
  await act(async () => event(current))
  expect(screen.getByText("provider@example.com")).toBeVisible()
  expect(screen.getByText("$2.00")).toBeVisible()
  expect(screen.getByText("$1.00")).toBeVisible()
  mocks.signOut.mockImplementation(async () => { current = { ...current, signedIn: false, account: null, shares: [] }; return current })
  fireEvent.click(screen.getByRole("button", { name: "Sign out" }))
  await waitFor(() => expect(screen.getByRole("button", { name: "Sign in" })).toBeEnabled())
  view.unmount()
  expect(stop).toHaveBeenCalled()
})

it("shares free or paid, reports provider stats and stops sharing without stopping the model", async () => {
  current = { ...current, signedIn: true, account }
  const view = render(<ModelNetworkPanel environmentId="env-one" />)
  await waitFor(() => expect(screen.getByRole("button", { name: "Share free" })).toBeEnabled())
  fireEvent.click(screen.getByRole("button", { name: "Share free" }))
  await waitFor(() => expect(mocks.share).toHaveBeenCalledWith("env-one", "free", false))
  await waitFor(() => expect(screen.getByRole("button", { name: "Share paid" })).toBeEnabled())
  fireEvent.click(screen.getByRole("button", { name: "Share paid" }))
  await waitFor(() => expect(mocks.share).toHaveBeenCalledWith("env-one", "paid", false))
  current.shares = [{ environmentId: "env-one", model: "google/gemma-4-31B", mode: "paid", nodeId: "node-one", status: "ready", live: true, listing: null, message: "Live on the Yougori Network", warnings: [], node: { id: "node-one", mode: "paid", gpu: "NVIDIA RTX 4090", tps: 12.5, tpsSource: "average", uptimeTodaySeconds: 3600, uptimeWeekSeconds: 7200, availability: 98.5, tokensIn: 100, tokensOut: 200, price: { input: 0.1, output: 0.34 }, earnedMicros: 500000 } }]
  await act(async () => event({ ...current }))
  expect(screen.getByText("NVIDIA RTX 4090")).toBeVisible()
  expect(screen.getByText("12.5 tokens/s · all-time average")).toBeVisible()
  expect(screen.getByText("1h 0m / 2h 0m")).toBeVisible()
  expect(screen.getByText("98.5%")).toBeVisible()
  expect(screen.getByText("100 / 200")).toBeVisible()
  expect(screen.getByText("$0.50")).toBeVisible()
  fireEvent.click(screen.getByRole("button", { name: "Stop sharing" }))
  await waitFor(() => expect(mocks.unshare).toHaveBeenCalledWith("env-one"))
  view.unmount()
})
