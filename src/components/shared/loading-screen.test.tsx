// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { LoadingScreen } from "./loading-screen"

afterEach(() => { cleanup(); vi.useRealTimers() })

it("announces loading without fake progress or an unnecessary delay", () => {
  const view = render(<LoadingScreen />)
  expect(screen.getByRole("main").getAttribute("aria-busy")).toBe("true")
  expect(screen.getByRole("status").textContent).toBe("Starting your workspace…")
  expect(screen.queryByRole("button")).toBeNull()
  view.unmount()
  expect(screen.queryByRole("status")).toBeNull()
})

it("keeps the loading message without a delayed reload prompt", () => {
  vi.useFakeTimers()
  const retry = vi.fn()
  render(<LoadingScreen onRetry={retry} />)
  act(() => vi.advanceTimersByTime(300_000))
  expect(retry).not.toHaveBeenCalled()
  expect(screen.getByRole("status").textContent).toBe("Starting your workspace…")
  expect(screen.queryByRole("button")).toBeNull()
})

it("shows startup errors with a working retry instead of an endless spinner", () => {
  const retry = vi.fn()
  const { container } = render(<LoadingScreen error="Runtime unavailable" onRetry={retry} />)
  expect(screen.getByRole("alert").textContent).toContain("Runtime unavailable")
  expect(screen.getByRole("main").getAttribute("aria-busy")).toBe("false")
  expect(container.querySelector(".startup-track")).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Try again" }))
  expect(retry).toHaveBeenCalledOnce()
})

it("keeps vault disk diagnostics collapsed and lets the user open the app", () => {
  const continueApp = vi.fn()
  render(<LoadingScreen error="Could not start Personal Vault: Container disk needs recovery; Leaked cluster 15130" onContinue={continueApp} />)
  expect(screen.getByRole("alert").textContent).toContain("vault container disk needs recovery")
  expect(screen.getByRole("alert").textContent).not.toContain("Leaked cluster")
  expect(screen.getByText("Technical details")).toBeTruthy()
  fireEvent.click(screen.getByRole("button", { name: "Open Yougori" }))
  expect(continueApp).toHaveBeenCalledOnce()
})
