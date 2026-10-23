// @vitest-environment jsdom
import { act, renderHook } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { useFleeting } from "./use-fleeting"

afterEach(() => { vi.useRealTimers() })

const show = (view: string, message: string | null) => renderHook(({ text }: { text: string | null }) => useFleeting(view, text), { initialProps: { text: message } })

it("shows an error for twenty seconds, then keeps it hidden while refreshes repeat it", () => {
  vi.useFakeTimers()
  const deleted = "Acme deleted this sandbox grid. This computer left it and deleted the desks it hosted."
  const { result, rerender } = show("test-repeat", deleted)
  expect(result.current).toBe(deleted)
  act(() => { vi.advanceTimersByTime(19_999) })
  expect(result.current).toBe(deleted)
  act(() => { vi.advanceTimersByTime(1) })
  expect(result.current).toBeNull()
  rerender({ text: deleted })
  expect(result.current).toBeNull()
  // Opening the same view again later does not bring it back.
  expect(show("test-repeat", deleted).result.current).toBeNull()
})

it("gives a different error its own time and shows an error again once the source cleared", () => {
  vi.useFakeTimers()
  const { result, rerender } = show("test-change", "Cannot reach the grid hub")
  act(() => { vi.advanceTimersByTime(20_000) })
  expect(result.current).toBeNull()
  rerender({ text: "This computer's membership is damaged" })
  expect(result.current).toBe("This computer's membership is damaged")
  rerender({ text: null })
  rerender({ text: "Cannot reach the grid hub" })
  expect(result.current).toBe("Cannot reach the grid hub")
})

it("keeps views apart", () => {
  vi.useFakeTimers()
  show("test-one", "Hub unreachable")
  act(() => { vi.advanceTimersByTime(20_000) })
  expect(show("test-two", "Hub unreachable").result.current).toBe("Hub unreachable")
})
