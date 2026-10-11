// @vitest-environment jsdom
import { act, cleanup, renderHook, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { StrictMode, type ReactNode } from "react"
import { vaultApi } from "@/api/vault-api"
import { useVaultStartup, VAULT_STARTUP_NOTICE_MS } from "./use-vault-startup"
vi.mock("@/api/vault-api", () => ({ vaultApi: { bootstrap: vi.fn() } }))
afterEach(() => { cleanup(); vi.clearAllMocks(); vi.useRealTimers() })
it("waits for the platform, then keeps startup blocked until the container is ready", async () => {
  let resolve!: (result: { created: boolean; ready: boolean }) => void
  vi.mocked(vaultApi.bootstrap).mockReturnValue(new Promise(done => { resolve = done }))
  const hook = renderHook(({ ready }) => useVaultStartup(ready), { initialProps: { ready: false }, wrapper: ({ children }: { children: ReactNode }) => <StrictMode>{children}</StrictMode> })
  expect(vaultApi.bootstrap).not.toHaveBeenCalled()
  hook.rerender({ ready: true })
  expect(hook.result.current.ready).toBe(false)
  expect(vaultApi.bootstrap).toHaveBeenCalledOnce()
  await act(async () => resolve({ created: true, ready: true }))
  expect(hook.result.current.ready).toBe(true)
})
it("does not require a container before the user creates a vault", async () => {
  vi.mocked(vaultApi.bootstrap).mockResolvedValue({ created: false })
  const hook = renderHook(() => useVaultStartup(true))
  await waitFor(() => expect(hook.result.current.ready).toBe(true))
})
it("shows failures and retries without reloading or bypassing readiness", async () => {
  vi.mocked(vaultApi.bootstrap).mockRejectedValueOnce(new Error("Container failed")).mockResolvedValueOnce({ created: true, ready: true })
  const hook = renderHook(() => useVaultStartup(true))
  await waitFor(() => expect(hook.result.current.error).toContain("Container failed"))
  expect(hook.result.current.ready).toBe(false)
  act(() => hook.result.current.retry())
  await waitFor(() => expect(hook.result.current.ready).toBe(true))
  expect(hook.result.current.error).toBeNull()
  expect(vaultApi.bootstrap).toHaveBeenCalledTimes(2)
})
it("rejects a startup response that has not confirmed container readiness", async () => {
  vi.mocked(vaultApi.bootstrap).mockResolvedValue({ created: true, ready: false })
  const hook = renderHook(() => useVaultStartup(true))
  await waitFor(() => expect(hook.result.current.error).toContain("not ready"))
  expect(hook.result.current.ready).toBe(false)
})

it("opens the app for an explicit vault update instead of prompting at launch", async () => {
  vi.mocked(vaultApi.bootstrap).mockResolvedValue({ created: true, ready: false, updateRequired: true })
  const hook = renderHook(() => useVaultStartup(true))
  await waitFor(() => expect(hook.result.current.ready).toBe(true))
  expect(hook.result.current.error).toBeNull()
})

it("offers to continue when startup is slow without starting a second bootstrap", async () => {
  vi.useFakeTimers()
  let resolve!: (result: { created: boolean; ready: boolean }) => void
  vi.mocked(vaultApi.bootstrap).mockReturnValue(new Promise(done => { resolve = done }))
  const hook = renderHook(() => useVaultStartup(true))
  act(() => vi.advanceTimersByTime(VAULT_STARTUP_NOTICE_MS))
  expect(hook.result.current.error).toContain("taking longer than expected")
  expect(hook.result.current.ready).toBe(false)
  act(() => hook.result.current.retry())
  expect(vaultApi.bootstrap).toHaveBeenCalledOnce()
  await act(async () => resolve({ created: true, ready: true }))
  expect(hook.result.current.ready).toBe(true)
  expect(hook.result.current.error).toBeNull()
})

it("allows an explicit app-only continuation after a vault failure", async () => {
  vi.mocked(vaultApi.bootstrap).mockRejectedValue(new Error("Container disk needs recovery"))
  const hook = renderHook(() => useVaultStartup(true))
  await waitFor(() => expect(hook.result.current.error).toContain("Container disk needs recovery"))
  act(() => hook.result.current.continueWithoutVault())
  expect(hook.result.current.ready).toBe(true)
  expect(vaultApi.bootstrap).toHaveBeenCalledOnce()
})
