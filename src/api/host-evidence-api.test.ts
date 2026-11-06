import { afterEach, expect, it, vi } from "vitest"

const run = vi.hoisted(() => vi.fn())
vi.mock("@/api/platform-api", () => ({ run }))

import { hostEvidenceApi, hostEvidenceError, HostEvidenceUnavailableError, isHostEvidenceUnavailable } from "./host-evidence-api"

afterEach(() => { run.mockReset() })

it("asks the engine's host_evidence command for the status, the plan or a refresh, always naming the action", async () => {
  run.mockResolvedValue({})
  await hostEvidenceApi.status()
  await hostEvidenceApi.plan()
  await hostEvidenceApi.refresh()
  expect(run.mock.calls.map(([command, args]) => [command, args])).toEqual([
    ["host_evidence", { action: "status" }],
    ["host_evidence", { action: "plan" }],
    ["host_evidence", { action: "refresh" }],
  ])
})

it("passes the engine's answer through unchanged", async () => {
  const status = { inventory: null, inventoryAgeMs: null, entries: [], uncovered: [] }
  run.mockResolvedValueOnce(status)
  await expect(hostEvidenceApi.status()).resolves.toBe(status)
})

it("never makes up evidence in a browser preview, and never runs a query there", async () => {
  run.mockImplementation((_command: string, _args: unknown, browser: () => unknown) => browser())
  await expect(hostEvidenceApi.status()).rejects.toBeInstanceOf(HostEvidenceUnavailableError)
  await expect(hostEvidenceApi.refresh()).rejects.toThrow("Host evidence needs Yougori Desktop.")
  await expect(hostEvidenceApi.plan()).rejects.toSatisfy(isHostEvidenceUnavailable)
})

it("says a build without the command is unavailable, and keeps the engine's own refusals", async () => {
  run.mockRejectedValueOnce("Command host_evidence not found")
  await expect(hostEvidenceApi.status()).rejects.toSatisfy(isHostEvidenceUnavailable)
  expect(isHostEvidenceUnavailable(hostEvidenceError("command host_evidence not allowed by ACL"))).toBe(true)
  run.mockRejectedValueOnce("Unknown host evidence action 'scan'. Use status, refresh or plan.")
  const refusal = await hostEvidenceApi.refresh().catch((reason: unknown) => reason)
  expect(isHostEvidenceUnavailable(refusal)).toBe(false)
  expect((refusal as Error).message).toBe("Unknown host evidence action 'scan'. Use status, refresh or plan.")
  run.mockRejectedValueOnce(new Error("Host evidence is unavailable: an adapter was registered twice"))
  await expect(hostEvidenceApi.status()).rejects.toThrow("Host evidence is unavailable: an adapter was registered twice")
  expect(hostEvidenceError("").message).toBe("Yougori could not read the host evidence. Try again.")
  expect(hostEvidenceError({}).message).toBe("Yougori could not read the host evidence. Try again.")
})
