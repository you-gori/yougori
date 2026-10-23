// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest"
import { gridApi } from "@/api/grid-api"
import { desksApi } from "@/api/desks-api"
import { swarmApi } from "@/api/swarm-api"
import { bountyApi } from "@/api/bounty-api"
import { ConflictError, DesktopOnlyError, GridError } from "@/api/grids/errors"
import { CARRIES_REQUEST_ID, call, requestId, resetTransport, setTransport } from "@/api/grids/wire"

afterEach(() => { resetTransport(); vi.restoreAllMocks() })

const records = () => {
  const calls: Array<{ command: string; args: Record<string, unknown> }> = []
  setTransport(async (command, args) => { calls.push({ command, args }); return {} as never })
  return calls
}

/** The refusal a call gave, for a test that is about the refusal. */
const refused = (make: () => Promise<unknown>): Promise<GridError> =>
  make().then(
    () => { throw new Error("That call was expected to be refused and was not") },
    (reason: unknown) => reason as GridError,
  )

describe("the one call path", () => {
  it("gives every call a name a person could read out, and a fresh one each time", () => {
    const first = requestId()
    expect(first).toMatch(/^[a-z]+-[a-z]+-[0-9a-f]{6}$/)
    expect(first).not.toBe(requestId())
  })

  it("carries that name onto the refusal, so two people reading a log can find the same call", async () => {
    setTransport(async () => { throw new Error("The hub stopped answering") })
    const failure = await refused(() => call("grid_status"))
    expect(failure).toBeInstanceOf(GridError)
    expect(failure.failure).toBe("offline")
    expect(failure.command).toBe("grid_status")
    expect(failure.requestId).toMatch(/^[a-z]+-[a-z]+-[0-9a-f]{6}$/)
  })

  it("uses one name for every call in one action, when the caller gives one", async () => {
    setTransport(async () => { throw new Error("The hub stopped answering") })
    const mine = "keen-heron-abc123"
    const first = await refused(() => call("grid_status", {}, { requestId: mine }))
    const second = await refused(() => call("grid_leave", {}, { requestId: mine }))
    expect([first.requestId, second.requestId]).toEqual([mine, mine])
  })

  it("puts no request name into the arguments of a command, because no command reads one", async () => {
    const calls = records()
    await call("grid_status", { when: "later" })
    expect(CARRIES_REQUEST_ID.size).toBe(0)
    expect(calls[0]!.args).toEqual({ when: "later" })
  })

  it("sends the version a caller believed it was changing, and nothing extra when it says nothing", async () => {
    const calls = records()
    await call("desks_assign", { desk: "d1" }, { expect: { version: 7 } })
    await call("desks_assign", { desk: "d1" })
    expect(calls[0]!.args).toEqual({ desk: "d1", ifVersion: 7 })
    expect(calls[1]!.args).toEqual({ desk: "d1" })
  })

  it("tells a stale page when a backend answers with a different version", async () => {
    setTransport(async () => ({ version: 9 }) as never)
    const failure = await refused(() => call("desks_assign", { desk: "d1" }, { expect: { version: 7 } })) as ConflictError
    expect(failure).toBeInstanceOf(ConflictError)
    expect([failure.expected, failure.actual]).toEqual([7, 9])
    // No engine command answers with one today, so this carries rather than enforces.
    await expect(call("desks_assign", { desk: "d1" }, { expect: { version: 9 } })).resolves.toEqual({ version: 9 })
  })

  it("replaces the whole path in one line, for every product at once", async () => {
    const calls = records()
    await gridApi.status()
    await desksApi.status()
    await swarmApi.workers().catch(() => [])
    await bountyApi.status()
    expect(calls.map(entry => entry.command)).toEqual(["grid_status", "desks_status", "swarm_dispatch", "bounty_dispatch"])
  })

  it("keeps each product's own sentence when there is no desktop app, rather than one for all four", async () => {
    const said = async (make: () => Promise<unknown>) => make().then(() => "", (reason: unknown) => (reason as Error).message)
    expect(await said(() => gridApi.leave())).toBe("Open Yougori Desktop to host or join a Closed Neo Grid")
    expect(await said(() => desksApi.leave())).toBe("Open Yougori Desktop to host or join a sandbox grid")
    expect(await said(() => swarmApi.workers())).toBe("Open Yougori Desktop to use Swarm Mining")
    expect(await said(() => bountyApi.status())).toBe("Open Yougori Desktop to host a private bounty")
    await expect(gridApi.leave()).rejects.toBeInstanceOf(DesktopOnlyError)
  })

  it("still answers a read in a browser fixture, because the four pages depend on that", async () => {
    await expect(gridApi.status()).resolves.toEqual({ hub: null, hubError: null, member: null, memberError: null })
    await expect(desksApi.suggestedAddress()).resolves.toBeNull()
  })
})
