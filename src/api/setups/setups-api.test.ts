import { afterEach, describe, expect, it, vi } from "vitest"

const invoke = vi.hoisted(() => vi.fn())
vi.mock("@/api/platform-api", () => ({ run: invoke }))

import { changedAnswers, draftAnswers, isUnavailable, newOperationId, SetupCommandError, secretBindings, setupError, setupsApi, SetupUnavailableError, withResourceDetails } from "./setups-api"

afterEach(() => { invoke.mockReset() })

it("says a command this build does not have is unavailable, never a failure", () => {
  expect(isUnavailable(setupError("setup_list", "Command setup_list not found"))).toBe(true)
  expect(isUnavailable(setupError("setup_list", "command setup_list not allowed by ACL"))).toBe(true)
  expect(isUnavailable(setupError("setup_plan", { code: "planner_unavailable", message: "The planner is not in this build." }))).toBe(true)
  expect(isUnavailable(setupError("setup_plan", JSON.stringify({ code: "planner_unavailable", message: "x" })))).toBe(true)
})

it("keeps the engine's code, retryability, operation and typed next actions", () => {
  const error = setupError("setup_apply", { code: "setup_busy", message: "Another change is running.", retryable: true, operation: "op-1", nextActions: [{ kind: "retry" }, "rm -rf /", null] })
  expect(error).toBeInstanceOf(SetupCommandError)
  expect(error).toMatchObject({ code: "setup_busy", message: "Another change is running.", retryable: true, operation: "op-1", nextActions: [{ kind: "retry" }] })
  expect(setupError("x", "")).toMatchObject({ message: "Yougori could not finish this. Try again." })
  expect(setupError("x", 42)).toBeInstanceOf(SetupCommandError)
})

it("turns a draft into the planner's answers, and secrets into bindings that carry no value", () => {
  expect(draftAnswers({
    name: "Acme",
    capabilities: {
      "grid.create": { selected: true, mode: "required", runnerEditable: false, settings: { grid_name: "acme" } },
      "web.site": { selected: false, mode: "optional", runnerEditable: true, settings: { port: 3000 } },
    },
    questions: [
      { id: "grid_name", label: "Grid name", kind: "text", capability: "grid.create" },
      { id: "port", label: "Port", kind: "number", capability: "web.site" },
      { id: "token", label: "Token", kind: "secret" },
    ],
    answers: { region: "eu", token: "never-an-answer" },
  })).toEqual([
    // Every capability is a switch, on or off; questions go by the template's own input ids, and
    // a question of a capability that is off, or a secret, is never an answer.
    { field: "capabilities.grid.create", value: true },
    { field: "capabilities.web.site", value: false },
    { field: "grid_name", value: "acme" },
    { field: "region", value: "eu" },
  ])
  expect(secretBindings(["admin.password", "api.key"])).toEqual([
    { field: "admin.password", secretRef: "apply:admin.password" },
    { field: "api.key", secretRef: "apply:api.key" },
  ])
})

it("applies with the reviewed digest, the revision and one operation id, and sends secrets only there", async () => {
  invoke.mockResolvedValue({ operationId: "op-a", setupId: "s1" })
  await setupsApi.apply({ setupId: "s1", digest: "d1", baseRevision: 0 }, "op-a", { "admin.password": "correct horse" })
  expect(invoke).toHaveBeenCalledWith("setup_apply", { request: { setupId: "s1", planDigest: "d1", operationId: "op-a", expectedRevision: 0, secrets: { "admin.password": "correct horse" } } }, expect.any(Function))
  await setupsApi.apply({ setupId: "s1", digest: "d1", baseRevision: 3 }, "op-b", {})
  expect(invoke).toHaveBeenLastCalledWith("setup_apply", { request: { setupId: "s1", planDigest: "d1", operationId: "op-b", expectedRevision: 3 } }, expect.any(Function))
})

it("agrees to a joined review's terms by continuing the waiting change with its own reviewed digest", async () => {
  invoke.mockImplementation(async (command: string) => command === "setup_operation" ? { planDigest: "d9", events: [], nextCursor: 0 } : { operationId: "op-w", setupId: "s1" })
  await setupsApi.agreeToTerms("s1", "op-w", "abcdef012345")
  expect(invoke).toHaveBeenCalledWith("setup_operation", { operationId: "op-w", cursor: null }, expect.any(Function))
  expect(invoke).toHaveBeenLastCalledWith("setup_apply", { request: { setupId: "s1", planDigest: "d9", operationId: "op-w", expectedRevision: 0, secrets: { accept_terms: "abcdef012345" } } }, expect.any(Function))
  // An engine that doesn't say which plan the change applies can't be answered from here.
  invoke.mockImplementation(async () => ({ events: [], nextCursor: 0 }))
  await expect(setupsApi.agreeToTerms("s1", "op-w", "abcdef012345")).rejects.toBeInstanceOf(SetupUnavailableError)
})

it("reads list and capabilities in either wrapped or bare form, and reports the browser preview as unavailable", async () => {
  invoke.mockResolvedValueOnce({ setups: [{ setupId: "a" }] }).mockResolvedValueOnce([{ setupId: "b" }])
  expect(await setupsApi.list()).toEqual([{ setupId: "a" }])
  expect(await setupsApi.list()).toEqual([{ setupId: "b" }])
  invoke.mockImplementationOnce((_command: string, _args: unknown, browser: () => unknown) => browser())
  await expect(setupsApi.capabilities()).rejects.toBeInstanceOf(SetupUnavailableError)
})

it("makes operation ids the engine accepts", () => {
  const id = newOperationId()
  expect(id).toMatch(/^op-[A-Za-z0-9._:-]+$/)
  expect(id.length).toBeLessThanOrEqual(128)
  expect(newOperationId()).not.toBe(id)
})

it("reads 'not available' only from Tauri's own refusal and the engine's codes for it, never from a sentence", () => {
  expect(isUnavailable(setupError("setup_get", { code: "setup_missing", message: "The command not found in this setup's record." }))).toBe(false)
  expect(isUnavailable(setupError("setup_get", "This setup's start command not found anywhere."))).toBe(false)
  expect(isUnavailable(setupError("setup_get", new Error("Command setup_get not found")))).toBe(true)
})

it("folds the engine's per-resource details into each resource, keeping only what it reads", () => {
  const detail = withResourceDetails({
    summary: { setupId: "s1", name: "x", source: { kind: "installed_setup", setupId: "y" }, state: "running", createdAt: 1 }, revision: 1, capabilities: [],
    resources: [
      { resourceId: "app", kind: "environment", owned: true, label: "app" },
      { resourceId: "link", kind: "connection", owned: true, label: "link" },
      { resourceId: "site", kind: "service_publication", owned: true, label: "site" },
      { resourceId: "remote", kind: "vm_sandbox", owned: true, label: "remote" },
    ],
    resourceDetails: {
      app: { dependsOn: ["db", 4], placement: "this computer", actions: ["start", "explode"], image: "node:24", lastCheckedAt: 1760001000, lastHealthyAt: 1760001000 },
      link: { connection: { from: "app", to: "db", ports: [5432, "x"], direction: "both" }, lastCheckedAt: 1760002000, lastHealthyAt: null },
      site: { connection: { to: "app", port: 3000, access: "quick" }, lastCheckedAt: "soon", lastHealthyAt: 1 },
      remote: { placement: "a restricted VM on SSH connection env-owned", remoteVm: true },
      ghost: { placement: "nowhere" },
    },
  })
  expect(detail.resources[0]).toMatchObject({ dependsOn: ["db"], placement: "This computer", actions: ["start"] })
  expect(detail.resources[1]!.connection).toEqual({ from: "app", to: "db", ports: [5432], direction: "both" })
  expect(detail.resources[2]).toMatchObject({ exposure: { to: "app", port: 3000, access: "quick" } })
  expect(detail.resources[2]!.connection).toBeUndefined()
  // Last-checked/last-healthy pass through as numbers; a drifted part keeps no healthy time, and a
  // non-number is dropped to null rather than shown as a time.
  expect(detail.resources[0]).toMatchObject({ lastCheckedAt: 1760001000, lastHealthyAt: 1760001000 })
  expect(detail.resources[1]).toMatchObject({ lastCheckedAt: 1760002000, lastHealthyAt: null })
  expect(detail.resources[2]!.lastCheckedAt).toBeNull()
  expect(detail.resources[3]).toMatchObject({ remoteVm: true, placement: "A restricted VM on SSH connection env-owned" })
})

it("sends consents with the apply only when some were ticked", async () => {
  invoke.mockResolvedValue({ operationId: "op-a", setupId: "s1" })
  await setupsApi.apply({ setupId: "s1", digest: "d1", baseRevision: 0 }, "op-a", undefined, ["b", "a", "a"])
  expect(invoke).toHaveBeenLastCalledWith("setup_apply", { request: { setupId: "s1", planDigest: "d1", operationId: "op-a", expectedRevision: 0, consents: ["a", "b"] } }, expect.any(Function))
  await setupsApi.apply({ setupId: "s1", digest: "d1", baseRevision: 0 }, "op-a", undefined, [])
  expect(invoke).toHaveBeenLastCalledWith("setup_apply", { request: { setupId: "s1", planDigest: "d1", operationId: "op-a", expectedRevision: 0 } }, expect.any(Function))
})

describe("changedAnswers", () => {
  it("keeps only what differs from the setup as it was read", () => {
    const before = { name: "Acme", capabilities: { "web.site": { selected: true, mode: "default" as const, runnerEditable: true, settings: { port: 8080, title: "Shop" } } } }
    const after = { ...before, capabilities: { "web.site": { ...before.capabilities["web.site"], settings: { port: 8081, title: "Shop" } } } }
    expect(changedAnswers(after, before)).toEqual([{ field: "port", value: 8081 }])
    expect(changedAnswers(before, before)).toEqual([])
    const off = { ...before, capabilities: { "web.site": { ...before.capabilities["web.site"], selected: false } } }
    expect(changedAnswers(off, before)).toEqual([{ field: "capabilities.web.site", value: false }])
  })
})

it("lists a setup's private outputs without their values, and reveals one only when asked", async () => {
  invoke.mockResolvedValueOnce({ setupId: "s1", private: [{ key: "invite", label: "Grid invite" }, { key: 7 }, null] })
  expect(await setupsApi.privateOutputs("s1")).toEqual([{ key: "invite", label: "Grid invite" }])
  expect(invoke).toHaveBeenLastCalledWith("setup_reveal", { setupId: "s1" }, expect.any(Function))
  invoke.mockResolvedValueOnce({ setupId: "s1", key: "invite", label: "Grid invite", value: "desk-invite:abc" })
  expect(await setupsApi.reveal("s1", "invite")).toBe("desk-invite:abc")
  expect(invoke).toHaveBeenLastCalledWith("setup_reveal", { setupId: "s1", key: "invite" }, expect.any(Function))
  // An answer without a value is never shown as an empty secret.
  invoke.mockResolvedValueOnce({ setupId: "s1", key: "invite", label: "Grid invite" })
  await expect(setupsApi.reveal("s1", "invite")).rejects.toMatchObject({ code: "output_not_ready", retryable: true })
})
