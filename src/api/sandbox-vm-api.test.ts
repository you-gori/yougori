import { afterEach, expect, it, vi } from "vitest"

const run = vi.hoisted(() => vi.fn())
vi.mock("@/api/platform-api", () => ({ run }))

import { isSandboxVmUnavailable, sandboxVmApi, sandboxVmError, SandboxVmUnavailableError, visibleText } from "./sandbox-vm-api"

afterEach(() => { run.mockReset() })

it("asks the engine's sandbox_vm command with the action inside the request", async () => {
  run.mockResolvedValue({})
  await sandboxVmApi.status()
  await sandboxVmApi.launch({ memoryGb: 1, workspace: "C:\\work\\project" })
  await sandboxVmApi.exec("exe-1", "ls $WORKSPACE")
  await sandboxVmApi.review("exe-1")
  await sandboxVmApi.promote("exe-1", "ab12", ["src/app.py"])
  await sandboxVmApi.discard("exe-1")
  await sandboxVmApi.connect("exe-1", "api", "exe-2", "web")
  await sandboxVmApi.disconnect("exe-1", "api")
  await sandboxVmApi.drill()
  expect(run.mock.calls.map(([command, args]) => [command, args])).toEqual([
    ["sandbox_vm", { action: "status", params: { action: "status" } }],
    ["sandbox_vm", { action: "launch", params: { action: "launch", memoryGb: 1, workspace: "C:\\work\\project" } }],
    ["sandbox_vm", { action: "exec", params: { action: "exec", sandbox: "exe-1", input: "ls $WORKSPACE", timeoutSeconds: 60 } }],
    ["sandbox_vm", { action: "workspace", params: { action: "workspace", op: "review", sandbox: "exe-1" } }],
    ["sandbox_vm", { action: "workspace", params: { action: "workspace", op: "promote", sandbox: "exe-1", review: "ab12", files: ["src/app.py"] } }],
    ["sandbox_vm", { action: "workspace", params: { action: "workspace", op: "discard", sandbox: "exe-1" } }],
    ["sandbox_vm", { action: "connect", params: { action: "connect", sandbox: "exe-1", endpoint: "api", to: "exe-2", service: "web", minutes: 60 } }],
    ["sandbox_vm", { action: "disconnect", params: { action: "disconnect", sandbox: "exe-1", endpoint: "api" } }],
    ["sandbox_vm", { action: "drill", params: { action: "drill", check: "vm-cp-29" } }],
  ])
})

it("never makes up an answer in a browser preview, and keeps the engine's refusals", async () => {
  run.mockImplementationOnce((_command: string, _args: unknown, browser: () => unknown) => browser())
  await expect(sandboxVmApi.status()).rejects.toBeInstanceOf(SandboxVmUnavailableError)
  run.mockRejectedValueOnce("Command sandbox_vm not found")
  await expect(sandboxVmApi.status()).rejects.toSatisfy(isSandboxVmUnavailable)
  run.mockRejectedValueOnce("that review is not the latest one; review again")
  const refusal = await sandboxVmApi.promote("exe-1", "old", ["a"]).catch((reason: unknown) => reason)
  expect(isSandboxVmUnavailable(refusal)).toBe(false)
  expect((refusal as Error).message).toBe("that review is not the latest one; review again")
  expect(sandboxVmError("").message).toContain("Try again")
})

it("shows control, invisible and direction-changing characters of untrusted text as code points", () => {
  expect(visibleText("ok\n\ttab")).toBe("ok\n\ttab")
  expect(visibleText("\u001b]52;c;cGF5bG9hZA==\u0007")).toBe("⟨U+001B⟩]52;c;cGF5bG9hZA==⟨U+0007⟩")
  expect(visibleText("invoice\u202Etxt.exe")).toBe("invoice⟨U+202E⟩txt.exe")
  expect(visibleText("a\u200Bb\uFEFFc\u0000")).toBe("a⟨U+200B⟩b⟨U+FEFF⟩c⟨U+0000⟩")
})

it("changes guest grid configuration with bounded commands and refuses malformed responses", async () => {
  run.mockResolvedValue({ exit_code: 0, output_text: '{"installed":true,"enabled":[]}' })
  await expect(sandboxVmApi.gridSettings("exe-a", [])).resolves.toEqual({ installed: true, enabled: [] })
  expect(run).toHaveBeenLastCalledWith("sandbox_vm", { action: "exec", params: {
    action: "exec", sandbox: "exe-a", input: "/run/yougori/bin/yougori-probe grid configure --resources none\n", timeoutSeconds: 30, maxOutputBytes: 4096,
  } }, expect.any(Function))
  await expect(sandboxVmApi.gridSettings("exe-a", ["gpu", "gpu"])).rejects.toThrow("Choose")
  expect(run).toHaveBeenCalledTimes(1)
  run.mockResolvedValueOnce({ exit_code: 0, output_text: '{"installed":true,"enabled":["unknown"]}' })
  await expect(sandboxVmApi.gridSettings("exe-a")).rejects.toThrow("invalid")
  run.mockResolvedValueOnce({ exit_code: 1, output_text: "VM stopped" })
  await expect(sandboxVmApi.gridSettings("exe-a", ["gpu"])).rejects.toThrow("VM stopped")
})
