import { afterEach, expect, it, vi } from "vitest"

const run = vi.hoisted(() => vi.fn())
vi.mock("@/api/platform-api", () => ({ run }))

import { doctorError, DoctorUnavailableError, isDoctorUnavailable, sandboxDoctorApi } from "./sandbox-doctor-api"

afterEach(() => { run.mockReset() })

it("asks the engine's sandbox_doctor command for the status or the plan, with the run profiles only when some are given", async () => {
  run.mockResolvedValue({ examined: false, reason: "Not yet" })
  await sandboxDoctorApi.status()
  await sandboxDoctorApi.status(["strict", "gpu_vm"])
  await sandboxDoctorApi.plan([])
  await sandboxDoctorApi.plan(["strict"])
  expect(run.mock.calls.map(([command, args]) => [command, args])).toEqual([
    ["sandbox_doctor", { action: "status", profiles: null }],
    ["sandbox_doctor", { action: "status", profiles: ["strict", "gpu_vm"] }],
    ["sandbox_doctor", { action: "plan", profiles: null }],
    ["sandbox_doctor", { action: "plan", profiles: ["strict"] }],
  ])
})

it("never makes up a report in a browser preview", async () => {
  run.mockImplementation((_command: string, _args: unknown, browser: () => unknown) => browser())
  const refused = sandboxDoctorApi.status()
  await expect(refused).rejects.toBeInstanceOf(DoctorUnavailableError)
  await expect(sandboxDoctorApi.plan()).rejects.toThrow("needs Yougori Desktop")
})

it("says a build without the command is unavailable, and keeps the engine's own refusals", async () => {
  run.mockRejectedValueOnce("Command sandbox_doctor not found")
  await expect(sandboxDoctorApi.status()).rejects.toSatisfy(isDoctorUnavailable)
  expect(isDoctorUnavailable(doctorError("command sandbox_doctor not allowed by ACL"))).toBe(true)
  run.mockRejectedValueOnce("Unknown run profile 'lenient'. Use strict, transport, pool, gpu_vm, remote, confidential, drill, release or research.")
  const refusal = await sandboxDoctorApi.status(["strict"]).catch((reason: unknown) => reason)
  expect(isDoctorUnavailable(refusal)).toBe(false)
  expect((refusal as Error).message).toContain("Unknown run profile 'lenient'")
  expect(doctorError("").message).toBe("Yougori could not read the VM sandbox doctor. Try again.")
  expect(doctorError(new Error("Host evidence failed")).message).toBe("Host evidence failed")
})
