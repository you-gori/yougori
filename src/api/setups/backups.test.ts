import { afterEach, describe, expect, it, vi } from "vitest"

const invoke = vi.hoisted(() => vi.fn())
vi.mock("@/api/platform-api", () => ({ run: invoke }))

import { backupsApi, stamp } from "./backups"
import { isUnavailable, SetupCommandError } from "./setups-api"

afterEach(() => { invoke.mockReset() })

const listed = {
  setupId: "acme",
  volumes: [{
    resource: "data", through: "backup", mountedAt: "/data", schedule: "every day at 02:00, this computer's time zone", keep: 7, kept: 2,
    consistency: "stop", consistencyWords: "Before each backup the sandboxes that write to data are stopped.", paused: false, nextAt: 1793066400,
    nextWhen: "2026-10-27 02:00", lastOutcome: "done", lastDetail: "", lastFinishedAt: 1792980000, lastWhen: "2026-10-26 02:00",
    backups: [
      { id: "backup-2", at: 1792980000, when: "2026-10-26 02:00", files: 12, bytes: 4096, consistency: "stop", describe: "2026-10-26 02:00 — 12 files, 4 KB, taken with its sandboxes stopped" },
      { id: "backup-1", at: 1792893600, when: "2026-10-25 02:00", files: 11, bytes: 4000, consistency: "live", describe: "2026-10-25 02:00 — 11 files, 4 KB, taken while everything kept running" },
    ],
  }],
  limits: "A backup holds what is in the volume and nothing else.",
}

describe("backupsApi", () => {
  it("reads a setup's backups by its id, newest copy first, as the engine lists them", async () => {
    invoke.mockResolvedValue(listed)
    const found = await backupsApi.list("acme")
    expect(invoke).toHaveBeenCalledWith("setup_backups", { setupId: "acme" }, expect.any(Function))
    expect(found.volumes[0]).toMatchObject({ resource: "data", through: "backup", keep: 7, nextWhen: "2026-10-27 02:00", lastOutcome: "done", lastWhen: "2026-10-26 02:00" })
    expect(found.volumes[0]!.backups.map(backup => backup.id)).toEqual(["backup-2", "backup-1"])
    expect(found.limits).toBe("A backup holds what is in the volume and nothing else.")
  })

  it("leaves out what it can't read, and never calls a copy quiet unless the engine says so", async () => {
    invoke.mockResolvedValue({ volumes: [
      { resource: "data", backups: [{ id: "backup-x", at: 1792980000 }, { files: 3 }, null], lastOutcome: "exploded" },
      { through: "nameless" },
      "data",
    ] })
    const found = await backupsApi.list("acme")
    expect(found.setupId).toBe("acme")
    expect(found.volumes).toHaveLength(1)
    const [only] = found.volumes
    expect(only).toMatchObject({ lastOutcome: "never_run", consistency: "live", paused: false, nextWhen: null, keep: 0 })
    expect(only!.backups).toHaveLength(1)
    expect(only!.backups[0]).toMatchObject({ id: "backup-x", consistency: "live", when: stamp(1792980000), describe: stamp(1792980000) })
    invoke.mockResolvedValue(null)
    expect(await backupsApi.list("acme")).toEqual({ setupId: "acme", volumes: [], limits: "" })
  })

  it("checks one copy by setup, volume and backup, and works out its time when the engine leaves it out", async () => {
    invoke.mockResolvedValue({ files: 12, bytes: 4096, checksum: "c".repeat(64), at: 1792980000, consistency: "live", note: "It does not hold passwords." })
    const checked = await backupsApi.check("acme", "data", "backup-2")
    expect(invoke).toHaveBeenCalledWith("setup_backup_verify", { setupId: "acme", resource: "data", backupId: "backup-2" }, expect.any(Function))
    expect(checked).toEqual({ resource: "data", backupId: "backup-2", files: 12, bytes: 4096, when: stamp(1792980000), consistency: "live", note: "It does not hold passwords." })
    invoke.mockResolvedValue({ files: 1, at: 1792980000, when: "2026-10-26 02:00", consistency: "stop" })
    expect(await backupsApi.check("acme", "data", "backup-2")).toMatchObject({ when: "2026-10-26 02:00", consistency: "stop" })
  })

  it("asks for a review with no confirmation, into a new folder unless the volume itself is asked for", async () => {
    invoke.mockResolvedValue({ reviewed: true, applied: false, overwrites: false, review: ["The backup holds 12 files.", ""], confirm: "restore-0123456789abcdef", next: "Nothing has been changed." })
    const review = await backupsApi.reviewRestore("acme", "data", "backup-2")
    expect(invoke).toHaveBeenCalledWith("setup_backup_restore", { setupId: "acme", resource: "data", backupId: "backup-2", overOriginal: false }, expect.any(Function))
    expect(invoke.mock.calls[0]![1]).not.toHaveProperty("confirm")
    expect(review).toEqual({ setupId: "acme", resource: "data", backupId: "backup-2", overwrites: false, review: ["The backup holds 12 files."], confirm: "restore-0123456789abcdef" })
    await backupsApi.reviewRestore("acme", "data", "backup-2", true)
    expect(invoke).toHaveBeenLastCalledWith("setup_backup_restore", { setupId: "acme", resource: "data", backupId: "backup-2", overOriginal: true }, expect.any(Function))
  })

  it("refuses a review it can't confirm, and says nothing was changed", async () => {
    for (const answer of [
      { reviewed: true, review: ["A line."] },
      { reviewed: true, confirm: "restore-1", review: [] },
      { confirm: "restore-1", review: ["A line."] },
    ]) {
      invoke.mockResolvedValueOnce(answer)
      const refused = await backupsApi.reviewRestore("acme", "data", "backup-2").catch(reason => reason)
      expect(refused).toBeInstanceOf(SetupCommandError)
      expect(refused.message).toMatch(/nothing was changed/)
    }
    expect(invoke).toHaveBeenCalledTimes(3)
  })

  it("restores exactly what the review described, with the word it gave", async () => {
    invoke.mockResolvedValue({ restoredTo: "original", volume: "data", sandbox: "backup", checked: {}, next: "data now holds what the backup from 2026-10-26 02:00 held." })
    const done = await backupsApi.restore({ setupId: "acme", resource: "data", backupId: "backup-2", overwrites: true, review: ["Everything now on data is replaced."], confirm: "restore-fedcba9876543210" })
    expect(invoke).toHaveBeenCalledWith("setup_backup_restore", { setupId: "acme", resource: "data", backupId: "backup-2", overOriginal: true, confirm: "restore-fedcba9876543210" }, expect.any(Function))
    expect(done).toEqual({ restoredTo: "original", folder: null, next: "data now holds what the backup from 2026-10-26 02:00 held." })
    invoke.mockResolvedValue({ restoredTo: "copy", folder: "/tmp/yougori-restore-abc/files", sandbox: "backup", next: "The files are in /tmp/yougori-restore-abc/files inside backup." })
    expect(await backupsApi.restore({ setupId: "acme", resource: "data", backupId: "backup-1", overwrites: false, review: ["A line."], confirm: "restore-1" }))
      .toEqual({ restoredTo: "copy", folder: "/tmp/yougori-restore-abc/files", next: "The files are in /tmp/yougori-restore-abc/files inside backup." })
    expect(invoke).toHaveBeenLastCalledWith("setup_backup_restore", { setupId: "acme", resource: "data", backupId: "backup-1", overOriginal: false, confirm: "restore-1" }, expect.any(Function))
  })

  it("keeps the engine's refusal, and reads a build without these commands as unavailable", async () => {
    invoke.mockRejectedValueOnce({ code: "setup_busy", message: "Another change is running.", retryable: true, resource: "data" })
    await expect(backupsApi.list("acme")).rejects.toMatchObject({ code: "setup_busy", message: "Another change is running.", retryable: true })
    invoke.mockRejectedValueOnce("Command setup_backups not found")
    expect(isUnavailable(await backupsApi.list("acme").catch(reason => reason))).toBe(true)
    invoke.mockImplementationOnce((_command: string, _args: unknown, browser: () => unknown) => browser())
    expect(isUnavailable(await backupsApi.check("acme", "data", "backup-2").catch(reason => reason))).toBe(true)
  })
})

describe("stamp", () => {
  it("writes a moment the way the engine does, in this computer's time", () => {
    const at = new Date(2026, 9, 27, 2, 5).getTime() / 1000
    expect(stamp(at)).toBe("2026-10-27 02:05")
    expect(stamp(Number.NaN)).toBe("an unknown time")
  })
})
