import { run } from "@/api/platform-api"
import { SetupCommandError, setupError, SetupUnavailableError } from "./setups-api"

/** A setup's scheduled backups: the list, a check of one copy, and putting one back. The engine
 *  keeps, checks and restores every copy; the desktop only asks and shows. `yougori setup backups`
 *  reaches the same three commands, so both doors read the same copies.
 *
 *  Putting a copy back is always two calls, as removing a setup is. The first changes nothing and
 *  answers with what it would do and a word for exactly that restore; only the second, carrying
 *  that word, puts anything back. */

/** How a copy was taken: with the sandboxes that write to the volume stopped, or while they ran. */
export type BackupConsistency = "stop" | "live"

/** How a volume's last scheduled backup went. */
export type BackupOutcome = "never_run" | "done" | "failed" | "skipped"

/** One copy kept of a volume. */
export interface KeptBackup {
  /** `backup-<uuid>`: the name the CLI uses for it. */
  id: string
  /** When it finished, in Unix seconds. */
  at: number
  /** The same moment as people read it, in this computer's own time. */
  when: string
  files: number
  bytes: number
  consistency: BackupConsistency
  /** The copy in one line: the line the CLI prints for it. */
  describe: string
}

/** A volume the setup backs up: its times, how the last run went, and the copies it keeps. */
export interface BackupVolume {
  /** The volume's name inside the setup. */
  resource: string
  /** The setup's sandbox it is read and restored through. */
  through: string
  /** The times in words, such as "every day at 02:00, this computer's time zone". */
  schedule: string
  /** The most copies kept. */
  keep: number
  consistency: BackupConsistency
  /** What `consistency` means for this volume, in a sentence. */
  consistencyWords: string
  /** Set while the setup is stopped: nothing runs until it starts again. */
  paused: boolean
  nextWhen: string | null
  lastOutcome: BackupOutcome
  /** One sentence about the last run, when there is one. */
  lastDetail: string
  lastWhen: string | null
  /** When the last run finished, in seconds, when one has. */
  lastFinishedAt: number | null
  /** Newest first. */
  backups: KeptBackup[]
}

export interface BackupList {
  setupId: string
  volumes: BackupVolume[]
  /** What a backup does not carry, said with the list as well as on every review. */
  limits: string
}

/** A kept copy read again and compared, file by file, with the record made when it was taken. */
export interface BackupCheck {
  resource: string
  backupId: string
  files: number
  bytes: number
  /** When the copy was taken. */
  when: string
  consistency: BackupConsistency
  /** What the copy does not hold, as its own record says. */
  note: string
}

/** What putting a copy back would do. When this comes back, nothing has been changed. */
export interface RestoreReview {
  setupId: string
  resource: string
  backupId: string
  /** True only for a restore over the volume itself; false for a new folder beside it. */
  overwrites: boolean
  /** What would happen, in sentences, read before anything is done. */
  review: string[]
  /** The engine's word for exactly this restore, and no other. */
  confirm: string
}

/** What a restore did. */
export interface RestoreDone {
  restoredTo: "copy" | "original"
  /** For a copy: the new folder inside the sandbox. */
  folder: string | null
  /** What happened and what to do now, in the engine's words. */
  next: string
}

const UNREVIEWED = "Yougori could not work out what this restore would do, so nothing was changed."

const record = (value: unknown): Record<string, unknown> => value && typeof value === "object" && !Array.isArray(value) ? value as Record<string, unknown> : {}
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : []
const text = (value: unknown) => typeof value === "string" ? value : ""
const count = (value: unknown) => typeof value === "number" && Number.isFinite(value) && value >= 0 ? value : 0
// A copy is only called quiet when the engine says so: anything else is read as taken live,
// which warns about half-written files rather than hiding them.
const consistency = (value: unknown): BackupConsistency => value === "stop" ? "stop" : "live"
const OUTCOMES = new Set<BackupOutcome>(["done", "failed", "skipped"])
const outcome = (value: unknown): BackupOutcome => OUTCOMES.has(value as BackupOutcome) ? value as BackupOutcome : "never_run"

/** A moment as the engine writes one for people, `2026-10-27 02:00`, in this computer's time. */
export function stamp(seconds: number): string {
  const at = new Date(seconds * 1000)
  if (!Number.isFinite(seconds) || Number.isNaN(at.getTime())) return "an unknown time"
  const two = (part: number) => String(part).padStart(2, "0")
  return `${at.getFullYear()}-${two(at.getMonth() + 1)}-${two(at.getDate())} ${two(at.getHours())}:${two(at.getMinutes())}`
}

function keptBackup(value: unknown): KeptBackup | null {
  const one = record(value)
  const id = text(one.id)
  if (!id) return null
  const at = count(one.at)
  const when = text(one.when) || stamp(at)
  return { id, at, when, files: count(one.files), bytes: count(one.bytes), consistency: consistency(one.consistency), describe: text(one.describe) || when }
}

function volume(value: unknown): BackupVolume | null {
  const one = record(value)
  const resource = text(one.resource)
  if (!resource) return null
  return {
    resource,
    through: text(one.through),
    schedule: text(one.schedule),
    keep: count(one.keep),
    consistency: consistency(one.consistency),
    consistencyWords: text(one.consistencyWords),
    paused: one.paused === true,
    nextWhen: text(one.nextWhen) || null,
    lastOutcome: outcome(one.lastOutcome),
    lastDetail: text(one.lastDetail),
    lastWhen: text(one.lastWhen) || null,
    lastFinishedAt: count(one.lastFinishedAt) || null,
    backups: list(one.backups).map(keptBackup).filter((backup): backup is KeptBackup => backup !== null),
  }
}

async function call(command: string, args: Record<string, unknown>): Promise<unknown> {
  try {
    return await run<unknown>(command, args, () => { throw new SetupUnavailableError(command) })
  } catch (reason) {
    throw setupError(command, reason)
  }
}

export const backupsApi = {
  /** Every volume the setup backs up, with the copies kept of each. Reads only. */
  async list(setupId: string): Promise<BackupList> {
    const answer = record(await call("setup_backups", { setupId }))
    return {
      setupId: text(answer.setupId) || setupId,
      volumes: list(answer.volumes).map(volume).filter((one): one is BackupVolume => one !== null),
      limits: text(answer.limits),
    }
  },
  /** Reads one kept copy again and compares every file with the record made when it was taken.
   *  Nothing is changed, on the copy or on the volume. */
  async check(setupId: string, resource: string, backupId: string): Promise<BackupCheck> {
    const answer = record(await call("setup_backup_verify", { setupId, resource, backupId }))
    return {
      resource,
      backupId,
      files: count(answer.files),
      bytes: count(answer.bytes),
      // The CLI's door words the moment in the engine; this one leaves it to the caller, which
      // is on the same computer and so reads the same clock.
      when: text(answer.when) || stamp(count(answer.at)),
      consistency: consistency(answer.consistency),
      note: text(answer.note),
    }
  },
  /** What putting `backupId` back would do. Nothing is changed by asking. The files go into a
   *  new folder inside the sandbox unless `overOriginal` is given, which replaces what is on the
   *  volume and is never assumed. */
  async reviewRestore(setupId: string, resource: string, backupId: string, overOriginal = false): Promise<RestoreReview> {
    const answer = record(await call("setup_backup_restore", { setupId, resource, backupId, overOriginal }))
    const confirm = text(answer.confirm)
    const review = list(answer.review).filter((line): line is string => typeof line === "string" && line.trim() !== "")
    // A review with nothing to read is not a review: there would be no way to confirm what it is.
    if (answer.reviewed !== true || !confirm || !review.length) throw new SetupCommandError(UNREVIEWED, { code: "restore_unreviewed" })
    return { setupId, resource, backupId, overwrites: overOriginal, review, confirm }
  },
  /** Takes a backup of one volume now, as its schedule would. Its regular times stay as they are.
   *  The answer says it has started; the copy shows in the list when it is done. */
  async backUpNow(setupId: string, resource: string): Promise<string> {
    const answer = record(await call("setup_backup_now", { setupId, resource }))
    return text(answer.said) || `A backup of ${resource} starts now. It shows in the list when it finishes.`
  },
  /** Puts the copy back exactly as `review` described: the same setup, volume, copy and target,
   *  with the word that review gave. It cannot confirm anything else. */
  async restore(review: RestoreReview): Promise<RestoreDone> {
    const answer = record(await call("setup_backup_restore", {
      setupId: review.setupId, resource: review.resource, backupId: review.backupId, overOriginal: review.overwrites, confirm: review.confirm,
    }))
    const restoredTo = answer.restoredTo === "original" ? "original" : "copy"
    return {
      restoredTo,
      folder: restoredTo === "copy" ? text(answer.folder) || null : null,
      next: text(answer.next) || (restoredTo === "original" ? `${review.resource} now holds what the backup held.` : `${review.resource} is unchanged.`),
    }
  },
}
