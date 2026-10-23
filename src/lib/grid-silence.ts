/** A hub that has stopped answering. One that was deleted says so; one that was switched off for
 *  good never does, so after a week this computer's person is asked whether to leave it. */
export const ASK_TO_LEAVE_DAYS = 7

/** Whole days since a Unix time, or null when it never happened. */
export function daysSince(seconds: number | null | undefined) {
  if (!seconds) return null
  return Math.floor((Date.now() / 1000 - seconds) / 86400)
}

/** What to tell someone whose hub has been silent for `days`, if anything. */
export function silenceNotice(days: number | null, grid: string) {
  if (days === null || days < ASK_TO_LEAVE_DAYS) return null
  return `${grid}'s hub has not answered for ${days} days. If it is gone for good, leave the grid; nothing here is removed by leaving.`
}
