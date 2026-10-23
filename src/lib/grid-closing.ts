/** A grid its admin is deleting: paused until `until` (and restorable), then gone. */
export interface GridClosing {
  requestedAt: number
  until: number
  /** Past `until`: deleted; computers are told as they check in. */
  gone: boolean
  /** Computers that heard it was deleted, of all of them. A grid that keeps no per-computer
   *  record of who was told leaves both out rather than reporting none of none. */
  told?: number
  computers?: number
  /** The hub stops waiting for computers that are away at this time. */
  tellUntil: number
}

/** How long a hub keeps telling computers that a grid was deleted, before it stops waiting for
 *  the ones that never came back. Thirty days, which is what the hub itself waits. */
export const TELL_FOR = 30 * 24 * 60 * 60

/** `later` pauses a grid for three days (restorable), `now` deletes it, `forget` stops waiting for computers. */
export type DeleteWhen = "later" | "now" | "forget"

/** When, in this computer's own time: "Mon 20 Oct, 23:10". */
export function when(seconds: number) {
  return new Date(seconds * 1000).toLocaleString(undefined, { weekday: "short", day: "numeric", month: "short", hour: "2-digit", minute: "2-digit" })
}
