/** Turning a grid's record into words a person reads.
 *
 *  Grid Core writes one sealed event per decision. Each one carries a principal id and an action
 *  as a dotted token, such as `realm.lifecycle` or `workspace.image.refused`. Neither is ever
 *  shown. This file turns the first into a person's name and the second into a sentence, and the
 *  four products' own activity lines go through the same door so one timeline reads as one thing.
 */
import type { AuditDecision } from "@/api/grids/types"

/** What the first word of an action is about. */
const SUBJECT: Record<string, string> = {
  approval: "a request",
  capability: "something this grid does",
  connector: "a company connector",
  credential: "a credential",
  device: "a computer",
  grid: "an imported grid",
  host: "a computer",
  model: "a model plan",
  policy: "the grid's policy",
  principal: "a person",
  realm: "this grid",
  research: "research",
  work: "a piece of work",
  workspace: "a desk",
}

/** What the last word of an action says happened. */
const HAPPENED: Record<string, string> = {
  accepted: "was accepted",
  acquired: "was taken in",
  added: "was added",
  admitted: "was let in",
  allowed: "was allowed",
  archived: "was put away",
  assigned: "was given to a person",
  adopted: "was taken over",
  cancelled: "was cancelled",
  closed: "was closed",
  committed: "was committed to this grid",
  created: "was created",
  decided: "was decided",
  disposed: "was thrown away",
  draining: "started emptying",
  drafted: "was written",
  egress: "changed what may leave it",
  enrolled: "joined this grid",
  ended: "ended",
  exported: "was written out",
  failed: "did not finish",
  forgotten: "was forgotten",
  frozen: "was frozen",
  granted: "was given a role",
  halted: "was stopped",
  imported: "was brought in",
  leased: "was given to a computer",
  lent: "was lent to an agent",
  lifecycle: "changed state",
  moving: "started moving to another computer",
  network: "changed what it may reach",
  offered: "offered a share of itself",
  opened: "was opened",
  ordered: "was ordered",
  parked: "was parked",
  pinned: "was pinned",
  placed: "was placed on a computer",
  published: "was published",
  queued: "was queued",
  quarantined: "was set aside",
  raised: "was raised",
  rebuilt: "was built again",
  recorded: "was recorded",
  refused: "was refused",
  removed: "was removed",
  reset: "was reset",
  retired: "was retired",
  retracted: "was withdrawn",
  revised: "was changed",
  revoked: "was taken back",
  rotated: "was replaced with a new value",
  sealed: "was sealed",
  sent: "was used on a request",
  submitted: "was sent in",
  suspended: "was suspended",
  unknown: "was not recognised",
  used: "was used",
  updated: "was changed",
  verified: "was checked",
  withdrawn: "was withdrawn",
}

/** The word in the middle, when there is one, says which part of the subject it was about. */
const PART: Record<string, string> = {
  access: "the way in to",
  admission: "the admission of",
  artifact: "a result of",
  commitment: "the commitment of",
  crossing: "a crossing of",
  dependencies: "what is needed by",
  finding: "a finding of",
  image: "the image of",
  placement: "the placement of",
  result: "a result of",
  scope: "the scope of",
  sessions: "a session of",
  source: "a source of",
  work: "a piece of work in",
}

/** The four shipped grids write their own single words rather than Grid Core's dotted tokens.
 *  One timeline reads them all, so they are said here too. */
const PRODUCT: Record<string, string> = {
  approve: "A request was agreed to.",
  change: "Something in this grid was changed.",
  deny: "A request was refused.",
  reveal: "The value of a credential was shown to a person.",
  signin: "Somebody signed in.",
  use: "A credential was used on a request.",
}

const capitalise = (text: string) => text.charAt(0).toUpperCase() + text.slice(1)

/** One action, as a sentence. An action nobody has words for still reads as English rather than
 *  as a machine token, and never shows the token itself. */
export function actionSentence(action: string): string {
  const own = PRODUCT[action.trim().toLowerCase()]
  if (own) return own
  const words = action.split(".").filter(Boolean)
  const subject = SUBJECT[words[0] ?? ""]
  const happened = HAPPENED[words[words.length - 1] ?? ""]
  if (!subject) return "Something in this grid changed."
  if (!happened) return `${capitalise(subject)} changed.`
  if (words.length >= 3) {
    const part = PART[words[1] ?? ""]
    if (part) return `${capitalise(part)} ${subject} ${happened}.`
  }
  return `${capitalise(subject)} ${happened}.`
}

/** A person's name, from whatever the record kept. An id nobody can put a name to is still said
 *  as a person rather than shown. */
export function personName(principal: string, people: ReadonlyMap<string, string>): string {
  const trimmed = principal.trim()
  if (!trimmed) return "Somebody"
  const known = people.get(trimmed)
  if (known) return known
  if (trimmed === "system" || trimmed === "engine") return "Yougori itself"
  // An id has no spaces and is long; a name is what a product already wrote.
  const looksLikeAnId = /^[a-z]+[-_][a-z0-9]{6,}$/i.test(trimmed) || /^[0-9a-f-]{16,}$/i.test(trimmed)
  return looksLikeAnId ? "Somebody who has since left" : trimmed
}

/** How long ago, in words. */
export function momentsAgo(seconds: number, now = Math.floor(Date.now() / 1000)): string {
  const since = Math.max(0, now - Math.floor(seconds))
  if (since < 60) return "just now"
  if (since < 3600) return `${Math.floor(since / 60)} min ago`
  if (since < 86_400) return `${Math.floor(since / 3600)} h ago`
  return `${Math.floor(since / 86_400)} days ago`
}

export interface TimelineLine {
  id: string
  when: string
  who: string
  what: string
  why: string
  refused: boolean
}

/** One line of the timeline: when, who, what and why, with nothing machine-made in it. */
export function timelineLine(
  event: { id: string; at: number; principal: string; action: string; decision: AuditDecision; reason?: string },
  people: ReadonlyMap<string, string>,
  now?: number,
): TimelineLine {
  return {
    id: event.id,
    when: momentsAgo(event.at, now),
    who: personName(event.principal, people),
    what: actionSentence(event.action),
    why: (event.reason ?? "").trim(),
    refused: event.decision === "refused",
  }
}
