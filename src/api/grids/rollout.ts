/** Moving the four shipped products onto Grid Core, as a page would read it.
 *
 *  There is one backend door for all of this, `grids_rollout`, and it takes a verb: status,
 *  rehearse, backup, observe, advance and back are the ones this screen uses. Each verb answers
 *  with `{ said, found }`, where `said` is a sentence for a command line and `found` is the shape.
 *  This client never shows `said`, because the engine builds it with absolute paths in it; it
 *  reads `found` and writes its own sentences, so nothing a person sees is a path, a realm's own
 *  identifier, a vault entry's name or a dotted token.
 *
 *  The stages, the four products and which of them has a bridge are compile-time facts of this
 *  build, the same on every computer, so they are held here as constants rather than asked for.
 *  They mirror `grid/src/core/compat/rollout.rs` and the frozen register in `frozen.rs`. The
 *  live state that is per-deployment, where each profile stands and what a rehearsal or a
 *  comparison found, is read through the door.
 */
import { call } from "@/api/grids/wire"
import { safePath } from "@/api/grids/redact"

// ---- The eight stages ----

export type RolloutStage =
  | "freeze" | "survey" | "backup" | "rehearsal" | "import" | "observation" | "cutover" | "retire"

export interface StageInfo {
  word: RolloutStage
  /** Where this stage sits in the order, counting from zero. */
  order: number
  /** A person's word for the stage. */
  title: string
  /** What reaching this stage changes, in a sentence. */
  changes: string
  /** How it is undone, in a sentence. */
  undoneBy: string
  /** How long that undo stays available. */
  keptFor: string
}

/** The eight stages, in order, with a person's word for each and what it does. The sentences are
 *  this build's own, not the engine's, because the engine's carry paths. */
export const ROLLOUT_STAGES: readonly StageInfo[] = [
  {
    word: "freeze", order: 0, title: "Frozen",
    changes: "The record shapes are written down, and three of the four products refuse a record written by a newer build.",
    undoneBy: "Nothing has to be undone: the check only ever refuses to read a newer record.",
    keptFor: "For ever.",
  },
  {
    word: "survey", order: 1, title: "Inventory taken",
    changes: "One inventory file is written on this computer. It is sent nowhere and carries no names, no addresses and no paths.",
    undoneBy: "Delete the file.",
    keptFor: "For ever.",
  },
  {
    word: "backup", order: 2, title: "Backed up",
    changes: "Every product's record is copied into one stamped folder and read back.",
    undoneBy: "Delete the folder, once its keeping time has run out.",
    keptFor: "Until the backup's keeping time runs out.",
  },
  {
    word: "rehearsal", order: 3, title: "Rehearsed",
    changes: "The whole move is run on copies and undone again. Nothing it holds changes.",
    undoneBy: "Delete the scratch folder, which is kept only when something failed so the failure can be read.",
    keptFor: "Not needed: a rehearsal changes nothing.",
  },
  {
    word: "import", order: 4, title: "Imported beside the hub",
    changes: "A realm is built beside the hub and the hub still owns everything. No command in this build performs this yet.",
    undoneBy: "Take the import back out, then delete the realm and its key. No command in this build does either half yet.",
    keptFor: "Until the profile is enabled.",
  },
  {
    word: "observation", order: 5, title: "Observing",
    changes: "Both paths answer the same questions and every difference is written down instead of being applied.",
    undoneBy: "Stop comparing, and if the pilot is ending undo the import as well.",
    keptFor: "Until the profile is enabled.",
  },
  {
    word: "cutover", order: 6, title: "Enabled",
    changes: "The product reads the realm instead of the hub. This is the only stage that changes what the product does.",
    undoneBy: "Point the product back at its hub, which is still exactly the grid it was.",
    keptFor: "The keeping time, which is ninety days unless a longer one was asked for.",
  },
  {
    word: "retire", order: 7, title: "Old record retired",
    changes: "The old record is moved aside, with its keeping time running.",
    undoneBy: "Put the record back, which is what unretire does.",
    keptFor: "The same keeping time.",
  },
]

export function stageInfo(word: RolloutStage): StageInfo {
  return ROLLOUT_STAGES.find(stage => stage.word === word) ?? ROLLOUT_STAGES[0]!
}

export function nextStage(word: RolloutStage): StageInfo | null {
  return ROLLOUT_STAGES[stageInfo(word).order + 1] ?? null
}

export function previousStage(word: RolloutStage): StageInfo | null {
  const order = stageInfo(word).order
  return order > 0 ? ROLLOUT_STAGES[order - 1] ?? null : null
}

// ---- The four shipped products ----

export type RolloutProfile = "models" | "workspaces" | "research" | "credentials"
export type ProductWord = "neo" | "sandbox" | "swarm" | "access"

export interface ProductMeta {
  profile: RolloutProfile
  word: ProductWord
  /** The product's name as a person knows it. */
  product: string
  /** Whether anything can bring this product's grid across today. */
  hasBridge: boolean
  /** When nothing can, why not, in words. Null when it has a bridge. */
  bridgeReason: string | null
}

/** The four products, in the order the rollout moves them, with whether each has a bridge today.
 *  All four have one, which mirrors the frozen register. The shape still carries a no-bridge
 *  reason so that a product added later without one is shown as unavailable rather than hidden. */
export const ROLLOUT_PRODUCTS: readonly ProductMeta[] = [
  { profile: "models", word: "neo", product: "Closed Neo Grid", hasBridge: true, bridgeReason: null },
  { profile: "workspaces", word: "sandbox", product: "Sandbox Grid", hasBridge: true, bridgeReason: null },
  { profile: "research", word: "swarm", product: "Swarm Mining", hasBridge: true, bridgeReason: null },
  { profile: "credentials", word: "access", product: "Access Grid", hasBridge: true, bridgeReason: null },
]

export function productOf(profile: RolloutProfile): ProductMeta {
  return ROLLOUT_PRODUCTS.find(meta => meta.profile === profile) ?? ROLLOUT_PRODUCTS[0]!
}

// ---- Where each profile stands ----

export interface ProfileStanding {
  profile: RolloutProfile
  stage: RolloutStage
  since: number
  keptUntil: number | null
  notes: string[]
}

export interface RolloutStanding {
  version: number
  updatedAt: number
  profiles: ProfileStanding[]
}

// ---- What a rehearsal found ----

/** One kind of thing an import would create, and how many. */
export interface MoveCount { kind: string; count: number }

export interface ProductRehearsal {
  profile: RolloutProfile | null
  product: string
  /** What the import would create, by kind and count. */
  moves: MoveCount[]
  historyVerified: boolean
  returnedClean: boolean
  /** What the realm would not let an undo delete, named before the trial ran. */
  kept: string[]
  /** Why the import would refuse, when it would, already in a person's words. */
  refusal: string | null
}

export interface RehearsalReading {
  at: number
  products: ProductRehearsal[]
  /** What would have stopped the move, in words. */
  refusals: string[]
  /** What could not be rehearsed at all, and why not. */
  notRehearsed: string[]
  notes: string[]
}

// ---- What a comparison found ----

export type Band = "agrees" | "noted" | "stop" | "unobserved"
export type RolloutHeading = "plans" | "assignments" | "permissions" | "workloads" | "audit" | "answers"

/** A person's phrase for each of the six questions both paths are asked. */
export const HEADING_PHRASE: Record<RolloutHeading, string> = {
  plans: "what the administrator asked the grid to do",
  assignments: "which computer each thing runs on",
  permissions: "what each person may do",
  workloads: "what is running, and in which state",
  audit: "what each side recorded",
  answers: "what somebody asking the product would be told",
}

export interface ObservationLine {
  heading: RolloutHeading
  headingPhrase: string
  band: Band
  /** A person's sentence describing the agreement or what differs. Never an identifier. */
  detail: string
}

export interface ProfileObservation {
  profile: RolloutProfile
  product: string
  at: number
  /** Whether every question that could be asked agreed. */
  agree: boolean
  agreed: number
  noted: number
  stopped: number
  unobserved: number
  lines: ObservationLine[]
}

export interface ObservationReading {
  at: number
  profiles: ProfileObservation[]
}

// ---- An honest gap ----

/** What is not reachable from this screen yet, named with the command that does it today. The
 *  engine has no verb that returns a stored result without re-running the work, so the last
 *  rehearsal and the stored comparison can only be read by running a fresh one here. */
export interface NotWired {
  wired: false
  reason: string
  /** The command line that does it today. */
  line: string
}

function notWired(what: string, line: string): NotWired {
  return {
    wired: false,
    reason: `Reading ${what} without re-running it is not wired to this screen yet.`,
    line,
  }
}

// ---- Turning the engine's words into a person's ----

/** A token a grid minted rather than a word somebody chose: a name and a tail of at least four
 *  hex, which is how `compat::observe::an_identifier` recognises one. Folded to a plain noun so
 *  no realm identifier or minted name is ever rendered. */
const IDENTIFIER = /\S*-[0-9a-f]{4,}\b/gi

function withoutIdentifiers(text: string): string {
  return text.replace(IDENTIFIER, "something it named")
}

/** Every sentence this build surfaces from the engine goes through here first: a home folder is
 *  folded away and a minted identifier becomes a plain noun. */
export function humanSentence(text: string): string {
  return withoutIdentifiers(safePath(text)).replace(/\s+/g, " ").trim()
}

function capitalise(text: string): string {
  return text ? text.charAt(0).toUpperCase() + text.slice(1) : text
}

// ---- The raw shapes the door answers with ----

interface Said<T> { said: string; found: T }
interface RawProfileState { profile: RolloutProfile; stage: RolloutStage; since: number; keptUntil: number | null; notes?: string[] }
interface RawRollout { rollout: number; updatedAt: number; profiles: RawProfileState[] }
interface RawTrial {
  product: string
  wrote: Array<[string, number]>
  auditVerified: boolean
  returnedClean: boolean
  differences?: string[]
  kept?: string[]
  refusal: string | null
}
interface RawReport {
  takenAt: number
  trials: RawTrial[]
  refusals?: string[]
  notRehearsed?: string[]
  notes?: string[]
}
interface RawVerdict { verdict: Band; because?: string }
interface RawObservation { at: number; profile: RolloutProfile; heading: RolloutHeading; subject: string; hub: string; core: string; verdict: RawVerdict }
interface RawPass { profile: RolloutProfile; at: number; observations: RawObservation[] }

function toStanding(raw: RawRollout): RolloutStanding {
  return {
    version: raw.rollout,
    updatedAt: raw.updatedAt,
    profiles: raw.profiles.map(state => ({
      profile: state.profile,
      stage: state.stage,
      since: state.since,
      keptUntil: state.keptUntil ?? null,
      notes: (state.notes ?? []).map(humanSentence),
    })),
  }
}

function profileByProductName(name: string): RolloutProfile | null {
  return ROLLOUT_PRODUCTS.find(meta => meta.product === name)?.profile ?? null
}

function toRehearsalReading(report: RawReport): RehearsalReading {
  return {
    at: report.takenAt,
    products: report.trials.map(trial => ({
      profile: profileByProductName(trial.product),
      product: trial.product,
      moves: trial.wrote.map(([kind, count]) => ({ kind, count })),
      historyVerified: trial.auditVerified,
      returnedClean: trial.returnedClean,
      kept: trial.kept ?? [],
      refusal: trial.refusal ? humanSentence(trial.refusal) : null,
    })),
    refusals: (report.refusals ?? []).map(humanSentence),
    notRehearsed: (report.notRehearsed ?? []).map(humanSentence),
    notes: (report.notes ?? []).map(humanSentence),
  }
}

function toObservationLine(observation: RawObservation): ObservationLine {
  const band = observation.verdict.verdict
  const because = observation.verdict.because ?? ""
  let detail: string
  if (band === "agrees") {
    detail = "Both paths agree."
  } else if (band === "unobserved") {
    detail = because ? capitalise(humanSentence(because)) : "This question cannot be asked from a record on this computer."
  } else if (band === "noted") {
    detail = because ? capitalise(humanSentence(because)) : "The two paths differ in a way the rollout allows."
  } else if (observation.heading === "assignments") {
    // A placement difference is always between two identifiers, so it is said in words rather
    // than by naming either computer.
    detail = "The two paths would place it on different computers, and any difference in placement stops the rollout."
  } else {
    detail = because ? capitalise(humanSentence(because)) : "The two paths disagree here, so the rollout stops."
  }
  return { heading: observation.heading, headingPhrase: HEADING_PHRASE[observation.heading], band, detail }
}

function toObservationReading(passes: RawPass[]): ObservationReading {
  return {
    at: passes[0]?.at ?? 0,
    profiles: passes.map(pass => {
      const count = (band: Band) => pass.observations.filter(observation => observation.verdict.verdict === band).length
      const stopped = count("stop")
      const noted = count("noted")
      return {
        profile: pass.profile,
        product: productOf(pass.profile).product,
        at: pass.at,
        agree: stopped === 0 && noted === 0,
        agreed: count("agrees"),
        noted,
        stopped,
        unobserved: count("unobserved"),
        lines: pass.observations.map(toObservationLine),
      }
    }),
  }
}

// ---- The one door ----

const DESKTOP = "Open Yougori Desktop to move this computer's grids onto Grid Core"

function door<T>(verb: string, request: Record<string, unknown> = {}, browser?: () => T): Promise<Said<T>> {
  return call<Said<T>>(
    "grids_rollout",
    { request: { do: verb, ...request } },
    { desktop: DESKTOP, policy: { paths: ["said"] }, browser: browser ? () => ({ said: "", found: browser() }) : undefined },
  )
}

/** What this computer looks like before anything has been read: every profile frozen, which is
 *  where they all start. Used only when there is no desktop app to ask. */
function freshStanding(): RawRollout {
  return {
    rollout: 1,
    updatedAt: 0,
    profiles: ROLLOUT_PRODUCTS.map(meta => ({ profile: meta.profile, stage: "freeze", since: 0, keptUntil: null, notes: [] })),
  }
}

export const rollout = {
  /** The four products, in the order they move, with whether each has a bridge. @local */
  products: (): readonly ProductMeta[] => ROLLOUT_PRODUCTS,
  /** The eight stages, in order. @local */
  stages: (): readonly StageInfo[] => ROLLOUT_STAGES,

  /** Where every profile stands. Reads a file or returns every profile frozen; writes nothing.
   *  @command grids_rollout status */
  status: async (): Promise<RolloutStanding> => toStanding((await door<RawRollout>("status", {}, freshStanding)).found),

  /** Runs the whole move on copies and reports what it would do. Copies every record and realm,
   *  runs each import, verifies the history, rolls it back and compares. Nothing it holds changes.
   *  @command grids_rollout rehearse */
  rehearse: async (): Promise<RehearsalReading> => toRehearsalReading((await door<RawReport>("rehearse")).found),

  /** Copies every product's record into a stamped folder on this computer and reads it back.
   *  @command grids_rollout backup */
  backUp: async (stage: RolloutStage = "backup"): Promise<void> => { await door<unknown>("backup", { stage }) },

  /** Asks both paths the same questions on a throwaway copy and writes down every difference.
   *  Nothing is applied. @command grids_rollout observe */
  observe: async (): Promise<ObservationReading> => toObservationReading((await door<RawPass[]>("observe")).found),

  /** Moves one profile on by exactly one stage, or says why it may not. @command grids_rollout advance */
  advance: async (profile: RolloutProfile): Promise<RolloutStanding> => toStanding((await door<RawRollout>("advance", { profile })).found),

  /** Takes one profile back by exactly one stage. @command grids_rollout back */
  rollBack: async (profile: RolloutProfile): Promise<RolloutStanding> => toStanding((await door<RawRollout>("back", { profile })).found),

  /** Not wired yet: the engine has no verb that returns the most recent stored rehearsal, so the
   *  only way to see one is to run a fresh rehearsal here. @local */
  lastRehearsal: (): NotWired => notWired("the last rehearsal", "yougori rollout rehearse"),

  /** Not wired yet: the engine's coverage verb returns aggregate counts rather than the stored
   *  comparison line by line, so the readout here is from a fresh comparison. @local */
  lastObservations: (): NotWired => notWired("the stored comparison", "yougori rollout observe"),
}
