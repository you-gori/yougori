import { call } from "@/api/grids/wire"
import { DESKTOP_ONLY, decodeUtf8 as decode, readInvite as read } from "@/api/grids/profiles/shared"
import type { DeleteWhen, GridClosing } from "@/lib/grid-closing"

/** How far a model has come on its way to ready; bytes in the phases that count them. */
export interface GridProgress {
  phase: "preparing" | "installing" | "downloading" | "verifying" | "loading" | "queued" | "freeing_memory" | string
  done: number
  total: number
  /** Bytes per second while downloading. */
  rate: number
}

/** What a computer says about the model the grid gave it. */
export interface GridModelReport {
  model: string
  state: string
  reason?: string
  progress?: GridProgress
}

/** A computer that joined the hub this computer runs. */
export interface GridComputer {
  id: string
  name: string
  platform: string
  joinedAt: string
  capable: boolean
  /** The admin left it out: no model and no work until brought back. */
  excluded: boolean
  planId: string | null
  jobs: number
  online: boolean
  lastSeenSeconds: number | null
  address: string | null
  appVersion: string | null
  running: number
  models: GridModelReport[]
}

/** Which computers a plan runs on: a share of all of them, a share of those nobody picked, or the picked ones. */
export type GridScope = { kind: "all" } | { kind: "remaining" } | { kind: "computers"; members: string[] }

/** A model the admin asks computers to run. */
export interface GridPlan {
  id: string
  model: string
  quant: string | null
  percent: number
  rules: string
  computers: number
  target: number
  ready: number
  scope: GridScope
  /** The picked computers' names, for a plan on picked computers. */
  names: string[]
}

/** Where a new plan runs: the picked computers, or a share of all or of the remaining ones. */
export type GridPlanTarget = { kind: "computers"; members: string[] } | { kind: "all" | "remaining"; percent: number }

export type SwarmStrategy = "plan" | "mixture"

/** A team of models an app calls as the model `swarm/NAME`; one call runs on several computers. */
export interface GridHarness {
  id: string
  name: string
  /** What apps call: `swarm/NAME`. */
  model: string
  strategy: SwarmStrategy
  lead: string
  workers: string[]
  /** How many computers work on one call at once. */
  computers: number
  /** Plan: tasks per round. Mixture: answers per layer. */
  tasks: number
  /** Plan: rounds. Mixture: layers. */
  rounds: number
  /** Every model it needs has a computer ready now. */
  ready: boolean
}

/** One worker's part of a swarm call, as the trace records it. */
export interface SwarmPart {
  title: string
  brief?: string
  model: string
  computer?: string | null
  seconds: number
  answer?: string
  error?: string
}

export interface SwarmTrace {
  harness: string
  strategy: SwarmStrategy
  rounds?: Array<{ round: number; planner?: string | null; done?: boolean; note?: string; tasks?: SwarmPart[] }>
  layers?: Array<{ layer: number; answers: SwarmPart[] }>
  final?: { model: string; computer?: string | null }
  computersUsed: string[]
  seconds: number
}

export interface SwarmRun {
  model: string
  answer: string
  trace: SwarmTrace
  usage: { promptTokens: number; completionTokens: number }
}

export interface NewHarness {
  name: string
  strategy: SwarmStrategy
  lead: string
  workers: string[]
  computers: number
  rounds: number
}

export interface GridHub {
  id: string
  name: string
  address: string
  port: number
  url: string
  fingerprint: string
  createdAt: string
  computers: { total: number; capable: number; online: number }
  plans: GridPlan[]
  planWarning: string | null
  members: GridComputer[]
  queue: { waiting: number; running: number }
  harnesses: GridHarness[]
  tunnel?: { kind: "quick" | "domain"; domain: string | null; url: string | null; connected: boolean; error: string | null }
  /** Shared with company computers to join; it carries no secret. */
  invite?: string
  /** Its admin is deleting it: paused until a time, then gone. */
  closing?: GridClosing | null
}

/** This computer's place in a grid someone else hosts. */
export interface GridMembership {
  gridId: string
  grid: string
  hub: string
  fingerprint: string
  memberId: string
  joinedAt: string
  connected: boolean
  error: string | null
  capable: boolean | null
  backend: string | null
  assignment: { model?: string; quant?: string | null } | null
  rules: string | null
  state: string | null
  reason: string | null
  progress?: GridProgress | null
  jobs: number
  failures: number
  lastError: string | null
  /** Its admin scheduled the grid for deletion at this time; until then it is paused. */
  pausedUntil?: number | null
  /** The hub has not answered since this time. */
  unreachableSince?: number | null
}

export interface GridStatus {
  hub: GridHub | null
  hubError: string | null
  member: GridMembership | null
  memberError: string | null
  message?: string
}

export type GridReach = "network" | "quick"

/** What a change reports; the page always reads the status again afterwards. */
export interface GridResult { message?: string; warning?: string | null }

/** A rented NeoCloud GPU pod: one in the grid this computer hosts, or one that could join it. */
export interface GridRentedGpu {
  environmentId: string
  memberId?: string
  name: string
  gpu: string | null
  gpuCount: number | null
  /** RunPod's price while the pod runs, in US dollars an hour. */
  hourlyUsd: number | null
  /** The pod's own state in NeoCloud, such as Running or Stopped. */
  podState: string | null
  /** What the grid's stand-in is doing for it: available, busy, outside_schedule, preparing,
   *  loading, starting, stopping, stopped, idle or error. Absent for a pod that is not in the grid. */
  state?: string
  reason?: string
  model?: string | null
  jobs?: number
}

/** The rented GPUs of the grid this computer hosts, and the pods that could join it. */
export interface GridRentedGpus {
  /** This computer runs the grid now. Pods listed while it does not are stopped, and stay to remove. */
  hosting: boolean
  /** The most rented GPUs one grid takes. */
  max: number
  /** What the grid's running rented GPUs cost together, in US dollars an hour. */
  hourlyUsd: number
  /** Running pods whose price NeoCloud did not record, which `hourlyUsd` leaves out. */
  unpriced?: number
  members: GridRentedGpu[]
  candidates: GridRentedGpu[]
  /** Why rented GPUs last left the grid on their own, if they did. */
  notice: string | null
  /** How the latest stops went, a failure included until NeoCloud confirms the pod stopped. */
  notices: { at: number; text: string; warning: boolean }[]
}

export const noRentedGpus: GridRentedGpus = { hosting: false, max: 8, hourlyUsd: 0, members: [], candidates: [], notice: null, notices: [] }

const empty: GridStatus = { hub: null, hubError: null, member: null, memberError: null }
const desktop = DESKTOP_ONLY.models

/** The Closed Neo Grid's own surface, unchanged. Every type above is declared here and nowhere
 *  else, because several of them hold what Grid Core has no room for yet: a joined computer's
 *  model assignment, its progress and the replies it has served.
 *
 *  What did change is underneath: each method now goes through the one call path in
 *  `@/api/grids/wire`, so a refusal arrives typed, a call carries a name that ties it to the
 *  others in the same action, and the redaction pass sees the answer. The command, the argument
 *  names, the answers and this object's own shape are exactly what they were, so a page or a
 *  browser test that replaces a method here still works. `grids.models` is the same four grids
 *  in Grid Core's words, for a page that has moved over. */
export const gridApi = {
  status: () => call<GridStatus>("grid_status", {}, { browser: () => empty, desktop }),
  suggestedAddress: () => call<string | null>("grid_suggested_address", {}, { browser: () => null, desktop }),
  create: (name: string, address: string, password: string, reach: GridReach) =>
    call<GridStatus>("grid_create", { name, address, password, tunnel: reach === "quick" ? "quick" : null }, { desktop }),
  join: (invite: string, password?: string) => call<GridStatus>("grid_join", { invite, password: password || null }, { desktop }),
  leave: () => call<GridResult>("grid_leave", {}, { desktop }),
  /** `later` pauses the grid for three days (restorable), `now` deletes it, `forget` stops waiting for computers. */
  delete: (when: DeleteWhen = "later") => call<GridResult>("grid_delete", { when }, { desktop }),
  restore: () => call<GridResult>("grid_restore", {}, { desktop }),
  addPlan: (model: string, target: GridPlanTarget, quant?: string) => call<GridResult>("grid_plan_add", target.kind === "computers"
    ? { model, computers: target.members, scope: null, percent: null, quant: quant || null }
    : { model, scope: target.kind, percent: target.percent, computers: null, quant: quant || null }, { desktop }),
  removePlan: (planId: string) => call<GridResult>("grid_plan_remove", { planId }, { desktop }),
  removeComputer: (memberId: string) => call<GridResult>("grid_member_remove", { memberId }, { desktop }),
  excludeComputer: (memberId: string) => call<GridResult>("grid_member_exclude", { memberId }, { desktop }),
  includeComputer: (memberId: string) => call<GridResult>("grid_member_include", { memberId }, { desktop }),
  rentedGpus: () => call<GridRentedGpus>("grid_neocloud_status", {}, { browser: () => noRentedGpus, desktop }),
  addRentedGpu: (environmentId: string) => call<GridResult>("grid_neocloud_add", { environmentId }, { desktop }),
  removeRentedGpu: (environmentId: string) => call<GridResult>("grid_neocloud_remove", { environmentId }, { desktop }),
  stopRentedGpus: () => call<GridResult>("grid_neocloud_stop_all", {}, { desktop }),
  addHarness: (harness: NewHarness) => call<GridResult & { missing?: string[] }>("grid_swarm_add", { ...harness, tasks: null }, { desktop }),
  removeHarness: (harnessId: string) => call<GridResult>("grid_swarm_remove", { harnessId }, { desktop }),
  runHarness: (harness: string, prompt: string) => call<SwarmRun>("grid_swarm_run", { harness, prompt }, { desktop, policy: { opaque: ["trace"], keep: ["answer"] } }),
}

/** `atob` gives one character per byte; an invite's JSON is UTF-8, so a company name with letters
 *  outside ASCII must be decoded as bytes, not read as Latin-1. */
export function decodeUtf8(bytes: string): string {
  return decode(bytes)
}

/** The company an invite names, read locally so a mistyped code is caught before joining. */
export function readInvite(code: string): { company: string; address: string; fingerprint: string } | null {
  return read("models", code)
}
