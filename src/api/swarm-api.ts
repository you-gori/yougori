import { call } from "@/api/grids/wire"
import { DESKTOP_ONLY } from "@/api/grids/profiles/shared"
import type { FieldPolicy } from "@/api/grids/redact"

/** A bounty worker on this computer: it joins the Yougori board and works one bounty at a time. */
export interface SwarmWorker {
  id: string
  name: string
  model: string
  /** preparing · ready_waiting · waiting · ready · running · preparing_bounty · paused · stopped */
  state: string
  stage: string
  gpu: string
  resources: { cpu?: number; memoryGb?: number }
  workspaceQuotaGb: number
  keepResident: boolean
  error: string | null
  summary: string
  completedAttempts?: number
  bountyId?: string | null
  quant?: string | null
  networkMode?: "public" | "closed"
  reviewReports?: string[]
  createdAt: number
  restored?: boolean
  /** The NeoCloud pod whose rented GPU runs this worker's model. Absent when it runs here. */
  rentedGpu?: string
  /** An explicitly configured API relay for a private worker in a development build. */
  developmentApiModel?: boolean
}

/** One line in a worker's activity log. */
export interface SwarmActivity {
  seq: number
  /** A full, replaceable snapshot of one message as the model writes it. */
  streamId?: string
  streaming?: boolean
  at?: number
  kind?: string
  text?: string
  stage?: string
  detail?: string
  tool?: string
  target?: string
  status?: string
}

/** A bounty offered to a worker; accepting it needs the person's explicit authorization. */
export interface SwarmOffer {
  id: string
  termsVersion: number | string
  termsDigest: string
  sourceRevision?: string
  authorizationDigest?: string
  bounty: {
    id: string
    title?: string
    summary?: string
    publisher?: string
    companyName?: string
    reward?: string | { amount?: string; currency?: string }
    scope?: string
    authorization?: string
    terms?: { inScope?: string; objective?: string; authorization?: Record<string, unknown>; target?: Record<string, unknown>; setupCommand?: string; testCommand?: string; sourceDigest?: string; serviceRules?: { version?: string | number; digest?: string; text?: string } }
  }
}

/** A bounty on the public Yougori board. */
export interface SwarmBounty {
  id: string
  title?: string
  summary?: string
  publisher?: string
  reward?: string
  scope?: string
}

const desktop = DESKTOP_ONLY.research

/** A bounty's terms, a worker's trace and a report's document belong to somebody else and are
 *  passed through exactly as they arrive. So are the words a person reads before they agree to
 *  anything: the authorization, the scope, the objective and the service rules. */
const policy: FieldPolicy = {
  opaque: ["terms", "target", "document", "trace", "bounty", "policy", "coordination"],
  keep: ["authorization", "scope", "objective", "summary", "text", "answer", "content", "observations", "reason", "error"],
}

/** Every Swarm Mining action goes through one engine command with an `action`. */
function dispatch<T>(action: string, request: Record<string, unknown> = {}): Promise<T> {
  return call<T>("swarm_dispatch", { request: { action, ...request } }, { desktop, policy })
}

export interface WorkerSetup {
  name: string
  model: string
  gpu?: string | null
  quant?: string | null
  /** `storageGb` is how much room the model's runtime and weights may use, and `storageDrive` is
   *  which drive they go on. Both are checked against that drive's free space before the worker is
   *  created, so a model that will not fit is refused while it can still be changed. */
  resources?: { cpu: number; memoryGb?: number; storageGb?: number; storageDrive?: string }
  workspaceQuotaGb?: number
  keepResident?: boolean
  /** Runs the model on this rented NeoCloud pod instead of this computer. Only a closed bounty
   *  whose host allowed rented GPUs takes one. */
  rentedGpu?: string
}

/** A worker whose model runs on a rented NeoCloud GPU, with what that GPU costs and does. */
export interface SwarmRentedWorker {
  workerId: string
  workerName: string
  workerState: string
  environmentId: string
  name: string | null
  gpu: string | null
  gpuCount: number | null
  hourlyUsd: number | null
  /** NeoCloud's own word for the pod: Running, Starting, Stopping, Stopped, Deleted. */
  podState: string
  /** Running or still powering on, so billed by the hour. */
  billing: boolean
}

/** A rented pod a new worker could run its model on: running, and serving nothing else. */
export interface SwarmRentedPod {
  environmentId: string
  name: string
  gpu: string
  gpuCount: number
  hourlyUsd: number
  podState: string
}

export interface SwarmRentedGpus {
  workers: SwarmRentedWorker[]
  candidates: SwarmRentedPod[]
  /** What the workers' rented GPUs cost together, while they run. */
  hourlyUsd: number
  /** Running pods whose price NeoCloud did not record, which `hourlyUsd` leaves out. */
  unpriced?: number
  /** How the latest stops went, a failure included until it is fixed. */
  notices: { at: number; text: string; warning: boolean }[]
}

export const noRentedGpus: SwarmRentedGpus = { workers: [], candidates: [], hourlyUsd: 0, notices: [] }

/** What stopping a rented GPU did. A warning means the pod may still be billing. */
export interface RentedGpuStop { message?: string; warning?: string }

export interface SwarmMessage { id: string; sequence: number; role: string; content: string }
export interface SwarmReport { id: string; title: string; state: string; document?: Record<string, unknown> }
export const swarmApi = {
  messages: (workerId: string, after = 0) => dispatch<{ messages: SwarmMessage[] }>("messages", { workerId, after }),
  chat: (workerId: string, content: string) => dispatch("chat", { workerId, content }),
  reports: (workerId: string) => dispatch<{ reports: SwarmReport[] }>("reports", { workerId }),
  submitReport: (workerId: string, reportId: string) => dispatch("submitReport", { workerId, reportId, confirmed: true }),
  workers: () => dispatch<{ workers: SwarmWorker[] }>("workers").then(result => result.workers),
  status: (workerId: string) => dispatch<{ worker: SwarmWorker }>("status", { workerId }).then(result => result.worker),
  activity: (workerId: string, after = 0) => dispatch<{ worker: SwarmWorker; events?: SwarmActivity[]; latest?: number; next?: number }>("activity", { workerId, after }),
  /** Checks a model and this computer's resources before a worker is created. */
  doctor: (model: string, quant?: string) => dispatch<{ host: unknown; preflight: unknown; minimumResources: { cpu: number; memoryGb: number } }>("doctor", { model, quant: quant || null, preflightModel: true }),
  /** Create a worker that joins the public board. */
  prepare: (setup: WorkerSetup) => dispatch<{ worker: SwarmWorker }>("prepare", { ...setup, gpu: setup.gpu ?? null, quant: setup.quant || null }).then(result => result.worker),
  pause: (workerId: string) => dispatch<{ worker: SwarmWorker }>("pause", { workerId }),
  resume: (workerId: string, budgetMinutes = 30) => dispatch<{ worker: SwarmWorker }>("resume", { workerId, budgetMinutes }),
  leave: (workerId: string) => dispatch<{ worker?: SwarmWorker }>("leave", { workerId }),
  remove: (workerId: string) => dispatch<{ removed?: boolean }>("delete", { workerId, confirmed: true }),
  /** Clears a paused worker's activity and attempt count; reports, receipts and its bounty stay. */
  clearHistory: (workerId: string) => dispatch<{ worker: SwarmWorker }>("clearHistory", { workerId }),

  /** The bounties this worker is offered, with the terms each one needs. */
  offers: (workerId: string) => dispatch<{ offers: SwarmOffer[] }>("offers", { workerId }).then(result => result.offers ?? []),
  skipOffer: (workerId: string, offerId: string) => dispatch<{ skipped: boolean }>("skip", { workerId, offerId }),
  /** Accepts a bounty. The person must be authorized to test the target; this records that consent. */
  accept: (workerId: string, offer: SwarmOffer, budgetMinutes: number, reportPolicy = "review") => dispatch<{ worker: SwarmWorker }>("accept", {
    workerId,
    bountyId: offer.bounty.id,
    termsVersion: offer.termsVersion,
    termsDigest: offer.termsDigest,
    sourceRevision: offer.sourceRevision,
    sourceDigest: offer.bounty.terms?.sourceDigest,
    authorizationAccepted: true,
    authorizationDigest: offer.authorizationDigest,
    directPaymentAccepted: true,
    rulesAccepted: true,
    rulesVersion: offer.bounty.terms?.serviceRules?.version,
    rulesDigest: offer.bounty.terms?.serviceRules?.digest,
    reportPolicy,
    budgetMinutes,
    confirmed: true,
  }),

  /** The public Yougori bounty board. */
  bounties: () => dispatch<{ bounties?: SwarmBounty[] }>("bounties").then(result => result.bounties ?? []),

  /** Workers whose model runs on a rented GPU, what each GPU costs, and how recent stops went. */
  rentedGpus: () => call<SwarmRentedGpus>("swarm_dispatch", { request: { action: "rentedGpus" } }, { desktop, policy, browser: () => noRentedGpus }),
  /** Pauses this worker and stops its rented GPU, which ends the GPU's billing. */
  stopRentedGpu: (workerId: string) => dispatch<RentedGpuStop>("stopRentedGpu", { workerId }),
  /** Stops every worker's rented GPU. */
  stopRentedGpus: () => dispatch<RentedGpuStop>("stopRentedGpus"),

  /** A closed bounty: a worker works a source you give it, on this computer only. */
  practiceStart: (workerId: string, content: string) => dispatch<{ worker?: SwarmWorker }>("practiceStart", { workerId, content }),
  practiceStop: (workerId: string) => dispatch<{ stopped: boolean }>("practiceStop", { workerId }),

  /** The editable prompts and guardrails every worker uses. Changes take effect on the next turn. */
  prompts: () => dispatch<SwarmPrompts>("promptsGet"),
  /** Saves one or more prompt overrides; an empty string restores that prompt to its default. */
  savePrompts: (changes: Partial<Record<keyof SwarmPrompts, string>>) => dispatch<SwarmPrompts>("promptsSet", changes),
  /** Clears every override, returning all prompts to their built-in defaults. */
  resetPrompts: () => dispatch<SwarmPrompts>("promptsReset"),
}

/** One editable prompt: its current text, the built-in default, and whether it has been overridden. */
export interface SwarmPrompt {
  value: string
  default: string
  custom: boolean
}

/** The worker's editable prompts and guardrails, read from disk at runtime. */
export interface SwarmPrompts {
  /** The system rules / guardrails handed to the agent every turn. */
  rules: SwarmPrompt
  /** The per-turn instruction for a live-URL target. Placeholders: {url}, {category}. */
  liveTask: SwarmPrompt
  /** The per-turn instruction for a source-review target. Placeholder: {component}. */
  sourceTask: SwarmPrompt
  /** The agent's core operating instructions (its system prompt inside the sandbox). */
  agents: SwarmPrompt
  /** The system prompt used when you message a private worker directly. */
  chatReply: SwarmPrompt
  /** Which placeholders each template may contain. */
  placeholders: { liveTask: string[]; sourceTask: string[] }
}
