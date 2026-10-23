/** The research profile: Swarm Mining and the closed bounty a company hosts, in Grid Core's
 *  words. A research realm is a realm of its own, holding its own keys and its own permissions.
 *
 *  Nothing here starts anything on its own: every method is one request, and the test for this
 *  file mocks the transport so no worker is ever created, paused or run by a test.
 *
 *  What a person consented to has to stay readable. A bounty's authorization sentence, its
 *  scope, its objective and the service rules are rendered in the dialog where somebody ticks
 *  "I am authorized to test this target", so the redaction policy keeps them exactly as they
 *  arrived, and a bounty's terms and a report's document are not walked at all.
 */
import type { PrivateHost, PrivatePreview, ProjectImport } from "@/api/bounty-api"
import { noRentedGpus, type RentedGpuStop, type SwarmActivity, type SwarmBounty, type SwarmMessage, type SwarmOffer, type SwarmPrompts, type SwarmRentedGpus, type SwarmReport, type SwarmWorker, type WorkerSetup } from "@/api/swarm-api"
import { toResearchJob } from "@/api/grids/compat"
import { mentions, paginate, where, type Page, type PageRequest, type ResearchFilter } from "@/api/grids/page"
import { DESKTOP_ONLY, type Done } from "@/api/grids/profiles/shared"
import type { FieldPolicy } from "@/api/grids/redact"
import { call } from "@/api/grids/wire"
import type { ResearchJob, ResearchStatus, ResearchStep } from "@/api/grids/types"

/** Somebody else's documents, and the words a person has to read before they agree to
 *  anything. Neither is touched. */
const POLICY: FieldPolicy = {
  opaque: ["terms", "target", "document", "trace", "bounty", "policy", "coordination"],
  keep: ["authorization", "scope", "objective", "summary", "text", "answer", "content", "observations", "reason", "error"],
}

/** Every Swarm Mining action goes through one engine command with an `action`. */
const swarm = <T>(action: string, request: Record<string, unknown> = {}) =>
  call<T>("swarm_dispatch", { request: { action, ...request } }, { desktop: DESKTOP_ONLY.research, policy: POLICY })

/** And every closed bounty action through another. */
const closedCall = <T>(action: string, request: Record<string, unknown> = {}) =>
  call<T>("bounty_dispatch", { request: { action, ...request } }, { desktop: DESKTOP_ONLY.closed, policy: POLICY })

/** This computer is its own research realm today: the workers run here and there is no hub. */
const REALM = "research"

export interface ResearchSteps { job: ResearchJob; steps: ResearchStep[]; latest: number }

export const research = {
  /** This computer's worker prompts. @command swarm_dispatch */
  prompts: () => swarm<SwarmPrompts>("promptsGet"),
  /** @command swarm_dispatch */
  savePrompts: (values: Partial<Record<"agents" | "rules" | "liveTask" | "sourceTask" | "chatReply", string>>) =>
    swarm<SwarmPrompts>("promptsSet", values),
  /** @command swarm_dispatch */
  resetPrompts: () => swarm<SwarmPrompts>("promptsReset"),
  /** Every research job on this computer. @command swarm_dispatch */
  status: async (): Promise<ResearchStatus> => {
    const answer = await swarm<{ workers: SwarmWorker[] }>("workers")
    return {
      profile: "research",
      hub: null, hubError: null, member: null, memberError: null, me: null,
      jobs: (answer.workers ?? []).map(worker => toResearchJob(worker, REALM)),
    }
  },

  /** The research jobs, filtered and paged. Asking for no page asks for all of them.
   *  @command swarm_dispatch */
  jobs: async (filter: ResearchFilter = {}, page: PageRequest = {}): Promise<Page<ResearchJob>> => {
    const { jobs } = await research.status()
    const tests = [
      (job: ResearchJob) => !filter.stage || (job.stage !== null && filter.stage.includes(job.stage)),
      (job: ResearchJob) => !filter.state || filter.state.includes(job.state),
      (job: ResearchJob) => mentions(filter.search, job.name, job.model, job.summary),
    ]
    return paginate(where(jobs, tests), page, job => job.id)
  },

  /** One job. @command swarm_dispatch */
  job: (jobId: string) =>
    swarm<{ worker: SwarmWorker }>("status", { workerId: jobId }).then(answer => toResearchJob(answer.worker, REALM)),

  /** Progress since a line you have already seen. A cursor read, not a stream: the engine keeps
   *  a ring of lines and this asks for what came after `after`. @command swarm_dispatch */
  steps: (jobId: string, after = 0): Promise<ResearchSteps> =>
    swarm<{ worker: SwarmWorker; events?: SwarmActivity[]; latest?: number }>("activity", { workerId: jobId, after })
      .then(answer => ({ job: toResearchJob(answer.worker, REALM), steps: answer.events ?? [], latest: answer.latest ?? after })),

  /** Checks a model and this computer's resources before anything is created.
   *  @command swarm_dispatch */
  check: (model: string, quant?: string) =>
    swarm<{ host: unknown; preflight: unknown; minimumResources: { cpu: number; memoryGb: number } }>("doctor", { model, quant: quant || null, preflightModel: true }),

  /** Creates a job that joins the public board. @command swarm_dispatch */
  prepare: (setup: WorkerSetup) =>
    swarm<{ worker: SwarmWorker }>("prepare", { ...setup, gpu: setup.gpu ?? null, quant: setup.quant || null }).then(answer => toResearchJob(answer.worker, REALM)),

  /** @command swarm_dispatch */
  pause: (jobId: string) => swarm<{ worker?: SwarmWorker }>("pause", { workerId: jobId }),
  /** @command swarm_dispatch */
  resume: (jobId: string, budgetMinutes = 30) => swarm<{ worker?: SwarmWorker }>("resume", { workerId: jobId, budgetMinutes }),
  /** Leaves the bounty it holds, and keeps the job. @command swarm_dispatch */
  stop: (jobId: string) => swarm<{ worker?: SwarmWorker }>("leave", { workerId: jobId }),
  /** @command swarm_dispatch */
  remove: (jobId: string) => swarm<{ removed?: boolean }>("delete", { workerId: jobId, confirmed: true }),
  /** Clears a paused job's activity and attempt count; reports and receipts stay. @command swarm_dispatch */
  clearHistory: (jobId: string) => swarm<{ worker?: SwarmWorker }>("clearHistory", { workerId: jobId }),

  /** What the job and the person have said to each other. @command swarm_dispatch */
  messages: async (jobId: string, after = 0, page: PageRequest = {}): Promise<Page<SwarmMessage>> => {
    const answer = await swarm<{ messages: SwarmMessage[] }>("messages", { workerId: jobId, after })
    return paginate(answer.messages ?? [], page, message => message.id)
  },

  /** @command swarm_dispatch */
  say: (jobId: string, content: string) => swarm<Done>("chat", { workerId: jobId, content }),

  /** What it wrote up. The document is somebody's findings and is never touched.
   *  @command swarm_dispatch */
  reports: async (jobId: string, page: PageRequest = {}): Promise<Page<SwarmReport>> => {
    const answer = await swarm<{ reports: SwarmReport[] }>("reports", { workerId: jobId })
    return paginate(answer.reports ?? [], page, report => report.id)
  },

  /** @command swarm_dispatch */
  submitReport: (jobId: string, reportId: string) => swarm<Done>("submitReport", { workerId: jobId, reportId, confirmed: true }),

  /** The bounties this job is offered, with the terms each one needs. @command swarm_dispatch */
  offers: (jobId: string) => swarm<{ offers?: SwarmOffer[] }>("offers", { workerId: jobId }).then(answer => answer.offers ?? []),

  /** @command swarm_dispatch */
  skipOffer: (jobId: string, offerId: string) => swarm<{ skipped: boolean }>("skip", { workerId: jobId, offerId }),

  /** Accepts a bounty. The person must be authorized to test the target, and this is what
   *  records that they said so, with the digests of exactly what they agreed to.
   *  @command swarm_dispatch */
  accept: (jobId: string, offer: SwarmOffer, budgetMinutes: number, reportPolicy = "review") =>
    swarm<{ worker: SwarmWorker }>("accept", {
      workerId: jobId,
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

  /** Jobs whose model runs on a rented NeoCloud GPU, what each GPU costs, and how recent stops
   *  went. @command swarm_dispatch */
  rentedGpus: () => call<SwarmRentedGpus>("swarm_dispatch", { request: { action: "rentedGpus" } }, { desktop: DESKTOP_ONLY.research, policy: POLICY, browser: () => noRentedGpus }),
  /** Pauses the job and stops its rented GPU, which ends the GPU's billing. @command swarm_dispatch */
  stopRentedGpu: (jobId: string) => swarm<RentedGpuStop>("stopRentedGpu", { workerId: jobId }),
  /** Stops every job's rented GPU. @command swarm_dispatch */
  stopRentedGpus: () => swarm<RentedGpuStop>("stopRentedGpus"),

  /** The public bounty board. @command swarm_dispatch */
  board: () => swarm<{ bounties?: SwarmBounty[] }>("bounties").then(answer => answer.bounties ?? []),

  /** A bounty a company hosts on its own computer, for its own source. */
  closed: {
    /** @command bounty_dispatch */
    status: () => closedCall<{ host: PrivateHost | null }>("status"),
    /** @command bounty_suggested_address */
    suggestedAddress: () => call<string | null>("bounty_suggested_address", {}, { browser: () => null, desktop: DESKTOP_ONLY.closed }),
    /** Reads a project folder or archive and says what it found. @command bounty_dispatch */
    inspect: (path: string) => closedCall<ProjectImport>("inspectProject", { path }),
    /** @command bounty_dispatch */
    publish: (request: Record<string, unknown>) => closedCall<PrivateHost & { preview: PrivatePreview }>("hostProject", request),
    /** @command bounty_dispatch */
    connect: (invite: string, password: string, name: string) => closedCall<PrivatePreview>("connect", { invite, password, name }),
    /** @command bounty_dispatch */
    connectHere: () => closedCall<PrivatePreview>("localConnect"),
    /** @command bounty_dispatch */
    discard: (ticket: string) => closedCall<Done>("discardConnection", { ticket }),
    /** Begins work on a connected closed bounty. @command bounty_dispatch */
    begin: (preview: PrivatePreview, setup: WorkerSetup, budgetMinutes: number, reportPolicy: string) =>
      closedCall<{ worker: SwarmWorker }>("startWorker", { ticket: preview.ticket, termsDigest: preview.policy.termsDigest, worker: setup, budgetMinutes, reportPolicy, confirmed: true }),
    /** Works a source given on this computer alone. @command swarm_dispatch */
    start: (jobId: string, content: string) => swarm<{ worker?: SwarmWorker }>("practiceStart", { workerId: jobId, content }),
    /** @command swarm_dispatch */
    stop: (jobId: string) => swarm<{ stopped: boolean }>("practiceStop", { workerId: jobId }),
    /** @command bounty_member_remove */
    removeHunter: (memberId: string) => call<Done>("bounty_member_remove", { memberId }, { desktop: DESKTOP_ONLY.closed }),
    /** @command bounty_delete */
    unpublish: () => call<Done>("bounty_delete", {}, { desktop: DESKTOP_ONLY.closed }),
    /** Asks the desktop for a project folder or archive. One place, so a test can answer
     *  instead of opening a window. @local */
    async choosePath(directory: boolean) {
      const { open: pick } = await import("@tauri-apps/plugin-dialog")
      const path = await pick({ directory, multiple: false, title: directory ? "Choose the project root folder" : "Choose a project ZIP or source file" })
      return typeof path === "string" ? path : null
    },
  },
}
