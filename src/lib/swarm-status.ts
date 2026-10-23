import type { SwarmWorker } from "@/api/swarm-api"

export interface WorkerStatus {
  text: string
  tone: "ok" | "busy" | "wait" | "off" | "error"
  /** The worker can take a bounty now, so offers are worth showing. */
  waiting: boolean
}

/** The four words the status sentence needs. `SwarmWorker` already satisfies it, and so does a
 *  research job on the Grids tab, which is the same worker in Grid Core's words. */
export interface WorkerWords {
  state: string
  stage: string
  summary: string
  error: string | null
}

/** What a bounty worker is doing, in words a person understands without the docs. */
export function workerStatus(worker: WorkerWords): WorkerStatus {
  if (worker.error) return { text: worker.error, tone: "error", waiting: false }
  switch (worker.state) {
    case "preparing": return { text: worker.stage || "Setting up the worker", tone: "wait", waiting: false }
    case "preparing_bounty": return { text: worker.stage || "Starting the bounty", tone: "wait", waiting: false }
    case "awaiting_review": return { text: "Report ready for your review", tone: "busy", waiting: false }
    case "running": return { text: worker.stage || "Working on a bounty", tone: "busy", waiting: false }
    case "ready":
    case "ready_waiting":
    case "waiting": return { text: "Ready · waiting for a bounty to accept", tone: "wait", waiting: true }
    case "paused": return { text: "Paused", tone: "off", waiting: false }
    case "stopped": return { text: worker.summary || "Stopped", tone: "off", waiting: false }
    default: return { text: worker.stage || worker.state, tone: "wait", waiting: false }
  }
}

/** Whether a worker is in the middle of something, so leaving it needs a confirm. */
export function workerBusy(worker: SwarmWorker): boolean {
  return ["running", "awaiting_review", "preparing_bounty", "preparing"].includes(worker.state)
}
