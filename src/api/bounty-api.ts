import { call } from "@/api/grids/wire"
import { DESKTOP_ONLY } from "@/api/grids/profiles/shared"
import type { FieldPolicy } from "@/api/grids/redact"
import type { WorkerSetup, SwarmWorker } from "./swarm-api"

export interface ProjectTarget {
  kind: "source" | "web" | "api" | "url"
  setupCommand: string
  startCommand: string
  testCommand: string
  port: number
  healthPath: string
  installNetwork: boolean
  baseUrl: string
}
export interface ProjectImport {
  importId: string; name: string; fileCount: number; bytes: number
  files: string[]; excluded: string[]; suggestedTarget: ProjectTarget
}
export interface PrivatePreview {
  ticket: string
  policy: { title: string; objective: string; authorization: string; termsDigest: string; sourceRevision: string; target: ProjectTarget
    /** The host lets workers send this bounty's code to a GPU rented from an outside provider. */
    rentedGpu?: boolean }
}
export interface PrivateHost {
  name: string; invite: string; address: string
  bounty: { title: string; fileCount?: number }
  members: { id: string; name: string; state?: string }[]
  coordination?: { events: { sequence: number; workerId: string; type: string; body: { content?: string; observations?: string; summary?: string } }[]; reports: { id: string; title: string; state: string; document?: Record<string, unknown> }[] }
}
const desktop = DESKTOP_ONLY.closed
/** The policy a person reads before they agree, and the reports the workers write, are
 *  somebody else's words and are passed through exactly as they arrive. */
const policy: FieldPolicy = {
  opaque: ["policy", "target", "document", "coordination", "bounty"],
  keep: ["authorization", "objective", "title", "summary", "content", "observations"],
}
const dispatch = <T,>(action: string, request: Record<string, unknown> = {}) => call<T>("bounty_dispatch", { request: { action, ...request } }, { desktop, policy })
export const bountyApi = {
  /** Asks the desktop for a project folder or archive. One place, so a test can answer instead. */
  async choosePath(directory: boolean) {
    const { open: pick } = await import("@tauri-apps/plugin-dialog")
    const path = await pick({ directory, multiple: false, title: directory ? "Choose the project root folder" : "Choose a project ZIP or source file" })
    return typeof path === "string" ? path : null
  },
  inspect: (path: string) => dispatch<ProjectImport>("inspectProject", { path }),
  host: (request: Record<string, unknown>) => dispatch<PrivateHost & { preview: PrivatePreview }>("hostProject", request),
  connect: (invite: string, password: string, name: string) => dispatch<PrivatePreview>("connect", { invite, password, name }),
  localConnect: () => dispatch<PrivatePreview>("localConnect"),
  discard: (ticket: string) => dispatch("discardConnection", { ticket }),
  start: (preview: PrivatePreview, worker: WorkerSetup, budgetMinutes: number, reportPolicy: string) => dispatch<{ worker: SwarmWorker }>("startWorker", { ticket: preview.ticket, termsDigest: preview.policy.termsDigest, worker, budgetMinutes, reportPolicy, confirmed: true }),
  status: () => dispatch<{ host: PrivateHost | null }>("status"),
  suggestedAddress: () => call<string | null>("bounty_suggested_address", {}, { desktop }),
  removeMember: (memberId: string) => call("bounty_member_remove", { memberId }, { desktop }),
  remove: () => call("bounty_delete", {}, { desktop }),
}
