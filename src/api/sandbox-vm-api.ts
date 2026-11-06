import { run } from "@/api/platform-api"

/** The engine's restricted VM sandbox, the desktop command `sandbox_vm` (the answers of
 *  `yougori sandbox ...`): a pinned guest in a restricted VM, started with a staged copy of a
 *  folder; commands run on the guest's shell; what changed in the copy is reviewed against the
 *  folder, and only the files the user approves are written into it, exactly as reviewed.
 *
 *  The types follow the engine's serialized answers (`sandbox_vm::engine` and
 *  `sandbox_vm::workspace`) for the fields the desktop reads. Nothing is made up in a browser
 *  preview, and every refusal is the engine's own sentence. */

export type BootPhase = "starting" | "ready" | "stopping" | "ended"

export interface SandboxSummary {
  sandbox: string
  /** The launch transaction's state (`running`, `revoking`, `stopped`, ...). */
  state: string | null
  phase: BootPhase | null
  boot: number | null
  revocation: unknown | null
}

export interface AppliedFile {
  name: string
  applied: "added" | "modified" | "unchanged"
  /** Where the replaced original was kept, beneath the workspace's backup folder. */
  original_kept_at?: string
}

/** Where a staged workspace stands. A promotion cut short by an engine stop is found at the
 *  next start, undone and reported file by file (`promotion_undone`); a workspace an older
 *  engine left reads `promotion_interrupted`. */
export type WorkspaceState =
  | { state: "imported" }
  | { state: "reviewed"; review: string }
  | { state: "promoting"; review: string; approved: Record<string, string> }
  | { state: "promoted"; review: string; applied: AppliedFile[] }
  | { state: "promotion_interrupted"; review: string; applied: string[]; not_applied: string[]; changed: string[] }
  | { state: "promotion_undone"; review: string; restored: string[]; removed: string[]; not_applied: string[]; left: string[] }

export interface WorkspaceSummary {
  sandbox: string
  /** Whether the sandbox still runs, and so still reaches its workspace. */
  sandbox_running: boolean
  folder: string
  imported_at: string
  files: number
  /** How many credential locations (`.ssh`, `.env`, keys...) the import left out. */
  excluded: number
  /** How many entries were not imported (links, special files, files over the copy's 1 GiB). */
  skipped: number
  state: WorkspaceState
}

/** The lifetime supervisor beside the engine (`sandbox_vm::supervisor`): a separate,
 *  restricted process that holds every VM and ends a task sandbox's VM when Yougori quits or
 *  stops answering, so no VM outlives the engine unseen. */
export interface SupervisorView {
  running: boolean
  /** The sandboxes whose VMs it holds. */
  held: string[]
  /** How many supervisors this run started (more than one: one ended and was replaced). */
  starts: number
}

/** Who may reach a publication: its owner with its token address, or anyone on this computer. */
export type PublicationAudience = "owner" | "public"

/** One publication of a guest service (M14), as the engine shows it; never its token. */
export interface PublicationView {
  publication: number
  service: string
  port: number
  audience: PublicationAudience
  expires_in_seconds: number
  state: "active" | "response_budget_spent" | "expired" | "withdrawn" | "authority_ended" | "policy_changed" | "grant_revoked"
  response_budget: { limit_bytes: number; used_bytes: number; remaining_bytes: number }
  open_sessions: number
  sessions_admitted: number
}

/** A sandbox's declared services, its publications and their listeners. */
export interface SandboxPublications {
  declared: { service: string; port: number }[]
  publications: PublicationView[]
  released_bytes: number
  previews: { publication: number; service: string; audience: PublicationAudience; address: string; connections_served: number }[]
}

/** What publishing answers: the address, with the owner's token in it, shown once. */
export interface PublishResult {
  publication: number
  service: string
  guest_port: number
  audience: PublicationAudience
  url: string
  port: number
  expires_in_seconds: number
  response_budget_bytes: number
  released_so_far_bytes: number
  release_bound_bytes: number
}

/** One connection endpoint of a sandbox (M14): a name its programs reach on a port, and the
 *  service of another sandbox it is granted, if any. */
export interface ConnectionEndpointView {
  name: string
  port: number
  granted: { sandbox: string; service: string; state: "active" | "expired"; expires_in_seconds: number; budget_bytes: number; connections_opened: number } | null
}

/** A sandbox's connection endpoints, the grants other sandboxes hold to its services, and its
 *  open and refused connections. */
export interface SandboxConnections {
  endpoints: ConnectionEndpointView[]
  callers: { sandbox: string; endpoint: string; service: string; expires_in_seconds: number }[]
  open_connections: number
  refused_connections: number
}

/** One attempt of the connection drill, as the host counted it. */
export interface DrillCaseView {
  case: "ungranted" | "granted" | "other_service" | "revoked" | "expired" | "transitive" | "transitive_control"
  expected: string
  judged: string
  as_expected: boolean
  host_observed: { refused: number; admitted: number; callee_opens: number }
}

/** What the connection drill answers. */
export interface DrillReport {
  check: string
  cases: DrillCaseView[]
  shared_state: boolean | null
  as_expected: boolean
  doctor: string
  stopped: { sandbox: string; stopped: boolean; error?: string }[]
}

/** What a grant answers: where the sandbox's programs reach the service. */
export interface ConnectResult {
  endpoint: string
  to: string
  service: string
  address: string
  expires_in_seconds: number
  budget_bytes: number
}

export interface SandboxVmStatus {
  images?: { sandbox: string; id: string; command: number | null; outcome: { exit_code: number | null; output_text: string } | null }[]
  sandboxes: SandboxSummary[]
  workspaces: WorkspaceSummary[]
  /** Absent from an engine without the lifetime supervisor. */
  supervisor?: SupervisorView
  /** Each sandbox that declared services, by its id; absent from an older engine. */
  publications?: Record<string, SandboxPublications>
  /** Each sandbox with connection endpoints or callers, by its id; absent from an older engine. */
  connections?: Record<string, SandboxConnections>
}

/** A change the reviewer must see called out (`files::ReviewFlag`). */
export type ReviewFlag =
  | "executable_bit" | "executable_type" | "git_hook" | "git_configuration" | "ci_workflow"
  | "shell_init" | "build_script" | "package_lifecycle" | "tool_configuration"

export interface ReviewedFile {
  name: string
  change: "add" | "modify" | "unchanged"
  size_bytes: number
  /** The content key the promotion must find again. */
  content: string
  flags: ReviewFlag[]
  /** The folder's file is not what was imported: the user changed it meanwhile. */
  folder_changed_since_import: boolean
  /** A unified diff when both sides are small text; written by the guest, so untrusted. */
  diff: string | null
}

export interface WorkspaceReview {
  /** The digest a promotion must name; null when nothing changed. */
  review: string | null
  files: ReviewedFile[]
  /** Files deleted in the workspace: listed, never promoted. */
  deleted: string[]
  folder?: string
}

export interface Promotion {
  sandbox: string
  folder: string
  promoted: { applied: AppliedFile[]; manifest: string; authorization: string; audit_admission: number; audit_outcome: number | null }
}

export interface ExecResult {
  command: number
  exit_code: number | null
  /** The guest's own words, untrusted. */
  output_text: string
}

export type GridKind = "gpu" | "sandbox"
export interface GridSettings { installed: boolean; enabled: GridKind[] }

/** Uses the guest's bounded configuration command; never reads its admin token. */
async function gridSettings(sandbox: string, enabled?: readonly GridKind[]): Promise<GridSettings> {
  if (enabled && (new Set(enabled).size !== enabled.length || enabled.some(kind => kind !== "gpu" && kind !== "sandbox"))) {
    throw new Error("Choose GPU Grid and/or Sandbox Grid.")
  }
  const command = enabled === undefined ? "config" : `configure --resources ${enabled.length ? enabled.join(",") : "none"}`
  const result = await ask<ExecResult>("exec", { sandbox, input: `/run/yougori/bin/yougori-probe grid ${command}\n`, timeoutSeconds: 30, maxOutputBytes: 4096 })
  if (result.exit_code !== 0) throw new Error(result.output_text.trim() || "The VM could not update grid settings. Start a VM with the current guest tools and try again.")
  let value: GridSettings
  try { value = JSON.parse(result.output_text) as GridSettings } catch { throw new Error("The VM returned unreadable grid settings.") }
  if (!value || typeof value.installed !== "boolean" || !Array.isArray(value.enabled) || value.enabled.some(kind => kind !== "gpu" && kind !== "sandbox") || new Set(value.enabled).size !== value.enabled.length) {
    throw new Error("The VM returned invalid grid settings.")
  }
  return value
}

/** Formats the normalizer reads (`untrusted::DeclaredFormat`); the engine refuses the others. */
export type NormalizeFormat = "html" | "archive" | "plain_text"

export interface NormalizeRequest {
  /** The file's name in the sandbox's staged workspace. */
  file: string
  format: NormalizeFormat
  target?: "plain_text" | "markdown"
  /** Keep the raw bytes beside the result (the engine's default). */
  keepRaw?: boolean
}

/** A file of a staged workspace parsed in a throwaway VM (VM-W58): the text, its label and where
 *  it came from. Nothing about it is trusted. */
export interface NormalizedResult {
  job: string
  /** Always "format normalized; prompt injection may survive". */
  label: string
  stored: string
  output_text: string
  output_truncated: boolean
  took_ms: number
  artifact: {
    format: string
    output: { content: string; size_bytes: number }
    raw: { raw: "kept_separately" | "discarded" }
    provenance: { raw: string; normalizer: { name: string; version: string; recipe: string }; execution: string; boot: number }
  }
  normalizer_sandbox: { sandbox: string; copy_removed: boolean }
}

export interface SandboxVmCapabilities {
  gpu: { available: boolean; reason?: string; backend?: string; minimumMemoryGb?: number; shared?: boolean; requiresElevation?: boolean }
}

export interface LaunchRequest {
  /** Direct GPU access through the supported native VM backend. */
  gpu?: boolean
  /** Explicit outbound IPv4 NAT; omitted/false leaves the network adapter absent. */
  internet?: boolean
  /** All-port ingress is currently unsupported; true is explicitly refused. */
  incoming?: boolean
	/** Install the selected grid controller tools and their in-guest skill. */
	gridHosting?: ("gpu" | "sandbox")[]
  cpu?: number
  image?: string
  memoryGb?: number
  /** The folder whose staged copy the guest works on. */
  workspace?: string
  /** Route declarations for the sandbox's relay (names, hosts, operations, credential names). */
  routes?: unknown[]
  /** The guest services it may publish: `web=8080,api=3000`. */
  publish?: string
  /** The names its programs may reach other sandboxes' services by, once granted: `api=8080`. */
  connect?: string
}

export interface LaunchResult {
  sandbox: string
  launch_ms: number
  workspace: (Omit<WorkspaceSummary, "files" | "excluded" | "skipped" | "sandbox_running"> & { mounted_in_guest_at: string }) | null
}

/** The command is not in this build of Yougori, or this is not the desktop app. */
export class SandboxVmUnavailableError extends Error {
  constructor(message = "This build of Yougori can't run VM sandboxes.") {
    super(message)
    this.name = "SandboxVmUnavailableError"
  }
}

export const isSandboxVmUnavailable = (reason: unknown): reason is SandboxVmUnavailableError => reason instanceof SandboxVmUnavailableError

const MISSING = /^\s*command \S+ not (?:found|allowed)\b/i

/** Keeps the engine's sentence and reads a missing command as unavailable. */
export function sandboxVmError(reason: unknown): Error {
  if (reason instanceof SandboxVmUnavailableError) return reason
  const text = reason instanceof Error ? reason.message : typeof reason === "string" ? reason : ""
  if (MISSING.test(text)) return new SandboxVmUnavailableError()
  return new Error(text.trim() || "Yougori could not reach the VM sandbox service. Try again.")
}

async function ask<T>(action: string, params: Record<string, unknown> = {}): Promise<T> {
  try {
    return await run<T>("sandbox_vm", { action, params: { ...params, action } }, () => {
      throw new SandboxVmUnavailableError("VM sandboxes need Yougori Desktop.")
    })
  } catch (reason) {
    throw sandboxVmError(reason)
  }
}

export const sandboxVmApi = {
  gridSettings,
  hostAccess: (sandbox: string, operation = "status", fields: Record<string, unknown> = {}) =>
    ask<HostAccessView>("host_access", { sandbox, operation, ...fields }),
  remoteStatus: (run?: string) => ask<RemoteVmPage | RemoteVmRun>("remote", { operation: "status", ...(run ? { run } : {}) }),
  remoteHistory: (after?: string) => ask<RemoteVmPage>("remote", { operation: "status", archived: true, ...(after ? { after } : {}) }),
  remoteArchive: (run: string) => ask<RemoteVmRun>("remote", { operation: "archive", run }),
  remoteLaunch: (request: RemoteVmLaunch) => ask<RemoteVmRun>("remote", { operation: "launch", ...request }),
  remoteTrust: (connection: string, fingerprint: string) => ask<{ cleanup_pending: number; new_authority: false }>("remote", { operation: "trust", connection, accept_host_key: fingerprint }),
  remoteStop: (run: string) => ask<RemoteVmRun>("remote", { operation: "stop", run }),
  remoteReconcile: (run: string) => ask<RemoteVmRun>("remote", { operation: "reconcile", run }),
  remoteStart: (run: string, script: string) => ask<{ state: "started"; command: number }>("remote", {
    operation: "start", run, input_hex: Array.from(new TextEncoder().encode(script), byte => byte.toString(16).padStart(2, "0")).join(""),
  }),
  remoteOutcome: (run: string, command: number) => ask<RemoteVmOutcome>("remote", { operation: "outcome", run, command }),
  remoteCancel: (run: string, command: number) => ask<unknown>("remote", { operation: "cancel", run, command }),
  images: () => ask<VmImage[]>("image", { operation: "list" }),
  importImage: (layout: string, rootGb: number) => ask<VmImage>("image", { operation: "import", layout, rootGb, ownerSelected: true }),
  importRegistryImage: (reference: string, rootGb: number, authOrigin?: string, secret?: string) => ask<VmImage>("image", {
    operation: "import", reference, rootGb, ownerSelected: true, ...(authOrigin ? { authOrigin } : {}), ...(secret ? { secret } : {}),
  }),
  status: () => ask<SandboxVmStatus>("status"),
  capabilities: () => ask<SandboxVmCapabilities>("capabilities"),
  launch: (request: LaunchRequest) => ask<LaunchResult>("launch", { ...request }),
  exec: (sandbox: string, input: string, timeoutSeconds = 60) => ask<ExecResult>("exec", { sandbox, input, timeoutSeconds }),
  stop: (sandbox: string) => ask<unknown>("stop", { sandbox }),
  workspaces: () => ask<{ workspaces: WorkspaceSummary[] }>("workspace", { op: "list" }),
  review: (sandbox: string) => ask<WorkspaceReview>("workspace", { op: "review", sandbox }),
  /** Writes exactly the named files of review `review` into the folder. */
  promote: (sandbox: string, review: string, files: readonly string[]) => ask<Promotion>("workspace", { op: "promote", sandbox, review, files: [...files] }),
  discard: (sandbox: string) => ask<unknown>("workspace", { op: "discard", sandbox }),
  /** Serves a declared guest service of the sandbox on this computer's loopback. */
  publish: (sandbox: string, service: string, audience: PublicationAudience, minutes = 60) =>
    ask<PublishResult>("publish", { sandbox, service, audience, minutes }),
  /** Stops serving a publication; its connections close. */
  withdraw: (sandbox: string, publication: number) => ask<unknown>("withdraw", { sandbox, publication }),
  /** Lets the sandbox's endpoint reach a service another sandbox declared, until the grant ends. */
  connect: (sandbox: string, endpoint: string, to: string, service: string, minutes = 60) =>
    ask<ConnectResult>("connect", { sandbox, endpoint, to, service, minutes }),
  /** Withdraws what the endpoint was granted; its connections close. */
  disconnect: (sandbox: string, endpoint: string) => ask<unknown>("disconnect", { sandbox, endpoint }),
  /** The doctor's VM-CP-29 connection drill on three throwaway VMs of its own, stopped after. */
  drill: () => ask<DrillReport>("drill", { check: "vm-cp-29" }),
  /** Parses a file of the sandbox's staged workspace in a throwaway VM and keeps its text. */
  normalize: (sandbox: string, request: NormalizeRequest) => ask<NormalizedResult>("normalize", { sandbox, ...request }),
  /** One VM holding both running sandboxes: what it would be (nothing changes). */
  combinePreview: (sandbox: string, other: string, decisions: CombineDecisions) =>
    ask<CombinePreview>("combine", { operation: "preview", sandbox, with: other, decisions }),
  /** Applies exactly the previewed combination (its digest) with the owner's decisions. */
  combineStart: (sandbox: string, other: string, preview: string, decisions: CombineDecisions) =>
    ask<CombineOperation>("combine", { operation: "start", sandbox, with: other, preview, decisions, requestKey: `desktop-${preview.slice(0, 32)}` }),
  /** Keeps or removes the originals' workspaces after a healthy combine. */
  combineFinish: (id: string, originals: "keep" | "remove") => ask<CombineOperation>("combine", { operation: "finish", id, originals }),
  /** The desktop's folder picker; null when the person closed it. */
  async chooseFolder(): Promise<string | null> {
    const { open } = await import("@tauri-apps/plugin-dialog")
    const selected = await open({ directory: true, multiple: false, title: "Choose the folder the sandbox works on" })
    return typeof selected === "string" ? selected : null
  },
}

export interface CombineDecisions {
  layout: "separate" | "merged"
  keep: Record<string, "first" | "second">
  files: Record<string, "first" | "second">
  adopt: string[]
  imageProcess?: "once"
}
export interface CombinePreview {
  compatible: boolean
  reasons: string[]
  digest: string
  sources: { sandbox: string; os: Record<string, string>; image: string | null; memoryBytes: number; cpu: number; workspace: { folder: string; files: number; bytes: number } | null }[]
  combined: { params: { memoryGb: number; cpu: number }; layout: string; workspace: { path: string; sha256: string; bytes: number; from: string }[] }
  conflicts: { kind: string; key: string; decision: string | null }[]
  undecidedConflicts: number
  capacity: { fits: boolean | null; requiredBytes: number; releasedByOriginalsBytes: number }
  permissions: { lastingGrants: { grant: string; path: string; mode: HostAccessMode; folder: boolean; adopt: boolean }[] }
  notCarried: string[]
  transition: string
  trust: string
}
export interface CombineOperation {
  operation: string
  state: "copying" | "stopping-originals" | "launching" | "checking" | "healthy" | "rolled-back" | "failed" | "interrupted" | "finished"
  combined?: string
  failure?: string
}

export type HostAccessMode = "read" | "read_write"
export interface HostAccessView {
  policy: { treeVisible: boolean; askForAccess: boolean }
  requests: { id: string; sandbox: string; path: string; mode: HostAccessMode; state: string; grant: string | null }[]
  grants: { id: string; sandbox: string; path: string; folder: boolean; mode: HostAccessMode; duration: "once" | "always" }[]
  endpoint: string
  maxFileBytes: number
}

export interface RemoteVmLaunch {
  connection: string
  parent: string
  program: string
  endpoint: string
  engine_sha256: string
  accept_host_key?: string
  memory_mib?: number
  lifetime_seconds?: number
}
export interface RemoteVmRun {
  archived?: boolean
  run: string
  parent: string
  connection: string
  host: string
  port: number
  phase: "starting" | "ready" | "stopping" | "ended" | "creation_cancelled" | "unconfirmed"
  detail: string | null
  billing: "externally_managed"
  server_power_changed: false
  observation: { binding: { execution: string; boot: number }; accelerator: string } | null
}
export interface RemoteVmPage {
  runs: RemoteVmRun[]
  archived_count?: number
  archive_limit?: number
  archive_bytes?: number
  archive_byte_limit?: number
  next_after?: string | null
}
export interface RemoteVmOutcome {
  state: "running" | "completed"
  command: number
  source: "guest_report"
  outcome: { exit_code: number | null; output: string; end: { end: string } } | null
}

export interface VmImage {
  id: string
  error?: string
  source?: { repository?: string; reference?: string } | null
  image?: { root_bytes: number; process: { entrypoint: string[]; cmd: string[] } }
}

/** Untrusted text (guest output, file names, diffs) as it may be shown: control characters
 *  other than newline and tab, and invisible or direction-changing format characters, are shown
 *  as their code points, so nothing the guest wrote can hide text, reorder it or act on a
 *  terminal. */
export function visibleText(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/[\u0000-\u0008\u000B-\u001F\u007F-\u009F\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g,
    character => `\u27e8U+${character.codePointAt(0)!.toString(16).toUpperCase().padStart(4, "0")}\u27e9`)
}
