import { run } from "@/api/platform-api"
import type {
  Answer, Binding, CapabilityReport, ComposeSource, Diagnostic, EnvironmentsSource, NextAction, OperationProgress, OperationRef, ResourceAction, SetupDetailView, SetupDraft,
  SetupPermissions, SetupPlan, SetupSummary, SourceRef, ValidateResponse,
} from "./types"

/** The engine's setup commands. The engine plans, applies and records every setup; the desktop
 *  only asks and shows. A command this build does not have is said plainly, never filled in. */

/** The command is not in this build of Yougori, or this is not the desktop app. */
export class SetupUnavailableError extends Error {
  readonly command: string
  constructor(command: string) {
    super("Setups are not available in this build of Yougori yet.")
    this.name = "SetupUnavailableError"
    this.command = command
  }
}

/** A refusal or failure the engine explained: a stable code, the sentence to show, and the typed
 *  actions that may follow. */
export class SetupCommandError extends Error {
  readonly code: string
  readonly retryable: boolean
  readonly field: string | null
  readonly resource: string | null
  /** The operation it is about, such as the one already running when a setup is busy. */
  readonly operation: string | null
  readonly nextActions: NextAction[]
  constructor(message: string, detail: Partial<Pick<SetupCommandError, "code" | "retryable" | "field" | "resource" | "operation" | "nextActions">> = {}) {
    super(message)
    this.name = "SetupCommandError"
    this.code = detail.code ?? "failed"
    this.retryable = detail.retryable ?? false
    this.field = detail.field ?? null
    this.resource = detail.resource ?? null
    this.operation = detail.operation ?? null
    this.nextActions = detail.nextActions ?? []
  }
}

export const isUnavailable = (reason: unknown): reason is SetupUnavailableError => reason instanceof SetupUnavailableError

/** Tauri's own refusal of a command this build does not register, or does not allow. Only a
 *  plain string from Tauri is read this way, never a sentence the engine wrote. */
const MISSING = /^\s*command \S+ not (?:found|allowed)\b/i
/** Codes the engine uses for a part of setups this build does not have yet. */
const NOT_IN_THIS_BUILD = new Set(["planner_unavailable", "not_in_this_build", "draft_unavailable", "hub_source_unavailable"])
const AGAIN = "Yougori could not finish this. Try again."

const textOr = (value: unknown, fallback: string | null) => typeof value === "string" && value.trim() ? value : fallback

function explained(value: Partial<Record<keyof Diagnostic, unknown>> & { next?: unknown }, command: string): Error {
  const message = textOr(value.message, "") ?? ""
  const code = textOr(value.code, "failed") ?? "failed"
  if (NOT_IN_THIS_BUILD.has(code)) return new SetupUnavailableError(command)
  const actions = Array.isArray(value.nextActions) ? value.nextActions.filter((action): action is NextAction => Boolean(action) && typeof action === "object" && typeof (action as NextAction).kind === "string") : []
  return new SetupCommandError(message || AGAIN, {
    code,
    retryable: value.retryable === true,
    field: textOr(value.field, null),
    resource: textOr(value.resource, null),
    operation: textOr(value.operation, null),
    nextActions: actions,
  })
}

/** Turns whatever the engine rejected with into one of the two errors above. */
export function setupError(command: string, reason: unknown): Error {
  if (reason instanceof SetupUnavailableError || reason instanceof SetupCommandError) return reason
  if (typeof reason === "string") {
    if (MISSING.test(reason)) return new SetupUnavailableError(command)
    if (reason.trim().startsWith("{")) {
      try { return explained(JSON.parse(reason) as Record<string, unknown>, command) } catch { /* plain text after all */ }
    }
    return new SetupCommandError(reason || AGAIN)
  }
  if (reason instanceof Error) return MISSING.test(reason.message) ? new SetupUnavailableError(command) : new SetupCommandError(reason.message || AGAIN)
  if (reason && typeof reason === "object") return explained(reason as Record<string, unknown>, command)
  return new SetupCommandError(AGAIN)
}

async function call<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  try {
    return await run<T>(command, args, () => { throw new SetupUnavailableError(command) })
  } catch (reason) {
    throw setupError(command, reason)
  }
}

/** A plan for a new setup or for a change to one. Secret values are never part of it: only
 *  bindings that say which fields will get one when it is applied. */
export interface PlanAsk {
  source?: SourceRef | null
  name?: string
  answers?: Answer[]
  bindings?: Binding[]
  existingSetup?: string
  draft?: SetupDraft
  /** The drive this computer should store the setup's sandboxes on, as it spells it (`D:\`). Left
   *  out to use the usual drive. Only meant for a new setup: a sandbox can't move drives in place,
   *  so a change to a setup keeps the drive it is already on and this is ignored. */
  storageDrive?: string
}

/** The public answers a draft gives, as the planner reads them: each capability switched on or off
 *  (`capabilities.ID`), and each question answered by the template's own input id. Answers to
 *  questions of a capability that is off are left out; secrets are never answers. */
export function draftAnswers(draft: SetupDraft): Answer[] {
  const answers: Answer[] = []
  for (const [id, choice] of Object.entries(draft.capabilities)) answers.push({ field: `capabilities.${id}`, value: choice.selected })
  const secret = new Set((draft.questions ?? []).filter(question => question.kind === "secret").map(question => question.id))
  const off = new Set((draft.questions ?? []).filter(question => question.capability && !draft.capabilities[question.capability]?.selected).map(question => question.id))
  const given = new Map<string, unknown>()
  for (const choice of Object.values(draft.capabilities)) if (choice.selected) for (const [id, value] of Object.entries(choice.settings)) given.set(id, value)
  for (const [id, value] of Object.entries(draft.answers ?? {})) given.set(id, value)
  for (const [field, value] of given) if (!secret.has(field) && !off.has(field) && value !== "") answers.push({ field, value })
  return answers
}

/** The answers a draft gives that differ from `baseline`'s: what the person changed here. An
 *  update to a newer version sends only these, so the engine's merge keeps the rest of their
 *  choices and the new version's defaults apply where they never chose. */
export function changedAnswers(draft: SetupDraft, baseline: SetupDraft): Answer[] {
  const before = new Map(draftAnswers(baseline).map(answer => [answer.field, JSON.stringify(answer.value)]))
  return draftAnswers(draft).filter(answer => before.get(answer.field) !== JSON.stringify(answer.value))
}

/** Secret fields go to the engine by reference only; their values travel once, with the apply. */
export const secretBindings = (fields: string[]): Binding[] => [...fields].sort().map(field => ({ field, secretRef: `apply:${field}` }))

export const setupsApi = {
  async capabilities() {
    const result = await call<{ capabilities: CapabilityReport[] } | CapabilityReport[]>("setup_capabilities")
    return Array.isArray(result) ? result : result.capabilities
  },
  /** Checks a package from where it is (a folder, a Hub template, an installed setup, a Compose file
   *  to import, or source text), or a builder draft, and reads it back as a draft. */
  validate: (request: { draft: SetupDraft } | { source: SourceRef | ComposeSource | EnvironmentsSource | string }) => call<ValidateResponse>("setup_validate", { request }),
  /** Plans without changing anything. */
  plan: (request: PlanAsk) => call<SetupPlan>("setup_plan", { request }),
  /** Applies a reviewed plan. The digest makes the engine refuse a plan that changed since; the
   *  operation id, made once per click and sent again on a retry, makes a repeat join the same
   *  operation instead of starting a second one; the revision stops two writers racing. */
  apply: (plan: Pick<SetupPlan, "setupId" | "digest" | "baseRevision">, operationId: string, secrets?: Record<string, string>, consents?: string[]) =>
    call<OperationRef>("setup_apply", {
      request: {
        setupId: plan.setupId, planDigest: plan.digest, operationId, expectedRevision: plan.baseRevision,
        ...(secrets && Object.keys(secrets).length ? { secrets } : {}),
        // Only what the person ticked; anything left unticked is not done for them.
        ...(consents && consents.length ? { consents: [...new Set(consents)].sort() } : {}),
      },
    }),
  async list() {
    const result = await call<{ setups: SetupSummary[] } | SetupSummary[]>("setup_list")
    return Array.isArray(result) ? result : result.setups
  },
  async get(setupId: string) { return withResourceDetails(await call<SetupDetailView>("setup_get", { setupId })) },
  /** What a setup is allowed to do now: its template planned again with its own answers, read back as
   *  its review's lines. Reads only; never a secret value. `known` is false, with a reason, for a
   *  setup Yougori keeps no template for or one that no longer plans. */
  permissions: (setupId: string) => call<SetupPermissions>("setup_permissions", { setupId }),
  operation: (operationId: string, cursor?: number | null) => call<OperationProgress>("setup_operation", { operationId, cursor: cursor ?? null }),
  /** Agrees to the terms a review someone else hosts asks of this computer's worker, so the change
   *  that is waiting for that continues. `agreed` is the start of the terms' digest the engine
   *  named; terms that changed since are not agreed to. */
  async agreeToTerms(setupId: string, operationId: string, agreed: string): Promise<OperationRef> {
    const { planDigest } = await setupsApi.operation(operationId)
    if (!planDigest) throw new SetupUnavailableError("setup_operation")
    return setupsApi.apply({ setupId, digest: planDigest, baseRevision: 0 }, operationId, { accept_terms: agreed })
  },
  cancel: (operationId: string) => call<unknown>("setup_cancel", { operationId }),
  /** Start and stop apply at once; they keep data and leave borrowed resources alone. */
  action: (setupId: string, action: SetupLifecycleAction, extra: { operationId?: string; expectedRevision?: number | null } = {}) =>
    call<OperationRef>("setup_action", { request: { setupId, action, ...extra } }),
  /** Starts or stops one part of a setup, where the engine allows it. */
  resourceAction: (setupId: string, resource: string, action: "start" | "stop", extra: { operationId?: string; expectedRevision?: number | null } = {}) =>
    call<OperationRef>("setup_action", { request: { setupId, action, resource, ...extra } }),
  /** Removing or detaching one part asks for its review first, like removing a whole setup. */
  reviewResourceAction: (setupId: string, resource: string, action: "remove" | "detach", expectedRevision?: number | null) =>
    call<SetupPlan>("setup_action", { request: { setupId, action, resource, ...(expectedRevision != null ? { expectedRevision } : {}) } }),
  /** Taking an older grid into a setup: the review of what would be recorded. Nothing is moved,
   *  stopped or restarted by it; applying the review only starts keeping the record. */
  reviewAdoption: (setupId: string) => call<SetupPlan>("setup_action", { request: { setupId, action: "adopt" } }),
  /** Joining a Neo Grid or Sandbox Grid as this computer, from its invitation: the review of the
   *  new setup that does it. The invitation and password travel again only with the apply. */
  reviewJoin: (invitation: string) => call<SetupPlan>("setup_action", { request: { action: "join", invitation } }),
  /** Remove asks for its review first; applying that review is what removes anything. */
  reviewRemoval: (setupId: string, expectedRevision?: number | null) =>
    call<SetupPlan>("setup_action", { request: { setupId, action: "remove", ...(expectedRevision != null ? { expectedRevision } : {}) } }),
  /** The review for repairing a setup — making again the parts that are missing or have drifted, and
   *  touching nothing else. Two-step, like removal: this returns the plan to confirm; applying it
   *  goes through `apply`. */
  reviewRepair: (setupId: string, expectedRevision?: number | null) =>
    call<SetupPlan>("setup_action", { request: { setupId, action: "repair", ...(expectedRevision != null ? { expectedRevision } : {}) } }),
  /** The private outputs this setup has, such as a grid's invite: each key and label, never a
   *  value. A build without the command has none to show. */
  async privateOutputs(setupId: string): Promise<PrivateOutput[]> {
    const result = await call<{ private?: unknown }>("setup_reveal", { setupId })
    return (Array.isArray(result?.private) ? result.private : [])
      .filter((one): one is PrivateOutput => Boolean(one) && typeof (one as PrivateOutput).key === "string" && typeof (one as PrivateOutput).label === "string")
  },
  /** One private output's value, asked of the product again each time. Nothing keeps it: the
   *  caller shows it to the person and lets it go. */
  async reveal(setupId: string, key: string): Promise<string> {
    const result = await call<{ value?: unknown }>("setup_reveal", { setupId, key })
    if (typeof result?.value !== "string" || !result.value) throw new SetupCommandError("Yougori couldn't read that just now. Try again in a moment.", { code: "output_not_ready", retryable: true })
    return result.value
  },
  /** The results a setup's jobs handed back, newest first. Reads only; no path of this computer. */
  async artifacts(setupId: string): Promise<SetupArtifact[]> {
    const result = await call<{ artifacts?: unknown }>("setup_artifacts", { setupId })
    return (Array.isArray(result?.artifacts) ? result.artifacts : []).filter((one): one is SetupArtifact => Boolean(one) && typeof (one as SetupArtifact).id === "string")
  },
  /** Copies one result into a folder the person chose, checked against its checksum. */
  saveArtifact: (setupId: string, artifactId: string, folder: string) => call<{ path: string; bytes: number; sha256: string }>("setup_artifact_save", { setupId, artifactId, folder }),
  /** What a job's last attempts printed, oldest first. */
  async jobLogs(setupId: string, resource: string): Promise<JobAttemptLog[]> {
    const result = await call<{ attempts?: unknown }>("setup_job_logs", { setupId, resource })
    return (Array.isArray(result?.attempts) ? result.attempts : []).filter((one): one is JobAttemptLog => Boolean(one) && typeof (one as JobAttemptLog).text === "string")
  },
  /** Settles a job nobody knows the outcome of, after the person looked at what it did. */
  settleJob: (setupId: string, resource: string, outcome: "succeeded" | "failed" | "run_again") => call<{ state: string }>("setup_job_settle", { setupId, resource, outcome }),
  /** What its hosted models were used for this month, from each cloud model gateway's own count. */
  async usage(setupId: string): Promise<ModelUsage[]> {
    const result = await call<{ models?: unknown }>("setup_usage", { setupId })
    return (Array.isArray(result?.models) ? result.models : []).filter((one): one is ModelUsage => Boolean(one) && typeof (one as ModelUsage).resource === "string")
  },
  /** What one of the setup's own sandboxes printed lately: its last 64 KB. */
  sandboxLogs: (setupId: string, resource: string) => call<{ text: string; truncated: boolean }>("setup_sandbox_logs", { setupId, resource }),
}

/** One result a setup's job handed back. */
export interface SetupArtifact {
  id: string
  /** The job it came from, by its id in the setup, when the setup still has it. */
  resource: string | null
  name: string
  bytes: number
  sha256: string
  recordedAt: number
  /** Retention removed its bytes; the record stays. */
  removed: boolean
  removedBecause?: string | null
}

/** One cloud model's use this month, as its gateway counts it. */
export interface ModelUsage {
  resource: string
  model?: string | null
  month?: string | null
  spentUsd?: number | null
  budgetUsd?: number | null
  requests?: number | null
  refused?: number | null
  unpriced?: number | null
  freeOnly?: boolean
  error?: string
}

/** The end of what one attempt of a job printed. */
export interface JobAttemptLog { attempt: string; at: number | null; text: string }

/** A private output a setup has, by the template's own key and label. */
export interface PrivateOutput { key: string; label: string }

const RESOURCE_ACTIONS = new Set(["start", "stop", "remove", "detach", "logs"])
const textIn = (value: unknown) => typeof value === "string" && value.trim() ? value.trim() : null

/** Folds the engine's per-resource extras into each resource, keeping only fields of the shape
 *  this app reads: what it needs, where it runs, what it connects or publishes, what can be done. */
export function withResourceDetails(detail: SetupDetailView): SetupDetailView {
  const extras = detail.resourceDetails && typeof detail.resourceDetails === "object" ? detail.resourceDetails as Record<string, Record<string, unknown> | null> : {}
  return {
    ...detail,
    resources: (detail.resources ?? []).map(resource => {
      const extra = extras[resource.resourceId]
      if (!extra || typeof extra !== "object") return resource
      const place = textIn(extra.placement)
      const link = extra.connection && typeof extra.connection === "object" ? extra.connection as Record<string, unknown> : null
      const from = textIn(link?.from), to = textIn(link?.to)
      const ports = Array.isArray(link?.ports) ? link!.ports.filter((port): port is number => Number.isInteger(port)) : []
      const seconds = (value: unknown) => typeof value === "number" && Number.isFinite(value) ? value : null
      return {
        ...resource,
        dependsOn: Array.isArray(extra.dependsOn) ? extra.dependsOn.filter((id): id is string => typeof id === "string") : resource.dependsOn,
        placement: place ? place.charAt(0).toUpperCase() + place.slice(1) : resource.placement,
        ...(resource.kind === "vm_sandbox" && extra.remoteVm === true ? { remoteVm: true } : {}),
        connection: from && to ? { from, to, ports, direction: link!.direction === "both" ? "both" as const : "one_way" as const } : resource.connection,
        exposure: !from && to && Number.isInteger(link?.port) ? { to, port: link!.port as number, access: textIn(link?.access) ?? "lan" } : resource.exposure,
        actions: Array.isArray(extra.actions) ? extra.actions.filter((action): action is ResourceAction => typeof action === "string" && RESOURCE_ACTIONS.has(action)) : resource.actions,
        // When Yougori last looked at this part, and when it was last seen well (null when the last
        // look didn't find it well): shown in the parts table so a quiet drift isn't a surprise.
        lastCheckedAt: "lastCheckedAt" in extra ? seconds(extra.lastCheckedAt) : resource.lastCheckedAt,
        lastHealthyAt: "lastHealthyAt" in extra ? seconds(extra.lastHealthyAt) : resource.lastHealthyAt,
      }
    }),
  }
}

export type SetupLifecycleAction = "start" | "stop" | "refresh" | "reconcile" | "retry" | "repair"

/** One id per click: `op-` and a random part, well under the engine's 128 characters, sent again
 *  unchanged when the same click is retried. */
export function newOperationId() {
  const random = typeof crypto !== "undefined" && "randomUUID" in crypto ? crypto.randomUUID() : `${Date.now().toString(36)}-${Math.random().toString(36).slice(2)}`
  return `op-${random}`.replace(/[^A-Za-z0-9._:-]/g, "-").slice(0, 128)
}

export const errorText = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)
