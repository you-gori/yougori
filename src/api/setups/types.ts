/** The shapes the desktop's setup screens read.
 *
 *  Everything the engine and desktop exchange comes from `./contract`, the mirror of the engine's
 *  own message types. The few shapes below are the builder's side of calls the contract does not
 *  describe yet (checking a draft and showing a plan). They are read defensively: a part the
 *  engine does not send is simply not shown.
 */
export type {
  Answer, ApplyRequest, Binding, CapabilityAvailability, CapabilityAvailabilityReport, CapabilityDescriptor, CapabilityGroup,
  CapabilityHealth, CapabilityStatus, Diagnostic, GridProfile, InstanceState, NextAction, OperationEvent, OperationProgress,
  OperationRef, OperationState, Output, PlanRequest, ResourceKind, ResourceRef, SetupAction, SetupDetail, SetupSummary, Severity,
  SourceRef,
} from "./contract"
import type { CapabilityAvailabilityReport, CapabilityGroup, Diagnostic, OperationState, ResourceRef, SetupDetail, SourceRef } from "./contract"

/** `setup_capabilities` for one capability: the contract's report, and whether this engine can
 *  already set up the resources it needs. */
export interface CapabilityReport extends CapabilityAvailabilityReport {
  engineReady?: boolean
  engineReason?: string | null
}

/** One recent operation on a setup, newest first in `SetupDetailView.operations`. */
export interface OperationBrief {
  operationId: string
  kind: string
  state: OperationState
  createdAt: number
  completedAt?: number | null
  error?: Diagnostic | null
}

/** A resource as `setup_get` shows it: the contract's reference, plus how it fits with the
 *  others when the engine says. Every extra is optional; a part it does not send is not drawn. */
export type ResourceView = ResourceRef & {
  /** The resources it waits for. Needing one is not a connection to it. */
  dependsOn?: string[]
  /** Where it runs or lives, in words, such as "This computer". */
  placement?: string | null
  /** A delegated remote VM, with remote commands and externally managed server cost. */
  remoteVm?: boolean
  /** For a connection: which way it goes and on which ports. */
  connection?: { from: string; to: string; ports?: number[]; direction?: "one_way" | "both" } | null
  /** For a publication: the part it makes reachable, on which port, and how. */
  exposure?: { to: string; port: number; access: string } | null
  /** What can be done to this one resource now. A borrowed one is only ever detached. */
  actions?: ResourceAction[]
  /** When Yougori last looked at this part, in seconds since the epoch, or null if never. */
  lastCheckedAt?: number | null
  /** When it was last seen well (there and as the setup wants it), in seconds, or null when the
   *  last look didn't find it well. Never guessed: a missing or drifted part has none. */
  lastHealthyAt?: number | null
}

export type ResourceAction = "start" | "stop" | "remove" | "detach" | "logs"

/** `setup_get`: the contract's detail, plus the engine's own record of it. */
export type SetupDetailView = Omit<SetupDetail, "resources"> & {
  resources: ResourceView[]
  /** What the person chose, public answers only: capabilities on or off, answers, additions. */
  customization?: { answers?: Record<string, unknown>; capabilities?: Record<string, boolean>; added?: unknown[] } | null
  /** The engine's own extras per resource, folded into `resources` when read. */
  resourceDetails?: Record<string, unknown>
  operations?: OperationBrief[]
  /** Plain notes, such as why an adopted grid can't be changed here. */
  notes?: string[]
  /** False when Yougori found the setup's records but could not read them. */
  readable?: boolean
  /** The setup's CORE-07 product document; read it with `readProduct` (`./product`). */
  product?: unknown
  /** Why the engine sent no product document. */
  productUnavailable?: string
}

/** How a template's author offers a capability to the person who runs it. */
export type ChoiceMode = "required" | "optional" | "default"

/** The setup flow, as plan section 5.4 has it. Steps with nothing to ask are skipped. */
export type SetupStepId = "source" | "capabilities" | "compute" | "models" | "admin" | "people" | "review" | "progress" | "ready"

/** One question a draft asks. Secret answers are never shown back or written to source. */
export interface SettingDescriptor {
  id: string
  label: string
  /** The last four are installation-time bindings the person picks on their own computer. */
  kind: "text" | "number" | "choice" | "toggle" | "secret" | "folder" | "drive" | "file" | "resource"
  help?: string
  options?: { value: string; label: string; hint?: string }[]
  default?: string | number | boolean
  min?: number
  max?: number
  /** The capability it belongs to, where it belongs to one. */
  capability?: string | null
  group?: CapabilityGroup | null
  /** Which setup step asks it. Without one it is asked where its group is. */
  step?: SetupStepId | null
  /** It must be answered before the setup can be planned. */
  required?: boolean
  /** False when the template's author fixed the answer: it is shown, not asked. */
  editable?: boolean
  /** The template's condition for asking it, which the engine works out. */
  when?: unknown
  /** Set when this is a binding the person picks here: "folder", "drive", "file", "resource". */
  binding?: string | null
  /** For a folder binding: what the setup may do with the folder, in the review's own words. */
  access?: string | null
}

export type SettingValue = string | number | boolean

export interface CapabilityChoice {
  selected: boolean
  mode: ChoiceMode
  /** Whether the person who runs the template may change its settings. */
  runnerEditable: boolean
  settings: Record<string, SettingValue>
  /** Per question, when a capability carries more than one: how each is offered. */
  controls?: Record<string, { mode: ChoiceMode; runnerEditable: boolean }>
}

/** The kind of grid a draft is, as the shared format stores it in `recipe` and the engine's
 *  generator reads it (`GridProfile::recipe_slug`). A grid's people, models and credentials are
 *  served by different trusted code, so a draft with a grid has to say which. Not a starter
 *  catalogue: there is none. */
export type RecipeSlug = "sandbox-grid" | "neo-grid" | "access-grid" | "swarm-mining-grid"

/** What the builder has so far. Secret values are never part of it. */
export interface SetupDraft {
  name: string
  title?: string | null
  subtitle?: string | null
  summary?: string | null
  /** Where it starts from, when it starts from something that exists. */
  source?: SourceRef | null
  recipe?: RecipeSlug | null
  /** Environments on this computer it is made from. */
  environments?: string[]
  capabilities: Record<string, CapabilityChoice>
  /** The questions the engine read from its source, with their answers in `answers`. */
  questions?: SettingDescriptor[]
  answers?: Record<string, SettingValue>
}

export interface ValidateResponse {
  valid?: boolean
  /** The template source the engine wrote for this draft: yougori-template.yaml. */
  manifest: string
  projectPath?: string | null
  /** Its project file, yougori.yaml, when the draft has one. */
  project?: string | null
  diagnostics: Diagnostic[]
  /** The draft read back, filled in from its source. */
  draft?: SetupDraft | null
  /** Plain notes about an import, such as what a Compose file carried over. For a draft the
   *  engine generated from, its generator's notes instead, each about a field. */
  notes?: (string | Diagnostic)[]
  /** For a generated draft: the capabilities the generator put in the source because a chosen
   *  one needs them, by id. The same list the CLI's `template new` reports as added for you. */
  added?: string[]
  /** For a generated draft: files the template carries beside its two, by name, such as the
   *  cloud model gateway's script. Saved with it. */
  files?: Record<string, string>
}

/** One-off capture sources for `setup_validate`: a Compose file the engine converts, or chosen
 *  environments on this computer it captures into a draft. Neither is a lasting source the setup
 *  follows, so neither is a `SourceRef`. */
export interface ComposeSource { kind: "compose"; path: string }
export interface EnvironmentsSource { kind: "environments"; environments: string[] }

/** `setup_permissions`: what a setup is allowed to do now, read again from its own template and
 *  answers. Every secret is named by the question it comes from, never by its value. When `known` is
 *  false, only `reason` is set, in plain words. */
export interface SetupPermissions {
  setupId: string
  known: boolean
  /** Set when `known` is false: why its permissions can't be read again, in plain words. */
  reason?: string | null
  version?: string | null
  permissions?: string[]
  downloads?: { kind: string; name: string; from?: string | null }[]
  /** Which secret reaches which part, by the question it comes from — never a value. */
  secrets?: { resource: string; variable: string; source: string }[]
  /** Folders of this computer the setup may use. */
  pcAccess?: { environment: string; path: string; target?: string | null; readOnly: boolean; sync?: boolean; staged?: boolean }[]
  costs?: string[]
  /** The setup's CORE-07 product document when its template was read again: what its chosen
   *  capabilities ask for, each requested; a capability does not grant access. Read it with `readProduct` (`./product`). */
  product?: unknown
  /** Why the engine sent no product document. */
  productUnavailable?: string | null
}

/** The planner's own review of a plan: the same one the CLI prints. */
export interface EngineReview {
  creates?: { id: string; kind: string; title: string; placement: string }[]
  borrows?: { id: string; kind: string; title: string; placement: string }[]
  downloads?: { kind: string; name: string; from?: string | null }[]
  permissions?: string[]
  costs?: string[]
  warnings?: string[]
  notes?: string[]
  totals?: { environments: number; cpu: number; memoryGb: number; storageGb: number; gpu: string }
  questions?: { id: string; question: string; answer?: string | null; secret: boolean; group?: string | null }[]
  pcAccess?: { environment: string; path: string; target?: string | null; readOnly: boolean; sync?: boolean; staged?: boolean }[]
  public?: { resource: string; port: number; access: string }[]
  /** Every line each tool runs in its sandbox when it is installed, and its check, exactly as
   *  applying runs them: a tool bundled with the template, or a Hub tool resolved for this review. */
  installs?: { resource: string; tool: string; commands: string[]; check?: string | null }[]
  /** The most the setup may use, as its template caps it: one line each. */
  limits?: string[]
}

/** The Hub page's published review against the files, as the engine compared them when it planned
 *  a Hub package: one rule for the desktop and the CLI. `compared` false means nothing was compared,
 *  with the reason; it never means the page matched. Absent for a folder or a setup planned again. */
export interface PageCheck {
  compared: boolean
  differs: boolean
  differences: string[]
  reason?: string | null
}

/** A reviewed plan, held by the engine until it is applied or expires. */
export interface SetupPlan {
  review?: EngineReview | null
  /** What the Hub page said about this version against what its files would do. */
  page?: PageCheck | null
  /** Things it does only if the person agrees, each unticked until they do. */
  consents?: { id: string; message: string }[]
  setupId: string
  digest: string
  baseRevision: number
  planId?: string | null
  intent?: string | null
  /** Seconds since the epoch. After this the engine refuses to apply it. */
  expiresAt?: number | null
  /** In words: what this plan does. */
  headline?: string | null
  steps?: { id?: string; title: string; detail?: string | null }[]
  resources?: PlanResource[]
  downloads?: { name: string; bytes?: number | null }[]
  permissions?: string[]
  costs?: { label: string; amount?: string | null }[]
  /** Changes to resources that already exist. */
  changes?: string[]
  /** What is kept after a removal. */
  retained?: string[]
  warnings?: string[]
  notes?: string[]
  /** What moving to a newer version does to the choices this setup already has: a question the new
   *  version removed, one it needs answered, a capability it now requires, a value it now fixes.
   *  Each is also the first of the plan's notes, so a review reads them before anything else. */
  conflicts?: { code: string; message: string; subject: string; action: string }[]
  /** Problems that stop it from being applied. */
  blockers?: Diagnostic[]
  /** The plan's CORE-07 product document: what its chosen capabilities ask for, each requested.
   *  Read it with `readProduct` (`./product`). */
  product?: unknown
  /** Why the engine sent no product document. */
  productUnavailable?: string | null
}

export interface PlanResource {
  resourceId?: string
  id?: string
  label?: string
  name?: string
  kind: string
  owned: boolean
  action?: string | null
  /** Where it runs or lives, in words. */
  placement?: string | null
  detail?: string | null
}
