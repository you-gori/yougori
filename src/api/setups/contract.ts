/** The messages the engine, CLI and desktop exchange, as the desktop reads them.
 *
 *  This is the hand-written mirror of `setup/src/dto.rs` and the capability descriptor shape from
 *  `setup/src/capability.rs`. It grants nothing and decides nothing: the engine is the authoritative
 *  writer, and these are the shapes it hands the client to show. A contract test
 *  (`contract.test.ts`) reads the fixtures the Rust side writes under `setup/tests/contract/` and
 *  fails when a value here drifts from the Rust source.
 *
 *  Convention, matching the engine: times are seconds since the epoch, counts are whole numbers, and
 *  a secret is never a value here — only a reference to one.
 */

/** Bump together with `dto::CONTRACT_VERSION` when a shape changes in a way a reader must notice. */
export const CONTRACT_VERSION = 1

// ---- States ----

/** Where one operation is in its life, apart from how the application is doing. */
export type OperationState =
  | "planned"
  | "awaiting_input"
  | "applying"
  | "cancelling"
  | "completed"
  | "failed"
  /** The outcome is not yet known and is being reconciled. A timeout lands here, never on failed. */
  | "unknown"

/** Where a setup is in its life. "Running with no workers" is still running; that is a health matter. */
export type InstanceState =
  | "draft"
  | "creating"
  | "running"
  | "stopped"
  | "updating"
  | "removing"
  /** Removed, but some data was kept on purpose. */
  | "retained"
  | "removed"

/** How one capability of a setup is doing. */
export type CapabilityHealth =
  | "ready"
  | "starting"
  | "needs_sign_in"
  | "waiting_for_computer"
  | "degraded"
  | "failed"
  | "unsupported"

// ---- Diagnostics ----

export type Severity = "error" | "warning" | "info"

/** Something the user can do next, named by what it is rather than a command to run. The UI turns
 *  each into a button; it is never a shell string a template supplied. */
export type NextAction =
  | { kind: "sign_in"; provider: string }
  | { kind: "provide_input"; field: string }
  | { kind: "choose_supported_option"; field: string }
  | { kind: "retry" }
  | { kind: "continue"; operation: string }
  /** Check what really happened after a crash, timeout or cancel. Distinct from retry: it finds
   *  out, it does not change anything. */
  | { kind: "reconcile"; operation: string }
  | { kind: "cancel"; operation: string }
  | { kind: "review" }
  | { kind: "add_computer" }
  | { kind: "view_logs" }
  | { kind: "open_docs"; topic: string }

/** One thing the engine wants to tell the user: a stable code, a plain sentence, typed next actions.
 *  An error is a `Diagnostic` with `severity: "error"`; `ApiError` is the same shape. */
export interface Diagnostic {
  /** A stable identifier for this kind of diagnostic, e.g. "capability_not_enableable". */
  code: string
  message: string
  /** A field path such as "inputs[2].group" or "capabilities.grid.create.grid_name". */
  field?: string
  severity: Severity
  retryable: boolean
  resource?: string
  operation?: string
  step?: string
  nextActions?: NextAction[]
}

export type ApiError = Diagnostic

// ---- Sources and references ----

/** Where a template or setup comes from. A Hub version is pinned; a setup never follows a moving
 *  latest. */
export type SourceRef =
  | { kind: "local_folder"; path: string }
  | { kind: "hub"; publisher: string; name: string; version: string }
  | { kind: "installed_setup"; setupId: string }

export interface OperationRef {
  operationId: string
  setupId: string
}

// ---- Requests ----

/** One public answer to a question, keyed by field path; the value may be a string, number, boolean
 *  or list. */
export interface Answer {
  field: string
  value: unknown
}

/** A private value delivered by reference. The value never travels in the message; the engine
 *  resolves the named secret. */
export interface Binding {
  field: string
  secretRef: string
}

export interface PlanRequest {
  source: SourceRef
  name?: string
  answers?: Answer[]
  bindings?: Binding[]
  existingSetup?: string
}

/** Apply a reviewed plan. The digest ties the apply to exactly the plan shown; the operation id
 *  makes a replay safe; the expected revision stops two writers racing. */
export interface ApplyRequest {
  setupId: string
  planDigest: string
  operationId: string
  expectedRevision: number
}

/** The human-readable review of a plan: what it creates and borrows, downloads, permissions, costs,
 *  warnings and totals. The engine and planner own its exact shape (snake_case author fields inside);
 *  the desktop reads the parts it shows. Kept loose here so a new review field never breaks the type. */
export type PlanReview = Record<string, unknown>

/** The author's resolved plan graph, carried verbatim from the planner. Its resource specs keep the
 *  snake_case field names the author wrote, so the source view and `template export` show the same
 *  YAML. Read it as opaque unless you own the planner's shape. */
export type Plan = Record<string, unknown>

/** The answer to a plan request: the concrete plan, ready to review and apply. For a brand-new setup
 *  the engine reserves the setup's id at plan time and returns it here with `baseRevision` 0; send that
 *  id back in ApplyRequest, which is what stops a replayed create plan from making a second setup.
 *  `digest` equals the plan's own digest, copied up so a reader need not reach into the plan to match
 *  it. Only this envelope is camelCase. */
export interface PlanResponse {
  /** The id the engine reserved for this setup (new or existing); sent back in ApplyRequest. */
  setupId?: string
  baseRevision: number
  digest: string
  review: PlanReview
  plan: Plan
}

// ---- Operations and progress ----

export interface OperationEvent {
  /** A monotonic position, so a reader can resume after it. */
  cursor: number
  /** Seconds since the epoch. */
  at: number
  /** A short machine tag for the step, e.g. "reserving_storage". */
  step: string
  message: string
  resource?: string
  diagnostic?: Diagnostic
}

/** A bounded, resumable read of an operation's progress. `truncated` says earlier events were
 *  dropped before this read, so the UI can say so rather than imply completeness. */
export interface OperationProgress {
  operation: OperationRef
  state: OperationState
  events: OperationEvent[]
  nextCursor: number
  truncated?: boolean
  error?: Diagnostic
  /** The digest of the plan this operation applies (`ApplyRequest.planDigest`). A client that was
   *  not there for the review can answer an operation waiting for input by sending this and the
   *  operation's id back, so the operation that asked continues. An older engine leaves it out. */
  planDigest?: string
}

// ---- Setups ----

/** Which of the four grids a setup presents as, kept separate from capability names. "generic" is
 *  any setup that is not one of the four. */
export type GridProfile = "neo_grid" | "sandbox_grid" | "access_grid" | "swarm_mining_grid" | "generic"

export interface SetupSummary {
  setupId: string
  name: string
  source: SourceRef
  state: InstanceState
  /** Whether the engine has actually observed this setup's state. An adopted legacy grid is managed
   *  from its own page, so its state was never observed here: `state` reads "stopped" (never implying
   *  it runs or can start), and the UI should say "state not checked" instead of the state word.
   *  Defaults to true; omitted when true. */
  stateObserved?: boolean
  profile?: GridProfile
  /** True for an older grid adopted into a setup rather than created as one. */
  adoptedLegacy?: boolean
  /** The combined health across the setup, so a list can show "degraded" without fetching detail. */
  health?: CapabilityHealth
  createdAt: number
  currentOperation?: OperationRef
}

/** What the engine last saw of a resource. "unknown" until observed; "missing" is how drift shows. */
export type ResourceObserved = "unknown" | "missing" | "present" | "running" | "stopped"

/** What a resource is costing. A stop never implies "costs nothing" without evidence:
 *  "shutdown_unconfirmed" says a charge may still be running. */
export type ResourceCost = "free" | "unknown" | "accruing" | "stopped" | "shutdown_unconfirmed"

/** A resource a setup owns or borrows. An owned resource follows the setup's lifecycle; a borrowed
 *  one is never destroyed by the borrowing setup. */
export interface ResourceRef {
  resourceId: string
  kind: ResourceKind
  owned: boolean
  label: string
  /** What the engine last saw of it. Defaults to "unknown" when omitted. */
  observed?: ResourceObserved
  /** A plain sentence when the resource drifted from what was expected, e.g. "Removed outside
   *  Yougori." Absent when it matches. */
  drift?: string
  /** What it is costing. Defaults to "unknown" when omitted. */
  cost?: ResourceCost
  /** Whether removing the setup would leave this resource's data behind. */
  retainedData?: boolean
  /** For a borrowed resource, the setup that owns it. Absent for an owned resource. */
  borrowedFrom?: string
}

/** One safe output of a setup: a public URL, a port, a workspace link. Never a secret. */
export interface Output {
  key: string
  label: string
  value: string
}

export interface CapabilityStatus {
  /** The capability id, e.g. "grid.create". */
  id: string
  health: CapabilityHealth
  detail?: string
  nextActions?: NextAction[]
}

/** The full view of one setup: only safe state. No secret values, no private answers. */
export interface SetupDetail {
  summary: SetupSummary
  /** The setup revision, as `ApplyRequest.expectedRevision` uses it. */
  revision: number
  capabilities: CapabilityStatus[]
  resources: ResourceRef[]
  outputs?: Output[]
  actions?: SetupAction[]
  /** The standard views the template declared, read from its kept package. The desktop shapes the
   *  setup's tabs from them; a build that doesn't send them falls back to the capability tabs. */
  views?: string[]
}

/** An action a user can take on a whole setup. Destructive ones (delete data) always need their own
 *  explicit step. */
export type SetupAction =
  | "start"
  | "stop"
  | "remove"
  | "detach"
  | "pause_admission"
  | "release_compute"
  | "delete_data"

// ---- Resources ----

/** The kinds a v2 project resource can have. Mirrors `resource::Kind`. */
export type ResourceKind =
  | "environment"
  | "grid"
  | "compute_pool"
  | "worker_group"
  | "model_service"
  | "workspace_pool"
  | "access_binding"
  | "credential_broker"
  | "service_publication"
  | "volume"
  | "connection"
  | "job"
  | "artifact_store"
  | "vm_sandbox"

// ---- Capabilities (the catalogue the generated table fills) ----

/** The six prominent groups on the creation screen. Mirrors `capability::Group`. */
export type CapabilityGroup =
  | "grid_workers"
  | "ai_models"
  | "website_api"
  | "people_access"
  | "files_data"
  | "automation_recovery"

/** How ready a capability is in this build. A "planned" capability cannot be enabled; a
 *  "private_build" one never appears in a public build's generated table at all. */
export type CapabilityStatusLevel = "shipped" | "planned" | "private_build"

/** The control the wizard draws for a capability's main choice. */
export type CapabilityWidget = "toggle" | "choice" | "amount" | "list" | "text"

/** How a capability stands on a particular host, as `setup_capabilities` reports it. */
export type CapabilityAvailability = "available" | "needs_configuration" | "unsupported" | "planned"

/** One capability, as the generated `capabilities.generated.ts` table carries it.
 *  `requires` keeps its all-of-any-of shape: a list of groups, each satisfied by any one id. */
export interface CapabilityDescriptor {
  id: string
  version: number
  group: CapabilityGroup
  name: string
  summary: string
  examples: string[]
  resourceKinds: ResourceKind[]
  requires: string[][]
  conflicts: string[]
  /** Search words that lead to this capability's group. */
  aliases: string[]
  permissions: string[]
  actions: SetupAction[]
  widget: CapabilityWidget
  /** The engine mechanism's status, not per-profile wiring. The UI shows the four availability
   *  states, derived from this plus `profiles` and the host — never "shipped" itself. */
  status: CapabilityStatusLevel
  /** The grid profiles whose handler wires this capability today. Empty means it is not
   *  profile-specific: any setup the platform supports can use it. A setup of a profile not listed
   *  here shows "unsupported" for this capability, even when status is "shipped". */
  profiles: GridProfile[]
  /** Profiles whose handler supplies this capability's dependencies itself, so `requires` does not
   *  apply to them (e.g. Access Grid backs up as a file export, needing no volume). Empty means
   *  `requires` applies to every profile. */
  requiresWaivedFor: GridProfile[]
}

/** What `setup_capabilities` returns for a given host: the per-capability availability and a reason
 *  when it is not simply available. */
export interface CapabilityAvailabilityReport {
  id: string
  availability: CapabilityAvailability
  reason?: string
}
