/** What every grid is made of, whatever it is for.
 *
 *  These are Grid Core's shapes as a page would read them: camelCase, seconds since the epoch for
 *  every time, and never a secret value. They sit beside the four products' own types rather than
 *  replacing them. A product type that a page already reads keeps its own declaration in its own
 *  module; `@/api/grids/compat` holds the conversions, one table per state that differs.
 */
import type { GridClosing, DeleteWhen } from "@/lib/grid-closing"

/** A grid being deleted, and the three answers to "when". Declared once, in `@/lib/grid-closing`,
 *  because the pages and the four product modules already share those. */
export type { GridClosing, DeleteWhen }

// ---- Realm ----

export type RealmKind = "primary" | "research"

/** What a grid does. Switching one on gives it nothing from the others. */
export type Capability = "models" | "workspaces" | "credentials" | "research"

/** Which product a grid is shown as while the four hubs still exist. */
export type Profile = Capability

/** Where a grid is in its life. A paused grid answers but serves nothing. */
export type RealmLifecycle = "open" | "paused" | "closing" | "gone"

export interface NetworkPolicy {
  outbound: boolean
  /** Where a workload may reach when `outbound` is on; empty means anywhere. */
  destinations: string[]
  /** The hub may be reached from outside the company network, through a tunnel. */
  published: boolean
}

/** Declared now, filled later: no command reads or creates a realm yet, so nothing in this
 *  client returns one. It is here because the status shapes below are written against it. */
export interface Realm {
  id: string
  name: string
  kind: RealmKind
  capabilities: Capability[]
  network: NetworkPolicy
  lifecycle: RealmLifecycle
  keyFingerprint: string
  createdAt: number
}

export interface Tunnel {
  kind: "quick" | "domain"
  domain: string | null
  url: string | null
  connected: boolean
  error: string | null
}

/** Where a new hub may be reached from: the company network only, a quick link, or a domain. */
export type Reach = "network" | "quick" | { domain: string }

/** The hub this computer runs. The counts and the fingerprint are what the hub reports, so a
 *  product that does not report one leaves it out rather than inventing a zero. */
export interface RealmHub {
  id: string
  name: string
  address: string
  port: number
  createdAt: number
  profile: Profile
  fingerprint?: string
  lifecycle?: RealmLifecycle
  capabilities?: Capability[]
  computers?: { total: number; capable: number; online: number }
  tunnel?: Tunnel
  /** Shared with company computers to join; it carries no secret. */
  invite?: string
  closing?: GridClosing | null
}

/** This computer's place in a grid someone else hosts. */
export interface Membership {
  realmId: string
  realm: string
  hub: string
  fingerprint: string
  deviceId: string
  joinedAt: number
  connected: boolean
  error: string | null
  /** Its admin scheduled the grid for deletion; until then it is paused. */
  pausedUntil?: number | null
  /** The hub has not answered since this time. */
  unreachableSince?: number | null
}

// ---- People and computers ----

export type PrincipalKind = "person" | "service"

/** The ten roles of `grid/src/core/identity.rs`. Holding one never implies another, except that
 *  administering a realm brings the two approving permissions with it. */
export type Role =
  | "user" | "operator" | "researcher" | "workspaceAdmin" | "modelAdmin" | "credentialAdmin"
  | "credentialApprover" | "researchApprover" | "securityAdmin" | "auditor" | "realmAdmin"

export type Action =
  | "readOwn" | "readRealm" | "readAudit" | "useWorkspace" | "callModel" | "placeWork"
  | "drainHost" | "revokeDevice" | "manageWorkspaces" | "manageModels" | "manageCredentials"
  | "managePeople" | "manageSecurity" | "doResearch" | "approveCredential" | "approveResearch"

export interface Principal {
  id: string
  realmId: string
  kind: PrincipalKind
  name: string
  /** The username they sign in with, where the profile has sign-in. */
  username?: string
  email?: string | null
  roles: Role[]
  createdAt: number
  lastSeenAt?: number | null
  /** Set when they are suspended: nothing they hold works from that moment. */
  suspendedAt?: number | null
  /** Two-step sign-in is on for them. */
  twoStep?: boolean
  devices?: Device[]
}

/** What a computer could show about its own state. Absent is unverified, never assumed safe. */
export interface Attestation {
  secureBoot: boolean | null
  tpm: boolean | null
  os?: string | null
  agentVersion?: string | null
}

export interface Device {
  id: string
  realmId: string
  principalId: string
  name: string
  platform: string
  enrolledAt: number
  lastSeenAt?: number | null
  revokedAt?: number | null
  attestation?: Attestation
  /** This sign-in had a second factor. */
  strong?: boolean
}

/** The person signed in on this computer, for the profiles that have sign-in. */
export interface Me {
  principal: Principal
  realmId: string
  realm: string
  deviceId: string | null
  signedInAt: number
  strong: boolean
  /** The grid requires two-step and this sign-in had none. */
  blocked?: boolean
}

// ---- Computers that offer themselves ----

export interface Resources {
  cpu: number
  memoryGb: number
  diskGb: number
  gpu: boolean
  vramGb?: number
}

/** How much of a computer its owner gave the grid. */
export type Commitment = "share" | "dedicated" | "none"

/** What a computer has and is using right now; only true at this moment. */
export interface HostLoad {
  /** Of the whole computer, 0 to 100. */
  cpuUsedPercent: number
  usedMemoryGb: number
  freeDiskGb: number
  gpuUsedPercent?: number | null
  onBattery: boolean
  /** Someone used its keyboard or mouse in the last few minutes. */
  inUse: boolean
}

/** A computer in a grid, as the hub reports it now. */
export interface HostStatus {
  id: string
  realmId: string
  name: string
  platform: string
  joinedAt: number
  online: boolean
  lastSeenSeconds: number | null
  address: string | null
  appVersion: string | null
  /** It can do what the grid asks of it. */
  capable: boolean
  /** The admin left it out: no work until it is brought back. */
  excluded: boolean
  /** Being emptied: it takes no new work. */
  draining: boolean
  commitment?: Commitment
  capacity?: Resources | null
  offered?: (Resources & { idleOnly: boolean }) | null
  /** The admin set the offer themselves, rather than leaving the suggestion in force. */
  offerSet?: boolean
  load?: HostLoad | null
  /** Pieces of work running on it. */
  running: number
  /** Replies it has served. */
  jobs: number
  planId?: string | null
  /** What it says about the model it was given. */
  models: ModelReport[]
  /** Workspaces it holds. */
  workspaces?: number
}

// ---- Model plans ----

/** How far a model has come on its way to ready; bytes in the phases that count them. */
export interface ModelProgress {
  phase: string
  done: number
  total: number
  /** Bytes per second while downloading. */
  rate: number
}

export interface ModelReport {
  model: string
  state: string
  reason?: string
  progress?: ModelProgress | null
}

/** Which computers a plan runs on: a share of all of them, a share of those nobody picked, or
 *  the picked ones. `hosts` is Grid Core's word for what the Closed Neo Grid calls members. */
export type PlanTarget =
  | { kind: "all"; percent: number }
  | { kind: "remaining"; percent: number }
  | { kind: "hosts"; hosts: string[] }

export interface ModelPlan {
  id: string
  realmId: string
  model: string
  quant: string | null
  percent: number
  target: PlanTarget
  /** What the hub adds: how it is going right now. */
  computers: number
  wanted: number
  ready: number
  /** The picked computers' names, for a plan on picked computers. */
  names: string[]
  /** When it serves, in words: "always on", "idle only". */
  rules: string
}

export interface NewModelPlan {
  model: string
  quant?: string | null
  target: PlanTarget
}

/** A team of models an app calls as `swarm/NAME`; one call runs on several computers. */
export interface Harness {
  id: string
  name: string
  /** What apps call: `swarm/NAME`. */
  model: string
  strategy: "plan" | "mixture"
  lead: string
  workers: string[]
  computers: number
  tasks: number
  rounds: number
  ready: boolean
}

// ---- Workspaces ----

export type WorkspaceKind = "container" | "microVm" | "vm"
export type WorkspaceAccess = "standard" | "restricted"

/** `grid/src/core/workspace.rs`. The Sandbox Grid's own five words do not match these one for
 *  one; `@/api/grids/compat` holds the table both ways. */
export type WorkspaceState =
  | "requested" | "provisioning" | "ready" | "assigned"
  | "running" | "draining" | "archived" | "failed"

export interface Workspace {
  id: string
  realmId: string
  name: string
  ownerId: string | null
  /** The owner's name, when the hub knows it. */
  owner: string | null
  username: string | null
  kind: WorkspaceKind
  shape: Resources
  image: string
  access: WorkspaceAccess
  roleId?: string | null
  state: WorkspaceState
  /** The product's own word for the state, kept because it says more than the core state does. */
  productState: string
  summary: string
  note: string
  /** Rises whenever ownership or placement changes, so a stale page can be told. No product
   *  reports one yet, so it is absent rather than invented. */
  generation?: number
  attempts: number
  createdAt: number
  updatedAt: number
  /** Where it is now, as the hub sees it. */
  hostId: string | null
  host: string | null
  hostOnline: boolean
  /** While moving: the computer that still holds its data. */
  movingFrom?: string | null
  /** How much data is packed and waiting. */
  parcelBytes?: number | null
  /** Ready, its computer online and a share live: its person can open it now. */
  reachable: boolean
  environmentId: string | null
}

export interface NewWorkspace {
  name: string
  ownerId?: string | null
  kind: WorkspaceKind
  shape: Pick<Resources, "cpu" | "memoryGb" | "diskGb" | "gpu">
  image?: string | null
}

/** An image a workspace is built from. Declared now, filled later: the Sandbox Grid answers
 *  with its images only through the admin door, which this client passes through untyped. */
export interface Image {
  id: string
  name: string
  version: string
  description: string
  applications: string[]
  kind: WorkspaceKind
  digest: string | null
  createdAt: number
}

// ---- Credentials ----

/** How the broker puts a credential on a request. The last three make short-lived ones. */
export type CredentialShape =
  "bearer" | "header" | "basic" | "query" | "oauth" | "githubApp" | "aws"

export interface Credential {
  id: string
  realmId: string
  name: string
  shape: CredentialShape
  /** The header name (header), query parameter (query) or username (basic). */
  field: string
  /** Where it may be sent, over HTTPS. */
  destinations: string[]
  note: string
  /** The value's last four characters, empty for short values. The value is never sent. */
  hint: string
  ownerId: string
  createdAt: number
  updatedAt: number
  /** How many rules mention it. */
  rules: number
  /** Never secret: tokenUrl, clientId, appId, region, roleArn and the like. */
  config?: Record<string, string | number>
}

/** Who may use a credential, and for what. Holding one is not permission on its own. */
export interface Grant {
  id: string
  realmId: string
  credentialId: string
  credentialName: string | null
  /** `everyone`, `team:NAME` or `person:ID`. */
  who: string
  whoLabel: string
  methods: string[]
  path: string
  decision: "allow" | "ask" | "never"
  /** The value may be shown to the person, not only used on their behalf. */
  reveal: boolean
  expiresAt?: number | null
  /** Uses an hour at once per person; past that, an approver decides. */
  limit?: number | null
  note: string
  grantedBy: string
  grantedAt: number
}

// ---- Approvals ----

export type ApprovalState = "waiting" | "running" | "granted" | "refused" | "failed"

/** What an approver decided. */
export type Verdict =
  | { kind: "once" }
  | { kind: "hours"; hours: number }
  | { kind: "denied"; reason: string }

export interface Approval {
  id: string
  realmId: string
  action: string
  resourceId: string
  resource: string
  method?: string | null
  path?: string | null
  requestedBy: string
  requestedById?: string | null
  requestedAt: number
  expiresAt: number
  state: ApprovalState
  decidedBy: string | null
  /** What the asker was trying to do, for the approver to read. */
  agent?: string
  computer?: string
  bodyBytes?: number
  /** Why it waits for an approver, in words. */
  why?: string
}

// ---- Work and research ----

/** Declared now, filled later. No command places work on Grid Core yet, so nothing here
 *  returns a workload or a lease and neither is declared; this is the vocabulary a page will
 *  read when one does. */
export type WorkKind =
  "inference" | "workspace" | "credentialRequest" | "research" | "connectorTask" | "artifactTransfer"

/** `grid/src/core/work.rs`. Swarm Mining has states this cannot hold (paused, stopped,
 *  ready_waiting, preparing_bounty), which is why `ResearchJob` keeps its own word as well. */
export type Stage =
  | "draft" | "validating" | "queued" | "leased" | "preparing" | "running"
  | "draining" | "completed" | "rejected" | "cancelled" | "expired" | "failed" | "quarantined"

/** One authorised research run. Today that is one Swarm Mining worker. */
export interface ResearchJob {
  id: string
  realmId: string
  /** A memorable name, such as Keen heron. */
  name: string
  model: string
  quant?: string | null
  /** The nearest core stage, or null where core has no stage for it. Four of Swarm Mining's
   *  own words have no core stage at all; see `WORKER_STATES_CORE_CANNOT_HOLD`. */
  stage: Stage | null
  /** The worker's own word, which is the one a page should branch on: preparing, ready_waiting,
   *  waiting, ready, running, preparing_bounty, paused, stopped. */
  state: string
  /** What it is doing, in words. */
  summary: string
  /** Where it is, in the worker's own words. */
  step: string
  gpu: string
  resources: { cpu?: number; memoryGb?: number }
  workspaceQuotaGb: number
  keepResident: boolean
  network: "public" | "closed"
  error: string | null
  startedAt: number
  attempts: number
  /** The bounty it accepted, when it has one. */
  subjectId?: string | null
  /** Reports waiting for the person to read before they are sent. */
  reviewReports?: string[]
}

/** One line of a research job's progress. */
export interface ResearchStep {
  seq: number
  at?: number
  kind?: string
  stage?: string
  text?: string
  detail?: string
  tool?: string
  target?: string
  status?: string
}

// ---- Audit ----

export type AuditDecision = "allowed" | "refused"

/** One recorded change or decision. No secret value is ever a field of this. */
export interface AuditEvent {
  id: string
  at: number
  realmId: string
  principal: string
  agent?: string
  computer?: string
  action: string
  resource?: string
  decision: AuditDecision
  /** Why, in words, for a person reading the log. Never a secret. */
  reason: string
}

export interface AuditCheck {
  whole: boolean
  /** The first event that was altered, removed or reordered. */
  brokenAt: number | null
  message: string
}

// ---- Status ----

export interface RealmStatus<P extends Profile = Profile> {
  profile: P
  /** The hub this computer runs, when it runs one. */
  hub: RealmHub | null
  hubError: string | null
  /** This computer's membership of a hub somebody else runs. */
  member: Membership | null
  memberError: string | null
  /** The person signed in on this computer, where the profile has sign-in. */
  me: Me | null
  message?: string
}

export interface ModelsStatus extends RealmStatus<"models"> {
  hosts: HostStatus[]
  plans: ModelPlan[]
  planWarning: string | null
  queue: { waiting: number; running: number }
  harnesses: Harness[]
  /** What this computer was asked to serve, when it joined somebody else's grid. */
  assignment: { model?: string; quant?: string | null; rules: string | null; state: string | null; reason: string | null; progress?: ModelProgress | null; jobs: number; failures: number; lastError: string | null } | null
}

export interface WorkspacesStatus extends RealmStatus<"workspaces"> {
  hosts: HostStatus[]
  people: Principal[]
  workspaces: Workspace[]
  /** Workspaces this computer holds for the grid's people. */
  hosting: Array<{ id: string; name: string; environmentId: string; shared: boolean }>
  /** The signed-in person's own workspaces. A sign-in answer carries less about each one than
   *  the hub's record does, so this is what they were told, not a `Workspace`. */
  mine: Array<{ id: string; name: string; state: string; note: string; host: string | null; environmentId: string | null; address: string | null }>
  /** Systems somebody else runs that this grid hands a workspace over to. */
  connections: Array<{ id: string; name: string; provider: string; url: string }>
  /** Orders the hub currently places on this computer, when it joined somebody else's grid. */
  orders: number | null
}

export interface CredentialsStatus extends RealmStatus<"credentials"> {
  credentials: Credential[]
  grants: Grant[]
  waiting: Approval[]
  /** The command line an agent uses. */
  mcp: { command: string; args: string[] }
}

export interface ResearchStatus extends RealmStatus<"research"> {
  jobs: ResearchJob[]
}

// ---- Call options ----

export interface Expect {
  /** The version the caller believes it is changing. */
  version: number
}

export interface CallOptions {
  expect?: Expect
  /** Supply one to tie several calls to the same action together in a log. */
  requestId?: string
}
