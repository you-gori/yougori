/** Where the four products' words meet Grid Core's.
 *
 *  Nothing here aliases one type to another. Every product type a page already reads keeps its
 *  own declaration in its own module, exactly as it is, because several of them hold fields
 *  Grid Core has no room for: a joined computer's model assignment and its progress, a desk
 *  that is building or moving, a worker that is paused. The conversions below are one way, from
 *  what a product answers to what Grid Core calls it, and every one of them is lossy in a way
 *  the comment above it names. A page moves over when its own test moves with it, and until
 *  then both sides work because both end at the same `call()`.
 */
import type { GridComputer, GridMembership, GridHub, GridPlan, GridPlanTarget, GridScope } from "@/api/grid-api"
import type { Desk, DeskPerson, DesksComputer, DesksHub, DesksMembership } from "@/api/desks-api"
import type { SwarmWorker } from "@/api/swarm-api"
import type {
  AccessActivity, AccessCredential, AccessHub, AccessMember, AccessPerson, AccessRequest, AccessRule,
} from "@/api/access-api"
import { ROLE_FROM_ACCESS, ROLE_FROM_DESKS } from "@/api/grids/permits"
import { TELL_FOR } from "@/lib/grid-closing"
import type {
  Approval, ApprovalState, AuditEvent, Credential, CredentialShape, Grant, HostStatus, Membership,
  ModelPlan, ModelsStatus, PlanTarget, Principal, RealmHub, ResearchJob, Role, Stage, Workspace, WorkspaceState,
} from "@/api/grids/types"

/** Seconds since the epoch, from whichever of the two shapes a product answers with. */
export function seconds(at: string | number | null | undefined): number {
  if (typeof at === "number") return at
  if (!at) return 0
  const parsed = Date.parse(at)
  return Number.isNaN(parsed) ? 0 : Math.floor(parsed / 1000)
}

// ---- Model plans ----

/** The Closed Neo Grid says "members" where Grid Core says "hosts". Nothing else differs. */
export function toPlanTarget(scope: GridScope, percent: number): PlanTarget {
  return scope.kind === "computers" ? { kind: "hosts", hosts: scope.members } : { kind: scope.kind, percent }
}

/** And back, for a page that has moved over but still reaches the old command. */
export function fromPlanTarget(target: PlanTarget): GridPlanTarget {
  return target.kind === "hosts" ? { kind: "computers", members: target.hosts } : { kind: target.kind, percent: target.percent }
}

/** Loses nothing. `target` the number becomes `wanted`, because `target` in Grid Core is where
 *  a plan runs, not how many computers it wants. */
export function toModelPlan(plan: GridPlan, realmId: string): ModelPlan {
  return {
    id: plan.id,
    realmId,
    model: plan.model,
    quant: plan.quant,
    percent: plan.percent,
    target: toPlanTarget(plan.scope, plan.percent),
    computers: plan.computers,
    wanted: plan.target,
    ready: plan.ready,
    names: plan.names,
    rules: plan.rules,
  }
}

// ---- Computers ----

/** A computer in the Closed Neo Grid. Loses nothing: `excluded` is kept as it is and also read
 *  as Grid Core's `draining`, which is the same decision under another name. */
export function toHostStatus(computer: GridComputer, realmId: string): HostStatus {
  return {
    id: computer.id,
    realmId,
    name: computer.name,
    platform: computer.platform,
    joinedAt: seconds(computer.joinedAt),
    online: computer.online,
    lastSeenSeconds: computer.lastSeenSeconds,
    address: computer.address,
    appVersion: computer.appVersion,
    capable: computer.capable,
    excluded: computer.excluded,
    draining: computer.excluded,
    running: computer.running,
    jobs: computer.jobs,
    planId: computer.planId,
    models: computer.models,
  }
}

/** A computer in the Sandbox Grid. `capacity.freeDiskGb` is read as the disk it has, because
 *  free space is the only disk figure that computer reports. */
export function toDeskHostStatus(computer: DesksComputer, realmId: string): HostStatus {
  const capacity = computer.capacity ?? null
  const share = computer.share ?? null
  return {
    ...toHostStatus(computer, realmId),
    commitment: share ? (share.idleOnly ? "share" : "dedicated") : "none",
    capacity: capacity ? { cpu: capacity.cpu, memoryGb: capacity.memoryGb, diskGb: capacity.freeDiskGb, gpu: capacity.gpu } : null,
    offered: share ? { cpu: share.cpu, memoryGb: share.memoryGb, diskGb: share.diskGb, gpu: share.gpu, idleOnly: share.idleOnly } : null,
    offerSet: computer.shareSet,
    load: capacity
      ? { cpuUsedPercent: capacity.cpuUsedPercent, usedMemoryGb: capacity.usedMemoryGb, freeDiskGb: capacity.freeDiskGb, gpuUsedPercent: capacity.gpuUsedPercent ?? null, onBattery: capacity.onBattery, inUse: capacity.inUse }
      : null,
    workspaces: computer.desks,
  }
}

// ---- Hubs and memberships ----

export function toModelsHub(hub: GridHub): RealmHub {
  return {
    id: hub.id,
    name: hub.name,
    address: hub.address,
    port: hub.port,
    createdAt: seconds(hub.createdAt),
    profile: "models",
    fingerprint: hub.fingerprint,
    capabilities: ["models"],
    computers: hub.computers,
    tunnel: hub.tunnel,
    invite: hub.invite,
    closing: hub.closing ?? null,
  }
}

export function toWorkspacesHub(hub: DesksHub): RealmHub {
  return {
    id: hub.id,
    name: hub.name,
    address: hub.address,
    port: hub.port,
    createdAt: seconds(hub.createdAt),
    profile: "workspaces",
    fingerprint: hub.fingerprint,
    capabilities: ["workspaces"],
    computers: hub.computers,
    tunnel: hub.tunnel,
    invite: hub.invite,
    closing: hub.closing ?? null,
  }
}

/** The Access Grid reports counts rather than lists, and no capable or online figure, so the
 *  computer counts are left out rather than filled with zeros. */
export function toCredentialsHub(hub: AccessHub): RealmHub {
  return {
    id: hub.id,
    name: hub.company,
    address: hub.address,
    port: hub.port,
    createdAt: hub.createdAt,
    profile: "credentials",
    fingerprint: hub.fingerprint,
    tunnel: hub.tunnel,
    invite: hub.invite,
    capabilities: ["credentials"],
    closing: hub.closing ? { requestedAt: hub.closing.requestedAt, until: hub.closing.until, gone: hub.closing.gone, tellUntil: hub.closing.until + TELL_FOR } : null,
  }
}

/** Keeps only what a membership is. Everything the Closed Neo Grid adds about what this
 *  computer was told to serve goes to `ModelsStatus.assignment`, so no field is dropped. */
export function toMembership(member: GridMembership): Membership {
  return {
    realmId: member.gridId,
    realm: member.grid,
    hub: member.hub,
    fingerprint: member.fingerprint,
    deviceId: member.memberId,
    joinedAt: seconds(member.joinedAt),
    connected: member.connected,
    error: member.error,
    pausedUntil: member.pausedUntil,
    unreachableSince: member.unreachableSince,
  }
}

/** What this computer was asked to serve. Grid Core has no place for it yet. */
export function toAssignment(member: GridMembership): ModelsStatus["assignment"] {
  return {
    model: member.assignment?.model,
    quant: member.assignment?.quant ?? null,
    rules: member.rules,
    state: member.state,
    reason: member.reason,
    progress: member.progress ?? null,
    jobs: member.jobs,
    failures: member.failures,
    lastError: member.lastError,
  }
}

export function toDesksMembership(member: DesksMembership): Membership {
  return {
    realmId: member.gridId,
    realm: member.grid,
    hub: member.hub,
    fingerprint: member.fingerprint,
    deviceId: member.memberId,
    joinedAt: member.joinedAt,
    connected: member.connected,
    error: member.error,
    pausedUntil: member.pausedUntil,
    unreachableSince: member.unreachableSince,
  }
}

export function toAccessMembership(member: AccessMember): Membership {
  return {
    realmId: member.accessId,
    realm: member.company,
    hub: member.hub,
    fingerprint: member.fingerprint,
    deviceId: member.deviceId ?? "",
    joinedAt: member.signedInAt,
    connected: member.connected,
    error: member.error,
  }
}

// ---- Workspaces ----

/** The Sandbox Grid's five words, onto Grid Core's eight. Two of the five have no core state
 *  of their own: a desk that is building is provisioning, and one that is moving is draining
 *  while its data is packed. A page that needs to tell those apart reads `productState`. */
export const WORKSPACE_STATE_FROM_DESK: Record<Desk["state"], WorkspaceState> = {
  planned: "requested",
  building: "provisioning",
  ready: "ready",
  failed: "failed",
  moving: "draining",
}

/** And back, for a control that still speaks to the old command. `assigned`, `running` and
 *  `archived` have no Sandbox Grid word, so they become the nearest one it has. */
export const DESK_STATE_FROM_WORKSPACE: Record<WorkspaceState, Desk["state"]> = {
  requested: "planned",
  provisioning: "building",
  ready: "ready",
  assigned: "ready",
  running: "ready",
  draining: "moving",
  archived: "failed",
  failed: "failed",
}

/** Keeps every field the desk pages read, under Grid Core's names, and keeps the Sandbox
 *  Grid's own word as `productState` so nothing has to guess it back. */
export function toWorkspace(desk: Desk, realmId: string): Workspace {
  return {
    id: desk.id,
    realmId,
    name: desk.name,
    ownerId: desk.personId,
    owner: desk.person,
    username: desk.username,
    kind: desk.spec.kind,
    shape: { cpu: desk.spec.cpu, memoryGb: desk.spec.memoryGb, diskGb: desk.spec.diskGb, gpu: desk.spec.gpu },
    image: desk.spec.image,
    access: desk.access ?? "standard",
    roleId: desk.roleId ?? null,
    state: WORKSPACE_STATE_FROM_DESK[desk.state],
    productState: desk.state,
    summary: desk.summary,
    note: desk.note,
    attempts: desk.attempts,
    createdAt: desk.createdAt,
    updatedAt: desk.updatedAt,
    hostId: desk.hostId,
    host: desk.host,
    hostOnline: desk.hostOnline,
    movingFrom: desk.movingFrom,
    parcelBytes: desk.parcelBytes,
    reachable: desk.reachable,
    environmentId: desk.environmentId,
  }
}

/** The Sandbox Grid's four admin words become Grid Core's roles. A person with no admin word
 *  is a user, which is what the hub treats them as. */
export function toDeskPrincipal(person: DeskPerson, realmId: string): Principal {
  const role: Role = ROLE_FROM_DESKS[person.adminRole ?? "user"]
  return {
    id: person.id,
    realmId,
    kind: "person",
    name: person.name,
    username: person.username,
    email: person.email ?? null,
    roles: [role],
    createdAt: person.createdAt,
    lastSeenAt: person.lastLoginAt,
    twoStep: person.mfa,
  }
}

// ---- Research ----

/** Swarm Mining's own words, onto Grid Core's stages. Four of them have no stage at all, and
 *  inventing one would tell a page something untrue, so those map to null and a page branches
 *  on `ResearchJob.state` instead. */
export const WORKER_STATES_CORE_CANNOT_HOLD: readonly string[] = ["ready_waiting", "preparing_bounty", "paused", "stopped"]

export const STAGE_FROM_WORKER: Record<string, Stage | null> = {
  preparing: "preparing",
  waiting: "queued",
  ready: "queued",
  running: "running",
  failed: "failed",
  done: "completed",
  ready_waiting: null,
  preparing_bounty: null,
  paused: null,
  stopped: null,
}

/** Keeps every field the Swarm Mining page reads. The one rename worth saying out loud: a
 *  worker's `stage` is free text about what it is doing, so it becomes `step`, and `stage`
 *  here is the enum. Nothing else changes name. */
export function toResearchJob(worker: SwarmWorker, realmId: string): ResearchJob {
  return {
    id: worker.id,
    realmId,
    name: worker.name,
    model: worker.model,
    quant: worker.quant ?? null,
    stage: STAGE_FROM_WORKER[worker.state] ?? null,
    state: worker.state,
    summary: worker.summary,
    step: worker.stage,
    gpu: worker.gpu,
    resources: worker.resources,
    workspaceQuotaGb: worker.workspaceQuotaGb,
    keepResident: worker.keepResident,
    network: worker.networkMode ?? "public",
    error: worker.error,
    startedAt: worker.createdAt,
    attempts: worker.completedAttempts ?? 0,
    subjectId: worker.bountyId ?? null,
    reviewReports: worker.reviewReports,
  }
}

// ---- Credentials ----

const SHAPE_FROM_ACCESS: Record<AccessCredential["kind"], CredentialShape> = {
  bearer: "bearer", header: "header", basic: "basic", query: "query",
  oauth: "oauth", "github-app": "githubApp", aws: "aws",
}

export function toCredential(credential: AccessCredential, realmId: string): Credential {
  return {
    id: credential.id,
    realmId,
    name: credential.name,
    shape: SHAPE_FROM_ACCESS[credential.kind],
    field: credential.field,
    destinations: credential.destinations,
    note: credential.note,
    hint: credential.hint,
    ownerId: credential.createdBy,
    createdAt: credential.createdAt,
    updatedAt: credential.updatedAt,
    rules: credential.rules,
    config: credential.config,
  }
}

/** The Access Grid calls these rules. Grid Core calls the same record a grant: who may use a
 *  credential, for what, and whether an approver has to agree each time. */
export function toGrant(rule: AccessRule, realmId: string): Grant {
  return {
    id: rule.id,
    realmId,
    credentialId: rule.credential,
    credentialName: rule.credentialName,
    who: rule.who,
    whoLabel: rule.whoLabel,
    methods: rule.methods,
    path: rule.path,
    decision: rule.decision,
    reveal: rule.reveal,
    expiresAt: rule.expiresAt,
    limit: rule.limit,
    note: rule.note,
    grantedBy: rule.createdBy,
    grantedAt: rule.createdAt,
  }
}

const APPROVAL_STATE_FROM_ACCESS: Record<AccessRequest["state"], ApprovalState> = {
  waiting: "waiting", running: "running", done: "granted", denied: "refused", failed: "failed",
}

export function toApproval(request: AccessRequest, realmId: string): Approval {
  return {
    id: request.id,
    realmId,
    action: request.kind === "reveal" ? "reveal a credential" : "use a credential",
    resourceId: request.credentialId,
    resource: request.credential,
    method: request.method ?? null,
    path: request.url ?? null,
    requestedBy: request.person,
    requestedAt: request.createdAt,
    expiresAt: request.expiresAt,
    state: APPROVAL_STATE_FROM_ACCESS[request.state],
    decidedBy: request.decidedBy,
    agent: request.agent,
    computer: request.computer,
    bodyBytes: request.bodyBytes,
    why: request.why,
  }
}

/** The Access Grid's activity line is the nearest thing any product has to an audit event. It
 *  carries no identifier of its own, so one is made from where it sits in the list; it is for a
 *  list key and nothing else. */
export function toAuditEvent(activity: AccessActivity, realmId: string, at: number): AuditEvent {
  return {
    id: `${activity.at}-${at}`,
    at: activity.at,
    realmId,
    principal: activity.person,
    agent: activity.agent,
    computer: activity.computer,
    action: activity.action,
    resource: activity.credential ?? activity.target,
    decision: activity.action === "deny" ? "refused" : "allowed",
    reason: activity.outcome,
  }
}

export function toAccessPrincipal(person: AccessPerson, realmId: string): Principal {
  return {
    id: person.id,
    realmId,
    kind: "person",
    name: person.name,
    username: person.username,
    email: person.email ?? null,
    roles: [ROLE_FROM_ACCESS[person.permission]],
    createdAt: person.createdAt,
    lastSeenAt: person.lastSeenAt,
    twoStep: person.twoStep,
    devices: person.devices.map(device => ({
      id: device.id,
      realmId,
      principalId: person.id,
      name: device.computer,
      platform: "",
      enrolledAt: device.createdAt,
      lastSeenAt: device.lastUsedAt,
      strong: device.strong,
    })),
  }
}

// ---- The table every legacy method is in ----

/** One row per method the four product modules export today. The replacement names what a page
 *  should call once it moves; the command is the engine command both of them reach, which does
 *  not change on the day this lands. `src/api/grids/compat.test.ts` fails when a row names a
 *  method that is not there, and `scripts/grid-client-docs.mjs` renders it into the guide. */
export interface LegacyRow { module: string; legacy: string; next: string; command: string }

export const LEGACY_METHODS: readonly LegacyRow[] = [
  { module: "grid-api", legacy: "gridApi.status", next: "grids.models.status", command: "grid_status" },
  { module: "grid-api", legacy: "gridApi.suggestedAddress", next: "grids.models.suggestedAddress", command: "grid_suggested_address" },
  { module: "grid-api", legacy: "gridApi.create", next: "grids.models.host", command: "grid_create" },
  { module: "grid-api", legacy: "gridApi.join", next: "grids.models.join", command: "grid_join" },
  { module: "grid-api", legacy: "gridApi.leave", next: "grids.models.leave", command: "grid_leave" },
  { module: "grid-api", legacy: "gridApi.delete", next: "grids.models.scheduleDeletion", command: "grid_delete" },
  { module: "grid-api", legacy: "gridApi.restore", next: "grids.models.restore", command: "grid_restore" },
  { module: "grid-api", legacy: "gridApi.addPlan", next: "grids.models.addPlan", command: "grid_plan_add" },
  { module: "grid-api", legacy: "gridApi.removePlan", next: "grids.models.removePlan", command: "grid_plan_remove" },
  { module: "grid-api", legacy: "gridApi.removeComputer", next: "grids.models.removeHost", command: "grid_member_remove" },
  { module: "grid-api", legacy: "gridApi.excludeComputer", next: "grids.models.drainHost", command: "grid_member_exclude" },
  { module: "grid-api", legacy: "gridApi.includeComputer", next: "grids.models.bringHostBack", command: "grid_member_include" },
  { module: "grid-api", legacy: "gridApi.rentedGpus", next: "grids.models.rentedGpus", command: "grid_neocloud_status" },
  { module: "grid-api", legacy: "gridApi.addRentedGpu", next: "grids.models.addRentedGpu", command: "grid_neocloud_add" },
  { module: "grid-api", legacy: "gridApi.removeRentedGpu", next: "grids.models.removeRentedGpu", command: "grid_neocloud_remove" },
  { module: "grid-api", legacy: "gridApi.stopRentedGpus", next: "grids.models.stopRentedGpus", command: "grid_neocloud_stop_all" },
  { module: "grid-api", legacy: "gridApi.addHarness", next: "grids.models.addHarness", command: "grid_swarm_add" },
  { module: "grid-api", legacy: "gridApi.removeHarness", next: "grids.models.removeHarness", command: "grid_swarm_remove" },
  { module: "grid-api", legacy: "gridApi.runHarness", next: "grids.models.runHarness", command: "grid_swarm_run" },

  { module: "desks-api", legacy: "desksApi.status", next: "grids.workspaces.status", command: "desks_status" },
  { module: "desks-api", legacy: "desksApi.manage", next: "grids.workspaces.manage", command: "desks_manage" },
  { module: "desks-api", legacy: "desksApi.suggestedAddress", next: "grids.workspaces.suggestedAddress", command: "desks_suggested_address" },
  { module: "desks-api", legacy: "desksApi.create", next: "grids.workspaces.host", command: "desks_create" },
  { module: "desks-api", legacy: "desksApi.join", next: "grids.workspaces.join", command: "desks_join" },
  { module: "desks-api", legacy: "desksApi.leave", next: "grids.workspaces.leave", command: "desks_leave" },
  { module: "desks-api", legacy: "desksApi.delete", next: "grids.workspaces.scheduleDeletion", command: "desks_delete" },
  { module: "desks-api", legacy: "desksApi.restore", next: "grids.workspaces.restore", command: "desks_restore" },
  { module: "desks-api", legacy: "desksApi.removeComputer", next: "grids.workspaces.removeHost", command: "desks_member_remove" },
  { module: "desks-api", legacy: "desksApi.setComputerShare", next: "grids.workspaces.setOffer", command: "desks_member_share" },
  { module: "desks-api", legacy: "desksApi.suggestComputerShare", next: "grids.workspaces.suggestOffer", command: "desks_member_share" },
  { module: "desks-api", legacy: "desksApi.addPerson", next: "grids.workspaces.addPerson", command: "desks_person_add" },
  { module: "desks-api", legacy: "desksApi.setPersonPassword", next: "grids.workspaces.setPersonPassword", command: "desks_person_password" },
  { module: "desks-api", legacy: "desksApi.removePerson", next: "grids.workspaces.removePerson", command: "desks_person_remove" },
  { module: "desks-api", legacy: "desksApi.addDesk", next: "grids.workspaces.order", command: "desks_add" },
  { module: "desks-api", legacy: "desksApi.assignDesk", next: "grids.workspaces.assign", command: "desks_assign" },
  { module: "desks-api", legacy: "desksApi.retryDesk", next: "grids.workspaces.retry", command: "desks_retry" },
  { module: "desks-api", legacy: "desksApi.removeDesk", next: "grids.workspaces.remove", command: "desks_remove" },
  { module: "desks-api", legacy: "desksApi.login", next: "grids.workspaces.signIn", command: "desk_login" },
  { module: "desks-api", legacy: "desksApi.loginSso", next: "grids.workspaces.signInSso", command: "desk_login" },
  { module: "desks-api", legacy: "desksApi.refreshDesk", next: "grids.workspaces.refresh", command: "desk_refresh" },
  { module: "desks-api", legacy: "desksApi.logout", next: "grids.workspaces.signOut", command: "desk_logout" },

  { module: "swarm-api", legacy: "swarmApi.workers", next: "grids.research.jobs", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.prompts", next: "grids.research.prompts", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.savePrompts", next: "grids.research.savePrompts", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.resetPrompts", next: "grids.research.resetPrompts", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.status", next: "grids.research.job", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.activity", next: "grids.research.steps", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.doctor", next: "grids.research.check", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.prepare", next: "grids.research.prepare", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.pause", next: "grids.research.pause", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.resume", next: "grids.research.resume", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.leave", next: "grids.research.stop", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.remove", next: "grids.research.remove", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.clearHistory", next: "grids.research.clearHistory", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.messages", next: "grids.research.messages", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.chat", next: "grids.research.say", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.reports", next: "grids.research.reports", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.submitReport", next: "grids.research.submitReport", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.offers", next: "grids.research.offers", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.skipOffer", next: "grids.research.skipOffer", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.accept", next: "grids.research.accept", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.rentedGpus", next: "grids.research.rentedGpus", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.stopRentedGpu", next: "grids.research.stopRentedGpu", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.stopRentedGpus", next: "grids.research.stopRentedGpus", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.bounties", next: "grids.research.board", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.practiceStart", next: "grids.research.closed.start", command: "swarm_dispatch" },
  { module: "swarm-api", legacy: "swarmApi.practiceStop", next: "grids.research.closed.stop", command: "swarm_dispatch" },

  { module: "bounty-api", legacy: "bountyApi.inspect", next: "grids.research.closed.inspect", command: "bounty_dispatch" },
  { module: "bounty-api", legacy: "bountyApi.host", next: "grids.research.closed.publish", command: "bounty_dispatch" },
  { module: "bounty-api", legacy: "bountyApi.connect", next: "grids.research.closed.connect", command: "bounty_dispatch" },
  { module: "bounty-api", legacy: "bountyApi.localConnect", next: "grids.research.closed.connectHere", command: "bounty_dispatch" },
  { module: "bounty-api", legacy: "bountyApi.discard", next: "grids.research.closed.discard", command: "bounty_dispatch" },
  { module: "bounty-api", legacy: "bountyApi.start", next: "grids.research.closed.begin", command: "bounty_dispatch" },
  { module: "bounty-api", legacy: "bountyApi.status", next: "grids.research.closed.status", command: "bounty_dispatch" },
  { module: "bounty-api", legacy: "bountyApi.suggestedAddress", next: "grids.research.closed.suggestedAddress", command: "bounty_suggested_address" },
  { module: "bounty-api", legacy: "bountyApi.removeMember", next: "grids.research.closed.removeHunter", command: "bounty_member_remove" },
  { module: "bounty-api", legacy: "bountyApi.remove", next: "grids.research.closed.unpublish", command: "bounty_delete" },
  { module: "bounty-api", legacy: "bountyApi.choosePath", next: "grids.research.closed.choosePath", command: "plugin-dialog" },

  { module: "access-api", legacy: "accessApi.status", next: "grids.credentials.status", command: "access_status" },
  { module: "access-api", legacy: "accessApi.create", next: "grids.credentials.host", command: "access_create" },
  { module: "access-api", legacy: "accessApi.delete", next: "grids.credentials.scheduleDeletion", command: "access_delete" },
  { module: "access-api", legacy: "accessApi.restore", next: "grids.credentials.restore", command: "access_restore" },
  { module: "access-api", legacy: "accessApi.signIn", next: "grids.credentials.signIn", command: "access_signin" },
  { module: "access-api", legacy: "accessApi.signInSso", next: "grids.credentials.signInSso", command: "access_signin" },
  { module: "access-api", legacy: "accessApi.signOut", next: "grids.credentials.signOut", command: "access_signout" },
  { module: "access-api", legacy: "accessApi.manage", next: "grids.credentials.manage", command: "access_manage" },
  { module: "access-api", legacy: "accessApi.account", next: "grids.credentials.account", command: "access_account" },
  { module: "access-api", legacy: "accessApi.backup", next: "grids.credentials.backup", command: "access_backup" },
  { module: "access-api", legacy: "accessApi.restoreBackup", next: "grids.credentials.restoreBackup", command: "access_restore_backup" },
]
