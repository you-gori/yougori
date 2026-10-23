import { call } from "@/api/grids/wire"
import { DESKTOP_ONLY, readInvite } from "@/api/grids/profiles/shared"
import { type GridComputer } from "@/api/grid-api"
import type { DeleteWhen, GridClosing } from "@/lib/grid-closing"

/** What a computer has and is using right now. How much of it the grid may take is the admin's
 *  to set (`DeskShare`); a computer someone is using still hosts desks within its share. */
export interface DesksCapacity {
  cpu: number
  /** Of the whole computer, 0–100. */
  cpuUsedPercent: number
  memoryGb: number
  usedMemoryGb: number
  freeDiskGb: number
  gpu: boolean
  gpuUsedPercent?: number | null
  onBattery: boolean
  /** Someone used its keyboard or mouse in the last few minutes. */
  inUse: boolean
}

/** What the grid may take from a computer for desks, whether or not its person is using it. */
export interface DeskShare {
  cpu: number
  memoryGb: number
  diskGb: number
  gpu: boolean
  /** Take desks only while nobody is using the computer. */
  idleOnly: boolean
}

export type DeskKind = "container" | "microVm" | "vm"

export interface DeskSpec { kind: DeskKind; cpu: number; memoryGb: number; diskGb: number; gpu: boolean; image: string }

/** A sandbox the admin ordered for a person, hosted on a company computer within its share. */
export interface Desk {
  id: string
  name: string
  spec: DeskSpec
  /** Restricted: a full VM without network, desktop and inbound uploads only. */
  access?: DeskAccess
  roleId?: string | null
  summary: string
  personId: string | null
  person: string | null
  username: string | null
  state: "planned" | "building" | "ready" | "failed" | "moving"
  /** While moving: the computer that still holds its data and is packing it up. */
  movingFrom?: string | null
  /** How much data is packed and waiting for its new computer. */
  parcelBytes?: number | null
  note: string
  hostId: string | null
  host: string | null
  hostOnline: boolean
  /** Ready, its computer online and a share invitation live: its person can open it now. */
  reachable: boolean
  environmentId: string | null
  attempts: number
  createdAt: number
  updatedAt: number
}

/** Someone who signs in to open their desk. */
export interface DeskPerson {
  id: string
  /** Two-step sign-in is on for them. */
  mfa?: boolean
  email?: string | null
  adminRole?: AdminRole
  roleId?: string | null
  username: string
  name: string
  createdAt: number
  lastLoginAt: number | null
  desks: string[]
}

export interface NewDesk { name: string; person?: string | null; kind: DeskKind; cpu: number; memoryGb: number; diskGb: number; gpu: boolean; image?: string | null }

/** A computer that joined the sandbox grid: what it has, what the grid may take, and how many desks it holds. */
export interface DesksComputer extends GridComputer {
  capacity?: DesksCapacity | null
  /** The admin's share, or the suggestion in force until they set one. */
  share?: DeskShare | null
  shareSet?: boolean
  desks?: number
}

/** The sandbox grid hosted on this computer. */
export interface DesksHub {
  id: string
  name: string
  address: string
  port: number
  fingerprint: string
  createdAt: string
  computers: { total: number; capable: number; online: number }
  members: DesksComputer[]
  desks: Desk[]
  people: DeskPerson[]
  tunnel?: { kind: "quick" | "domain"; domain: string | null; url: string | null; connected: boolean; error: string | null }
  /** Shared with company computers to join; it carries no secret. */
  invite?: string
  /** Its admin is deleting it: paused until a time, then gone. */
  closing?: GridClosing | null
}

/** The cloud computers this computer's grid created on its own: how many still run, why the last
 *  attempt failed and when the next may start, and what the admin should know about the rest.
 *  It outlives the grid, so a computer still costing money is never out of sight. */
export interface CloudComputers {
  /** Null when the record of them could not be read. */
  computers: number | null
  error: string | null
  note: string | null
  retryAfter: number | null
  /** Nothing is created until a deployment is inspected and deleted. */
  held: boolean
}

/** This computer's place in a sandbox grid someone else hosts. */
export interface DesksMembership {
  gridId: string
  grid: string
  hub: string
  fingerprint: string
  memberId: string
  joinedAt: number
  connected: boolean
  error: string | null
  /** Desks the hub currently orders from this computer. */
  orders: number
  /** Its admin scheduled the grid for deletion at this time; until then its desks are stopped. */
  pausedUntil?: number | null
  /** The hub has not answered since this time. */
  unreachableSince?: number | null
}

/** A desk this computer hosts for the grid's people. */
export interface HostedDesk { id: string; name: string; environmentId: string; shared: boolean }

/** This computer's person, signed in to their sandbox grid, and their desks. */
export interface DeskLogin {
  adminRole?: AdminRole
  /** Two-step sign-in is on for this person. */
  mfa?: boolean
  connections?: EnterpriseConnection[]
  gridId: string
  grid: string
  username: string
  personId: string
  name: string
  signedInAt: number
  desks: Array<{ id: string; name: string; state: string; note: string; host: string | null; environmentId: string | null; address: string | null }>
}

export interface DesksStatus {
  hub: DesksHub | null
  hubError: string | null
  member: DesksMembership | null
  memberError: string | null
  hosting: HostedDesk[]
  desk: DeskLogin | null
  cloudFallback?: CloudComputers | null
  message?: string
}

/** What a change reports; the page always reads the status again afterwards. */
export interface DesksResult { message?: string; warning?: string | null }

const empty: DesksStatus = { hub: null, hubError: null, member: null, memberError: null, hosting: [], desk: null }
const desktop = DESKTOP_ONLY.workspaces
/** The admin answer carries somebody else's connector settings and a desk's own target. */
const admin = { opaque: ["target", "enterprise"] }
/** Turning on two-step answers with the new authenticator key, which the person must read to
 *  type into their app. Only that answer keeps it; every other answer is still redacted. */
const enrol = { ...admin, keep: ["secret", "otpauth"] }

/** The Sandbox Grid's own surface, unchanged, now going through the one call path in
 *  `@/api/grids/wire`. The types above stay declared here: a desk that is building or moving
 *  has no state of its own in Grid Core, and a desk sign-in carries the person's desks and
 *  their connections, which a core principal does not. `grids.workspaces` is the same grid in
 *  Grid Core's words, with the conversion written down in `@/api/grids/compat`. */
export const desksApi = {
  manage: <T = EnterpriseStatus>(request: Record<string, unknown>) => call<T>("desks_manage", { request }, { desktop, policy: request.action === "mfaEnroll" ? enrol : admin }),
  status: () => call<DesksStatus>("desks_status", {}, { browser: () => empty, desktop }),
  suggestedAddress: () => call<string | null>("desks_suggested_address", {}, { browser: () => null, desktop }),
  create: (name: string, address: string, password: string, reach: "network" | "quick" = "network") => call<DesksStatus>("desks_create", { name, address, password, tunnel: reach === "quick" ? "quick" : null }, { desktop }),
  join: (invite: string, password: string, name?: string) => call<DesksStatus>("desks_join", { invite, password, name: name || null }, { desktop }),
  leave: () => call<DesksResult>("desks_leave", {}, { desktop }),
  /** `later` pauses the grid for three days (restorable), `now` deletes it, `forget` stops waiting for computers. */
  delete: (when: DeleteWhen = "later") => call<DesksResult>("desks_delete", { when }, { desktop }),
  restore: () => call<DesksResult>("desks_restore", {}, { desktop }),
  removeComputer: (memberId: string) => call<DesksResult>("desks_member_remove", { memberId }, { desktop }),
  setComputerShare: (memberId: string, share: DeskShare) => call<DesksResult>("desks_member_share", { memberId, cpu: share.cpu, memoryGb: share.memoryGb, diskGb: share.diskGb, gpu: share.gpu, idleOnly: share.idleOnly }, { desktop }),
  suggestComputerShare: (memberId: string) => call<DesksResult>("desks_member_share", { memberId, suggested: true }, { desktop }),
  /** Adds a person and, with `desk`, orders their desk (named after them) in the same step. */
  addPerson: (username: string, name: string, password: string, desk?: { kind?: DeskKind; cpu: number; memoryGb: number; diskGb: number; gpu: boolean }) =>
    call<DeskPerson & { desk?: Desk }>("desks_person_add", { username, name, password, kind: desk?.kind ?? null, cpu: desk?.cpu ?? null, memoryGb: desk?.memoryGb ?? null, diskGb: desk?.diskGb ?? null, gpu: desk?.gpu ?? null }, { desktop }),
  setPersonPassword: (person: string, password: string) => call<DesksResult>("desks_person_password", { person, password }, { desktop }),
  removePerson: (person: string) => call<DesksResult>("desks_person_remove", { person }, { desktop }),
  addDesk: (desk: NewDesk) => call<Desk>("desks_add", { name: desk.name, person: desk.person ?? null, kind: desk.kind, cpu: desk.cpu, memoryGb: desk.memoryGb, diskGb: desk.diskGb, gpu: desk.gpu, image: desk.image ?? null }, { desktop }),
  assignDesk: (desk: string, person: string | null) => call<Desk>("desks_assign", { desk, person }, { desktop }),
  retryDesk: (desk: string) => call<Desk>("desks_retry", { desk }, { desktop }),
  removeDesk: (desk: string) => call<DesksResult>("desks_remove", { desk }, { desktop }),
  refreshDesk: () => call<DeskLogin>("desk_refresh", {}, { desktop }),
  /** With two-step sign-in on, the hub answers "Enter the code from your authenticator app" until `code` is given. */
  login: (invite: string, username: string, password: string, code?: string) => call<DeskLogin>("desk_login", { invite, username, password, code: code || null }, { desktop }),
  /** The company's identity provider signs the person in: the browser opens on it and comes back. */
  loginSso: (invite: string) => call<DeskLogin>("desk_login", { invite, sso: true }, { desktop }),
  logout: () => call<DesksResult>("desk_logout", {}, { desktop }),
}

/** The company a sandbox grid invite names, read locally so a mistyped code is caught early. */
export function readDeskInvite(code: string): { company: string; address: string; fingerprint: string } | null {
  return readInvite("workspaces", code)
}

export type AdminRole = "user" | "auditor" | "operator" | "administrator"
export type DeskAccess = "standard" | "restricted"
export type EnterpriseProvider = "citrix" | "azureVirtualDesktop" | "windows365" | "horizon"
export interface DeskImage { id: string; name: string; version: string; description: string; applications: string[]; spec: DeskSpec; sha256: string | null; createdAt: number }
export interface WorkspaceRole { id: string; name: string; description: string; imageId: string; access: DeskAccess; createdAt: number }
export interface EnterpriseConnection { id: string; name: string; provider: EnterpriseProvider; url: string; roleIds: string[]; target?: Record<string, string>; credentialSet?: boolean; credentialAt?: number | null }
/** What a connector was asked to do for a person, and how it went. */
export interface ProvisioningTask { id: string; connectionId: string; want: "assign" | "revoke" | "test"; personId?: string | null; personName?: string; email?: string; state: "pending" | "running" | "done" | "failed"; note?: string; at: number; finishedAt?: number | null }
export interface SsoSettings { issuer: string; clientId: string; usernameClaim?: string; passwordless?: boolean; setAt?: number }
export interface ParkingSettings { provider: "awsS3" | "s3Compatible"; location: string; setAt?: number }
export interface CloudFallbackSettings { enabled: boolean; provider: "aws" | "azure" | "google"; account: string; region: string; image: string; imageProject?: string; machineType: string; subnet: string; securityGroup?: string; keyPair?: string; resourceGroup?: string; sshPublicKey?: string; username: string; identityFile: string; maxComputers: number; setAt?: number }
export interface EnterpriseStatus {
  id: string; name: string; actor: string; adminRole: AdminRole;
  people: DeskPerson[]; desks: (Desk & { access: DeskAccess; roleId: string | null })[];
  members: { id: string; name: string; online: boolean; capacity: DesksCapacity | null; share: DeskShare | null; desks: number }[];
  enterprise: { images: DeskImage[]; roles: WorkspaceRole[]; connections: EnterpriseConnection[]; computerLimit: number | null; audit: { at: number; actor: string; action: string; subject: string }[]; sso?: SsoSettings | null; parking?: ParkingSettings | null; cloudFallback?: CloudFallbackSettings | null; provisioning?: ProvisioningTask[] }
}
