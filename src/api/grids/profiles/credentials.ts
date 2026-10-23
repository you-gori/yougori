/** The credentials profile: the Access Grid, in Grid Core's words.
 *
 *  This profile calls `accessApi` and never an `access_*` command string. That module belongs
 *  to another part of the work and is not changed here, so everything below is a wrapper around
 *  what it already offers, and the profile can offer nothing that it does not.
 *
 *  Redaction: answers that come back through `accessApi` do not pass through `call()`, so the
 *  shared pass never sees them. Rather than leave the one grid that actually holds secrets
 *  uncovered, every answer is handed to `scrub` here, explicitly, before it is returned. A page
 *  that calls `accessApi` itself still bypasses it, and that is the honest limit of this.
 */
import { accessApi, type AccessMe, type AccessOverview, type AccessResult, type AccessStatus } from "@/api/access-api"
import {
  toAccessMembership, toAccessPrincipal, toApproval, toAuditEvent, toCredential, toCredentialsHub, toGrant,
} from "@/api/grids/compat"
import { guard, may, ROLE_FROM_ACCESS, type Held } from "@/api/grids/permits"
import { mentions, paginate, where, type ApprovalFilter, type AuditFilter, type CredentialFilter, type GrantFilter, type Page, type PageRequest } from "@/api/grids/page"
import { scrub, type FieldPolicy } from "@/api/grids/redact"
import { readInvite, tunnelOf } from "@/api/grids/profiles/shared"
import { cliOnly } from "@/api/grids/wire"
import type {
  Action, Approval, AuditCheck, AuditEvent, Credential, CredentialsStatus, DeleteWhen, Grant, Me, Principal, Reach, Verdict,
} from "@/api/grids/types"

/** What the Access Grid answers with that a person has to be able to read in full, and what is
 *  somebody else's document. The value of a credential is never in an answer at all; `hint` is
 *  its last four characters and the pages render it. */
const POLICY: FieldPolicy = {
  keep: ["hint", "note", "reason", "why", "outcome", "bodyPreview", "whoLabel", "path", "field"],
  opaque: ["config", "target"],
  urls: ["url"],
}

const guardAnswer = <T>(answer: T, command: string): T => scrub(answer, POLICY, command)

let held: Held = { roles: ["realmAdmin"], capabilities: ["credentials"] }

function toMe(me: AccessMe): Me {
  return {
    principal: toAccessPrincipal(me.person, me.accessId),
    realmId: me.accessId,
    realm: me.company,
    deviceId: me.device,
    signedInAt: me.person.lastSeenAt ?? me.person.createdAt,
    strong: me.strong,
    blocked: me.blocked,
  }
}

const overviewOf = (status: AccessStatus): AccessOverview | null => status.me?.overview ?? null

export function toCredentialsStatus(status: AccessStatus): CredentialsStatus {
  const safe = guardAnswer(status, "access_status")
  const hub = safe.hub
  const member = safe.member
  const me = safe.me
  const realmId = hub?.id ?? member?.accessId ?? me?.accessId ?? ""
  const overview = overviewOf(safe)
  return {
    profile: "credentials",
    hub: hub ? toCredentialsHub(hub) : null,
    hubError: safe.hubError,
    member: member ? toAccessMembership(member) : null,
    memberError: safe.memberError,
    me: me ? toMe(me) : null,
    credentials: (overview?.credentials ?? []).map(credential => toCredential(credential, realmId)),
    grants: (overview?.rules ?? []).map(rule => toGrant(rule, realmId)),
    waiting: (overview?.waiting ?? me?.requests ?? []).map(request => toApproval(request, realmId)),
    mcp: safe.mcp,
  }
}

const read = () => accessApi.status().then(status => {
  const permission = status.me?.person.permission
  held = { roles: permission ? [ROLE_FROM_ACCESS[permission]] : ["realmAdmin"], capabilities: ["credentials"] }
  return toCredentialsStatus(status)
})

const manage = (action: string, request: Record<string, unknown> = {}) =>
  accessApi.manage({ action, ...request }).then(answer => guardAnswer(answer, `access_manage ${action}`))

export const credentials = {
  /** The hub, this person's sign-in, and everything they may see. @via accessApi.status */
  status: read,

  /** What the client believes the person signed in here may do. The hub decides for real.
   *  @local */
  who: (): Held => held,
  /** Whether a control is worth offering. Never the decision itself. @local */
  may: (action: Action) => may(held, action),

  /** This computer's private network address to host on. @via accessApi.status */
  suggestedAddress: () => accessApi.status().then(status => status.suggestedAddress),

  /** Starts the hub on this computer, with its first administrator.
   *  @via accessApi.create */
  host: (company: string, address: string, admin: { username: string; name: string; password: string }, reach: Reach = "network") =>
    accessApi.create(company, address, admin.username, admin.name, admin.password, tunnelOf(reach) ?? undefined).then(toCredentialsStatus),

  /** `later` pauses the grid for three days and is restorable, `now` deletes it, `forget`
   *  removes it from this computer. @via accessApi.delete */
  scheduleDeletion: (when: DeleteWhen = "later") => {
    guard(held, "manageCredentials", "access_delete")
    return accessApi.delete(when)
  },

  /** @via accessApi.restore */
  restore: () => accessApi.restore(),

  /** @via accessApi.signIn */
  signIn: (invite: string, username: string, password: string, code?: string) =>
    accessApi.signIn(invite, username, password, code).then(toCredentialsStatus),

  /** @via accessApi.signInSso */
  signInSso: (invite: string) => accessApi.signInSso(invite).then(toCredentialsStatus),

  /** @via accessApi.signOut */
  signOut: () => accessApi.signOut(),

  /** The people in this grid. @via accessApi.status */
  people: async (page: PageRequest = {}): Promise<Page<Principal>> => {
    const status = await accessApi.status()
    const realmId = status.hub?.id ?? status.me?.accessId ?? ""
    const people = (overviewOf(guardAnswer(status, "access_status"))?.people ?? []).map(person => toAccessPrincipal(person, realmId))
    return paginate(people, page, person => person.id)
  },

  /** The credentials this grid holds. Never their values. @via accessApi.status */
  list: async (filter: CredentialFilter = {}, page: PageRequest = {}): Promise<Page<Credential>> => {
    const status = await read()
    const tests = [
      (credential: Credential) => filter.ownerId === undefined || credential.ownerId === filter.ownerId,
      (credential: Credential) => mentions(filter.search, credential.name, credential.note, ...credential.destinations),
    ]
    return paginate(where(status.credentials, tests), page, credential => credential.id)
  },

  /** Adds one. The value is handed straight to the hub, which puts it in the vault; it is
   *  never written to a log, a prompt or this client's own state. @via accessApi.manage */
  add: (credential: { name: string; shape: string; field?: string; destinations: string[]; value: string; note?: string; config?: Record<string, string | number> }) => {
    guard(held, "manageCredentials", "access_manage credentialAdd")
    return manage("credentialAdd", {
      name: credential.name, kind: credential.shape, field: credential.field ?? "",
      destinations: credential.destinations, value: credential.value, note: credential.note ?? "",
      ...(credential.config ? { config: credential.config } : {}),
    })
  },

  /** Replaces the value behind a credential, leaving every rule in place.
   *  @via accessApi.manage */
  rotate: (credentialId: string, value: string) => {
    guard(held, "manageCredentials", "access_manage credentialUpdate")
    return manage("credentialUpdate", { credential: credentialId, value })
  },

  /** @via accessApi.manage */
  retire: (credentialId: string) => {
    guard(held, "manageCredentials", "access_manage credentialRemove")
    return manage("credentialRemove", { credential: credentialId })
  },

  /** Who may use a credential, for what. @via accessApi.status */
  grants: async (filter: GrantFilter = {}, page: PageRequest = {}): Promise<Page<Grant>> => {
    const status = await read()
    const tests = [
      (grant: Grant) => filter.credentialId === undefined || grant.credentialId === filter.credentialId,
      (grant: Grant) => filter.who === undefined || grant.who === filter.who,
    ]
    return paginate(where(status.grants, tests), page, grant => grant.id)
  },

  /** @via accessApi.manage */
  allow: (grant: { credentialId: string; who: string; methods: string[]; path: string; decision: Grant["decision"]; reveal?: boolean; hours?: number; limit?: number }) => {
    guard(held, "manageCredentials", "access_manage ruleAdd")
    return manage("ruleAdd", {
      credential: grant.credentialId, who: grant.who, methods: grant.methods, path: grant.path,
      decision: grant.decision, reveal: grant.reveal ?? false,
      ...(grant.hours ? { hours: grant.hours } : {}), ...(grant.limit ? { limit: grant.limit } : {}),
    })
  },

  /** @via accessApi.manage */
  takeBack: (grantId: string) => {
    guard(held, "manageCredentials", "access_manage ruleRemove")
    return manage("ruleRemove", { rule: grantId })
  },

  /** What waits for an approver. @via accessApi.status */
  waiting: async (filter: ApprovalFilter = {}, page: PageRequest = {}): Promise<Page<Approval>> => {
    const status = await read()
    const tests = [
      (approval: Approval) => !filter.state || filter.state.includes(approval.state),
      (approval: Approval) => filter.requestedBy === undefined || approval.requestedBy === filter.requestedBy,
      (approval: Approval) => filter.credentialId === undefined || approval.resourceId === filter.credentialId,
    ]
    return paginate(where(status.waiting, tests), page, approval => approval.id)
  },

  /** Agrees to a request, agrees for a while, or refuses with a reason.
   *  @via accessApi.manage */
  decide: (approvalId: string, verdict: Verdict) => {
    guard(held, "approveCredential", "access_manage decide")
    if (verdict.kind === "denied") return manage("decide", { request: approvalId, approve: false, reason: verdict.reason })
    return manage("decide", { request: approvalId, approve: true, ...(verdict.kind === "hours" ? { hours: verdict.hours } : {}) })
  },

  /** What was decided and used, most recent first. @via accessApi.status */
  history: async (filter: AuditFilter = {}, page: PageRequest = {}): Promise<Page<AuditEvent>> => {
    const status = await accessApi.status()
    const realmId = status.hub?.id ?? status.me?.accessId ?? ""
    const events = (overviewOf(guardAnswer(status, "access_status"))?.activity ?? [])
      .map((activity, at) => toAuditEvent(activity, realmId, at))
    const tests = [
      (event: AuditEvent) => filter.action === undefined || event.action === filter.action,
      (event: AuditEvent) => filter.principal === undefined || event.principal === filter.principal,
      (event: AuditEvent) => filter.decision === undefined || event.decision === filter.decision,
      (event: AuditEvent) => filter.since === undefined || event.at >= filter.since,
      (event: AuditEvent) => filter.until === undefined || event.at <= filter.until,
    ]
    return paginate(where(events, tests), page, event => event.id)
  },

  /** Whether the history is whole, and where it first breaks if it is not.
   *  @via accessApi.manage */
  verifyHistory: async (): Promise<AuditCheck> => {
    const answer = await manage("activityVerify") as AccessResult & { ok?: boolean; brokenAt?: number; reason?: string; entries?: number }
    return {
      whole: answer.ok === true,
      brokenAt: answer.brokenAt ?? null,
      message: answer.ok === true
        ? `All ${answer.entries ?? 0} entries are whole and in order.`
        : answer.reason ?? "The history has been altered since it was written.",
    }
  },

  /** @via accessApi.backup */
  backup: (output: string, passphrase: string) => {
    guard(held, "manageSecurity", "access_backup")
    return accessApi.backup(output, passphrase)
  },

  /** @via accessApi.restoreBackup */
  restoreBackup: (file: string, passphrase: string, address: string) =>
    accessApi.restoreBackup(file, passphrase, address).then(toCredentialsStatus),

  /** The signed-in person's own account.
   *
   *  These answers are deliberately not handed to the redaction pass. Turning on two-step
   *  sign-in answers with the very thing the person has to scan into their authenticator app,
   *  under a field name the pass would replace. Hiding it from them would not make anything
   *  safer; it would stop them setting up two-step at all.
   *  @via accessApi.account */
  account: {
    /** Begins turning on two-step sign-in, and answers with what to scan. @via accessApi.account */
    twoStepStart: () => accessApi.account({ action: "twoStepStart" }),
    /** @via accessApi.account */
    twoStepConfirm: (code: string) => accessApi.account({ action: "twoStepConfirm", code }),
    /** @via accessApi.account */
    twoStepOff: (code: string) => accessApi.account({ action: "twoStepOff", code }),
    /** @via accessApi.account */
    changePassword: (password: string, code?: string) => accessApi.account({ action: "password", password, ...(code ? { code } : {}) }),
    /** Ends this person's sign-in on every other computer. @via accessApi.account */
    signOutOthers: () => accessApi.account({ action: "signOutOthers" }),
    /** @via accessApi.account */
    forgetDevice: (deviceId: string) => accessApi.account({ action: "deviceForget", device: deviceId }),
  },

  /** The door the Access Grid already has, for an action this profile has not named yet.
   *  @via accessApi.manage */
  manage: (request: { action: string } & Record<string, unknown>) => {
    const { action, ...rest } = request
    return manage(action, rest)
  },

  /** Using a credential, checking a request and revealing a value happen on the local wire and
   *  have no desktop command at all, so the desktop cannot offer them whatever this says.
   *  @command access_use */
  use: (): never => cliOnly("access_use", "yougori access use CREDENTIAL URL"),
  /** @command access_check */
  check: (): never => cliOnly("access_check", "yougori access check REQUEST_ID"),
  /** @command access_reveal */
  reveal: (): never => cliOnly("access_reveal", "yougori access use CREDENTIAL URL"),

  /** The company an invite names. @local */
  readInvite: (code: string) => readInvite("credentials", code),
}
