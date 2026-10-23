/** The workspaces profile: the Sandbox Grid, in Grid Core's words.
 *
 *  A desk is a workspace, a person is a principal, and a computer's share is what it offers.
 *  Two of the Sandbox Grid's five desk states have no state of their own in Grid Core, so every
 *  workspace here also carries the product's own word; `@/api/grids/compat` holds the table.
 */
import type {
  Desk, DeskKind, DeskLogin, DeskPerson, DesksResult, DesksStatus, EnterpriseStatus, NewDesk,
} from "@/api/desks-api"
import { toDeskHostStatus, toDeskPrincipal, toDesksMembership, toWorkspace, toWorkspacesHub } from "@/api/grids/compat"
import { guard, HOST_ROLES, MEMBER_ROLES, may, ROLE_FROM_DESKS, type Held } from "@/api/grids/permits"
import { mentions, paginate, where, type HostFilter, type Page, type PageRequest, type PersonFilter, type WorkspaceFilter } from "@/api/grids/page"
import { DESKTOP_ONLY, readInvite, tunnelOf } from "@/api/grids/profiles/shared"
import { call } from "@/api/grids/wire"
import type {
  Action, CallOptions, DeleteWhen, HostStatus, Me, NewWorkspace, Principal, Reach, Resources, Workspace, WorkspacesStatus,
} from "@/api/grids/types"

const EMPTY: DesksStatus = { hub: null, hubError: null, member: null, memberError: null, hosting: [], desk: null }

/** What the client last learned about whoever is asking. The Sandbox Grid does tell it: a
 *  signed-in person carries an admin role. Without a sign-in the client assumes the computer
 *  that runs the hub may administer it, and the hub refuses if it may not. */
let held: Held = { roles: HOST_ROLES, capabilities: ["workspaces"] }

function toMe(login: DeskLogin): Me {
  const principal: Principal = {
    id: login.personId,
    realmId: login.gridId,
    kind: "person",
    name: login.name,
    username: login.username,
    roles: [ROLE_FROM_DESKS[login.adminRole ?? "user"]],
    createdAt: login.signedInAt,
    twoStep: login.mfa,
  }
  return { principal, realmId: login.gridId, realm: login.grid, deviceId: null, signedInAt: login.signedInAt, strong: login.mfa ?? false }
}

export function toWorkspacesStatus(status: DesksStatus): WorkspacesStatus {
  const hub = status.hub
  const member = status.member
  const login = status.desk
  const realmId = hub?.id ?? member?.gridId ?? login?.gridId ?? ""
  return {
    profile: "workspaces",
    hub: hub ? toWorkspacesHub(hub) : null,
    hubError: status.hubError,
    member: member ? toDesksMembership(member) : null,
    memberError: status.memberError,
    me: login ? toMe(login) : null,
    hosts: hub ? hub.members.map(computer => toDeskHostStatus(computer, realmId)) : [],
    people: hub ? hub.people.map(person => toDeskPrincipal(person, realmId)) : [],
    workspaces: hub ? hub.desks.map(desk => toWorkspace(desk, realmId)) : [],
    hosting: status.hosting,
    mine: login?.desks ?? [],
    connections: (login?.connections ?? []).map(connection => ({ id: connection.id, name: connection.name, provider: connection.provider, url: connection.url })),
    orders: member?.orders ?? null,
    message: status.message,
  }
}

const read = () => call<DesksStatus>("desks_status", {}, { browser: () => EMPTY, desktop: DESKTOP_ONLY.workspaces })
  .then(status => {
    held = {
      roles: status.desk ? [ROLE_FROM_DESKS[status.desk.adminRole ?? "user"]] : status.hub ? HOST_ROLES : MEMBER_ROLES,
      capabilities: ["workspaces"],
    }
    return toWorkspacesStatus(status)
  })

const change = (command: string, args: Record<string, unknown> = {}, options?: CallOptions) =>
  call<DesksResult>(command, args, { ...options, desktop: DESKTOP_ONLY.workspaces })

/** What the share of a computer is offered as. */
export type Offer = Pick<Resources, "cpu" | "memoryGb" | "diskGb" | "gpu"> & { idleOnly: boolean }

export const workspaces = {
  /** The hub, this computer's membership, what it hosts, and the person signed in here.
   *  @command desks_status */
  status: read,

  /** What the client believes the person signed in here may do. The hub decides for real.
   *  @local */
  who: (): Held => held,
  /** Whether a control is worth offering. Never the decision itself. @local */
  may: (action: Action) => may(held, action),

  /** This computer's private network address to host on. @command desks_suggested_address */
  suggestedAddress: () => call<string | null>("desks_suggested_address", {}, { browser: () => null, desktop: DESKTOP_ONLY.workspaces }),

  /** Starts the hub on this computer. @command desks_create */
  host: (name: string, address: string, password: string, reach: Reach = "network") => {
    guard(held, "manageWorkspaces", "desks_create")
    return call<DesksStatus>("desks_create", { name, address, password, tunnel: tunnelOf(reach) }, { desktop: DESKTOP_ONLY.workspaces }).then(toWorkspacesStatus)
  },

  /** @command desks_join */
  join: (invite: string, password: string, name?: string) =>
    call<DesksStatus>("desks_join", { invite, password, name: name || null }, { desktop: DESKTOP_ONLY.workspaces }).then(toWorkspacesStatus),

  /** @command desks_leave */
  leave: () => change("desks_leave"),

  /** `later` pauses the grid for three days and is restorable, `now` deletes it, `forget` stops
   *  waiting for computers that are away. @command desks_delete */
  scheduleDeletion: (when: DeleteWhen = "later") => {
    guard(held, "manageWorkspaces", "desks_delete")
    return change("desks_delete", { when })
  },

  /** @command desks_restore */
  restore: () => change("desks_restore"),

  /** A computer the hub itself made takes up a membership that was prepared for it.
   *  @command desks_adopt_membership */
  adoptMembership: (membership: unknown) => change("desks_adopt_membership", { membership }),

  /** The computers in this grid. Asking for no page asks for all of them. @command desks_status */
  hosts: async (filter: HostFilter = {}, page: PageRequest = {}): Promise<Page<HostStatus>> => {
    const status = await read()
    const tests = [
      (host: HostStatus) => filter.online === undefined || host.online === filter.online,
      (host: HostStatus) => filter.excluded === undefined || host.excluded === filter.excluded,
      (host: HostStatus) => mentions(filter.search, host.name, host.address),
    ]
    return paginate(where(status.hosts, tests), page, host => host.id)
  },

  /** @command desks_member_remove */
  removeHost: (hostId: string) => change("desks_member_remove", { memberId: hostId }),

  /** What the grid may take from a computer, whether or not its person is using it.
   *  @command desks_member_share */
  setOffer: (hostId: string, offer: Offer) => {
    guard(held, "manageWorkspaces", "desks_member_share")
    return change("desks_member_share", { memberId: hostId, cpu: offer.cpu, memoryGb: offer.memoryGb, diskGb: offer.diskGb, gpu: offer.gpu, idleOnly: offer.idleOnly })
  },

  /** Puts the suggestion back in force. @command desks_member_share */
  suggestOffer: (hostId: string) => change("desks_member_share", { memberId: hostId, suggested: true }),

  /** The people who sign in to open a workspace. @command desks_status */
  people: async (filter: PersonFilter = {}, page: PageRequest = {}): Promise<Page<Principal>> => {
    const status = await read()
    const tests = [
      (person: Principal) => !filter.role || person.roles.includes(filter.role as Principal["roles"][number]),
      (person: Principal) => mentions(filter.search, person.name, person.username),
    ]
    return paginate(where(status.people, tests), page, person => person.id)
  },

  /** Adds a person and, with `workspace`, orders their first one in the same step. The password
   *  is an argument of the engine command and is never written anywhere by this client.
   *  @command desks_person_add */
  addPerson: (person: { username: string; name: string; password: string; workspace?: { kind?: DeskKind; cpu: number; memoryGb: number; diskGb: number; gpu: boolean } }) => {
    guard(held, "managePeople", "desks_person_add")
    const made = person.workspace
    return call<DeskPerson & { desk?: Desk }>("desks_person_add", {
      username: person.username, name: person.name, password: person.password,
      kind: made?.kind ?? null, cpu: made?.cpu ?? null, memoryGb: made?.memoryGb ?? null, diskGb: made?.diskGb ?? null, gpu: made?.gpu ?? null,
    }, { desktop: DESKTOP_ONLY.workspaces })
  },

  /** @command desks_person_password */
  setPersonPassword: (principalId: string, password: string) => {
    guard(held, "managePeople", "desks_person_password")
    return change("desks_person_password", { person: principalId, password })
  },

  /** @command desks_person_remove */
  removePerson: (principalId: string) => {
    guard(held, "managePeople", "desks_person_remove")
    return change("desks_person_remove", { person: principalId })
  },

  /** The workspaces this grid holds. @command desks_status */
  list: async (filter: WorkspaceFilter = {}, page: PageRequest = {}): Promise<Page<Workspace>> => {
    const status = await read()
    const tests = [
      (workspace: Workspace) => !filter.state || filter.state.includes(workspace.state),
      (workspace: Workspace) => filter.ownerId === undefined || workspace.ownerId === filter.ownerId,
      (workspace: Workspace) => filter.hostId === undefined || workspace.hostId === filter.hostId,
      (workspace: Workspace) => mentions(filter.search, workspace.name, workspace.owner, workspace.host),
    ]
    return paginate(where(status.workspaces, tests), page, workspace => workspace.id)
  },

  /** Orders one. @command desks_add */
  order: (workspace: NewWorkspace) => {
    guard(held, "manageWorkspaces", "desks_add")
    const desk: NewDesk = {
      name: workspace.name, person: workspace.ownerId ?? null, kind: workspace.kind,
      cpu: workspace.shape.cpu, memoryGb: workspace.shape.memoryGb, diskGb: workspace.shape.diskGb,
      gpu: workspace.shape.gpu, image: workspace.image ?? null,
    }
    return call<Desk>("desks_add", { ...desk }, { desktop: DESKTOP_ONLY.workspaces })
  },

  /** Gives one to a person, or takes it back with null. @command desks_assign */
  assign: (workspaceId: string, principalId: string | null, options?: CallOptions) => {
    guard(held, "manageWorkspaces", "desks_assign")
    return call<Desk>("desks_assign", { desk: workspaceId, person: principalId }, { ...options, desktop: DESKTOP_ONLY.workspaces })
  },

  /** @command desks_retry */
  retry: (workspaceId: string) => call<Desk>("desks_retry", { desk: workspaceId }, { desktop: DESKTOP_ONLY.workspaces }),

  /** @command desks_remove */
  remove: (workspaceId: string, options?: CallOptions) => {
    guard(held, "manageWorkspaces", "desks_remove")
    return change("desks_remove", { desk: workspaceId }, options)
  },

  /** With two-step sign-in on, the hub asks for the code from the authenticator app until one
   *  is given. @command desk_login */
  signIn: (invite: string, username: string, password: string, code?: string) =>
    call<DeskLogin>("desk_login", { invite, username, password, code: code || null }, { desktop: DESKTOP_ONLY.workspaces }).then(toMe),

  /** The company's identity provider signs the person in. @command desk_login */
  signInSso: (invite: string) =>
    call<DeskLogin>("desk_login", { invite, sso: true }, { desktop: DESKTOP_ONLY.workspaces }).then(toMe),

  /** @command desk_refresh */
  refresh: () => call<DeskLogin>("desk_refresh", {}, { desktop: DESKTOP_ONLY.workspaces }).then(toMe),

  /** @command desk_logout */
  signOut: () => change("desk_logout"),

  /** The one admin door the Sandbox Grid already has. Its actions keep their exact names, so
   *  the same request object works through either surface. @command desks_manage */
  manage: <T = EnterpriseStatus>(request: { action: string } & Record<string, unknown>) =>
    call<T>("desks_manage", { request }, { desktop: DESKTOP_ONLY.workspaces, policy: { opaque: ["target", "enterprise"] } }),

  /** The company an invite names, read here so a mistyped code is caught before joining.
   *  @local */
  readInvite: (code: string) => readInvite("workspaces", code),
}
