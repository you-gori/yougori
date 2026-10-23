/** The four grids on this computer, read as one thing.
 *
 *  Every grid is still served by its own hub today, so this reads what each product already
 *  answers and puts it in one shape: what the grid is called, what it can do, who holds its key,
 *  how far it can be reached, and the panels its capabilities allow. Nothing here starts
 *  anything, nothing polls: the app already reads all four statuses, and these are conversions
 *  of what it has.
 *
 *  Sidebar wording is the wording that was already there. A grid nobody has set up still says
 *  "Not set up", because that is what every row of this app says.
 */
import type { GridStatus } from "@/api/grid-api"
import type { DesksStatus } from "@/api/desks-api"
import type { AccessStatus } from "@/api/access-api"
import type { SwarmWorker } from "@/api/swarm-api"
import { toModelsStatus } from "@/api/grids/profiles/models"
import { toWorkspacesStatus } from "@/api/grids/profiles/workspaces"
import { toCredentialsStatus } from "@/api/grids/profiles/credentials"
import { toAuditEvent, toResearchJob } from "@/api/grids/compat"
import { HOST_ROLES, MEMBER_ROLES, ROLE_FROM_ACCESS, ROLE_FROM_DESKS, type Held } from "@/api/grids/permits"
import type {
  Approval, AuditEvent, Capability, Credential, HostStatus, ModelPlan, Principal, RealmLifecycle,
  ResearchJob, Role, Workspace,
} from "@/api/grids/types"
import { accessHint } from "@/components/use-access-status"
import type { GridKey } from "@/lib/grid-link"
import { TELL_FOR, type GridClosing } from "@/lib/grid-closing"
import { workerBusy } from "@/lib/swarm-status"

export type { GridKey }

/** What this computer is to a grid. */
export type GridRole = "host" | "member" | "person" | "none"

export interface GridRealm {
  key: GridKey
  /** The one capability this grid has while each product is still its own hub. */
  capabilities: Capability[]
  /** The name a person gave it, or the product's own name until there is one. */
  name: string
  /** Whether anything of it exists on this computer at all. */
  present: boolean
  role: GridRole
  lifecycle: RealmLifecycle
  /** The line under its name in the sidebar, in the wording that was already there. */
  hint: string
  /** The headline sentence at the top of its status. */
  state: string
  /** Where it answers, in words. Null when this computer does not host it. */
  reach: string | null
  /** Who holds the key, in words. */
  keyHolder: string
  /** Who a change made here is recorded as. Every mutating call in Grid Core takes the principal
   *  it acts as, so a person should never have to guess which one this is. */
  actor: string
  closing: GridClosing | null
  problem: string
  invite: string | null
  held: Held
  hosts: HostStatus[]
  plans: ModelPlan[]
  workspaces: Workspace[]
  credentials: Credential[]
  approvals: Approval[]
  people: Principal[]
  jobs: ResearchJob[]
  work: { queued: number; running: number; finished: number }
  /** The grid's own record, where it keeps one. */
  history: AuditEvent[] | null
}

/** The product's own name, used until a company has named its grid. */
export const GRID_NAME: Record<GridKey, string> = {
  models: "Neo Grid",
  workspaces: "Sandbox Grid",
  credentials: "Access Grid",
  research: "Swarm Mining",
}

const CAPABILITY_OF: Record<GridKey, Capability> = {
  models: "models",
  workspaces: "workspaces",
  credentials: "credentials",
  research: "research",
}

const NOT_SET_UP = "Not set up"

const empty = (key: GridKey, hint: string, held: Held): GridRealm => ({
  key,
  capabilities: [CAPABILITY_OF[key]],
  name: GRID_NAME[key],
  present: false,
  role: "none",
  lifecycle: "open",
  hint,
  state: "Not set up on this computer yet.",
  reach: null,
  keyHolder: "Nobody yet",
  actor: "this computer",
  closing: null,
  problem: "",
  invite: null,
  held,
  hosts: [],
  plans: [],
  workspaces: [],
  credentials: [],
  approvals: [],
  people: [],
  jobs: [],
  work: { queued: 0, running: 0, finished: 0 },
  history: null,
})

const reachWords = (address: string, port: number, tunnel: { kind: string; url: string | null; domain: string | null; connected: boolean; error: string | null } | null | undefined) => {
  const here = `${address}:${port} on your own network`
  if (!tunnel) return here
  if (tunnel.error) return `${here}. The public link is not working: ${tunnel.error}`
  if (tunnel.kind === "domain" && tunnel.domain) return `${here}, and at ${tunnel.domain} from anywhere`
  if (tunnel.url) return `${here}, and through a public link from anywhere`
  return `${here}. The public link is starting`
}

const lifecycleOf = (closing: GridClosing | null | undefined): RealmLifecycle =>
  !closing ? "open" : closing.gone ? "gone" : "closing"

/** The Closed Neo Grid: models served from the company's own computers. */
export function modelsRealm(status: GridStatus | null, thisComputer: string): GridRealm {
  const hub = status?.hub ?? null
  const member = status?.member ?? null
  const hint = hub
    ? `${hub.computers.online} of ${hub.computers.total} computers online`
    : member ? `Member of ${member.grid}` : NOT_SET_UP
  const held: Held = { roles: hub ? HOST_ROLES : MEMBER_ROLES, capabilities: ["models"] }
  const base = empty("models", hint, held)
  if (!status || (!hub && !member)) return base
  const typed = toModelsStatus(status)
  return {
    ...base,
    name: hub?.name ?? member?.grid ?? GRID_NAME.models,
    present: true,
    role: hub ? "host" : "member",
    lifecycle: lifecycleOf(hub?.closing),
    state: hub
      ? `Open, hosted on ${thisComputer}, with ${hub.computers.online} of ${hub.computers.total} computers online.`
      : `This computer is a member of ${member?.grid ?? "a grid"} that somebody else hosts.`,
    reach: hub ? reachWords(hub.address, hub.port, hub.tunnel ?? null) : null,
    keyHolder: hub ? thisComputer : (member?.hub ?? "the computer that hosts it"),
    actor: thisComputer,
    closing: hub?.closing ?? null,
    problem: status.hubError ?? status.memberError ?? "",
    invite: hub?.invite ?? null,
    hosts: typed.hosts,
    plans: typed.plans,
    work: { queued: typed.queue.waiting, running: typed.queue.running, finished: 0 },
  }
}

/** The Sandbox Grid: a desk for each person, built on company computers. */
export function workspacesRealm(status: DesksStatus | null, thisComputer: string): GridRealm {
  const hub = status?.hub ?? null
  const member = status?.member ?? null
  const login = status?.desk ?? null
  const hosting = status?.hosting ?? []
  const hint = hub
    ? `${hub.desks.length} ${hub.desks.length === 1 ? "desk" : "desks"} · ${hub.computers.online} of ${hub.computers.total} computers online`
    : member ? `Hosting ${hosting.length} ${hosting.length === 1 ? "desk" : "desks"} for ${member.grid}`
    : login ? `Signed in as ${login.name}` : NOT_SET_UP
  const roles: readonly Role[] = login ? [ROLE_FROM_DESKS[login.adminRole ?? "user"]] : hub ? HOST_ROLES : MEMBER_ROLES
  const held: Held = { roles, capabilities: ["workspaces"] }
  const base = empty("workspaces", hint, held)
  if (!status || (!hub && !member && !login)) return base
  const typed = toWorkspacesStatus(status)
  const running = typed.workspaces.filter(desk => desk.state === "running" || desk.state === "assigned").length
  return {
    ...base,
    name: hub?.name ?? member?.grid ?? login?.grid ?? GRID_NAME.workspaces,
    present: true,
    role: hub ? "host" : member ? "member" : "person",
    lifecycle: lifecycleOf(hub?.closing),
    state: hub
      ? `Open, hosted on ${thisComputer}, with ${hub.desks.length} ${hub.desks.length === 1 ? "desk" : "desks"} and ${hub.computers.online} of ${hub.computers.total} computers online.`
      : member
        ? `This computer hosts ${hosting.length} ${hosting.length === 1 ? "desk" : "desks"} for ${member.grid}.`
        : `Signed in to ${login?.grid ?? "a grid"} as ${login?.name ?? "yourself"}.`,
    reach: hub ? reachWords(hub.address, hub.port, hub.tunnel ?? null) : null,
    keyHolder: hub ? thisComputer : (member?.hub ?? login?.grid ?? "the computer that hosts it"),
    actor: login?.name ?? thisComputer,
    closing: hub?.closing ?? null,
    problem: status.hubError ?? status.memberError ?? "",
    invite: hub?.invite ?? null,
    hosts: typed.hosts,
    workspaces: typed.workspaces,
    people: typed.people,
    work: { queued: typed.workspaces.length - running, running, finished: 0 },
  }
}

/** The Access Grid: company credentials an agent uses and never sees. */
export function credentialsRealm(status: AccessStatus | null, thisComputer: string): GridRealm {
  const hub = status?.hub ?? null
  const member = status?.member ?? null
  const me = status?.me ?? null
  const hint = accessHint(status)
  const permission = me?.person.permission
  const roles: readonly Role[] = permission ? [ROLE_FROM_ACCESS[permission]] : hub ? HOST_ROLES : MEMBER_ROLES
  const held: Held = { roles, capabilities: ["credentials"] }
  const base = empty("credentials", hint, held)
  if (!status || (!hub && !member && !me)) return base
  const typed = toCredentialsStatus(status)
  const closing = hub?.closing
    ? { requestedAt: hub.closing.requestedAt, until: hub.closing.until, gone: hub.closing.gone, tellUntil: hub.closing.until + TELL_FOR }
    : null
  return {
    ...base,
    name: hub?.company ?? member?.company ?? me?.company ?? GRID_NAME.credentials,
    present: true,
    role: hub ? "host" : me ? "person" : "member",
    lifecycle: lifecycleOf(closing),
    state: hub
      ? `Open, hosted on ${thisComputer}, with ${hub.people} ${hub.people === 1 ? "person" : "people"} and ${hub.credentials} ${hub.credentials === 1 ? "credential" : "credentials"}.`
      : `Signed in to ${me?.company ?? member?.company ?? "a grid"} somebody else hosts.`,
    reach: hub ? reachWords(hub.address, hub.port, hub.tunnel ? { kind: "domain", url: null, domain: null, connected: true, error: null } : null) : null,
    keyHolder: hub ? thisComputer : (member?.company ?? "the computer that hosts it"),
    actor: me?.person.name ?? me?.person.username ?? thisComputer,
    closing,
    problem: status.hubError ?? status.memberError ?? "",
    invite: hub?.invite ?? null,
    credentials: typed.credentials,
    approvals: typed.waiting,
    work: { queued: typed.waiting.length, running: 0, finished: 0 },
    people: (me?.overview?.people ?? []).map(person => ({
      id: person.id, realmId: me?.accessId ?? "", kind: "person" as const, name: person.name,
      username: person.username, roles: [ROLE_FROM_ACCESS[person.permission]], createdAt: person.createdAt,
    })),
    history: (me?.overview?.activity ?? []).map((activity, at) => toAuditEvent(activity, me?.accessId ?? "", at)),
  }
}

/** Swarm Mining: authorised research, in a grid of its own.
 *
 *  Nothing here starts, resumes or touches a worker. It reads the list the app already polls and
 *  counts it. */
export function researchRealm(workers: readonly SwarmWorker[], thisComputer: string): GridRealm {
  const working = workers.filter(workerBusy).length
  const hint = workers.length
    ? `${working} working · ${workers.length} ${workers.length === 1 ? "worker" : "workers"}`
    : "No workers"
  const held: Held = { roles: HOST_ROLES, capabilities: ["research"] }
  const base = empty("research", hint, held)
  if (!workers.length) return { ...base, state: "No research is set up on this computer yet." }
  return {
    ...base,
    present: true,
    role: "host",
    state: `Open on ${thisComputer}, with ${working} of ${workers.length} ${workers.length === 1 ? "worker" : "workers"} working.`,
    keyHolder: thisComputer,
    actor: thisComputer,
    jobs: workers.map(worker => toResearchJob(worker, "research")),
    work: { queued: workers.length - working, running: working, finished: 0 },
  }
}

export interface GridSources {
  grid: GridStatus | null
  desks: DesksStatus | null
  access: AccessStatus | null
  workers: readonly SwarmWorker[]
  thisComputer: string
}

/** Every grid on this computer, in the order the sidebar lists them. */
export function gridRealms({ grid, desks, access, workers, thisComputer }: GridSources): GridRealm[] {
  return [
    workspacesRealm(desks, thisComputer),
    modelsRealm(grid, thisComputer),
    researchRealm(workers, thisComputer),
    credentialsRealm(access, thisComputer),
  ]
}

/** The line under "Grids" itself. */
export function gridsHint(realms: readonly GridRealm[]): string {
  const live = realms.filter(realm => realm.present)
  if (!live.length) return NOT_SET_UP
  const computers = new Set<string>()
  for (const realm of live) for (const host of realm.hosts) if (host.online) computers.add(host.name)
  const grids = `${live.length} ${live.length === 1 ? "grid" : "grids"}`
  return computers.size ? `${grids} · ${computers.size} ${computers.size === 1 ? "computer" : "computers"} online` : grids
}
