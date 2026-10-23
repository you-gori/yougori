/** The models profile: the Closed Neo Grid, in Grid Core's words.
 *
 *  Every method here reaches the engine command the Closed Neo Grid page reaches today. Nothing
 *  new is registered and nothing changes on the engine side; what changes is that a page can be
 *  written against realms, hosts and plans rather than against grids, members and scopes.
 */
import { noRentedGpus, type GridRentedGpus, type GridResult, type GridStatus, type NewHarness, type SwarmRun } from "@/api/grid-api"
import {
  fromPlanTarget, toAssignment, toHostStatus, toMembership, toModelPlan, toModelsHub,
} from "@/api/grids/compat"
import { guard, HOST_ROLES, MEMBER_ROLES, may, type Held } from "@/api/grids/permits"
import { mentions, paginate, where, type HostFilter, type Page, type PageRequest } from "@/api/grids/page"
import { DESKTOP_ONLY, readInvite, tunnelOf, type Done } from "@/api/grids/profiles/shared"
import { call, cliOnly } from "@/api/grids/wire"
import type {
  Action, CallOptions, DeleteWhen, Harness, HostStatus, ModelPlan, ModelsStatus, NewModelPlan, Reach,
} from "@/api/grids/types"

const EMPTY: GridStatus = { hub: null, hubError: null, member: null, memberError: null }

/** What the client last learned about whoever is asking. The Closed Neo Grid has no accounts,
 *  so the most it can know is whether this computer runs the hub. Until a read says otherwise
 *  the client assumes it may, because a mirror that guesses "no" hides a control the engine
 *  would have allowed; a mirror that guesses "yes" only costs one refused round trip. */
let held: Held = { roles: HOST_ROLES, capabilities: ["models"] }

export function toModelsStatus(status: GridStatus): ModelsStatus {
  const hub = status.hub
  const member = status.member
  const realmId = hub?.id ?? member?.gridId ?? ""
  return {
    profile: "models",
    hub: hub ? toModelsHub(hub) : null,
    hubError: status.hubError,
    member: member ? toMembership(member) : null,
    memberError: status.memberError,
    me: null,
    hosts: hub ? hub.members.map(computer => toHostStatus(computer, realmId)) : [],
    plans: hub ? hub.plans.map(plan => toModelPlan(plan, realmId)) : [],
    planWarning: hub?.planWarning ?? null,
    queue: hub?.queue ?? { waiting: 0, running: 0 },
    harnesses: hub?.harnesses ?? [],
    assignment: member ? toAssignment(member) : null,
    message: status.message,
  }
}

const read = () => call<GridStatus>("grid_status", {}, { browser: () => EMPTY, desktop: DESKTOP_ONLY.models })
  .then(status => {
    held = { roles: status.hub ? HOST_ROLES : MEMBER_ROLES, capabilities: ["models"] }
    return toModelsStatus(status)
  })

const change = (command: string, args: Record<string, unknown> = {}, options?: CallOptions) =>
  call<Done>(command, args, { ...options, desktop: DESKTOP_ONLY.models })

export const models = {
  /** The hub this computer runs and this computer's membership, with the tunnel.
   *  @command grid_status */
  status: read,

  /** What the client believes this computer may do here. The engine decides for real. @local */
  who: (): Held => held,
  /** Whether a control is worth offering. Never the decision itself. @local */
  may: (action: Action) => may(held, action),

  /** This computer's private network address to host on. @command grid_suggested_address */
  suggestedAddress: () => call<string | null>("grid_suggested_address", {}, { browser: () => null, desktop: DESKTOP_ONLY.models }),

  /** Starts the hub on this computer. @command grid_create */
  host: (name: string, address: string, password: string, reach: Reach = "network") => {
    guard(held, "manageModels", "grid_create")
    return call<GridStatus>("grid_create", { name, address, password, tunnel: tunnelOf(reach) }, { desktop: DESKTOP_ONLY.models }).then(toModelsStatus)
  },

  /** Joins a company hub from an invite code. @command grid_join */
  join: (invite: string, password?: string) =>
    call<GridStatus>("grid_join", { invite, password: password || null }, { desktop: DESKTOP_ONLY.models }).then(toModelsStatus),

  /** @command grid_leave */
  leave: () => change("grid_leave"),

  /** `later` pauses the grid for three days and is restorable, `now` deletes it, `forget` stops
   *  waiting for computers that are away. @command grid_delete */
  scheduleDeletion: (when: DeleteWhen = "later") => {
    guard(held, "manageModels", "grid_delete")
    return change("grid_delete", { when })
  },

  /** @command grid_restore */
  restore: () => change("grid_restore"),

  /** The computers in this grid, filtered and paged. Asking for no page asks for all of them.
   *  @command grid_status */
  hosts: async (filter: HostFilter = {}, page: PageRequest = {}): Promise<Page<HostStatus>> => {
    const status = await read()
    const tests = [
      (host: HostStatus) => filter.online === undefined || host.online === filter.online,
      (host: HostStatus) => filter.excluded === undefined || host.excluded === filter.excluded,
      (host: HostStatus) => filter.draining === undefined || host.draining === filter.draining,
      (host: HostStatus) => filter.planId === undefined || host.planId === filter.planId,
      (host: HostStatus) => mentions(filter.search, host.name, host.address),
    ]
    return paginate(where(status.hosts, tests), page, host => host.id)
  },

  /** The model plans in this grid. @command grid_status */
  plans: async (page: PageRequest = {}): Promise<Page<ModelPlan>> =>
    paginate((await read()).plans, page, plan => plan.id),

  /** Orders a model across the grid. @command grid_plan_add */
  addPlan: (plan: NewModelPlan, options?: CallOptions) => {
    guard(held, "manageModels", "grid_plan_add")
    const target = fromPlanTarget(plan.target)
    return change("grid_plan_add", target.kind === "computers"
      ? { model: plan.model, computers: target.members, scope: null, percent: null, quant: plan.quant ?? null }
      : { model: plan.model, scope: target.kind, percent: target.percent, computers: null, quant: plan.quant ?? null }, options)
  },

  /** @command grid_plan_remove */
  removePlan: (planId: string, options?: CallOptions) => {
    guard(held, "manageModels", "grid_plan_remove")
    return change("grid_plan_remove", { planId }, options)
  },

  /** @command grid_member_remove */
  removeHost: (hostId: string) => change("grid_member_remove", { memberId: hostId }),

  /** Leaves a computer out: no model and no work until it is brought back.
   *  @command grid_member_exclude */
  drainHost: (hostId: string) => {
    guard(held, "drainHost", "grid_member_exclude")
    return change("grid_member_exclude", { memberId: hostId })
  },

  /** @command grid_member_include */
  bringHostBack: (hostId: string) => {
    guard(held, "drainHost", "grid_member_include")
    return change("grid_member_include", { memberId: hostId })
  },

  /** The rented NeoCloud GPUs in the grid this computer hosts, with each pod's price and state,
   *  and the rented pods that could join. Nothing here rents or starts a pod.
   *  @command grid_neocloud_status */
  rentedGpus: () => call<GridRentedGpus>("grid_neocloud_status", {}, { browser: () => noRentedGpus, desktop: DESKTOP_ONLY.models }),

  /** Adds a pod already rented in NeoCloud, at most eight to a grid. @command grid_neocloud_add */
  addRentedGpu: (environmentId: string) => {
    guard(held, "manageModels", "grid_neocloud_add")
    return change("grid_neocloud_add", { environmentId })
  },

  /** Takes a rented GPU out of the grid and stops its pod, which ends its GPU billing.
   *  @command grid_neocloud_remove */
  removeRentedGpu: (environmentId: string) => {
    guard(held, "manageModels", "grid_neocloud_remove")
    return change("grid_neocloud_remove", { environmentId })
  },

  /** Stops every rented GPU in the grid. They stay in it, offline, until started in NeoCloud.
   *  @command grid_neocloud_stop_all */
  stopRentedGpus: () => {
    guard(held, "manageModels", "grid_neocloud_stop_all")
    return change("grid_neocloud_stop_all")
  },

  /** The teams of models this grid serves as `swarm/NAME`. @command grid_status */
  harnesses: async (page: PageRequest = {}): Promise<Page<Harness>> =>
    paginate((await read()).harnesses, page, harness => harness.id),

  /** @command grid_swarm_add */
  addHarness: (harness: NewHarness) =>
    call<GridResult & { missing?: string[] }>("grid_swarm_add", { ...harness, tasks: null }, { desktop: DESKTOP_ONLY.models }),

  /** @command grid_swarm_remove */
  removeHarness: (harnessId: string) => change("grid_swarm_remove", { harnessId }),

  /** Runs a team of models once and reports what each one did.
   *  The answer is a model's own words and is never shortened or rewritten.
   *  @command grid_swarm_run */
  runHarness: (harness: string, prompt: string) =>
    call<SwarmRun>("grid_swarm_run", { harness, prompt }, { desktop: DESKTOP_ONLY.models, policy: { opaque: ["trace"], keep: ["answer"] } }),

  /** Changes a plan after it was ordered. The command line has this; the desktop does not.
   *  @command grid_plan_update */
  changePlan: (): never => cliOnly("grid_plan_update", "yougori grid change-plan PLAN_ID"),

  /** Rotates the company password. The command line has this; the desktop does not.
   *  @command grid_password */
  changePassword: (): never => cliOnly("grid_password", "yougori grid password --yes"),

  /** @command grid_key_create */
  addKey: (): never => cliOnly("grid_key_create", "yougori grid add-key --name APP"),

  /** @command grid_key_revoke */
  revokeKey: (): never => cliOnly("grid_key_revoke", "yougori grid revoke-key KEY_ID --yes"),

  /** The company an invite names, read here so a mistyped code is caught before joining.
   *  @local */
  readInvite: (code: string) => readInvite("models", code),
}
