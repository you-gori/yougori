/** What the client offers, and nothing more.
 *
 *  The engine and the hub decide what actually happens: every desktop command checks the main
 *  window, every hub checks the session, and Grid Core checks its own table again at the moment
 *  it acts. This file exists so a control that would be refused is not offered, and so the
 *  refusal reads well without a round trip. A client with a wrong, stale or patched table
 *  changes nothing about what any of those three allow.
 */
import { ROLE_ACTIONS, ROLE_IMPLIES } from "@/api/grids/permits.generated"
import { CapabilityOffError, NotAllowedError } from "@/api/grids/errors"
import { requestId } from "@/api/grids/wire"
import type { Action, Capability, Role } from "@/api/grids/types"

/** What the client knows about whoever is asking, as far as the product tells it. */
export interface Held {
  roles: readonly Role[]
  /** Set when they are suspended. Grid Core's `Principal::may` needs an account that is still
   *  active as well as the role, so suspension answers before any role is read. */
  suspendedAt?: number | null
  /** What this grid turned on. Left out when the product does not say, and then a capability is
   *  never the reason for a refusal. */
  capabilities?: readonly Capability[]
}

/** Which capability an action belongs to, where it belongs to one at all. */
export function capabilityOf(action: Action): Capability | null {
  switch (action) {
    case "manageModels": case "callModel": return "models"
    case "manageWorkspaces": case "useWorkspace": return "workspaces"
    case "manageCredentials": case "approveCredential": return "credentials"
    case "doResearch": case "approveResearch": return "research"
    default: return null
  }
}

/** How to say a capability as something a grid does. The same words as `Capability::doing`. */
export const CAPABILITY_DOING: Record<Capability, string> = {
  models: "serve models",
  workspaces: "host workspaces",
  credentials: "broker credentials",
  research: "run authorised research",
}

/** Whether this grid does the thing at all. */
export function enabled(held: Held, action: Action): boolean {
  const capability = capabilityOf(action)
  return !capability || !held.capabilities || held.capabilities.includes(capability)
}

/** Whether these roles may do this now. Suspension answers first, exactly as Grid Core does. */
export function may(held: Held, action: Action): boolean {
  if (held.suspendedAt) return false
  if (!enabled(held, action)) return false
  const all = new Set<Role>(held.roles)
  for (const role of held.roles) for (const brought of ROLE_IMPLIES[role]) all.add(brought)
  for (const role of all) if (ROLE_ACTIONS[role].includes(action)) return true
  return false
}

/** Refuses before the engine is called, with the clearer of the two sentences. */
export function guard(held: Held, action: Action, command: string): void {
  const capability = capabilityOf(action)
  if (capability && !enabled(held, action)) {
    throw new CapabilityOffError(capability, CAPABILITY_DOING[capability], command, requestId())
  }
  if (!may(held, action)) throw new NotAllowedError(action, held.roles, command, requestId())
}

/** The Sandbox Grid's own words for a role. */
export const ROLE_FROM_DESKS: Record<"user" | "auditor" | "operator" | "administrator", Role> = {
  user: "user", auditor: "auditor", operator: "operator", administrator: "realmAdmin",
}

/** The Access Grid's own words for a role. */
export const ROLE_FROM_ACCESS: Record<"member" | "approver" | "auditor" | "admin", Role> = {
  member: "user", approver: "credentialApprover", auditor: "auditor", admin: "realmAdmin",
}

/** What the Closed Neo Grid and Swarm Mining can know today: this computer runs the hub, or it
 *  does not. Neither has an account to read, so for those two the real answer is the engine's
 *  and this is only enough to keep a control from being offered where there is no hub at all. */
export const HOST_ROLES: readonly Role[] = ["realmAdmin"]
export const MEMBER_ROLES: readonly Role[] = ["user"]
