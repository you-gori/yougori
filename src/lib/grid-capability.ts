/** What a grid is for, and who may be offered what.
 *
 *  One rule, written once, used by the sidebar, the create wizard and every panel of the realm
 *  view: a capability the grid never turned on is not offered, and a control the person may not
 *  use is not rendered at all. Nothing is shown disabled with a note about a permission somebody
 *  does not have; it is simply absent.
 *
 *  `allowedIn` mirrors `Capability::allowed_in` in `grid/src/core/realm.rs`, so the wizard cannot
 *  offer a combination the core would refuse. The wire word for a company grid is `primary`;
 *  `company` is only ever a word on screen.
 */
import { may as mayHold, type Held } from "@/api/grids/permits"
import type { Action, Capability, RealmKind, Role } from "@/api/grids/types"

export type { Action, Capability, RealmKind, Role }

/** The three a company grid may turn on, in the order they are offered. */
export const COMPANY_CAPABILITIES: readonly Capability[] = ["models", "workspaces", "credentials"]

/** What a person reads for each one. */
export const CAPABILITY_NAME: Record<Capability, string> = {
  models: "Serving models",
  workspaces: "Sandbox workspaces",
  credentials: "Credential access",
  research: "Authorised research",
}

/** The line under each choice in the wizard. */
export const CAPABILITY_LEAD: Record<Capability, string> = {
  models: "Run the models you choose on your own computers.",
  workspaces: "A desk for each person, built on company computers.",
  credentials: "Company keys your agents use without ever seeing them.",
  research: "A grid of its own, offline unless you open it.",
}

/** Research is alone in its grid, and the company's three never share a grid with it. */
export const RESEARCH_IS_ALONE =
  "Research gets a grid of its own, with its own key, its own records and its own permissions. It cannot be joined with the other three."

/** Which capabilities a kind of grid may turn on. */
export function allowedIn(kind: RealmKind): Capability[] {
  return kind === "research" ? ["research"] : [...COMPANY_CAPABILITIES]
}

/** Which kind of grid a set of choices makes. */
export function kindFor(chosen: readonly Capability[]): RealmKind {
  return chosen.includes("research") ? "research" : "primary"
}

/** Picking one capability, with the one rule the core has. Picking research clears the others,
 *  and picking any other clears research. Picking the same one again takes it off again. */
export function chooseCapability(chosen: readonly Capability[], picked: Capability): Capability[] {
  if (chosen.includes(picked)) return chosen.filter(one => one !== picked)
  if (picked === "research") return ["research"]
  const company: Capability[] = chosen.filter(one => one !== "research")
  return COMPANY_CAPABILITIES.filter(one => one === picked || company.includes(one))
}

/** Whether this grid does the thing at all. */
export function offers(realm: { capabilities: readonly Capability[] }, capability: Capability): boolean {
  return realm.capabilities.includes(capability)
}

/** Whether the person signed in here may do it. The engine decides for real; this only keeps a
 *  control from being offered where it would be refused. */
export function may(held: Held, action: Action): boolean {
  return mayHold(held, action)
}

/** Both, always. A panel asks this, and renders nothing at all when it is false. */
export function shows(
  realm: { capabilities: readonly Capability[] },
  held: Held,
  capability: Capability,
  action: Action,
): boolean {
  return offers(realm, capability) && mayHold({ ...held, capabilities: realm.capabilities }, action)
}

/** What a grid with these capabilities is called in one short line. */
export function capabilitiesSentence(capabilities: readonly Capability[]): string {
  const words = capabilities.map(one => CAPABILITY_NAME[one].toLowerCase())
  if (!words.length) return "nothing yet"
  if (words.length === 1) return words[0] as string
  return `${words.slice(0, -1).join(", ")} and ${words[words.length - 1] as string}`
}
