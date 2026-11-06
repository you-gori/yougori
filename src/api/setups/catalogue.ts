import { AVAILABILITY_TEXT as GENERATED_AVAILABILITY_TEXT, CAPABILITIES, CAPABILITY_GROUPS } from "./capabilities.generated"
import type { CapabilityAvailability, CapabilityDescriptor, CapabilityGroup, CapabilityReport, GridProfile } from "./types"

/** The capability catalogue, and how each capability stands on this computer.
 *
 *  The catalogue is generated from the engine's one descriptor table, so the builder, the CLI's
 *  help and the engine's checks cannot drift apart. It grants nothing: whether a capability can be
 *  used here is what `setup_capabilities` says.
 */
export const CATALOGUE: readonly CapabilityDescriptor[] = CAPABILITIES

/** The six groups, in the order the builder shows them, with each group's line under its name and
 *  the plain words people search for it with: all from the shared registry, through the generated
 *  table, so the desktop and the CLI say and find the same things. Grid & workers is first and
 *  always open. */
export const GROUPS: { id: CapabilityGroup; name: string; lead: string; words: string[] }[] =
  CAPABILITY_GROUPS.map(group => ({ id: group.id, name: group.name, lead: group.lead, words: [...group.words] }))

export const GROUP_NAME = Object.fromEntries(GROUPS.map(group => [group.id, group.name])) as Record<CapabilityGroup, string>

/** Availability as shown: the engine's four states, and "unknown" while this build cannot check. */
/** `other_grid`: usable here, but in another kind of grid than this setup is; choosing it makes
 *  the setup that kind of grid. */
export type ShownAvailability = CapabilityAvailability | "unknown" | "other_grid"

export const AVAILABILITY_TEXT: Record<ShownAvailability, string> = {
  ...GENERATED_AVAILABILITY_TEXT,
  other_grid: "Needs another kind of grid",
  unknown: "Not checked",
}

export interface CatalogueEntry {
  descriptor: CapabilityDescriptor
  availability: ShownAvailability
  reason: string | null
}

const PROFILE_NAME: Record<GridProfile, string> = {
  neo_grid: "Neo Grid",
  sandbox_grid: "Sandbox Grid",
  access_grid: "Access Grid",
  swarm_mining_grid: "Swarm Mining Grid",
  generic: "this kind of",
}

/** The grid kinds `profiles` names, as a person reads them: "a Neo Grid or a Sandbox Grid". */
const kindsInWords = (profiles: readonly GridProfile[]) => {
  const names = profiles.filter(one => one !== "generic").map(one => PROFILE_NAME[one] ?? one).map(name => `${/^[AEIOU]/.test(name) ? "an" : "a"} ${name}`)
  return names.length > 1 ? `${names.slice(0, -1).join(", ")} or ${names[names.length - 1]}` : names[0] ?? "a grid"
}

/** Joins the catalogue with what the engine said. `statuses` is null when the engine could not
 *  be asked. A planned capability stays planned whatever is said about it; one the engine did not
 *  mention is not offered by this build. One that belongs to other kinds of grid is `other_grid`
 *  while the setup's kind can still change (`switchable`, a template being made): choosing it
 *  makes the setup that kind. Where the kind is fixed, it is unsupported. One the engine can't set
 *  up yet can still go in a template, but not into a setup made here (`running`). */
export function withAvailability(catalogue: readonly CapabilityDescriptor[], statuses: CapabilityReport[] | null, profile: GridProfile = "generic", { running = false, switchable = false }: { running?: boolean; switchable?: boolean } = {}): CatalogueEntry[] {
  const byId = new Map((statuses ?? []).map(status => [status.id, status]))
  return catalogue.map(descriptor => {
    if (descriptor.status === "planned") return { descriptor, availability: "planned", reason: "Described, not built yet. It can't be turned on." }
    const profiles = Array.isArray(descriptor.profiles) ? descriptor.profiles : []
    const elsewhere = profiles.length > 0 && !profiles.includes(profile)
    if (elsewhere && !switchable) {
      return { descriptor, availability: "unsupported", reason: `Works in ${profiles.map(one => PROFILE_NAME[one] ?? one).join(" and ")} setups for now, not in ${PROFILE_NAME[profile]} setups.` }
    }
    const here = judged(descriptor, byId, statuses, running)
    if (elsewhere && selectable(here.availability)) {
      return {
        descriptor,
        availability: "other_grid",
        reason: profile === "generic"
          ? `It belongs to ${kindsInWords(profiles)}. Turning it on makes this setup ${profiles.length > 1 ? "a grid, and asks which kind" : kindsInWords(profiles)}.`
          : `It belongs to ${kindsInWords(profiles)}, not ${kindsInWords([profile])}. Turning it on makes this setup ${profiles.length > 1 ? "another kind of grid, and asks which" : kindsInWords(profiles)}.`,
      }
    }
    return elsewhere ? { ...here, availability: "unsupported" } : here
  })
}

/** What this computer and engine say of a capability, whatever kind of setup it goes in. */
function judged(descriptor: CapabilityDescriptor, byId: Map<string, CapabilityReport>, statuses: CapabilityReport[] | null, running: boolean): CatalogueEntry {
  if (!statuses) return { descriptor, availability: "unknown", reason: "This build can't check it yet." }
  const status = byId.get(descriptor.id)
  if (!status) return { descriptor, availability: "unsupported", reason: "This build of Yougori doesn't offer it." }
  if (status.availability === "planned") return { descriptor, availability: "planned", reason: status.reason ?? "Described, not built yet. It can't be turned on." }
  if (status.engineReady === false && status.availability !== "unsupported") {
    const engineReason = status.engineReason || "Yougori can't set this up on this computer yet."
    return running
      ? { descriptor, availability: "unsupported", reason: engineReason }
      : { descriptor, availability: status.availability, reason: `${engineReason} A template can still include it.` }
  }
  return { descriptor, availability: status.availability, reason: status.reason ?? null }
}

/** Only these can be turned on. Planned and unsupported ones never can, and neither can one this
 *  computer has not been checked for yet. */
export const selectable = (availability: ShownAvailability) => availability === "available" || availability === "needs_configuration"
