import { selectable, type CatalogueEntry } from "@/api/setups/catalogue"
import { GRID_KINDS } from "@/api/setups/capabilities.generated"
import type { CapabilityChoice, CapabilityDescriptor, GridProfile, RecipeSlug, SettingDescriptor, SettingValue, SetupDraft } from "@/api/setups/types"

/** Small, pure rules about a draft, shared by the builder's screens. */

/** The element id of a field, so a problem can send focus straight to it. */
export const fieldId = (field: string) => `setup-field-${field}`

/** The kinds of grid the shared generator can make, from the registry's own table (the CLI's
 *  `template new` asks the same question with the same words). Each is stored in the draft's
 *  `recipe`, which the generator reads as the grid's profile; it refuses a grid without one. */
export const gridKinds = () => GRID_KINDS

/** The profile each slug a draft can carry presents as: the kinds the generator makes, and Swarm
 *  Mining Grid, which a setup can be read with but not made as. */
const PROFILE_OF_RECIPE: Record<RecipeSlug, GridProfile> = {
  ...(Object.fromEntries(GRID_KINDS.map(kind => [kind.slug, kind.profile])) as Record<(typeof GRID_KINDS)[number]["slug"], GridProfile>),
  "swarm-mining-grid": "swarm_mining_grid",
}

/** The grid profile a draft presents as, from the kind of grid its author or its source gave it,
 *  or null when it has none. Some capabilities are only wired for some profiles. */
export const profileOfRecipe = (recipe: string | null | undefined): GridProfile | null =>
  recipe && Object.prototype.hasOwnProperty.call(PROFILE_OF_RECIPE, recipe) ? PROFILE_OF_RECIPE[recipe as RecipeSlug] : null

/** The capabilities that make a setup a grid, and so make it say which kind. */
const GRID_CAPABILITIES = ["grid.create", "grid.join"]

export const needsGridKind = (draft: SetupDraft) => GRID_CAPABILITIES.some(id => draft.capabilities[id]?.selected)

/** Why the draft can't be generated yet for want of a grid kind, in the generator's own words, or
 *  "". Asked only while a grid is chosen, so an author answers it only when their choices need it. */
export const gridKindProblem = (draft: SetupDraft) =>
  needsGridKind(draft) && !profileOfRecipe(draft.recipe) ? "A grid needs to say which kind it is: Sandbox Grid, Neo Grid, Access Grid or Swarm Mining Grid. Choose one first." : ""

/** The kinds of grid a capability belongs to, as the builder offers them; none for one that goes
 *  in any setup. */
export const kindsFor = (descriptor: Pick<CapabilityDescriptor, "profiles">) =>
  GRID_KINDS.filter(kind => (descriptor.profiles ?? []).includes(kind.profile))

/** The draft with a capability of another kind of grid turned on, made the grid it belongs to: a
 *  grid is created unless one is already being created or joined, and its kind is the one kind
 *  that has the capability, or is left to be chosen when several do. */
export function withItsGrid(draft: SetupDraft, descriptor: CapabilityDescriptor): SetupDraft {
  const kinds = kindsFor(descriptor)
  let next = toggled(draft, descriptor, true)
  if (!needsGridKind(next)) next = selectAll(next, ["grid.create"])
  // A grid is not a setup kept to this computer.
  if (next.capabilities["grid.local_only"]?.selected) next = { ...next, capabilities: { ...next.capabilities, "grid.local_only": { ...next.capabilities["grid.local_only"]!, selected: false } } }
  const recipe = kinds.length === 1 ? kinds[0]!.slug : kinds.some(kind => kind.slug === next.recipe) ? next.recipe ?? null : null
  return { ...next, recipe }
}

/** The draft with its grid kind kept only while a grid is chosen, so an answer to a question no
 *  longer asked does not travel with it. */
export const withGridKind = (draft: SetupDraft): SetupDraft => needsGridKind(draft) || !draft.recipe ? draft : { ...draft, recipe: null }

/** The capability a field path is about, and the setting within it. Capability ids have dots in
 *  them (`grid.create`), so the longest known id wins. */
export function fieldParts(field: string, known: Iterable<string> = []): { capability: string; setting: string | null } | null {
  if (!field.startsWith("capabilities.")) return null
  const rest = field.slice("capabilities.".length)
  const id = [...known].filter(one => rest === one || rest.startsWith(`${one}.`)).sort((a, b) => b.length - a.length)[0]
  if (id) return { capability: id, setting: rest === id ? null : rest.slice(id.length + 1) }
  return rest ? { capability: rest, setting: null } : null
}

/** Every field a path could be about, most precise first: the question itself (question ids have
 *  no dots, so it is the last part), then each capability it could belong to, longest first. */
export function fieldCandidates(field: string): string[] {
  if (!field.startsWith("capabilities.")) return []
  const parts = field.slice("capabilities.".length).split(".")
  const question = parts.length > 1 ? [parts[parts.length - 1]!] : []
  return [...question, ...parts.map((_, index) => `capabilities.${parts.slice(0, parts.length - index).join(".")}`)]
}

/** Field names in words, for "Go to" links. */
export function fieldLabel(field: string, names: Record<string, string> = {}) {
  if (field === "name") return "the name"
  if (field === "recipe") return "the kind of grid"
  const parts = fieldParts(field, Object.keys(names))
  if (parts) return parts.setting ? `${names[parts.capability] ?? parts.capability}: ${parts.setting.replace(/[_-]+/g, " ")}` : names[parts.capability] ?? parts.capability
  return field
}

/** Selects or deselects one capability. Deselecting keeps its answers, so turning it back on does
 *  not lose them; the engine leaves a deselected capability out of the plan. */
export function toggled(draft: SetupDraft, descriptor: CapabilityDescriptor, on: boolean): SetupDraft {
  const current = draft.capabilities[descriptor.id]
  const defaults = Object.fromEntries(questionsOf(draft, descriptor.id).filter(question => question.kind !== "secret" && question.default !== undefined).map(question => [question.id, question.default!]))
  const next: CapabilityChoice = current ? { ...current, selected: on } : { selected: on, mode: "default", runnerEditable: true, settings: defaults }
  return { ...draft, capabilities: { ...draft.capabilities, [descriptor.id]: next } }
}

/** The questions the draft asks about one capability. */
export const questionsOf = (draft: SetupDraft, capability: string): SettingDescriptor[] =>
  (draft.questions ?? []).filter(question => question.capability === capability)

/** Sets one answer: on its capability when it has one, otherwise on the draft. */
export function answered(draft: SetupDraft, question: SettingDescriptor, value: SettingValue): SetupDraft {
  const capability = question.capability
  if (!capability) return { ...draft, answers: { ...(draft.answers ?? {}), [question.id]: value } }
  const choice = draft.capabilities[capability] ?? { selected: true, mode: "default", runnerEditable: true, settings: {} }
  return { ...draft, capabilities: { ...draft.capabilities, [capability]: { ...choice, settings: { ...choice.settings, [question.id]: value } } } }
}

/** The field the engine uses for a question: the template's own input id. */
export const questionField = (question: SettingDescriptor) => question.id

/** Turns on each of these capabilities, keeping whatever they had. */
export function selectAll(draft: SetupDraft, ids: string[]): SetupDraft {
  return ids.reduce((next, id) => ({
    ...next,
    capabilities: { ...next.capabilities, [id]: { ...(next.capabilities[id] ?? { mode: "default", runnerEditable: true, settings: {} }), selected: true } },
  }), draft)
}

/** The requirements of a capability that no selected capability meets. Each requirement is a group
 *  of alternatives: any one of them is enough. A profile whose own handler supplies them waives
 *  them, as the catalogue says. */
export const missingRequirements = (draft: SetupDraft, descriptor: Pick<CapabilityDescriptor, "requires"> & { requiresWaivedFor?: GridProfile[] }, profile?: GridProfile | null): string[][] =>
  profile && descriptor.requiresWaivedFor?.includes(profile)
    ? []
    : descriptor.requires.filter(group => group.length > 0 && !group.some(id => draft.capabilities[id]?.selected))

/** The selected capabilities this one cannot be used with. */
export const conflictsWith = (draft: SetupDraft, descriptor: CapabilityDescriptor) =>
  descriptor.conflicts.filter(id => draft.capabilities[id]?.selected)

export const selectedIds = (draft: SetupDraft) => Object.entries(draft.capabilities).filter(([, choice]) => choice.selected).map(([id]) => id)

/** Whether a capability may be turned on now: usable here, and not clashing with a choice. */
export const canTurnOn = (draft: SetupDraft, entry: CatalogueEntry | undefined) =>
  Boolean(entry) && selectable(entry!.availability) && !conflictsWith(draft, entry!.descriptor).length

/** The first reason the chosen capabilities can't go ahead, in words, or "". Every way something
 *  gets chosen ends here, whether it was ticked, added, searched for or read from a source:
 *  nothing planned, unsupported, unchecked, clashing or missing what it needs gets past it. */
export function selectionProblem(draft: SetupDraft, entries: CatalogueEntry[], profile?: GridProfile | null): string {
  const byId = new Map(entries.map(entry => [entry.descriptor.id, entry]))
  const name = (id: string) => byId.get(id)?.descriptor.name ?? id
  for (const id of selectedIds(draft)) {
    const entry = byId.get(id)
    if (!entry) return `${id} isn't known to this version of Yougori. Turn it off, or update Yougori.`
    const { descriptor, availability, reason } = entry
    if (!selectable(availability)) {
      return availability === "unknown"
        ? `Yougori hasn't checked yet whether ${descriptor.name} works on this computer. It tries again by itself.`
        : `${descriptor.name} can't be used here${reason ? `: ${reason.replace(/\.$/, "")}` : ""}. Turn it off to go on.`
    }
    const clash = conflictsWith(draft, descriptor)
    if (clash.length) return `${descriptor.name} can't be used together with ${clash.map(name).join(" or ")}. Turn one of them off.`
    const [missing] = missingRequirements(draft, descriptor, profile)
    if (missing) return `${descriptor.name} also needs ${missing.map(name).join(" or ")}. Add it, or turn ${descriptor.name} off.`
  }
  return ""
}

const NAME = /^[A-Za-z0-9][A-Za-z0-9 ._-]{0,47}$/

/** Empty while the name may be used. */
export function nameProblem(name: string) {
  const trimmed = name.trim()
  if (!trimmed) return "Give it a name."
  if (!NAME.test(trimmed)) return "Use letters, digits, spaces, dots, dashes or underscores, up to 48 characters, starting with a letter or digit."
  return ""
}
