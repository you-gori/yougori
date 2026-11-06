import { CATALOGUE, GROUPS } from "@/api/setups/catalogue"
import type { CapabilityDescriptor, CapabilityGroup } from "@/api/setups/types"

/** Finding capabilities by the words people use for them.
 *
 *  A template is made of capabilities from the six shared groups, so a search lands on a group,
 *  and on the capabilities in it whose name, alias or example matches. There is no starter
 *  catalogue to search beside them: an author builds from the groups themselves.
 */

/** Lower case, letters and digits only, single spaces. */
export function normaliseQuery(value: string) {
  return value.toLowerCase().replace(/&/g, " and ").replace(/[^a-z0-9]+/g, " ").trim()
}

const wordsOf = (value: string) => normaliseQuery(value).split(" ").filter(Boolean)

/** True when every word typed starts a word of the text, so "back" finds "Backups". */
function covers(text: string, query: string) {
  const have = wordsOf(text)
  const want = wordsOf(query)
  return want.length > 0 && want.every(word => have.some(one => one === word || (word.length >= 3 && one.startsWith(word))))
}

export interface SetupMatches {
  /** Each group that matched, with the capabilities in it that matched by name or alias. */
  groups: { group: CapabilityGroup; capabilities: CapabilityDescriptor[] }[]
}

/** What a search finds among the capability groups. Short or empty queries find nothing. */
export function findSetupMatches(query: string, catalogue: readonly CapabilityDescriptor[] = CATALOGUE): SetupMatches {
  const typed = normaliseQuery(query)
  if (typed.length < 2) return { groups: [] }
  const capabilityHits = catalogue.filter(capability => [capability.name, ...capability.aliases, ...capability.examples].some(text => covers(text, typed)))
  const groups = GROUPS
    .map(group => ({
      group: group.id,
      capabilities: capabilityHits.filter(capability => capability.group === group.id),
      named: covers(group.name, typed) || group.words.some(word => covers(word, typed)),
    }))
    .filter(entry => entry.named || entry.capabilities.length)
  return { groups: groups.map(({ group, capabilities }) => ({ group, capabilities })) }
}
