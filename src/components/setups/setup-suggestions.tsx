import { useMemo } from "react"
import { GROUP_NAME } from "@/api/setups/catalogue"
import { Button } from "@/components/ui/button"
import { useSetupBuilder } from "./builder-context"
import { findSetupMatches } from "./setup-search"

/** What a Hub search found among the capability groups: each group a word names, with the
 *  capabilities in it that match, and a way to start a template with it. */
export function SetupSuggestions({ query }: { query: string }) {
  const builder = useSetupBuilder()
  const matches = useMemo(() => findSetupMatches(query), [query])
  if (!matches.groups.length) return null
  return <section className="setup-suggest" aria-label="Capabilities">
    {matches.groups.map(({ group, capabilities }) => <div key={group} className="setup-suggest-row">
      <span className="setup-suggest-name">{GROUP_NAME[group]}</span>
      <span className="setup-note">{capabilities.length ? capabilities.slice(0, 4).map(capability => capability.name).join(", ") : "Capabilities a template can have."}</span>
      <Button size="xs" variant="outline" onClick={() => builder.open({ mode: "create", group, ...(capabilities.length === 1 ? { capability: capabilities[0]!.id } : {}) })}>Create a template with it</Button>
    </div>)}
  </section>
}
