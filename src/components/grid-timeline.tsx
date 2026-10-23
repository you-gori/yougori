import { useMemo, useState } from "react"
import { Button } from "@/components/ui/button"
import type { GridRun } from "@/components/grid-swarm"
import { grids } from "@/api/grids"
import { may } from "@/lib/grid-capability"
import { timelineLine } from "@/lib/grid-words"
import type { GridRealm } from "@/lib/grid-realm"
import "@/components/neo-grid.css"
import "@/components/grids.css"

/** One grid's activity and its record, which are the same stream.
 *
 *  Grid Core writes one sealed event per decision, with a principal id and a dotted action such
 *  as `realm.lifecycle`. Neither is ever shown here: `@/lib/grid-words` turns the first into a
 *  person's name and the second into a sentence, and the four products' own words go through the
 *  same door, so one timeline reads as one thing. It is one card, read top to bottom like a feed,
 *  with each entry's time under its sentence rather than in a column of its own.
 */
export function GridTimeline({ realm, run }: { realm: GridRealm; run: GridRun }) {
  const [checked, setChecked] = useState("")
  const people = useMemo(() => {
    const names = new Map<string, string>()
    for (const person of realm.people) {
      names.set(person.id, person.name)
      if (person.username) names.set(person.username, person.name)
    }
    return names
  }, [realm.people])
  if (!may(realm.held, "readAudit")) return null
  const lines = (realm.history ?? []).map(event => timelineLine(event, people))
  return <section aria-label="History" className="rollout-group">
    <h3 className="rollout-group-title">History <span>what was decided here, newest first</span></h3>
    {realm.history === null
      ? <p className="rollout-said">This grid does not keep a record of its own yet. What happens in it shows on its own page.</p>
      : <div className="rollout-card">
        {lines.length
          ? <ol className="realm-timeline">
            {lines.slice(0, 50).map(line => <li key={line.id} data-tone={line.refused ? "error" : undefined}>
              <p className="rollout-text"><strong>{line.who}.</strong> {line.what}{line.why ? ` ${line.why}` : ""}</p>
              <p className="rollout-said">{line.when}</p>
            </li>)}
          </ol>
          : <p className="rollout-said">Nothing has happened in this grid yet.</p>}
        {realm.key === "credentials" ? <div className="rollout-card-foot realm-foot">
          <p className="rollout-said">{checked || "The record is sealed entry by entry, so a changed entry shows up."}</p>
          <Button
            size="xs"
            variant="outline"
            onClick={() => void run("Checking the record", async () => {
              const answer = await grids.credentials.verifyHistory()
              setChecked(answer.message)
              return answer
            })}
          >Check the record</Button>
        </div> : null}
      </div>}
  </section>
}
