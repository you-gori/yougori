import { Button } from "@/components/ui/button"
import type { SetupPlan } from "@/api/setups/types"
import { SetupReview } from "./setup-views"

/** The reviewed repair of a setup, the same on its card and in its own view.
 *
 *  Repair only makes again the parts that are missing or have drifted from what the setup says, and
 *  touches nothing else. Nothing is deleted and nothing already in place is remade, so unlike a
 *  removal there is no destructive step: the review names the parts it would put back, and the
 *  button puts them back once it is confirmed. If the engine finds nothing out of place, the review
 *  says so and there is nothing to apply. */
export function SetupRepair({ name, plan, names, agreed, onAgree, busy, onRepair, onKeep }: {
  name: string
  plan: SetupPlan
  names?: Record<string, string>
  agreed: string[]
  onAgree(id: string, on: boolean): void
  busy: boolean
  onRepair(): void
  onKeep(): void
}) {
  // A repair that would change nothing still reviews cleanly: no resources to put back means the
  // setup already matches what it says, so there is nothing to apply.
  const nothing = !(plan.resources?.length || plan.changes?.length || plan.steps?.length)
  return <section className="setup-repair" aria-label={`Repair ${name}`}>
    <SetupReview plan={plan} names={names} agreed={agreed} onAgree={onAgree} />
    <p className="setup-note">{nothing
      ? "Nothing is missing or out of place, so there is nothing to put back. Your data and everything already in place are untouched."
      : "Only the parts above are put back. Nothing is deleted, and everything already in place and your data are untouched."}</p>
    <div className="setup-actions">
      <Button size="xs" disabled={busy || nothing || Boolean(plan.blockers?.length)} onClick={onRepair}>Repair {name}</Button>
      <Button size="xs" variant="ghost" onClick={onKeep}>Not now</Button>
    </div>
  </section>
}
