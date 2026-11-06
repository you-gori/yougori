import { Button } from "@/components/ui/button"
import type { SetupPlan } from "@/api/setups/types"
import { SetupReview } from "./setup-views"

/** The reviewed removal of a setup, the same on its card and in its own view.
 *
 *  Data is kept. Only when the review offers to delete a volume (its template says
 *  `retention.onRemove: ask`) and the person ticks it does anything go, and then the last words
 *  before the button, and the button itself, name exactly which volumes, so nothing is deleted
 *  that they did not just read. */
export function SetupRemoval({ name, plan, names, agreed, onAgree, busy, onRemove, onKeep }: {
  name: string
  plan: SetupPlan
  names?: Record<string, string>
  agreed: string[]
  onAgree(id: string, on: boolean): void
  busy: boolean
  onRemove(): void
  onKeep(): void
}) {
  // What was ticked for deletion, by name: a volume goes with its backups (`delete_data:`), any
  // other part (a grid deleted now rather than paused, `delete_grid:`) on its own. A deletion the
  // review did not offer never counts.
  const ticked = (plan.consents ?? []).map(consent => consent.id).filter(id => id.startsWith("delete_") && agreed.includes(id))
  const volumes = ticked.filter(id => id.startsWith("delete_data:")).map(id => id.slice("delete_data:".length))
  const others = ticked.filter(id => !id.startsWith("delete_data:")).map(id => id.slice(id.indexOf(":") + 1))
  const deleting = [...volumes, ...others]
  const goes = deleting.join(", ")
  const said = [volumes.length ? `${volumes.join(", ")} and ${volumes.length === 1 ? "its" : "their"} backups` : "", others.join(", ")].filter(Boolean).join(", and ")
  return <section className="setup-removal" aria-label={`Remove ${name}`}>
    <SetupReview plan={plan} names={names} agreed={agreed} onAgree={onAgree} />
    <p className="setup-note">{deleting.length
      ? `Borrowed resources are never touched. ${said} ${volumes.length || deleting.length > 1 ? "are" : "is"} deleted, and that can't be undone. All other data is kept.`
      : "Borrowed resources are never touched. Data is kept unless you delete it separately."}</p>
    <div className="setup-actions">
      <Button size="xs" variant="destructive" disabled={busy || Boolean(plan.blockers?.length)} onClick={onRemove}>{deleting.length ? `Remove ${name} and delete ${goes}` : `Remove ${name}`}</Button>
      <Button size="xs" variant="ghost" onClick={onKeep}>Keep it</Button>
    </div>
  </section>
}
