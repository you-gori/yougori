import { useState } from "react"
import { Button } from "@/components/ui/button"
import { AccessBackupDialog, AccessRestoreDialog } from "@/components/access-dialogs"
import { DeleteGrid } from "@/components/grid-deletion"
import type { GridRun } from "@/components/grid-swarm"
import { may } from "@/lib/grid-capability"
import { deletableGrid } from "@/lib/grid-deletion-plan"
import type { GridRealm } from "@/lib/grid-realm"
import "@/components/neo-grid.css"

/** Pausing, deleting, restoring and backing up one grid.
 *
 *  The three shipped grids all mean one thing by this: "Delete in 3 days" pauses the grid at once
 *  and keeps it restorable until then, "Delete now" ends it, and "Stop waiting" stops waiting for
 *  computers that are away. Those are the words `DeleteGrid` already has and the words people
 *  have already learned, so they are the words here too. Nothing was renamed to look tidier.
 *
 *  A control is offered only where the grid can really do it and the person may.
 */
export function GridControls({ realm, run, done }: { realm: GridRealm; run: GridRun; done(message?: string): void }) {
  const [backing, setBacking] = useState(false)
  const [restoring, setRestoring] = useState(false)
  const hosted = realm.role === "host"
  const deletion = deletableGrid(realm)
  return <>
    {realm.key === "credentials" && hosted && may(realm.held, "manageSecurity")
      ? <Button size="xs" variant="outline" title="Writes this grid to a file you choose. Its key is not in the file." onClick={() => setBacking(true)}>Back up</Button>
      : null}
    {realm.key === "credentials" && !hosted
      ? <Button size="xs" variant="outline" title="Runs this grid on this computer again from a backup file." onClick={() => setRestoring(true)}>Restore from backup</Button>
      : null}
    {deletion
      ? <DeleteGrid closing={realm.closing} run={run} what={deletion.what} remove={deletion.remove} restore={deletion.restore} />
      : null}
    {backing ? <AccessBackupDialog open={backing} onOpenChange={setBacking} onDone={done} /> : null}
    {restoring ? <AccessRestoreDialog open={restoring} suggestedAddress={null} onOpenChange={setRestoring} onDone={done} /> : null}
  </>
}
