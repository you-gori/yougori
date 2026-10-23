import { grids } from "@/api/grids"
import { may } from "@/lib/grid-capability"
import type { Action } from "@/api/grids/types"
import type { GridRealm } from "@/lib/grid-realm"
import type { DeleteWhen } from "@/lib/grid-closing"

/** What each grid calls itself in a sentence about deleting it. */
const WHAT: Record<GridRealm["key"], string> = {
  models: "grid",
  workspaces: "sandbox grid",
  credentials: "access grid",
  research: "research",
}

/** Which permission administers each of them. */
const ADMINISTERS: Record<GridRealm["key"], Action> = {
  models: "manageModels",
  workspaces: "manageWorkspaces",
  credentials: "manageCredentials",
  research: "doResearch",
}

/** How to delete one grid, and what to call it, or nothing when it may not be deleted from here.
 *
 *  A grid is deleted only on the computer that hosts it, only by somebody who may administer it,
 *  and never for research, which is ended by unpublishing its bounty rather than deleted here. The
 *  per-grid handlers are kept in one place so the grid row and the grid's Status view cannot drift
 *  apart about what "Delete grid" does.
 */
export function deletableGrid(realm: GridRealm): { what: string; remove(when: DeleteWhen): Promise<unknown>; restore(): Promise<unknown> } | null {
  if (realm.role !== "host" || realm.key === "research" || !may(realm.held, ADMINISTERS[realm.key])) return null
  const remove = (when: DeleteWhen) => {
    if (realm.key === "models") return grids.models.scheduleDeletion(when)
    if (realm.key === "workspaces") return grids.workspaces.scheduleDeletion(when)
    return grids.credentials.scheduleDeletion(when)
  }
  const restore = () => {
    if (realm.key === "models") return grids.models.restore()
    if (realm.key === "workspaces") return grids.workspaces.restore()
    return grids.credentials.restore()
  }
  return { what: WHAT[realm.key], remove, restore }
}
