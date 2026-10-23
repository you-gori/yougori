/** Deep links into the one Grids area.
 *
 *  The four products used to be four entries in the sidebar, and a window could be opened on one
 *  of them with `?page=grid`. They are one area now, so the address says which grid is in front
 *  and whether its own page or its status is wanted. Both spellings are read for good; only the
 *  new one is ever written.
 *
 *  The word in the address is the grid's own word, never an identifier.
 */

/** The four grids a person already knows by name. */
export type GridKey = "models" | "workspaces" | "credentials" | "research"

/** What the Grids area is showing: the list, one grid's status, or one grid's own page. */
export type GridFocus =
  | null
  | { kind: "status"; grid: GridKey }
  | { kind: "page"; grid: GridKey }

/** The word each grid is spelled with in an address. */
export const GRID_WORD: Record<GridKey, string> = {
  models: "neo",
  workspaces: "sandbox",
  credentials: "access",
  research: "research",
}

/** Everything that has ever named one of these grids in an address. */
const WORDS: Record<string, GridKey> = {
  neo: "models",
  grid: "models",
  models: "models",
  sandbox: "workspaces",
  desks: "workspaces",
  workspaces: "workspaces",
  access: "credentials",
  credentials: "credentials",
  research: "research",
  swarm: "research",
}

/** Which grid an address names, and what it wants to see of it. An address with no grid in it
 *  leaves the area on its list, which is what a person who typed nothing asked for. */
export function gridFocusFromSearch(search: string): GridFocus {
  const parameters = new URLSearchParams(search)
  const named = parameters.get("grid") ?? parameters.get("page")
  if (!named) return null
  const grid = WORDS[named.trim().toLowerCase()]
  if (!grid) return null
  // `?page=` is the older spelling and always meant the product's own page.
  const wants = parameters.get("grid") ? parameters.get("show") : "page"
  return { kind: wants === "status" ? "status" : "page", grid }
}

/** The address for what is in front now, so a window can be opened on it again. */
export function gridSearchFor(focus: GridFocus): string {
  if (!focus) return ""
  const word = GRID_WORD[focus.grid]
  return focus.kind === "status" ? `?grid=${word}&show=status` : `?grid=${word}`
}
