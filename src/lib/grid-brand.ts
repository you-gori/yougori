/** A company's own name and support line on a grid.
 *
 *  This is presentation, and only presentation. Grid Core has no place to keep a brand: there is
 *  no brand row in `grid/src/core/store/schema.rs` and no field for one on a realm, and adding a
 *  schema step belongs with the phase that moves a product onto the core, not with a tab. So a
 *  brand is kept on this computer, for the person looking at this computer, and it travels
 *  nowhere: no other computer in the grid sees it, and a backup does not carry it.
 *
 *  It deliberately holds no colour. The app has exactly one writer of its theme tokens
 *  (`ThemeSync` in `src/app.tsx`, through `resolveAppearance`), and a second writer would fight
 *  it on every change of theme. A tenant's colours wait for that one writer to learn about them.
 *
 *  Tenants are grids. Each grid already has its own key, its own records, its own people and its
 *  own record of what happened, so the list of grids on this computer is the list of tenants, and
 *  nothing here crosses from one to another.
 */
import type { GridKey } from "@/lib/grid-link"

export interface GridBrand {
  /** What this company calls itself, where it is not what the grid was named. */
  company: string
  /** Who to ask when something here needs a person, in the admin's own words. */
  support: string
}

const EMPTY: GridBrand = { company: "", support: "" }

const where = (grid: GridKey) => `yougori.grid.brand.${grid}`

export function readGridBrand(grid: GridKey): GridBrand {
  try {
    const kept = window.localStorage.getItem(where(grid))
    if (!kept) return EMPTY
    const read = JSON.parse(kept) as Partial<GridBrand>
    return { company: String(read.company ?? ""), support: String(read.support ?? "") }
  } catch {
    return EMPTY
  }
}

/** An empty brand is removed rather than written, so nothing is left behind by clearing it. */
export function writeGridBrand(grid: GridKey, brand: GridBrand): void {
  try {
    if (!brand.company.trim() && !brand.support.trim()) window.localStorage.removeItem(where(grid))
    else window.localStorage.setItem(where(grid), JSON.stringify({ company: brand.company.trim(), support: brand.support.trim() }))
  } catch {
    // A computer that refuses to keep this still runs the grid; only the name on screen is lost.
  }
}

/** The name to show for a grid: the company's own, when it gave one. */
export function brandedName(name: string, brand: GridBrand): string {
  return brand.company.trim() || name
}
