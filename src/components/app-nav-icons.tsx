import type { ReactNode } from "react"
import type { GridKey } from "@/lib/grid-link"
import "./app-nav-icons.css"

export type NavIconName = "computer" | "grids" | "hub" | GridKey

const round = (value: number) => Math.round(value * 100) / 100
const plus = (x: number, y: number) => `M${round(x - 2.2)} ${y}h4.4M${x} ${round(y - 2.2)}v4.4`
const diamond = (x: number, y: number, d: number) => `M${x} ${round(y - d)}l${d} ${d}l${-d} ${d}l${-d} ${-d}z`
const hexagon = (x: number, y: number, r: number) => {
  const w = round(r * 0.866), h = round(r / 2)
  return `M${x} ${round(y - r)}l${w} ${h}v${r}l${-w} ${h}l${-w} ${-h}v${-r}z`
}
const field = [5, 12, 19].flatMap(y => [5, 12, 19].filter(x => x !== 12 || y !== 12).map(x => plus(x, y))).join("")

// Drawn for this sidebar only: one stroke weight, one solid accent each, no stock symbols.
const marks: Record<NavIconName, ReactNode> = {
  // One box held on this computer's screen.
  computer: <><rect x="3.5" y="4" width="17" height="12" rx="2.5" /><rect x="9.5" y="7.5" width="5" height="5" rx="1.2" fill="currentColor" stroke="none" /><path d="M9 20.5 12 16l3 4.5" /></>,
  // The plus field from the brand films, gathered on one point.
  grids: <><path d={field} /><circle cx="12" cy="12" r="1.9" fill="currentColor" stroke="none" /></>,
  // Desks laid out as tiles, one of them taken.
  workspaces: <><path d={diamond(12, 6.4, 3.9)} fill="currentColor" /><path d={diamond(6.4, 12, 3.9) + diamond(17.6, 12, 3.9) + diamond(12, 17.6, 3.9)} /></>,
  // Model nodes joined into an N.
  models: <><path d="M6.5 17.5v-11l11 11v-11" /><circle cx="6.5" cy="17.5" r="1.9" fill="currentColor" stroke="none" /><circle cx="6.5" cy="6.5" r="1.9" fill="currentColor" stroke="none" /><circle cx="17.5" cy="17.5" r="1.9" fill="currentColor" stroke="none" /><circle cx="17.5" cy="6.5" r="1.9" fill="currentColor" stroke="none" /></>,
  // A small comb of cells, one being worked.
  research: <><path d={hexagon(7.6, 8.4, 3.4) + hexagon(16.4, 8.4, 3.4)} /><path d={hexagon(12, 15.9, 3.4)} fill="currentColor" /></>,
  // Shared setups: three stacked blocks, the top one lifted out to be taken.
  hub: <><path d="M4.5 15.5 12 19.5l7.5-4M4.5 11.5 12 15.5l7.5-4" /><path d="M12 4.5l7.5 4-7.5 4-7.5-4z" fill="currentColor" /></>,
  // An arched door with its keyhole.
  credentials: <><path d="M6.5 20v-9.5a5.5 5.5 0 0 1 11 0V20M4.5 20h15M12 14v2.8" /><circle cx="12" cy="12.8" r="1.6" fill="currentColor" stroke="none" /></>,
}

export function NavIcon({ name }: { name: NavIconName }) {
  return (
    <svg className="app-nav-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.6} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true" focusable="false">
      {marks[name]}
    </svg>
  )
}
