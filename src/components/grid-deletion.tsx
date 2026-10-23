import { useState } from "react"
import type { GridRun } from "@/components/grid-swarm"
import { Button } from "@/components/ui/button"
import { type DeleteWhen, type GridClosing, when } from "@/lib/grid-closing"
import "@/components/neo-grid.css"

/** The hub's delete control. Deleting asks how: in three days (paused and restorable until then)
 *  or now. While the grid is paused it offers Restore; once gone, to stop waiting for computers. */
export function DeleteGrid({ closing, run, what, remove, restore }: { closing: GridClosing | null | undefined; run: GridRun; what: string; remove(when: DeleteWhen): Promise<unknown>; restore(): Promise<unknown> }) {
  const [asking, setAsking] = useState<"" | "delete" | "forget">("")
  if (closing && !closing.gone) {
    return <>
      <Button size="xs" onClick={() => void run(`Restoring the ${what}`, restore, `The ${what} is restored`)}>Restore</Button>
      {asking === "delete"
        ? <Button size="xs" variant="destructive" onClick={() => { setAsking(""); void run(`Deleting the ${what}`, () => remove("now"), `The ${what} is deleted`) }}>Confirm delete now</Button>
        : <Button size="xs" variant="ghost" onClick={() => setAsking("delete")}>Delete now</Button>}
    </>
  }
  if (closing?.gone) {
    return asking === "forget"
      ? <><Button size="xs" variant="destructive" onClick={() => { setAsking(""); void run(`Finishing the ${what}'s deletion`, () => remove("forget"), `The ${what} is gone`) }}>Confirm</Button><Button size="xs" variant="ghost" onClick={() => setAsking("")}>Cancel</Button></>
      : <Button size="xs" variant="outline" title="Stop waiting for computers that are away; they keep trying to reach it until their person leaves" onClick={() => setAsking("forget")}>Stop waiting</Button>
  }
  if (asking === "delete") {
    return <span className="grid-delete-choice" role="group" aria-label={`Delete the ${what}`}>
      <Button size="xs" variant="outline" title="Paused at once; you can restore it for three days, then it is deleted" onClick={() => { setAsking(""); void run(`Pausing the ${what}`, () => remove("later"), `The ${what} is paused and will be deleted in three days`) }}>Delete in 3 days</Button>
      <Button size="xs" variant="destructive" title="Every computer is told at its next check-in and cleans up" onClick={() => { setAsking(""); void run(`Deleting the ${what}`, () => remove("now"), `The ${what} is deleted`) }}>Delete now</Button>
      <Button size="xs" variant="ghost" onClick={() => setAsking("")}>Cancel</Button>
    </span>
  }
  return <Button size="xs" variant="outline" onClick={() => setAsking("delete")}>Delete grid</Button>
}

/** What a grid being deleted means right now, on its hub. `keeps` says what computers keep while paused. */
export function ClosingLine({ closing, keeps, cleans }: { closing: GridClosing | null | undefined; keeps: string; cleans: string }) {
  if (!closing) return null
  return <p role="status" className="grid-line grid-closing" data-gone={closing.gone || undefined}>
    {closing.gone
      ? closing.computers === undefined
        ? <>Deleted. People’s computers hear it when they come online and {cleans}, until {when(closing.tellUntil)}.</>
        : <>Deleted. {closing.told} of {closing.computers} {closing.computers === 1 ? "computer has" : "computers have"} heard and {cleans}; the rest hear it when they come online, until {when(closing.tellUntil)}.</>
      : <>Paused, deleted on {when(closing.until)} unless you restore it. {keeps}</>}
  </p>
}
