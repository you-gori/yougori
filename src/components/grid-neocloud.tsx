import { useCallback, useEffect, useState } from "react"
import { gridApi, type GridRentedGpu, type GridRentedGpus as Rented, type GridResult } from "@/api/grid-api"
import type { GridRun } from "@/components/grid-swarm"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import { price, together } from "@/lib/rented-gpu"
import "@/components/neo-grid.css"

const gpuText = (pod: GridRentedGpu) => pod.gpu ? `${pod.gpuCount && pod.gpuCount > 1 ? `${pod.gpuCount} × ` : ""}${pod.gpu}` : "GPU"
const serving = (state?: string) => state === "available" || state === "busy"
/** Pods that may be billing: running, still powering on, or a create NeoCloud has yet to check.
 *  Stop all reaches every one. */
const billing = (podState?: string | null) => podState === "Running" || podState === "Starting" || podState === "Creating" || !!podState?.includes("inspect")

/** What each rented GPU is doing, in a few words. A stopped or failed pod never reads as working. */
const STATE: Record<string, string> = {
  available: "Serving",
  busy: "Answering",
  outside_schedule: "Ready, outside the plan's hours",
  preparing: "Starting its model",
  loading: "Loading its model",
  starting: "Pod starting",
  stopping: "Stopping",
  stopped: "Stopped",
  idle: "No model assigned",
  error: "Needs attention",
}

/** Rented NeoCloud GPUs in the grid this computer hosts. Each row says what the pod costs and
 *  what it is doing. Nothing here rents or starts a pod: renting stays in NeoCloud, with its own
 *  price review, and one control stops every rented GPU at once. While no grid runs here, pods
 *  still listed stay in view, stopped, to remove; so do the notes on how their stops went. */
export function GridRentedGpus({ run }: { run: GridRun }) {
  const [rented, setRented] = useState<Rented | null>(null)
  const [chosen, setChosen] = useState("")
  const [error, setError] = useState("")

  const refresh = useCallback(async () => {
    try {
      setRented(await gridApi.rentedGpus())
      setError("")
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    }
  }, [])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 10_000)
    return () => window.clearInterval(timer)
  }, [refresh])

  // A warning means a pod may still be billing, so it reads as unfinished, never as done. The
  // engine says what actually happened, and a stop NeoCloud has not confirmed is a stop sent, not
  // one finished: its words are shown, and `done` stands in only when it gave none.
  const act = async (job: string, work: () => Promise<GridResult>, done: string) => {
    await run(job, async () => {
      const result = await work()
      if (result?.warning) throw new Error(result.warning)
      toastManager.add({ title: result?.message || done, type: "success" })
      return result
    })
    await refresh()
  }

  if (!rented || !rented.hosting && !rented.members.length && !rented.notices.length) return error ? <p role="alert" className="grid-line grid-error">{error}</p> : null
  const { hosting, members, candidates, max, hourlyUsd, unpriced, notice, notices } = rented
  const full = members.length >= max
  const pick = candidates.some(pod => pod.environmentId === chosen) ? chosen : candidates[0]?.environmentId ?? ""
  const running = members.filter(member => billing(member.podState))

  return <section aria-label="Rented GPUs" className="grid-part">
    <p className="grid-part-title">Rented GPUs <span>NeoCloud · {members.length} of {max}{running.length ? ` · ${together(hourlyUsd, unpriced)} while powered on` : ""}</span></p>
    {notice ? <p role="status" className="grid-line grid-muted">{notice}</p> : null}
    {notices.slice().reverse().map(said => <p key={`${said.at}-${said.text}`} role={said.warning ? "alert" : "status"} className={said.warning ? "grid-line grid-error" : "grid-note"}>{said.text}</p>)}
    {error ? <p role="alert" className="grid-line grid-error">{error}</p> : null}
    {members.map(member => <div key={member.environmentId}>
      <p className="grid-line">
        <i aria-hidden="true" className="grid-dot" data-online={serving(member.state) || undefined} />
        <span className="grid-key" title={member.name}>{member.name}</span>
        <span className="grid-muted">
          {gpuText(member)} · {price(member.hourlyUsd)} · {STATE[member.state ?? ""] ?? member.state}
          {serving(member.state) && member.model ? ` · ${member.model} · ${member.jobs ?? 0} ${member.jobs === 1 ? "job" : "jobs"}` : ""}
        </span>
        <span className="grid-line-actions">
          <Button size="xs" variant="ghost" title="Takes it out of the grid and stops the pod. Its disk stays in NeoCloud until you delete it there." onClick={() => void act(`Removing ${member.name}`, () => gridApi.removeRentedGpu(member.environmentId), billing(member.podState) ? `${member.name} left the grid and was stopped` : `${member.name} left the grid`)}>Remove and stop</Button>
        </span>
      </p>
      {member.reason && !serving(member.state) ? <p className="grid-note">{member.reason}</p> : null}
    </div>)}
    {hosting && candidates.length && !full ? <div className="grid-line">
      <select aria-label="Rented GPU pod to add" className="grid-select-field" value={pick} onChange={event => setChosen(event.target.value)}>
        {candidates.map(pod => <option key={pod.environmentId} value={pod.environmentId}>
          {pod.name} · {gpuText(pod)} · {price(pod.hourlyUsd)}{pod.podState && pod.podState !== "Running" ? ` · ${pod.podState}` : ""}
        </option>)}
      </select>
      <span className="grid-line-actions">
        <Button size="xs" disabled={!pick} onClick={() => void act("Adding the rented GPU", () => gridApi.addRentedGpu(pick), "The rented GPU joined the grid")}>Add to grid</Button>
      </span>
    </div> : null}
    {hosting ? <p className="grid-note">
      {full ? `This grid has its ${max} rented GPUs; remove one to add another. `
        : candidates.length ? "" : "No rented GPU pod is free to add. Rent one under Sandboxes, New environment, Neocloud, then add it here. "}
      Each rented GPU is billed by RunPod by the hour while it runs. It serves the models you assign under Models (safetensors models only), and it is stopped when it leaves the grid or Yougori quits.
    </p> : null}
    {running.length ? <div className="grid-line">
      <span className="grid-muted">{running.length} powered on · {together(hourlyUsd, unpriced)} together</span>
      <span className="grid-line-actions">
        <Button size="xs" variant="outline" onClick={() => void act("Stopping every rented GPU", () => gridApi.stopRentedGpus(), "Every rented GPU was stopped")}>Stop all rented GPUs</Button>
      </span>
    </div> : null}
  </section>
}
