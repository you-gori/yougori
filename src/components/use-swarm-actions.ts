import { useRef, useState } from "react"
import { toastManager } from "@/components/ui/toast"

/** Serialize controls: a Resume clicked during Pause must run after Pause acknowledges it. */
export function useSwarmActions(refresh: () => Promise<unknown>) {
  const [busy, setBusy] = useState("")
  const tail = useRef<Promise<void>>(Promise.resolve())
  const pending = useRef(new Set<string>())
  const run = (job: string, work: () => Promise<unknown>, done?: string): Promise<void> => {
    if (pending.current.has(job)) return tail.current
    const queued = pending.current.size > 0
    pending.current.add(job)
    setBusy(queued ? `${job} (queued)` : job)
    const next = tail.current.then(async () => {
      setBusy(job)
      try {
        await work()
        if (done) toastManager.add({ title: done, type: "success" })
      } catch (reason) {
        toastManager.add({ title: `${job} did not finish`, description: reason instanceof Error ? reason.message : String(reason), type: "error" })
      } finally {
        try { await refresh() } finally {
          pending.current.delete(job)
          if (!pending.current.size) setBusy("")
        }
      }
    })
    // A failed status refresh must not discard the next control action.
    tail.current = next.catch(() => {})
    return tail.current
  }
  return { busy, run }
}
