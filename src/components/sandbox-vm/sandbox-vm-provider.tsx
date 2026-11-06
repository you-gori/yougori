import { useCallback, useEffect, useRef, useState, type ReactNode } from "react"
import { SandboxVmContext } from "./sandbox-vm-context"
import { isSandboxVmUnavailable, sandboxVmApi, type SandboxVmStatus } from "@/api/sandbox-vm-api"

/** One inventory shared by the workspace, counts and detail view. No overlapping reads. */
export function SandboxVmProvider({ children }: { children: ReactNode }) {
  const [status, setStatus] = useState<SandboxVmStatus | null>(null)
  const [error, setError] = useState("")
  const active = useRef(false)
  const unavailable = useRef(false)
  const pending = useRef<Promise<void> | null>(null)
  const refresh = useCallback((): Promise<void> => {
    if (pending.current) return pending.current
    const read = sandboxVmApi.status().then(value => {
      if (active.current) { setStatus(value); setError(""); unavailable.current = false }
    }).catch(reason => {
      if (active.current) {
        setError(reason instanceof Error ? reason.message : String(reason))
        unavailable.current = isSandboxVmUnavailable(reason)
      }
    }).finally(() => { pending.current = null })
    pending.current = read
    return read
  }, [])
  useEffect(() => {
    active.current = true
    let disposed = false
    let timer: ReturnType<typeof setTimeout>
    const poll = async () => {
      await refresh()
      if (!disposed && active.current && !unavailable.current) timer = setTimeout(() => void poll(), 5000)
    }
    void poll()
    return () => { disposed = true; active.current = false; clearTimeout(timer) }
  }, [refresh])
  return <SandboxVmContext.Provider value={{ status, error, refresh }}>{children}</SandboxVmContext.Provider>
}
