import { useCallback, useEffect, useState } from "react"
import { marketApi, type NetworkStatus } from "@/api/market-api"

export function useNetwork(enabled = true) {
  const [status, setStatus] = useState<NetworkStatus | null>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const refresh = useCallback(async () => { const value = await marketApi.status(); setStatus(value); return value }, [])
  useEffect(() => {
    if (!enabled) return
    let alive = true, stop = () => {}, timer = 0
    const update = (value: NetworkStatus) => { if (alive) { setStatus(value); setError("") } }
    // Subscribe before the first read so a sign-in from the CLI is visible immediately.
    void marketApi.listen(update).then(unlisten => { if (alive) stop = unlisten; else unlisten() }).catch(() => {})
    const poll = async () => {
      try { update(await marketApi.status()) }
      catch (reason) { if (alive) setError(String(reason)) }
      finally { if (alive) timer = window.setTimeout(poll, 5000) }
    }
    void poll()
    return () => { alive = false; stop(); window.clearTimeout(timer) }
  }, [enabled])
  const perform = async (action: () => Promise<unknown>) => {
    if (busy) return
    setBusy(true); setError("")
    try { await action(); await refresh() }
    catch (reason) { setError(String(reason)) }
    finally { setBusy(false) }
  }
  return { status, setStatus, error, setError, busy, refresh, perform }
}
