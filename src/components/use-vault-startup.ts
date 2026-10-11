import { useEffect, useRef, useState } from "react"
import { vaultApi } from "@/api/vault-api"

// A slow start offers "Open Yougori" without cancelling it; a later success still unblocks.
export const VAULT_STARTUP_NOTICE_MS = 30_000

export function useVaultStartup(platformReady: boolean) {
  const [ready, setReady] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [attempt, setAttempt] = useState(0)
  const startup = useRef<ReturnType<typeof vaultApi.bootstrap> | null>(null)
  const pending = useRef(false)
  useEffect(() => {
    if (!platformReady) return
    let active = true
    if (!startup.current) {
      pending.current = true
      startup.current = vaultApi.bootstrap()
      void startup.current.catch(() => undefined).finally(() => { pending.current = false })
    }
    const slow = setTimeout(() => {
      if (active) setError(current => current ?? "Could not start Personal Vault: it is taking longer than expected.")
    }, VAULT_STARTUP_NOTICE_MS)
    void startup.current.then(result => {
      if (result.created && !result.ready && !result.updateRequired) throw new Error("The vault container is not ready yet")
      if (active) { setError(null); setReady(true) }
    }).catch(reason => {
      if (active) setError(`Could not start Personal Vault: ${reason instanceof Error ? reason.message : String(reason)}`)
    }).finally(() => clearTimeout(slow))
    return () => { active = false; clearTimeout(slow) }
  }, [platformReady, attempt])
  return {
    ready,
    error,
    // A still-running bootstrap is reused instead of starting a second one.
    retry: () => { if (!pending.current) startup.current = null; setError(null); setReady(false); setAttempt(value => value + 1) },
    continueWithoutVault: () => { if (error) setReady(true) },
  }
}
