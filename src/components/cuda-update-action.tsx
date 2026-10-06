import { useEffect, useRef, useState } from "react"
import { gpuApi } from "@/api/gpu-api"
import { Button } from "@/components/ui/button"
import type { Environment } from "@/types/platform"

export function needsCudaUpdate(environment: Environment, error: string | null | undefined) {
  return environment.provider === "yougoriCuda" && Boolean(error && /\[YOUGORI_CUDA_UPDATE_REQUIRED\]|CUDA runtime update is (?:required|available)/i.test(error))
}

/** Show beside a failed startup/storage check, using this environment's runtime drive. */
export function CudaUpdateAction({ environment, error, disabled, onUpdated, onBusyChange }: {
  environment: Environment; error?: string | null; disabled?: boolean; onUpdated?(): void | Promise<void>; onBusyChange?(busy: boolean): void
}) {
  if (!needsCudaUpdate(environment, error ?? environment.lastError)) return null
  return <UpdateRuntime key={`${environment.id}:${environment.storageDrive}`} environment={environment} disabled={disabled} onUpdated={onUpdated} onBusyChange={onBusyChange} />
}

function UpdateRuntime({ environment, disabled, onUpdated, onBusyChange }: {
  environment: Environment; disabled?: boolean; onUpdated?(): void | Promise<void>; onBusyChange?(busy: boolean): void
}) {
  const mounted = useRef(false)
  const lock = useRef(false)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState("")
  const [error, setError] = useState("")
  const [ready, setReady] = useState(false)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  const update = async () => {
    if (lock.current || disabled) return
    lock.current = true; setBusy(true); onBusyChange?.(true); setError(""); setMessage("")
    try {
      const drive = environment.storageDrive || undefined
      // Recheck at click time: old error text must never trigger an unnecessary update.
      let status = await gpuApi.cudaStatus(drive)
      if (!status.supported) throw new Error(status.detail)
      if (!status.installed || status.updateAvailable) {
        if (status.running) throw new Error("This CUDA runtime is in use. Close Yougori normally, reopen it, then update. Running containers were not stopped.")
        status = await gpuApi.installCuda(drive)
      }
      if (!status.supported || !status.installed || status.updateAvailable) throw new Error("The CUDA update is not ready yet. Recheck before starting this environment.")
      if (mounted.current) {
        setReady(true); setMessage("CUDA is up to date. Your disk was kept. You can start this environment.")
        await onUpdated?.()
      }
    } catch (reason) { if (mounted.current) setError(String(reason)) }
    finally { lock.current = false; if (mounted.current) setBusy(false); onBusyChange?.(false) }
  }
  return <div className="mt-2 space-y-2" aria-label="CUDA runtime update">
    {!ready ? <><p className="text-xs text-muted-foreground">Update the CUDA runtime{environment.storageDrive ? ` on ${environment.storageDrive}` : ""}. Existing container disks will be kept.</p>
      <Button type="button" size="sm" variant="outline" loading={busy} disabled={disabled || busy} onClick={() => void update()}>{busy ? "Updating…" : "Update now"}</Button></> : null}
    {message ? <p role="status" className="text-xs text-muted-foreground">{message}</p> : null}
    {error ? <p role="alert" className="text-xs text-destructive-foreground">{error}</p> : null}
  </div>
}
