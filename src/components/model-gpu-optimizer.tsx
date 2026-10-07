import { useEffect, useState } from "react"
import { modelsApi, type GpuOptimizer } from "@/api/projects-api"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

export function ModelGpuOptimizer({ environmentId }: { environmentId: string }) {
  const [value, setValue] = useState<GpuOptimizer | null>(null)
  const [idle, setIdle] = useState("0")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  useEffect(() => {
    let active = true, first = true
    const refresh = () => modelsApi.optimizer?.(environmentId)?.then(next => {
      if (active && next?.supported) { setValue(next); if (first) { setIdle(String(next.idleTimeoutSeconds)); first = false } }
    }).catch(() => {})
    void refresh()
    const timer = window.setInterval(refresh, 3000)
    return () => { active = false; window.clearInterval(timer) }
  }, [environmentId])
  const save = async (settings: { enabled?: boolean; pinned?: boolean; idleTimeoutSeconds?: number }) => {
    setBusy(true); setError("")
    try { setValue(await modelsApi.optimizer(environmentId, settings)) }
    catch (reason) { setError(String(reason)) }
    finally { setBusy(false) }
  }
  if (!value) return null
  return <section className="model-api-card" aria-label="GPU memory optimizer">
    <div className="model-api-row"><label htmlFor={`optimizer-${environmentId}`}>Automatic GPU memory</label><Switch id={`optimizer-${environmentId}`} checked={value.enabled} disabled={busy} onCheckedChange={enabled => void save({ enabled })} /></div>
    <p>{value.idleTimeoutSeconds === 0 ? "The current model stays loaded until another model needs the GPU." : `Models release GPU memory after ${value.idleTimeoutSeconds} idle seconds.`} Active requests finish before switching models.</p>
    <p role="status">{value.loading ? "Loading model" : value.resident ? "Ready" : "On demand"} · {value.active} active · {value.pending} waiting{value.allocatedBytes != null ? ` · ${(value.allocatedBytes / 1073741824).toFixed(1)} GB allocated` : ""}</p>
    {value.enabled ? <>
      <div className="model-api-row"><label htmlFor={`pin-${environmentId}`}>Prevent automatic model switching</label><Switch id={`pin-${environmentId}`} checked={value.pinned} disabled={busy} onCheckedChange={pinned => void save({ pinned })} /></div>
      <div className="model-api-enable"><label htmlFor={`idle-${environmentId}`}>Unload after idle seconds</label><Input id={`idle-${environmentId}`} type="number" min={0} max={3600} aria-describedby={`idle-hint-${environmentId}`} value={idle} onChange={event => setIdle(event.target.value)} /><Button size="sm" disabled={busy || idle.trim() === "" || !Number.isInteger(Number(idle)) || (Number(idle) !== 0 && (Number(idle) < 10 || Number(idle) > 3600))} onClick={() => void save({ idleTimeoutSeconds: Number(idle) })}>Save</Button></div>
      <p id={`idle-hint-${environmentId}`}>0 keeps the model loaded until switching. Use 10–3600 for timed unloading.</p>
    </> : null}
    {error ? <p role="alert">{error}</p> : null}
  </section>
}
