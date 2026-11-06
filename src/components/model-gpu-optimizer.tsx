import { useEffect, useRef, useState } from "react"
import { modelsApi, type GpuOptimizer, type ModelAdmission, type ModelStatus, type RunnerCapability } from "@/api/projects-api"
import { Switch } from "@/components/ui/switch"
import { Input } from "@/components/ui/input"
import { Button } from "@/components/ui/button"

const gb = (bytes: number) => `${(bytes / 1073741824).toFixed(1)} GB`
const tokens = (count: number) => `${count.toLocaleString("en-US")} tokens`

/** A grant the runner does not enforce itself: the engine reserves it on the host ledger. */
function reservedGrant(admission: ModelAdmission) {
  if (admission.profile === "local-single-llama-cpp-v1") return `Shared GPU grant of ${gb(admission.bytes)}: the model's weights, the KV cache of its context and llama.cpp's buffers, reserved beside other models.`
  if (admission.profile === "local-single-vllm-v1") return "vLLM's GPU grant: at least 90% of the GPU, reserved while it is loaded; other models load when it is parked."
  return `Shared GPU grant of ${gb(admission.bytes)}.`
}

/** What the runner's launch supports and does not, as the runner itself reports it (not host evidence). */
const CAPABILITY_NAMES: Record<string, string> = { kvGrowth: "KV growth in increments", adapters: "Unmerged adapters (LoRA)", kvReuse: "KV reuse across requests" }

export function ModelGpuOptimizer({ environmentId }: { environmentId: string }) {
  const [value, setValue] = useState<GpuOptimizer | null>(null)
  const [health, setHealth] = useState<Pick<ModelStatus, "context" | "capabilities" | "admission"> | null>(null)
  const [idle, setIdle] = useState("0")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  // Polls and saves can resolve out of order; only the newest-started request is shown.
  const order = useRef({ started: 0, applied: 0 })
  useEffect(() => {
    let active = true, first = true, reading = false
    const refresh = () => {
      if (reading) return
      const sequence = ++order.current.started
      // The whole status: the optimizer beside the served context and the runner's capability facts.
      const request = modelsApi.status?.(environmentId)
      if (!request) return
      reading = true
      void request.then(status => {
        const next = status?.optimizer
        if (!active || !next?.supported || sequence <= order.current.applied) return
        order.current.applied = sequence
        setValue(next); setHealth({ context: status.context, capabilities: status.capabilities, admission: status.admission })
        if (first) { setIdle(String(next.idleTimeoutSeconds)); first = false }
      }).catch(() => {}).finally(() => { reading = false })
    }
    refresh()
    const timer = window.setInterval(refresh, 3000)
    return () => { active = false; window.clearInterval(timer) }
  }, [environmentId])
  const save = async (settings: { enabled?: boolean; pinned?: boolean; idleTimeoutSeconds?: number }) => {
    setBusy(true); setError("")
    const sequence = ++order.current.started
    try {
      const next = await modelsApi.optimizer(environmentId, settings)
      if (sequence > order.current.applied) { order.current.applied = sequence; setValue(next) }
    }
    catch (reason) { setError(String(reason)) }
    finally { setBusy(false) }
  }
  if (!value) return null
  const capabilities = Object.entries(health?.capabilities ?? {}).filter((entry): entry is [string, RunnerCapability] => Boolean(entry[1]))
  const memory = [
    value.allocatedBytes != null ? `${gb(value.allocatedBytes)} allocated` : null,
    value.peakAllocatedBytes != null ? `peak ${gb(value.peakAllocatedBytes)} since the last unload` : null,
    value.reservedBytes != null ? `${gb(value.reservedBytes)} reserved by the allocator` : null,
  ].filter(Boolean).join(" · ")
  return <section className="model-api-card" aria-label="GPU memory optimizer">
    <div className="model-api-row"><label htmlFor={`optimizer-${environmentId}`}>Automatic GPU memory</label><Switch id={`optimizer-${environmentId}`} checked={value.enabled} disabled={busy} onCheckedChange={enabled => void save({ enabled })} /></div>
    <p>{value.idleTimeoutSeconds === 0 ? "The current model stays loaded until another model needs the GPU." : `Models release GPU memory after ${value.idleTimeoutSeconds} idle seconds.`} Active requests finish before switching models.</p>
    <p role="status">{value.releaseUncertain ? "Memory release unconfirmed" : value.loading ? "Loading model" : value.resident ? "Ready" : "On demand"} · {value.active} active · {value.pending} waiting{value.allocatedBytes != null ? ` · ${gb(value.allocatedBytes)} allocated` : ""}</p>
    {value.waitingFor ? <p role="status" aria-label="Why this model waits for the GPU">Waiting for GPU · {value.waitingFor}</p> : null}
    {value.releaseUncertain ? <p role="alert">GPU memory may still be in use. Restart this model environment if it does not recover.</p> : null}
    <dl className="model-gpu-facts" aria-label="GPU memory limits">
      <dt>Admission</dt>
      <dd>{value.capacityBytes != null
        ? `Shared GPU grant of ${gb(value.capacityBytes)}${value.capacityContext != null ? `, covering ${tokens(value.capacityContext)} of context` : ""}. The runner holds its allocator to the grant and refuses a longer conversation.`
        : health?.admission ? reservedGrant(health.admission)
        : "One resident model at a time; no shared GPU grant for this model."}</dd>
      {health?.context != null ? <><dt>Context window</dt><dd>{tokens(health.context)}</dd></> : null}
      {memory ? <><dt>Memory</dt><dd>{memory}</dd></> : null}
    </dl>
    {capabilities.length ? <ul className="model-gpu-facts" aria-label="Runner capabilities">
      {capabilities.map(([name, fact]) => <li key={name}><strong>{CAPABILITY_NAMES[name] ?? name}</strong>: {fact.supported ? "supported" : "not supported by this runner"}{fact.detail ? ` · ${fact.detail}` : ""}</li>)}
    </ul> : null}
    {value.enabled ? <>
      <div className="model-api-row"><label htmlFor={`pin-${environmentId}`}>Prevent automatic model switching</label><Switch id={`pin-${environmentId}`} checked={value.pinned} disabled={busy} onCheckedChange={pinned => void save({ pinned })} /></div>
      <div className="model-api-enable"><label htmlFor={`idle-${environmentId}`}>Unload after idle seconds</label><Input id={`idle-${environmentId}`} type="number" min={0} max={3600} aria-describedby={`idle-hint-${environmentId}`} value={idle} onChange={event => setIdle(event.target.value)} /><Button size="sm" disabled={busy || idle.trim() === "" || !Number.isInteger(Number(idle)) || (Number(idle) !== 0 && (Number(idle) < 10 || Number(idle) > 3600))} onClick={() => void save({ idleTimeoutSeconds: Number(idle) })}>Save</Button></div>
      <p id={`idle-hint-${environmentId}`}>0 keeps the model loaded until switching. Use 10–3600 for timed unloading.</p>
    </> : null}
    {error ? <p role="alert">{error}</p> : null}
  </section>
}
