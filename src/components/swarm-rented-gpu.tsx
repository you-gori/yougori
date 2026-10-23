import { useCallback, useEffect, useId, useState } from "react"
import { noRentedGpus, swarmApi, type RentedGpuStop, type SwarmRentedGpus as Rented, type SwarmRentedPod } from "@/api/swarm-api"
import { gpuText, price, RENTED_MODELS, rentedLine, together, withoutPrefix, type Placement } from "@/lib/rented-gpu"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { toastManager } from "@/components/ui/toast"
import "@/components/neo-grid.css"
import "@/components/swarm.css"

/** The host's permission, asked when a closed bounty is created. Off unless ticked, every time. */
export function RentedGpuPermission({ checked, onChange, disabled }: { checked: boolean; onChange(checked: boolean): void; disabled?: boolean }) {
  return <label className="swarm-check">
    <input type="checkbox" checked={checked} disabled={disabled} onChange={event => onChange(event.target.checked)} />
    <span>Let workers send this bounty's code to a GPU rented from an outside provider (RunPod), for their model to read. Leave this off to keep the code on the workers' own computers.</span>
  </label>
}

/** The choice in a closed bounty's worker step. Offered only when the bounty's host allowed rented
 *  GPUs; otherwise it says which bounty did not, and the model runs here. */
export function ModelPlacement({ title, allowed, value, onChange, disabled }: {
  title: string; allowed: boolean; value: Placement | null; onChange(value: Placement | null): void; disabled?: boolean
}) {
  const name = useId()
  const [pods, setPods] = useState<SwarmRentedPod[] | null>(null)
  // A list that could not be read is not an empty one: read as "none free", it would invite the
  // person to rent a second GPU beside one they already have.
  const [failed, setFailed] = useState("")
  const [attempt, setAttempt] = useState(0)
  useEffect(() => {
    if (!allowed) return
    let alive = true
    void swarmApi.rentedGpus()
      .then(rented => { if (alive) { setPods(rented.candidates); setFailed("") } })
      .catch(reason => { if (alive) setFailed(reason instanceof Error ? reason.message : String(reason)) })
    return () => { alive = false }
  }, [allowed, attempt])
  // A choice made before the pods arrived takes the first one, so the list never shows a pod that
  // is not the one chosen.
  useEffect(() => {
    if (value && !value.pod && pods?.length) onChange({ ...value, pod: pods[0]!.environmentId })
  }, [pods, value, onChange])

  if (!allowed) return <p className="grid-hint">“{title}” doesn't allow its code on a rented GPU, so the model runs on this computer.</p>
  const pod = pods?.find(candidate => candidate.environmentId === value?.pod)
  return <div className="grid-field">
    <span className="grid-field-label" id={`${name}-label`}>Where the model runs</span>
    <div role="radiogroup" aria-labelledby={`${name}-label`} style={{ display: "grid", gap: 8 }}>
      <label className="swarm-check">
        <input type="radio" name={name} checked={!value} disabled={disabled} onChange={() => onChange(null)} />
        <span>On this computer</span>
      </label>
      <label className="swarm-check">
        <input type="radio" name={name} checked={Boolean(value)} disabled={disabled} onChange={() => onChange({ pod: pods?.[0]?.environmentId ?? "", model: RENTED_MODELS[0]!.id })} />
        <span>On a GPU you rented in NeoCloud. The bounty's host allows its code there.</span>
      </label>
    </div>
    {value ? <div style={{ display: "grid", gap: 8 }}>
      {failed && pods === null ? <p role="alert" className="grid-error">Yougori could not read your rented GPUs ({failed}). Nothing was changed. <Button size="xs" variant="ghost" disabled={disabled} onClick={() => { setFailed(""); setAttempt(count => count + 1) }}>Try again</Button></p>
        : pods === null ? <p role="status" className="grid-hint">Looking for your rented GPUs…</p>
        : pods.length ? <select aria-label="Rented GPU" className="grid-select-field" value={value.pod} disabled={disabled} onChange={event => onChange({ ...value, pod: event.target.value })}>
          {pods.map(candidate => <option key={candidate.environmentId} value={candidate.environmentId}>{candidate.name} · {gpuText(candidate)} · {price(candidate.hourlyUsd)}</option>)}
        </select>
        : <p className="grid-hint" data-tone="short">No rented GPU is running and free. Rent one under Sandboxes, New environment, Neocloud, start it there, then come back. Yougori never rents or starts a GPU for you.</p>}
      <Input aria-label="Model on the rented GPU" value={value.model} disabled={disabled} placeholder="owner/model" spellCheck={false} autoComplete="off" onChange={event => onChange({ ...value, model: withoutPrefix(event.target.value) })} />
      <div className="swarm-suggest" role="group" aria-label="Models for a rented GPU">
        {RENTED_MODELS.map(model => <button key={model.id} type="button" disabled={disabled} aria-pressed={value.model === model.id} title={model.id} onClick={() => onChange({ ...value, model: model.id })}>
          <strong>{model.label}</strong><span>{model.note}</span>
        </button>)}
      </div>
      <p className="grid-hint">A rented GPU runs the model with vLLM, and only Qwen 2.5, Qwen 3, Llama 3, gpt-oss and Gemma 4 models call tools there, so other models are not listed. GGUF models run on this computer.</p>
      <p className="grid-hint">The bounty's code and the agent's work are sent to this GPU. {pod ? `It is billed by RunPod at ${price(pod.hourlyUsd)} while it runs. ` : "It is billed by RunPod by the hour while it runs. "}Pausing the worker keeps it running; stopping or removing the worker stops it.</p>
    </div> : null}
  </div>
}

/** A warning means a pod may still be billing, so it reads as unfinished, never as done. Otherwise
 *  the engine's own words are shown: a stop NeoCloud has not confirmed is a stop sent, not one
 *  finished, and `done` stands in only when the engine said nothing. */
const settled = (work: () => Promise<RentedGpuStop>, done: string) => async () => {
  const result = await work()
  if (result?.warning) throw new Error(result.warning)
  toastManager.add({ title: result?.message || done, type: "success" })
  return result
}

type Run = (job: string, work: () => Promise<unknown>, done?: string) => Promise<unknown>

/** The Swarm page's rented GPUs: what each worker's GPU costs and does, one Stop for each, one for
 *  all, and how the latest stops went. Nothing here rents or starts a pod. */
export function SwarmRentedGpus({ run, refreshKey }: { run: Run; refreshKey?: unknown }) {
  const [rented, setRented] = useState<Rented>(noRentedGpus)
  const [error, setError] = useState("")
  const refresh = useCallback(async () => {
    try { setRented(await swarmApi.rentedGpus()); setError("") }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
  }, [])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 10_000)
    return () => window.clearInterval(timer)
  }, [refresh, refreshKey])

  const act = async (job: string, work: () => Promise<RentedGpuStop>, done: string) => {
    await run(job, settled(work, done))
    await refresh()
  }

  const { workers, notices, hourlyUsd, unpriced } = rented
  if (!workers.length && !notices.length) return error ? <p role="alert" className="grid-error">{error}</p> : null
  const billing = workers.filter(worker => worker.billing)
  return <div className="grid-sheet"><section aria-label="Rented GPUs" className="grid-part">
    <p className="grid-part-title">Rented GPUs <span>NeoCloud · {workers.length} {workers.length === 1 ? "worker" : "workers"}{billing.length ? ` · ${together(hourlyUsd, unpriced)} while powered on` : ""}</span></p>
    {error ? <p role="alert" className="grid-error">{error}</p> : null}
    {workers.map(worker => <p key={worker.workerId} className="grid-line">
      <i aria-hidden="true" className="grid-dot" data-online={(worker.billing && worker.workerState !== "paused") || undefined} />
      <span className="grid-key" title={worker.workerName}>{worker.workerName}</span>
      <span className="grid-muted">{rentedLine(worker)}</span>
      {worker.billing ? <span className="grid-line-actions">
        <Button size="xs" variant="ghost" title="Pauses the worker and stops its rented GPU. Its disk stays in NeoCloud." onClick={() => void act(`Stopping ${worker.workerName}'s rented GPU`, () => swarmApi.stopRentedGpu(worker.workerId), `${worker.name ?? "The rented GPU"} was stopped and ${worker.workerName} paused. Start the GPU in NeoCloud, then choose Resume.`)}>Stop rented GPU</Button>
      </span> : null}
    </p>)}
    {notices.slice().reverse().map(notice => <p key={`${notice.at}-${notice.text}`} role={notice.warning ? "alert" : undefined} className={notice.warning ? "grid-error" : "grid-note"}>{notice.text}</p>)}
    <p className="grid-note">Each rented GPU is billed by RunPod by the hour while it runs. A paused worker keeps its GPU running; stopping or removing a worker stops it, and so does quitting Yougori.</p>
    {billing.length ? <div className="grid-line">
      <span className="grid-muted">{billing.length} powered on · {together(hourlyUsd, unpriced)} together</span>
      <span className="grid-line-actions">
        <Button size="xs" variant="outline" onClick={() => void act("Stopping every rented GPU", () => swarmApi.stopRentedGpus(), "Every rented GPU was stopped and its worker paused. Start them in NeoCloud, then choose Resume.")}>Stop all rented GPUs</Button>
      </span>
    </div> : null}
  </section></div>
}
