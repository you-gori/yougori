import { useEffect, useMemo, useState } from "react"
import { runpodApi, type EndpointRequest, type HubInput, type HubRepo, type HubRepoDetails, type RunpodAccount, type RunpodCatalog } from "@/api/runpod-api"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { gpuPools, suggestName, validName } from "@/lib/runpod"
import { OrderFrame, type Order } from "./neocloud-frame"
import { Badge, Field, Pills, Tile } from "./neocloud-ui"

const categories = [["", "Everything"], ["language", "Chat and text"], ["image", "Images"], ["video", "Video"], ["audio", "Speech and audio"], ["embedding", "Search and embeddings"]] as const
const categoryNames: Record<string, string> = { language: "Chat and text", image: "Images", video: "Video", audio: "Speech and audio", embedding: "Embeddings" }
const initial = (input: HubInput) => input.default == null ? "" : String(input.default)

export interface EndpointProps { catalog: RunpodCatalog; account: RunpodAccount | null | undefined; taken: string[]; busy: boolean; error?: string; onBack(): void; onCreate(request: EndpointRequest): void }

export function EndpointWorkbench(props: EndpointProps) {
  const { catalog, taken, onCreate } = props
  const [step, setStep] = useState(0)
  const [category, setCategory] = useState<string>("")
  const [search, setSearch] = useState("")
  const [repos, setRepos] = useState<HubRepo[] | null>(null)
  const [loadError, setLoadError] = useState("")
  const [repo, setRepo] = useState<HubRepo | null>(null)
  const [details, setDetails] = useState<HubRepoDetails | null>(null)
  // A model's settings that failed to load say why on its own step, and can be asked for again.
  const [detailError, setDetailError] = useState("")
  const [detailAttempt, setDetailAttempt] = useState(0)
  const [values, setValues] = useState<Record<string, string>>({})
  const [gpuId, setGpuId] = useState("")
  const [workersMax, setWorkersMax] = useState(1)
  const [warm, setWarm] = useState(false)
  const [idle, setIdle] = useState(5)
  const [networkVolume, setNetworkVolume] = useState("")
  const [name, setName] = useState("")
  const [nameTouched, setNameTouched] = useState(false)

  useEffect(() => {
    let alive = true
    const timer = window.setTimeout(() => {
      setLoadError("")
      void runpodApi.hub(search.trim() || undefined).then(r => { if (alive) setRepos(r) }).catch(e => { if (alive) { setRepos([]); setLoadError(String(e)) } })
    }, search ? 350 : 0)
    return () => { alive = false; window.clearTimeout(timer) }
  }, [search])
  useEffect(() => {
    if (!repo) return
    let alive = true
    setDetails(null)
    setDetailError("")
    void runpodApi.hubRepo(repo.id).then(d => {
      if (!alive) return
      setDetails(d)
      setValues(Object.fromEntries(d.inputs.map(i => [i.key, initial(i)])))
    }).catch(e => { if (alive) setDetailError(String(e)) })
    return () => { alive = false }
  }, [repo, detailAttempt])
  useEffect(() => { if (!nameTouched) setName(suggestName([repo?.title ?? "endpoint"], taken)) }, [nameTouched, repo, taken])

  const shown = useMemo(() => (repos ?? []).filter(r => !category || r.category === category), [category, repos])
  const required = details?.inputs.filter(i => i.required || !i.advanced) ?? []
  const advanced = details?.inputs.filter(i => !i.required && i.advanced) ?? []
  const missing = required.filter(i => i.required && !values[i.key]?.trim())
  const configured = Boolean(details?.ready) && missing.length === 0 && workersMax >= 1 && idle >= 1 && idle <= 3600
  const nameTaken = taken.some(t => t.toLowerCase() === name.toLowerCase())
  const named = validName(name) && name.length >= 3 && !nameTaken
  const pools = details?.gpuPools.map(p => gpuPools[p] ?? p).join(" or ")
  const volume = catalog.volumes.find(v => v.id === networkVolume)
  const gpuName = gpuId ? catalog.gpus.find(g => g.id === gpuId)?.name ?? gpuId : pools ? `Recommended: ${pools}` : "Recommended"

  const field = (input: HubInput) => {
    const value = values[input.key] ?? ""
    const set = (v: string) => setValues(current => ({ ...current, [input.key]: v }))
    const label = <>{input.name}{input.required ? <span className="neo-note"> · required</span> : null}</>
    if (input.type === "boolean") return <label key={input.key} className="neo-check"><Checkbox checked={value === "true"} onCheckedChange={v => set(v === true ? "true" : "false")} /><span>{input.name}{input.description ? <span className="neo-field-hint" style={{ display: "block" }}>{input.description}</span> : null}</span></label>
    if (input.options.length) return <Field key={input.key} label={label} hint={input.description}><select className="neo-select" value={value} onChange={e => set(e.target.value)}><option value="">Default</option>{input.options.map(o => <option key={String(o.value)} value={String(o.value)}>{o.label}</option>)}</select></Field>
    const presets = details?.presets.map(p => p.defaults[input.key]).filter((v): v is string => typeof v === "string") ?? []
    return <Field key={input.key} label={label} hint={input.description}>
      <Input className="neo-input" value={value} type={input.secret ? "password" : input.type === "number" ? "number" : "text"} autoComplete="off" spellCheck={false}
        placeholder={input.type === "huggingface" ? "owner/model, for example Qwen/Qwen2.5-7B-Instruct" : undefined} onChange={e => set(e.target.value)} />
      {presets.length ? <span className="neo-pills">{presets.map(p => <button key={p} type="button" className="neo-pill" aria-pressed={value === p} onClick={() => set(p)}>{p}</button>)}</span> : null}
    </Field>
  }

  const submit = () => {
    if (!details) return
    const env = Object.fromEntries(Object.entries(values).filter(([key, value]) => value.trim() && value !== initial(details.inputs.find(i => i.key === key)!)).map(([k, v]) => [k, v.trim()]))
    onCreate({ name, hubId: details.id, title: details.title, category: details.category, env, gpuId, workersMin: warm ? 1 : 0, workersMax, idleTimeout: idle, networkVolumeId: networkVolume, location: volume?.location ?? "" })
  }

  const main = <>
    {step === 0 ? <div className="neo-stack">
      <Pills<string> label="Category" value={category} options={categories} onChange={setCategory} />
      <Input className="neo-input neo-search" aria-label="Search models and apps" placeholder="Search, for example Whisper, Flux or Llama" value={search} onChange={e => setSearch(e.target.value)} />
      <div className="neo-grid is-wide">
        {shown.map((r, i) => <Tile key={r.id} selected={repo?.id === r.id} label={`Use ${r.title}`} onSelect={() => { setRepo(r); setDetailAttempt(attempt => attempt + 1); setStep(1) }}
          title={r.title} badge={i === 0 && !search && !category ? <Badge tone="primary">Most used</Badge> : categoryNames[r.category] ? <Badge>{categoryNames[r.category]}</Badge> : null}
          meta={`${r.deploys.toLocaleString()} deployments`}>
          {r.description}
        </Tile>)}
      </div>
      {repos === null ? <p role="status" className="neo-note">Loading models and apps…</p> : !shown.length ? <p className="neo-note">Nothing matches. Try another search or category.</p> : null}
      {loadError ? <p role="alert" className="neo-error">{loadError}</p> : null}
    </div> : null}

    {step === 1 && repo ? <div className="neo-stack">
      {!details ? detailError ? <div className="neo-stack"><p role="alert" className="neo-error">{detailError}</p><div><Button size="sm" variant="outline" onClick={() => setDetailAttempt(attempt => attempt + 1)}>Try again</Button></div></div> : <p role="status" className="neo-note">Loading its settings…</p> : <>
        {!details.ready ? <p role="alert" className="neo-error">This one has no finished build yet. Choose another.</p> : null}
        <div className="neo-fields">{required.map(field)}</div>
        <div className="neo-fields">
          <Field label="GPU" hint="A smaller GPU costs less and is enough for small models.">
            <select className="neo-select" value={gpuId} onChange={e => setGpuId(e.target.value)}>
              <option value="">Recommended{pools ? `: ${pools}` : ""}</option>
              {catalog.gpus.filter(g => !g.amd).map(g => <option key={g.id} value={g.id}>{g.name} · {g.vramGb} GB</option>)}
            </select>
          </Field>
          <Field label="Requests at once" hint="Each request that runs at the same time uses one worker.">
            <select className="neo-select" value={workersMax} onChange={e => setWorkersMax(Number(e.target.value))}>{[1, 2, 3, 5, 10, 20].map(n => <option key={n} value={n}>Up to {n}</option>)}</select>
          </Field>
          <Field label="Stay ready after a request" hint="Longer means faster follow-ups and a little more cost.">
            <select className="neo-select" value={idle} onChange={e => setIdle(Number(e.target.value))}>{[[5, "5 seconds"], [30, "30 seconds"], [60, "1 minute"], [300, "5 minutes"], [900, "15 minutes"]].map(([s, l]) => <option key={s} value={s}>{l}</option>)}</select>
          </Field>
          {catalog.volumes.length ? <Field label="Network volume" hint="Optional, for models kept on your own storage.">
            <select className="neo-select" value={networkVolume} onChange={e => setNetworkVolume(e.target.value)}><option value="">None</option>{catalog.volumes.map(v => <option key={v.id} value={v.id}>{v.name} · {v.sizeGb} GB · {v.location}</option>)}</select>
          </Field> : null}
        </div>
        <label className="neo-check"><Checkbox checked={warm} onCheckedChange={v => setWarm(v === true)} /><span>Keep one worker always on. Answers start instantly, but it bills every second, even when nobody is using it.</span></label>
        {advanced.length ? <details className="neo-details"><summary>More settings ({advanced.length})</summary><div><div className="neo-fields">{advanced.map(field)}</div></div></details> : null}
        {missing.length ? <p className="neo-note">Fill in {missing.map(m => m.name).join(", ")} to continue.</p> : null}
      </>}
    </div> : null}

    {step === 2 ? <div className="neo-stack">
      <Field label="Name" error={!validName(name) || name.length < 3 ? "Use 3–40 letters, numbers, hyphens or underscores." : nameTaken ? "Another environment already has this name." : undefined} className="neo-search">
        <Input className="neo-input" value={name} maxLength={40} onChange={e => { setName(e.target.value); setNameTouched(true) }} spellCheck={false} aria-invalid={!named} />
      </Field>
      <div className="neo-panel">
        <p className="neo-h2">What you get</p>
        <p className="neo-note">An API address for {repo?.title ?? "this app"} that you call from your own code{details?.category === "language" ? ", including an OpenAI-compatible one" : ""}. The node has a box to try it right away. The first request after a quiet spell waits while a worker starts.</p>
      </div>
    </div> : null}
  </>

  const order: Order = {
    kicker: "Serverless endpoint",
    title: ["What should it run?", repo?.title ?? "Settings", "Name it"][step] ?? "",
    lede: ["Ready-made models and apps. Each becomes an API that scales to zero when nobody uses it.", repo?.description ?? "", "Check the summary on the right, then create it."][step] ?? "",
    steps: ["Model or app", "Settings", "Name"], step, setStep,
    complete: [Boolean(repo), configured, named], main,
    summary: [
      ["Runs", repo?.title ?? null],
      ...required.filter(i => values[i.key]).map(i => [i.name, i.secret ? "••••••" : values[i.key]] as [string, string]),
      ["GPU", repo ? gpuName : null],
      ["Workers", repo ? `Up to ${workersMax} · ${warm ? "one always on" : "none when idle"}` : null],
      ...(volume ? [["Network volume", volume.name] as [string, string]] : []),
      ["Name", name || null],
    ],
    price: { amount: null, unit: "hour", lines: [], empty: warm ? "One worker bills every second, and more while requests run." : "Nothing while idle. You pay per second only while a worker answers requests." },
    consent: "I understand this bills my account for the time its workers run.",
    submitLabel: "Create endpoint",
    ready: Boolean(repo) && configured && named,
    signature: JSON.stringify([repo?.id, gpuId, workersMax, warm, idle, values, networkVolume]),
    submit,
  }
  return <OrderFrame order={order} account={props.account} busy={props.busy} error={props.error} onBack={props.onBack} />
}
