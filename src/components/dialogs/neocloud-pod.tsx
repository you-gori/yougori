import { useEffect, useMemo, useState } from "react"
import { goodFor, money, runpodApi, STORAGE_RATES, type PodRequest, type RunpodAccount, type RunpodCatalog, type RunpodGpu, type RunpodTemplate } from "@/api/runpod-api"
import { Checkbox } from "@/components/ui/checkbox"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { gpuPrice, stockLevel, suggestName, templateName, templateRank, validName, vramTiers } from "@/lib/runpod"
import { OrderFrame, type Order } from "./neocloud-frame"
import { Badge, Field, Meter, Pills, Segments, Tile } from "./neocloud-ui"

const stockWords = ["Out of stock", "Few left", "Available", "Plenty"] as const
const memoryFilters = [[0, "Any memory"], [16, "16 GB+"], [24, "24 GB+"], [48, "48 GB+"], [80, "80 GB+"]] as const
const clouds = [
  { id: "secure", title: "Secure Cloud", note: "Certified data centres, most reliable" },
  { id: "community", title: "Community Cloud", note: "Vetted hosts, usually cheaper" },
] as const
const diskPresets = [20, 50, 100, 200] as const

function parseEnv(text: string): { env: Record<string, string>; error: string } {
  const env: Record<string, string> = {}
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim()
    if (!line || line.startsWith("#")) continue
    const at = line.indexOf("=")
    const key = at > 0 ? line.slice(0, at).trim() : ""
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) return { env, error: `Write each variable as NAME=value (“${line.slice(0, 30)}”)` }
    env[key] = line.slice(at + 1).trim()
  }
  return { env, error: "" }
}

function parsePorts(text: string): { ports: number[]; error: string } {
  const ports = text.split(/[\s,]+/).filter(Boolean).map(Number)
  if (ports.some(p => !Number.isInteger(p) || p < 1 || p > 65535 || p === 22)) return { ports: [], error: "Web ports are numbers from 1 to 65535, other than 22" }
  return { ports: [...new Set(ports)], error: "" }
}

function Size({ label, value, onChange, presets, hint, min = 1 }: { label: string; value: number; onChange(value: number): void; presets: readonly number[]; hint: string; min?: number }) {
  return <Field label={label} hint={hint}>
    <span className="neo-size">
      <Input className="neo-input" type="number" min={min} max={4000} value={value} aria-label={label} onChange={e => onChange(Number(e.target.value) || 0)} />
      <span className="neo-note">GB</span>
      {presets.map(p => <button key={p} type="button" className="neo-pill" aria-pressed={value === p} onClick={() => onChange(p)}>{p} GB</button>)}
    </span>
  </Field>
}

export interface PodProps { compute: "gpu" | "cpu"; catalog: RunpodCatalog; account: RunpodAccount | null | undefined; taken: string[]; busy: boolean; error?: string; onBack(): void; onCreate(request: PodRequest): void }

export function PodWorkbench(props: PodProps) {
  const { compute, catalog, taken, onCreate } = props
  const steps = compute === "gpu" ? ["Software", "GPU", "Storage", "Name and extras"] : ["Software", "Storage", "Name and extras"]
  const [step, setStep] = useState(0)
  const [template, setTemplate] = useState<RunpodTemplate | null>(null)
  const [details, setDetails] = useState<RunpodTemplate | null>(null)
  const [customImage, setCustomImage] = useState("")
  const [search, setSearch] = useState("")
  const [found, setFound] = useState<RunpodTemplate[] | null>(null)
  const [cloud, setCloud] = useState<"secure" | "community">("secure")
  const [minVram, setMinVram] = useState(0)
  const [showAll, setShowAll] = useState(false)
  const [gpu, setGpu] = useState<RunpodGpu | null>(null)
  const [count, setCount] = useState(1)
  const [location, setLocation] = useState("")
  const [containerDisk, setContainerDisk] = useState(20)
  const [storage, setStorage] = useState<"volume" | "network" | "none">("volume")
  const [volumeGb, setVolumeGb] = useState(20)
  const [mountPath, setMountPath] = useState("/workspace")
  const [networkVolume, setNetworkVolume] = useState("")
  const [name, setName] = useState("")
  const [nameTouched, setNameTouched] = useState(false)
  const [portsText, setPortsText] = useState("")
  const [envText, setEnvText] = useState("")
  const [registry, setRegistry] = useState("")
  const [publicIp, setPublicIp] = useState(true)
  const [globalNetworking, setGlobalNetworking] = useState(false)
  const [compliance, setCompliance] = useState<string[]>([])
  const [minCuda, setMinCuda] = useState("")

  const templates = useMemo(() => (found ?? catalog.templates)
    .filter(t => compute === "cpu" ? t.kind === "cpu" : t.kind !== "cpu")
    .sort((a, b) => templateRank(a) - templateRank(b)), [catalog.templates, compute, found])
  const amd = template?.kind === "amd"
  const gpus = useMemo(() => catalog.gpus
    .filter(g => g.amd === amd && gpuPrice(g, cloud) != null && (showAll || g.available) && (g.vramGb ?? 0) >= minVram)
    .sort((a, b) => Number(!a.available) - Number(!b.available) || (gpuPrice(a, cloud) ?? 0) - (gpuPrice(b, cloud) ?? 0)), [amd, catalog.gpus, cloud, minVram, showAll])
  // The in-stock GPU with the most memory per dollar, from 16 GB up.
  const bestValue = useMemo(() => gpus.filter(g => g.available && (g.vramGb ?? 0) >= 16).sort((a, b) => (gpuPrice(a, cloud)! / (a.vramGb ?? 1)) - (gpuPrice(b, cloud)! / (b.vramGb ?? 1)))[0]?.id, [cloud, gpus])
  const perGpu = gpu ? gpuPrice(gpu, cloud) : null
  const hourly = compute === "gpu" && perGpu != null ? perGpu * count : null
  const places = gpu && cloud === "secure" ? gpu.locations.filter(l => l.stock !== "none") : []
  const volume = catalog.volumes.find(v => v.id === networkVolume)
  const countryOf = (id: string) => catalog.locations.find(l => l.id === id)?.country ?? ""
  const envParsed = parseEnv(envText)
  const portsParsed = parsePorts(portsText)
  const software = template ? templateName(template.name) : customImage.trim() || null

  useEffect(() => {
    const term = search.trim()
    if (!term) { setFound(null); return }
    let alive = true
    const timer = window.setTimeout(() => {
      void runpodApi.searchTemplates(term)
        .then(result => { if (alive) setFound(result) })
        .catch(() => { if (alive) setFound([]) })
    }, 350)
    return () => { alive = false; window.clearTimeout(timer) }
  }, [search])
  useEffect(() => {
    setDetails(null)
    if (!template) return
    setContainerDisk(template.containerDiskGb || 20)
    setVolumeGb(template.volumeGb || (compute === "gpu" ? 20 : 0))
    if (!template.volumeGb && compute === "cpu") setStorage("none")
    setMountPath(template.mountPath || "/workspace")
    let alive = true
    void runpodApi.template(template.id).then(d => { if (alive) setDetails(d) }).catch(() => undefined)
    return () => { alive = false }
  }, [compute, template])
  // Picking a GPU or cloud clears the location; a network volume pins it back to its data centre.
  useEffect(() => { if (storage === "network" && volume) setLocation(volume.location) }, [storage, volume, gpu, cloud])
  useEffect(() => {
    if (nameTouched) return
    const source = template ? templateName(template.name) : customImage.split(/[/:]/).slice(-2, -1)[0] || customImage
    setName(suggestName(compute === "gpu" ? [gpu?.name ?? "gpu", source] : ["cpu", source], taken))
  }, [compute, customImage, gpu, nameTouched, taken, template])

  const startReady = Boolean(template) || /^[a-z0-9][\w.\-/:@]*$/i.test(customImage.trim())
  const gpuReady = compute === "cpu" || (gpu != null && perGpu != null && gpu.available)
  const storageReady = containerDisk >= 5 && containerDisk <= 4000
    && (storage !== "volume" || (volumeGb >= 1 && volumeGb <= 4000 && mountPath.startsWith("/")))
    && (storage !== "network" || (Boolean(volume) && (compute === "cpu" || cloud === "secure")))
  const nameTaken = taken.some(t => t.toLowerCase() === name.toLowerCase())
  const extrasReady = validName(name) && !nameTaken && !envParsed.error && !portsParsed.error
  const complete = compute === "gpu" ? [startReady, gpuReady, storageReady, extrasReady] : [startReady, storageReady, extrasReady]
  const monthlyRunning = containerDisk * STORAGE_RATES.container + (storage === "volume" ? volumeGb * STORAGE_RATES.volumeRunning : 0)
  const monthlyStopped = storage === "volume" ? volumeGb * STORAGE_RATES.volumeStopped : 0
  const jupyter = (details?.ports ?? []).some(p => p.port === 8888)
  const gpuStep = compute === "gpu" ? 1 : -1, storageStep = compute === "gpu" ? 2 : 1, extrasStep = steps.length - 1

  const submit = () => onCreate({
    name, compute,
    ...(compute === "gpu" ? { gpuId: gpu!.id, gpuCount: count, cloud, maxHourlyUsd: hourly, publicIp: cloud === "community" && publicIp, globalNetworking: cloud === "secure" && globalNetworking, minCuda: minCuda.trim() } : {}),
    location,
    ...(template ? { templateId: template.id } : { image: customImage.trim() }),
    containerDiskGb: containerDisk,
    volumeGb: storage === "volume" ? volumeGb : 0,
    volumeMountPath: storage === "none" ? "" : mountPath,
    networkVolumeId: storage === "network" ? networkVolume : "",
    registryAuthId: registry,
    httpPorts: portsParsed.ports,
    env: envParsed.env,
    compliance,
  })

  const tiers = vramTiers.map(t => ({ ...t, gpus: gpus.filter(g => (g.vramGb ?? 0) >= t.min && (g.vramGb ?? 0) < t.max) })).filter(t => t.gpus.length)

  const main = <>
    {step === 0 ? <div className="neo-stack">
      <Input className="neo-input neo-search" aria-label="Search software" placeholder="Search, for example ComfyUI, vLLM or Stable Diffusion" value={search} onChange={e => setSearch(e.target.value)} />
      <div className="neo-grid is-wide">
        {templates.map((t, i) => <Tile key={`${t.own ? "own" : "public"}:${t.id}`} selected={template?.id === t.id} label={`Start from ${templateName(t.name)}`}
          onSelect={() => { setTemplate(t); setCustomImage(""); if (gpu && gpu.amd !== (t.kind === "amd")) setGpu(null) }}
          title={templateName(t.name)}
          badge={i === 0 && !found ? <Badge tone="primary">Recommended</Badge> : t.own ? <Badge>Yours</Badge> : t.kind === "amd" ? <Badge>AMD</Badge> : !t.official ? <Badge>Community</Badge> : null}
          meta={`${t.containerDiskGb ?? 20} GB disk${t.volumeGb ? ` · ${t.volumeGb} GB saved volume` : ""}`}>
          {t.official || t.own ? null : <span className="neo-mono">{t.image}</span>}
        </Tile>)}
      </div>
      {!templates.length ? <p className="neo-note">{found ? "Nothing matches that search." : "No software was found."}</p> : null}
      <Field label="Or run any container image" hint="The terminal and files need SSH and Python 3 in the image. The ready-made software above has both." className="neo-search">
        <Input className="neo-input" value={customImage} spellCheck={false} placeholder={compute === "gpu" ? "for example vllm/vllm-openai:latest" : "for example ubuntu:24.04"}
          onChange={e => { setCustomImage(e.target.value); if (e.target.value.trim()) setTemplate(null) }} />
      </Field>
      {details?.readme ? <details className="neo-details"><summary>About {templateName(details.name)}</summary><div><pre className="neo-code">{details.readme}</pre></div></details> : null}
    </div> : null}

    {step === gpuStep ? <div className="neo-stack">
      <div className="neo-row" style={{ justifyContent: "space-between" }}>
        <Segments label="Cloud" value={cloud} options={clouds} onChange={value => { setCloud(value); setGpu(null); setLocation("") }} />
        <label className="neo-check"><Checkbox checked={showAll} onCheckedChange={v => setShowAll(v === true)} />Show GPUs that are out of stock</label>
      </div>
      <Pills<number> label="GPU memory" value={minVram} options={memoryFilters} onChange={setMinVram} />
      <div className="neo-gpus">
        {tiers.map(tier => <section key={tier.title} className="neo-gpu-group" aria-label={tier.title}>
          <p className="neo-h3">{tier.title}</p>
          {tier.gpus.map(g => {
            const level = stockLevel(g.stock, g.available)
            return <button key={g.id} type="button" className={`neo-gpu${gpu?.id === g.id ? " is-selected" : ""}`} aria-pressed={gpu?.id === g.id} aria-label={`Choose ${g.name}`} disabled={!g.available}
              onClick={() => { setGpu(g); setLocation("") }}>
              <span className="neo-gpu-name"><strong>{g.name} {g.id === bestValue ? <Badge tone="good">Best value</Badge> : null}</strong><span>{g.vramGb} GB memory</span></span>
              <span className="neo-gpu-use">{goodFor(g.vramGb)}</span>
              <span className="neo-stock"><Meter level={level} />{stockWords[level]}</span>
              <span className="neo-gpu-price"><strong>{money(gpuPrice(g, cloud))}</strong><span>per hour</span></span>
            </button>
          })}
        </section>)}
        {!tiers.length ? <p className="neo-note">No GPU matches. Choose less memory, show out-of-stock GPUs, or switch the cloud.</p> : null}
      </div>
      {gpu ? <div className="neo-fields">
        <Field label="Number of GPUs" hint={`${(gpu.vramGb ?? 0) * count} GB of GPU memory in total`}>
          <select className="neo-select" value={count} onChange={e => setCount(Number(e.target.value))}>{[1, 2, 3, 4, 5, 6, 7, 8].map(n => <option key={n} value={n}>{n} × {gpu.name} · {money((perGpu ?? 0) * n)}/hr</option>)}</select>
        </Field>
        {cloud === "secure" ? <Field label="Location" hint="Anywhere starts fastest. Pick a place to keep data in one country.">
          <select className="neo-select" value={location} onChange={e => setLocation(e.target.value)} disabled={storage === "network" && Boolean(volume)}>
            <option value="">Anywhere</option>
            {location && !places.some(p => p.id === location) ? <option value={location}>{countryOf(location) || location} · {location}</option> : null}
            {places.map(p => <option key={p.id} value={p.id}>{countryOf(p.id) || p.id} · {p.id} · {stockWords[stockLevel(p.stock)].toLowerCase()}</option>)}
          </select>
        </Field> : <Field label="Location" hint="Community hosts are chosen for you."><select className="neo-select" disabled><option>Anywhere</option></select></Field>}
      </div> : null}
    </div> : null}

    {step === storageStep ? <div className="neo-stack">
      <div className="neo-grid" role="group" aria-label="Saved storage">
        <Tile selected={storage === "volume"} onSelect={() => setStorage("volume")} title="Saved volume" badge={<Badge tone="primary">Recommended</Badge>}>Your files stay when the pod stops. Deleted with the pod.</Tile>
        <Tile selected={storage === "network"} disabled={!catalog.volumes.length} onSelect={() => setStorage("network")} title="Network volume">{catalog.volumes.length ? "Outlives the pod and can be shared between pods." : "Create one from the Neocloud home screen first."}</Tile>
        <Tile selected={storage === "none"} onSelect={() => setStorage("none")} title="Nothing saved">Everything is erased when the pod stops.</Tile>
      </div>
      {storage === "volume" ? <div className="neo-fields">
        <Size label="Volume size" value={volumeGb} onChange={setVolumeGb} presets={diskPresets} hint={`About ${money(volumeGb * STORAGE_RATES.volumeRunning)}/month while running, ${money(volumeGb * STORAGE_RATES.volumeStopped)}/month while stopped.`} />
        <Field label="Folder in the pod" hint="Save your work here."><Input className="neo-input" value={mountPath} onChange={e => setMountPath(e.target.value)} spellCheck={false} /></Field>
      </div> : null}
      {storage === "network" ? <Field label="Network volume" error={volume && gpu && cloud === "secure" && !gpu.locations.some(l => l.id === volume.location && l.stock !== "none") ? `${gpu.name} is out of stock in ${volume.location}, where this volume is. Choose another GPU.` : volume && compute === "gpu" && cloud === "community" ? "Network volumes need Secure Cloud." : undefined}>
        <select className="neo-select" value={networkVolume} onChange={e => setNetworkVolume(e.target.value)}>
          <option value="">Choose a volume</option>
          {catalog.volumes.map(v => <option key={v.id} value={v.id}>{v.name} · {v.sizeGb} GB · {v.location}</option>)}
        </select>
      </Field> : null}
      <Size label="System disk" value={containerDisk} onChange={setContainerDisk} min={5} presets={[10, 20, 50, 100]} hint="For installed packages and temporary files. Erased when the pod stops." />
    </div> : null}

    {step === extrasStep ? <div className="neo-stack">
      <Field label="Name" error={!validName(name) ? "Use 2–40 letters, numbers, hyphens or underscores." : nameTaken ? "Another environment already has this name." : undefined} className="neo-search">
        <Input className="neo-input" value={name} maxLength={40} onChange={e => { setName(e.target.value); setNameTouched(true) }} spellCheck={false} aria-invalid={!validName(name) || nameTaken} />
      </Field>
      <div className="neo-panel">
        <p className="neo-h2">What you get</p>
        <p className="neo-note">A {compute === "gpu" ? "GPU" : "Linux"} machine that opens here with a terminal and your files{jupyter ? ", plus Jupyter in your browser" : ""}. Yougori connects it by itself as soon as it starts, usually within a few minutes. Stop it when you're done; a stopped pod only pays for its saved volume.</p>
      </div>
      <details className="neo-details">
        <summary>Extras: web ports, environment variables, private images, networking</summary>
        <div>
          <Field label="Extra web ports" hint="Opened through a secure web address, for example 7860 for a Gradio app." error={portsParsed.error || undefined}>
            <Input className="neo-input" value={portsText} placeholder="7860, 8000" onChange={e => setPortsText(e.target.value)} />
          </Field>
          <Field label="Environment variables" hint="One NAME=value per line." error={envParsed.error || undefined}>
            <Textarea value={envText} rows={3} spellCheck={false} placeholder={"HF_TOKEN=...\nMODEL=Qwen/Qwen2.5-7B-Instruct"} onChange={e => setEnvText(e.target.value)} />
          </Field>
          {catalog.registries.length ? <Field label="Private image login">
            <select className="neo-select" value={registry} onChange={e => setRegistry(e.target.value)}><option value="">None</option>{catalog.registries.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}</select>
          </Field> : null}
          {compute === "gpu" && cloud === "community" ? <label className="neo-check"><Checkbox checked={publicIp} onCheckedChange={v => setPublicIp(v === true)} />Require a public IP address (needed for the terminal on Community Cloud)</label> : null}
          {compute === "gpu" && cloud === "secure" ? <label className="neo-check"><Checkbox checked={globalNetworking} onCheckedChange={v => setGlobalNetworking(v === true)} />Private network between your pods</label> : null}
          {compute === "gpu" ? <Field label="Minimum CUDA version" hint="Leave empty for any."><Input className="neo-input" value={minCuda} placeholder="for example 12.8" onChange={e => setMinCuda(e.target.value)} /></Field> : null}
          <fieldset className="neo-stack"><legend className="neo-field">Only run in data centres certified for</legend>
            <span className="neo-row">{[["SOC_2_TYPE_2", "SOC 2 Type II"], ["HIPAA", "HIPAA"], ["ISO_27001", "ISO 27001"], ["GDPR", "GDPR"]].map(([id, label]) => <label key={id} className="neo-check"><Checkbox checked={compliance.includes(id!)} onCheckedChange={v => setCompliance(c => v === true ? [...c, id!] : c.filter(x => x !== id))} />{label}</label>)}</span>
          </fieldset>
        </div>
      </details>
    </div> : null}
  </>

  const order: Order = {
    kicker: compute === "gpu" ? "GPU pod" : "CPU pod",
    title: ["What should it run?", ...(compute === "gpu" ? ["Choose a GPU"] : []), "Where should files live?", "Name it"][step] ?? "",
    lede: ["Ready-made software with Python, CUDA, Jupyter and SSH, or any container image.", ...(compute === "gpu" ? ["Sorted by price and grouped by memory. You pay per second while the pod runs."] : []), "The system disk is erased when a pod stops. Keep your work on a saved volume.", "Check the summary on the right, then create it."][step] ?? "",
    steps, step, setStep, complete, main,
    summary: [
      ["Software", software],
      ...(compute === "gpu" ? [["GPU", gpu ? `${count} × ${gpu.name} · ${(gpu.vramGb ?? 0) * count} GB` : null] as [string, string | null]] : [["Machine", "CPU; the size is chosen for you"] as [string, string]]),
      ...(compute === "gpu" ? [["Cloud", cloud === "secure" ? "Secure" : "Community"] as [string, string]] : []),
      ["Location", location ? `${countryOf(location) || location} · ${location}` : "Anywhere"],
      ["Storage", `${containerDisk} GB system${storage === "volume" ? ` · ${volumeGb} GB saved at ${mountPath}` : storage === "network" && volume ? ` · ${volume.name}` : ""}`],
      ["Name", name || null],
    ],
    price: {
      amount: hourly, unit: "hour", empty: compute === "gpu" ? "Choose a GPU to see the price." : "The hourly price of a CPU pod appears on its node once it starts.",
      lines: hourly != null ? [`About ${money(hourly * 24)} a day`, `Storage about ${money(monthlyRunning)}/month${monthlyStopped ? `, ${money(monthlyStopped)}/month when stopped` : ""}`] : [],
    },
    consent: hourly != null ? `I understand this bills my account ${money(hourly)} an hour while it runs, and its storage until I delete it.` : "I understand this bills my account while it runs, and its storage until I delete it.",
    submitLabel: "Create pod",
    ready: complete.every(Boolean),
    signature: JSON.stringify([gpu?.id, count, cloud, location, template?.id, customImage, containerDisk, volumeGb, storage, networkVolume]),
    submit,
  }
  return <OrderFrame order={order} account={props.account} busy={props.busy} error={props.error} onBack={props.onBack} />
}
