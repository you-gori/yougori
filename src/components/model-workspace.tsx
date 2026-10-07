import { lazy, Suspense, useEffect, useRef, useState } from "react"
import { ModelChat } from "@/components/model-chat"
import { ModelArchitectureSupport } from "@/components/model-architecture-support"
import { HuggingfaceAccess } from "@/components/huggingface-access"
import { ModelApiPanel } from "@/components/model-api-panel"
import { ModelUsagePanel } from "@/components/model-usage-panel"
import { ModelNetworkPanel, NetworkAccount } from "@/components/network-panel"
import { registryApi } from "@/api/model-registry-api"
import { ModelLibrary } from "@/components/model-library"
import { useNetwork } from "@/components/use-network"
import { marketApi, type SharingMode } from "@/api/market-api"
import { modelsApi, type ModelPreflight } from "@/api/projects-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Dialog, DialogClose, DialogTrigger, DialogPopup, DialogTitle, DialogDescription, DialogPanel } from "@/components/ui/dialog"
import { useTopicWalkthroughModal } from "@/lib/topic-walkthrough"
import { toastManager } from "@/components/ui/toast"
import "@/components/model-workspace.css"

export { ModelChat }

const NeocloudForm = lazy(async () => ({ default: (await import("@/components/dialogs/neocloud-form")).NeocloudForm }))

/** `compact` renders a small "Chat" trigger for use inside a graph node. */
export function ModelWorkspace({ environmentId, compact = false }: { environmentId?: string; compact?: boolean }) {
  const { state, refreshPlatform } = usePlatform()
  const [open, setOpen] = useState(false)
  const topic = useTopicWalkthroughModal(open)
  const [model, setModel] = useState("hf.co/TinyLlama/TinyLlama-1.1B-Chat-v1.0")
  const [api, setApi] = useState(false)
  const [port, setPort] = useState("8000")
  const [selected, setSelected] = useState(environmentId ?? "")
  const [view, setView] = useState<"chat" | "api" | "usage" | "network">("chat")
  const [sharing, setSharing] = useState<"off" | SharingMode>("off")
  const [quant, setQuant] = useState("")
  const [folder, setFolder] = useState("")
  const [closedWeights, setClosedWeights] = useState(false)
  const [target, setTarget] = useState<"local" | "neocloud">("local")
  const [pod, setPod] = useState("")
  const [creatingPod, setCreatingPod] = useState(false)
  const network = useNetwork(open && sharing !== "off" && !selected)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [preflight,setPreflight]=useState<ModelPreflight|null>(null)
  const lock = useRef(false)
  const [launching, setLaunching] = useState(false)
  const [elapsed, setElapsed] = useState(0)
  const previousIds = useRef(new Set<string>())
  useEffect(() => {
    if (!launching) return
    let active = true, timer = 0
    const started = Date.now()
    const clock = window.setInterval(() => setElapsed(Math.floor((Date.now() - started) / 1000)), 1000)
    const poll = async () => {
      try { await refreshPlatform() } catch { /* The launch reports its own errors. */ }
      finally { if (active) timer = window.setTimeout(poll, 3000) }
    }
    void poll()
    return () => { active = false; window.clearTimeout(timer); window.clearInterval(clock) }
  }, [launching, refreshPlatform])
  const normalizedModel = model.trim().replace(/^(https:\/\/huggingface.co\/|hf.co\/)/, "")
  const pendingModel = launching ? state?.environments.find(e => !previousIds.current.has(e.id) && e.description === `Hugging Face · ${normalizedModel}`) : undefined
  const visibleId = selected || pendingModel?.id
  const models = state?.environments.filter(e => e.description.startsWith("Hugging Face · ")) ?? []
  // Same pods the CLI offers for `--neocloud`: RunPod GPU pods that still exist.
  const pods = state?.environments.filter(env => {
    const deployment = state.neocloudDeployments?.[env.id]
    return env.kind === "cloud" && deployment?.provider === "runpod" && ["pod", "gpu"].includes(deployment.product)
      && !["Deleted", "Terminated"].includes(deployment.state) && deployment.extra?.compute !== "cpu"
  }) ?? []
  const firstPod = pods[0]?.id ?? ""
  const podAvailable = pods.some(env => env.id === pod)
  useEffect(() => { if (!podAvailable) setPod(firstPod) }, [podAvailable, firstPod])
  const launch = async () => {
    if (lock.current) return
    lock.current = true; setBusy(true)
    try {
      const result = await modelsApi.preflight(model, target === "local" ? quant.trim() || undefined : undefined, target === "local" ? folder || undefined : undefined)
      setPreflight(result)
      if (!result.supported) { setError(result.reason); lock.current = false; setBusy(false); return }
      if (result.sourceOnly && (sharing === "paid" || closedWeights)) { setError("This folder has source files only. Choose Free sharing with open downloads; weights are required for inference."); lock.current = false; setBusy(false); return }
    } catch (reason) { setError(String(reason)); lock.current = false; setBusy(false); return }
    if (sharing !== "off") {
      setError("")
      try {
        const status = await network.refresh()
        if (!status.signedIn) {
          await network.perform(marketApi.signIn)
          setError("Approve the sign-in code in your browser, then press Run model.")
          lock.current = false; setBusy(false)
          return
        }
      } catch (reason) { setError(String(reason)); lock.current = false; setBusy(false); return }
    }
    previousIds.current = new Set(state?.environments.map(e => e.id))
    lock.current = true; setBusy(true); setLaunching(true); setElapsed(0); setError(""); setOpen(false)
    try {
      const result = target === "neocloud" ? await modelsApi.runNeocloud(model, pod, api ? Number(port) : null) : await modelsApi.run(model, api ? Number(port) : null, quant.trim() || undefined, folder || undefined)
      setSelected(result.id); setView(result.sourceOnly ? "network" : "chat")
      if (sharing !== "off") {
        try { await marketApi.share(result.id, sharing, closedWeights); setView("network") }
        catch (reason) { toastManager.add({ title: "Model is running; sharing needs attention", description: String(reason), type: "error" }); setError(String(reason)); setView("network") }
      }
      await refreshPlatform()
    }
    catch (e) { setError(String(e)); toastManager.add({ title: "Model setup needs attention", description: String(e), type: "error" }); await refreshPlatform().catch(() => undefined) }
    finally { setBusy(false); setLaunching(false); lock.current = false }
  }
  const showTabs = !environmentId && models.length > 0
  const close = <DialogClose render={<Button variant="outline" size="sm" className="model-close" />}>Close</DialogClose>
  const validPort = Number.isInteger(Number(port)) && Number(port) >= 1 && Number(port) <= 65535
  return <Dialog modal={!topic} open={open} onOpenChange={(value, details) => { if (!(!value && topic && details.reason === "focus-out") && !(details.event.target instanceof Element && details.event.target.closest('[data-topic-ui]'))) setOpen(value) }}>
    <DialogTrigger render={compact ? <Button size="xs" variant="ghost" className="node-chat nodrag" /> : <Button data-instruction="model-trigger" size="sm" variant="outline" className={environmentId ? undefined : "dashboard-action"} />}>{compact ? "Chat" : environmentId ? "Chat with model" : "Huggingface"}</DialogTrigger>
    <DialogPopup data-instruction="model-dialog" bottomStickOnMobile={false} showCloseButton={false} className={`model-popup max-w-none${visibleId ? " model-popup-chat" : ""}`}>
      <DialogTitle className="sr-only">Hugging Face</DialogTitle>
      <DialogDescription className="sr-only">Run a language model on your NVIDIA GPU.</DialogDescription>
      {showTabs || !selected ? <header className="model-header">
        {showTabs ? <div className="model-tabs" role="group" aria-label="Your models">
          {models.map(e => <button key={e.id} type="button" aria-pressed={selected === e.id} disabled={busy} onClick={() => setSelected(e.id)}>{e.description.replace("Hugging Face · ", "")}</button>)}
          <button type="button" aria-pressed={!selected} disabled={busy} onClick={() => setSelected("")}>{selected ? "Run another model" : "New model"}</button>
        </div> : null}
        {selected ? null : close}
      </header> : null}
      <DialogPanel className="model-panel" scrollFade={false}>
        {!environmentId && !selected ? <div className="model-form">
          <div className="model-intro">
            <h2>Run a Hugging Face model</h2>
            <p>Text-generation and supported decision models with safetensors or GGUF. Larger models select a lower precision when needed to fit the GPU.</p>
          </div>

          <section className="model-card">
            <label className="model-label" htmlFor="hf-model">Model</label>
            <ModelLibrary onRun={(value, precision) => { setModel(value); setFolder(""); setQuant(precision ?? ""); setPreflight(null); setTarget("local") }} />
            {target === "local" ? <div><label className="model-label" htmlFor="model-folder">Local weights (optional)</label><Input id="model-folder" value={folder} disabled={busy} onChange={e => {setFolder(e.target.value);setPreflight(null)}} placeholder="Leave empty to download from Hugging Face" /><Button variant="outline" disabled={busy} onClick={() => void registryApi.folder().then(value => {if(value){setFolder(value);setPreflight(null)}}).catch(e => setError(String(e)))}>Choose model folder</Button></div> : null}
          {sharing !== "off" ? <label><input type="checkbox" checked={closedWeights} disabled={busy} onChange={e => setClosedWeights(e.target.checked)} />Closed weights — publish chat and API only</label> : null}
          <Input id="hf-model" value={model} disabled={busy} onChange={e => {setModel(e.target.value);setPreflight(null)}} placeholder="hf.co/owner/model" />
            <HuggingfaceAccess />
          </section>

          <section className="model-card">
            <span className="model-label" id="hf-target-label">Where to run</span>
            <div className="model-targets" role="radiogroup" aria-labelledby="hf-target-label">
              <button type="button" role="radio" aria-checked={target === "local"} disabled={busy} onClick={() => { setTarget("local"); setPreflight(null) }}><strong>This PC</strong><span>Your NVIDIA GPU</span></button>
              <button type="button" role="radio" aria-checked={target === "neocloud"} disabled={busy} onClick={() => { setTarget("neocloud"); setPreflight(null) }}><strong>Neo Cloud <code>--neocloud</code></strong><span>An existing RunPod GPU pod</span></button>
            </div>
            {target === "neocloud" ? <div className="model-neocloud">
              {pods.length ? <label className="model-pod"><span className="model-label">RunPod GPU pod</span>
                <select value={pod} disabled={busy} onChange={e => setPod(e.target.value)}>{pods.map(env => <option key={env.id} value={env.id}>{env.name} · {env.status}</option>)}</select>
              </label> : <p className="model-hint">No RunPod GPU pod yet. Create one, then choose it here.</p>}
              <Dialog open={creatingPod} onOpenChange={setCreatingPod}>
                <DialogTrigger render={<Button size="sm" variant="outline" disabled={busy} />}>Create a RunPod pod</DialogTrigger>
                <DialogPopup className="model-neocloud-create" bottomStickOnMobile={false}>
                  <DialogTitle className="sr-only">Create a RunPod pod</DialogTitle>
                  <DialogPanel><Suspense fallback={<p className="model-hint">Loading…</p>}><NeocloudForm onClose={() => setCreatingPod(false)} /></Suspense></DialogPanel>
                </DialogPopup>
              </Dialog>
              <p className="model-hint">Uses the pod's own resources. Yougori connects to a powered-on pod and never starts or rents one for you. GGUF models run on this PC only.</p>
            </div> : null}
          </section>

          <div className="model-options">
            {target === "local" ? <section className="model-card">
              <label className="model-label" htmlFor="hf-quant">GGUF quantization (optional)</label>
              <Input id="hf-quant" value={quant} disabled={busy} placeholder="Q4_K_M by default" onChange={e => { setQuant(e.target.value); setPreflight(null) }} />
            </section> : null}
            <section className="model-card model-api-row">
              <div><label htmlFor="hf-api">Local API</label><p>OpenAI-compatible, this PC only.</p></div>
              <div className="model-api-controls">
                {api ? <Input className="w-24" aria-label="Model API port" type="number" min={1} max={65535} value={port} disabled={busy} onChange={e => setPort(e.target.value)} /> : null}
                <Switch id="hf-api" checked={api} disabled={busy} onCheckedChange={setApi} />
              </div>
            </section>
          </div>

          <section className="model-card">
            <span className="model-label">Neo Grid sharing</span>
            <div className="model-tabs" role="group" aria-label="Neo Grid sharing">
              {([['off', 'Off'], ['paid', 'Paid (--now)'], ['free', 'Free (--nowfree)']] as const).map(([mode, label]) => <button key={mode} type="button" disabled={busy} aria-pressed={sharing === mode} onClick={() => setSharing(mode)}>{label}</button>)}
            </div>
            {sharing !== "off" ? <><p className="model-hint">Share through the Yougori endpoint. Published models use publisher pricing; Hugging Face models get an automatic price when metadata supports it. Free access needs no deposit.</p><NetworkAccount network={network} />{network.error ? <p role="alert" className="model-error">{network.error}</p> : null}</> : null}
          </section>

          {preflight ? <div aria-label="Model compatibility" className="model-card model-preflight" data-supported={preflight.supported || undefined}><p className="model-preflight-title">{preflight.sourceOnly ? "Source files only" : preflight.supported ? (preflight.task === "structured-decision" ? "Compatible with typed decisions" : "Compatible with text chat") : "Requires a dedicated runner"} · {preflight.task}</p><p>{preflight.reason}</p>{preflight.resources.storageGbRecommended ? <p>Estimated storage {preflight.resources.storageGbRecommended} GB · estimated GPU memory {preflight.resources.gpuMemoryGbEstimated ?? "unknown"} GB. Actual memory varies with context and settings.</p> : null}<p>Weights download directly to persistent model storage and are verified before loading.</p></div> : null}
          {preflight?.supported === false && preflight.supportAvailable ? <ModelArchitectureSupport key={`${model}:${quant}`} model={model} quant={quant.trim() || undefined} active={open} /> : null}
          <div className="model-form-actions"><Button variant="outline" disabled={busy || !model.trim()} onClick={() => {setBusy(true);setError("");void modelsApi.preflight(model, target === "local" ? quant.trim() || undefined : undefined, target === "local" ? folder || undefined : undefined).then(setPreflight).catch(e=>setError(String(e))).finally(()=>setBusy(false))}}>Check compatibility</Button><Button disabled={busy || network.busy || !model.trim() || preflight?.supported===false || (api && !validPort) || (target === "neocloud" && !pod)} loading={busy} onClick={() => void launch()}>Run model</Button></div>
        </div> : null}

        {selected ? <div className="model-view-row">
          <div className="model-tabs" role="group" aria-label="View">
            <button type="button" aria-pressed={view === "chat"} onClick={() => setView("chat")}>Chat</button>
            <button type="button" aria-pressed={view === "api"} onClick={() => setView("api")}>API access</button>
            <button type="button" aria-pressed={view === "usage"} onClick={() => setView("usage")}>Usage</button>
            <button type="button" aria-pressed={view === "network"} onClick={() => setView("network")}>Neo Grid</button>
          </div>
          {close}
        </div> : null}

        {visibleId && open ? view === "network" && selected ? <ModelNetworkPanel key={visibleId} environmentId={visibleId} /> : view === "api" && selected ? <ModelApiPanel key={visibleId} environmentId={visibleId} /> : view === "usage" && selected ? <ModelUsagePanel key={visibleId} environmentId={visibleId} /> : <ModelChat key={visibleId} environmentId={visibleId} /> : null}
        {error ? <p role="alert" className="model-error">{error}</p> : null}
        {busy ? <p role="status" className="model-hint">{launching ? `${pendingModel ? "Starting the model" : "Preparing GPU runtime"}… ${Math.floor(elapsed / 60)}m ${elapsed % 60}s` : null}</p> : null}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
