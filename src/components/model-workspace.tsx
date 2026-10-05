import { useEffect, useRef, useState } from "react"
import { ModelChat } from "@/components/model-chat"
import { HuggingfaceAccess } from "@/components/huggingface-access"
import { ModelApiPanel } from "@/components/model-api-panel"
import { ModelUsagePanel } from "@/components/model-usage-panel"
import { ModelNetworkPanel, NetworkAccount } from "@/components/network-panel"
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
  const launch = async () => {
    if (lock.current) return
    lock.current = true; setBusy(true)
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
      const result = await modelsApi.run(model, api ? Number(port) : null, quant.trim() || undefined)
      setSelected(result.id); setView("chat")
      if (sharing !== "off") {
        try { await marketApi.share(result.id, sharing); setView("network") }
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
          <label className="model-label" htmlFor="hf-model">Model</label>
          <Input id="hf-model" value={model} disabled={busy} onChange={e => {setModel(e.target.value);setPreflight(null)}} placeholder="hf.co/owner/model" />
          <p className="model-hint">Text-generation and supported decision models with safetensors or GGUF. Larger models select a lower precision when needed to fit the GPU.</p>
          <HuggingfaceAccess />
          <label className="model-label" htmlFor="hf-quant">GGUF quantization (optional)</label>
          <Input id="hf-quant" value={quant} disabled={busy} placeholder="Q4_K_M by default" onChange={e => { setQuant(e.target.value); setPreflight(null) }} />
          <div className="model-tabs" role="group" aria-label="Network sharing">
            {([['off', 'Off'], ['paid', 'Paid (--now)'], ['free', 'Free (--nowfree)']] as const).map(([mode, label]) => <button key={mode} type="button" disabled={busy} aria-pressed={sharing === mode} onClick={() => setSharing(mode)}>{label}</button>)}
          </div>
          {sharing !== "off" ? <><p className="model-hint">Share through the Yougori endpoint. Paid pricing covers ten models; other models are shared free. Free access needs no wallet.</p><NetworkAccount network={network} />{network.error ? <p role="alert" className="model-error">{network.error}</p> : null}</> : null}
          <div className="model-api-row">
            <div><label htmlFor="hf-api">Local API</label><p>OpenAI-compatible, this PC only.</p></div>
            <div className="model-api-controls">
              {api ? <Input className="w-24" aria-label="Model API port" type="number" min={1} max={65535} value={port} disabled={busy} onChange={e => setPort(e.target.value)} /> : null}
              <Switch id="hf-api" checked={api} disabled={busy} onCheckedChange={setApi} />
            </div>
          </div>
          {preflight ? <div aria-label="Model compatibility" className="model-hint"><p>{preflight.supported ? (preflight.task === "structured-decision" ? "Compatible with typed decisions" : "Compatible with text chat") : "Requires a dedicated runner"} · {preflight.task}</p><p>{preflight.reason}</p>{preflight.resources.storageGbRecommended ? <p>Estimated storage {preflight.resources.storageGbRecommended} GB · estimated GPU memory {preflight.resources.gpuMemoryGbEstimated ?? "unknown"} GB. Actual memory varies with context and settings.</p> : null}<p>Weights download directly to persistent model storage and are verified before loading.</p></div> : null}
          <div className="model-form-actions"><Button variant="outline" disabled={busy || !model.trim()} onClick={() => {setBusy(true);setError("");void modelsApi.preflight(model, quant.trim() || undefined).then(setPreflight).catch(e=>setError(String(e))).finally(()=>setBusy(false))}}>Check compatibility</Button><Button disabled={busy || network.busy || !model.trim() || preflight?.supported===false || (api && !validPort)} loading={busy} onClick={() => void launch()}>Run model</Button></div>
        </div> : null}

        {selected ? <div className="model-view-row">
          <div className="model-tabs" role="group" aria-label="View">
            <button type="button" aria-pressed={view === "chat"} onClick={() => setView("chat")}>Chat</button>
            <button type="button" aria-pressed={view === "api"} onClick={() => setView("api")}>API access</button>
            <button type="button" aria-pressed={view === "usage"} onClick={() => setView("usage")}>Usage</button>
            <button type="button" aria-pressed={view === "network"} onClick={() => setView("network")}>Network</button>
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
