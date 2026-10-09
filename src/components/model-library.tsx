import { useCallback, useEffect, useRef, useState } from "react"
import { registryApi, type PublishedModel } from "@/api/model-registry-api"
import { workspaceApi } from "@/api/workspace-api"
import { useNetwork } from "@/components/use-network"
import { NetworkAccount } from "@/components/network-panel"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogDescription, DialogPanel, DialogPopup, DialogTitle, DialogTrigger } from "@/components/ui/dialog"

export function ModelLibrary({ onRun }: { onRun: (model: string, quant?: string) => void }) {
  const [open, setOpen] = useState(false), [mine, setMine] = useState(false)
  const network = useNetwork(open)
  const [models, setModels] = useState<PublishedModel[]>([]), [selected, setSelected] = useState<PublishedModel | null>(null)
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("")
  const lock = useRef(false)
  const refresh = useCallback(async () => { setModels((await registryApi.list(mine)).models) }, [mine])
  useEffect(() => { if (!open || mine && !network.status?.signedIn) return; const update=()=>void refresh().catch(e=>setError(String(e))); update(); const timer=window.setInterval(update,15000); return ()=>window.clearInterval(timer) }, [open, mine, network.status?.signedIn, refresh])
  const action = async (work: () => Promise<void>) => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError(""); setNotice("")
    try { await work(); await refresh() } catch (e) { setError(String(e)) } finally { lock.current = false; setBusy(false) }
  }
  const website = network.status?.website ?? "https://yougori.com"
  return <Dialog open={open} onOpenChange={value => { if (!busy) setOpen(value) }}>
    <DialogTrigger render={<Button size="sm" variant="outline" />}>Model library</DialogTrigger>
    <DialogPopup showCloseButton={false} className="model-popup max-w-none" bottomStickOnMobile={false}>
      <DialogTitle>Model library</DialogTitle><DialogDescription>LLMs created in the EU and Horizon Europe-associated countries. Model files are stored on Yougori.</DialogDescription>
      <DialogPanel className="model-panel"><NetworkAccount network={network} />
        <div className="model-tabs"><button disabled={busy} aria-pressed={!mine} onClick={() => { setMine(false); setSelected(null) }}>Browse</button><button disabled={busy} aria-pressed={mine} onClick={() => { setMine(true); setSelected(null) }}>Publish</button></div>
        {mine && network.status?.signedIn ? <section className="model-form"><p>Upload your model weights, tokenizer, configuration, card and license on Yougori.</p><Button onClick={() => void workspaceApi.openUrl(`${website}/publish`)}>Upload a model</Button></section> : null}
        <div className="model-tabs">{models.map(item => <button key={item.id} disabled={busy} aria-pressed={selected?.id === item.id} onClick={() => setSelected(item)}>{item.name} · {item.visibility === "api-only" ? "Closed weights" : item.visibility}</button>)}</div>
        {selected ? <section className="model-form"><strong>{selected.name}</strong><code>{selected.ref}</code><p>{selected.description}</p><p>License: {selected.license} · {selected.downloads ?? 0} downloads initiated</p><p className="model-hint">Model files download from Yougori. You can run a downloaded model on your own GPU.</p><Button variant="outline" onClick={() => void workspaceApi.openUrl(`${website}/modellibrary?model=${encodeURIComponent(selected.ref)}`)}>Model card and files</Button>
          {selected.canDownload && selected.visibility !== "api-only" && selected.version?.source === "upload" ? <><Button variant="outline" disabled={busy} onClick={() => void action(async () => { const folder = await registryApi.folder(); if (folder) { await registryApi.download(selected.ref, folder); setNotice("Model files downloaded from Yougori and verified.") } })}>Download model files</Button><Button disabled={busy || selected.version?.inferenceAvailable === false} onClick={() => { onRun(selected.ref, selected.version?.quant ?? undefined); setOpen(false) }}>Run on my GPU</Button></> : null}
          {selected.owned ? <Button variant="outline" onClick={() => void workspaceApi.openUrl(`${website}/publish?model=${encodeURIComponent(selected.ref)}`)}>Edit page and permissions</Button> : null}
        </section> : null}
        {busy ? <Button variant="outline" onClick={() => void registryApi.pause()}>Pause download</Button> : null}{notice ? <p role="status" className="model-hint">{notice}</p> : null}{error ? <p role="alert" className="model-error">{error}</p> : null}<DialogClose render={<Button variant="outline" disabled={busy} />}>Close</DialogClose>
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
