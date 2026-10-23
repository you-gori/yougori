import { useCallback, useEffect, useRef, useState } from "react"
import { registryApi, type PublishedModel } from "@/api/model-registry-api"
import { workspaceApi } from "@/api/workspace-api"
import { useNetwork } from "@/components/use-network"
import { NetworkAccount } from "@/components/network-panel"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogDescription, DialogPanel, DialogPopup, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import "@/components/model-workspace.css"

export function ModelLibrary({ onRun }: { onRun: (model: string, quant?: string) => void }) {
  const [open, setOpen] = useState(false), [mine, setMine] = useState(false)
  const network = useNetwork(open)
  const [models, setModels] = useState<PublishedModel[]>([]), [selected, setSelected] = useState<PublishedModel | null>(null)
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("")
  const lock = useRef(false)
  // The tab a request was made for: an answer that arrives after switching tabs is dropped.
  const tab = useRef(mine)
  tab.current = mine
  const refresh = useCallback(async () => { const { models } = await registryApi.list(mine); if (tab.current === mine) setModels(models) }, [mine])
  useEffect(() => { setModels([]); if (!open || mine && !network.status?.signedIn) return; const update=()=>void refresh().catch(e=>setError(String(e))); update(); const timer=window.setInterval(update,15000); return ()=>window.clearInterval(timer) }, [open, mine, network.status?.signedIn, refresh])
  const action = async (work: () => Promise<void>) => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError(""); setNotice("")
    try { await work(); await refresh() } catch (e) { setError(String(e)) } finally { lock.current = false; setBusy(false) }
  }
  const website = network.status?.website ?? "https://yougori.com"
  return <Dialog open={open} onOpenChange={value => { if (!busy) setOpen(value) }}>
    <DialogTrigger render={<Button size="sm" variant="outline" />}>Model library</DialogTrigger>
    <DialogPopup showCloseButton={false} className="model-popup max-w-none" bottomStickOnMobile={false}>
      <header className="model-dialog-header">
        <div>
          <DialogTitle>Model library</DialogTitle>
          <DialogDescription>LLMs created in the EU and Horizon Europe-associated countries. Model files are stored on Yougori.</DialogDescription>
        </div>
        <DialogClose render={<Button variant="outline" size="sm" className="model-close" disabled={busy} />}>Close</DialogClose>
      </header>
      <DialogPanel className="model-panel" scrollFade={false}>
        <NetworkAccount network={network} />
        <div className="model-tabs" role="group" aria-label="Library"><button type="button" disabled={busy} aria-pressed={!mine} onClick={() => { setMine(false); setSelected(null) }}>Browse</button><button type="button" disabled={busy} aria-pressed={mine} onClick={() => { setMine(true); setSelected(null) }}>Publish</button></div>
        {mine && network.status?.signedIn ? <section className="model-card">
          <p className="model-library-text">Upload your model weights, tokenizer, configuration, card and license on Yougori.</p>
          <div className="model-library-actions"><Button onClick={() => void workspaceApi.openUrl(`${website}/publish`)}>Upload a model</Button></div>
        </section> : null}
        {models.length ? <ul className="model-library-list" aria-label="Models">
          {models.map(item => {
            const visibility = item.visibility === "api-only" ? "Closed weights" : item.visibility
            return <li key={item.id}>
              <button type="button" aria-label={`${item.name} · ${visibility}`} disabled={busy} aria-pressed={selected?.id === item.id} onClick={() => setSelected(item)}>
                <span className="model-library-name">{item.name}</span>
                <span className="model-library-tag">{visibility}</span>
              </button>
            </li>
          })}
        </ul> : <p className="model-hint">{mine ? "You have not published a model yet." : "No models in the library yet."}</p>}
        {selected ? <section className="model-card model-library-detail" aria-label={selected.name}>
          <div className="model-library-detail-head">
            <strong>{selected.name}</strong>
            <code>{selected.ref}</code>
          </div>
          {selected.description ? <p className="model-library-text">{selected.description}</p> : null}
          <p className="model-hint">License: {selected.license} · {selected.downloads ?? 0} downloads initiated</p>
          <p className="model-hint">Model files download from Yougori. You can run a downloaded model on your own GPU.</p>
          <div className="model-library-actions">
            <Button variant="outline" onClick={() => void workspaceApi.openUrl(`${website}/modellibrary?model=${encodeURIComponent(selected.ref)}`)}>Model card and files</Button>
            {selected.owned ? <Button variant="outline" onClick={() => void workspaceApi.openUrl(`${website}/publish?model=${encodeURIComponent(selected.ref)}`)}>Edit page and permissions</Button> : null}
            {selected.canDownload && selected.visibility !== "api-only" && selected.version?.source === "upload" ? <>
              <Button variant="outline" disabled={busy} onClick={() => void action(async () => { const folder = await registryApi.folder(); if (folder) { await registryApi.download(selected.ref, folder); setNotice("Model files downloaded from Yougori and verified.") } })}>Download model files</Button>
              <Button disabled={busy || selected.version?.inferenceAvailable === false} onClick={() => { onRun(selected.ref, selected.version?.quant ?? undefined); setOpen(false) }}>Run on my GPU</Button>
            </> : null}
          </div>
        </section> : null}
        {busy ? <div className="model-library-actions"><Button variant="outline" onClick={() => void registryApi.pause()}>Pause download</Button></div> : null}
        {notice ? <p role="status" className="model-hint">{notice}</p> : null}
        {error ? <p role="alert" className="model-error">{error}</p> : null}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
