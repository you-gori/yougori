import { useEffect, useRef, useState } from "react"
import { modelsApi, type ModelRun } from "@/api/projects-api"
import { workspaceApi } from "@/api/workspace-api"
import type { Environment } from "@/types/platform"
import { modelApiSkill } from "@/lib/model-api-skill"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel } from "@/components/ui/dialog"

export function ModelEnvironmentActions({ environment, onChat }: { environment: Environment; onChat(): void }) {
  const [view, setView] = useState<"api" | null>(null)
  const isModel = environment.kind === "container" && environment.description.startsWith("Hugging Face · ")
  if (!isModel) return null
  return <>
    <Button size="sm" variant="ghost" className="text-xs text-muted-foreground" disabled={environment.status !== "running"} onClick={onChat}>Chat</Button>
    <Button size="sm" variant="ghost" className="text-xs text-muted-foreground" onClick={() => setView("api")}>API skill</Button>
    <Dialog open={view !== null} onOpenChange={open => { if (!open) setView(null) }}>
      <DialogPopup className="max-h-[calc(100dvh-4rem)] max-w-4xl">
        <DialogHeader>
          <DialogTitle>API skill</DialogTitle>
          <DialogDescription>{environment.description.slice("Hugging Face · ".length)}</DialogDescription>
        </DialogHeader>
        <DialogPanel>
          {view === "api" ? <ModelApiSkill key={environment.id} environment={environment} /> : null}
        </DialogPanel>
      </DialogPopup>
    </Dialog>
  </>
}

function ModelApiSkill({ environment }: { environment: Environment }) {
  const [port, setPort] = useState("8000")
  const [checking, setChecking] = useState(true)
  const [busy, setBusy] = useState(false)
  const [result, setResult] = useState<ModelRun | null>(null)
  const [reveal, setReveal] = useState(false)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const alive = useRef(false)
  const lock = useRef(false)
  useEffect(() => {
    alive.current = true
    let current = true
    void workspaceApi.services(environment.id).then(services => {
      if (!current) return
      const existing = services.publications.find(p => p.kind === "loopback" && p.port === 8000)
      if (existing) setPort(String(existing.hostPort))
    }).catch(reason => { if (current) setError(`Could not check existing API access: ${String(reason)}`) })
      .finally(() => { if (current) setChecking(false) })
    return () => { current = false; alive.current = false }
  }, [environment.id])
  const validPort = /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535
  const configure = async () => {
    if (lock.current || checking || !validPort || environment.status !== "running") return
    lock.current = true; setBusy(true); setError(""); setNotice(""); setResult(null)
    try {
      const value = await modelsApi.api(environment.id, Number(port))
      if (alive.current) { setResult(value); setReveal(false) }
    } catch (reason) { if (alive.current) setError(String(reason)) }
    finally { lock.current = false; if (alive.current) setBusy(false) }
  }
  const copy = async (text: string, message: string) => {
    setError(""); setNotice("")
    try { await navigator.clipboard.writeText(text); if (alive.current) setNotice(message) }
    catch { if (alive.current) setError("Could not copy. Select and copy the text manually.") }
  }
  const skill = result?.apiUrl ? modelApiSkill(result) : ""
  return <section className="space-y-4" aria-label="Model API skill">
    <p className="text-sm text-muted-foreground">Use this model from an app or coding agent on this PC. Enable local API access, then copy the skill and provide the API key separately.</p>
    <div className="flex flex-wrap items-end gap-2">
      <label className="space-y-1 text-xs">Local API port<Input aria-label="Local API port" className="w-28" type="number" min={1} max={65535} value={port} disabled={checking || busy} onChange={event => { setPort(event.target.value); setResult(null); setNotice("") }} /></label>
      <Button size="sm" variant="outline" disabled={checking || busy || !validPort || environment.status !== "running"} onClick={() => void configure()}>{checking ? "Checking API…" : busy ? "Configuring…" : "Enable / get API access"}</Button>
    </div>
    {environment.status !== "running" ? <p className="text-xs text-muted-foreground">Start the model environment to enable its API. Use the environment’s Start button first.</p> : null}
    {result?.apiUrl ? <>
      <div className="space-y-3 rounded-lg border p-3">
        <label className="block space-y-1 text-xs">Base URL<Input aria-label="Model API base URL" readOnly value={result.apiUrl} /></label>
        <div className="flex items-end gap-2"><label className="min-w-0 flex-1 space-y-1 text-xs">API key<Input aria-label="Model API key" readOnly type={reveal ? "text" : "password"} value={result.apiKey ?? ""} /></label><Button size="sm" variant="ghost" onClick={() => setReveal(value => !value)}>{reveal ? "Hide key" : "Show key"}</Button><Button size="sm" variant="outline" disabled={!result.apiKey} onClick={() => void copy(result.apiKey!, "API key copied")}>Copy key</Button></div>
        <p className="text-xs text-muted-foreground">Set YOUGORI_MODEL_API_KEY in your app's environment. The copied skill contains no key. This address works on the host PC; online agents cannot reach it directly.</p>
      </div>
      <div className="flex items-center justify-between gap-2"><p className="text-xs text-muted-foreground">Give these instructions to your agent, or save as yougori-model-api/SKILL.md.</p><Button size="sm" onClick={() => void copy(skill, "API skill copied")}>Copy API skill</Button></div>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap break-words rounded-lg border bg-muted/20 p-3 text-xs" tabIndex={0}>{skill}</pre>
    </> : null}
    {notice ? <p role="status" className="text-xs text-muted-foreground">{notice}</p> : null}
    {error ? <p role="alert" className="max-h-32 overflow-auto whitespace-pre-wrap break-words text-xs text-destructive-foreground">{error}</p> : null}
  </section>
}
