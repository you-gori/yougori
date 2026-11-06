import { useEffect, useId, useState } from "react"
import { sandboxVmApi, visibleText, type GridKind, type GridSettings } from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"

export function GridHostingBox({ sandbox, disabled }: { sandbox: string; disabled: boolean }) {
  const [settings, setSettings] = useState<GridSettings | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [round, setRound] = useState(0)
  const id = useId()
  useEffect(() => {
    let active = true
    setSettings(null); setError("")
    void sandboxVmApi.gridSettings(sandbox).then(value => { if (active) setSettings(value) }, reason => { if (active) setError(String(reason)) })
    return () => { active = false }
  }, [sandbox, round])
  async function toggle(kind: GridKind, checked: boolean) {
    if (!settings || busy || disabled) return
    setBusy(true); setError(""); setNotice("")
    const enabled = checked ? [...settings.enabled, kind] : settings.enabled.filter(value => value !== kind)
    try {
      setSettings(await sandboxVmApi.gridSettings(sandbox, enabled))
      setNotice("Grid settings saved in this VM.")
    } catch (reason) { setError(String(reason)) }
    finally { setBusy(false) }
  }
  return <section aria-label="Grid hosting" aria-busy={busy} className="space-y-3 rounded-lg border p-3">
    <div className="flex items-center justify-between gap-2"><h3 className="font-medium">Grid hosting</h3>
      <Button size="xs" variant="ghost" disabled={disabled || busy} onClick={() => { setNotice(""); setRound(value => value + 1) }}>Refresh grids</Button></div>
    <p className="text-muted-foreground">Choose the grids your app can host. Settings are saved in this VM’s workspace.</p>
    {settings ? <div className="grid gap-3 sm:grid-cols-2">{([
      ["gpu", "GPU Grid", "Accept model workers from computers and cloud GPUs."],
      ["sandbox", "Sandbox Grid", "Accept CPU and memory workers together."],
    ] as const).map(([kind, label, description]) => <div key={kind} className="rounded-lg bg-muted/30 p-3">
      <div className="flex items-center justify-between gap-3"><label htmlFor={`${id}-${kind}`} className="font-medium">{label}</label>
        <Switch id={`${id}-${kind}`} checked={settings.enabled.includes(kind)} disabled={disabled || busy} onCheckedChange={checked => void toggle(kind, checked)} /></div>
      <p className="mt-2 text-muted-foreground">{description}</p>
    </div>)}</div> : !error ? <p role="status">Reading grid settings…</p> : null}
    <p className="text-muted-foreground">Turning a grid off stops new jobs and rejects results from its outstanding jobs. It cannot stop work already executing on another computer.</p>
    {settings?.enabled.length ? <p className="text-muted-foreground">Tools and the grid skill are installed. Your app starts the controller, or run <code>yougori grid serve</code> in the VM terminal. Sharing with other computers uses the VM’s app-sharing settings. GPU Grid does not enable local GPU acceleration.</p> : null}
    {busy ? <p role="status">Saving grid settings…</p> : notice ? <p role="status">{notice}</p> : null}
    {error ? <p role="alert" className="text-destructive">{visibleText(error)}</p> : null}
  </section>
}
