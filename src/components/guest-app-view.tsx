import { useEffect, useState } from "react"
import { guestAppsApi, type GuestApp } from "@/api/guest-apps-api"
import { VncDesktop } from "@/components/guest-desktop"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"

export function GuestAppView({ environmentId, sessionId, active }: { environmentId: string; sessionId: string; active: boolean }) {
  const [app, setApp] = useState<GuestApp | null>(null)
  const [url, setUrl] = useState("")
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [revision, setRevision] = useState(0)
  const [stopping, setStopping] = useState(false)
  useEffect(() => {
    if (!active) return
    let disposed = false, timer = 0, displayUrl = "", failures = 0
    setError(""); setNotice(""); setUrl("")
    const refresh = async () => {
      try {
        const status = await guestAppsApi.status(environmentId)
        const current = status.apps.find(item => item.id === sessionId)
        if (!current) { if (!disposed) setError("This app session has closed. Open Apps to launch it again."); return }
        if (disposed) return
        setApp(current)
        if (current.state === "running" && !displayUrl) {
          displayUrl = (await guestAppsApi.view(environmentId, sessionId)).websocketUrl
          if (!disposed) setUrl(displayUrl)
        }
        failures = 0
        if (!disposed) setNotice("")
        if (!disposed && current.state !== "stopped") timer = window.setTimeout(refresh, 2500)
      } catch (reason) {
        if (disposed) return
        // A transient status or display error keeps the app open and retries with backoff.
        const message = reason instanceof Error ? reason.message : String(reason)
        if (++failures > 5) { setError(message); return }
        setNotice(`${message} Retrying…`)
        timer = window.setTimeout(refresh, Math.min(30_000, 2500 * 2 ** failures))
      }
    }
    void refresh()
    return () => { disposed = true; window.clearTimeout(timer) }
  }, [environmentId, sessionId, active, revision])
  return <div className="flex size-full min-h-0 flex-col">
    <div className="flex shrink-0 items-center justify-between gap-2 border-b px-3 py-1.5 text-xs"><span className="truncate">{app?.name ?? "App display"}</span>{notice ? <span role="status" className="min-w-0 flex-1 truncate text-muted-foreground">{notice}</span> : null}<div className="flex gap-2"><Button type="button" size="xs" variant="ghost" onClick={() => setRevision(value => value + 1)}>Reconnect</Button><Button type="button" size="xs" variant="destructive-outline" loading={stopping} disabled={!app || app.state === "stopped"} onClick={() => { setStopping(true); void guestAppsApi.stop(environmentId, sessionId).then(() => { setApp(current => current ? { ...current, state: "stopped", message: "App stopped." } : null); setUrl("") }).catch(reason => setError(String(reason))).finally(() => setStopping(false)) }}>Stop app</Button></div></div>
    <div className="min-h-0 flex-1">{error || app?.state === "stopped" ? <div role="status" className="grid size-full place-items-center overflow-auto p-6"><p className="max-w-xl whitespace-pre-wrap break-words text-sm text-muted-foreground">{error || app?.message || "App closed."}</p></div> : url && active ? <VncDesktop key={`${url}-${revision}`} websocketUrl={url} password="" /> : <div role="status" className="flex size-full flex-col items-center justify-center gap-3 text-sm text-muted-foreground"><Spinner />Starting app display…</div>}</div>
  </div>
}
