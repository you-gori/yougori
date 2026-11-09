import { useCallback, useEffect, useState } from "react"
import { ExternalLinkIcon, GlobeIcon, RefreshCwIcon } from "lucide-react"
import { workspaceApi, type EnvironmentServices } from "@/api/workspace-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

// Opens this environment's own web services in a Yougori browser window.
// Public addresses are left to the system browser, so a guest cannot use this
// panel to open arbitrary sites inside the app.
export function GuestBrowser({ environmentId, active }: { environmentId: string; active: boolean }) {
  const [services, setServices] = useState<EnvironmentServices | null>(null)
  const [address, setAddress] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const load = useCallback(async () => {
    try { setServices(await workspaceApi.services(environmentId)); setError("") }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
  }, [environmentId])
  useEffect(() => { if (active) void load() }, [active, load])
  const open = (url: string, inApp: boolean) => void (async () => {
    if (busy) return
    setBusy(true); setError("")
    try { await (inApp ? workspaceApi.openServiceWindow(environmentId, url) : workspaceApi.openUrl(url)) }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(false) }
  })()
  // A loopback publication is on this computer only; "local" is the local network.
  const published = (services?.publications ?? []).flatMap(publication => publication.urls.map(url => ({ url, label: `Port ${publication.port} · ${publication.kind === "cloudflare" ? "Cloudflare Tunnel" : publication.kind === "public" ? "Public access" : publication.kind === "loopback" ? "This computer" : "Local network"}`, local: publication.kind === "local" || publication.kind === "loopback" })))

  return <div data-guest-browser className="flex h-full min-h-0 flex-col gap-3 overflow-auto p-3 text-sm">
    <div className="flex flex-wrap items-center gap-2">
      <Input aria-label="Service address" className="h-7 min-w-0 flex-1" placeholder="http://127.0.0.1:8080" value={address} onChange={event => setAddress(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && address.trim()) open(address.trim(), true) }} />
      <Button size="xs" disabled={busy || !address.trim()} onClick={() => open(address.trim(), true)}><GlobeIcon aria-hidden="true" />Open in Yougori</Button>
      <Button size="xs" variant="ghost" aria-label="Refresh services" onClick={() => void load()}><RefreshCwIcon aria-hidden="true" /></Button>
    </div>
    {error ? <p role="alert" className="break-words text-xs text-destructive-foreground">{error}</p> : null}
    <section aria-label="Environment web services" className="space-y-2">
      <h3 className="text-xs font-medium text-muted-foreground">Detected service ports</h3>
      {services?.services.length ? services.services.map(service => <div key={`${service.port}-${service.address}`} className="flex flex-wrap items-center gap-2 rounded border p-2 text-xs">
        <span className="min-w-0 flex-1 truncate">TCP {service.port}{service.name ? ` · ${service.name}` : ""}</span>
        <span className="text-muted-foreground">Publish this port to open it</span>
      </div>) : <p className="text-xs text-muted-foreground">No listening service ports were detected yet.</p>}
    </section>
    <section aria-label="Published addresses" className="space-y-2">
      <h3 className="text-xs font-medium text-muted-foreground">Published addresses</h3>
      {published.length ? published.map(entry => <div key={entry.url} className="flex flex-wrap items-center gap-2 rounded border p-2 text-xs">
        <span className="min-w-0 flex-1 break-all">{entry.label} · {entry.url}</span>
        {entry.local ? <Button size="xs" variant="outline" disabled={busy} onClick={() => open(entry.url, true)}><GlobeIcon aria-hidden="true" />Open in Yougori</Button> : null}
        <Button size="xs" variant="ghost" disabled={busy} onClick={() => open(entry.url, false)}><ExternalLinkIcon aria-hidden="true" />System browser</Button>
      </div>) : <p className="text-xs text-muted-foreground">Nothing published yet. Use Publish to in the right sidebar.</p>}
    </section>
    <p className="text-[11px] text-muted-foreground">Yougori windows open only this computer's private addresses. To browse the wider web from inside an environment, install a browser in it and launch it from Apps.</p>
  </div>
}
