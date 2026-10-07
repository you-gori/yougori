import { useEffect, useState } from "react"
import { EyeIcon, EyeOffIcon, Globe2Icon, PlugZapIcon, PlusIcon, Trash2Icon } from "lucide-react"
import { workspaceApi, type SetupTunnelConnection } from "@/api/workspace-api"
import type { GraphEnvironment } from "@/components/graph-capabilities"
import { sameEndpoint, type CapabilityEndpoint } from "@/components/graph-capabilities"
import type { useCapabilityConnections } from "@/components/use-capability-connections"
import { Button } from "@/components/ui/button"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { accountRequest, emptyCloudflareDraft } from "@/lib/cloudflare-account"
import { cloudflareTokenInput } from "@/lib/cloudflare-token"
import { publicAccessPresetScope, readPublicAccessPresets, validServicePort, writePublicAccessPresets, type PublicAccessPreset } from "@/lib/public-access-presets"
import { useTopicWalkthroughModal } from "@/lib/topic-walkthrough"

type PresetWiring = Pick<ReturnType<typeof useCapabilityConnections>, "active" | "hovered" | "clickEndpoint" | "pointerDown">

export function SavedSetupCard({ preset, onManage, wiring }: { preset: PublicAccessPreset; onManage(): void; wiring: PresetWiring }) {
  const [domainVisible, setDomainVisible] = useState(false)
  const endpoint: CapabilityEndpoint = { kind: "preset", id: preset.id }
  const highlighted = sameEndpoint(wiring.active, endpoint) || sameEndpoint(wiring.hovered, endpoint)
  return <div className="workspace-access-card workspace-domain-card relative min-w-0 shrink-0" data-saved-setups-card data-preset-card={preset.id}>
    <Button aria-label={domainVisible ? `Manage ${preset.hostname}, app port ${preset.port}` : `Manage saved setup, app port ${preset.port}`} title={domainVisible ? `${preset.hostname} · app port :${preset.port}` : `Saved domain · app port :${preset.port}`} className={`workspace-access-button w-full min-w-0 ${highlighted ? "border-primary! ring-2 ring-primary/20" : ""}`} type="button" variant="outline" onClick={onManage}>
      <span className="workspace-access-icon"><Globe2Icon aria-hidden="true" /></span>
      <span className="truncate">{domainVisible ? preset.hostname : "Domain"} <span className="text-muted-foreground">:{preset.port}</span></span>
    </Button>
    <Button aria-label={domainVisible ? `Hide domain for port ${preset.port}` : `Show domain for port ${preset.port}`} aria-pressed={domainVisible} className="absolute! right-2 top-1/2 z-20 size-7! -translate-y-1/2" onClick={() => setDomainVisible(value => !value)} size="icon-xs" type="button" variant="ghost">
      {domainVisible ? <EyeOffIcon aria-hidden="true" /> : <EyeIcon aria-hidden="true" />}
    </Button>
    <Button aria-label={`Connect saved setup for app port ${preset.port}`} aria-pressed={sameEndpoint(wiring.active, endpoint)} className="absolute! -bottom-px left-1/2 z-30 size-11! -translate-x-1/2 translate-y-1/2 touch-none rounded-full! p-0! hover:bg-transparent" data-preset-connection-point={preset.id} data-connection-side="bottom" onClick={() => wiring.clickEndpoint(endpoint)} onPointerDown={event => wiring.pointerDown(event, endpoint)} type="button" variant="ghost"><span aria-hidden="true" className="pointer-events-none size-4 rounded-full border-[3px] border-background bg-primary shadow-[0_0_0_1px_var(--primary)]" /></Button>
  </div>
}

export function PublicAccessPresets({ environments, refresh, wiring }: { environments: GraphEnvironment[]; refresh(id: string): Promise<void>; wiring?: PresetWiring }) {
  const [open, setOpen] = useState(false)
  const topic = useTopicWalkthroughModal(open)
  const [presets, setPresets] = useState(readPublicAccessPresets)
  const [port, setPort] = useState("")
  const [hostname, setHostname] = useState("")
  const [hostPort, setHostPort] = useState("")
  const [token, setToken] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [message, setMessage] = useState("")
  const [connectingTunnel, setConnectingTunnel] = useState<string | null>(null)
  const [setupTunnel, setSetupTunnel] = useState<(SetupTunnelConnection & { id: string }) | null>(null)
  const [target, setTarget] = useState<{ environmentId: string; port: number } | null>(null)
  const [editing, setEditing] = useState<{ id: string; port: string; hostPort: string } | null>(null)
  useEffect(() => {
    const openForConnection = (event: Event) => { const detail = (event as CustomEvent<{ environmentId: string; port: number; error?: string }>).detail; setPresets(readPublicAccessPresets()); setTarget(detail); setPort(String(detail.port)); setError(detail.error ?? ""); setMessage(detail.error ? "" : "Choose a saved setup for this port."); setOpen(true) }
    window.addEventListener("yougori-open-public-presets", openForConnection)
    const openManager = () => { setPresets(readPublicAccessPresets()); setTarget(null); setError(""); setMessage(""); setOpen(true) }
    window.addEventListener("yougori-open-public-presets-manager", openManager)
    return () => { window.removeEventListener("yougori-open-public-presets", openForConnection); window.removeEventListener("yougori-open-public-presets-manager", openManager) }
  }, [])
  useEffect(() => {
    const refreshPresets = () => setPresets(readPublicAccessPresets())
    window.addEventListener("yougori-public-presets-changed", refreshPresets)
    return () => window.removeEventListener("yougori-public-presets-changed", refreshPresets)
  }, [])
  const targets = environments.filter(env => ["container", "microVm", "fullVm"].includes(env.kind) && !env.runtime.startsWith("shared://"))
  const visiblePresets = target ? presets.filter(item => item.port === target.port) : presets
  const saveList = async (next: PublicAccessPreset[]) => { await writePublicAccessPresets(next); setPresets(readPublicAccessPresets()) }
  const perform = async (action: () => Promise<void>) => {
    if (busy) return
    setBusy(true); setError(""); setMessage(""); setSetupTunnel(null)
    try { await action() } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(false) }
  }
  const startSetupTunnel = async (preset: PublicAccessPreset) => {
    setConnectingTunnel(preset.id)
    setMessage(`Connecting ${preset.hostname} to Cloudflare…`)
    try {
      const connection = await workspaceApi.startSetupTunnel(preset.id)
      setSetupTunnel({ ...connection, id: preset.id })
      setMessage("")
    } catch (reason) {
      setMessage("")
      throw new Error(`Your setup is saved, but the tunnel could not connect: ${reason instanceof Error ? reason.message : String(reason)}. Choose “Connect for tunnel setup” to retry.`)
    } finally { setConnectingTunnel(null) }
  }
  const save = () => void perform(async () => {
    const guestPort = Number(port)
    if (!validServicePort(guestPort)) throw new Error("Enter the port your app uses inside the environment")
    const { hostPort: bridgePort, options } = accountRequest({ ...emptyCloudflareDraft(), mode: "account", hostname, localPort: hostPort, token, routesReviewed: true })
    if (!token.trim()) throw new Error("Paste the dedicated Cloudflare tunnel token")
    if (presets.length >= 200) throw new Error("Remove an unused setup before adding another")
    const preset: PublicAccessPreset = { id: crypto.randomUUID(), credentialEnvironmentId: publicAccessPresetScope, port: guestPort, hostname: options.hostname, hostPort: bridgePort }
    if (presets.some(item => item.hostname === preset.hostname)) throw new Error("This domain already has a saved setup")
    if (presets.some(item => item.hostPort === preset.hostPort)) throw new Error("Choose a different local tunnel port for each setup")
    await workspaceApi.saveCloudflarePreset(publicAccessPresetScope, guestPort, preset.id, preset.hostname, bridgePort, token)
    try { await saveList([...presets, preset]) }
    catch (reason) { await workspaceApi.forgetCloudflarePreset(publicAccessPresetScope, guestPort, preset.id); throw reason }
    setToken(""); setHostname(""); setHostPort("")
    await startSetupTunnel(preset)
  })
  const connect = (preset: PublicAccessPreset) => void perform(async () => {
    const environment = targets.find(env => env.id === target?.environmentId)
    if (!environment || !target || preset.port !== target.port) throw new Error("Connect an environment's matching app port to Public access first.")
    if (environment.status !== "running") throw new Error(`Start ${environment.name} before connecting this setup.`)
    const usingSetup = targets.find(env => env.id !== environment.id && env.workspace?.publications.some(item => item.kind === "cloudflare" && item.hostPort === preset.hostPort && item.urls.includes(`https://${preset.hostname}`)))
    if (usingSetup) throw new Error(`${preset.hostname} is already connected to ${usingSetup.name}. Disconnect it there before using this setup with ${environment.name}.`)
    const publications = environment.workspace?.publications.filter(item => item.port === preset.port && item.kind === "cloudflare") ?? []
    if (publications.some(item => item.urls.includes(`https://${preset.hostname}`))) { setMessage(`${preset.hostname} is already connected.`); return }
    if (publications.length) throw new Error(`Port ${preset.port} is already public. Disconnect its current Cloudflare publication in Port settings, then connect this setup.`)
    try {
      await workspaceApi.publish(environment.id, preset.port, "cloudflare", preset.hostPort, { hostname: preset.hostname, presetId: preset.id, presetSourceEnvironmentId: preset.credentialEnvironmentId, remember: false, routesReviewed: true })
    } finally { await refresh(environment.id) }
    setMessage(`${preset.hostname} is connected to ${environment.name}.`)
  })
  const saveEdit = (preset: PublicAccessPreset) => void perform(async () => {
    if (!editing) return
    const guestPort = Number(editing.port), bridgePort = Number(editing.hostPort)
    if (!validServicePort(guestPort)) throw new Error("Enter the port your app uses inside the environment")
    if (!validServicePort(bridgePort)) throw new Error("Enter a local tunnel port from 1 to 65535, excluding 7443")
    if (presets.some(item => item.id !== preset.id && item.hostPort === bridgePort)) throw new Error("Choose a different local tunnel port for each setup")
    if (guestPort === preset.port && bridgePort === preset.hostPort) { setEditing(null); return }
    await workspaceApi.updateSavedDomain(preset.id, guestPort, bridgePort)
    await saveList(presets.map(item => item.id === preset.id ? { ...item, port: guestPort, hostPort: bridgePort } : item))
    setEditing(null)
    // Show the route again: Cloudflare must point at the new local tunnel port.
    if (bridgePort !== preset.hostPort) await startSetupTunnel({ ...preset, port: guestPort, hostPort: bridgePort })
    else setMessage(`${preset.hostname} now uses app port :${guestPort}.`)
  })
  const remove = (preset: PublicAccessPreset) => void perform(async () => {
    await workspaceApi.forgetCloudflarePreset(preset.credentialEnvironmentId, preset.port, preset.id)
    await saveList(presets.filter(item => item.id !== preset.id))
    setMessage("Setup removed. Active connections and tokens remembered for individual nodes remain until you disconnect or forget them there.")
  })
  const openManager = () => { setPresets(readPublicAccessPresets()); setTarget(null); setError(""); setMessage(""); setOpen(true) }

  return <>
    {wiring ? presets.map(preset => <SavedSetupCard key={preset.id} preset={preset} onManage={openManager} wiring={wiring} />) : null}
    <Dialog modal={!topic} open={open} onOpenChange={(value, details) => { if (!busy && !(!value && topic && details.reason === "focus-out") && !(details.event.target instanceof Element && details.event.target.closest('[data-topic-ui]'))) setOpen(value) }}>
      <DialogPopup data-instruction="public-presets-dialog" className="max-w-3xl" closeProps={{ disabled: busy }}>
        <DialogHeader><DialogTitle>Public access setups</DialogTitle><DialogDescription>Save a domain and app port once, then use it with any environment running an app on that port. Each domain needs its own dedicated Cloudflare tunnel and local bridge port.</DialogDescription></DialogHeader>
        <DialogPanel className="space-y-5">
          {error ? <p role="alert" className="text-sm text-destructive-foreground">{error}</p> : null}
          {message ? <p role="status" className="text-sm text-muted-foreground">{message}</p> : null}
          {setupTunnel ? <section className="space-y-2 rounded-lg border p-3 text-sm" aria-label="Cloudflare tunnel setup">
            <p role="status" className="font-medium">Connection is on — tunnel connected to Cloudflare</p>
            <p className="text-xs text-muted-foreground">The connection stays on while you set up the tunnel in Cloudflare. Keep Yougori running.</p>
            <p>In Cloudflare, open this tunnel and add a Published application route:</p>
            <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1">
              <dt>Hostname</dt><dd className="break-all">{setupTunnel.hostname}</dd>
              <dt>Type</dt><dd>HTTP</dd>
              <dt>URL</dt><dd className="break-all"><code>http://localhost:{setupTunnel.hostPort}</code></dd>
            </dl>
            <p className="text-xs text-muted-foreground">{setupTunnel.servingApp ? "An environment is already connected to this domain." : "The domain shows a setup message until you connect an environment's matching app port to this saved setup."}</p>
            <div className="flex flex-wrap gap-2">
              <Button size="xs" variant="outline" onClick={() => void workspaceApi.openUrl("https://dash.cloudflare.com/").catch(reason => setError(String(reason)))}>Open Cloudflare dashboard</Button>
              {!setupTunnel.servingApp ? <Button size="xs" variant="ghost" disabled={busy} onClick={() => void perform(async () => { await workspaceApi.stopSetupTunnel(setupTunnel.id); setMessage("Setup connection is off. Your saved setup is kept.") })}>Stop setup tunnel</Button> : null}
            </div>
          </section> : null}
          <section className="space-y-2" aria-label="Saved setups">
            <h3 className="text-sm font-medium">Domain and port</h3>
            <p className="text-xs text-muted-foreground">Choose Connect for tunnel setup to bring a tunnel online while you create its route in Cloudflare. No environment needs to be running.</p>
            {target ? <p className="text-xs text-muted-foreground">Connecting {targets.find(env => env.id === target.environmentId)?.name ?? "environment"} · app port :{target.port}</p> : <p className="text-xs text-muted-foreground">After routing is ready, connect an environment's matching app port to Public access to serve your app.</p>}
            {visiblePresets.length ? visiblePresets.map(preset => {
              const environment = targets.find(env => env.id === target?.environmentId)
              const connected = environment?.workspace?.publications.some(item => item.kind === "cloudflare" && item.port === preset.port && item.urls.includes(`https://${preset.hostname}`))
              if (editing?.id === preset.id) return <form key={preset.id} aria-label={`Edit ${preset.hostname}`} className="space-y-2 rounded-lg border p-2 text-sm" onSubmit={event => { event.preventDefault(); saveEdit(preset) }}>
                <strong className="block truncate">{preset.hostname}</strong>
                <div className="grid gap-3 sm:grid-cols-2">
                  <label className="space-y-1 text-xs">App port<Input aria-label="App port" required inputMode="numeric" value={editing.port} disabled={busy} onChange={event => setEditing({ ...editing, port: event.target.value })} /></label>
                  <label className="space-y-1 text-xs">Local tunnel port<Input aria-label="Local tunnel port" required inputMode="numeric" value={editing.hostPort} disabled={busy} onChange={event => setEditing({ ...editing, hostPort: event.target.value })} /></label>
                </div>
                {editing.hostPort !== String(preset.hostPort) ? <p className="text-xs text-muted-foreground">After saving, change this tunnel's route in Cloudflare to <code>http://localhost:{editing.hostPort || preset.hostPort}</code>. Disconnect any environment using this domain first.</p> : null}
                <div className="flex gap-2">
                  <Button type="submit" size="xs" loading={busy} disabled={busy}>Save ports</Button>
                  <Button type="button" size="xs" variant="ghost" disabled={busy} onClick={() => setEditing(null)}>Cancel</Button>
                </div>
              </form>
              return <div key={preset.id} className="flex flex-wrap items-center gap-2 rounded-lg border p-2 text-sm">
                <span className="min-w-0 flex-1"><strong className="block truncate">{preset.hostname} · :{preset.port}</strong><span className="text-xs text-muted-foreground">Any environment · local bridge :{preset.hostPort}</span></span>
                {target ? <Button size="xs" variant="outline" disabled={busy || !environment || environment.status !== "running" || connected} onClick={() => connect(preset)}>{connected ? "App connected" : "Connect app"}</Button> : null}
                <Button size="sm" className="shrink-0" aria-label={`Connect for tunnel setup: ${preset.hostname}`} loading={connectingTunnel === preset.id} disabled={busy} onClick={() => void perform(() => startSetupTunnel(preset))}><PlugZapIcon aria-hidden="true" />Connect for tunnel setup</Button>
                <Button aria-label={`Edit ports for ${preset.hostname}`} size="xs" variant="ghost" disabled={busy} onClick={() => { setError(""); setMessage(""); setEditing({ id: preset.id, port: String(preset.port), hostPort: String(preset.hostPort) }) }}>Edit</Button>
                <Button aria-label={`Remove ${preset.hostname}`} title={`Remove ${preset.hostname}`} size="icon-xs" variant="ghost" disabled={busy} onClick={() => remove(preset)}><Trash2Icon aria-hidden="true" /></Button>
              </div>
            }) : <p className="text-xs text-muted-foreground">{target ? "No saved setups for this app port yet." : "No saved domain setups yet."}</p>}
          </section>
          <form className="space-y-3 border-t pt-4" onSubmit={event => { event.preventDefault(); save() }}>
            <h3 className="flex items-center gap-2 text-sm font-medium"><PlusIcon aria-hidden="true" className="size-4" />Add a setup</h3>
            <div className="grid gap-3 sm:grid-cols-2">
              <label className="space-y-1 text-xs">App port<Input aria-label="App port" required inputMode="numeric" placeholder="3000" value={port} disabled={busy} onChange={event => setPort(event.target.value)} /></label>
              <label className="space-y-1 text-xs">Domain<Input aria-label="Domain" required autoComplete="off" spellCheck={false} placeholder="crm.example.com" value={hostname} disabled={busy} onChange={event => setHostname(event.target.value)} /></label>
              <label className="space-y-1 text-xs">Local tunnel port<Input aria-label="Local tunnel port" required inputMode="numeric" placeholder="45000" value={hostPort} disabled={busy} onChange={event => setHostPort(event.target.value)} /></label>
            </div>
            <label className="block space-y-1 text-xs">Cloudflare tunnel token<Input aria-label="Cloudflare tunnel token" required type="password" autoComplete="new-password" maxLength={4096} placeholder="Paste token or Cloudflare command" value={token} disabled={busy} onChange={event => setToken(cloudflareTokenInput(event.target.value))} /></label>
            <p className="text-xs text-muted-foreground">In Cloudflare, create a dedicated tunnel with no routes yet, or only this domain pointing to <code>http://localhost:{hostPort || "45000"}</code>. Paste the token or full installation command. Yougori connects the tunnel and keeps the connection on while you set up its route. The app port is inside the environment. Anyone who knows the public URL can visit unless you configure visitor protection. Your token is saved in the OS credential vault.</p>
            <Button type="button" size="xs" variant="link" onClick={() => void perform(() => workspaceApi.openUrl("https://dash.cloudflare.com/"))}>Open Cloudflare dashboard</Button>
            <Button type="submit" size="sm" loading={busy} disabled={busy}>Save and connect tunnel</Button>
          </form>
        </DialogPanel>
        <DialogFooter><Button variant="ghost" disabled={busy} onClick={() => setOpen(false)}>Done</Button></DialogFooter>
      </DialogPopup>
    </Dialog>
  </>
}
