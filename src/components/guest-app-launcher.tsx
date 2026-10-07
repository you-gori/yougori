import { useEffect, useRef, useState } from "react"
import { AppWindowIcon, DownloadIcon, ExternalLinkIcon, PlayIcon, RefreshCwIcon, SquareIcon } from "lucide-react"
import { guestAppsApi, type GuestAppsStatus } from "@/api/guest-apps-api"
import { Button } from "@/components/ui/button"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import type { Environment } from "@/types/platform"

export function GuestAppLauncher({ environment }: { environment: Environment }) {
  const [open, setOpen] = useState(false)
  const [status, setStatus] = useState<GuestAppsStatus | null>(null)
  const [error, setError] = useState("")
  const [pendingOperation, setPendingOperation] = useState<string | null>(null)
  const operationLock = useRef(false)
  const busy = pendingOperation !== null
  const [revision, setRevision] = useState(0)
  // A container runs apps from its own image, so it has no Firefox download and
  // starts from a command that exists in most graphical images.
  const container = environment.kind === "container"
  const [name, setName] = useState(container ? "Graphical terminal" : "Firefox")
  const [command, setCommand] = useState(container ? "xterm -fa monospace -fs 12" : "firefox --no-remote --new-window about:blank")
  useEffect(() => {
    if (!open) return
    let disposed = false, timer = 0
    const refresh = () => { void guestAppsApi.status(environment.id).then(next => { if (!disposed) setStatus(next) }).catch(reason => { if (!disposed) setError(String(reason)) }).finally(() => { if (!disposed) timer = window.setTimeout(refresh, 2500) }) }
    refresh()
    return () => { disposed = true; window.clearTimeout(timer) }
  }, [open, environment.id, revision])
  const perform = async (action: () => Promise<unknown>, key = "launch") => {
    if (operationLock.current) return
    operationLock.current = true; setPendingOperation(key); setError("")
    try { await action(); setRevision(value => value + 1) } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) } finally { operationLock.current = false; setPendingOperation(null) }
  }
  const enoughMemory = environment.resourcePolicy.memoryGb.current >= 0.5
  const needsBrowser = !container && command.trim().startsWith("firefox") && !status?.browserReady
  const place = container ? "container" : "MicroVM"
  return <Dialog open={open} onOpenChange={setOpen}>
    <DialogTrigger render={<Button type="button" aria-label="Apps" title="Graphical apps" variant="outline" size="sm" disabled={environment.status !== "running"} />}><AppWindowIcon aria-hidden="true" /><span className="hidden sm:inline">Apps</span></DialogTrigger>
    <DialogPopup className="sm:max-w-3xl">
      <DialogHeader><DialogTitle>Apps · {environment.name}</DialogTitle><DialogDescription>Run graphical Linux apps in this {place}, each in its own window. Closing a viewer leaves the app running; Stop app ends it.</DialogDescription></DialogHeader>
      <DialogPanel className="flex flex-col gap-5">
        {!enoughMemory ? <p role="status" className="rounded-lg border p-3 text-xs text-muted-foreground">This {place} is running with {environment.resourcePolicy.memoryGb.current} GB. {container ? "Give it at least 0.5 GB for graphical apps, and 2 GB for browsers." : "Set Preferred memory to at least 0.5 GB and restart for graphical apps. For browsers, start with 2 GB."}</p> : null}
        <section className="flex flex-col gap-3 rounded-lg border bg-muted/20 p-3" aria-label="Graphical app support">
          <div className="flex items-center justify-between gap-3"><p className="text-sm font-medium">{status?.ready ? "Graphical support installed" : "Optional graphical support"}</p><Button type="button" aria-label="Refresh apps" variant="ghost" size="icon-xs" onClick={() => { setError(""); setRevision(value => value + 1) }}><RefreshCwIcon aria-hidden="true" /></Button></div>
          <p className="text-xs leading-5 text-muted-foreground">{container ? "Installs a software display and a small window manager in Yougori's container engine. The app itself comes from this container's image, and only this container can reach its display." : "Installs a software display and a small window manager inside this MicroVM only. Nothing runs until you launch an app. Firefox is an optional extra download."}</p>
          <p className="text-xs text-muted-foreground">{container ? "Nothing is installed inside your container image." : "Downloads packages over this MicroVM’s existing network connection."}</p>
          <div className="flex flex-wrap gap-2">
            {!status?.ready ? <Button type="button" size="sm" variant="outline" disabled={!status || busy || status.installing || !enoughMemory} loading={pendingOperation === "base"} onClick={() => void perform(() => guestAppsApi.install(environment.id, "base"), "base")}><DownloadIcon aria-hidden="true" />Install app support</Button> : null}
            {!container && !status?.browserReady ? <Button type="button" size="sm" variant="outline" disabled={!status || busy || status.installing || !enoughMemory} loading={pendingOperation === "browser"} onClick={() => void perform(() => guestAppsApi.install(environment.id, "browser"), "browser")}><DownloadIcon aria-hidden="true" />Install Firefox + app support</Button> : null}
          </div>
          {status?.installing ? <p role="status" className="text-xs text-muted-foreground">Installing… This can take a few minutes. You can close this panel and return.</p> : null}
          {status?.containerNotice ? <p role="status" className="text-xs text-muted-foreground">{status.containerNotice}</p> : null}
          {status?.error ? <p role="alert" className="max-h-32 overflow-auto whitespace-pre-wrap break-words text-xs text-destructive-foreground">{status.error}</p> : null}
        </section>
        <div className="flex flex-wrap gap-2" aria-label="App presets">
          {container ? null : <Button type="button" variant="ghost" size="xs" onClick={() => { setName("Firefox"); setCommand("firefox --no-remote --new-window about:blank") }}>Firefox</Button>}
          <Button type="button" variant="ghost" size="xs" onClick={() => { setName("Graphical terminal"); setCommand("xterm -fa monospace -fs 12") }}>Graphical terminal</Button>
          <Button type="button" variant="ghost" size="xs" onClick={() => { setName(""); setCommand("") }}>Custom Linux app</Button>
        </div>
        <Field><FieldLabel>App name</FieldLabel><Input type="text" maxLength={80} value={name} onChange={event => setName(event.target.value)} /></Field>
        <Field><FieldLabel>Linux launch command</FieldLabel><Input type="text" maxLength={4096} value={command} onChange={event => setCommand(event.target.value)} placeholder="Installed executable or /path/to/app" /><FieldDescription>{container ? "Runs inside this container, as the container's own user, from a program that is already in its image. Install graphical programs from this container's terminal first. Windows .exe files will not work here." : "Runs as an unprivileged guest user. Install custom apps from the terminal first. Windows .exe files and incompatible Linux builds will not work here."}</FieldDescription></Field>
        {needsBrowser ? <p className="text-xs text-muted-foreground">Install Firefox above before launching this command.</p> : null}
        <Button type="button" disabled={!status?.ready || status.installing || busy || !enoughMemory || needsBrowser || !name.trim() || !command.trim()} loading={pendingOperation === "launch"} onClick={() => void perform(async () => { const app = await guestAppsApi.launch(environment.id, name.trim(), command.trim()); await guestAppsApi.openWindow(environment.id, app.id) })}><PlayIcon aria-hidden="true" />Launch in new window</Button>
        {error ? <p role="alert" className="whitespace-pre-wrap break-words text-xs text-destructive-foreground">{error}</p> : null}
        {status?.apps.length ? <section className="flex flex-col gap-2" aria-label="App sessions"><h3 className="text-xs font-medium text-muted-foreground">App sessions</h3>{status.apps.map(app => <div key={app.id} className="flex flex-col gap-2 rounded-lg border p-3"><div className="flex items-center gap-2"><AppWindowIcon aria-hidden="true" className="size-4 text-muted-foreground" /><span className="min-w-0 flex-1 truncate text-sm">{app.name}</span><span className="text-xs text-muted-foreground">{app.state}</span><Button type="button" size="icon-sm" variant="ghost" aria-label={`Open ${app.name} window`} disabled={app.state === "stopped" || busy} loading={pendingOperation === `open:${app.id}`} onClick={() => void perform(() => guestAppsApi.openWindow(environment.id, app.id), `open:${app.id}`)}><ExternalLinkIcon aria-hidden="true" /></Button><Button type="button" size="icon-sm" variant="ghost" aria-label={`Stop ${app.name}`} disabled={busy} loading={pendingOperation === `stop:${app.id}`} onClick={() => void perform(() => guestAppsApi.stop(environment.id, app.id), `stop:${app.id}`)}><SquareIcon aria-hidden="true" /></Button></div>{app.message ? <p className="max-h-24 overflow-auto whitespace-pre-wrap break-words text-xs text-muted-foreground">{app.message}</p> : null}</div>)}</section> : null}
      </DialogPanel>
      <DialogFooter><Button type="button" variant="ghost" onClick={() => setOpen(false)}>Close</Button></DialogFooter>
    </DialogPopup>
  </Dialog>
}
