import { useEffect, useRef, useState } from "react"
import { environmentDownloadApi, type EnvironmentDownload } from "@/api/environment-download-api"
import { workspaceApi } from "@/api/workspace-api"
import { usePlatform } from "@/context/platform-context"
import type { Environment } from "@/types/platform"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Address, Slot } from "@/components/popup-kit"

export function EnvironmentDownloadDialog({ environment, onClose }: { environment: Environment; onClose(): void }) {
  const { state, setEnvironmentStatus } = usePlatform()
  const [link, setLink] = useState<EnvironmentDownload | null>(null)
  const [domain, setDomain] = useState("")
  const [occupied, setOccupied] = useState(new Set<string>())
  const [loading, setLoading] = useState(true), [busy, setBusy] = useState(false), [error, setError] = useState("")
  const [reviewed, setReviewed] = useState(false), [copied, setCopied] = useState(false)
  const guard = useRef(false)
  const current = state?.environments.find(item => item.id === environment.id) ?? environment
  const supported = current.kind === "container" && ["yougoriOci", "yougoriCuda"].includes(current.provider ?? "")
    || current.provider === "qemu" && (current.kind === "fullVm" || current.kind === "microVm" && current.runtime === "builtin:alpine")
  const canStop = ["running", "paused"].includes(current.status)
  const domainInUse = Boolean(domain && occupied.has(domain))
  const unavailable = !supported ? "Complete-copy downloads support local containers, VMs and built-in Alpine microVMs."
    : current.status !== "stopped" && !canStop ? "Wait until this environment is ready, then stop it to create a copy." : ""
  const environmentIds = (state?.environments ?? []).map(item => item.id).join("\n")
  useEffect(() => {
    let active = true, timer: ReturnType<typeof setTimeout>
    let nextDiscovery = 0, serviceDomains = new Set<string>()
    const poll = async () => {
      try {
        const links = await environmentDownloadApi.list()
        if (active && !guard.current) setLink(links.find(item => item.environmentId === environment.id) ?? null)
        const busyDomains = new Set(links.filter(item => item.active && item.environmentId !== environment.id && item.domain).map(item => item.domain!))
        if (Date.now() >= nextDiscovery) {
          nextDiscovery = Date.now() + 60_000
          const discovered = new Set<string>(), ids = environmentIds.split("\n").filter(Boolean)
          for (let index = 0; index < ids.length; index += 8) {
            const services = await Promise.all(ids.slice(index, index + 8).map(id => workspaceApi.services(id).catch(() => null)))
            for (const service of services) for (const publication of service?.publications ?? []) {
              for (const url of publication.urls) { try { discovered.add(new URL(url).hostname) } catch { /* Not a domain URL. */ } }
            }
          }
          serviceDomains = discovered
        }
        for (const domain of serviceDomains) busyDomains.add(domain)
        if (active) setOccupied(busyDomains)
      } catch (reason) { if (active) setError(String(reason)) }
      finally { if (active) { setLoading(false); timer = setTimeout(() => void poll(), 3000) } }
    }
    void poll()
    return () => { active = false; clearTimeout(timer) }
  }, [environment.id, environmentIds])
  const change = async () => {
    if (guard.current || loading || !link?.active && (!reviewed || unavailable || domainInUse)) return
    guard.current = true; setBusy(true); setError(""); setCopied(false)
    try {
      if (link?.active) {
        await environmentDownloadApi.stop(environment.id)
        setLink({ ...link, active: false, url: null, domain: null, sizeBytes: 0 })
      } else {
        if (canStop) await setEnvironmentStatus(environment.id, "stopped")
        setLink(await environmentDownloadApi.start(environment.id, domain || undefined))
      }
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { guard.current = false; setBusy(false) }
  }
  return <Dialog open onOpenChange={open => { if (!open && !guard.current) onClose() }}>
    <DialogPopup closeProps={{ disabled: busy }} className="nodrag nopan" onPointerDown={event => event.stopPropagation()}>
      <DialogHeader><DialogTitle>Environment download link</DialogTitle><DialogDescription>A link anyone can use to download a complete copy of {environment.name} and run it as their own, independent environment.</DialogDescription></DialogHeader>
      <DialogPanel className="space-y-4">
        <p className="text-sm">The copy holds the environment’s disk, files, installed apps and settings.</p>
        <p className="text-xs text-muted-foreground">Shared PC folders, external disks, connection permissions and backup history stay with their owner. Files stored inside the environment are included, including databases and hidden files.</p>
        <div className="flex items-center justify-between gap-3"><p className="text-sm font-medium">Download link: {loading ? "Checking…" : link?.active ? "On" : "Off"}</p><Switch aria-label="Download link" checked={Boolean(link?.active)} disabled={busy || loading || !link?.active && (!reviewed || Boolean(unavailable) || domainInUse)} onCheckedChange={() => void change()} /></div>
        <p className="text-sm">Downloads (all time): {link?.downloads ?? 0}</p>
        <p className="text-xs text-muted-foreground">Counts completed downloads across all links. Repeated downloads count again.</p>
        {link?.active && link.url ? <div className="space-y-2">
          <Input aria-label="Download link" readOnly value={link.url} />
          <Button size="sm" variant="outline" onClick={() => { void terminalClipboard.writeText(link.url!).then(() => setCopied(true)).catch(reason => setError(String(reason))) }}>{copied ? "Copied" : "Copy link"}</Button>
          <p className="text-xs text-muted-foreground">Copy size: {(link.sizeBytes / 1_000_000_000).toFixed(2)} GB. Changes made after creating this copy are included when you create a new link.</p>
        </div> : <>
          <label className="block space-y-2 text-sm">Link address<select aria-label="Link address" className="h-9 w-full rounded-md border bg-background px-2" value={domain} disabled={busy || loading} onChange={event => setDomain(event.target.value)}>
            <option value="">Quick link, through Cloudflare</option>
            {(state?.savedDomains ?? []).map(item => <option key={item.id} value={item.hostname} disabled={occupied.has(item.id) || occupied.has(item.hostname)}>{item.hostname}{occupied.has(item.id) || occupied.has(item.hostname) ? " · In use" : ""}</option>)}
          </select></label>
          <p className="text-xs leading-relaxed text-muted-foreground">People download from <Address>{domain ? <>https://{domain}</> : <>https://<Slot>random-words</Slot>.trycloudflare.com</>}/<Slot>private token</Slot></Address>{domain ? ", your saved domain." : ". Cloudflare picks the words when the link turns on, and the token is new for every link."}</p>
          {!state?.savedDomains?.length && <p className="text-xs text-muted-foreground">Add a custom domain in Public access setups to use it here.</p>}
          <label className="flex items-start gap-2 text-sm"><input type="checkbox" className="mt-1" checked={reviewed} disabled={busy} onChange={event => setReviewed(event.target.checked)} />Anyone with this link can download every file and credential inside this environment.</label>
          {canStop && <p className="text-sm">Creating the copy stops this environment so databases and files remain consistent.</p>}
          {unavailable && <p role="status" className="text-sm text-muted-foreground">{unavailable}</p>}
        </>}
        <p className="text-xs text-muted-foreground">The link turns off when its owning app or CLI closes, or the computer turns off. Next time, create a new link. Download counts stay saved.</p>
        {busy && <p role="status" className="text-sm">{link?.active ? "Turning off the link…" : "Preparing and verifying the complete copy… Keep Yougori open."}</p>}
        {error && <p role="alert" className="text-sm text-destructive-foreground">{error}</p>}
      </DialogPanel>
      <DialogFooter><Button variant="ghost" disabled={busy} onClick={onClose}>Close</Button><Button disabled={busy || loading || !link?.active && (!reviewed || Boolean(unavailable) || domainInUse)} loading={busy} onClick={() => void change()}>{link?.active ? "Turn off download link" : canStop ? "Stop and create download link" : "Create download link"}</Button></DialogFooter>
    </DialogPopup>
  </Dialog>
}
