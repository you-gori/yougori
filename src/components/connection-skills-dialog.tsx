import { useEffect, useRef, useState, type ReactNode } from "react"
import { CheckIcon, CopyIcon, RefreshCwIcon } from "lucide-react"
import { platformApi, type InstalledSkills } from "@/api/platform-api"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import { Button } from "@/components/ui/button"
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogPopup, DialogPanel, DialogFooter } from "@/components/ui/dialog"
import { usePlatform } from "@/context/platform-context"
import { nodeConnections } from "@/lib/environment-connections"
import { readSkillSnapshot, type SkillSnapshot } from "@/lib/connection-skills"
import { environmentKindLabel, statusLabel } from "@/lib/domain"

export function ConnectionSkillsDialog({ environmentId, remoteCanInstall = false, renderTrigger }: { environmentId: string; remoteCanInstall?: boolean; renderTrigger?(open: () => void): ReactNode }) {
  const [open, setOpen] = useState(false)
  const [text, setText] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [copying, setCopying] = useState(false)
  const [copied, setCopied] = useState(false)
  const [snapshot, setSnapshot] = useState<SkillSnapshot | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [installed, setInstalled] = useState<InstalledSkills | null>(null)
  const [installing, setInstalling] = useState(false)
  const [installError, setInstallError] = useState("")
  const installInFlight = useRef(false)
  const installSequence = useRef(0)
  const generation = useRef(0)
  const requestSequence = useRef(0)
  const copyingRef = useRef(false)
  const { state } = usePlatform()
  const environment = state?.environments.find(item => item.id === environmentId)
  const canInstall = environment?.status === "running" && (remoteCanInstall || ["container", "microVm", "fullVm"].includes(environment.kind))
  useEffect(() => {
    setInstalled(null); setInstallError(""); setInstalling(false); installInFlight.current = false
    const sequence = installSequence
    ++sequence.current
    return () => { ++sequence.current }
  }, [environmentId])
  const install = async () => {
    if (installInFlight.current) return
    installInFlight.current = true
    const request = ++installSequence.current
    setInstalling(true); setInstallError("")
    try {
      const result = await platformApi.installEnvironmentSkills(environmentId)
      if (request === installSequence.current) setInstalled(result)
    } catch (reason) {
      if (request === installSequence.current) setInstallError(`Skills installation was not confirmed: ${String(reason)}`)
    } finally {
      if (request === installSequence.current) { installInFlight.current = false; setInstalling(false) }
    }
  }
  const connections = nodeConnections(environmentId, state?.connections ?? [])
  const ids = new Set([environmentId, ...connections.flatMap(c => [c.sourceId, c.targetId])])
  // Host metrics update frequently; only access/state changes need a new skill.
  const revision = JSON.stringify([connections, state?.environments.filter(e => ids.has(e.id)).map(e => [e.id, e.name, e.kind, e.status, e.runtime, e.runtimeId])])
  useEffect(() => {
    if (!open) return
    const current = ++generation.current
    let inFlight = false
    setCopied(false); setCopying(false); copyingRef.current = false
    const load = async () => {
      if (inFlight || copyingRef.current) return
      const request = ++requestSequence.current
      inFlight = true; setLoading(true); setError("")
      try {
        const value = await platformApi.connectionSkills(environmentId)
        if (current !== generation.current || request !== requestSequence.current) return
        const data = readSkillSnapshot(value)
        setText(value); setSnapshot(data); setCopied(false)
      } catch (reason) { if (current === generation.current && request === requestSequence.current) setError(`Could not refresh Skills. The displayed snapshot may be out of date: ${String(reason)}`) }
      finally { inFlight = false; if (current === generation.current) setLoading(false) }
    }
    void load()
    const timer = window.setInterval(() => void load(), 10000)
    return () => { generation.current = current + 1; window.clearInterval(timer) }
  }, [open, environmentId, revision, refresh])
  const copy = async () => {
    if (copyingRef.current || loading) return
    const current = generation.current
    const request = ++requestSequence.current
    copyingRef.current = true; setCopying(true); setCopied(false); setError("")
    try {
      // Fetch again: a peer/share may have changed since this dialog opened.
      const fresh = await platformApi.connectionSkills(environmentId)
      if (current !== generation.current || request !== requestSequence.current) return
      const data = readSkillSnapshot(fresh)
      setText(fresh); setSnapshot(data)
      await terminalClipboard.writeText(fresh)
      if (current === generation.current) setCopied(true)
    }
    catch (reason) { if (current === generation.current) setError(`Could not refresh or copy Skills. No cached instructions were copied. ${String(reason)}`) }
    finally { if (current === generation.current) { copyingRef.current = false; setCopying(false) } }
  }
  const openSkills = () => { setOpen(true); if (canInstall && !installed) void install() }
  return <>
    {renderTrigger ? renderTrigger(openSkills) : <Button aria-label="Connection skills" title="Install environment instructions for your AI agent" size="sm" variant="ghost" onClick={openSkills} className="text-xs text-muted-foreground">Skills</Button>}
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogPopup className="max-w-5xl sm:max-w-5xl">
        <DialogHeader><DialogTitle>Connection skills</DialogTitle><DialogDescription>Every directly connected node, its access rules and what to do when it cannot be reached. My PC shares are included when attached.</DialogDescription></DialogHeader>
        <DialogPanel>
          <section aria-label="Installed skill files" className="mb-4 rounded-md border p-3 text-xs">
            {installing ? <p role="status">Installing Skills inside this environment…</p> : null}
            {installed ? <>
              <p className="mb-2">{installed.message}</p>
              <label className="block font-medium">{installed.delivery === "drive" ? "Skill location on guest drive" : "Skill path inside environment"}<input aria-label="Installed skill path" className="mt-1 w-full rounded border bg-muted/30 p-2 font-mono text-xs" readOnly value={installed.skillPath} onFocus={event => event.currentTarget.select()} /></label>
              <label className="mt-2 block font-medium">Connection reference<input aria-label="Installed connection reference path" className="mt-1 w-full rounded border bg-muted/30 p-2 font-mono text-xs" readOnly value={installed.referencePath} onFocus={event => event.currentTarget.select()} /></label>
              <p className="mt-2 text-muted-foreground">After changing access, generate a new bundle. Previous copies remain snapshots.</p>
            </> : !installing ? <p>{canInstall ? "Generate a concise skill and connection reference inside this environment." : environment?.kind === "cloud" ? "Copy the connection instructions for this cloud environment below." : "Start this environment to install Skills. Instructions are still available below."}</p> : null}
            {installError ? <p role="alert" className="mt-2 text-destructive-foreground">{installError}</p> : null}
            {canInstall ? <Button className="mt-2" size="xs" variant="outline" disabled={installing} onClick={() => void install()}>{installed ? "Generate updated skill files" : "Install skill files"}</Button> : null}
          </section>
          {snapshot ? <>
            <div className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-muted-foreground">
              <span>{snapshot.summary.connectedNodes} connected {snapshot.summary.connectedNodes === 1 ? "node" : "nodes"}</span>
              <span>{snapshot.summary.connections} links · {snapshot.summary.ready} ready · {snapshot.summary.blocked} unavailable</span>
              <span className="ml-auto">This node: {statusLabel[snapshot.sourceStatus]}</span>
            </div>
            <ul aria-label="Connected nodes" className="mb-3 max-h-52 overflow-y-auto divide-y border-y">
              {snapshot.connections.map(peer => <li key={peer.connectionId} className="py-2.5 text-xs">
                <div className="flex flex-wrap items-center gap-2"><span className="font-semibold">{peer.peerName}</span><span className="text-muted-foreground">{peer.peerKind ? environmentKindLabel[peer.peerKind] : "Missing node"} · {peer.peerStatus === "missing" ? "Missing" : statusLabel[peer.peerStatus]}</span><span className={peer.usableNow ? "ml-auto text-success-foreground" : "ml-auto text-destructive-foreground"}>{peer.usableNow ? "Connection ready" : "Unavailable"}</span></div>
                <p className="mt-1 text-muted-foreground">{peer.permissions.join(", ") || "No permissions"} · {peer.direction === "oneWay" ? "One-way" : "Both directions"}</p>
                {peer.remoteControl ? <p className="mt-1">{peer.remoteControl.method} · TCP {peer.remoteControl.port} · {peer.remoteControl.canConnect ? "Authenticate from this environment to run commands, manage processes and edit files." : "Remote control is unavailable from this side."} {peer.remoteControl.scope}.</p> : null}
                {peer.issues.length ? peer.issues.map(item => <p key={`${item.code}-${item.nodeId ?? ""}`} className="mt-1 leading-relaxed"><span className="font-medium">{item.side === "source" ? "This node: " : item.side === "peer" ? "Connected node: " : ""}{item.explanation}</span> <span className="text-muted-foreground">{item.nextStep}</span></p>) : <p className="mt-1 text-muted-foreground">{peer.summary}</p>}
                {peer.limitations?.map(limit => <p key={limit} className="mt-1 text-muted-foreground">{limit}</p>)}
              </li>)}
            </ul>
          </> : null}
          <div className="mb-2 flex items-center justify-between gap-2"><span className="text-xs text-muted-foreground">Full AI instructions · status, files, My PC and error guide</span><Button aria-label="Refresh skills" size="xs" variant="ghost" loading={loading} disabled={copying} onClick={() => setRefresh(value => value + 1)}><RefreshCwIcon aria-hidden="true" />Refresh</Button></div>
          {loading && !text ? <p role="status" className="text-sm text-muted-foreground">Reading current connections…</p> : <textarea aria-label="AI agent connection instructions" readOnly value={text} className="h-[min(32vh,20rem)] w-full resize-none rounded-md border bg-muted/30 p-3 font-mono text-xs leading-relaxed outline-none focus-visible:ring-2 focus-visible:ring-ring" />}
          {error ? <p role="alert" className="mt-2 text-sm text-destructive-foreground">{error}</p> : null}
        </DialogPanel>
        <DialogFooter><p className="mr-auto text-xs text-muted-foreground">Copy refreshes the snapshot. Folder paths are included; contents and private tokens are not. No access is granted by copying.</p><Button disabled={!text || loading} loading={copying} onClick={() => void copy()}>{copied ? <CheckIcon aria-hidden="true" /> : <CopyIcon aria-hidden="true" />}{copied ? "Copied" : "Copy skills"}</Button></DialogFooter>
      </DialogPopup>
    </Dialog>
  </>
}
