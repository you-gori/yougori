import type { ReactNode } from "react"
import { useEffect, useState } from "react"
import type { Environment } from "@/types/platform"
import { usePlatform } from "@/context/platform-context"
import { cloudApi, type CloudProfile } from "@/api/cloud-api"
import { Button } from "@/components/ui/button"
import { Dialog, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter } from "@/components/ui/dialog"
import { AlertDialog, AlertDialogPopup, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter } from "@/components/ui/alert-dialog"
import { environmentActionLabel } from "@/lib/environment-actions"
import { NeocloudDeploymentCard } from "@/components/neocloud-deployment-card"
import { NeocloudNodeCard } from "@/components/neocloud-node-card"
import { runpodExtra } from "@/api/runpod-api"

export function CloudEnvironmentDetails({ environment, onOpenChange, onOpenEnvironment, setupActions }: { environment: Environment; onOpenChange(open: boolean): void; onOpenEnvironment(id: string): void; setupActions?: ReactNode }) {
  const { state, environmentActions, setEnvironmentStatus, deleteEnvironment, setConnectionActive, deleteConnection } = usePlatform()
  const [profile, setProfile] = useState<CloudProfile | null>(null)
  const [error, setError] = useState("")
  const [remove, setRemove] = useState(false)
  const [working, setWorking] = useState(false)
  const neocloud = state?.neocloudDeployments?.[environment.id]
  const serverless = neocloud?.product === "serverless"
  const runpod = neocloud?.provider === "runpod"
  const podReady = runpod && runpodExtra(neocloud).sshReady === true
  useEffect(() => { let alive = true; void cloudApi.details(environment.id).then(d => { if (alive) setProfile(d.profile) }).catch(e => { if (alive && !neocloud) setError(String(e)) }); return () => { alive = false } }, [environment.id, environment.runtime, neocloud])
  const action = environmentActions[environment.id], busy = working || Boolean(action), connected = environment.status === "running"
  const links = state?.connections.filter(c => c.sourceId === environment.id || c.targetId === environment.id) ?? []
  const perform = async (operation: () => Promise<unknown>) => { if (busy) return; setWorking(true); setError(""); try { await operation() } catch (e) { setError(String(e instanceof Error ? e.message : e)) } finally { setWorking(false) } }
  return <>
    <Dialog open onOpenChange={open => { if (!busy) onOpenChange(open) }}><DialogPopup bottomStickOnMobile={false} className="environment-inspector inspector-cloud" closeProps={{ disabled: busy }}>
      <DialogHeader className="inspector-header"><DialogTitle className="text-base">{environment.name}</DialogTitle><DialogDescription>{runpod ? (serverless ? "Neocloud endpoint" : `Neocloud pod · ${connected ? "Connected" : podReady ? "Ready to open" : "Starting"}`) : <>{neocloud ? `Neocloud · ${neocloud.state}` : "Cloud environment"}{serverless ? " · Model API" : ` · ${connected ? "Connected" : "Disconnected"}`}</>}</DialogDescription></DialogHeader>
      <DialogPanel className="inspector-cloud-page">
        {runpod ? <NeocloudNodeCard environmentId={environment.id} /> : neocloud ? <NeocloudDeploymentCard environmentId={environment.id} /> : null}
        {!serverless && (!runpod || podReady) ? <section className="space-y-2"><h3 className="text-sm font-medium">SSH connection</h3><p className="break-all text-sm">{environment.runtime}</p><p className="break-all text-xs text-muted-foreground">{profile?.identityFile}</p><p className="text-xs text-muted-foreground">Disconnect closes SSH and these terminals. Your server and its independently running applications stay on.</p></section> : null}
        {environment.lastError || error ? <p tabIndex={0} role="alert" className="max-h-32 min-w-0 max-w-full overflow-y-auto overscroll-contain whitespace-pre-wrap [overflow-wrap:anywhere] text-sm text-destructive">{error || environment.lastError}</p> : null}
        {connected && !serverless ? <section className="space-y-2"><h3 className="text-sm font-medium">Files from connected nodes</h3><p className="text-xs leading-relaxed text-muted-foreground">Cloud terminals open in your usual home folder. To access folders shared by connected nodes, run <code>cd ~/Yougori/shared</code> and <code>ls</code>, then open the folder named for the node. The Shared files tab also lets you browse and edit them.</p></section> : null}
        {!serverless ? <section className="space-y-3"><h3 className="text-sm font-medium">Connected nodes</h3>{links.length ? links.map(c => { const peer = state?.environments.find(e => e.id === (c.sourceId === environment.id ? c.targetId : c.sourceId)); return <div key={c.id} className="rounded-md border p-3 text-xs space-y-2"><p className="font-medium">{peer?.name ?? "Removed node"} · {c.direction === "bidirectional" ? "Both directions" : "One way"}</p><p className="text-muted-foreground">{c.permissions.join(", ")}{c.ports.length ? ` · TCP ${c.ports.join(", ")}` : ""} · {c.active ? c.enforcementStatus : "Disabled"}</p>{c.selectedFolders?.map(folder => <p key={`${folder.environmentId}:${folder.path}`} className="break-all text-muted-foreground">Shared folder: {state?.environments.find(item => item.id === folder.environmentId)?.name ?? "Environment"} · <code>{folder.path}</code></p>)}{c.lastError ? <p tabIndex={0} className="max-h-32 min-w-0 max-w-full overflow-y-auto overscroll-contain whitespace-pre-wrap [overflow-wrap:anywhere] text-destructive">{c.lastError}</p> : null}<div className="flex gap-2"><Button size="xs" variant="outline" disabled={busy} onClick={() => void perform(() => setConnectionActive(c.id, !c.active))}>{c.active ? "Disconnect link" : "Reconnect link"}</Button><Button size="xs" variant="ghost" disabled={busy} onClick={() => void perform(() => deleteConnection(c.id))}>Remove link</Button></div></div> }) : <p className="text-xs text-muted-foreground">Use the node's left or right connection point to connect a local node.</p>}</section> : null}
        <p className="border-t pt-4 text-xs text-muted-foreground">Local network and Public access are blocked. {runpod ? "The pod or endpoint is controlled above. Delete it there before removing this node." : neocloud ? "Provider compute is controlled above. Delete the provider resource before removing this node." : "Resources, snapshots and power are managed outside Yougori. Removing this node never deletes the remote server or its files."}</p>
      {setupActions}</DialogPanel>
      <DialogFooter className="inspector-cloud-footer"><Button variant="ghost" disabled={busy || Boolean(neocloud && neocloud.state !== "Deleted")} onClick={() => setRemove(true)}>Remove node</Button>{connected && !serverless ? <Button variant="outline" disabled={busy} loading={action === "disconnecting"} onClick={() => void perform(() => setEnvironmentStatus(environment.id, "stopped"))}>Disconnect</Button> : null}{!serverless ? <Button disabled={busy || Boolean(neocloud && !profile) || (runpod && !podReady && !connected)} loading={action === "connecting" || action === "opening"} onClick={() => onOpenEnvironment(environment.id)}>{action ? environmentActionLabel[action] : connected ? "Open" : "Connect"}</Button> : null}</DialogFooter>
    </DialogPopup></Dialog>
    <AlertDialog open={remove} onOpenChange={value => { if (!busy) setRemove(value) }}><AlertDialogPopup><AlertDialogHeader><AlertDialogTitle>Remove cloud node?</AlertDialogTitle><AlertDialogDescription>{neocloud ? "The provider resource has been deleted. This removes its remaining Yougori node and connections." : "This removes its Yougori connections only. The remote server and its data are not deleted."}</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><Button variant="outline" disabled={busy} onClick={() => setRemove(false)}>Cancel</Button><Button variant="destructive" loading={action === "deleting"} disabled={busy} onClick={() => { if (busy) return; setRemove(false); onOpenChange(false); void deleteEnvironment(environment.id).catch(() => undefined) }}>Remove node</Button></AlertDialogFooter></AlertDialogPopup></AlertDialog>
  </>
}
