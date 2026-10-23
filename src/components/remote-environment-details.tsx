import { useEffect, useState } from "react"
import type { Environment } from "@/types/platform"
import { remoteAccessApi, type RemoteCapabilities } from "@/api/remote-access-api"
import { usePlatform } from "@/context/platform-context"
import { SharingPanel } from "@/components/sharing-panel"
import { Button } from "@/components/ui/button"
import { Dialog, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter } from "@/components/ui/dialog"
import { AlertDialog, AlertDialogPopup, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter } from "@/components/ui/alert-dialog"

export function RemoteEnvironmentDetails({ environment, onOpenChange, onOpenEnvironment }: { environment: Environment; onOpenChange(open: boolean): void; onOpenEnvironment(id: string): void }) {
  const { deleteEnvironment, refreshPlatform } = usePlatform()
  const [capabilities, setCapabilities] = useState<RemoteCapabilities | null>(null), [error, setError] = useState(""), [confirm, setConfirm] = useState(false), [reconnecting, setReconnecting] = useState(false)
  const [connectionVersion, setConnectionVersion] = useState(0)
  useEffect(() => { setCapabilities(null); setError(""); let alive = true; void remoteAccessApi.inspect(environment.id).then(value => { if (alive) setCapabilities(value) }).catch(e => { if (alive) setError(String(e)) }); return () => { alive = false } }, [environment.id, environment.runtime, connectionVersion])
  const reconnect = async () => {
    if (reconnecting) return
    setReconnecting(true); setError("")
    try { await remoteAccessApi.reconnect(environment.id); await refreshPlatform(); setConnectionVersion(value => value + 1) }
    catch (e) { setError(String(e)) }
    finally { setReconnecting(false) }
  }
  return <><Dialog open onOpenChange={onOpenChange}><DialogPopup><DialogHeader><DialogTitle>{environment.name}</DialogTitle><DialogDescription>Shared with you from the owner's computer · {environment.status}</DialogDescription></DialogHeader><DialogPanel className="space-y-4 text-sm">
    <p>Workloads and files stay on the owner's computer. Access follows their current sharing permissions.</p>
    {capabilities ? <ul className="space-y-1 text-xs text-muted-foreground">{[["Files", capabilities.files], ["Edit files", capabilities.files && capabilities.permission !== "view"], ["Terminal & commands", capabilities.commands], ["Desktop control", capabilities.desktop], ["Start, stop & restart", capabilities.power]].map(([label, enabled]) => <li key={String(label)} className="flex justify-between"><span>{label}</span><span>{enabled ? "Allowed" : "Unavailable"}</span></li>)}</ul> : null}
    {error ? <p tabIndex={0} role="alert" className="max-h-32 min-w-0 max-w-full overflow-y-auto overscroll-contain whitespace-pre-wrap [overflow-wrap:anywhere] text-xs text-destructive-foreground">{error}</p> : null}<div className="flex flex-wrap gap-2"><Button variant="outline" loading={reconnecting} disabled={reconnecting} onClick={() => void reconnect()}>Reconnect</Button><SharingPanel reconnectEnvironmentId={environment.id} onConnected={() => { setError(""); setConnectionVersion(value => value + 1) }} /></div>
    <p className="text-xs text-muted-foreground">Reconnect uses the saved link and recipient credentials. If either changed, use Connect to Shared Environment to update them. The owner manages resources and permissions. Removing this entry never stops or deletes the original target.</p>
  </DialogPanel><DialogFooter><Button variant="ghost" onClick={() => setConfirm(true)}>Remove remote entry</Button><Button onClick={() => onOpenEnvironment(environment.id)}>Open</Button></DialogFooter></DialogPopup></Dialog>
    <AlertDialog open={confirm} onOpenChange={setConfirm}><AlertDialogPopup><AlertDialogHeader><AlertDialogTitle>Remove this remote entry</AlertDialogTitle><AlertDialogDescription>Only your saved session on this computer is removed. The owner's environment keeps running, and you can connect again with their link and your credentials.</AlertDialogDescription></AlertDialogHeader><AlertDialogFooter><Button variant="outline" onClick={() => setConfirm(false)}>Cancel</Button><Button variant="destructive" onClick={() => { setConfirm(false); onOpenChange(false); void deleteEnvironment(environment.id).catch(() => undefined) }}>Remove entry</Button></AlertDialogFooter></AlertDialogPopup></AlertDialog>
  </>
}
