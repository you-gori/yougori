import { useState } from "react"
import { localBackupApi } from "@/api/local-backup-api"
import { Outcome } from "@/components/popup-kit"
import { Button } from "@/components/ui/button"
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter, DialogPopup, DialogTrigger } from "@/components/ui/dialog"
import { usePlatform } from "@/context/platform-context"
import type { Environment } from "@/types/platform"
import { CudaRuntimePanel } from "@/components/dialogs/cuda-runtime-panel"

export function LocalBackupDialog({ environment, triggerClassName, triggerDisabled, embedded = false, onClose, onBusyChange }: { embedded?: boolean; onClose?(): void; onBusyChange?(busy: boolean): void; environment?: Environment; triggerClassName?: string; triggerDisabled?: boolean }) {
  const { importLocalBackup } = usePlatform()
  const [open, setOpen] = useState(false)
  const [busy, setBusy] = useState(false)
  const [path, setPath] = useState("")
  const [error, setError] = useState("")
  const [saved, setSaved] = useState("")
  const [targetProvider, setTargetProvider] = useState<"yougoriCuda" | undefined>()
  const importing = !environment
  const supported = importing || (["yougoriOci", "yougoriCuda"].includes(environment.provider ?? "") && environment.kind === "container") || (environment.provider === "qemu" && (environment.kind === "fullVm" || (environment.kind === "microVm" && environment.runtime === "builtin:alpine")))
  const canExport = supported && (importing || environment.status === "stopped")
  const close = () => { setOpen(false); onClose?.() }
  const choose = async () => {
    onBusyChange?.(true); setBusy(true); setError("")
    try { const selected = await localBackupApi.choose(importing); if (selected) { setPath(selected); setSaved("") } }
    catch (reason) { setError(String(reason)) }
    finally { setBusy(false); onBusyChange?.(false) }
  }
  const submit = async () => {
    if (busy || !path || !canExport) return
    onBusyChange?.(true); setBusy(true); setError(""); setSaved("")
    try {
      if (environment) setSaved(await localBackupApi.export(environment.id, path))
      else { await importLocalBackup(path, targetProvider); close() }
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(false); onBusyChange?.(false) }
  }
  const content = <>
      {embedded ? <p className="px-6 pt-4 text-sm text-muted-foreground">Restore disk/files and settings into a new, stopped environment. Existing nodes are not overwritten.</p> : <DialogHeader><DialogTitle>{importing ? "Load a local backup" : `Back up ${environment.name}`}</DialogTitle><DialogDescription>{importing ? "Restore disk/files and settings into a new, stopped environment. Existing nodes are not overwritten." : "Save the environment’s disk/files and settings in a portable folder on your computer."}</DialogDescription></DialogHeader>}
      <DialogPanel className="flex flex-col gap-4">
        <p className="text-sm text-muted-foreground">{importing ? "Choose backup.yougori inside the backup folder, with disk.data beside it. Backups from earlier versions also work." : "Choose a folder. The backup is written there as one folder; keep it together."}</p>
        <p className="rounded-lg border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-sm">{importing ? "Only load backups you trust: they contain programs that will run." : "Backups are not encrypted. They may hold passwords or other private files from inside the environment."}</p>
        <Outcome title={importing ? "Not in the backup" : "Not included"}>
          <p>Shared PC folders, host credentials, public tunnels, terminal sessions, connection permissions, VM firmware settings and snapshot history. Reconnect access after restoring.</p>
        </Outcome>
        {importing ? <div className="space-y-2"><p className="text-sm font-medium">Restore engine</p><div className="flex gap-2" role="group" aria-label="Restore engine">
          <Button type="button" size="sm" variant={targetProvider ? "outline" : "secondary"} disabled={busy} aria-pressed={!targetProvider} onClick={() => setTargetProvider(undefined)}>Keep original</Button>
          <Button type="button" size="sm" variant={targetProvider ? "secondary" : "outline"} disabled={busy} aria-pressed={Boolean(targetProvider)} onClick={() => setTargetProvider("yougoriCuda")}>NVIDIA CUDA · containers</Button>
        </div>{targetProvider ? <><p className="text-xs text-muted-foreground">Copies a container backup into the GPU category (NVIDIA CUDA). The original and backup stay untouched. Enable GPU access in the new node's settings after restoring; other permissions remain disconnected. This does not convert VM disks, Windows apps or incompatible Linux libraries.</p><CudaRuntimePanel /></> : null}</div> : null}
        {!supported ? <p role="alert" className="text-sm">Portable backups for native branches and custom microVMs are not supported yet.</p> : !canExport ? <p role="alert" className="text-sm">Stop this environment before backing it up. This prevents an inconsistent disk copy.</p> : null}
        <Button disabled={busy || !canExport} onClick={() => void choose()} type="button" variant="outline">{importing ? "Choose backup file" : "Choose destination folder"}</Button>
        {path ? <p className="break-all text-xs text-muted-foreground">{path}</p> : null}
        {error ? <p role="alert" className="break-words text-sm text-destructive-foreground">{error}</p> : null}
        {saved ? <p role="status" className="break-all text-sm">Backup saved and verified: {saved}</p> : null}
        {busy ? <p role="status" className="text-sm text-muted-foreground">Working… Large disks can take several minutes. Keep Yougori open.</p> : null}
      </DialogPanel>
      <DialogFooter><Button disabled={busy} onClick={close} type="button" variant="ghost">{saved ? "Done" : "Cancel"}</Button><Button disabled={!path || !canExport || Boolean(saved)} loading={busy} onClick={() => void submit()} type="button">{importing ? "Restore as new environment" : "Create local backup"}</Button></DialogFooter>
    </>
  if (embedded) return content
  return <Dialog open={open} onOpenChange={value => { if (!busy) { setOpen(value); if (value) { setPath(""); setError(""); setSaved(""); setTargetProvider(undefined) } } }}>
    <DialogTrigger render={<Button data-tour={importing ? "load-backup" : undefined} className={triggerClassName} disabled={triggerDisabled} aria-label={importing ? "Load local backup" : "Back up to this PC"} title={importing ? "Load local backup" : "Back up to this PC"} size="sm" type="button" variant="outline" />}>
      <span>{importing ? "Load local backup" : "Back up to this PC"}</span>
    </DialogTrigger>
    <DialogPopup showCloseButton={!busy}>
      {content}
    </DialogPopup>
  </Dialog>
}
