import { RemoteEnvironmentDetails } from "@/components/remote-environment-details"
import { EnvironmentChanges } from "@/components/environment-changes"
import { ModelWorkspace } from "@/components/model-workspace"
import { ArrowDownLeftIcon, ArrowLeftRightIcon, ArrowUpRightIcon, ArchiveIcon, BoxIcon, CircleAlertIcon, ExternalLinkIcon, HistoryIcon, Link2Icon, MoreHorizontalIcon, PlayIcon, PlusIcon, SlidersHorizontalIcon } from "lucide-react"
import { useEffect, useMemo, useRef, useState } from "react"
import {
  AlertDialog,
  AlertDialogClose,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogPopup,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog"
import { Button } from "@/components/ui/button"
import {
  Menu,
  MenuItem,
  MenuPopup,
  MenuSeparator,
  MenuTrigger,
} from "@/components/ui/menu"
import {
  Dialog,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogPanel,
  DialogPopup,
  DialogTitle,
} from "@/components/ui/dialog"
import { ConfigurationHelp } from "@/components/configuration-help"
import { usePlatform } from "@/context/platform-context"
import { formatBytesFromGb, formatDateTime, permissionLabel } from "@/lib/domain"
import { environmentLabel } from "@/lib/environment-category"
import { environmentActionLabel } from "@/lib/environment-actions"
import { ResourcePolicyEditor } from "@/components/resource-policy-editor"
import { GuestAppLauncher } from "@/components/guest-app-launcher"
import { SnapshotDialog } from "@/components/dialogs/snapshot-dialog"
import { Status } from "@/components/shared/status"
import { LocalBackupDialog } from "@/components/dialogs/local-backup-dialog"
import { FactoryResetDialog } from "@/components/dialogs/factory-reset-dialog"
import { CudaVerification } from "@/components/cuda-verification"
import { CudaUpdateAction } from "@/components/cuda-update-action"
import "./environment-detail-sheet.css"
import { PauseIcon, XIcon } from "lucide-react"
import { CloudEnvironmentDetails } from "@/components/cloud-environment-details"
import { ImportedFilesDrives } from "@/components/imported-files-drives"
import { ContainerStartupCommand } from "@/components/container-startup-command"

export function EnvironmentDetailSheet({ environmentId, onOpenChange, onOpenEnvironment }: {
  environmentId: string | null
  onOpenChange(open: boolean): void
  onOpenEnvironment(environmentId: string): void
}) {
  const { state, environmentActions, setEnvironmentStatus, deleteEnvironment, deleteSnapshot, restoreSnapshot, setConnectionActive, deleteConnection, updateEnvironmentGpu } = usePlatform()
  const environment = state?.environments.find((item) => item.id === environmentId)
  const snapshots = useMemo(() => state?.snapshots.filter((item) => item.environmentId === environmentId) ?? [], [environmentId, state?.snapshots])
  const connections = useMemo(() => state?.connections.filter((item) => item.sourceId === environmentId || item.targetId === environmentId) ?? [], [environmentId, state?.connections])
  const [deleteOpen, setDeleteOpen] = useState(false)
  const resourcesRef = useRef<HTMLElement>(null)
  const [deletingIds, setDeletingIds] = useState<Set<string>>(() => new Set())
  const deleting = Boolean(environmentId && deletingIds.has(environmentId))
  const [startupDraft, setStartupDraft] = useState<string | null>(null)
  const [deleteErrors, setDeleteErrors] = useState<Record<string, string>>({})
  const deleteError = environmentId ? deleteErrors[environmentId] ?? "" : ""
  const deleteLock = useRef(new Set<string>())
  const [localAction, setLocalAction] = useState<string | null>(null)
  const [openingFromHere, setOpeningFromHere] = useState(false)
  const [policySaveTarget, setPolicySaveTarget] = useState<HTMLDivElement | null>(null)
  const [snapshotAction, setSnapshotAction] = useState<string | null>(null)
  const actionLock = useRef(false)
  const [actionError, setActionError] = useState("")
  const action = environmentId ? environmentActions[environmentId] : undefined
  useEffect(() => { if (!action) setOpeningFromHere(false) }, [action])
  useEffect(() => { setActionError(""); setDeleteOpen(false); setOpeningFromHere(false); setStartupDraft(null) }, [environmentId])

  if (!state || !environment) return null
  if (environment.runtime.startsWith("shared://tunnel/")) return <RemoteEnvironmentDetails key={environment.id} environment={environment} onOpenChange={onOpenChange} onOpenEnvironment={onOpenEnvironment} />
  if (environment.kind === "cloud") return <CloudEnvironmentDetails key={environment.id} environment={environment} onOpenChange={onOpenChange} onOpenEnvironment={onOpenEnvironment} />
  const isComputerBranch = environment.kind === "computerBranch" || environment.provider === "nativeSandbox"
  const busy = Boolean(localAction) || Boolean(action) || deleting || environment.status === "provisioning"
  const activeConnections = connections.filter(connection => connection.active).length
  const perform = async (operation: () => Promise<unknown>, label = "Updating environment…", snapshotId?: string) => {
    if (busy || actionLock.current) return
    actionLock.current = true
    setLocalAction(label); setSnapshotAction(snapshotId ?? null); setActionError("")
    try { await operation() }
    catch (reason) { setActionError(reason instanceof Error ? reason.message : String(reason)) }
    finally { actionLock.current = false; setLocalAction(null); setSnapshotAction(null) }
  }

  const openDelete = () => setDeleteOpen(true)
  const remove = async (recoverRuntime = false) => {
    if (deleteLock.current.has(environment.id) || busy) return
    deleteLock.current.add(environment.id)
    setDeletingIds(current => new Set(current).add(environment.id))
    setDeleteErrors(current => { const next = { ...current }; delete next[environment.id]; return next })
    setDeleteOpen(false)
    onOpenChange(false)
    try {
      await deleteEnvironment(environment.id, recoverRuntime)
    } catch (reason) {
      setDeleteErrors(current => ({ ...current, [environment.id]: reason instanceof Error ? reason.message : String(reason) }))
    } finally {
      deleteLock.current.delete(environment.id)
      setDeletingIds(current => { const next = new Set(current); next.delete(environment.id); return next })
    }
  }

  return (
    <Dialog onOpenChange={open => { if (!open) setStartupDraft(null); onOpenChange(open) }} open={Boolean(environmentId)}>
      <DialogPopup className="environment-inspector" bottomStickOnMobile={false}>
        <DialogHeader className="inspector-header">
          <div className="inspector-eyebrow"><span><SlidersHorizontalIcon aria-hidden="true" />Configuration</span><Status compact status={environment.status} /></div>
          <DialogTitle className="inspector-title text-base leading-6" title={environment.name}>{environment.name}</DialogTitle>
          <DialogDescription className="sr-only">Settings, resource allocation and restore points for this {environmentLabel(environment).toLowerCase()}.</DialogDescription>
        </DialogHeader>
        <DialogPanel scrollFade={false} className="inspector-page">
          <div className="inspector-column inspector-overview" key={`overview:${environment.id}`}>
              {environment.status === "error" ? <section className="inspector-attention" aria-label="Environment needs attention">
                <p className="inspector-section-title"><CircleAlertIcon aria-hidden="true" />This environment needs attention</p>
                <p tabIndex={0} aria-label="Environment error details" className="max-h-32 min-w-0 max-w-full overflow-y-auto overscroll-contain whitespace-pre-wrap [overflow-wrap:anywhere] text-xs text-muted-foreground">{environment.lastError || "The last operation failed. Retry Start, or use Stop to check for a leftover runtime."}</p>
                <div className="flex flex-wrap gap-2">
                  <Button disabled={busy} loading={action === "starting"} onClick={() => void perform(() => setEnvironmentStatus(environment.id, "running"))} size="sm" type="button">Retry Start</Button>
                  <Button disabled={busy} loading={action === "stopping"} onClick={() => void perform(() => setEnvironmentStatus(environment.id, "stopped"))} size="sm" type="button" variant="outline">Stop</Button>
                  {environment.lastError && /memory|pc\.ram/i.test(environment.lastError) ? <Button onClick={() => { resourcesRef.current?.scrollIntoView({ block: "nearest" }); resourcesRef.current?.focus({ preventScroll: true }) }} size="sm" type="button" variant="outline">Adjust memory</Button> : null}
                </div>
              </section> : null}
              <section aria-label="Environment information" className="inspector-section">
                <div className="flex flex-wrap gap-2"><EnvironmentChanges environmentId={environment.id} />{environment.description.startsWith("Hugging Face · ") ? <ModelWorkspace environmentId={environment.id} /> : null}</div>
                <h3 className="inspector-section-title"><BoxIcon aria-hidden="true" />Environment</h3>
                {environment.description ? <p className="inspector-description">{environment.description}</p> : null}
                <dl className="inspector-properties"><div><dt>Environment</dt><dd>{environmentLabel(environment)}</dd></div><div><dt>Isolation</dt><dd>{environment.provider === "yougoriCuda" ? "Container · shared WSL kernel" : environmentLabel(environment)}</dd></div>{environment.storageDrive ? <div><dt>Storage drive</dt><dd>{environment.storageDrive}</dd></div> : null}<div><dt>Image / runtime</dt><dd className="inspector-runtime" title={environment.runtime}>{environment.runtime}</dd></div></dl>
              </section>
              {environment.kind === "container" ? <ContainerStartupCommand key={`startup:${environment.id}`} environment={environment} draft={startupDraft} disabled={busy} onDraftChange={setStartupDraft} /> : null}
              {environment.kind === "microVm" && environment.runtime === "builtin:alpine" ? <GuestAppLauncher environment={environment} /> : null}
              {environment.kind === "fullVm" ? <ImportedFilesDrives key={`imported:${environment.id}`} environment={environment} /> : null}
              {!isComputerBranch ? <CudaVerification key={`${environment.id}:${environment.status}:${environment.gpuAccess}`} environment={environment} disabled={busy} onEnableGpu={() => updateEnvironmentGpu(environment.id, true)} /> : null}
          </div>
          <section className="inspector-column inspector-resources" aria-label="Resource allocation" tabIndex={-1} ref={resourcesRef}>
            <ResourcePolicyEditor key={environment.id} environment={environment} saveTarget={policySaveTarget} startupDraft={environment.kind === "container" ? startupDraft : null} onStartupSaved={() => setStartupDraft(null)} />
          </section>
          <div className="inspector-column inspector-access">
              <section className="inspector-section" aria-label="Local backups">
                <div className="inspector-section-heading"><h3 className="inspector-section-title"><ArchiveIcon aria-hidden="true" />Local backups</h3><ConfigurationHelp label="Local backup help">Save a portable copy to your PC, or load a backup as a new environment.</ConfigurationHelp></div>
                <div className="inspector-backup-actions"><LocalBackupDialog environment={environment} /><LocalBackupDialog /></div>
              </section>
              <section className="inspector-section" aria-label="Environment connections">
                <div className="inspector-section-heading"><h3 className="inspector-section-title"><Link2Icon aria-hidden="true" />{environment.provider === "nativeSandbox" ? "Allowed access" : "Connections"}</h3><span>{environment.provider === "nativeSandbox" ? `${environment.sandboxPolicy?.shares.length ?? 0} shared folders` : `${activeConnections} active · ${connections.length} total`}</span></div>
                {environment.provider === "nativeSandbox" ? (
                  <div className="divide-y border-y">
                    <div className="flex items-center justify-between gap-4 py-3 text-sm"><span>Network</span><span className="text-xs text-muted-foreground">{environment.sandboxPolicy?.networkAccess ? "Allowed" : "Blocked"}</span></div>
                    {environment.sandboxPolicy?.shares.map((share) => <div className="flex items-center justify-between gap-4 py-3" key={share.path}><span className="min-w-0 truncate text-sm" title={share.path}>{share.path}</span><span className="shrink-0 text-xs text-muted-foreground">{share.access === "readWrite" ? "Read & write" : "Read only"}</span></div>)}
                    {!environment.sandboxPolicy?.shares.length ? <p className="py-5 text-center text-sm text-muted-foreground">No host folders shared.</p> : null}
                  </div>
                ) : connections.length ? connections.map((connection) => {
                  const outgoing = connection.sourceId === environment.id
                  const otherId = outgoing ? connection.targetId : connection.sourceId
                  const other = state.environments.find((item) => item.id === otherId)
                  return (
                    <div className="inspector-connection" key={connection.id}>
                      {connection.direction === "bidirectional" ? <ArrowLeftRightIcon aria-hidden="true" /> : outgoing ? <ArrowUpRightIcon aria-hidden="true" /> : <ArrowDownLeftIcon aria-hidden="true" />}
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm" title={other?.name}>{connection.direction === "bidirectional" ? "With" : outgoing ? "To" : "From"} {other?.name ?? "Unknown environment"}</p>
                        <p className="inspector-description">{connection.permissions.map((permission) => permissionLabel[permission]).join(" · ")}</p>
                        {connection.active && connection.selectedFolders?.map((folder, index) => {
                          const owner = state.environments.find(item => item.id === folder.environmentId)
                          const mount = folder.environmentId === environment.id ? folder.path : environment.kind === "container" || (environment.kind === "microVm" && environment.runtime === "builtin:alpine") ? `/yougori/shared/${connection.id}-selected-${index}` : null
                          return <p className="mt-1 min-w-0 text-xs" key={`${folder.environmentId}:${folder.path}`}><span className="text-muted-foreground">{owner?.name ?? "Peer"} · {folder.path}</span><br /><code className="break-all">{mount ?? "Open Selected folders in this environment's private file browser"}</code></p>
                        })}
                        {connection.active && connection.lastError ? <p tabIndex={0} className="max-h-32 min-w-0 max-w-full overflow-y-auto overscroll-contain whitespace-pre-wrap [overflow-wrap:anywhere] mt-1 text-xs text-destructive-foreground">{connection.lastError}</p> : null}
                      </div>
                      <span className="text-xs text-muted-foreground">{!connection.active ? "Disconnected" : connection.enforcementStatus === "error" ? "Needs attention" : connection.enforcementStatus === "pending" ? "Pending" : "Active"}</span>
                      {connection.active && connection.enforcementStatus === "error" ? <Button size="xs" variant="ghost" disabled={busy} onClick={() => void perform(() => setConnectionActive(connection.id, true), "Retrying connection…")}>Retry</Button> : null}
                      <Button size="icon-xs" variant="ghost" disabled={busy} loading={localAction === `${connection.active ? "Disconnecting from" : "Reconnecting to"} ${other?.name ?? "environment"}…`} aria-label={`${connection.active ? "Disconnect from" : "Reconnect to"} ${other?.name ?? "environment"}`} title={connection.active ? "Disconnect" : "Reconnect"} onClick={() => void perform(() => setConnectionActive(connection.id, !connection.active), `${connection.active ? "Disconnecting from" : "Reconnecting to"} ${other?.name ?? "environment"}…`)}>{connection.active ? <PauseIcon aria-hidden="true" /> : <PlayIcon aria-hidden="true" />}</Button>
                      <Button size="icon-xs" variant="ghost" disabled={busy} aria-label={`Remove connection with ${other?.name ?? "environment"}`} title="Remove connection (keeps environment data)" onClick={() => void perform(() => deleteConnection(connection.id), "Removing connection…")}><XIcon aria-hidden="true" /></Button>
                    </div>
                  )
                }) : <p className="inspector-empty">No environment connections yet. Connect nodes on the graph to share access.</p>}
              </section>
            {environment.provider !== "nativeSandbox" ? <section className="inspector-section" aria-label="Restore points">
              <div className="inspector-section-heading inspector-snapshot-heading">
                <h3 className="inspector-section-title"><HistoryIcon aria-hidden="true" />Restore points<ConfigurationHelp label="Restore point help">Local copy-on-write snapshots. Create a restore point before making changes you may want to undo.</ConfigurationHelp></h3>
                <SnapshotDialog environmentId={environment.id} environmentName={environment.name} trigger={<Button disabled={busy} size="sm" type="button" variant="outline"><PlusIcon aria-hidden="true" />New snapshot</Button>} />
              </div>
              <div className="divide-y border-y">
                {snapshots.map((snapshot) => (
                  <div className="inspector-snapshot" key={snapshot.id}>
                    <div className="min-w-0"><p className="truncate text-sm font-medium">{snapshot.name}</p><p className="mt-1 text-xs text-muted-foreground">{formatDateTime(snapshot.createdAt)} · +{formatBytesFromGb(snapshot.deltaGb)}</p></div>
                    <div className="flex items-center gap-1">
                      <AlertDialog>
                        <AlertDialogTrigger render={<Button disabled={busy} loading={snapshotAction === `restore:${snapshot.id}`} size="xs" type="button" variant="ghost" />}>Restore</AlertDialogTrigger>
                        <AlertDialogPopup>
                          <AlertDialogHeader><AlertDialogTitle>Restore {snapshot.name}?</AlertDialogTitle><AlertDialogDescription>{environment.name} will shut down and return to this point, including its saved connections and resource policy.</AlertDialogDescription></AlertDialogHeader>
                          <AlertDialogFooter><AlertDialogClose render={<Button type="button" variant="ghost" />}>Cancel</AlertDialogClose><AlertDialogClose render={<Button type="button" />} onClick={() => void perform(() => restoreSnapshot(snapshot.id), "Restoring snapshot…", `restore:${snapshot.id}`)}>Restore</AlertDialogClose></AlertDialogFooter>
                        </AlertDialogPopup>
                      </AlertDialog>
                      <Button disabled={busy} loading={snapshotAction === `delete:${snapshot.id}`} onClick={() => void perform(() => deleteSnapshot(snapshot.id), "Deleting snapshot…", `delete:${snapshot.id}`)} size="xs" type="button" variant="ghost">Delete</Button>
                    </div>
                  </div>
                ))}
                {!snapshots.length ? <p className="inspector-empty">No snapshots for this environment.</p> : null}
              </div>
            </section> : null}
              <section className="inspector-dates">
                <div><span className="block">Created</span><span className="mt-1 block text-foreground">{formatDateTime(environment.createdAt)}</span></div>
                <div><span className="block">Last opened</span><span className="mt-1 block text-foreground">{environment.lastOpenedAt ? formatDateTime(environment.lastOpenedAt) : "Never"}</span></div>
              </section>
              {!isComputerBranch ? <FactoryResetDialog key={environment.id} environment={environment} disabled={busy} /> : null}
          </div>
        </DialogPanel>
        <DialogFooter className="inspector-footer">
          {actionError ? <p tabIndex={0} className="inspector-action-error max-h-32 min-w-0 max-w-full overflow-y-auto overscroll-contain whitespace-pre-wrap [overflow-wrap:anywhere]" role="alert">{actionError}</p> : null}
          <CudaUpdateAction environment={environment} error={actionError || environment.lastError} disabled={busy} onUpdated={() => { setActionError("") }} />
          {!deleting && (action || localAction) ? <p className="inspector-description" role="status">{action ? environmentActionLabel[action] : localAction}</p> : null}
          <div className="inspector-footer-row">
          <Menu>
            <MenuTrigger render={<Button disabled={busy} loading={action === "pausing" || action === "stopping"} aria-label="More environment actions" type="button" variant="ghost" />}><MoreHorizontalIcon aria-hidden="true" />Actions</MenuTrigger>
            <MenuPopup>
              {environment.status === "running" && environment.provider !== "nativeSandbox" ? <MenuItem closeOnClick onClick={() => void perform(() => setEnvironmentStatus(environment.id, "paused"))}>Pause environment</MenuItem> : null}
              {environment.status !== "stopped" || environment.provider === "qemu" ? <MenuItem closeOnClick onClick={() => void perform(() => setEnvironmentStatus(environment.id, "stopped"))}>Shut down</MenuItem> : null}
              <MenuSeparator />
              <MenuItem closeOnClick onClick={openDelete} variant="destructive">Delete environment</MenuItem>
            </MenuPopup>
          </Menu>
          <div className="flex items-center gap-2">
            {!isComputerBranch && environment.status !== "running" ? <Button disabled={busy} loading={action === "starting" && !openingFromHere} onClick={() => void perform(() => setEnvironmentStatus(environment.id, "running"))} type="button" variant="outline"><PlayIcon aria-hidden="true" />Start</Button> : null}
            <div className="empty:hidden" ref={setPolicySaveTarget} />
            <Button disabled={isComputerBranch || busy} loading={action === "opening" || (action === "starting" && openingFromHere)} onClick={() => { setOpeningFromHere(true); onOpenEnvironment(environment.id) }} type="button"><ExternalLinkIcon aria-hidden="true" />{isComputerBranch ? "Unavailable" : "Open"}</Button>
          </div>
          </div>
        </DialogFooter>
        <AlertDialog open={deleteOpen} onOpenChange={open => { if (!deleting) setDeleteOpen(open) }}>
          <AlertDialogPopup>
            <AlertDialogHeader>
              <AlertDialogTitle>Delete {environment.name}?</AlertDialogTitle>
              <AlertDialogDescription>This permanently removes its writable layer, local snapshots, and connection permissions. Unused cached VM images are cleaned up too. Images still used by other environments, your original installer files, and exported backups are kept. Only the space actually used is reclaimed, rather than the virtual disk capacity.</AlertDialogDescription>
            </AlertDialogHeader>
            {deleteError ? <div className="flex flex-col gap-3 px-6 pb-4">
              <p className="break-words text-sm text-destructive-foreground" role="alert">Deletion failed: {deleteError}</p>
              {environment.kind === "container" ? <p className="text-sm text-muted-foreground">If an abandoned runtime is locking the container, recovery can stop it and retry deletion. This interrupts any containers still inside that abandoned runtime. Saved data for other environments is not deleted. A runtime owned by another live app will not be stopped.</p> : null}
            </div> : null}
            {deleting ? <p className="px-6 pb-4 text-sm text-muted-foreground" role="status">Deleting environment… Runtime startup and cleanup can take a moment.</p> : null}
            <AlertDialogFooter>
              <AlertDialogClose render={<Button disabled={deleting} type="button" variant="ghost" />}>Cancel</AlertDialogClose>
              {deleteError && environment.kind === "container" ? <Button disabled={deleting} onClick={() => void remove(true)} type="button" variant="destructive">Recover runtime and delete</Button> : null}
              <Button loading={deleting} onClick={() => void remove()} type="button" variant={deleteError ? "outline" : "destructive"}>{deleteError ? "Retry deletion" : "Delete environment"}</Button>
            </AlertDialogFooter>
          </AlertDialogPopup>
        </AlertDialog>
      </DialogPopup>
    </Dialog>
  )
}
