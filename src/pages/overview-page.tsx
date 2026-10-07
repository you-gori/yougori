import { ProjectManager } from "@/components/project-manager"
import { DuplicationActivity } from "@/components/duplication-activity"
import { lazy, Suspense, useCallback, useMemo, useState } from "react"
import { EnvironmentGraph } from "@/components/environment-graph"
import { usePlatform } from "@/context/platform-context"
import { formatBytesFromGb } from "@/lib/domain"
import { storageDrives, driveLabel } from "@/lib/storage-drives"
import { ConfigurationHelp } from "@/components/configuration-help"
import { ThemePicker } from "@/components/theme-picker"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import { InstructionGuides } from "@/components/instruction-guides"

const loadConnectionDialog = () => import("@/components/dialogs/connection-dialog")
const ConnectionDialog = lazy(async () => ({ default: (await loadConnectionDialog()).ConnectionDialog }))

export function OverviewPage({ onOpenEnvironment, onSelectEnvironment }: {
  onOpenEnvironment(environmentId: string): void
  onSelectEnvironment(environmentId: string): void
}) {
  const { state, reclaimStorage } = usePlatform()
  const [reclaiming, setReclaiming] = useState(false)
  const reclaim = async () => {
    if (reclaiming) return
    setReclaiming(true)
    try { await reclaimStorage() }
    catch (error) { toastManager.add({ title: "Storage cleanup could not finish", description: String(error), type: "error", timeout: 0 }) }
    finally { setReclaiming(false) }
  }
  const [graphErrorContainer, setGraphErrorContainer] = useState<HTMLDivElement | null>(null)
  const [connectionOpen, setConnectionOpen] = useState(false)
  const [connectionMounted, setConnectionMounted] = useState(false)
  const [connectionSourceId, setConnectionSourceId] = useState<string | undefined>()
  const [connectionTargetId, setConnectionTargetId] = useState<string | undefined>()
  const environments = useMemo(() => [...(state?.environments ?? []).filter(environment => environment.id !== state?.cliEnvironmentId)].sort((a, b) => new Date(b.lastOpenedAt ?? b.createdAt).getTime() - new Date(a.lastOpenedAt ?? a.createdAt).getTime()), [state?.environments, state?.cliEnvironmentId])
  const runningCount = environments.filter((environment) => environment.status === "running").length

  const openConnection = useCallback((sourceId?: string, targetId?: string) => {
    void loadConnectionDialog()
    setConnectionMounted(true)
    setConnectionSourceId(sourceId)
    setConnectionTargetId(targetId)
    setConnectionOpen(true)
  }, [])

  if (!state) return null

  return (
    <div className="workspace-overview flex flex-col">
      <div className="relative">
      <div className="absolute inset-x-0 bottom-full flex h-8 items-center empty:hidden sm:h-10 [&>*]:w-full" ref={setGraphErrorContainer} />

      </div>

      <section aria-label="Environments workspace">
        <EnvironmentGraph connections={state.connections} environments={environments} errorContainer={graphErrorContainer} onConnect={openConnection} onOpen={onOpenEnvironment} onSelect={onSelectEnvironment} footer={(openEdit, editDisabled, editActive, toggleCli, cliActive) =>
          <section aria-label="Host resources and storage" className="workspace-footer-stats">
            <div className="workspace-footer-resources">
            <span className="workspace-footer-running" title={`${runningCount} running · ${environments.length - runningCount} not running`}><i aria-hidden="true" data-active={runningCount > 0} /><strong>{runningCount}</strong> running<span className="sr-only"> · {environments.length - runningCount} not running</span></span>
            <span className="workspace-footer-metric"><span>Host CPU</span><strong>{Math.round(state.host.usedCpuPercent)}%</strong></span>
            <span className="workspace-footer-metric"><span>Host GPU</span><strong>{state.host.gpuUsagePercent === null ? "—" : `${Math.round(state.host.gpuUsagePercent)}%`}</strong>{state.host.gpuUsagePercent === null ? <span className="sr-only">Unavailable</span> : null}</span>
            <span className="workspace-footer-metric"><span>Memory</span><strong>{state.host.usedMemoryGb.toFixed(1)}<span className="workspace-footer-total"> / {Math.round(state.host.totalMemoryGb)} GB</span></strong></span>
            {storageDrives(state.host).map(drive => <span key={drive.path} className="workspace-footer-metric workspace-footer-storage" title={`${drive.name} · ${drive.fileSystem} · ${formatBytesFromGb(drive.totalGb - drive.freeGb)} used / ${formatBytesFromGb(drive.totalGb)} total${drive.readOnly ? " · Read-only" : ""}${drive.removable ? " · Removable" : ""}`}><span>{drive.path ? driveLabel(drive.path) : "Storage"}</span><strong>{drive.totalGb > 0 ? `${formatBytesFromGb(drive.freeGb)} free` : "Unavailable"}</strong></span>)}
            <ConfigurationHelp label="Storage usage details">{storageDrives(state.host).map(drive => <span className="block" key={drive.path}>{driveLabel(drive.path)}: {formatBytesFromGb(drive.freeGb)} free of {formatBytesFromGb(drive.totalGb)}{drive.readOnly ? " · Read-only" : ""}</span>)}Choose a drive in New environment. Each drive has its own free-space limit.</ConfigurationHelp>
            </div>
            <div className="workspace-footer-actions">
            <Button id="host-terminal-toggle" data-instruction-view="cli" size="xs" variant="ghost" className="workspace-footer-reclaim" aria-pressed={cliActive} aria-controls="host-terminal-panel" title="CLI (Ctrl+`)" disabled={editDisabled} onClick={toggleCli} type="button">CLI</Button>
            <ProjectManager />
            <DuplicationActivity />
            <Button id="edit-app-toggle" size="xs" variant="ghost" className="workspace-footer-reclaim" aria-pressed={editActive} aria-controls="edit-app-terminal-panel" disabled={editDisabled} onClick={openEdit} type="button">Edit the App</Button>
            <InstructionGuides />
            <Button data-instruction="reclaim" size="xs" variant="ghost" className="workspace-footer-reclaim" disabled={reclaiming} aria-busy={reclaiming} onClick={() => void reclaim()} title="Return unused disk blocks to your computer. Keeps images, snapshots and backups. Stop containers first for full compaction.">{reclaiming ? "Reclaiming…" : "Reclaim space"}</Button>
            <ThemePicker />
            </div>
          </section>
        } />
      </section>

      {connectionMounted ? (
        <Suspense fallback={null}>
          <ConnectionDialog initialSourceId={connectionSourceId} initialTargetId={connectionTargetId} onOpenChange={setConnectionOpen} open={connectionOpen} />
        </Suspense>
      ) : null}
    </div>
  )
}
