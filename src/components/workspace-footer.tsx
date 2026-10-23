import { type ReactNode, useState } from "react"
import { usePlatform } from "@/context/platform-context"
import { formatBytesFromGb } from "@/lib/domain"
import { storageDrives, driveLabel } from "@/lib/storage-drives"
import { ConfigurationHelp } from "@/components/configuration-help"
import { ThemePicker } from "@/components/theme-picker"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import { InstructionGuides } from "@/components/instruction-guides"

/** The shared workspace footer: host stats on the left, the same actions on the right.
 *  `status` is page-specific (the running count on Sandboxes). */
export function WorkspaceFooter({ status }: { status?: ReactNode }) {
  const { state, reclaimStorage } = usePlatform()
  const [reclaiming, setReclaiming] = useState(false)
  const reclaim = async () => {
    if (reclaiming) return
    setReclaiming(true)
    try { await reclaimStorage() }
    catch (error) { toastManager.add({ title: "Storage cleanup could not finish", description: String(error), type: "error", timeout: 0 }) }
    finally { setReclaiming(false) }
  }
  if (!state) return null
  return (
    <section aria-label="Host resources and storage" className="workspace-footer-stats">
      <div className="workspace-footer-resources">
        {status}
        <span className="workspace-footer-metric"><span>Host CPU</span><strong>{Math.round(state.host.usedCpuPercent)}%</strong></span>
        <span className="workspace-footer-metric"><span>Host GPU</span><strong>{state.host.gpuUsagePercent === null ? "—" : `${Math.round(state.host.gpuUsagePercent)}%`}</strong>{state.host.gpuUsagePercent === null ? <span className="sr-only">Unavailable</span> : null}</span>
        <span className="workspace-footer-metric"><span>Memory</span><strong>{state.host.usedMemoryGb.toFixed(1)}<span className="workspace-footer-total"> / {Math.round(state.host.totalMemoryGb)} GB</span></strong></span>
        {storageDrives(state.host).map(drive => <span key={drive.path} className="workspace-footer-metric workspace-footer-storage" title={`${drive.name} · ${drive.fileSystem} · ${formatBytesFromGb(drive.totalGb - drive.freeGb)} used / ${formatBytesFromGb(drive.totalGb)} total${drive.readOnly ? " · Read-only" : ""}${drive.removable ? " · Removable" : ""}`}><span>{drive.path ? driveLabel(drive.path) : "Storage"}</span><strong>{drive.totalGb > 0 ? `${formatBytesFromGb(drive.freeGb)} free` : "Unavailable"}</strong></span>)}
        <ConfigurationHelp label="Storage usage details">{storageDrives(state.host).map(drive => <span className="block" key={drive.path}>{driveLabel(drive.path)}: {formatBytesFromGb(drive.freeGb)} free of {formatBytesFromGb(drive.totalGb)}{drive.readOnly ? " · Read-only" : ""}</span>)}Choose a drive in New sandbox. Each drive has its own free-space limit.</ConfigurationHelp>
      </div>
      <div className="workspace-footer-actions">
        <InstructionGuides />
        <Button data-instruction="reclaim" size="xs" variant="ghost" className="workspace-footer-reclaim" disabled={reclaiming} aria-busy={reclaiming} onClick={() => void reclaim()} title="Return unused disk blocks to your computer. Keeps images, snapshots and backups. Stop containers first for full compaction.">{reclaiming ? "Reclaiming…" : "Reclaim space"}</Button>
        <ThemePicker />
      </div>
    </section>
  )
}
