import { useEffect, useImperativeHandle, useState, type Ref } from "react"
import { platformApi } from "@/api/platform-api"
import { Button } from "@/components/ui/button"
import { CudaUpdateAction } from "@/components/cuda-update-action"
import { needsCudaUpdate } from "@/lib/cuda-update"
import { ConfigurationHelp } from "@/components/configuration-help"
import { StorageCapacitySlider } from "@/components/storage-capacity-slider"
import type { SectionSave } from "@/lib/resource-controls"
import type { Environment, StorageAllocation } from "@/types/platform"

/** Edits a draft; the configuration's Save changes button stores it through `saveRef`. */
export function StorageAllocationEditor({ environment, saveRef, disabled = false }: {
  environment: Environment; otherContainersActive: boolean; saveRef?: Ref<SectionSave>; disabled?: boolean
}) {
  const [allocation, setAllocation] = useState<StorageAllocation | null>(null)
  const [capacity, setCapacity] = useState(0)
  // Only a slider the user moved is a change, including accepting a suggested limit.
  const [touched, setTouched] = useState(false)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    let active = true
    setLoading(true)
    setError("")
    setTouched(false)
    platformApi.getStorageAllocation(environment.id).then(value => {
      if (active) { setAllocation(value); setCapacity(Math.ceil(value.capacityGb)) }
    }).catch(reason => { if (active) setError(String(reason)) }).finally(() => { if (active) setLoading(false) })
    return () => { active = false }
  }, [environment.id, environment.status, retry])
  const container = environment.kind === "container"
  const needsLimit = container && allocation?.limitEnforced !== true
  const mustStop = environment.status !== "stopped" && (!container || needsLimit)
  const minimum = container ? 1 : allocation ? Math.ceil(allocation.capacityGb) : 1
  const belowUsage = Boolean(container && allocation && capacity <= allocation.physicalGb)
  const changed = Boolean(touched && allocation && capacity >= minimum && (container ? needsLimit || capacity !== allocation.capacityGb : capacity > allocation.capacityGb))
  const stopMessage = container ? "Stop this container once to enable its storage limit. Other containers can keep running." : "Stop this environment before expanding storage."
  const usageMessage = allocation ? `This container uses ${allocation.physicalGb.toFixed(2)} GB. Choose at least ${Math.max(1, Math.floor(allocation.physicalGb) + 1)} GB.` : ""
  useImperativeHandle(saveRef, () => ({
    changed: () => changed,
    problem: () => mustStop ? stopMessage : belowUsage ? usageMessage : null,
    save: async () => {
      const value = await platformApi.expandEnvironmentStorage(environment.id, capacity)
      setAllocation(value); setCapacity(Math.ceil(value.capacityGb)); setTouched(false)
    },
  }), [belowUsage, capacity, changed, environment.id, mustStop, stopMessage, usageMessage])
  if (loading) return <p role="status" className="text-xs text-muted-foreground">Loading storage capacity…</p>
  return <div className="inspector-storage">
    {allocation ? <>
      <StorageCapacitySlider value={capacity} min={minimum} max={allocation.maximumGb} container={container} disabled={disabled} onChange={value => { setCapacity(value); setTouched(true) }} />
      {container ? <p className="text-xs text-muted-foreground">{needsLimit ? "Suggested" : "Current"} limit: {Number(allocation.capacityGb.toFixed(2))} GB · Used by this container: {allocation.physicalGb.toFixed(2)} GB</p> : null}
      {!container ? <p className="text-xs text-muted-foreground">Current disk: {Number(allocation.capacityGb.toFixed(2))} GB · Host space used: {allocation.physicalGb.toFixed(2)} GB</p> : null}
      <div className="inspector-section-heading"><span className="inspector-description">Storage details</span><ConfigurationHelp label="Storage allocation help">{container ? "Choose from 1 GB to the available maximum. Writable files, private volumes and logs count toward this limit. Base images, snapshots and connected folders use additional space. An enabled limit can increase or decrease while the container runs, but must stay above its current usage." : `${environment.runtime === "builtin:alpine" ? "The filesystem expands automatically at the next start." : "After expansion, extend the partition inside the guest (Windows: Disk Management → Extend Volume)."} Shrinking is disabled to protect your files.`}</ConfigurationHelp></div>
      {belowUsage && touched ? <p role="alert" className="text-xs text-destructive-foreground">{usageMessage}</p> : null}
      {mustStop ? <p role="status" className="text-xs text-muted-foreground">{stopMessage}</p> : null}
    </> : null}
    {error ? needsCudaUpdate(environment, error)
      ? <CudaUpdateAction environment={environment} error={error} disabled={disabled} onUpdated={() => setRetry(value => value + 1)} />
      : <div role="alert" className="text-xs text-destructive-foreground">{error}<Button type="button" variant="ghost" size="sm" disabled={disabled} onClick={() => setRetry(value => value + 1)}>Refresh storage</Button></div> : null}
  </div>
}
