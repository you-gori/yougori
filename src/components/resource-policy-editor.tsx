import { useEffect, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { Button } from "@/components/ui/button"
import { Field, FieldError } from "@/components/ui/field"
import { ConfigurationHelp } from "@/components/configuration-help"
import { ResourceValueControl } from "@/components/resource-value-control"
import { StorageAllocationEditor } from "@/components/storage-allocation-editor"
import { EnvironmentNameEditor } from "@/components/environment-name-editor"
import { fixedResourceErrors, fixedResourcePolicy, resourceControlLimits } from "@/lib/resource-controls"
import { usePlatform } from "@/context/platform-context"
import type { SectionSave } from "@/lib/resource-controls"
import type { Environment, ResourcePolicy } from "@/types/platform"

export function ResourcePolicyEditor({ environment, saveTarget, startupDraft = null, onStartupSaved }: {
  environment: Environment; saveTarget?: HTMLElement | null
  /** Unsaved container startup command from the same configuration, saved together. */
  startupDraft?: string | null; onStartupSaved?(): void
}) {
  const { updateResourcePolicy, updateContainerStartupCommand, state } = usePlatform()
  const [policy, setPolicy] = useState<ResourcePolicy>(() => fixedResourcePolicy(environment.resourcePolicy))
  const [saving, setSaving] = useState(false)
  const [dirty, setDirty] = useState(false)
  const [saveError, setSaveError] = useState("")
  const [saved, setSaved] = useState(false)

  // Host polling creates a new environment object repeatedly. Never discard
  // a draft while the user is typing; current allocation is not an edit field.
  useEffect(() => { if (!dirty) setPolicy(fixedResourcePolicy(environment.resourcePolicy)) }, [environment, dirty])
  const limits = resourceControlLimits(environment.kind, state?.host.totalCpu, state?.host.totalMemoryGb)
  if (environment.description?.startsWith("Hugging Face · ")) {
    limits.cpu.min = 2
    limits.memory.min = 4
  }
  const errors = fixedResourceErrors(policy.cpu.preferred, policy.memoryGb.preferred, limits)
  const update = (next: ResourcePolicy) => { setPolicy(fixedResourcePolicy(next)); setDirty(true); setSaved(false); setSaveError("") }
  const memoryRestart = environment.kind === "microVm" && environment.status === "running" && policy.memoryGb.preferred !== environment.resourcePolicy.memoryGb.current
  const macVm = /macos|mac os|darwin/i.test(state?.host.os ?? "") && ["fullVm", "microVm"].includes(environment.kind)

  const nameSave = useRef<SectionSave>(null)
  const storageSave = useRef<SectionSave>(null)
  const startupChanged = startupDraft !== null && startupDraft.trim() !== (environment.containerCommand ?? "")
  // One button stores every edited section. Check them all first so a blocked
  // section never leaves the others half saved.
  // Invalid resource values only block saving when the user edited them.
  const blocked = dirty && errors.length > 0
  const save = async () => {
    if (saving || blocked) return
    const sections = [nameSave.current, storageSave.current].filter((section): section is SectionSave => Boolean(section?.changed()))
    const startupProblem = startupChanged && environment.status !== "stopped" ? "Stop the container, then Save changes to use the new startup command." : null
    const problem = sections.map(section => section.problem()).find(Boolean) ?? startupProblem
    if (!dirty && !sections.length && !startupChanged && errors.length) return
    setSaved(false)
    if (problem) { setSaveError(problem); return }
    setSaving(true)
    setSaveError("")
    try {
      if (nameSave.current?.changed()) await nameSave.current.save()
      if (dirty || (!sections.length && !startupChanged)) {
        await updateResourcePolicy(environment.id, { ...fixedResourcePolicy(policy), dynamic: true })
        setDirty(false)
      }
      if (storageSave.current?.changed()) await storageSave.current.save()
      if (startupChanged) {
        await updateContainerStartupCommand(environment.id, startupDraft)
        onStartupSaved?.()
      }
      setSaved(true)
    } catch (reason) { setSaveError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setSaving(false) }
  }

  const saveButton = <Button disabled={blocked} loading={saving} onClick={save} type="button" variant="outline">Save changes</Button>

  return (
    <div className="inspector-resource-editor flex flex-col gap-6">
      {environment.kind === "fullVm" || environment.kind === "microVm" ? <EnvironmentNameEditor key={`${environment.id}:name`} environment={environment} saveRef={nameSave} disabled={saving} onSubmit={() => void save()} /> : null}
      <div className="inspector-section-heading"><h3 className="inspector-section-title">Resource allocation</h3><span>Fixed</span></div>
      <ResourceValueControl label="CPU" min={limits.cpu.min} max={limits.cpu.max} step={limits.cpu.step} disabled={saving} unit="CPUs" value={policy.cpu.preferred} onChange={value => update({ ...policy, cpu: { ...policy.cpu, preferred: value } })} />
      <ResourceValueControl label="Memory" min={limits.memory.min} max={limits.memory.max} step={limits.memory.step} disabled={saving} unit="GB" value={policy.memoryGb.preferred} onChange={value => update({ ...policy, memoryGb: { ...policy.memoryGb, preferred: value } })} />
      {environment.kind !== "computerBranch" ? <StorageAllocationEditor key={`${environment.id}:storage`} environment={environment} saveRef={storageSave} disabled={saving} otherContainersActive={Boolean(state?.environments.some(item => item.kind === "container" && ["running", "paused", "provisioning"].includes(item.status)))} /> : null}
      <div className="inspector-section-heading"><span className="inspector-description">Fixed allocation</span><ConfigurationHelp label="Runtime limits and restart behavior">CPU and memory stay at the values you save; host pressure does not resize them. {macVm ? "VM changes apply after shutdown and restart." : environment.kind === "microVm" ? "Memory changes apply after shutdown and restart. Stop the MicroVM before increasing its allocation." : environment.kind === "fullVm" ? "Stop the VM before increasing its allocation. Live memory changes require a guest balloon driver." : "Container changes apply live when the shared runtime has capacity. Otherwise stop the containers before increasing the allocation."}</ConfigurationHelp></div>
      {errors.length ? <Field invalid><FieldError match role="alert">{errors[0]}</FieldError></Field> : null}
      {memoryRestart ? <p role="status" className="text-xs text-muted-foreground">Restart required for memory: running with {Number(environment.resourcePolicy.memoryGb.current.toFixed(3))} GB; next boot uses {Number.isFinite(policy.memoryGb.preferred) ? Number(policy.memoryGb.preferred.toFixed(3)) : "—"} GB.</p> : null}
      {saveError ? <p role="alert" className="text-xs text-destructive-foreground">{saveError}</p> : null}
      {saved ? <p role="status" className="text-xs text-success-foreground">Changes saved.</p> : null}
      {saveTarget === undefined ? <div className="inspector-policy-footer">{saveButton}</div> : saveTarget ? createPortal(saveButton, saveTarget) : null}
    </div>
  )
}
