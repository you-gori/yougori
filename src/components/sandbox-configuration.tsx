import { lazy, Suspense } from "react"
import { ArrowRight, Boxes, ChevronDown, Layers, Plus, Settings2, ShieldCheck } from "lucide-react"
import type { Environment } from "@/types/platform"
import { useSetupFeed } from "@/api/setups/progress"
import { useSetupBuilder } from "@/components/setups/builder-context"
import { Dialog, DialogPopup, DialogTitle, DialogDescription, DialogHeader, DialogPanel, DialogFooter } from "@/components/ui/dialog"
import { Button } from "@/components/ui/button"
import { Status } from "@/components/shared/status"
import { environmentLabel } from "@/lib/environment-category"
import { SandboxVmPanel } from "@/components/sandbox-vm/sandbox-vm-panel"
import "./sandbox-configuration.css"

const EnvironmentDetailSheet = lazy(async () => ({ default: (await import("./environment-detail-sheet")).EnvironmentDetailSheet }))
const isVm = (environment: Environment) => environment.runtime.startsWith("sandbox-vm://")

/** Open actual settings for a single selection; a group chooses which settings to edit. */
export function SandboxConfiguration({ environments, onClose, onConfigureEnvironment, onOpenEnvironment }: {
  environments: Environment[]
  onClose(): void
  onConfigureEnvironment(id: string): void
  onOpenEnvironment(id: string): void
}) {
  const feed = useSetupFeed()
  const builder = useSetupBuilder()
  const ids = new Set(environments.map(environment => environment.id))
  const setups = (feed.setups ?? []).filter(setup => {
    const detail = feed.details[setup.setupId]
    return !setup.adoptedLegacy && (detail?.resources.some(resource => ids.has(resource.resourceId))
      || detail?.outputs?.some(output => ids.has(output.value)))
  })
  const captureSupported = environments.length > 0 && environments.every(isVm)
  const setupActions = setups.length || captureSupported || feed.error ? <section aria-label="Setups and templates" className="selection-setup-actions">
    <h3><Layers aria-hidden="true" />Setups &amp; templates</h3>
    {feed.error ? <p role="status" className="selection-note">Setup configuration could not be read: {feed.error}</p> : null}
    {setups.map(setup => <button key={setup.setupId} type="button" className="selection-setup-row" onClick={() => {
      onClose(); builder.open({ mode: "configure", setupId: setup.setupId, setupName: setup.name })
    }}><span><strong>{setup.name}</strong><small>Configure setup</small></span><ArrowRight aria-hidden="true" /></button>)}
    {captureSupported ? <>
      <p className="selection-note">Reuse this {environments.length === 1 ? "environment" : "selection"} as a template.</p>
      <Button size="sm" variant="outline" onClick={() => {
        onClose(); builder.open({ mode: "create", entry: "environments", environments: [...ids] })
      }}><Plus aria-hidden="true" />Create template</Button>
    </> : null}
  </section> : null
  const selected = environments.length === 1 ? environments[0] : null
  const changeOpen = (open: boolean) => { if (!open) onClose() }
  if (!environments.length) return null
  if (selected && !isVm(selected)) return <Suspense fallback={<Dialog open onOpenChange={changeOpen}>
    <DialogPopup className="selection-configuration" bottomStickOnMobile={false}>
      <DialogHeader><DialogTitle>{selected.name}</DialogTitle><DialogDescription>Environment configuration</DialogDescription></DialogHeader>
      <DialogPanel><p role="status" className="selection-note">Loading settings…</p></DialogPanel>
    </DialogPopup>
  </Dialog>}><EnvironmentDetailSheet environmentId={selected.id} onOpenChange={changeOpen}
    onOpenEnvironment={id => { onClose(); onOpenEnvironment(id) }} setupActions={setupActions} /></Suspense>
  return <Dialog open onOpenChange={changeOpen}>
    <DialogPopup className={`selection-configuration${selected ? " selection-vm-configuration" : ""}`} bottomStickOnMobile={false}>
      <DialogHeader className="selection-configuration-header">
        <div className="selection-eyebrow"><Settings2 aria-hidden="true" />Configuration{selected ? <Status compact status={selected.status} /> : <span>{environments.length} selected</span>}</div>
        <DialogTitle>{selected?.name ?? "Configure environments"}</DialogTitle>
        <DialogDescription>{selected ? "Workspace, permissions and services for this Sandbox VM." : "Adjust an environment’s settings or configure a setup that uses your selection."}</DialogDescription>
      </DialogHeader>
      <DialogPanel className="selection-configuration-body">
        {selected ? <SandboxVmPanel sandbox={selected.id} /> : <div className="selection-environments" aria-label="Selected environments">
          {environments.map(environment => isVm(environment) ? <details className="selection-vm-row" key={environment.id}>
            <summary><ShieldCheck aria-hidden="true" /><span className="selection-environment-name">{environment.name}<small>Sandbox VM</small></span><Status compact status={environment.status} /><ChevronDown className="selection-chevron" aria-hidden="true" /></summary>
            <div className="selection-vm-controls"><SandboxVmPanel sandbox={environment.id} /></div>
          </details> : <button key={environment.id} type="button" className="selection-environment-row" aria-label={`Configure ${environment.name}`} onClick={() => { onClose(); onConfigureEnvironment(environment.id) }}>
            <Boxes aria-hidden="true" /><span className="selection-environment-name">{environment.name}<small>{environmentLabel(environment)}</small></span><Status compact status={environment.status} /><ArrowRight aria-hidden="true" />
          </button>)}
        </div>}
        {setupActions}
      </DialogPanel>
      <DialogFooter className="selection-configuration-footer"><Button variant="outline" onClick={onClose}>Done</Button></DialogFooter>
    </DialogPopup>
  </Dialog>
}
