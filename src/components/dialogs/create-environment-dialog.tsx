import { useEffect, useRef, useState } from "react"
import { SharedEnvironmentForm } from "@/components/shared-environment-form"
import { LocalBackupDialog } from "./local-backup-dialog"
import { CloudEnvironmentDialog } from "./cloud-environment-dialog"
import { NeocloudForm } from "./neocloud-form"
import { SandboxVmLaunchForm } from "@/components/sandbox-vm/sandbox-vm-launch-form"
import { useSandboxVms } from "@/components/sandbox-vm/sandbox-vm-context"
import { sandboxVmApi, type LaunchRequest } from "@/api/sandbox-vm-api"
import { Dialog, DialogDescription, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Label } from "@/components/ui/label"
import { Radio, RadioGroup } from "@/components/ui/radio-group"
import { cn } from "@/lib/utils"
import type { EnvironmentKind } from "@/types/platform"
import "./create-environment-dialog.css"

const choices = [
  ["sandbox", "Sandbox VM"], ["cloud", "Cloud environment"], ["neocloud", "Neocloud"],
  ["shared", "Shared environment"], ["backup", "Load local backup"],
] as const
type Workflow = typeof choices[number][0]

export function CreateEnvironmentDialog({ open, onOpenChange, initialKind }: {
  open: boolean; onOpenChange(open: boolean): void; initialKind?: EnvironmentKind
}) {
  const [workflow, setWorkflow] = useState<Workflow>("sandbox")
  const [busy, setBusy] = useState(false)
  const [importing, setImporting] = useState(false)
  const [error, setError] = useState("")
  const lock = useRef(false)
  const { refresh } = useSandboxVms()
  useEffect(() => {
    if (open) { setWorkflow(initialKind === "cloud" ? "cloud" : "sandbox"); setError("") }
  }, [open, initialKind])
  const launch = async (request: LaunchRequest) => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError("")
    try {
      const result = await sandboxVmApi.launch(request)
      await refresh()
      onOpenChange(false)
      window.dispatchEvent(new CustomEvent("yougori-open-sandbox-vm", { detail: result.sandbox }))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
      await refresh()
    } finally { lock.current = false; setBusy(false) }
  }
  const locked = busy || importing
  return <Dialog open={open} onOpenChange={value => { if (!locked) onOpenChange(value) }}>
    <DialogPopup bottomStickOnMobile={false} closeProps={{ disabled: locked }} className="creation-workbench overflow-hidden" data-create-environment data-create-kind={workflow}>
      <DialogTitle className="sr-only">New environment</DialogTitle>
      <DialogDescription className="sr-only">Create a Sandbox VM, connect a remote environment, or load a backup.</DialogDescription>
      <section aria-label="Environment options" className="creation-isolation">
        <div className="creation-heading"><h2 aria-hidden="true">New environment</h2>
          <p className="creation-isolation-description">A private virtual machine for your tools, services and files.</p>
        </div>
        <div className="creation-type-tabs">
          <RadioGroup aria-label="Environment type" className="creation-types" disabled={locked} value={workflow} onValueChange={value => setWorkflow(value as Workflow)}>
            {choices.map(([value, label]) => <Label key={value} className={cn("creation-type", workflow === value && "is-selected")}>
              <Radio className="sr-only" value={value} /><span>{label}</span>
            </Label>)}
          </RadioGroup>
        </div>
      </section>
      {workflow === "sandbox" ? <SandboxVmLaunchForm key={String(open)} disabled={busy} error={error}
        onCancel={() => onOpenChange(false)} onImportBusyChange={setImporting} onLaunch={request => void launch(request)} />
        : workflow === "cloud" ? <CloudEnvironmentDialog embedded open={open} onOpenChange={onOpenChange} onBusyChange={setBusy} />
        : <DialogPanel key={workflow}>
          {workflow === "neocloud" ? <NeocloudForm onClose={() => onOpenChange(false)} onBusyChange={setBusy} />
            : workflow === "shared" ? <SharedEnvironmentForm onClose={() => onOpenChange(false)} onBusyChange={setBusy} />
              : <LocalBackupDialog embedded onClose={() => onOpenChange(false)} onBusyChange={setBusy} />}
        </DialogPanel>}
    </DialogPopup>
  </Dialog>
}
