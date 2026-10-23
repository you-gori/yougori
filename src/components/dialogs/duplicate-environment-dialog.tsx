import { CloudFilesDialog } from "@/components/dialogs/cloud-files-dialog"
import { CloudDuplicateDialog } from "@/components/dialogs/cloud-duplicate-dialog"
import { useRef, useState } from "react"
import type { Environment } from "@/types/platform"
import { Outcome, StillNeeded } from "@/components/popup-kit"
import type { DuplicateDestination } from "@/components/environment-duplicate-action"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { driveLabel, storageDrives } from "@/lib/storage-drives"

function LocalDuplicateEnvironmentDialog({ environment, destination, onClose }: {
  environment: Environment
  destination: DuplicateDestination
  onClose(): void
}) {
  const { state, duplicateLocalEnvironment } = usePlatform()
  const [name, setName] = useState(() => {
    const base = environment.name.slice(0, 65)
    let candidate = `${base} copy`, number = 2
    while (state?.environments.some(item => item.name.toLowerCase() === candidate.toLowerCase())) candidate = `${base} copy ${number++}`
    return candidate
  })
  const [drive, setDrive] = useState(environment.storageDrive ?? "")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const guard = useRef(false)
  const localSupported = environment.kind === "container" && ["yougoriOci", "yougoriCuda"].includes(environment.provider ?? "")
    || environment.provider === "qemu" && (environment.kind === "fullVm" || environment.kind === "microVm" && environment.runtime === "builtin:alpine")
  const issue = !localSupported ? "This environment’s runtime does not support a complete disk copy."
    : environment.status !== "stopped" ? "Stop this environment before duplicating its disk and files." : null
  const nameIssue = !name.trim() ? "Enter a name for the copy." : state?.environments.some(item => item.name.toLowerCase() === name.toLowerCase()) ? "An environment with this name already exists." : null
  const submit = async (event: React.FormEvent) => {
    event.preventDefault()
    if (guard.current || issue || nameIssue) return
    guard.current = true; setBusy(true); setError("")
    try { await duplicateLocalEnvironment(environment.id, name, drive || undefined); onClose() }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { guard.current = false; setBusy(false) }
  }
  return <Dialog open onOpenChange={open => { if (!open && !guard.current) onClose() }}>
    <DialogPopup closeProps={{ disabled: busy }}>
      <DialogHeader>
        <DialogTitle>Duplicate environment</DialogTitle>
        <DialogDescription>Makes an independent copy of {environment.name} on this computer. The copy starts stopped, and changes to one never reach the other.</DialogDescription>
      </DialogHeader>
      <form className="contents" onSubmit={event => void submit(event)}>
        <DialogPanel className="space-y-4">
          <label className="block space-y-2 text-sm">Name<Input autoFocus maxLength={80} value={name} onChange={event => setName(event.target.value)} disabled={busy} required /></label>
          {destination === "local" && state ? <label className="flex items-center justify-between gap-3 text-sm">Storage drive<select aria-label="Storage drive" className="h-9 min-w-0 rounded-md border bg-background px-2 text-sm" disabled={busy} value={drive} onChange={event => setDrive(event.target.value)}>
            <option value="">Default drive</option>
            {storageDrives(state.host).filter(item => item.path).map(item => <option key={item.path} value={item.path} disabled={item.readOnly}>{driveLabel(item.path)} · {item.freeGb.toFixed(1)} GB free</option>)}
            {drive && !storageDrives(state.host).some(item => item.path === drive) ? <option value={drive} disabled>{driveLabel(drive)} · Disconnected</option> : null}
          </select></label> : null}
          <Outcome title="What the copy holds">
            <p>The disk, installed apps, files, startup command and resource settings.</p>
            <p>Shared PC folders, external disks, network connections and snapshot history stay with {environment.name}.</p>
          </Outcome>
          {issue ? <p role="status" className="text-sm text-muted-foreground">{issue}</p> : null}
          {error ? <p role="alert" className="text-sm text-destructive-foreground">{error}</p> : null}
          {busy ? <p role="status" className="text-sm text-muted-foreground">Copying and verifying the disk… Keep Yougori open.</p> : null}
        </DialogPanel>
        <DialogFooter><StillNeeded>{busy || issue ? "" : nameIssue}</StillNeeded><Button type="button" variant="ghost" disabled={busy} onClick={onClose}>Cancel</Button><Button type="submit" loading={busy} disabled={busy || Boolean(issue || nameIssue)}>Duplicate</Button></DialogFooter>
      </form>
    </DialogPopup>
  </Dialog>
}

export function DuplicateEnvironmentDialog(props: { environment: Environment; destination: DuplicateDestination; onClose(): void }) {
  if (props.destination === "local" && props.environment.kind === "cloud") return <CloudFilesDialog environment={props.environment} onClose={props.onClose} />
  return props.destination === "cloud" ? <CloudDuplicateDialog {...props} /> : <LocalDuplicateEnvironmentDialog {...props} />
}
