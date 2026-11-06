import { useState } from "react"
import type { Environment } from "@/types/platform"
import { sandboxVmApi } from "@/api/sandbox-vm-api"
import { EnvironmentListRow } from "@/components/environment-list"
import { Button } from "@/components/ui/button"
import { useSandboxVms } from "./sandbox-vm-context"

export function SandboxVmEnvironmentRow({ environment, onOpen }: { environment: Environment; onOpen(id: string): void }) {
  const { refresh } = useSandboxVms()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const stop = async () => {
    if (busy) return
    setBusy(true); setError("")
    try { await sandboxVmApi.stop(environment.id); await refresh() }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setBusy(false) }
  }
  return <EnvironmentListRow environment={environment} accent="var(--primary)" canLink={false} busy={busy}
    managedExternally metricsAvailable={false} fileStatus={null} dropHint="" access={<Button size="xs" variant="ghost" onClick={() => onOpen(environment.id)}>Files & permissions</Button>}
    services={<Button size="xs" variant="ghost" onClick={() => onOpen(environment.id)}>Ports & connections</Button>}
    status={error ? <span role="alert" className="text-destructive">{error}</span> : <span>{environment.status === "running" ? "Running" : environment.status === "provisioning" ? "Starting…" : "Stopped"}</span>}
    actions={<div className="flex gap-2">
      <Button size="xs" onClick={() => onOpen(environment.id)}>Open</Button>
      {environment.status === "running" ? <Button size="xs" variant="outline" disabled={busy} onClick={() => void stop()}>Stop</Button> : null}
    </div>}
    onConfigure={() => onOpen(environment.id)} onDoubleClick={event => { if (!(event.target as HTMLElement).closest("button, input")) onOpen(environment.id) }}
    details={<p className="text-xs">{environment.id} · Sandbox VM. Open this environment to run commands, manage permissions and review workspace changes.</p>} />
}
