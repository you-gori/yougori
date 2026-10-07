import { useEffect, useState } from "react"
import { duplicationApi } from "@/api/duplication-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Dialog, DialogTrigger, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel } from "@/components/ui/dialog"

export function DuplicationActivity() {
  const { state, refreshPlatform, duplicateEnvironment, environmentActions } = usePlatform()
  const [open, setOpen] = useState(false)
  const [pending, setPending] = useState<string | null>(null)
  const [error, setError] = useState("")
  const jobs = Object.entries(state?.duplicationJobs ?? {}).reverse()
  const running = jobs.some(([, job]) => job.status === "running")
  useEffect(() => {
    if (!running && !open) return
    const timer = window.setInterval(() => void refreshPlatform().catch(() => undefined), 2500)
    return () => window.clearInterval(timer)
  }, [running, open, refreshPlatform])
  const perform = async (id: string, action: () => Promise<unknown>) => {
    if (pending) return
    setPending(id); setError("")
    try { await action() } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { await refreshPlatform().catch(() => undefined); setPending(null) }
  }
  if (!jobs.length) return null
  return <Dialog open={open} onOpenChange={setOpen}>
    <DialogTrigger render={<Button size="xs" variant="ghost" className="workspace-footer-reclaim" />}>Copies{running ? "…" : ""}</DialogTrigger>
    <DialogPopup className="max-w-3xl">
      <DialogHeader><DialogTitle>Environment copies</DialogTitle><DialogDescription>Progress, recovery and transfer-resource cleanup.</DialogDescription></DialogHeader>
      <DialogPanel className="space-y-3">
        {jobs.map(([id, job]) => {
          const active = job.status === "running" || Boolean(environmentActions[job.request.environmentId])
          const sourceExists = state?.environments.some(environment => environment.id === job.request.environmentId)
          return <section aria-label={job.request.name} key={id} className="space-y-2 rounded-lg border p-3 text-xs">
            <div className="flex items-center justify-between gap-3"><strong>{job.request.name}</strong><span className="text-muted-foreground">{job.request.destination === "cloud" ? job.request.target?.provider : "Local"}</span></div>
            <p role="status">{job.phase}{active ? "…" : ""}</p>
            {job.error ? <p className="whitespace-pre-wrap text-destructive-foreground">{job.error}</p> : null}
            <div className="flex gap-2">
              {job.status !== "complete" ? <Button type="button" size="xs" variant="outline" disabled={active || Boolean(pending) || !sourceExists} loading={pending === id} onClick={() => void perform(id, () => duplicateEnvironment(job.request))}>Resume copy</Button> : !job.completed?.cleanup ? <Button type="button" size="xs" variant="outline" disabled={Boolean(pending)} loading={pending === id} onClick={() => void perform(id, () => duplicationApi.cleanup(id))}>Clean up transfer resources</Button> : <span className="text-muted-foreground">Transfer resources cleaned up</span>}
              {job.status !== "complete" && !active && (!job.resources.length || job.request.localFiles) ? <Button type="button" size="xs" variant="ghost" disabled={Boolean(pending)} onClick={() => void perform(id, () => duplicationApi.cleanup(id))}>Discard copy</Button> : null}
            </div>
            {job.resources.length ? <details><summary>Resource history</summary><ul className="mt-2 space-y-1">{job.resources.map(resource => <li className="break-all" key={resource}>{resource}</li>)}</ul>{job.status !== "complete" ? <p className="mt-2 text-muted-foreground">{job.request.localFiles ? "Resume to finish the copy, or discard its transfer job. Discarding keeps the local environment and any copied files for inspection." : "Resources are retained so this copy can resume. They may incur charges; inspect them in the provider console before abandoning a copy."}</p> : null}</details> : null}
          </section>
        })}
        {error ? <p role="alert" className="text-sm text-destructive-foreground">{error}</p> : null}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
