import { useState } from "react"
import { discardable, duplicationApi } from "@/api/duplication-api"
import { copyFor, providerName } from "@/lib/environment-copies"
import type { DuplicateDestination } from "@/components/environment-duplicate-action"
import { usePlatform } from "@/context/platform-context"
import type { Environment } from "@/types/platform"
import { Button } from "@/components/ui/button"
import { GiveUpCopy } from "@/components/give-up-copy"

/** What a copy needs from its person, on its row: how far it has got while it runs, where to resume
 *  or discard it once it stops, and the transfer resources a finished copy could not remove, which
 *  are billed until they go. The Copies window this replaces is gone at the owner's request; this is
 *  only what a person must still be able to reach. */
export function EnvironmentCopyStatus({ environment, onOpen }: { environment: Environment; onOpen(sourceId: string, destination: DuplicateDestination): void }) {
  const { state, refreshPlatform } = usePlatform()
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const found = copyFor(environment, state?.duplicationJobs ?? {}, state?.environments ?? [])
  if (!found) return null
  const [id, job] = found
  const own = job.environmentId === environment.id
  const leftover = job.status === "complete" && !job.completed?.cleanup && Boolean(job.error)
  if (job.status === "complete" && !leftover) return null
  const remove = async () => {
    if (busy) return
    setBusy(true); setError("")
    try { await duplicationApi.cleanup(id) } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { await refreshPlatform().catch(() => undefined); setBusy(false) }
  }
  const sourceThere = state?.environments.some(other => other.id === job.request.environmentId) ?? false
  const destination: DuplicateDestination = job.request.localFiles ? "local" : job.request.destination
  return <div className="nodrag mt-2 space-y-1 break-words text-[11px]" onClick={event => event.stopPropagation()}>
    {job.status === "running"
      ? <p role="status" className="text-muted-foreground">{own ? "Being copied" : `Copying to ${job.request.name}`}: {job.phase}…</p>
      : leftover
        ? <>
          <p role="status">Copied, but transfer resources it used are still at {providerName(job)}, and they are billed until they go.</p>
          <Button type="button" size="xs" variant="outline" loading={busy} disabled={busy} onClick={() => void remove()}>Remove them</Button>
        </>
        : <>
          <p role="status">{own ? "This copy" : `The copy ${job.request.name}`} stopped part way.{sourceThere ? "" : " Its original is gone, so it cannot be resumed."}</p>
          {sourceThere
            ? <Button type="button" size="xs" variant="outline" onClick={() => onOpen(job.request.environmentId, destination)}>Resume or discard</Button>
            : discardable(job)
              ? <Button type="button" size="xs" variant="outline" loading={busy} disabled={busy} onClick={() => void remove()}>Discard it</Button>
              : job.pending
                ? <p className="text-muted-foreground">What it made at {providerName(job)} is still there and is billed until it goes: {job.resources.join(", ")}. A step’s result was never written down, so Yougori cannot remove it safely: remove it in {providerName(job)}’s console, where it carries this copy’s ID, {id}.</p>
                : <><p className="text-muted-foreground">What it made at {providerName(job)} is still there and is billed until it goes: {job.resources.join(", ")}.</p><GiveUpCopy id={id} job={job} /></>}
        </>}
    {error ? <p role="alert" className="whitespace-pre-wrap text-destructive-foreground">{error}</p> : null}
  </div>
}
