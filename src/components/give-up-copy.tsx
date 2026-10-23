import { useRef, useState } from "react"
import { duplicationApi, type DuplicationJob } from "@/api/duplication-api"
import { usePlatform } from "@/context/platform-context"
import { providerName } from "@/lib/environment-copies"
import { Button } from "@/components/ui/button"
import { AlertDialog, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogPopup, AlertDialogTitle } from "@/components/ui/alert-dialog"

/** Gives up a cloud copy that stopped part way, after asking. It removes what the copy made at the
 *  provider, and the copy cannot be resumed afterwards, so it is never one click: this button only
 *  opens the question, and only the question's confirm asks the engine. */
export function GiveUpCopy({ id, job, onDone }: { id: string; job: DuplicationJob; onDone?(): void }) {
  const { refreshPlatform } = usePlatform()
  const [asking, setAsking] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const guard = useRef(false)
  const where = providerName(job)
  const confirm = async () => {
    if (guard.current) return
    guard.current = true; setBusy(true); setError("")
    try {
      await duplicationApi.abandon(id)
      setAsking(false)
      onDone?.()
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { guard.current = false; setBusy(false); await refreshPlatform().catch(() => undefined) }
  }
  return <>
    <Button type="button" size="xs" variant="outline" onClick={() => { setError(""); setAsking(true) }}>Give up this copy</Button>
    <AlertDialog open={asking} onOpenChange={open => { if (!guard.current) setAsking(open) }}>
      <AlertDialogPopup>
        <AlertDialogHeader>
          <AlertDialogTitle>Give up {job.request.name}?</AlertDialogTitle>
          <AlertDialogDescription>This removes the disks and images this copy made at {where}, and the copy cannot be resumed afterwards. The original is not changed.</AlertDialogDescription>
        </AlertDialogHeader>
        {error ? <p role="alert" className="whitespace-pre-wrap px-6 text-sm text-destructive-foreground">{error}</p> : null}
        <AlertDialogFooter>
          <Button variant="outline" disabled={busy} onClick={() => setAsking(false)}>Keep the copy</Button>
          <Button variant="destructive" loading={busy} disabled={busy} onClick={() => void confirm()}>Remove them and give up</Button>
        </AlertDialogFooter>
      </AlertDialogPopup>
    </AlertDialog>
  </>
}
