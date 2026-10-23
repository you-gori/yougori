import { useEffect, useRef, useState } from "react"
import { vaultApi, type VaultPending } from "@/api/vault-api"
import { blockedBy } from "@/lib/vault-delete"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { AlertDialog, AlertDialogPopup, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter } from "@/components/ui/alert-dialog"

/** The word that has to be typed before the delete button does anything. */
const CONFIRM = "delete"

const text = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

/** Opened by the native right-click item on the vault row, which only dispatches an event and
 *  never deletes anything itself. Typing the word is the first gate; the protected broker then
 *  asks once more, and that approval is shown here, in this dialog: the person is already here,
 *  and a modal dialog would hide any other place to approve it. Nothing is destroyed until it is
 *  approved. */
export function VaultRowMenu() {
  const [open, setOpen] = useState(false)
  const [typed, setTyped] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  // What a finished delete could not clean up, each named by the app; empty when nothing is left.
  const [left, setLeft] = useState<string[]>([])
  // The vault's state when the dialog opened: still being read, fine to delete, or why not.
  const [check, setCheck] = useState<"checking" | "ready" | { blocked: string }>("checking")
  // The broker's own approval of this delete, once it asks.
  const [approval, setApproval] = useState<VaultPending | null>(null)
  const [deciding, setDeciding] = useState(false)
  // A request already sent to the broker must not be cancelled by closing this dialog.
  const pending = useRef(false)
  useEffect(() => {
    const requested = () => {
      if (pending.current) return
      setTyped(""); setError(""); setLeft([]); setApproval(null); setDeciding(false); setCheck("checking"); setOpen(true)
      void vaultApi.status()
        .then(status => { const blocked = blockedBy(status); setCheck(blocked ? { blocked } : "ready") })
        .catch(reason => setCheck({ blocked: `Yougori could not read Personal Vault’s state (${text(reason)}), so nothing is offered to delete. Try again in a moment.` }))
    }
    window.addEventListener("yougori-delete-vault", requested)
    return () => window.removeEventListener("yougori-delete-vault", requested)
  }, [])
  // While the delete waits, look for the broker's approval so it can be answered here.
  useEffect(() => {
    if (!busy) return
    let alive = true
    const look = () => void vaultApi.status()
      .then(status => { if (alive) setApproval(status.pending.find(request => request.destroy && request.ready) ?? null) })
      .catch(() => undefined)
    look()
    const timer = window.setInterval(look, 1000)
    return () => { alive = false; window.clearInterval(timer) }
  }, [busy])
  const ready = typed.trim().toLowerCase() === CONFIRM
  const destroy = async () => {
    if (pending.current || !ready) return
    pending.current = true; setBusy(true); setError(""); setApproval(null); setDeciding(false)
    try {
      // Only asks. The broker answers once the person approves or denies below.
      const result = (await vaultApi.control("destroy")) as unknown as { destroyed?: boolean; leftBehind?: string[] }
      if (result?.destroyed !== true) {
        // Never sent by this broker; said plainly rather than guessed at.
        setError("Personal Vault answered without saying the vault was deleted. Open Personal Vault to see whether it is still there.")
        return
      }
      // Deleted. Anything small that stayed behind is listed by name, and the dialog stays open
      // so it can be read: the vault is gone, and that must not read as a failed delete.
      if (result.leftBehind?.length) {
        setLeft(result.leftBehind)
        return
      }
      setOpen(false)
      // Nothing else to do: the status poll sees setup.created go false, which drops the row
      // and brings the "Create my personal vault MCP" button back on its own.
    } catch (reason) {
      setError(text(reason))
    } finally { pending.current = false; setBusy(false); setApproval(null); setDeciding(false) }
  }
  const decide = (action: "approve" | "deny") => {
    if (!approval || deciding) return
    setDeciding(true)
    // The delete itself answers once the broker has the decision; a failure here is said.
    vaultApi.control(action, approval.id).catch(reason => { setDeciding(false); setError(text(reason)) })
  }
  return <AlertDialog open={open} onOpenChange={value => { if (!pending.current) setOpen(value) }}>
    <AlertDialogPopup className="vault-delete-confirm">
      {left.length ? <>
        <AlertDialogHeader>
          <AlertDialogTitle>Your Personal Vault was deleted</AlertDialogTitle>
          <AlertDialogDescription>Every secret in it is gone. A few things on this computer could not be cleaned up afterwards:</AlertDialogDescription>
        </AlertDialogHeader>
        <ul className="vault-delete-left">{left.map(item => <li key={item}>{item}</li>)}</ul>
        <AlertDialogFooter>
          <Button onClick={() => setOpen(false)}>Done</Button>
        </AlertDialogFooter>
      </> : typeof check === "object" ? <>
        <AlertDialogHeader>
          <AlertDialogTitle>Personal Vault can’t be deleted right now</AlertDialogTitle>
          <AlertDialogDescription>{check.blocked} Nothing was deleted.</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Close</Button>
        </AlertDialogFooter>
      </> : <>
      <AlertDialogHeader>
        <AlertDialogTitle>Delete your Personal Vault?</AlertDialogTitle>
        <AlertDialogDescription>
          This destroys every secret in the vault, its approvals, its connected apps and its keys, along with its public link. The activity record is kept, without any secrets, and notes the deletion. Nothing else can be recovered, by you or by Yougori. After you confirm here, Personal Vault asks once more, in this dialog — nothing is deleted until you approve that too.
        </AlertDialogDescription>
      </AlertDialogHeader>
      {check === "checking" ? <p role="status" className="grid-hint">Checking Personal Vault…</p> : <label className="vault-delete-field">
        <span>Type <strong>{CONFIRM}</strong> to confirm</span>
        <Input value={typed} disabled={busy} autoComplete="off" aria-label={`Type ${CONFIRM} to confirm`} onChange={event => setTyped(event.target.value)} />
      </label>}
      {busy && approval ? <section aria-label="Personal Vault approval" className="vault-delete-approval">
        <p><strong>{approval.title ?? "Delete your Personal Vault?"}</strong></p>
        {approval.description ? <p className="grid-hint">{approval.description}</p> : null}
        <div className="vault-actions">
          <Button variant="outline" disabled={deciding} onClick={() => decide("deny")}>Keep my vault</Button>
          <Button variant="destructive" disabled={deciding} loading={deciding} onClick={() => decide("approve")}>{approval.allowLabel ?? "Delete everything"}</Button>
        </div>
      </section> : busy ? <p role="status" className="grid-hint">{deciding ? "Deleting your vault…" : "Waiting for Personal Vault to ask for your approval…"}</p> : null}
      {error ? <p role="alert" className="grid-error">{error}</p> : null}
      {busy ? null : <AlertDialogFooter>
        <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
        <Button variant="destructive" disabled={check !== "ready" || !ready} onClick={() => void destroy()}>Delete everything</Button>
      </AlertDialogFooter>}
      </>}
    </AlertDialogPopup>
  </AlertDialog>
}
