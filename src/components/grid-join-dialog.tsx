import { useEffect, useState } from "react"
import { gridApi, readInvite, type GridMembership } from "@/api/grid-api"
import { desksApi, readDeskInvite } from "@/api/desks-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Address, Outcome, StillNeeded } from "@/components/popup-kit"
import "@/components/neo-grid.css"

const fingerprint = (value: string) => value.replace(/:/g, "").toUpperCase()

/** Joins a company's Closed Neo Grid from the invite its admin shared. With `variant="desks"` it joins
 *  a Sandbox Grid instead, so this computer hosts desks within the share its admin sets. */
export function GridJoinDialog({ open, onOpenChange, membership, onJoined, variant = "grid" }: { open: boolean; onOpenChange(open: boolean): void; membership: GridMembership | null; onJoined(message?: string): void; variant?: "grid" | "desks" }) {
  const desks = variant === "desks"
  const [code, setCode] = useState("")
  const [password, setPassword] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => { if (open) setError("") }, [open])

  const invite = code.trim() ? (desks ? readDeskInvite(code) : readInvite(code)) : null
  // A new invite for the grid this computer is already in only moves it to the hub's new address.
  const moving = !desks && Boolean(invite && membership && fingerprint(membership.fingerprint) === invite.fingerprint)
  const otherGrid = Boolean(invite && membership && !moving)
  const problem = !code.trim() ? "Paste the invite your admin sent you."
    : !invite ? (desks ? "That is not a sandbox grid invite. Paste the whole code, starting with desk-invite:" : "That is not a grid invite. Paste the whole code, starting with grid-invite:")
    : otherGrid ? `This computer is already in ${membership!.grid}'s grid. Leave it first.`
    : !moving && !password ? "Add the company password to continue."
    : ""

  const join = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      const result = desks ? await desksApi.join(code.trim(), password) : await gridApi.join(code.trim(), moving ? undefined : password)
      setCode(""); setPassword("")
      onJoined(result.message)
      onOpenChange(false)
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setBusy(false)
    }
  }

  return <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>{desks ? "Join a sandbox grid" : "Join a closed grid"}</DialogTitle>
        <DialogDescription>{desks
          ? "This computer joins your company's sandbox grid and hosts desks for colleagues, within the share of its processor, memory and disk your admin sets, whether or not you are using it."
          : "This computer joins your company's private model grid. The admin then decides which model it runs and when it serves."}</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="popup-stack" onSubmit={event => { event.preventDefault(); void join() }}>
          <div className="grid-field">
            <label htmlFor="grid-invite">Invite from your admin</label>
            <textarea id="grid-invite" className="grid-textarea" rows={3} value={code} disabled={busy} spellCheck={false} placeholder={desks ? "desk-invite:…" : "grid-invite:…"} onChange={event => setCode(event.target.value)} />
            <p className="grid-hint">It names the grid and how to reach it. Your admin sends the password separately.</p>
          </div>
          {invite ? <Outcome title={moving ? "Moving to the hub's new address" : "You are joining"}>
            <p><strong>{invite.company}</strong> at <Address>{invite.address}</Address></p>
            <p>{moving
              ? "This computer is already in this grid. The invite only moves it to the new address, so no password is needed."
              : desks
                ? "This computer connects to the hub. Your admin then sets its share, and desks for colleagues run on it within that share."
                : "This computer connects to the hub and waits for the admin to choose which model it runs."}</p>
          </Outcome> : null}
          {moving ? null : <div className="grid-field">
            <label htmlFor="grid-join-password">Company password</label>
            <Input id="grid-join-password" type="password" value={password} disabled={busy} autoComplete="current-password" onChange={event => setPassword(event.target.value)} />
          </div>}
          {busy ? <p role="status" className="popup-status">Joining the grid. A link that was only just created can take a few seconds to answer.</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          <button type="submit" hidden aria-hidden="true" tabIndex={-1} />
        </form>
      </DialogPanel>
      <DialogFooter>
        <StillNeeded>{busy ? "" : problem}</StillNeeded>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} onClick={() => void join()}>{moving ? "Move to the new address" : "Join grid"}</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
