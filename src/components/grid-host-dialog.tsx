import { useEffect, useState } from "react"
import { gridApi, type GridReach } from "@/api/grid-api"
import { desksApi } from "@/api/desks-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Address, Outcome, PopupGroup, QuickLinkNote, ReachCards, StillNeeded } from "@/components/popup-kit"
import "@/components/neo-grid.css"

const MIN_PASSWORD = 10

/** Hosts a Closed Neo Grid on this computer: the company's own computers join it with the password.
 *  With `variant="desks"` it hosts a Sandbox Grid instead: its own hub, where company computers host desks. */
export function GridHostDialog({ open, onOpenChange, onHosted, variant = "grid" }: { open: boolean; onOpenChange(open: boolean): void; onHosted(message?: string): void; variant?: "grid" | "desks" }) {
  const desks = variant === "desks"
  const port = desks ? 7463 : 7460
  const [company, setCompany] = useState("")
  const [address, setAddress] = useState("")
  const [reach, setReach] = useState<GridReach>("network")
  const [password, setPassword] = useState("")
  const [again, setAgain] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!open) return
    setError("")
    void (desks ? desksApi.suggestedAddress() : gridApi.suggestedAddress()).then(found => { if (found) setAddress(current => current || found) }).catch(() => undefined)
  }, [open, desks])

  const problem = !company.trim() ? "Add the company name to continue."
    : !address.trim() ? "Add this computer's address to continue."
    : password.length < MIN_PASSWORD ? `The password needs at least ${MIN_PASSWORD} characters.`
    : password !== again ? "The two passwords do not match yet."
    : ""

  const host = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      const result = desks ? await desksApi.create(company.trim(), address.trim(), password, reach) : await gridApi.create(company.trim(), address.trim(), password, reach)
      setPassword(""); setAgain("")
      onHosted(result.message)
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
        <DialogTitle>{desks ? "Host a sandbox grid" : "Host a grid"}</DialogTitle>
        <DialogDescription>{desks
          ? "This computer becomes the hub of your company's sandbox grid. Company computers join it with an invite and the password, then host desks for people within the share you set for each."
          : "This computer becomes the hub of your company's private model grid. Company computers join it with an invite and the password, and you choose which models they run."}</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="popup-stack" onSubmit={event => { event.preventDefault(); void host() }}>
          <PopupGroup title="Company">
            <div className="grid-fields">
              <div className="grid-field">
                <label htmlFor="grid-company">Company name</label>
                <Input id="grid-company" value={company} disabled={busy} autoComplete="organization" placeholder="Acme" onChange={event => setCompany(event.target.value)} />
                <p className="grid-hint">Everyone who joins sees this name.</p>
              </div>
              <div className="grid-field">
                <label htmlFor="grid-address">This computer's address</label>
                <Input id="grid-address" value={address} disabled={busy} placeholder="192.168.1.20" onChange={event => setAddress(event.target.value)} />
                <p className="grid-hint">Its IP address on your Wi-Fi, office network or VPN.</p>
              </div>
            </div>
          </PopupGroup>
          <div className="popup-group">
            <ReachCards who="computers" value={reach} onPick={setReach} address={address} port={port} disabled={busy} />
            {reach === "quick" ? <QuickLinkNote who="computers" /> : null}
          </div>
          <PopupGroup title="Password" hint="Every computer that joins needs it. Send it separately from the invite.">
            <div className="grid-fields">
              <div className="grid-field">
                <label htmlFor="grid-password">Company password</label>
                <Input id="grid-password" type="password" value={password} disabled={busy} autoComplete="new-password" aria-describedby="grid-password-rule" onChange={event => setPassword(event.target.value)} />
                <p id="grid-password-rule" className="grid-hint" data-tone={password.length >= MIN_PASSWORD ? "ok" : password ? "short" : undefined}>
                  {password.length >= MIN_PASSWORD ? `Long enough · ${password.length} characters` : password ? `${password.length} of ${MIN_PASSWORD} characters` : `At least ${MIN_PASSWORD} characters. A short sentence works well.`}
                </p>
              </div>
              <div className="grid-field">
                <label htmlFor="grid-password-again">Type it again</label>
                <Input id="grid-password-again" type="password" value={again} disabled={busy} autoComplete="new-password" aria-describedby="grid-password-match" onChange={event => setAgain(event.target.value)} />
                <p id="grid-password-match" className="grid-hint" data-tone={again ? (again === password ? "ok" : "short") : undefined}>
                  {again ? (again === password ? "Passwords match" : "The passwords do not match") : "To be sure it is the one you meant."}
                </p>
              </div>
            </div>
          </PopupGroup>
          <Outcome title="When you host">
            <p>
              This computer starts the hub{reach === "quick" ? " and its Cloudflare link" : ` on port ${port}`}, and you get an invite
              starting with <Address>{desks ? "desk-invite:" : "grid-invite:"}</Address> to send to your company's computers.
              They join with the invite and the password.
            </p>
            <p>The grid works while this computer is on.</p>
          </Outcome>
          {busy ? <p role="status" className="popup-status">{reach === "quick" ? "Starting the hub and asking Cloudflare for its link. This can take up to a minute." : "Starting the hub."}</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          <button type="submit" hidden aria-hidden="true" tabIndex={-1} />
        </form>
      </DialogPanel>
      <DialogFooter>
        <StillNeeded>{busy ? "" : problem}</StillNeeded>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} onClick={() => void host()}>Host grid</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
