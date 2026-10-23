import { useEffect, useState } from "react"
import { desksApi, readDeskInvite } from "@/api/desks-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Address, ChoiceCards, Outcome, StillNeeded } from "@/components/popup-kit"
import "@/components/neo-grid.css"

/** A person signs in to their company's grid and opens the desks the admin gave them. */
export function DeskLoginDialog({ open, onOpenChange, onSignedIn }: { open: boolean; onOpenChange(open: boolean): void; onSignedIn(message: string): void }) {
  const [code, setCode] = useState("")
  const [way, setWay] = useState<"password" | "company">("password")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [otp, setOtp] = useState("")
  const [needsCode, setNeedsCode] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => { if (open) { setError(""); setNeedsCode(false); setOtp("") } }, [open])

  const invite = code.trim() ? readDeskInvite(code) : null
  const problem = !code.trim() ? "Paste the invite your admin sent you."
    : !invite ? "That is not a sandbox grid invite. Paste the whole code, starting with desk-invite:"
    : way === "company" ? ""
    : !username.trim() ? "Add your username to continue."
    : !password ? "Add your password to continue."
    : needsCode && otp.trim().length !== 6 ? "Add the six digits your authenticator app shows."
    : ""

  const signIn = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      // The company's identity provider signs them in from the invite alone; the browser does the rest.
      const result = way === "company"
        ? await desksApi.loginSso(code.trim())
        : await desksApi.login(code.trim(), username.trim(), password, needsCode ? otp.trim() : undefined)
      setPassword("")
      setOtp("")
      const ready = result.desks.filter(desk => desk.state === "ready" && desk.environmentId).length
      onSignedIn(ready ? `Signed in to ${result.grid}: ${ready === 1 ? "your desk is" : `${ready} desks are`} in your sandbox list` : `Signed in to ${result.grid}; no desk is ready yet`)
      onOpenChange(false)
    } catch (reason) {
      const text = reason instanceof Error ? reason.message : String(reason)
      // The password was right; the hub now wants the second step.
      if (way === "password" && text.includes("authenticator app") && !needsCode) { setNeedsCode(true); setError("") } else setError(text)
    } finally {
      setBusy(false)
    }
  }

  return <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Open my desk</DialogTitle>
        <DialogDescription>Sign in to your company's sandbox grid with the invite your admin sent you. Each desk that is ready then appears in your sandbox list.</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="popup-stack" onSubmit={event => { event.preventDefault(); void signIn() }}>
          <div className="grid-field">
            <label htmlFor="desk-invite">Grid invite from your admin</label>
            <textarea id="desk-invite" className="grid-textarea" rows={3} value={code} disabled={busy} spellCheck={false} placeholder="desk-invite:…" onChange={event => setCode(event.target.value)} />
            {invite ? <p className="grid-hint"><strong>{invite.company}</strong> at <Address>{invite.address}</Address></p> : null}
          </div>
          <ChoiceCards
            label="How you sign in"
            value={way}
            onPick={setWay}
            disabled={busy}
            options={[
              { value: "password", title: "Sign-in details from your admin", detail: "The username and password your admin set up for you." },
              { value: "company", title: "Company account", detail: "If your admin turned on single sign-on, your browser opens your company's sign-in page and then comes back here." },
            ]}
          />
          {way === "password" ? <div className="grid-fields">
            <div className="grid-field">
              <label htmlFor="desk-username">Username</label>
              <Input id="desk-username" value={username} disabled={busy} autoComplete="username" spellCheck={false} onChange={event => setUsername(event.target.value)} />
            </div>
            <div className="grid-field">
              <label htmlFor="desk-password">Password</label>
              <Input id="desk-password" type="password" value={password} disabled={busy} autoComplete="current-password" onChange={event => setPassword(event.target.value)} />
            </div>
            {needsCode ? <div className="grid-field">
              <label htmlFor="desk-otp">Code from your authenticator app</label>
              <Input id="desk-otp" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={otp} disabled={busy} autoFocus onChange={event => setOtp(event.target.value.replace(/\D/g, ""))} />
            </div> : null}
          </div> : null}
          <Outcome title="After you sign in">
            <p>Each desk your admin gave you appears in your sandbox list as soon as it is ready, and opens like any other sandbox.</p>
          </Outcome>
          {busy ? <p role="status" className="popup-status">{way === "company" ? "Finish signing in on your company's page in the browser." : "Signing in and opening your desks."}</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          <button type="submit" hidden aria-hidden="true" tabIndex={-1} />
        </form>
      </DialogPanel>
      <DialogFooter>
        <StillNeeded>{busy ? "" : problem}</StillNeeded>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} onClick={() => void signIn()}>{way === "company" ? "Continue in the browser" : "Sign in"}</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
