import { useEffect, useState } from "react"
import { accessApi, TWO_STEP_MESSAGE } from "@/api/access-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Address, ChoiceCards, Outcome, PopupGroup, QuickLinkNote, ReachCards, StillNeeded } from "@/components/popup-kit"
import "@/components/neo-grid.css"

const MIN_PASSWORD = 10
const PORT = 7465
const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

function PasswordFields({ password, again, busy, onPassword, onAgain, purpose, label = "Your password" }: { password: string; again: string; busy: boolean; onPassword(value: string): void; onAgain(value: string): void; purpose: string; label?: string }) {
  return <div className="grid-fields">
    <div className="grid-field">
      <label htmlFor="access-password">{label}</label>
      <Input id="access-password" type="password" value={password} disabled={busy} autoComplete="new-password" aria-describedby="access-password-rule" onChange={event => onPassword(event.target.value)} />
      <p id="access-password-rule" className="grid-hint" data-tone={password.length >= MIN_PASSWORD ? "ok" : password ? "short" : undefined}>
        {password.length >= MIN_PASSWORD ? `Long enough · ${password.length} characters` : password ? `${password.length} of ${MIN_PASSWORD} characters` : `At least ${MIN_PASSWORD} characters. A short sentence works well.`}
      </p>
    </div>
    <div className="grid-field">
      <label htmlFor="access-password-again">Type it again</label>
      <Input id="access-password-again" type="password" value={again} disabled={busy} autoComplete="new-password" onChange={event => onAgain(event.target.value)} />
      <p className="grid-hint" data-tone={again ? (again === password ? "ok" : "short") : undefined}>{again ? (again === password ? "Passwords match" : "The passwords do not match") : purpose}</p>
    </div>
  </div>
}

/** Runs an Access Grid on this computer, with the person creating it as its first admin. */
export function AccessHostDialog({ open, suggestedAddress, onOpenChange, onDone }: { open: boolean; suggestedAddress: string | null; onOpenChange(open: boolean): void; onDone(message?: string): void }) {
  const [company, setCompany] = useState("")
  const [address, setAddress] = useState("")
  const [username, setUsername] = useState("")
  const [name, setName] = useState("")
  const [reach, setReach] = useState<"network" | "quick">("network")
  const [password, setPassword] = useState("")
  const [again, setAgain] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => {
    if (!open) return
    setError("")
    if (suggestedAddress) setAddress(current => current || suggestedAddress)
  }, [open, suggestedAddress])

  const problem = !company.trim() ? "Add the company name to continue."
    : !address.trim() ? "Add this computer's address to continue."
    : !/^[a-z0-9][a-z0-9._-]{2,31}$/i.test(username.trim()) ? "Choose a username: 3 to 32 letters, digits, dots, dashes or underscores."
    : password.length < MIN_PASSWORD ? `Your password needs at least ${MIN_PASSWORD} characters.`
    : password !== again ? "The two passwords do not match yet."
    : ""

  const host = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      const result = await accessApi.create(company.trim(), address.trim(), username.trim(), name.trim(), password, reach === "quick" ? "quick" : undefined)
      setPassword(""); setAgain("")
      onDone(result.message)
      onOpenChange(false)
    } catch (reason) {
      setError(message(reason))
    } finally {
      setBusy(false)
    }
  }

  return <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Host an access grid</DialogTitle>
        <DialogDescription>This computer keeps your company's API keys and tokens. People sign in with their own passwords, and their agents use the keys through it without ever seeing them. You become its first admin.</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="popup-stack" onSubmit={event => { event.preventDefault(); void host() }}>
          <PopupGroup title="Company">
            <div className="grid-fields">
              <div className="grid-field">
                <label htmlFor="access-company">Company name</label>
                <Input id="access-company" value={company} disabled={busy} autoComplete="organization" placeholder="Acme" onChange={event => setCompany(event.target.value)} />
                <p className="grid-hint">Everyone who signs in sees this name.</p>
              </div>
              <div className="grid-field">
                <label htmlFor="access-address">This computer's address</label>
                <Input id="access-address" value={address} disabled={busy} placeholder="192.168.1.20" onChange={event => setAddress(event.target.value)} />
                <p className="grid-hint">Its IP address on your office network or VPN.</p>
              </div>
            </div>
          </PopupGroup>
          <div className="popup-group">
            <ReachCards who="people" value={reach} onPick={setReach} address={address} port={PORT} disabled={busy} />
            {reach === "quick" ? <QuickLinkNote who="people" /> : null}
          </div>
          <PopupGroup title="Your admin account" hint="You sign in to the grid with this username and password.">
            <div className="grid-fields">
              <div className="grid-field">
                <label htmlFor="access-username">Your username</label>
                <Input id="access-username" value={username} disabled={busy} autoComplete="username" placeholder="ada" onChange={event => setUsername(event.target.value)} />
              </div>
              <div className="grid-field">
                <label htmlFor="access-name">Your name</label>
                <Input id="access-name" value={name} disabled={busy} autoComplete="name" placeholder="Ada Lovelace" onChange={event => setName(event.target.value)} />
              </div>
            </div>
            <PasswordFields password={password} again={again} busy={busy} onPassword={setPassword} onAgain={setAgain} purpose="To be sure it is the one you meant." />
          </PopupGroup>
          <Outcome title="When you host">
            <p>
              This computer starts the grid{reach === "quick" ? " and its Cloudflare link" : ` on port ${PORT}`} and signs you in as its
              first admin. You then get an invite starting with <Address>access-invite:</Address> to send to people; they sign in
              with it and their own passwords.
            </p>
            <p>Agents reach the credentials only while this computer is on.</p>
          </Outcome>
          {busy ? <p role="status" className="popup-status">{reach === "quick" ? "Starting the grid and asking Cloudflare for its link. This can take up to a minute." : "Starting the grid."}</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          <button type="submit" hidden aria-hidden="true" tabIndex={-1} />
        </form>
      </DialogPanel>
      <DialogFooter>
        <StillNeeded>{busy ? "" : problem}</StillNeeded>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} onClick={() => void host()}>Host access grid</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}

/** Signs this person in to their company's Access Grid with the admin's invite: with their
 *  password (and two-step code), or through the company's identity provider. */
export function AccessSignInDialog({ open, onOpenChange, onDone }: { open: boolean; onOpenChange(open: boolean): void; onDone(message?: string): void }) {
  const [invite, setInvite] = useState("")
  const [way, setWay] = useState<"password" | "company">("password")
  const [username, setUsername] = useState("")
  const [password, setPassword] = useState("")
  const [code, setCode] = useState("")
  const [needsCode, setNeedsCode] = useState(false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")

  useEffect(() => { if (open) { setError(""); setNeedsCode(false); setCode("") } }, [open])

  const inviteProblem = !invite.trim() ? "Paste the invite your admin sent you."
    : !invite.trim().startsWith("access-invite:") ? "That is not an access grid invite. Paste the whole code, starting with access-invite:"
    : ""
  const problem = inviteProblem || (way === "company" ? ""
    : !username.trim() ? "Add your username to continue."
    : !password ? "Add your password to continue."
    : needsCode && !/^\d{6}$/.test(code.trim()) ? "Add the six digits your authenticator app shows."
    : "")

  const signIn = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      const result = way === "company"
        ? await accessApi.signInSso(invite.trim())
        : await accessApi.signIn(invite.trim(), username.trim(), password, needsCode ? code.trim() : undefined)
      setPassword(""); setCode("")
      onDone(result.message)
      onOpenChange(false)
    } catch (reason) {
      const text = message(reason)
      if (text === TWO_STEP_MESSAGE) setNeedsCode(true)
      else setError(text)
    } finally {
      setBusy(false)
    }
  }

  return <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Sign in to an access grid</DialogTitle>
        <DialogDescription>Use the invite your admin sent you. Your agents on this computer can then use the company credentials your admin allows, without ever seeing them.</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="popup-stack" onSubmit={event => { event.preventDefault(); void signIn() }}>
          <div className="grid-field">
            <label htmlFor="access-invite">Invite from your admin</label>
            <Input id="access-invite" value={invite} disabled={busy} placeholder="access-invite:…" autoComplete="off" spellCheck={false} onChange={event => setInvite(event.target.value)} />
            <p className="grid-hint">It lets this computer check that it reaches your company's real grid.</p>
          </div>
          <ChoiceCards
            label="How you sign in"
            value={way}
            onPick={setWay}
            disabled={busy}
            options={[
              { value: "password", title: "Sign-in details from your admin", detail: "The username and password your admin set up for you. Your password never leaves this computer." },
              { value: "company", title: "Company account", detail: "If your admin turned on single sign-on, your browser opens your company's sign-in page and then comes back here." },
            ]}
          />
          {way === "password" ? <div className="grid-fields">
            <div className="grid-field">
              <label htmlFor="access-signin-username">Username</label>
              <Input id="access-signin-username" value={username} disabled={busy} autoComplete="username" onChange={event => setUsername(event.target.value)} />
            </div>
            <div className="grid-field">
              <label htmlFor="access-signin-password">Password</label>
              <Input id="access-signin-password" type="password" value={password} disabled={busy} autoComplete="current-password" onChange={event => setPassword(event.target.value)} />
            </div>
          </div> : null}
          {way === "password" && needsCode ? <div className="grid-field">
            <label htmlFor="access-signin-code">Two-step code</label>
            <Input id="access-signin-code" value={code} disabled={busy} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" autoFocus onChange={event => setCode(event.target.value)} />
            <p className="grid-hint">Your account has two-step sign-in on: give the six digits your authenticator app shows now.</p>
          </div> : null}
          <p className="popup-note">This computer stays signed in until you sign out, your password changes, or it goes unused for 30 days.</p>
          {busy && way === "company" ? <p role="status" className="popup-status">Finish signing in on your company's page in the browser.</p> : null}
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

/** A file path, typed or chosen with the system dialog where the desktop app has one. */
function FileField({ id, label, value, onChange, save, disabled, hint }: { id: string; label: string; value: string; onChange(value: string): void; save: boolean; disabled: boolean; hint?: string }) {
  const choose = async () => {
    try {
      const dialog = await import("@tauri-apps/plugin-dialog")
      const filters = [{ name: "Access Grid backup", extensions: ["backup"] }]
      const chosen = save ? await dialog.save({ defaultPath: "access-grid.backup", filters }) : await dialog.open({ multiple: false, directory: false, filters })
      if (typeof chosen === "string") onChange(chosen)
    } catch {
      // No system dialog here: the path is typed instead.
    }
  }
  return <div className="grid-field">
    <label htmlFor={id}>{label}</label>
    <div className="access-file">
      <Input id={id} value={value} disabled={disabled} spellCheck={false} placeholder="D:/backups/access-grid.backup" onChange={event => onChange(event.target.value)} />
      <Button type="button" size="sm" variant="outline" disabled={disabled} onClick={() => void choose()}>Choose…</Button>
    </div>
    {hint ? <p className="grid-hint">{hint}</p> : null}
  </div>
}

/** Writes an encrypted backup of the grid this computer runs: record, activity log and keys. */
export function AccessBackupDialog({ open, onOpenChange, onDone }: { open: boolean; onOpenChange(open: boolean): void; onDone(message?: string): void }) {
  const [output, setOutput] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [again, setAgain] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  useEffect(() => { if (open) setError("") }, [open])
  const problem = !output.trim() ? "Choose where to write the backup."
    : passphrase.length < MIN_PASSWORD ? `The passphrase needs at least ${MIN_PASSWORD} characters.`
    : passphrase !== again ? "The two passphrases do not match yet."
    : ""
  const write = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      const result = await accessApi.backup(output.trim(), passphrase)
      setPassphrase(""); setAgain("")
      onDone(result.message)
      onOpenChange(false)
    } catch (reason) {
      setError(message(reason))
    } finally {
      setBusy(false)
    }
  }
  return <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Back up the access grid</DialogTitle>
        <DialogDescription>Writes one encrypted file with the grid's people, credentials, rules, activity log and keys. With its passphrase it brings the grid back on this or another computer, and people's computers keep trusting it.</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="popup-stack" onSubmit={event => { event.preventDefault(); void write() }}>
          <FileField id="access-backup-file" label="Backup file" value={output} onChange={setOutput} save disabled={busy} hint="Somewhere off this computer is best, such as a USB drive or a network share." />
          <PasswordFields password={passphrase} again={again} busy={busy} onPassword={setPassphrase} onAgain={setAgain} purpose="To be sure it is the one you meant." label="Passphrase" />
          <Outcome title="Keep them apart">
            <p>Store the file and its passphrase in different places: together they open every credential in the grid. Without the passphrase, nobody can restore it, including you.</p>
          </Outcome>
          {busy ? <p role="status" className="popup-status">Writing and checking the backup.</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          <button type="submit" hidden aria-hidden="true" tabIndex={-1} />
        </form>
      </DialogPanel>
      <DialogFooter>
        <StillNeeded>{busy ? "" : problem}</StillNeeded>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} onClick={() => void write()}>Write backup</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}

/** Runs an access grid on this computer from a backup. */
export function AccessRestoreDialog({ open, suggestedAddress, onOpenChange, onDone }: { open: boolean; suggestedAddress: string | null; onOpenChange(open: boolean): void; onDone(message?: string): void }) {
  const [file, setFile] = useState("")
  const [address, setAddress] = useState("")
  const [passphrase, setPassphrase] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  useEffect(() => {
    if (!open) return
    setError("")
    if (suggestedAddress) setAddress(current => current || suggestedAddress)
  }, [open, suggestedAddress])
  const problem = !file.trim() ? "Choose the backup file."
    : !address.trim() ? "Add this computer's address to continue."
    : !passphrase ? "Add the backup's passphrase to continue."
    : ""
  const restore = async () => {
    if (busy || problem) return
    setBusy(true); setError("")
    try {
      const result = await accessApi.restoreBackup(file.trim(), passphrase, address.trim())
      setPassphrase("")
      onDone(result.message)
      onOpenChange(false)
    } catch (reason) {
      setError(message(reason))
    } finally {
      setBusy(false)
    }
  }
  return <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="grid-dialog" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>Restore an access grid</DialogTitle>
        <DialogDescription>Runs your company's access grid on this computer from a backup file and its passphrase.</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <form className="popup-stack" onSubmit={event => { event.preventDefault(); void restore() }}>
          <FileField id="access-restore-file" label="Backup file" value={file} onChange={setFile} save={false} disabled={busy} />
          <div className="grid-fields">
            <div className="grid-field">
              <label htmlFor="access-restore-address">This computer's address</label>
              <Input id="access-restore-address" value={address} disabled={busy} placeholder="192.168.1.20" onChange={event => setAddress(event.target.value)} />
              <p className="grid-hint">Its IP address on your office network or VPN.</p>
            </div>
            <div className="grid-field">
              <label htmlFor="access-restore-passphrase">Backup passphrase</label>
              <Input id="access-restore-passphrase" type="password" value={passphrase} disabled={busy} autoComplete="off" onChange={event => setPassphrase(event.target.value)} />
            </div>
          </div>
          <Outcome title="After restoring">
            <p>
              The grid runs here, at {address.trim() ? <Address>{address.trim()}:{PORT}</Address> : `this computer's address on port ${PORT}`},
              with everything the backup holds. People sign in at the new address with a new invite; their computers move over
              without a password.
            </p>
          </Outcome>
          {busy ? <p role="status" className="popup-status">Opening the backup and starting the grid.</p> : null}
          {error ? <p role="alert" className="grid-error">{error}</p> : null}
          <button type="submit" hidden aria-hidden="true" tabIndex={-1} />
        </form>
      </DialogPanel>
      <DialogFooter>
        <StillNeeded>{busy ? "" : problem}</StillNeeded>
        <DialogClose render={<Button variant="outline" disabled={busy} />}>Cancel</DialogClose>
        <Button disabled={busy || Boolean(problem)} loading={busy} onClick={() => void restore()}>Restore grid</Button>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
