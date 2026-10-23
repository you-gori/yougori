import { useState, type FormEvent } from "react"
import { accessApi, type AccessMe } from "@/api/access-api"
import type { AccessRun } from "@/components/access-admin"
import { useArmed } from "@/components/use-armed"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import "@/components/neo-grid.css"
import "@/components/access-grid.css"

const MIN_PASSWORD = 10

function ago(at: number) {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - at)
  if (seconds < 60) return "just now"
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`
  return new Date(at * 1000).toLocaleDateString()
}

/** Turning two-step sign-in on: the secret for the authenticator app, then its first code. */
function TwoStep({ me, run }: { me: AccessMe; run: AccessRun }) {
  const [started, setStarted] = useState<{ secret: string; link: string } | null>(null)
  const [code, setCode] = useState("")
  const [turningOff, setTurningOff] = useState(false)
  const on = me.person.twoStep
  const start = () => void run("Starting two-step sign-in", async () => {
    const answer = await accessApi.account({ action: "twoStepStart" }) as { secret?: string; link?: string }
    setStarted({ secret: answer.secret ?? "", link: answer.link ?? "" })
    setCode("")
    return answer
  })
  const confirm = (event: FormEvent) => {
    event.preventDefault()
    if (!/^\d{6}$/.test(code.trim())) return
    void run("Turning on two-step sign-in", () => accessApi.account({ action: "twoStepConfirm", code: code.trim() }), "Two-step sign-in is on").then(ok => { if (ok) { setStarted(null); setCode("") } })
  }
  const off = (event: FormEvent) => {
    event.preventDefault()
    if (!/^\d{6}$/.test(code.trim())) return
    void run("Turning off two-step sign-in", () => accessApi.account({ action: "twoStepOff", code: code.trim() }), "Two-step sign-in is off").then(ok => { if (ok) { setTurningOff(false); setCode("") } })
  }
  return <div className="access-row">
    <div className="grid-line">
      <span className="grid-key">Two-step</span>
      <span className="grid-muted">{on ? "On: new sign-ins ask for the code from your authenticator app" : me.twoStepRequired ? "Required by your company and not on yet" : "Off: a password alone signs you in"}{me.strong ? " · this sign-in had a second factor" : ""}</span>
      <span className="grid-line-actions">
        {on ? <Button size="xs" variant="outline" aria-expanded={turningOff} onClick={() => { setTurningOff(value => !value); setCode("") }}>Turn off</Button> : <Button size="xs" disabled={Boolean(started)} onClick={start}>Turn on</Button>}
      </span>
    </div>
    {started ? <form className="grid-form-block" aria-label="Confirm two-step sign-in" onSubmit={confirm}>
      <p className="grid-hint">Add this to your authenticator app: scan the link as a QR code where your app can, or type the secret. Then give the six digits it shows.</p>
      <div className="grid-line grid-command"><span className="grid-command-label">Secret</span><code>{started.secret}</code></div>
      <div className="grid-line grid-command"><span className="grid-command-label">Link</span><code>{started.link}</code></div>
      <div className="access-inline grid-line">
        <Input aria-label="Six-digit code" value={code} inputMode="numeric" autoComplete="one-time-code" placeholder="123456" onChange={event => setCode(event.target.value)} />
        <Button type="submit" size="xs" disabled={!/^\d{6}$/.test(code.trim())}>Confirm</Button>
        <Button type="button" size="xs" variant="ghost" onClick={() => setStarted(null)}>Cancel</Button>
      </div>
    </form> : null}
    {turningOff ? <form className="access-inline grid-line" aria-label="Turn off two-step sign-in" onSubmit={off}>
      <Input aria-label="Six-digit code" value={code} inputMode="numeric" autoComplete="one-time-code" placeholder="Code from your app" onChange={event => setCode(event.target.value)} />
      <Button type="submit" size="xs" variant="destructive" disabled={!/^\d{6}$/.test(code.trim())}>Turn off two-step</Button>
    </form> : null}
  </div>
}

function Password({ me, run }: { me: AccessMe; run: AccessRun }) {
  const [open, setOpen] = useState(false)
  const [password, setPassword] = useState("")
  const [again, setAgain] = useState("")
  const [code, setCode] = useState("")
  const problem = password.length < MIN_PASSWORD ? `At least ${MIN_PASSWORD} characters.` : password !== again ? "The passwords do not match." : me.person.twoStep && !/^\d{6}$/.test(code.trim()) ? "Give the code from your authenticator app." : ""
  const save = (event: FormEvent) => {
    event.preventDefault()
    if (problem) return
    void run("Changing your password", () => accessApi.account({ action: "password", password, ...(me.person.twoStep ? { code: code.trim() } : {}) }), "Password changed").then(ok => { if (ok) { setOpen(false); setPassword(""); setAgain(""); setCode("") } })
  }
  return <div className="access-row">
    <div className="grid-line">
      <span className="grid-key">Password</span>
      <span className="grid-muted">{me.sso ? "Your company also signs you in through its identity provider" : "Signs you in on a new computer"}</span>
      <span className="grid-line-actions"><Button size="xs" variant="outline" aria-expanded={open} onClick={() => setOpen(value => !value)}>Change</Button></span>
    </div>
    {open ? <form className="grid-inline-form access-form access-row-form" aria-label="Change your password" onSubmit={save}>
      <div className="grid-fields">
        <div className="grid-field"><label htmlFor="access-own-password">New password</label><Input id="access-own-password" type="password" value={password} autoComplete="new-password" onChange={event => setPassword(event.target.value)} /></div>
        <div className="grid-field"><label htmlFor="access-own-again">Type it again</label><Input id="access-own-again" type="password" value={again} autoComplete="new-password" onChange={event => setAgain(event.target.value)} /></div>
        {me.person.twoStep ? <div className="grid-field"><label htmlFor="access-own-code">Two-step code</label><Input id="access-own-code" value={code} inputMode="numeric" autoComplete="one-time-code" onChange={event => setCode(event.target.value)} /></div> : null}
      </div>
      <div className="grid-form-actions">
        <Button type="submit" size="sm" disabled={Boolean(problem)} title={problem || undefined}>Change password</Button>
        <p className="grid-hint">{problem || "Your other computers must sign in again; this one stays signed in."}</p>
      </div>
    </form> : null}
  </div>
}

function Computers({ me, run }: { me: AccessMe; run: AccessRun }) {
  const { armed, arm, disarm } = useArmed()
  const devices = me.person.devices
  return <div className="access-row">
    <div className="grid-line">
      <span className="grid-key">Computers</span>
      <span className="grid-muted">{devices.length} {devices.length === 1 ? "computer stays" : "computers stay"} signed in; each lapses after 30 days unused</span>
      <span className="grid-line-actions">
        {devices.length > 1 ? <Button size="xs" variant={armed === "others" ? "destructive" : "outline"} onClick={() => armed === "others" ? (disarm(), void run("Signing out your other computers", () => accessApi.account({ action: "signOutOthers" }), "Signed out on your other computers")) : arm("others")}>{armed === "others" ? "Confirm" : "Sign out the others"}</Button> : null}
      </span>
    </div>
    <ul className="grid-part" aria-label="Your computers">
      {devices.map(device => <li key={device.id} className="grid-line">
        <span className="grid-muted">{device.computer || "A computer"}{device.id === me.device ? " (this one)" : ""} · last used {ago(device.lastUsedAt)}{device.strong ? " · with a second factor" : ""}</span>
        {device.id === me.device ? null : <span className="grid-line-actions"><Button size="xs" variant={armed === device.id ? "destructive" : "ghost"} onClick={() => armed === device.id ? (disarm(), void run("Signing that computer out", () => accessApi.account({ action: "deviceForget", device: device.id }), "Signed out")) : arm(device.id)}>{armed === device.id ? "Confirm" : "Sign out"}</Button></span>}
      </li>)}
    </ul>
  </div>
}

/** The signed-in person's own account: two-step sign-in, password and computers. */
export function AccessAccount({ me, run }: { me: AccessMe; run: AccessRun }) {
  return <section className="grid-sheet" aria-label="Your account">
    <p className="grid-part-title">Your account <span>{me.person.email ?? me.person.username}</span></p>
    {me.blocked ? <p role="alert" className="grid-line grid-error">Your company requires two-step sign-in. Turn it on below; until then your agents cannot use anything. Other computers you signed in on without it must sign in again with the code.</p> : null}
    <TwoStep me={me} run={run} />
    <Password me={me} run={run} />
    <Computers me={me} run={run} />
  </section>
}
