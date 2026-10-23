import { useEffect, useRef, useState } from "react"
import { desksApi, type DeskLogin } from "@/api/desks-api"
import { say } from "@/api/grids/errors"
import { usePlatform } from "@/context/platform-context"
import { workspaceApi } from "@/api/workspace-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import "@/components/neo-grid.css"
import "@/components/sandbox-grid-admin.css"

/** A signed-in person's own desks and company workspaces, refreshed on their own so a desk that
 *  moves or is shared anew opens without signing in again. */
export function DeskPortal({ login, onSignOut }: { login: DeskLogin; onSignOut(): void }) {
  const { openEnvironmentWindow, refreshPlatform } = usePlatform()
  const [latest, setLatest] = useState<DeskLogin>(login)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const refreshRef = useRef(refreshPlatform)
  useEffect(() => { refreshRef.current = refreshPlatform }, [refreshPlatform])
  useEffect(() => {
    let alive = true
    let timer: ReturnType<typeof setTimeout>
    const refresh = async () => {
      try { const value = await desksApi.refreshDesk(); if (alive) { setLatest(value); setError(""); await refreshRef.current() } }
      catch (reason) { if (alive) setError(say(reason)) }
      finally { if (alive) timer = setTimeout(() => void refresh(), 15000) }
    }
    void refresh()
    return () => { alive = false; clearTimeout(timer) }
  }, [])
  const open = (environmentId: string) => { setBusy(true); void openEnvironmentWindow(environmentId).catch(reason => setError(String(reason))).finally(() => setBusy(false)) }
  // Two-step sign-in is the person's own: a secret shown once, confirmed with a first code.
  const [enrol, setEnrol] = useState<{ secret: string; otpauth: string } | null>(null)
  const [mfa, setMfa] = useState<boolean | null>(null)
  const [otp, setOtp] = useState("")
  const twoStep = mfa ?? Boolean(latest.mfa)
  const manage = async (request: Record<string, unknown>, done: (value: Record<string, unknown>) => void) => {
    setBusy(true); setError("")
    try { done(await desksApi.manage<Record<string, unknown>>(request)) } catch (reason) { setError(say(reason)) } finally { setBusy(false) }
  }
  const ready = latest.desks.some(desk => desk.state === "ready" && desk.environmentId)
  return <div className="grid-sheet">
    <section className="grid-line grid-line-head" aria-label="My desk">
      <i aria-hidden="true" className="grid-dot" data-online={ready || undefined} />
      <strong>{latest.name}</strong>
      <span className="grid-muted">{latest.desks.length ? latest.desks.map(desk => `${desk.name}: ${desk.state === "ready" && desk.environmentId ? "in your sandbox list" : desk.note}`).join(" · ") : "No desk yet; ask your admin for one"}</span>
      <span className="grid-line-actions"><Button size="xs" variant="ghost" onClick={onSignOut}>Sign out</Button></span>
    </section>
    {error ? <p role="alert" className="grid-line grid-error">{error}</p> : null}
    {latest.desks.map(desk => <div key={desk.id} className="grid-line">
      <span className="grid-key">Desk</span>
      <span className="grid-muted">{desk.name}{desk.host ? ` · on ${desk.host}` : ""} · {desk.note}</span>
      <span className="grid-line-actions"><Button size="xs" disabled={!desk.environmentId || busy} onClick={() => { if (desk.environmentId) open(desk.environmentId) }}>Open desk</Button></span>
    </div>)}
    <div className="grid-line">
      <span className="grid-key">Two-step</span>
      {enrol ? <form className="grid-muted desk-portal-enrol" onSubmit={event => { event.preventDefault(); void manage({ action: "mfaConfirm", code: otp.trim() }, () => { setEnrol(null); setMfa(true); setOtp("") }) }}>
        <span>Add this to your authenticator app, then type its first code: <code className="desk-admin-code">{enrol.secret}</code></span>
        <Input size="sm" inputMode="numeric" maxLength={6} aria-label="First code from your authenticator app" value={otp} onChange={event => setOtp(event.target.value.replace(/\D/g, ""))} />
        <Button size="xs" type="submit" disabled={busy || otp.trim().length !== 6}>Turn on</Button>
        <Button size="xs" type="button" variant="ghost" onClick={() => { setEnrol(null); setOtp("") }}>Cancel</Button>
      </form>
        : twoStep ? <form className="grid-muted desk-portal-enrol" onSubmit={event => { event.preventDefault(); void manage({ action: "mfaDisable", code: otp.trim() }, () => { setMfa(false); setOtp("") }) }}>
          <span>On: your password and a code from your authenticator app.</span>
          <Input size="sm" inputMode="numeric" maxLength={6} aria-label="Code to turn two-step off" placeholder="Code" value={otp} onChange={event => setOtp(event.target.value.replace(/\D/g, ""))} />
          <Button size="xs" type="submit" variant="ghost" disabled={busy || otp.trim().length !== 6}>Turn off</Button>
        </form>
        : <span className="grid-muted">Off. <Button size="xs" variant="outline" disabled={busy} onClick={() => void manage({ action: "mfaEnroll" }, value => setEnrol({ secret: String(value.secret), otpauth: String(value.otpauth) }))}>Turn on</Button></span>}
    </div>
    {latest.connections?.map(connection => <div key={connection.id} className="grid-line">
      <span className="grid-key">Company</span>
      <span className="grid-muted">{connection.name}</span>
      <span className="grid-line-actions"><Button size="xs" variant="outline" onClick={() => { void workspaceApi.openUrl(connection.url).catch(reason => setError(String(reason))) }}>Open workspace</Button></span>
    </div>)}
  </div>
}
