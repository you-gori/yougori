import { useState } from "react"
import { accessApi, type AccessAvailable, type AccessHub, type AccessMe, type AccessMember, type AccessRequest, type AccessStatus, type AccessUse } from "@/api/access-api"
import { useAccessStatus } from "@/components/use-access-status"
import { AccessBackupDialog, AccessHostDialog, AccessRestoreDialog, AccessSignInDialog } from "@/components/access-dialogs"
import { AccessAdmin, type AccessRun } from "@/components/access-admin"
import { AccessAccount } from "@/components/access-account"
import { PageHeader, PillButton } from "@/components/prompx"
import { useArmed } from "@/components/use-armed"
import { useFleeting } from "@/components/use-fleeting"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import "@/components/neo-grid.css"
import "@/components/access-grid.css"

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

function copyText(text: string, title: string, description?: string) {
  void navigator.clipboard?.writeText(text).then(() => toastManager.add({ title, description, type: "success" }))
    .catch(() => toastManager.add({ title: "Could not copy", description: "Select the text and copy it instead.", type: "error" }))
}

/** "in 12 min" until a deadline. */
function left(at: number) {
  const seconds = at - Math.floor(Date.now() / 1000)
  if (seconds <= 0) return "expiring"
  if (seconds < 60) return "less than a minute left"
  return `${Math.ceil(seconds / 60)} min left`
}

const permissionLabel = { member: "Member", approver: "Approver", auditor: "Auditor", admin: "Administrator" } as const

/** One way a rule lets you use a credential, in a line: "GET, POST /repos/acme · at once". */
function ruleText(use: Pick<AccessUse, "methods" | "path" | "decision" | "reveal" | "expiresAt" | "limit">) {
  const methods = use.methods.length ? use.methods.join(", ") : "Any method"
  const path = use.path || "any path"
  const decision = use.decision === "allow" ? "at once" : use.decision === "ask" ? "an approver decides" : "never"
  const limit = use.limit ? ` · ${use.limit} an hour, then an approver decides` : ""
  const lapses = use.expiresAt ? ` · until ${new Date(use.expiresAt * 1000).toLocaleString()}` : ""
  return `${methods} ${path} · ${decision}${limit}${use.reveal ? " · may ask to see the value" : ""}${lapses}`
}

/** Deleting asks when: paused for three days (and restorable), or at once. */
function DeleteGrid({ hub, run }: { hub: AccessHub; run: AccessRun }) {
  const [asking, setAsking] = useState(false)
  if (hub.closing?.gone) {
    return <Button size="xs" variant="outline" onClick={() => void run(`Removing ${hub.company}'s access grid`, () => accessApi.delete("forget"), "Removed from this computer")}>Remove now</Button>
  }
  if (hub.closing) {
    return <Button size="xs" onClick={() => void run(`Restoring ${hub.company}'s access grid`, accessApi.restore, "Access grid restored")}>Restore</Button>
  }
  if (!asking) return <Button size="xs" variant="outline" onClick={() => setAsking(true)}>Delete grid</Button>
  return <span className="access-choice" role="group" aria-label="Delete the access grid">
    <Button size="xs" variant="outline" onClick={() => { setAsking(false); void run(`Pausing ${hub.company}'s access grid`, () => accessApi.delete("later"), "Paused; deleted in three days unless restored") }}>In 3 days</Button>
    <Button size="xs" variant="destructive" onClick={() => { setAsking(false); void run(`Deleting ${hub.company}'s access grid`, () => accessApi.delete("now"), "Access grid deleted") }}>Now</Button>
    <Button size="xs" variant="ghost" onClick={() => setAsking(false)}>Cancel</Button>
  </span>
}

/** The hub this computer runs: where it is, its invite, backing it up, and deleting it. */
function HubSheet({ hub, run, onBackup }: { hub: AccessHub; run: AccessRun; onBackup(): void }) {
  const [revealed, setRevealed] = useState(false)
  const reach = hub.tunnel ? (hub.tunnel.url ?? (hub.tunnel.error ? "public link unavailable" : "starting public link…")) : `${hub.address}:${hub.port}`
  const until = hub.closing && !hub.closing.gone ? new Date(hub.closing.until * 1000).toLocaleString() : ""
  return <div className="grid-sheet">
    <section className="grid-line grid-line-head" aria-label="Hosted access grid">
      <i aria-hidden="true" className="grid-dot" data-online={(!hub.closing && (!hub.tunnel || hub.tunnel.connected)) || undefined} />
      <strong>{hub.company}</strong>
      <span className="grid-muted">Hosted here · {reach} · {hub.people} {hub.people === 1 ? "person" : "people"} · {hub.credentials} {hub.credentials === 1 ? "credential" : "credentials"} · {hub.rules} {hub.rules === 1 ? "rule" : "rules"} · {hub.signedIn} signed in{hub.requireTwoStep ? " · two-step required" : ""}{hub.sso ? " · single sign-on" : ""}</span>
      <span className="grid-line-actions">
        <Button size="xs" disabled={!hub.invite} onClick={() => { if (hub.invite) copyText(hub.invite, "Invite copied", "Send it with each person's username; they choose nothing else.") }}>Copy invite</Button>
        {hub.closing?.gone ? null : <Button size="xs" variant="outline" onClick={onBackup}>Back up</Button>}
        <DeleteGrid hub={hub} run={run} />
      </span>
    </section>
    {hub.closing?.gone ? <p role="status" className="grid-line grid-closing" data-gone>Deleted: its credentials, people and rules are gone. It tells people's computers so for 30 days, then removes itself.</p>
      : hub.closing ? <p role="status" className="grid-line grid-closing">Paused: deleted on {until} unless restored. Nobody signs in or uses its credentials until then.</p> : null}
    {hub.tunnel?.error ? <p role="alert" className="grid-line grid-error">{hub.tunnel.error}</p> : null}
    {hub.invite ? <section aria-label="Invite people" className="grid-part">
      <p className="grid-part-title">Invite people <span>{hub.tunnel ? "from anywhere" : "on this network"}</span></p>
      <div className="grid-line grid-command">
        <span className="grid-command-label">Sign in</span>
        <code data-blurred={!revealed || undefined}>{`yougori access signin --invite ${hub.invite} --username NAME`}</code>
        <Button size="xs" variant="outline" aria-pressed={revealed} onClick={() => setRevealed(value => !value)}>{revealed ? "Hide" : "Unblur"}</Button>
        <Button size="xs" variant="ghost" aria-label="Copy sign-in command" onClick={() => copyText(`yougori access signin --invite ${hub.invite} --username NAME`, "Sign-in command copied", "It asks for the person's password.")}>Copy</Button>
      </div>
      <p className="grid-note">Add each person below with their own username and password first. They sign in on their own computer with the invite, in Yougori or with the command; the fingerprint inside it means they can only reach this grid.{hub.tunnel?.kind === "quick" ? " The public link changes when this computer restarts; people then sign in with the new invite." : ""}</p>
    </section> : null}
  </div>
}

/** Who is signed in on this computer. */
function SignedInSheet({ member, me, run, onSignIn }: { member: AccessMember; me: AccessMe | null; run: AccessRun; onSignIn(): void }) {
  const { armed, arm, disarm } = useArmed()
  return <div className="grid-sheet">
    <section className="grid-line grid-line-head" aria-label="Your sign-in">
      <i aria-hidden="true" className="grid-dot" data-online={member.connected || undefined} />
      <strong>{me?.person.name ?? member.username}</strong>
      <span className="grid-muted">{member.username} · {me ? permissionLabel[me.person.permission] : "not reachable"} at {member.company}'s access grid{me?.person.teams.length ? ` · ${me.person.teams.join(", ")}` : ""}</span>
      <span className="grid-line-actions">
        {member.needsSignIn ? <Button size="xs" onClick={onSignIn}>Sign in again</Button> : null}
        <Button size="xs" variant={armed === "out" ? "destructive" : "outline"} onClick={() => armed === "out" ? (disarm(), void run("Signing out", accessApi.signOut, "Signed out")) : arm("out")}>{armed === "out" ? "Confirm sign out" : "Sign out"}</Button>
      </span>
    </section>
    {member.error ? <p role="alert" className="grid-line grid-error">{member.error}</p> : null}
  </div>
}

function RequestLine({ request }: { request: AccessRequest }) {
  const what = request.kind === "reveal" ? `wants to see the value of ${request.credential}` : `${request.method} ${request.url}${request.hasQuery ? "?…" : ""} with ${request.credential}`
  return <span className="grid-muted" title={what}>
    <b className="access-who">{request.person}</b> via {request.agent || "an agent"}{request.computer ? ` on ${request.computer}` : ""} · {what}
  </span>
}

/** Requests that wait for an approver, with what each would send. */
function Approvals({ me, run }: { me: AccessMe; run: AccessRun }) {
  const waiting = me.overview?.waiting ?? []
  const decides = me.person.permission === "approver" || me.person.permission === "admin"
  if (!decides) return null
  const decide = (request: AccessRequest, approve: boolean, hours?: number) => run(
    approve ? `Approving ${request.person}'s request` : `Denying ${request.person}'s request`,
    () => accessApi.manage({ action: "decide", request: request.id, approve, ...(hours ? { hours } : {}) }),
    approve ? (hours ? `Approved; ${request.person} may repeat this for ${hours} hour${hours === 1 ? "" : "s"}` : "Approved once") : "Denied",
  )
  return <section className="grid-sheet" aria-label="Waiting for approval">
    <p className="grid-part-title">Waiting for approval <span>{waiting.length ? `${waiting.length} ${waiting.length === 1 ? "request" : "requests"}` : "nothing right now"}</span></p>
    {waiting.map(request => {
      const own = request.person === me.person.username && !me.canApproveOwn
      return <div key={request.id} className="access-request">
        <div className="grid-line">
          <RequestLine request={request} />
          <span className="grid-meta">{left(request.expiresAt)}</span>
        </div>
        {request.why ? <p className="access-detail">Waits because {request.why}.</p> : null}
        {request.kind === "reveal" && request.reason ? <p className="access-detail">Reason: {request.reason}</p> : null}
        {request.bodyPreview ? <details className="access-detail"><summary>What it sends · {request.bodyBytes} bytes</summary><pre>{request.bodyPreview}</pre></details> : null}
        <div className="grid-line access-decide">
          {own ? <span className="grid-muted">Someone else approves your own requests.</span> : <>
            <Button size="xs" onClick={() => void decide(request, true)}>Approve once</Button>
            {request.kind === "use" ? <Button size="xs" variant="outline" title={`${request.person} may repeat ${request.method} with ${request.credential} without asking for an hour`} onClick={() => void decide(request, true, 1)}>Approve for 1 hour</Button> : null}
            <Button size="xs" variant="ghost" onClick={() => void decide(request, false)}>Deny</Button>
          </>}
        </div>
      </div>
    })}
  </section>
}

function CredentialLine({ credential }: { credential: AccessAvailable }) {
  return <div className="access-available">
    <div className="grid-line">
      <strong>{credential.name}</strong>
      <span className="grid-muted" title={credential.destinations.join(", ")}>{credential.destinations.join(", ")}{credential.shortLived ? " · sent as short-lived tokens" : ""}{credential.note ? ` · ${credential.note}` : ""}</span>
    </div>
    <ul className="access-uses">
      {credential.uses.map(use => <li key={use.ruleId} data-decision={use.decision}>{ruleText(use)}</li>)}
    </ul>
  </div>
}

/** What this person's agents may use, and how to connect them. */
function Available({ me, mcp }: { me: AccessMe; mcp: AccessStatus["mcp"] }) {
  const config = JSON.stringify({ mcpServers: { "yougori-access": { command: mcp.command, args: mcp.args } } }, null, 2)
  return <section className="grid-sheet" aria-label="What your agents can use">
    <p className="grid-part-title">What your agents can use <span>values are never shown to them</span></p>
    {me.available.length ? me.available.map(credential => <CredentialLine key={credential.id} credential={credential} />)
      : <p className="grid-line grid-muted">Nothing yet. An admin adds a rule that lets you use a credential.</p>}
    <div className="grid-part">
      <p className="grid-part-title">Connect your agents <span>any MCP client that runs local servers</span></p>
      <pre className="access-config">{config}</pre>
      <div className="grid-line">
        <Button size="xs" variant="outline" onClick={() => copyText(config, "MCP settings copied", "Paste them into your agent's MCP settings.")}>Copy settings</Button>
        <span className="grid-muted">Agents call list_company_access, then company_request with a credential and a URL. Access Grid adds the credential and hides it in the answer.</span>
      </div>
    </div>
  </section>
}

function MyRequests({ me }: { me: AccessMe }) {
  if (!me.requests.length) return null
  return <section className="grid-sheet" aria-label="Your requests">
    <p className="grid-part-title">Your requests <span>until your agent collects the answer</span></p>
    {me.requests.map(request => <div key={request.id} className="grid-line">
      <RequestLine request={request} />
      <span className="grid-tag" data-tone={request.state === "done" ? "ok" : request.state === "waiting" ? "wait" : undefined}>{request.state === "waiting" ? `waiting · ${left(request.expiresAt)}` : request.state}{request.decidedBy ? ` · ${request.decidedBy}` : ""}</span>
    </div>)}
  </section>
}

/** The Access Grid page: host the company's credential hub, or sign in to it, and decide what agents may use. */
export function AccessPage() {
  const { status, error: loadError, refresh } = useAccessStatus(4000)
  const [busy, setBusy] = useState("")
  const [hosting, setHosting] = useState(false)
  const [signingIn, setSigningIn] = useState(false)
  const [backingUp, setBackingUp] = useState(false)
  const [restoring, setRestoring] = useState(false)

  const run: AccessRun = async (job, work, done) => {
    if (busy) return false
    setBusy(job)
    try {
      const result = await work() as { message?: string } | undefined
      if (done) toastManager.add({ title: done, description: result?.message, type: "success" })
      return true
    } catch (reason) {
      toastManager.add({ title: `${job} did not finish`, description: message(reason), type: "error" })
      return false
    } finally {
      setBusy("")
      await refresh()
    }
  }
  const finished = (title: string) => (description?: string) => {
    toastManager.add({ title, description, type: "success" })
    void refresh()
  }

  const hub = status?.hub ?? null
  const member = status?.member ?? null
  const me = status?.me ?? null
  const issue = useFleeting("access-grid-page", status?.hubError ?? status?.memberError ?? loadError)
  return <section className="app-page" aria-label="Access Grid workspace" aria-busy={Boolean(busy)}>
    <PageHeader
      title="Access Grid."
      lead="Company credentials your people's agents use without ever seeing them. You decide who may use what, and approve the rest."
      aside={member ? <span className="page-note" title={`Signed in as ${member.username}`}>Signed in to {member.company} as {member.username}</span> : null}
      actions={<>
        <PillButton tone="dark" disabled={Boolean(hub || member)} title={hub ? "This computer already runs an access grid." : member ? "Sign out before hosting a grid of your own." : "Keep the company's credentials on this computer; you become its admin."} onClick={() => setHosting(true)}>Host an access grid</PillButton>
        <PillButton tone="light" disabled={Boolean(member) && !member?.needsSignIn} title={member && !member.needsSignIn ? `Signed in to ${member.company}.` : "Sign in with the invite your admin gave you."} onClick={() => setSigningIn(true)}>Sign in</PillButton>
        {!hub && !member ? <PillButton tone="light" title="Run your company's access grid on this computer from a backup." onClick={() => setRestoring(true)}>Restore from backup</PillButton> : null}
      </>}
    />
    <div className="app-page-body">
      {hub || member || issue ? <div className="grid-board">
        {busy ? <p role="status" className="grid-muted">{busy}…</p> : null}
        {issue ? <p role="alert" className="grid-error">{issue}</p> : null}
        {hub ? <HubSheet hub={hub} run={run} onBackup={() => setBackingUp(true)} /> : null}
        {member ? <SignedInSheet member={member} me={me} run={run} onSignIn={() => setSigningIn(true)} /> : null}
        {me ? <Approvals me={me} run={run} /> : null}
        {me && status ? <Available me={me} mcp={status.mcp} /> : null}
        {me ? <MyRequests me={me} /> : null}
        {me ? <AccessAccount me={me} run={run} /> : null}
        {me?.overview ? <AccessAdmin me={me} overview={me.overview} run={run} /> : null}
      </div> : <div className="grid-empty">
        <p className="grid-empty-title">Host or sign in to an access grid</p>
        <p className="grid-empty-hint">Host one on a computer that stays on and keep your company's API keys there, or sign in to the one your company runs. Agents then use the keys through it, within the rules, and never see them.</p>
      </div>}
    </div>
    <AccessHostDialog open={hosting} suggestedAddress={status?.suggestedAddress ?? null} onOpenChange={setHosting} onDone={finished("Access grid is running")} />
    <AccessSignInDialog open={signingIn} onOpenChange={setSigningIn} onDone={finished("Signed in")} />
    <AccessBackupDialog open={backingUp} onOpenChange={setBackingUp} onDone={finished("Backup written")} />
    <AccessRestoreDialog open={restoring} suggestedAddress={status?.suggestedAddress ?? null} onOpenChange={setRestoring} onDone={finished("Access grid restored")} />
  </section>
}
