import { useState } from "react"
import { desksApi, type DeskShare, type DesksComputer, type DesksHub, type DesksMembership, type HostedDesk } from "@/api/desks-api"
import { useWorkspaceActions } from "@/components/use-workspace-actions"
import { PageHeader, PillButton } from "@/components/prompx"
import { GridPeopleAndDesks, UnitField } from "@/components/grid-desks"
import { SandboxGridAdmin } from "@/components/sandbox-grid-admin"
import { DeskPortal } from "@/components/desk-portal"
import type { GridRun } from "@/components/grid-swarm"
import { useArmed } from "@/components/use-armed"
import { useFleeting } from "@/components/use-fleeting"
import { ClosingLine, DeleteGrid } from "@/components/grid-deletion"
import { when } from "@/lib/grid-closing"
import { daysSince, silenceNotice } from "@/lib/grid-silence"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import "@/components/neo-grid.css"

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

function copyText(text: string, title: string, description?: string) {
  void navigator.clipboard?.writeText(text).then(() => toastManager.add({ title, description, type: "success" }))
    .catch(() => toastManager.add({ title: "Could not copy", description: "Select the text and copy it instead.", type: "error" }))
}

function seen(seconds: number | null) {
  if (seconds === null) return "not seen yet"
  if (seconds < 60) return "seen just now"
  if (seconds < 3600) return `seen ${Math.floor(seconds / 60)} min ago`
  return `seen ${Math.floor(seconds / 3600)} h ago`
}

const whole = (value: number) => Math.round(value).toString()
const trim = (value: number) => Number.isInteger(value) ? value.toString() : value.toFixed(1)

/** A share in one line: "4 CPU · 15 GB memory · 150 GB disk · GPU · only while nobody is using it". */
function shareText(share: DeskShare) {
  return `${trim(share.cpu)} CPU · ${trim(share.memoryGb)} GB memory · ${trim(share.diskGb)} GB disk${share.gpu ? " · GPU" : ""}${share.idleOnly ? " · only while nobody is using it" : ""}`
}

/** The admin decides what the grid may take from one computer. */
function ShareForm({ computer, share, run, onClose }: { computer: DesksComputer; share: DeskShare; run: GridRun; onClose(): void }) {
  const [cpu, setCpu] = useState(trim(share.cpu))
  const [memory, setMemory] = useState(trim(share.memoryGb))
  const [disk, setDisk] = useState(trim(share.diskGb))
  const [gpu, setGpu] = useState(share.gpu)
  const [idleOnly, setIdleOnly] = useState(share.idleOnly)
  const capacity = computer.capacity ?? null
  const problem = [cpu, memory, disk].some(value => value.trim() === "" || !Number.isFinite(Number(value)) || Number(value) < 0) ? "Give the CPU, memory and disk as numbers; 0 takes none of it." : ""
  const save = () => {
    if (problem) return
    const next = { cpu: Number(cpu), memoryGb: Number(memory), diskGb: Number(disk), gpu, idleOnly }
    void run(`Setting ${computer.name}'s share`, () => desksApi.setComputerShare(computer.id, next), `${computer.name}'s share is set`).then(onClose)
  }
  return <form className="grid-inline-form" aria-label={`Share of ${computer.name}`} onSubmit={event => { event.preventDefault(); save() }}>
    <div className="grid-fields">
      <UnitField id={`share-${computer.id}-cpu`} label="CPU cores" unit={capacity ? `of ${capacity.cpu}` : "cores"} value={cpu} min={0} max={1024} step={0.5} onChange={setCpu} />
      <UnitField id={`share-${computer.id}-memory`} label="Memory (GB)" unit={capacity ? `of ${whole(capacity.memoryGb)}` : "GB"} value={memory} min={0} max={65536} step={0.5} onChange={setMemory} />
      <UnitField id={`share-${computer.id}-disk`} label="Disk (GB)" unit={capacity ? `of ${whole(capacity.freeDiskGb)} free` : "GB"} value={disk} min={0} max={1048576} step={1} onChange={setDisk} />
      <div className="grid-field">
        <span className="grid-field-label">GPU</span>
        <label className="grid-check-field"><input type="checkbox" aria-label="GPU" checked={gpu} disabled={capacity ? !capacity.gpu : false} onChange={event => setGpu(event.target.checked)} />{capacity && !capacity.gpu ? "No usable GPU" : "Desks may use its GPU"}</label>
      </div>
      <div className="grid-field grid-field-wide">
        <span className="grid-field-label">When</span>
        <label className="grid-check-field"><input type="checkbox" aria-label="Only while nobody is using it" checked={idleOnly} onChange={event => setIdleOnly(event.target.checked)} />Only while nobody is using it</label>
      </div>
    </div>
    <div className="grid-form-actions">
      <Button size="sm" type="submit" disabled={Boolean(problem)} title={problem || undefined}>Save share</Button>
      <Button size="sm" variant="outline" type="button" onClick={() => void run(`Suggesting ${computer.name}'s share`, () => desksApi.suggestComputerShare(computer.id), `${computer.name} is back on the suggested share`).then(onClose)}>Use suggested</Button>
      <Button size="sm" variant="ghost" type="button" onClick={onClose}>Cancel</Button>
      <p className="grid-hint">{problem || "Capped by what the computer has. Desks already here stay, since their data is here."}</p>
    </div>
  </form>
}

/** One company computer: its state, what it has and is using, and what the grid may take from it. */
function ComputerRow({ computer, run }: { computer: DesksComputer; run: GridRun }) {
  const { armed, arm, disarm } = useArmed()
  const [editing, setEditing] = useState(false)
  const capacity = computer.capacity ?? null
  const share = computer.share ?? null
  const desks = computer.desks ?? 0
  const removing = armed === "remove"
  return <section aria-label={computer.name} className="grid-block">
    <div className="grid-block-head">
      <i aria-hidden="true" className="grid-dot" data-online={computer.online || undefined} />
      <strong>{computer.name}</strong>
      {!computer.online ? <span className="grid-tag">Offline · {seen(computer.lastSeenSeconds)}</span>
        : !capacity ? <span className="grid-tag">Waiting for its first report</span>
        : capacity.onBattery ? <span className="grid-tag" data-tone="wait">On battery</span>
        : capacity.inUse ? <span className="grid-tag">In use</span>
        : <span className="grid-tag" data-tone="ok">Nobody using it</span>}
      <span className="grid-tag">{desks} {desks === 1 ? "desk" : "desks"}</span>
      <span className="grid-line-actions">
        <Button size="xs" variant="outline" aria-expanded={editing} onClick={() => setEditing(value => !value)}>{editing ? "Close" : "Adjust share"}</Button>
        <Button size="xs" variant={removing ? "destructive" : "ghost"} aria-label={`Remove ${computer.name}`} title="Remove it from the sandbox grid; its desks are placed again elsewhere" onClick={() => removing ? (disarm(), void run(`Removing ${computer.name}`, () => desksApi.removeComputer(computer.id), `${computer.name} removed`)) : arm("remove")}>{removing ? "Confirm" : "Remove"}</Button>
      </span>
    </div>
    {capacity ? <dl className="grid-stats" aria-label={`${computer.name} right now`}>
      <div className="grid-stat"><dt>CPU</dt><dd>{capacity.cpu} cores <small>· {whole(capacity.cpuUsedPercent)}% busy</small></dd></div>
      <div className="grid-stat"><dt>Memory</dt><dd>{whole(capacity.usedMemoryGb)} of {whole(capacity.memoryGb)} GB <small>used</small></dd></div>
      <div className="grid-stat"><dt>GPU</dt><dd>{!capacity.gpu ? <small>None usable</small> : typeof capacity.gpuUsedPercent === "number" ? <>{whole(capacity.gpuUsedPercent)}% <small>busy</small></> : "Available"}</dd></div>
      <div className="grid-stat"><dt>Disk</dt><dd>{whole(capacity.freeDiskGb)} GB <small>free</small></dd></div>
    </dl> : null}
    {share ? <p className="grid-share">
      <span>Grid may use</span>{" "}
      <strong>{shareText(share)}</strong>{" "}
      {computer.shareSet ? null : <span className="grid-tag" title="Half of what it has, until you set a share">Suggested</span>}
    </p> : null}
    {editing ? <ShareForm key={JSON.stringify(share)} computer={computer} share={share ?? { cpu: 2, memoryGb: 4, diskGb: 50, gpu: false, idleOnly: false }} run={run} onClose={() => setEditing(false)} /> : null}
  </section>
}

/** The sandbox grid this computer hosts: its computers with what each has and gives, its people and desks. */
function HubView({ hub, run, refresh }: { hub: DesksHub; run: GridRun; refresh(): Promise<unknown> }) {
  const [revealed, setRevealed] = useState(false)
  const reach = hub.tunnel ? (hub.tunnel.url ?? (hub.tunnel.error ? "public link unavailable" : "starting public link…")) : `${hub.address}:${hub.port}`
  return <div className="grid-sheet">
    <section className="grid-line grid-line-head" aria-label="Hosted sandbox grid">
      <i aria-hidden="true" className="grid-dot" data-online={!hub.tunnel || hub.tunnel.connected || undefined} />
      <strong>{hub.name}</strong>
      <span className="grid-muted">Hosted here · {reach} · {hub.computers.online} of {hub.computers.total} online · {hub.desks.length} {hub.desks.length === 1 ? "desk" : "desks"}</span>
      <span className="grid-line-actions">
        <Button size="xs" disabled={!hub.invite} onClick={() => { if (hub.invite) copyText(hub.invite, "Invite copied", "Paste it in Join a sandbox grid; share the password separately.") }}>Copy invite</Button>
        <DeleteGrid closing={hub.closing} run={run} what="sandbox grid" remove={desksApi.delete} restore={desksApi.restore} />
      </span>
    </section>
    <ClosingLine closing={hub.closing} keeps="Desks are stopped and unshared and nobody signs in; their data is kept until then." cleans="deleted the desks they hosted" />
    {hub.tunnel?.error ? <p role="alert" className="grid-line grid-error">{hub.tunnel.error}</p> : null}
    {hub.invite ? <section aria-label="Connect computers" className="grid-part">
      <p className="grid-part-title">Connect computers <span>{hub.tunnel ? "from anywhere" : "on this network"}</span></p>
      <div className="grid-line grid-command">
        <span className="grid-command-label">Join</span>
        <code data-blurred={!revealed || undefined}>{`yougori desks join --invite ${hub.invite}`}</code>
        <Button size="xs" variant="outline" aria-pressed={revealed} onClick={() => setRevealed(value => !value)}>{revealed ? "Hide" : "Unblur"}</Button>
        <Button size="xs" variant="ghost" aria-label="Copy join command" onClick={() => copyText(`yougori desks join --invite ${hub.invite}`, "Join command copied", "It asks for the password; share that separately.")}>Copy</Button>
      </div>
      <p className="grid-note">Each company computer joins once. From then on it reports what it has and hosts desks within the share you set below, whether or not someone is using it. The password is never in the command.{hub.tunnel?.kind === "quick" ? " The public link changes when this computer restarts; joined computers only paste the new invite." : ""}</p>
    </section> : null}
    <section aria-label="Computers" className="grid-part">
      <p className="grid-part-title">Computers <span>what each has, and what the grid may take from it</span></p>
      {hub.members.length ? hub.members.map(computer => <ComputerRow key={computer.id} computer={computer} run={run} />) : <p className="grid-line grid-muted">No computers yet. Send them the join command above.</p>}
    </section>
    <GridPeopleAndDesks hub={hub} run={run} />
    <details className="grid-part grid-fold">
      <summary className="grid-part-title">Enterprise <span>images, workspace roles, permissions, company workspaces</span></summary>
      <SandboxGridAdmin key={hub.id} onChanged={refresh} />
    </details>
  </div>
}

/** This computer as a member of a sandbox grid: what it hosts. */
function MemberView({ member, hosting, run }: { member: DesksMembership; hosting: HostedDesk[]; run: GridRun }) {
  const { armed, arm, disarm } = useArmed()
  return <div className="grid-sheet">
    <section className="grid-line grid-line-head" aria-label="Joined sandbox grid">
      <i aria-hidden="true" className="grid-dot" data-online={member.connected || undefined} />
      <strong>{member.grid}</strong>
      <span className="grid-muted">{member.connected ? "Connected" : member.error ?? "Reconnecting"} · hosting {hosting.length} {hosting.length === 1 ? "desk" : "desks"}{member.orders > hosting.length ? ` · ${member.orders - hosting.length} building` : ""}</span>
      <span className="grid-line-actions">
        <Button size="xs" variant={armed === "leave" ? "destructive" : "outline"} onClick={() => armed === "leave" ? (disarm(), void run(`Leaving ${member.grid}'s sandbox grid`, desksApi.leave, `Left ${member.grid}'s sandbox grid`)) : arm("leave")}>{armed === "leave" ? "Confirm leave" : "Leave grid"}</Button>
      </span>
    </section>
    {silenceNotice(daysSince(member.unreachableSince), member.grid) ? <p role="status" className="grid-line grid-closing">{silenceNotice(daysSince(member.unreachableSince), member.grid)}</p> : null}
    {member.pausedUntil ? <p role="status" className="grid-line grid-closing">Paused: {member.grid}'s admin scheduled this grid for deletion on {when(member.pausedUntil)}. The desks here are stopped but keep their data; if the grid is deleted, they are deleted too.</p> : null}
    {hosting.length ? <ul className="grid-part" aria-label="Desks on this computer">
      {hosting.map(desk => <li key={desk.id} className="grid-line"><span className="grid-key">Desk</span><span className="grid-muted">{desk.name}{desk.shared ? "" : " · not shared yet"}</span></li>)}
    </ul> : null}
    <p className="grid-note">Desks are built here within the share your admin set for this computer, each with the CPU, memory and disk the admin chose, and shared with their person over pinned TLS.</p>
  </div>
}

/** The Sandbox Grid page: host or join a grid of company computers, and open your own desk. */
export function DesksPage() {
  const { desks: status, desksError: loadError, refreshDesks: refresh, openDesksHost, openDesksJoin, openDeskLogin } = useWorkspaceActions()
  const [busy, setBusy] = useState("")

  const run: GridRun = async (job, work, done) => {
    if (busy) return false
    setBusy(job)
    try {
      const result = await work() as { warning?: string | null } | undefined
      if (done) toastManager.add({ title: done, description: result?.warning ?? undefined, type: result?.warning ? "warning" : "success" })
      return true
    } catch (reason) {
      toastManager.add({ title: `${job} did not finish`, description: message(reason), type: "error" })
      return false
    } finally {
      setBusy("")
      await refresh()
    }
  }

  const hub = status?.hub ?? null
  const member = status?.member ?? null
  const login = status?.desk ?? null
  const cloud = status?.cloudFallback?.error || status?.cloudFallback?.note ? status.cloudFallback : null
  const issue = useFleeting("sandbox-grid-page", status?.hubError ?? status?.memberError ?? loadError)
  return <section className="app-page" aria-label="Sandbox Grid workspace" aria-busy={Boolean(busy)}>
    <PageHeader
      title="Sandbox Grid."
      lead="Your company's computers each host a sandbox for a person, within the share you allow; people open theirs from any computer, on the company network or through the grid from anywhere."
      aside={login ? <span className="page-note" title={`Signed in as ${login.username}`}>Signed in to {login.grid} as {login.name}</span> : null}
      actions={<>
        <PillButton tone="dark" disabled={Boolean(hub)} title={hub ? `This computer already hosts ${hub.name}'s sandbox grid.` : "Run the grid on this computer; the admin orders desks here."} onClick={openDesksHost}>Host a sandbox grid</PillButton>
        <PillButton tone="light" title="Join this computer with the invite and password your admin shared; the admin sets what the grid may take from it." onClick={openDesksJoin}>Join a sandbox grid</PillButton>
        <PillButton tone="light" title="Sign in and open the desk your admin gave you." onClick={openDeskLogin}>Open my desk</PillButton>
      </>}
    />
    <div className="app-page-body">
      {hub || member || issue || login || cloud ? <div className="grid-board">
        {busy ? <p role="status" className="grid-muted">{busy}…</p> : null}
        {issue ? <p role="alert" className="grid-error">{issue}</p> : null}
        {cloud?.error ? <p role="alert" className="grid-error">{cloud.error}{cloud.retryAfter ? ` The next try is at ${new Date(cloud.retryAfter * 1000).toLocaleTimeString()}.` : ""}</p> : null}
        {cloud?.note ? <p role="status" className="grid-muted">{cloud.note}</p> : null}
        {hub ? <HubView hub={hub} run={run} refresh={refresh} /> : null}
        {member && !hub ? <MemberView member={member} hosting={status?.hosting ?? []} run={run} /> : null}
        {login ? <DeskPortal key={login.gridId + login.personId} login={login} onSignOut={() => void run("Signing out", desksApi.logout, "Signed out")} /> : null}
        {!hub && login?.adminRole && login.adminRole !== "user" ? <div className="grid-sheet"><details className="grid-part grid-fold" open>
          <summary className="grid-part-title">Enterprise <span>you manage {login.grid}'s grid as {login.adminRole}</span></summary>
          <SandboxGridAdmin key={login.gridId} onChanged={refresh} />
        </details></div> : null}
      </div> : <div className="grid-empty">
        <p className="grid-empty-title">Host or join a sandbox grid</p>
        <p className="grid-empty-hint">Host a sandbox grid on this computer and order a desk for each person, or join the one your company runs so this computer hosts desks within the share its admin allows. If your admin gave you a desk, open it here.</p>
      </div>}
    </div>
  </section>
}
