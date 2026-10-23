import { useState } from "react"
import { ChevronDownIcon } from "lucide-react"
import type { GridHub, GridPlan } from "@/api/grid-api"
import { grids } from "@/api/grids"
import { toModelsStatus } from "@/api/grids/profiles/models"
import type { Membership, ModelsStatus, PlanTarget } from "@/api/grids/types"
import { useWorkspaceActions } from "@/components/use-workspace-actions"
import { PageHeader, PillButton } from "@/components/prompx"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import { GridSwarms, type GridRun } from "@/components/grid-swarm"
import { computerStatus, progressFraction, progressText } from "@/lib/grid-status"
import { useArmed } from "@/components/use-armed"
import { useFleeting } from "@/components/use-fleeting"
import { GridRentedGpus } from "@/components/grid-neocloud"
import { ClosingLine, DeleteGrid } from "@/components/grid-deletion"
import { when } from "@/lib/grid-closing"
import { daysSince, silenceNotice } from "@/lib/grid-silence"
import "@/components/neo-grid.css"

type Run = GridRun

/** Rented GPUs kept from a grid this computer no longer hosts: deleted, or its hub not starting.
 *  They may still be billing, so the list, its stop notes and Remove and stop stay in reach. The
 *  panel shows nothing when there is nothing to show. */
function RentedWithoutHub({ run }: { run: Run }) {
  return <div className="grid-sheet"><GridRentedGpus run={run} /></div>
}

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

/** The official installers; engine and CLI are all a computer needs to join and serve. */
const INSTALL = {
  windows: { label: "Windows", command: "irm https://yougori.com/install.ps1 | iex" },
  unix: { label: "macOS · Linux", command: "curl -fsSL https://yougori.com/install.sh | sh" },
} as const


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

/** Install once, then join; the invite inside the join command stays blurred until unblurred. */
function ConnectComputers({ hub }: { hub: GridHub }) {
  const [revealed, setRevealed] = useState(false)
  const [os, setOs] = useState<keyof typeof INSTALL>("windows")
  if (!hub.invite) return <p className="grid-line grid-muted">The join commands appear once the hub can be reached.</p>
  const join = `yougori grid join --invite ${hub.invite}`
  return <section aria-label="Connect other computers" className="grid-part">
    <p className="grid-part-title">Connect other computers <span>{hub.tunnel ? "from anywhere" : "on this network"}</span></p>
    <div className="grid-line grid-command">
      <span className="grid-command-label">Install</span>
      <span className="grid-seg" role="group" aria-label="Operating system">
        {(Object.keys(INSTALL) as Array<keyof typeof INSTALL>).map(key => <button key={key} type="button" aria-pressed={os === key} onClick={() => setOs(key)}>{INSTALL[key].label}</button>)}
      </span>
      <code>{INSTALL[os].command}</code>
      <Button size="xs" variant="ghost" aria-label="Copy install command" onClick={() => copyText(INSTALL[os].command, "Install command copied", INSTALL[os].label)}>Copy</Button>
    </div>
    <div className="grid-line grid-command">
      <span className="grid-command-label">Join</span>
      <code data-blurred={!revealed || undefined}>{join}</code>
      <Button size="xs" variant="outline" aria-pressed={revealed} onClick={() => setRevealed(value => !value)}>{revealed ? "Hide" : "Unblur"}</Button>
      <Button size="xs" variant="ghost" aria-label="Copy join command" onClick={() => copyText(join, "Join command copied", "It asks for the company password; share that separately.")}>Copy</Button>
    </div>
    <p className="grid-note">It asks for the company password; share it separately, it is never in the command. Or run <code>yougori join grid</code> and paste the invite.{hub.tunnel?.kind === "quick" ? " The public link changes when this computer restarts; joined computers only paste the new invite." : ""}</p>
  </section>
}

/** The model field's fixed prefix; a pasted link or `hf.co/` name keeps only `owner/model`. */
const HF = "hf.co/"
const withoutPrefix = (value: string) => value.trimStart().replace(/^(https?:\/\/)?(www\.)?(hf\.co|huggingface\.co)\//i, "")

/** How a plan's computers read on its row. */
function scopeText(plan: GridPlan) {
  if (plan.scope.kind === "computers") return plan.names.length ? plan.names.join(", ") : `${plan.computers} picked`
  return `${plan.percent}% of ${plan.scope.kind === "remaining" ? "computers without a model" : "all computers"}`
}

type Scope = "selected" | "remaining" | "all"

function HubView({ hub, run }: { hub: GridHub; run: Run }) {
  const { armed, arm, disarm } = useArmed()
  const [model, setModel] = useState("")
  const [percent, setPercent] = useState("100")
  const [selected, setSelected] = useState<string[]>([])
  const [scope, setScope] = useState<Scope>("remaining")
  const reach = hub.tunnel ? (hub.tunnel.url ?? (hub.tunnel.error ? "public link unavailable" : "starting public link…")) : `${hub.address}:${hub.port}`
  // A computer that left the grid cannot stay selected.
  const picked = selected.filter(id => hub.members.some(member => member.id === id))
  const target: Scope = picked.length ? "selected" : scope === "selected" ? "remaining" : scope
  const share = Number(percent)
  const planProblem = !model.trim() ? "Give a model, such as owner/model."
    : target !== "selected" && (!Number.isInteger(share) || share < 1 || share > 100) ? "Choose between 1 and 100 percent of the computers."
    : ""
  const toggle = (id: string) => setSelected(current => current.includes(id) ? current.filter(item => item !== id) : [...current, id])
  const assign = () => {
    if (planProblem) return
    const name = HF + model.trim()
    const where: PlanTarget = target === "selected" ? { kind: "hosts", hosts: picked }
      : target === "all" ? { kind: "all", percent: share }
      : { kind: "remaining", percent: share }
    void run(`Assigning ${name}`, () => grids.models.addPlan({ model: name, target: where }), `${name} assigned`).then(ok => { if (ok) { setModel(""); setSelected([]) } })
  }
  return <div className="grid-sheet">
    <section className="grid-line grid-line-head" aria-label="Hosted grid">
      <i aria-hidden="true" className="grid-dot" data-online={!hub.tunnel || hub.tunnel.connected || undefined} />
      <strong>{hub.name}</strong>
      <span className="grid-muted">Hosted here · {reach} · {hub.computers.online} of {hub.computers.total} online</span>
      <span className="grid-line-actions">
        <Button size="xs" disabled={!hub.invite} onClick={() => { if (hub.invite) copyText(hub.invite, "Invite copied", "Paste it in Join a closed grid; share the password separately.") }}>Copy invite</Button>
        <DeleteGrid closing={hub.closing} run={run} what="grid" remove={grids.models.scheduleDeletion} restore={grids.models.restore} />
      </span>
    </section>
    <ClosingLine closing={hub.closing} keeps="No API key works; computers stopped serving and keep their models until then." cleans="removed the model the grid installed" />
    {hub.tunnel?.error ? <p role="alert" className="grid-line grid-error">{hub.tunnel.error}</p> : null}
    <ConnectComputers hub={hub} />
    <GridRentedGpus run={run} />

    <section aria-label="Computers" className="grid-part">
      <p className="grid-part-title">Computers <span>{hub.computers.online} of {hub.computers.total} online</span></p>
      {hub.members.length ? hub.members.map(computer => {
        const plan = hub.plans.find(item => item.id === computer.planId)
        const status = computerStatus(computer, plan?.model)
        const removing = armed === `remove-${computer.id}`
        const leaving = armed === `exclude-${computer.id}`
        return <div key={computer.id} className="grid-line grid-computer" data-selected={picked.includes(computer.id) || undefined} data-excluded={computer.excluded || undefined}>
          <input type="checkbox" className="grid-check" aria-label={`Select ${computer.name}`} checked={picked.includes(computer.id)} disabled={!computer.capable || computer.excluded} title={!computer.capable ? "This computer cannot run models" : computer.excluded ? "This computer is left out of the grid's work" : undefined} onChange={() => toggle(computer.id)} />
          <i aria-hidden="true" className="grid-dot" data-online={computer.online && !computer.excluded || undefined} />
          <span className="grid-computer-main">
            <strong>{computer.name}</strong>
            <span className="grid-status" data-tone={status.tone}>{status.text}</span>
            {status.fraction === undefined ? null : <span className="grid-bar" role="progressbar" aria-label={`${computer.name} progress`} aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(status.fraction * 100)}><span style={{ width: `${Math.round(status.fraction * 100)}%` }} /></span>}
          </span>
          <span className="grid-meta" title={`${computer.platform}${computer.appVersion ? ` · Yougori ${computer.appVersion}` : ""} · ${computer.online ? "online" : seen(computer.lastSeenSeconds)}`}>{computer.jobs} {computer.jobs === 1 ? "reply" : "replies"}</span>
          <span className="grid-line-actions">
            {computer.excluded
              ? <Button size="xs" variant="outline" aria-label={`Bring ${computer.name} back`} onClick={() => void run(`Bringing ${computer.name} back`, () => grids.models.bringHostBack(computer.id), `${computer.name} is back in the grid`)}>Bring back</Button>
              : <Button size="xs" variant={leaving ? "destructive" : "ghost"} aria-label={`Leave ${computer.name} out`} title="It keeps its membership but gets no model and no work" onClick={() => leaving ? (disarm(), void run(`Leaving ${computer.name} out`, () => grids.models.drainHost(computer.id), `${computer.name} is left out`)) : arm(`exclude-${computer.id}`)}>{leaving ? "Confirm" : "Leave out"}</Button>}
            <Button size="xs" variant={removing ? "destructive" : "ghost"} aria-label={`Remove ${computer.name}`} title="Remove it from the grid; it would have to join again" onClick={() => removing ? (disarm(), void run(`Removing ${computer.name}`, () => grids.models.removeHost(computer.id), `${computer.name} removed`)) : arm(`remove-${computer.id}`)}>{removing ? "Confirm" : "Remove"}</Button>
          </span>
        </div>
      }) : <p className="grid-line grid-muted">No computers yet. Send them the join command above.</p>}
    </section>

    <section aria-label="Models" className="grid-part">
      <p className="grid-part-title">Models <span>what the computers run</span></p>
      {hub.planWarning ? <p className="grid-line grid-muted">{hub.planWarning}</p> : null}
      {hub.plans.map(plan => <div key={plan.id} className="grid-line">
        <strong>{plan.model}{plan.quant ? ` · ${plan.quant}` : ""}</strong>
        <span className="grid-muted">{scopeText(plan)} · {plan.ready} of {plan.target} ready · {plan.rules}</span>
        <span className="grid-line-actions">
          <Button size="xs" variant={armed === plan.id ? "destructive" : "ghost"} aria-label={`Stop ${plan.model}`} onClick={() => armed === plan.id ? (disarm(), void run(`Stopping ${plan.model}`, () => grids.models.removePlan(plan.id), `${plan.model} stopped`)) : arm(plan.id)}>{armed === plan.id ? "Confirm" : "Stop"}</Button>
        </span>
      </div>)}
      <form className="grid-line grid-plan-form" onSubmit={event => { event.preventDefault(); assign() }}>
        <label className="grid-box grid-model-field">
          <span className="grid-box-affix" aria-hidden="true">{HF}</span>
          <input aria-label="Run a model on the computers" value={model} placeholder="owner/model" spellCheck={false} autoComplete="off" onChange={event => setModel(withoutPrefix(event.target.value))} />
        </label>
        <select aria-label="Run it on" className="grid-box grid-select" value={target} onChange={event => { const value = event.target.value as Scope; if (value !== "selected") setSelected([]); setScope(value) }}>
          {picked.length ? <option value="selected">{picked.length === 1 ? "The selected computer" : `The ${picked.length} selected computers`}</option> : null}
          <option value="remaining">Computers without a model</option>
          <option value="all">All computers</option>
        </select>
        {target === "selected" ? null : <label className="grid-box grid-percent-field">
          <input aria-label="Share of computers (%)" type="number" min={1} max={100} value={percent} onChange={event => setPercent(event.target.value)} />
          <span className="grid-box-affix" aria-hidden="true">%</span>
        </label>}
        <Button size="sm" className="grid-assign" type="submit" disabled={Boolean(planProblem)} title={planProblem || undefined}>Assign</Button>
      </form>
      <p className="grid-note">{target === "selected"
        ? "The selected computers switch to this model; the model they ran before is deleted from them to free its space."
        : "Tick computers above to give them a model of their own. Computers you picked keep their model; a computer moved to another model has the old one deleted."}</p>
    </section>

    <GridSwarms hub={hub} run={run} />
  </div>
}

/** A joined computer. `member` is Grid Core's Membership; everything about the model this
 *  computer was told to serve lives in `assignment`, which is where ModelsStatus keeps the
 *  fields the Membership type itself does not carry (model, quant, progress, state, rules,
 *  reason and the replies served). */
function MemberView({ member, assignment, run }: { member: Membership; assignment: NonNullable<ModelsStatus["assignment"]>; run: Run }) {
  const { armed, arm, disarm } = useArmed()
  const [open, setOpen] = useState(false)
  const model = assignment.model
  const progress = assignment.progress ?? undefined
  const fraction = progressFraction(progress)
  const summary = progress && model ? progressText(progress, model) : [member.connected ? "Connected" : "Reconnecting", model ?? "No model yet", assignment.state ?? "waiting"].join(" · ")
  return <div className="grid-sheet">
    <section className="grid-line grid-line-head" aria-label="Joined grid">
      <i aria-hidden="true" className="grid-dot" data-online={member.connected || undefined} />
      <strong>{member.realm}</strong>
      <span className="grid-computer-main">
        <span className="grid-status" data-tone={member.connected ? (progress ? "wait" : "ok") : "off"}>{summary}</span>
        {fraction === undefined ? null : <span className="grid-bar" role="progressbar" aria-label="Model progress" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(fraction * 100)}><span style={{ width: `${Math.round(fraction * 100)}%` }} /></span>}
      </span>
      <span className="grid-line-actions">
        <Button size="icon-xs" variant="ghost" aria-expanded={open} aria-controls="grid-member-details" aria-label={open ? "Hide details" : "Show details"} onClick={() => setOpen(value => !value)}>
          <ChevronDownIcon aria-hidden="true" className="grid-chevron" data-open={open || undefined} />
        </Button>
        <Button size="xs" variant={armed === "leave" ? "destructive" : "outline"} onClick={() => armed === "leave" ? (disarm(), void run(`Leaving ${member.realm}'s grid`, grids.models.leave, `Left ${member.realm}'s grid`)) : arm("leave")}>{armed === "leave" ? "Confirm leave" : "Leave grid"}</Button>
      </span>
    </section>
    {silenceNotice(daysSince(member.unreachableSince), member.realm) ? <p role="status" className="grid-line grid-closing">{silenceNotice(daysSince(member.unreachableSince), member.realm)}</p> : null}
    {member.pausedUntil ? <p role="status" className="grid-line grid-closing">Paused: {member.realm}'s admin scheduled this grid for deletion on {when(member.pausedUntil)}. This computer serves nothing until then and keeps its model; if the grid is deleted, the model the grid installed is removed.</p> : null}
    {open ? <ul id="grid-member-details" className="grid-part" aria-label="This computer in the grid">
      <li className="grid-line"><span className="grid-key">Hub</span><span className="grid-muted">{member.hub}</span></li>
      <li className="grid-line"><span className="grid-key">Connection</span><span className="grid-muted">{member.connected ? "Connected to the hub" : member.error ?? "Reconnecting to the hub"}</span></li>
      <li className="grid-line"><span className="grid-key">Model</span><span className="grid-muted">{model ? `${model}${assignment.quant ? ` · ${assignment.quant}` : ""}` : "The admin has not assigned a model yet"}{assignment.rules ? ` · ${assignment.rules}` : ""}</span></li>
      <li className="grid-line"><span className="grid-key">Serving</span><span className="grid-muted">{assignment.state ?? "Waiting"}{assignment.reason ? ` · ${assignment.reason}` : ""} · {assignment.jobs} {assignment.jobs === 1 ? "reply" : "replies"}</span></li>
      {assignment.lastError ? <li className="grid-line"><span className="grid-key">Last error</span><span className="grid-muted">{assignment.lastError}</span></li> : null}
    </ul> : null}
  </div>
}

/** The Neo Grid page: the headline and its actions, then the hosted or joined grid. */
export function NeoGridPage() {
  const { grid: status, gridError: loadError, refreshGrid: refresh, network, openHost, openJoin, openNetwork } = useWorkspaceActions()
  const [busy, setBusy] = useState("")

  const run: Run = async (job, work, done) => {
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

  // The membership and what this computer was told to serve are read through the grids client.
  // The hosted view (HubView, below) keeps reading the legacy GridHub shape: its computer rows go
  // through the shared `computerStatus` helper and its swarm panel through GridSwarms, both typed
  // to the Closed Neo Grid's own shapes and shared with the pages that are still on the legacy
  // client, so moving them would change those shared parts too.
  const hub = status?.hub ?? null
  const typed = status ? toModelsStatus(status) : null
  const member = typed?.member ?? null
  const assignment = typed?.assignment ?? null
  const account = network.status
  const issue = useFleeting("neo-grid-page", status?.hubError ?? status?.memberError ?? loadError)
  return <section className="app-page" aria-label="Neo Grid workspace" aria-busy={Boolean(busy)}>
    <PageHeader
      title="Neo Grid."
      lead="Run the models you choose across your own computers, or join a grid someone else hosts."
      actions={<>
        <PillButton tone="dark" disabled={Boolean(hub)} title={hub ? `This computer already hosts ${hub.name}'s grid.` : "Let your other computers join and run the models you choose."} onClick={openHost}>Host a grid</PillButton>
        <PillButton tone="light" title="Join your company's private grid with its invite and password." onClick={openJoin}>Join a closed grid</PillButton>
        <PillButton tone="light" title="Share or use models across the public Yougori Neo Grid." onClick={openNetwork}>Join Yougori grid</PillButton>
      </>}
    />
    <div className="app-page-body">
      {hub || member || issue || account?.signedIn ? <div className="grid-board">
        {busy ? <p role="status" className="grid-muted">{busy}…</p> : null}
        {issue ? <p role="alert" className="grid-error">{issue}</p> : null}
        {hub ? <HubView hub={hub} run={run} /> : <RentedWithoutHub run={run} />}
        {member && assignment ? <MemberView member={member} assignment={assignment} run={run} /> : null}
        {account?.signedIn ? <div className="grid-sheet">
          <section className="grid-line grid-line-head" aria-label="Yougori Neo Grid">
            <i aria-hidden="true" className="grid-dot" data-online />
            <strong>Yougori Neo Grid</strong>
            <span className="grid-muted">Signed in{account.account?.email ? ` as ${account.account.email}` : ""} · {account.shares.length} {account.shares.length === 1 ? "model" : "models"} shared</span>
            <span className="grid-line-actions"><Button size="xs" variant="outline" onClick={openNetwork}>Open</Button></span>
          </section>
        </div> : null}
      </div> : <>
        <RentedWithoutHub run={run} />
        <div className="grid-empty">
        <p className="grid-empty-title">Host or join a model grid</p>
        <p className="grid-empty-hint">Host a grid on your network so your other computers can join and run the models you choose, or join a grid someone else hosts. Every computer in the grid shows up here.</p>
        </div>
      </>}
    </div>
  </section>
}
