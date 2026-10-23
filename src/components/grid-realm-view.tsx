import { useState, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useArmed } from "@/components/use-armed"
import { useFleeting } from "@/components/use-fleeting"
import { brandedName, readGridBrand, writeGridBrand } from "@/lib/grid-brand"
import { ClosingLine } from "@/components/grid-deletion"
import { GridControls } from "@/components/grid-controls"
import { GridTimeline } from "@/components/grid-timeline"
import type { GridRun } from "@/components/grid-swarm"
import { grids } from "@/api/grids"
import { capabilitiesSentence, may, shows } from "@/lib/grid-capability"
import { workerStatus } from "@/lib/swarm-status"
import { GRID_NAME, type GridRealm } from "@/lib/grid-realm"
import "@/components/neo-grid.css"
import "@/components/grids.css"

const capitalise = (text: string) => text.charAt(0).toUpperCase() + text.slice(1)

/** One grid, as it is right now.
 *
 *  Every panel below asks the same question before it renders anything: does this grid do that
 *  at all, and may this person do it. When either answer is no the panel is not there. Nothing
 *  is rendered disabled with a note about a permission somebody does not have, because an
 *  offer that cannot be taken is still an offer.
 *
 *  It reads the way the Grids overview does: the grid's own card opened up at the top, what is
 *  true of the whole grid said once under it, then each thing the grid holds as a card in its
 *  own group.
 */
export function GridRealmView({ realm, run, done, onOpenPage }: {
  realm: GridRealm
  run: GridRun
  done(message?: string): void
  onOpenPage(): void
}) {
  const brand = readGridBrand(realm.key)
  const problem = useFleeting(`grid-${realm.key}`, realm.problem)
  return <div className="realm-view">
    <section className="realm-head" aria-label="This grid">
      <header className="grids-head">
        <p className="grids-card-kind">{capitalise(capabilitiesSentence(realm.capabilities))}</p>
        <h2 className="grids-heading">{brandedName(realm.name, brand)}</h2>
        <p className="grids-card-state">
          <i aria-hidden="true" className="grid-dot" data-online={realm.lifecycle === "open" || undefined} />
          <span>{realm.state}</span>
        </p>
      </header>
      <ClosingLine
        closing={realm.closing}
        keeps="Nothing new runs in it and nobody new signs in. Everything it holds is kept until then."
        cleans="cleaned up what this grid put there"
      />
      {problem ? <p role="alert" className="rollout-callout" data-tone="error">{problem}</p> : null}
      <div className="rollout-actions">
        <Button size="xs" onClick={onOpenPage}>Open {GRID_NAME[realm.key]}</Button>
        <GridControls realm={realm} run={run} done={done} />
      </div>
      <dl className="grids-cards realm-facts">
        {realm.reach ? <Fact label="Reach">{realm.reach}</Fact> : null}
        <Fact label="Key">{realm.keyHolder} holds this grid's key. A backup of it can only be opened with that key.</Fact>
        {brand.support ? <Fact label="Who to ask">{brand.support}</Fact> : null}
        <Fact label="You">Anything you change here is recorded as {realm.actor}.</Fact>
      </dl>
    </section>
    <Computers realm={realm} run={run} />
    <Work realm={realm} />
    <Models realm={realm} run={run} />
    <Workspaces realm={realm} />
    <Credentials realm={realm} />
    <Waiting realm={realm} run={run} />
    <GridTimeline realm={realm} run={run} />
    <Branding realm={realm} />
  </div>
}

/** Something true of the whole grid, said once at the top rather than on every card below it. */
function Fact({ label, children }: { label: string; children: ReactNode }) {
  return <div className="grids-card">
    <dt className="grids-card-kind">{label}</dt>
    <dd className="rollout-text">{children}</dd>
  </div>
}

/** One thing the grid holds: its name, with a short word for its state beside it where it has
 *  one, then what it is and what can be done with it. */
function Item({ name, tag, tone, children }: { name: string; tag?: string; tone?: "noted" | "stop"; children?: ReactNode }) {
  return <article className="rollout-card" aria-label={name}>
    <header className="rollout-card-head">
      <h4 className="rollout-card-name">{name}</h4>
      {tag ? <span className="rollout-tag" data-tone={tone}>{tag}</span> : null}
    </header>
    {children}
  </article>
}

/** What an armed control is about to do, said in its place with the one button that does it.
 *  The ask still lapses by itself after a few seconds, as it always has. */
function Confirm({ says, children }: { says: string; children: ReactNode }) {
  return <div className="rollout-confirm">
    <p>{says}</p>
    <span className="rollout-actions">{children}</span>
  </div>
}

/** A company's own name and the line that says who to ask.
 *
 *  This is presentation and nothing else: it is kept on this computer, for whoever is looking at
 *  this computer. Grid Core has nowhere to keep a brand yet, and inventing a place for one in a
 *  tab would mean a schema step that belongs with the phase that moves a product onto the core.
 */
function Branding({ realm }: { realm: GridRealm }) {
  const [brand, setBrand] = useState(() => readGridBrand(realm.key))
  const [saved, setSaved] = useState("")
  if (realm.role !== "host" || !may(realm.held, "managePeople")) return null
  return <section aria-label="Branding" className="rollout-group">
    <h3 className="rollout-group-title">Branding <span>on this computer only</span></h3>
    <div className="rollout-card">
      <div className="grid-fields">
        <div className="grid-field grid-ask">
          <label>Company name<Input value={brand.company} placeholder={realm.name} onChange={event => setBrand({ ...brand, company: event.target.value })} /></label>
        </div>
        <div className="grid-field grid-ask grid-field-wide">
          <label>Who to ask<Input value={brand.support} placeholder="Ask Grace in Security." onChange={event => setBrand({ ...brand, support: event.target.value })} /></label>
        </div>
      </div>
      <div className="rollout-card-foot realm-foot">
        <p className="rollout-said">{saved || "Shown wherever this grid is named here. Nobody else's computer sees it, and a backup does not carry it."}</p>
        <Button size="xs" variant="outline" onClick={() => { writeGridBrand(realm.key, brand); setSaved("Kept on this computer.") }}>Save</Button>
      </div>
    </div>
  </section>
}

function Computers({ realm, run }: { realm: GridRealm; run: GridRun }) {
  const { armed, arm, disarm } = useArmed()
  if (!may(realm.held, "readRealm") || realm.role !== "host") return null
  // Only the grids that really have these are offered them: the Closed Neo Grid can leave a
  // computer out and bring it back, and both it and the Sandbox Grid can take one out for good.
  const canDrain = may(realm.held, "drainHost") && realm.key === "models"
  const canRevoke = may(realm.held, "revokeDevice") && (realm.key === "models" || realm.key === "workspaces")
  const takeOut = (hostId: string) => realm.key === "models" ? grids.models.removeHost(hostId) : grids.workspaces.removeHost(hostId)
  const online = realm.hosts.filter(host => host.online).length
  return <section aria-label="Computers" className="rollout-group">
    <h3 className="rollout-group-title">Computers <span>{online} of {realm.hosts.length} online</span></h3>
    {realm.hosts.length ? <div className="rollout-cards">{realm.hosts.map(host => {
      const leaving = armed === `drain-${host.id}`
      const leavesOut = `Nothing new runs on ${host.name} until it is brought back. What runs there now finishes.`
      const takesOut = realm.key === "workspaces"
        ? `${host.name} stops holding desks for this grid and gives its reservations back. It can join again with the invite.`
        : `${host.name} leaves this grid and removes the model it was given. It can join again with the invite.`
      return <Item key={host.id} name={host.name}>
        <p className="grids-card-state">
          <i aria-hidden="true" className="grid-dot" data-online={host.online || undefined} />
          <span>
            {host.online ? "Online" : "Away"}
            {host.commitment === "dedicated" ? ", committed whole" : host.offered ? `, offering ${host.offered.cpu} cores and ${host.offered.memoryGb} GB of memory` : ""}
            {host.draining || host.excluded ? ", left out of this grid's work" : ""}
            {host.workspaces ? `, holding ${host.workspaces} ${host.workspaces === 1 ? "desk" : "desks"}` : ""}
          </span>
        </p>
        {canDrain || canRevoke ? <div className="rollout-actions rollout-card-foot">
          {canDrain ? host.excluded
            ? <Button size="xs" variant="outline" onClick={() => void run(`Bringing ${host.name} back`, () => grids.models.bringHostBack(host.id), `${host.name} is back in the grid`)}>Bring back</Button>
            : leaving
              ? <Confirm says={leavesOut}>
                <Button size="xs" variant="destructive" onClick={() => { disarm(); void run(`Leaving ${host.name} out`, () => grids.models.drainHost(host.id), `${host.name} is left out`) }}>Confirm leaving out {host.name}</Button>
              </Confirm>
              : <Button size="xs" variant="ghost" title={leavesOut} onClick={() => arm(`drain-${host.id}`)}>Leave out</Button>
            : null}
          {canRevoke ? armed === `revoke-${host.id}`
            ? <Confirm says={takesOut}>
              <Button size="xs" variant="destructive" onClick={() => { disarm(); void run(`Taking ${host.name} out`, () => takeOut(host.id), `${host.name} is out of this grid`) }}>Confirm taking out {host.name}</Button>
            </Confirm>
            : <Button size="xs" variant="ghost" title={takesOut} onClick={() => arm(`revoke-${host.id}`)}>Take out</Button>
            : null}
        </div> : null}
      </Item>
    })}</div> : <p className="rollout-said">No other computer has joined this grid yet.</p>}
  </section>
}

function Work({ realm }: { realm: GridRealm }) {
  if (!may(realm.held, "readRealm")) return null
  const { queued, running } = realm.work
  if (!queued && !running && !realm.jobs.length) return null
  return <section aria-label="Work" className="rollout-group">
    <h3 className="rollout-group-title">Work <span>{running} running, {queued} waiting</span></h3>
    {realm.jobs.length ? <div className="rollout-cards">{realm.jobs.slice(0, 10).map(job => <Item key={job.id} name={job.name}>
      <p className="rollout-text">{workerStatus({ state: job.state, stage: job.step, summary: job.summary, error: job.error }).text}</p>
    </Item>)}</div> : null}
  </section>
}

function Models({ realm, run }: { realm: GridRealm; run: GridRun }) {
  const { armed, arm, disarm } = useArmed()
  if (!shows(realm, realm.held, "models", "readRealm")) return null
  const mayManage = may(realm.held, "manageModels")
  return <section aria-label="Models" className="rollout-group">
    <h3 className="rollout-group-title">Models <span>{realm.plans.length} {realm.plans.length === 1 ? "plan" : "plans"}</span></h3>
    {realm.plans.length ? <div className="rollout-cards">{realm.plans.map(plan => {
      const drops = `Every computer running ${plan.model} stops serving it and gives the room back.`
      return <Item key={plan.id} name={plan.model} tag={capitalise(plan.rules)}>
        <p className="rollout-text">{plan.ready} of {plan.wanted} computers ready.</p>
        {mayManage ? <div className="rollout-actions rollout-card-foot">
          {armed === `plan-${plan.id}`
            ? <Confirm says={drops}>
              <Button size="xs" variant="destructive" onClick={() => { disarm(); void run(`Dropping ${plan.model}`, () => grids.models.removePlan(plan.id), `${plan.model} is no longer ordered`) }}>Confirm dropping {plan.model}</Button>
            </Confirm>
            : <Button size="xs" variant="ghost" title={drops} onClick={() => arm(`plan-${plan.id}`)}>Drop</Button>}
        </div> : null}
      </Item>
    })}</div> : <p className="rollout-said">No model is ordered in this grid yet.</p>}
  </section>
}

function Workspaces({ realm }: { realm: GridRealm }) {
  if (!shows(realm, realm.held, "workspaces", "readRealm")) return null
  return <section aria-label="Desks" className="rollout-group">
    <h3 className="rollout-group-title">Desks <span>{realm.workspaces.length} in all</span></h3>
    {realm.workspaces.length ? <div className="rollout-cards">{realm.workspaces.slice(0, 20).map(desk => {
      const where = desk.owner ? `${desk.owner}${desk.host ? `, on ${desk.host}` : ""}.` : desk.host ? `On ${desk.host}.` : ""
      return <Item key={desk.id} name={desk.name} tag={capitalise(desk.productState)} tone={desk.productState === "failed" ? "stop" : undefined}>
        {where ? <p className="rollout-text">{where}</p> : null}
        {desk.note ? <p className="rollout-said">{desk.note}</p> : null}
      </Item>
    })}</div> : <p className="rollout-said">No desk has been ordered in this grid yet.</p>}
  </section>
}

function Credentials({ realm }: { realm: GridRealm }) {
  if (!shows(realm, realm.held, "credentials", "readRealm")) return null
  return <section aria-label="Credentials" className="rollout-group">
    <h3 className="rollout-group-title">Credentials <span>{realm.credentials.length} in all</span></h3>
    {realm.credentials.length ? <div className="rollout-cards">{realm.credentials.map(credential => <Item key={credential.id} name={credential.name}>
      <p className="rollout-text">{credential.destinations.length ? `May be sent to ${credential.destinations.join(", ")}.` : "No destination yet."}</p>
      <p className="rollout-said">
        {credential.rules ? `${credential.rules} ${credential.rules === 1 ? "rule says" : "rules say"} who may use it.` : "Nobody may use it yet."}
      </p>
    </Item>)}</div> : <p className="rollout-said">No credential has been added to this grid yet.</p>}
  </section>
}

function Waiting({ realm, run }: { realm: GridRealm; run: GridRun }) {
  if (!shows(realm, realm.held, "credentials", "readRealm")) return null
  const mayDecide = may(realm.held, "approveCredential")
  return <section aria-label="Waiting for approval" className="rollout-group">
    <h3 className="rollout-group-title">Waiting <span>{realm.approvals.length ? `${realm.approvals.length} for a person to decide` : "nothing right now"}</span></h3>
    {realm.approvals.length ? <div className="rollout-cards">{realm.approvals.map(approval => <Item key={approval.id} name={approval.requestedBy} tag={approval.resource}>
      <p className="rollout-text">{approval.why || `${capitalise(approval.method ?? "a request")} with ${approval.resource}.`}</p>
      {mayDecide ? <div className="rollout-actions rollout-card-foot">
        <Button size="xs" onClick={() => void run("Agreeing to the request", () => grids.credentials.decide(approval.id, { kind: "once" }), "Agreed once")}>Agree once</Button>
        <Button size="xs" variant="outline" onClick={() => void run("Agreeing for an hour", () => grids.credentials.decide(approval.id, { kind: "hours", hours: 1 }), "Agreed for an hour")}>Agree for an hour</Button>
        <Button size="xs" variant="ghost" onClick={() => void run("Refusing the request", () => grids.credentials.decide(approval.id, { kind: "denied", reason: "Refused from the grid's status" }), "Refused")}>Refuse</Button>
      </div> : null}
    </Item>)}</div> : null}
  </section>
}
