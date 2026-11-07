import { useCallback, useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { ExternalLink } from "@/components/shared/external-link"
import { CATALOGUE, GROUPS } from "@/api/setups/catalogue"
import { isMoving, useOperation, useSetupFeed } from "@/api/setups/progress"
import type { CapabilityGroup, NextAction, OperationBrief, Output, ResourceRef, ResourceView, SetupDetailView, SetupSummary, SourceRef } from "@/api/setups/types"
import { useSetupBuilder } from "./builder-context"
import { StateLabel } from "./setup-marks"
import { LastFailure, SetupOutputs, SetupProgress, SetupReadiness } from "./setup-views"
import { SetupDiagram } from "./setup-diagram"
import { SetupBackups } from "./setup-backups"
import { SetupArtifacts, SetupJobs, SetupModelUsage, SetupSandboxLogs } from "./setup-jobs"
import { SetupRemoval } from "./setup-removal"
import { SetupRepair } from "./setup-repair"
import { PrivateOutputs } from "./setup-private-outputs"
import { SetupProduct } from "./setup-product"
import { errorText, setupsApi } from "@/api/setups/setups-api"
import { useNewerVersion } from "@/api/setups/versions"
import type { SetupPermissions as SetupPermissionsView } from "@/api/setups/types"
import { lifecycleOf, operationOf } from "./setup-words"
import { lastFailure, stoppedPartWay, useSetupActions } from "./use-setup-actions"
import { ALL_ACTIONS, GENERAL_ACTIONS, useNextActions } from "./use-next-actions"
import "./setups.css"

/** One setup in full: the same frame for every setup, Overview, its capabilities, Activity and
 *  Settings, with a tab for each kind of thing it holds. Everything shown is what the engine
 *  records of a setup made from a template. */

export type DetailTab = "overview" | "activity" | "settings" | CapabilityGroup

const NAMES = Object.fromEntries(CATALOGUE.map(capability => [capability.id, capability.name]))
const GROUP_OF = new Map(CATALOGUE.map(capability => [capability.id, capability.group]))
const KINDS_OF = new Map(CATALOGUE.map(capability => [capability.id, capability.resourceKinds as string[]]))

/** A capability group's tab, in the words of what it holds. */
const GROUP_TAB: Record<CapabilityGroup, string> = {
  grid_workers: "Workers",
  ai_models: "Models",
  website_api: "Website & API",
  people_access: "People",
  files_data: "Data",
  automation_recovery: "Automation",
}

/** A declared view that maps to a capability-group tab, so a template can ask for that tab even
 *  when no capability of the group is on. Only the views whose tab the desktop can already draw are
 *  here; any other declared view is left to the capabilities to decide, so an unknown one changes
 *  nothing. `storage`/`files` → the Data tab is the one the plan calls for first. */
const VIEW_TAB: Partial<Record<string, CapabilityGroup>> = {
  storage: "files_data", files: "files_data",
  workers: "grid_workers", models: "ai_models",
  people: "people_access", workspaces: "people_access",
  publications: "website_api", api: "website_api",
  jobs: "automation_recovery", logs: "automation_recovery",
}

/** Declared views that bring the setup's history forward. When one is present, Activity sits right
 *  after Overview rather than near the end, because its history is the first thing to look at. */
const ACTIVITY_FIRST_VIEWS = new Set(["logs", "audit", "attempts", "jobs", "reports"])

/** The resource kinds each group's tab shows, matching what `GroupContent` draws. Used as a fallback
 *  so a group tab a declared view asked for (with no capability of its own) still lists its parts
 *  instead of looking empty. */
const GROUP_KINDS: Record<CapabilityGroup, string[]> = {
  grid_workers: ["compute_pool", "worker_group", "grid", "vm_sandbox"],
  ai_models: ["model_service"],
  website_api: ["service_publication"],
  people_access: ["workspace_pool", "access_binding", "credential_broker"],
  files_data: ["volume", "artifact_store"],
  automation_recovery: [],
}

const OBSERVED: Record<string, string> = { unknown: "Not checked yet", missing: "Missing", present: "There", running: "Running", stopped: "Stopped" }
const COST: Record<string, string> = {
  free: "Free",
  unknown: "Cost not known",
  accruing: "Costing money now",
  stopped: "No longer charging",
  shutdown_unconfirmed: "Shutdown not confirmed, it may still be charging",
}

/** What each kind of operation did, as its line in Activity. */
const OPERATION_KIND: Record<string, string> = { create: "Set up", update: "Change", start: "Start", stop: "Stop", remove: "Remove", repair: "Repair", refresh: "Check" }

/** A part is out of place when the engine last saw it missing, or saw it drift from what the setup
 *  says. Either is what a repair puts right; both together still make one repair. */
const outOfPlace = (resource: ResourceRef) => resource.observed === "missing" || Boolean(resource.drift)
/** Whether any part of a setup is missing or drifted, so repair is worth offering. */
const needsRepair = (resources: ResourceRef[] | undefined) => (resources ?? []).some(outOfPlace)

const when = (seconds: number | null | undefined) => seconds ? new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : ""
/** A time on its own ("20:41"), for the parts table where the day is the same context. Uses this
 *  computer's locale, like the rest of the view. */
const timeOnly = (seconds: number | null | undefined) => seconds ? new Date(seconds * 1000).toLocaleTimeString(undefined, { timeStyle: "short" }) : ""

function sourceLine(source: SourceRef | null | undefined) {
  if (!source) return ""
  if (source.kind === "hub") return `From hub/${source.publisher}/${source.name}@${source.version}`
  if (source.kind === "local_folder") return "From a folder on this computer"
  return "From another setup"
}

/** The tablist pattern: arrow keys, Home and End move between tabs, and the panel follows. */
function Tabs({ label, tabs, current, onPick }: { label: string; tabs: { id: DetailTab; name: string }[]; current: DetailTab; onPick(tab: DetailTab): void }) {
  const refs = useRef<Partial<Record<string, HTMLButtonElement | null>>>({})
  const move = (event: KeyboardEvent, at: number) => {
    const to = event.key === "ArrowRight" ? at + 1 : event.key === "ArrowLeft" ? at - 1 : event.key === "Home" ? 0 : event.key === "End" ? tabs.length - 1 : null
    if (to === null) return
    event.preventDefault()
    const next = tabs[(to + tabs.length) % tabs.length]!
    onPick(next.id)
    refs.current[next.id]?.focus()
  }
  return <div className="setup-tabs" role="tablist" aria-label={label}>
    {tabs.map((tab, at) => <button
      key={tab.id}
      ref={node => { refs.current[tab.id] = node }}
      type="button"
      role="tab"
      id={`setup-tab-${tab.id}`}
      aria-controls={`setup-panel-${tab.id}`}
      aria-selected={tab.id === current}
      tabIndex={tab.id === current ? 0 : -1}
      onClick={() => onPick(tab.id)}
      onKeyDown={event => move(event, at)}
    >{tab.name}</button>)}
  </div>
}

function Resources({ resources, label = "Resources" }: { resources: ResourceView[]; label?: string }) {
  if (!resources.length) return <p className="setup-note">Nothing recorded yet.</p>
  return <div className="setup-table-wrap">
    <table className="setup-table" aria-label={label}>
      <thead><tr><th scope="col">Name</th><th scope="col">Kind</th><th scope="col">State</th><th scope="col">Checked</th><th scope="col">Cost</th><th scope="col">Ownership</th><th scope="col">Data</th></tr></thead>
      <tbody>{resources.map(resource => {
        // When it was last looked at, and whether that look found it well. A part never looked at
        // shows a dash; one looked at but not found well says so, so a quiet drift isn't a surprise.
        const checked = timeOnly(resource.lastCheckedAt)
        const notHealthy = resource.lastCheckedAt != null && resource.lastHealthyAt == null
        return <tr key={resource.resourceId}>
          <th scope="row">{resource.label}{resource.drift ? <span className="setup-note"> {resource.drift}</span> : null}</th>
          <td>{resource.kind.replace(/_/g, " ")}</td>
          <td>{OBSERVED[resource.observed ?? "unknown"] ?? resource.observed}</td>
          <td>{checked ? <>Checked {checked}{notHealthy ? <span className="setup-note"> · not healthy when last checked</span> : null}</> : "—"}</td>
          <td>{COST[resource.cost ?? "unknown"] ?? resource.cost}</td>
          <td>{resource.owned ? "Owned by this setup" : resource.borrowedFrom ? `Borrowed from ${resource.borrowedFrom}, never removed by it` : "Borrowed, never removed by it"}</td>
          <td>{resource.retainedData ? "Kept when it is removed" : "—"}</td>
        </tr>
      })}</tbody>
    </table>
  </div>
}

/** "What it is allowed to do": the setup's effective permissions, read from the engine when the
 *  Settings tab opens. Lists what each part may do, what it downloads, which secret reaches which part
 *  (by the question it comes from, never a value), the folders it may use and the costs. When the
 *  engine can't read them again it shows the plain reason instead of guessing. */
function Permissions({ setupId }: { setupId: string }) {
  const [state, setState] = useState<{ loading: boolean; error: string; data: SetupPermissionsView | null }>({ loading: true, error: "", data: null })
  useEffect(() => {
    let live = true
    setState({ loading: true, error: "", data: null })
    // Deferred so a build without this call shows nothing rather than throwing, the way the
    // private outputs are read. A build that has it but can't read now shows the plain reason.
    Promise.resolve().then(() => setupsApi.permissions(setupId))
      .then(data => { if (live) setState({ loading: false, error: "", data }) })
      .catch(reason => { if (live) setState({ loading: false, error: reason instanceof TypeError ? "" : errorText(reason), data: null }) })
    return () => { live = false }
  }, [setupId])

  const list = (label: string, lines: string[]) => lines.length
    ? <><h4 className="setup-permissions-head">{label}</h4><ul className="setup-plain-list">{lines.map((line, index) => <li key={index}>{line}</li>)}</ul></>
    : null

  return <section className="setup-permissions" aria-label="What it is allowed to do">
    <h3 className="setup-panel-title">What it is allowed to do</h3>
    {state.loading ? <p className="setup-note">Reading its permissions…</p>
      : state.error ? <p className="setup-note" role="alert">{state.error}</p>
      : !state.data ? null
      : state.data.known === false ? <p className="setup-note">{state.data.reason || "Yougori can't read this setup's permissions again."}</p>
      : <>
        {state.data.version ? <p className="setup-note">Read from the template at version {state.data.version}.</p> : null}
        {list("Allowed to", state.data.permissions ?? [])}
        {list("Downloads", (state.data.downloads ?? []).map(download => `${download.name}${download.from ? ` from ${download.from}` : ""}`))}
        {list("Secrets", (state.data.secrets ?? []).map(secret => `${secret.resource}: ${secret.variable} — from ${secret.source}`))}
        {list("Folders on this computer", (state.data.pcAccess ?? []).map(folder => `${folder.environment}: ${folder.path}${folder.staged ? " (a copy; the folder changes only with files you approve)" : folder.readOnly ? " (read only)" : ""}`))}
        {list("Costs", state.data.costs ?? [])}
        {!(state.data.permissions?.length || state.data.downloads?.length || state.data.secrets?.length || state.data.pcAccess?.length || state.data.costs?.length)
          ? <p className="setup-note">It asks for nothing beyond running on this computer.</p> : null}
        <SetupProduct detail={state.data} lines="declares" />
      </>}
  </section>
}

/** How a publication is reached, in words. */
const ACCESS_WORD: Record<string, string> = {
  lan: "on the local network", quick: "a quick public link", quick_link: "a quick public link",
  domain: "your own domain", private: "this computer only", loopback: "this computer only",
}

/** Group-specific content for a capability tab, built only from what the engine already sent: the
 *  group's resources (with placement, exposure, connection and data), the setup's safe outputs, and —
 *  for data — a link to the backups panel. Where a field isn't known, it says so rather than inventing
 *  one. `parts` are the resources whose kind belongs to this group. */
function GroupContent({ group, parts, outputs }: { group: CapabilityGroup; parts: ResourceRef[]; outputs: Output[] }) {
  const views = parts as ResourceView[]
  // A safe output whose value is a web address, matched to a publication for its link.
  const urlFor = (label: string) => outputs.find(output => output.label === label || output.key === label)?.value

  if (group === "website_api") {
    const published = views.filter(view => view.kind === "service_publication")
    if (!published.length) return <p className="setup-note">No website or API is published yet.</p>
    return <ul className="setup-group-list" aria-label="Published addresses">
      {published.map(view => {
        const exposure = view.exposure
        const url = urlFor(view.label)
        return <li key={view.resourceId}>
          <strong>{view.label}</strong>
          {exposure ? <span> — {exposure.to} on port {exposure.port}, reached {ACCESS_WORD[exposure.access] ?? exposure.access}</span> : <span className="setup-note"> — how it is reached is not recorded yet</span>}
          {url ? <span> · <ExternalLink href={url}>{url}</ExternalLink></span> : null}
          <span className="setup-note"> · {OBSERVED[view.observed ?? "unknown"] ?? "state not checked"}</span>
        </li>
      })}
    </ul>
  }

  if (group === "files_data") {
    const volumes = views.filter(view => view.kind === "volume" || view.kind === "artifact_store")
    if (!volumes.length) return <p className="setup-note">No stored data yet.</p>
    return <ul className="setup-group-list" aria-label="Stored data">
      {volumes.map(view => <li key={view.resourceId}>
        <strong>{view.label}</strong>
        <span> — {view.retainedData ? "its data is kept when the setup is removed" : "its data is removed with the setup"}</span>
        {view.placement ? <span className="setup-note"> · {view.placement}</span> : null}
        <span className="setup-note"> · backups are listed under Automation &amp; recovery</span>
      </li>)}
    </ul>
  }

  if (group === "ai_models") {
    const models = views.filter(view => view.kind === "model_service")
    if (!models.length) return <p className="setup-note">No model is set up yet.</p>
    return <ul className="setup-group-list" aria-label="Model services">
      {models.map(view => <li key={view.resourceId}>
        <strong>{view.label}</strong>
        <span className="setup-note"> — {OBSERVED[view.observed ?? "unknown"] ?? "state not checked"}</span>
        {view.placement ? <span className="setup-note"> · {view.placement}</span> : null}
      </li>)}
    </ul>
  }

  if (group === "grid_workers") {
    const pools = views.filter(view => view.kind === "compute_pool" || view.kind === "worker_group" || view.kind === "grid")
    const vms = views.filter(view => view.kind === "vm_sandbox")
    if (!pools.length && !vms.length) return <p className="setup-note">No grid or workers yet.</p>
    return <>
      {pools.length ? <ul className="setup-group-list" aria-label="Grid and workers">
        {pools.map(view => <li key={view.resourceId}>
          <strong>{view.label}</strong>
          <span> — {view.placement ?? "where it runs is not recorded yet"}</span>
          <span className="setup-note"> · {OBSERVED[view.observed ?? "unknown"] ?? "state not checked"}</span>
        </li>)}
      </ul> : null}
      {vms.length ? <ul className="setup-group-list" aria-label="VM sandboxes">
        {vms.map(view => <li key={view.resourceId}>
          <strong>{view.label}</strong>
          <span> — {view.placement ?? "a restricted VM on this computer"}</span>
          <span className="setup-note"> · {OBSERVED[view.observed ?? "unknown"] ?? "state not checked"}</span>
          <div className="setup-note">{view.remoteVm
            ? "Its run ID is among the setup's outputs. Open its parent environment and use Advanced tools, or yougori sandbox remote start, outcome and stop. It depends on its local parent's lease. Stopping the VM leaves the server's power and externally managed billing unchanged."
            : "Its id is among the setup's outputs. Run commands in it, review its changes and promote the files you approve by opening its environment in My computer, or with yougori sandbox exec, review and promote. A stopped one is launched fresh when the setup starts."}</div>
        </li>)}
      </ul> : null}
    </>
  }

  if (group === "people_access") {
    const pools = views.filter(view => view.kind === "workspace_pool")
    const bindings = views.filter(view => view.kind === "access_binding" || view.kind === "credential_broker")
    if (!pools.length && !bindings.length) return <p className="setup-note">No workspaces or access bindings yet.</p>
    return <>
      {pools.length ? <ul className="setup-group-list" aria-label="Workspaces">
        {pools.map(view => <li key={view.resourceId}><strong>{view.label}</strong>{view.placement ? <span className="setup-note"> — {view.placement}</span> : null}</li>)}
      </ul> : null}
      {bindings.length ? <ul className="setup-group-list" aria-label="Access">
        {bindings.map(view => <li key={view.resourceId}><strong>{view.label}</strong><span className="setup-note"> — {view.kind === "credential_broker" ? "brokers credentials, never hands them out" : "access binding"}</span></li>)}
      </ul> : null}
    </>
  }

  return null
}

function OperationList({ operations, chosen, onChoose }: { operations: OperationBrief[]; chosen: string | null; onChoose(id: string): void }) {
  if (!operations.length) return <p className="setup-note">Nothing has happened to it yet.</p>
  return <ol className="setup-operations" aria-label="Recent changes">
    {operations.map(operation => {
      const state = operation.state === "failed" && operation.error?.code === "operation_cancelled" ? { text: "Cancelled", tone: "off" as const } : operationOf(operation.state)
      return <li key={operation.operationId}>
        <button type="button" className="setup-operation" aria-pressed={chosen === operation.operationId} onClick={() => onChoose(operation.operationId)}>
          <span className="setup-operation-kind">{OPERATION_KIND[operation.kind] ?? operation.kind.replace(/_/g, " ")}</span>
          <StateLabel tone={state.tone}>{state.text}</StateLabel>
          <span className="setup-note">{when(operation.createdAt)}</span>
        </button>
        {operation.error && operation.error.code !== "operation_cancelled" ? <p className="setup-note">{operation.error.message}</p> : null}
      </li>
    })}
  </ol>
}

function ChosenOperation({ operationId, onAction, handles }: { operationId: string; onAction(action: NextAction): void; handles: ReadonlySet<string> }) {
  const operation = useOperation(operationId)
  return operation
    ? <SetupProgress operation={operation} onAction={onAction} handles={handles} idPrefix={`setup-activity-${operationId}`} />
    : <p role="status" className="setup-note">Reading what happened…</p>
}

/** A setup made from a template, from what the engine records of it. A grid made from one has
 *  the grid's own page as its `product` tab. */
function TemplateSetup({ summary, detail, tab, setTab }: {
  summary: SetupSummary
  detail: SetupDetailView | undefined
  tab: DetailTab
  setTab(tab: DetailTab): void
}) {
  const builder = useSetupBuilder()
  const feed = useSetupFeed()
  const actions = useSetupActions(summary, detail)
  const configure = useCallback(() => builder.open({ mode: "configure", setupId: summary.setupId, setupName: summary.name }), [builder, summary.setupId, summary.name])
  const newer = useNewerVersion(summary.source)
  const update = useCallback(() => {
    if (summary.source.kind !== "hub" || !newer) return
    builder.open({ mode: "configure", setupId: summary.setupId, setupName: summary.name, update: { publisher: summary.source.publisher, name: summary.source.name, version: newer } })
  }, [builder, summary.setupId, summary.name, summary.source, newer])
  const next = useNextActions({ onActivity: () => setTab("activity"), onConfigure: configure })
  const currentId = summary.currentOperation?.operationId ?? null
  const current = currentId ? feed.operations[currentId] ?? null : null
  const moving = isMoving(current)
  const newerNote = newer ? <p className="setup-callout" role="status">
    Version {newer} of this template is out. Updating shows what changes before anything does, and keeps the choices you made.
    {" "}<Button size="xs" variant="outline" disabled={moving} onClick={update}>Update to {newer}</Button>
  </p> : null
  const [chosen, setChosen] = useState<string | null>(null)
  const [cancelling, setCancelling] = useState(false)
  const operationAction = (action: NextAction, operationId: string | null) => {
    if (GENERAL_ACTIONS.has(action.kind)) { next.act(action); return }
    if (!operationId) return
    if (action.kind === "cancel") { setCancelling(true); return }
    if (action.kind === "review") { configure(); return }
    const target = (action.kind === "continue" || action.kind === "reconcile") && action.operation ? action.operation : operationId
    void actions.lifecycle(action.kind === "reconcile" ? "reconcile" : "retry", action.kind === "reconcile" ? "Checking what happened" : "Trying again", target)
  }
  const failed = lastFailure(summary, detail)
  const listed = detail?.actions
  const may = (action: "start" | "stop" | "remove") => listed ? listed.includes(action) : false
  // Repair is offered only when a part of the setup is missing or has drifted from what it says,
  // and only on a setup that still exists to be put right: a part out of place is what repair is
  // for, and the engine takes "repair" on any such setup, so the parts are the signal. A setup the
  // engine won't act on at all (it offers nothing) is left alone.
  const repairable = needsRepair(detail?.resources) && Boolean(listed?.length)
  const capabilities = detail?.capabilities ?? []
  const groupOf = (id: string) => GROUP_OF.get(id)
  const status = <>
    {actions.error ? <p role="alert" className="grid-error">{actions.error}</p> : null}
    {actions.busy ? <p role="status" className="setup-note">{actions.busy}…</p> : null}
    {next.said ? <p role="status" className="setup-callout">{next.said}</p> : null}
  </>

  if (tab === "overview") return <div className="setup-panel-body">
    {(detail?.notes ?? []).map((note, index) => <p key={index} className="setup-note">{note}</p>)}
    {newerNote}
    {detail?.readable === false ? <p role="alert" className="grid-error">Yougori found this setup's records but couldn't read them. Nothing was changed.</p> : null}
    {detail ? <SetupReadiness capabilities={capabilities} names={NAMES} label={`Readiness of ${summary.name}`} onAction={next.act} /> : <p role="status" className="setup-note">Reading how it is doing…</p>}
    {repairable ? <p className="setup-callout" role="status">
      Some parts are missing or have drifted from what this setup says. Repair puts them back and touches nothing else. It shows what it would do before anything changes.
      {" "}<Button size="xs" variant="outline" disabled={Boolean(actions.busy) || moving} onClick={() => setTab("settings")}>Repair…</Button>
    </p> : null}
    {current && (moving || current.state === "failed") ? <SetupProgress operation={current} onAction={action => operationAction(action, currentId)} handles={ALL_ACTIONS} busy={Boolean(actions.busy)} idPrefix={`setup-${summary.setupId}-overview`} agreeFor={currentId ? { setupId: summary.setupId, operationId: currentId } : null} /> : null}
    {failed ? <LastFailure operation={failed} busy={Boolean(actions.busy)} onRetry={() => void actions.lifecycle("retry", "Trying again", failed.operationId)} onDetails={() => setTab("activity")} /> : null}
    {cancelling && currentId ? <p className="setup-confirm" role="group" aria-label={`Cancel the change to ${summary.name}?`}>
      <span>Cancel it? What is already done is kept.</span>
      <Button size="xs" variant="destructive-outline" onClick={() => { setCancelling(false); void actions.cancel(currentId) }}>Cancel the change</Button>
      <Button size="xs" variant="ghost" onClick={() => { document.getElementById(`setup-${summary.setupId}-overview-cancel`)?.focus(); setCancelling(false) }}>Keep going</Button>
    </p> : null}
    {detail?.resources.length ? <section className="setup-panel-section" aria-labelledby={`setup-${summary.setupId}-diagram`}>
      <h3 className="setup-panel-title" id={`setup-${summary.setupId}-diagram`}>How it fits together</h3>
      <SetupDiagram setupId={summary.setupId} resources={detail.resources} revision={detail.revision} onLogs={() => setTab("activity")} />
    </section> : null}
    <SetupOutputs outputs={detail?.outputs} />
    {detail ? <PrivateOutputs setupId={summary.setupId} revision={detail.revision} /> : null}
    {status}
    <div className="setup-actions">
      {may("start") ? <Button size="xs" variant="outline" disabled={Boolean(actions.busy) || moving} onClick={() => void actions.lifecycle("start", "Starting")}>Start</Button> : null}
      {may("stop") ? <Button size="xs" variant="outline" disabled={Boolean(actions.busy) || moving} onClick={() => void actions.lifecycle("stop", "Stopping")}>Stop</Button> : null}
      <Button size="xs" variant="ghost" onClick={() => setTab("settings")}>Settings</Button>
    </div>
  </div>

  if (tab === "activity") {
    const operations = detail?.operations ?? []
    const shown = chosen ?? currentId ?? operations[0]?.operationId ?? null
    return <div className="setup-panel-body setup-activity">
      <OperationList operations={operations} chosen={shown} onChoose={setChosen} />
      {shown ? <ChosenOperation operationId={shown} onAction={action => operationAction(action, shown)} handles={ALL_ACTIONS} /> : null}
      {status}
    </div>
  }

  if (tab === "settings") return <div className="setup-panel-body">
    <p className="setup-note">{[sourceLine(summary.source), detail ? `Revision ${detail.revision}` : ""].filter(Boolean).join(" · ")}</p>
    {newerNote}
    <div className="setup-actions">
      <Button size="xs" variant="outline" disabled={moving} onClick={configure}>Configure</Button>
      <Button size="xs" variant="outline" disabled={moving} onClick={() => builder.open({ mode: "configure", setupId: summary.setupId, setupName: summary.name, addCapability: true })}>Add capability</Button>
      <Button size="xs" variant="outline" disabled={Boolean(actions.busy) || moving} title="Looks again at every resource it owns, and says what changed outside Yougori." onClick={() => void actions.lifecycle("refresh", "Checking every part")}>Check every part</Button>
    </div>
    <Chosen detail={detail} />
    <h3 className="setup-panel-title">What it is made of</h3>
    <Resources resources={detail?.resources ?? []} label={`Resources of ${summary.name}`} />
    <Permissions setupId={summary.setupId} />
    <SetupProduct detail={detail} lines="none" />
    {status}
    {actions.repair ? <SetupRepair
      name={summary.name} plan={actions.repair} names={NAMES} agreed={actions.agreed} onAgree={actions.agree} busy={Boolean(actions.busy)}
      onRepair={() => void actions.confirmRepair()}
      onKeep={() => { actions.keepRepair(); requestAnimationFrame(() => document.getElementById(`setup-${summary.setupId}-settings-repair`)?.focus()) }}
    /> : repairable ? <div className="setup-actions">
      <Button id={`setup-${summary.setupId}-settings-repair`} size="xs" variant="outline" disabled={Boolean(actions.busy) || moving} onClick={() => void actions.reviewRepair()}>Repair…</Button>
      <span className="setup-note">Some parts are missing or have drifted. Repair puts them back and touches nothing else.</span>
    </div> : null}
    {actions.removal ? <SetupRemoval
      name={summary.name} plan={actions.removal} names={NAMES} agreed={actions.agreed} onAgree={actions.agree} busy={Boolean(actions.busy)}
      onRemove={() => void actions.confirmRemoval()}
      onKeep={() => { actions.keep(); requestAnimationFrame(() => document.getElementById(`setup-${summary.setupId}-settings-remove`)?.focus()) }}
    /> : may("remove") ? <div className="setup-actions">
      <Button id={`setup-${summary.setupId}-settings-remove`} size="xs" variant="ghost" disabled={Boolean(actions.busy) || moving} onClick={() => void actions.reviewRemoval()}>Remove…</Button>
    </div> : null}
  </div>

  // A capability group: its capabilities and the parts they own. When the group tab is here only
  // because a declared view asked for it (no capability of its own contributes kinds), its parts
  // fall back to the group's natural kinds, so the tab still lists what it holds.
  const group = tab as CapabilityGroup
  const mine = capabilities.filter(capability => groupOf(capability.id) === group)
  const fromCapabilities = new Set(mine.flatMap(capability => KINDS_OF.get(capability.id) ?? []))
  const kinds = fromCapabilities.size ? fromCapabilities : new Set(GROUP_KINDS[group])
  const parts = (detail?.resources ?? []).filter(resource => kinds.has(resource.kind))
  return <div className="setup-panel-body">
    <SetupReadiness capabilities={mine} names={NAMES} label={GROUP_TAB[group]} onAction={next.act} />
    <GroupContent group={group} parts={parts} outputs={detail?.outputs ?? []} />
    <h3 className="setup-panel-title">Parts</h3>
    <Resources resources={parts} label={`${GROUP_TAB[group]} parts`} />
    {group === "automation_recovery" ? <>
      <SetupJobs setupId={summary.setupId} parts={detail?.resources ?? []} moving={moving} />
      {capabilities.some(capability => capability.id === "run.health_logs") || (detail?.views ?? []).includes("logs") ? <SetupSandboxLogs setupId={summary.setupId} parts={detail?.resources ?? []} /> : null}
      <SetupBackups setupId={summary.setupId} name={summary.name} moving={moving} />
    </> : null}
    {group === "files_data" && (detail?.resources ?? []).some(resource => resource.kind === "artifact_store") ? <SetupArtifacts setupId={summary.setupId} /> : null}
    {group === "ai_models" && capabilities.some(capability => capability.id === "models.cloud") ? <SetupModelUsage setupId={summary.setupId} /> : null}
    {status}
    <div className="setup-actions"><Button size="xs" variant="outline" disabled={moving} onClick={configure}>Configure</Button></div>
  </div>
}

/** What the person chose when it was set up: capabilities on or off, and public answers. */
function Chosen({ detail }: { detail: SetupDetailView | undefined }) {
  const chosen = detail?.customization
  const capabilities = Object.entries(chosen?.capabilities ?? {}).filter(([, on]) => typeof on === "boolean")
  const answers = Object.entries(chosen?.answers ?? {}).filter(([, value]) => ["string", "number", "boolean"].includes(typeof value))
  if (!capabilities.length && !answers.length) return null
  return <>
    <h3 className="setup-panel-title">What you chose</h3>
    <dl className="setup-outputs">
      {capabilities.map(([id, on]) => <div key={`c-${id}`}><dt>{NAMES[id] ?? id}</dt><dd>{on ? "On" : "Off"}</dd></div>)}
      {answers.map(([id, value]) => <div key={`a-${id}`}><dt>{id.replace(/[_-]+/g, " ")}</dt><dd>{typeof value === "boolean" ? (value ? "Yes" : "No") : String(value)}</dd></div>)}
    </dl>
  </>
}

export function SetupDetailView({ setupId, onBack, initialTab = "overview" }: {
  /** The engine's record, for a setup made from a template. */
  setupId: string | null
  onBack(): void
  initialTab?: DetailTab
}) {
  const feed = useSetupFeed()
  const summary = setupId ? feed.setups?.find(one => one.setupId === setupId) ?? null : null
  const detail = setupId ? feed.details[setupId] : undefined
  const [tab, setTab] = useState<DetailTab>(initialTab)
  const heading = useRef<HTMLHeadingElement>(null)
  useEffect(() => { heading.current?.focus() }, [])

  const tabs = useMemo<{ id: DetailTab; name: string }[]>(() => {
    // The template's declared views, read defensively: a view the desktop can't draw a tab for is
    // left out, so an unknown or absent view changes nothing. A view can bring in a group tab that
    // the capabilities alone wouldn't (such as `storage` → Data), and a history view brings Activity
    // forward.
    const views = detail?.views ?? []
    const groups = new Set((detail?.capabilities ?? []).map(capability => GROUP_OF.get(capability.id)).filter(Boolean))
    for (const view of views) { const group = VIEW_TAB[view]; if (group) groups.add(group) }
    const activity = { id: "activity" as DetailTab, name: "Activity" }
    const activityFirst = views.some(view => ACTIVITY_FIRST_VIEWS.has(view))
    const groupTabs = GROUPS.filter(group => groups.has(group.id)).map(group => ({ id: group.id as DetailTab, name: GROUP_TAB[group.id] }))
    return [
      { id: "overview", name: "Overview" },
      ...(activityFirst ? [activity] : []),
      ...groupTabs,
      ...(activityFirst ? [] : [activity]),
      { id: "settings", name: "Settings" },
    ]
  }, [detail?.capabilities, detail?.views])
  const shownTab = tabs.some(one => one.id === tab) ? tab : "overview"

  const name = summary?.name ?? (setupId ? "This setup" : "")
  const state = summary ? stoppedPartWay(summary) ? { text: "Stopped part way", tone: "attention" as const } : lifecycleOf(summary.state) : null
  const subtitle = sourceLine(summary?.source)

  let panel: ReactNode
  if (summary) panel = <TemplateSetup summary={summary} detail={detail} tab={shownTab} setTab={setTab} />
  else panel = <p role="status" className="setup-note">{feed.setups === null ? "Reading this setup…" : "This setup isn't on this computer any more."}</p>

  return <div className="setup-detail">
    <div className="setup-detail-head">
      <Button size="xs" variant="ghost" onClick={onBack}>All setups</Button>
      <div className="setup-item-head">
        <h2 ref={heading} tabIndex={-1} className="setup-detail-name">{name}</h2>
        {state ? <StateLabel tone={state.tone}>{state.text}</StateLabel> : null}
        {subtitle ? <p className="setup-item-source">{subtitle}</p> : null}
      </div>
    </div>
    <Tabs label={`${name} sections`} tabs={tabs} current={shownTab} onPick={setTab} />
    <div role="tabpanel" id={`setup-panel-${shownTab}`} aria-labelledby={`setup-tab-${shownTab}`} className="setup-panel">
      {panel}
    </div>
  </div>
}
