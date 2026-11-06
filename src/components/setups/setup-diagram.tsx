import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from "react"
import { Button } from "@/components/ui/button"
import { errorText, isUnavailable, newOperationId, SetupCommandError, setupsApi } from "@/api/setups/setups-api"
import { setupFeed } from "@/api/setups/progress"
import type { ResourceAction, ResourceView, SetupPlan } from "@/api/setups/types"
import { diagramItems, layoutSetup, NODE_HEIGHT, NODE_WIDTH, neighbour, type DiagramEdge, type DiagramLayout, type DiagramNode } from "./diagram-layout"
import { SetupReview } from "./setup-views"

/** A setup as a picture: its parts, where they run, what each needs, and what may reach what.
 *
 *  Every part is a button: arrow keys move between them, Enter or Space opens its controls, and
 *  the same picture is also a plain list below it. Owned parts have a solid edge and borrowed
 *  ones a dashed edge, and both say so in words; a dependency is a thin line with a hollow arrow,
 *  a connection a dashed line with a solid arrow and its ports, so nothing depends on colour.
 */

const KIND_WORDS: Record<string, string> = {
  environment: "Sandbox", grid: "Grid", compute_pool: "Computers", worker_group: "Workers", model_service: "Model",
  workspace_pool: "Desks", access_binding: "Access", credential_broker: "Credentials", service_publication: "Website or API",
  volume: "Stored data", connection: "Connection", job: "Job", artifact_store: "Results store",
  vm_sandbox: "VM sandbox",
}
const OBSERVED: Record<string, string> = { unknown: "Not checked yet", missing: "Missing", present: "There", running: "Running", stopped: "Stopped" }
const COST: Record<string, string> = { free: "Free", unknown: "Cost not known", accruing: "Costing money now", stopped: "No longer charging", shutdown_unconfirmed: "Shutdown not confirmed, it may still be charging" }
const ACTION_WORDS: Record<ResourceAction, string> = { start: "Start", stop: "Stop", remove: "Remove…", detach: "Detach…", logs: "Logs" }

const kindWords = (kind: string) => KIND_WORDS[kind] ?? kind.replace(/_/g, " ")
const ports = (edge: Pick<DiagramEdge, "ports">) => edge.ports.length ? `${edge.ports.length === 1 ? "port" : "ports"} ${edge.ports.join(", ")}` : "no ports named"

/** One small mark per kind, in the sidebar's hand: one stroke, one solid accent. */
const KIND_MARKS: Record<string, ReactNode> = {
  environment: <><rect x="2" y="3" width="16" height="12" rx="2.5" /><rect x="7" y="6.5" width="6" height="5" rx="1" fill="currentColor" stroke="none" /></>,
  grid: <><path d="M3 5h2.6M4.3 3.7v2.6M14.4 5H17M15.7 3.7v2.6M3 15h2.6M4.3 13.7v2.6M14.4 15H17M15.7 13.7v2.6" /><circle cx="10" cy="10" r="2.2" fill="currentColor" stroke="none" /></>,
  compute_pool: <><rect x="2.5" y="4" width="6" height="5" rx="1.2" fill="currentColor" stroke="none" /><rect x="11.5" y="4" width="6" height="5" rx="1.2" /><rect x="7" y="11.5" width="6" height="5" rx="1.2" /></>,
  worker_group: <><circle cx="6" cy="7" r="2.2" fill="currentColor" stroke="none" /><circle cx="14" cy="7" r="2.2" /><path d="M2.5 16a3.5 3.5 0 0 1 7 0M10.5 16a3.5 3.5 0 0 1 7 0" /></>,
  model_service: <><path d="M5 15V5l10 10V5" /><circle cx="5" cy="5" r="1.7" fill="currentColor" stroke="none" /><circle cx="15" cy="15" r="1.7" fill="currentColor" stroke="none" /></>,
  workspace_pool: <><path d="M10 2.5l3.2 3.2L10 8.9 6.8 5.7z" fill="currentColor" /><path d="M5.7 6.8l3.2 3.2-3.2 3.2-3.2-3.2zM14.3 6.8l3.2 3.2-3.2 3.2-3.2-3.2zM10 11.1l3.2 3.2L10 17.5l-3.2-3.2z" /></>,
  access_binding: <><circle cx="7" cy="10" r="3.4" /><path d="M10.4 10H17.5M15 10v2.6M12.8 10v1.8" /><circle cx="7" cy="10" r="1.2" fill="currentColor" stroke="none" /></>,
  credential_broker: <><path d="M5 17V9a5 5 0 0 1 10 0v8M3 17h14M10 12v2.4" /><circle cx="10" cy="11" r="1.4" fill="currentColor" stroke="none" /></>,
  service_publication: <><rect x="2.5" y="3.5" width="15" height="13" rx="2.2" /><path d="M2.5 7.5h15M6 11h8M6 13.6h5" /><circle cx="5" cy="5.5" r=".8" fill="currentColor" stroke="none" /></>,
  volume: <><ellipse cx="10" cy="5.5" rx="6" ry="2.2" fill="currentColor" stroke="none" /><path d="M4 5.5v9c0 1.2 2.7 2.2 6 2.2s6-1 6-2.2v-9" /></>,
  connection: <><path d="M3 10h12M12 6.5 15.5 10 12 13.5" /><circle cx="4" cy="10" r="1.6" fill="currentColor" stroke="none" /></>,
  job: <><path d="M15.5 10a5.5 5.5 0 1 1-1.6-3.9" /><path d="M14.5 3.2v3.3h-3.3" /><circle cx="10" cy="10" r="1.6" fill="currentColor" stroke="none" /></>,
  artifact_store: <><rect x="3" y="7" width="14" height="10" rx="1.8" /><path d="M2.5 4h15v3h-15zM8 11h4" /></>,
  vm_sandbox: <><rect x="2" y="3" width="16" height="12" rx="2.5" /><path d="M10 6.2l3 1.2v2.3c0 1.7-1.3 2.9-3 3.4-1.7-.5-3-1.7-3-3.4V7.4z" fill="currentColor" stroke="none" /></>,
}

function KindMark({ kind, x, y }: { kind: string; x: number; y: number }) {
  return <g transform={`translate(${x} ${y})`} className="setup-node-mark" fill="none" stroke="currentColor" strokeWidth={1.5} strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
    {KIND_MARKS[kind] ?? <circle cx="10" cy="10" r="6" />}
  </g>
}

const short = (text: string, length = 20) => text.length > length ? `${text.slice(0, length - 1)}…` : text

/** What a part is, in one sentence a screen reader says when it is reached. */
function partSentence(resource: ResourceView, names: Map<string, string>) {
  const ownership = resource.owned ? "owned by this setup" : resource.borrowedFrom ? `borrowed from ${resource.borrowedFrom}, never removed by this setup` : "borrowed, never removed by this setup"
  const needs = (resource.dependsOn ?? []).filter(id => names.has(id)).map(id => names.get(id)!)
  return [
    `${resource.label}: ${kindWords(resource.kind).toLowerCase()}`,
    resource.placement ? `on ${resource.placement}` : null,
    ownership,
    OBSERVED[resource.observed ?? "unknown"]?.toLowerCase(),
    needs.length ? `needs ${needs.join(" and ")}` : null,
    resource.drift ?? null,
  ].filter(Boolean).join(", ")
}

function connectionSentence(edge: DiagramEdge, names: Map<string, string>) {
  const from = names.get(edge.from) ?? edge.from, to = names.get(edge.to) ?? edge.to
  return `${edge.resource?.label ?? "Connection"}: ${from} ${edge.direction === "both" ? "and" : "can reach"} ${to}${edge.direction === "both" ? " can reach each other" : ""} on ${ports(edge)}`
}

function edgePath(layout: DiagramLayout, edge: DiagramEdge) {
  const at = new Map(layout.nodes.map(node => [node.id, node]))
  const from = at.get(edge.from)!, to = at.get(edge.to)!
  const midY = (node: DiagramNode) => node.y + NODE_HEIGHT / 2
  if (from.x === to.x) {
    // Side by side in one column: out into the gap beside them and back.
    const sx = from.x + NODE_WIDTH, ex = to.x + NODE_WIDTH
    return `M${sx} ${midY(from)} C${edge.x} ${midY(from)} ${edge.x} ${midY(to)} ${ex} ${midY(to)}`
  }
  const rightwards = to.x > from.x
  const sx = rightwards ? from.x + NODE_WIDTH : from.x
  const ex = rightwards ? to.x : to.x + NODE_WIDTH
  const bend = (ex - sx) / 2
  return `M${sx} ${midY(from)} C${sx + bend} ${midY(from)} ${ex - bend} ${midY(to)} ${ex} ${midY(to)}`
}

export function SetupDiagram({ setupId, resources, revision, onLogs }: {
  setupId: string
  resources: ResourceView[]
  revision?: number | null
  /** Opens the setup's Activity, where its logs are. */
  onLogs(): void
}) {
  const layout = useMemo(() => layoutSetup(resources), [resources])
  const items = useMemo(() => diagramItems(layout), [layout])
  const names = useMemo(() => new Map(resources.map(resource => [resource.resourceId, resource.label])), [resources])
  const [current, setCurrent] = useState<string | null>(null)
  const [opened, setOpened] = useState<string | null>(null)
  const svg = useRef<SVGSVGElement>(null)
  const focused = current ?? items[0]?.id ?? null
  const focusItem = (id: string) => requestAnimationFrame(() => svg.current?.querySelector<SVGGElement>(`[data-item="${CSS.escape(id)}"]`)?.focus())

  if (!resources.length) return null

  const onKey = (event: KeyboardEvent, id: string) => {
    if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setOpened(id); return }
    const next = neighbour(items, id, event.key)
    if (!next || next === id) return
    event.preventDefault()
    setCurrent(next)
    focusItem(next)
  }
  const choose = (id: string) => { setCurrent(id); setOpened(id) }
  const openedResource = opened ? resources.find(resource => resource.resourceId === opened) ?? null : null
  const connections = layout.edges.filter(edge => edge.type === "connects")

  return <figure className="setup-diagram">
    <div className="setup-diagram-scroll">
      <svg
        ref={svg}
        role="group"
        aria-label={`How it fits together: ${layout.nodes.length} ${layout.nodes.length === 1 ? "part" : "parts"}${connections.length ? ` and ${connections.length} ${connections.length === 1 ? "connection" : "connections"}` : ""}. Use the arrow keys to move, Enter to open one.`}
        viewBox={`0 0 ${layout.width} ${layout.height}`}
        width={layout.width}
        height={layout.height}
      >
        <defs>
          <marker id={`${setupId}-needs`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M1 1 9 5 1 9" fill="none" stroke="currentColor" strokeWidth="1.4" />
          </marker>
          <marker id={`${setupId}-connects`} viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">
            <path d="M0 0 10 5 0 10z" fill="currentColor" />
          </marker>
        </defs>
        {layout.lanes.map(lane => <g key={lane.name} className="setup-lane" aria-hidden="true">
          <rect x={4} y={lane.y} width={layout.width - 8} height={lane.height} rx={12} />
          <text x={16} y={lane.y + 17}>{lane.name}</text>
        </g>)}
        {layout.edges.map(edge => <path
          key={edge.id}
          className={`setup-edge setup-edge-${edge.type}`}
          d={edgePath(layout, edge)}
          markerEnd={`url(#${setupId}-${edge.type})`}
          markerStart={edge.type === "connects" && edge.direction === "both" ? `url(#${setupId}-connects)` : undefined}
          aria-hidden="true"
        />)}
        {layout.nodes.map(node => {
          const resource = node.resource
          return <g
            key={node.id}
            data-item={node.id}
            className="setup-node"
            data-owned={resource.owned || undefined}
            data-drift={resource.drift ? "" : undefined}
            role="button"
            tabIndex={focused === node.id ? 0 : -1}
            aria-label={partSentence(resource, names)}
            aria-expanded={opened === node.id}
            onClick={() => choose(node.id)}
            onFocus={() => setCurrent(node.id)}
            onKeyDown={event => onKey(event, node.id)}
          >
            <rect x={node.x} y={node.y} width={NODE_WIDTH} height={NODE_HEIGHT} rx={11} />
            <KindMark kind={resource.kind} x={node.x + 12} y={node.y + 18} />
            <text className="setup-node-name" x={node.x + 42} y={node.y + 24}>{short(resource.label)}</text>
            <text className="setup-node-sub" x={node.x + 42} y={node.y + 42}>{short(`${kindWords(resource.kind)} · ${resource.owned ? OBSERVED[resource.observed ?? "unknown"] : "Borrowed"}`, 24)}</text>
          </g>
        })}
        {connections.map(edge => {
          const id = edge.resource!.resourceId
          return <g
            key={edge.id}
            data-item={id}
            className="setup-link-handle"
            role="button"
            tabIndex={focused === id ? 0 : -1}
            aria-label={connectionSentence(edge, names)}
            aria-expanded={opened === id}
            onClick={() => choose(id)}
            onFocus={() => setCurrent(id)}
            onKeyDown={event => onKey(event, id)}
          >
            <path d={`M${edge.x} ${edge.y - 8} l8 8 -8 8 -8 -8z`} />
            <text x={edge.x + 12} y={edge.y - 6}>{ports(edge)}</text>
          </g>
        })}
      </svg>
    </div>
    <figcaption className="setup-diagram-legend">
      <span><svg width="34" height="10" aria-hidden="true"><path d="M1 5h26" className="setup-edge setup-edge-needs" /><path d="M26 1 32 5 26 9" fill="none" stroke="currentColor" /></svg> needs: waits for that part to be ready</span>
      <span><svg width="34" height="10" aria-hidden="true"><path d="M1 5h26" className="setup-edge setup-edge-connects" /><path d="M26 1 33 5 26 9z" fill="currentColor" /></svg> connects: may reach it, on the ports shown</span>
      <span><svg width="22" height="14" aria-hidden="true"><rect x="1" y="1" width="20" height="12" rx="3" className="setup-legend-owned" /></svg> owned by this setup</span>
      <span><svg width="22" height="14" aria-hidden="true"><rect x="1" y="1" width="20" height="12" rx="3" className="setup-legend-borrowed" /></svg> borrowed, never removed by it</span>
    </figcaption>
    <details className="setup-diagram-list">
      <summary>The same, as a list</summary>
      <ul aria-label="Parts">
        {layout.nodes.map(node => <li key={node.id}>
          <button type="button" className="hub-link" onClick={() => choose(node.id)}>{partSentence(node.resource, names)}</button>
        </li>)}
      </ul>
      {connections.length ? <ul aria-label="Connections">
        {connections.map(edge => <li key={edge.id}>
          <button type="button" className="hub-link" onClick={() => choose(edge.resource!.resourceId)}>{connectionSentence(edge, names)}</button>
        </li>)}
      </ul> : null}
    </details>
    {openedResource ? <PartControls
      key={openedResource.resourceId}
      setupId={setupId}
      resource={openedResource}
      revision={revision}
      onLogs={onLogs}
      onClose={() => { const back = openedResource.resourceId; setOpened(null); focusItem(back) }}
    /> : null}
  </figure>
}

/** The standard controls of one part: what the engine allows on it now. A borrowed part can only
 *  be detached, which ends this setup's use of it and leaves the part with its owner. */
function PartControls({ setupId, resource, revision, onLogs, onClose }: {
  setupId: string
  resource: ResourceView
  revision?: number | null
  onLogs(): void
  onClose(): void
}) {
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const [review, setReview] = useState<{ action: "remove" | "detach"; plan: SetupPlan } | null>(null)
  const [agreed, setAgreed] = useState<string[]>([])
  const ids = useRef(new Map<string, string>())
  const heading = useRef<HTMLHeadingElement>(null)
  // Opening a part's controls takes focus to them; closing gives it back to the part.
  useEffect(() => { heading.current?.focus() }, [])
  const allowed: ResourceAction[] = resource.actions ?? (resource.owned ? [] : ["detach"])
  const shown = resource.owned ? allowed : allowed.filter(action => action === "detach" || action === "logs")
  const idFor = (key: string) => { const known = ids.current.get(key); if (known) return known; const made = newOperationId(); ids.current.set(key, made); return made }

  async function run(label: string, work: () => Promise<unknown>, key?: string) {
    if (busy) return false
    setBusy(label)
    setError("")
    try {
      await work()
      if (key) ids.current.delete(key)
      await setupFeed.refresh(setupId)
      return true
    } catch (reason) {
      if (key && !(reason instanceof SetupCommandError && reason.retryable)) ids.current.delete(key)
      setError(isUnavailable(reason) || (reason instanceof SetupCommandError && (reason.code === "unsupported_here" || reason.code === "invalid_request"))
        ? "This isn't in this build of Yougori yet. Nothing was changed."
        : errorText(reason))
      return false
    } finally {
      setBusy("")
    }
  }

  const act = (action: ResourceAction) => {
    if (action === "logs") { onLogs(); return }
    if (action === "remove" || action === "detach") {
      void run(action === "remove" ? "Working out what removing it does" : "Working out what detaching it does", async () => {
        setReview({ action, plan: await setupsApi.reviewResourceAction(setupId, resource.resourceId, action, revision ?? null) })
      })
      return
    }
    const key = `${action}:${revision ?? ""}`
    void run(action === "start" ? "Starting" : "Stopping", () => setupsApi.resourceAction(setupId, resource.resourceId, action, { expectedRevision: revision ?? null, operationId: idFor(key) }), key)
  }

  return <section className="setup-part" aria-label={`${resource.label} controls`} onKeyDown={event => { if (event.key === "Escape") { event.stopPropagation(); onClose() } }}>
    <h4 tabIndex={-1} ref={heading}>{resource.label} <span className="setup-note">{kindWords(resource.kind)}</span></h4>
    <dl className="setup-outputs">
      <div><dt>Where</dt><dd>{resource.placement ?? "Not known yet"}</dd></div>
      <div><dt>State</dt><dd>{OBSERVED[resource.observed ?? "unknown"]}</dd></div>
      <div><dt>Cost</dt><dd>{COST[resource.cost ?? "unknown"]}</dd></div>
      <div><dt>Ownership</dt><dd>{resource.owned ? "Owned by this setup" : `Borrowed${resource.borrowedFrom ? ` from ${resource.borrowedFrom}` : ""}, never removed by this setup`}</dd></div>
      {resource.exposure ? <div><dt>Reachable</dt><dd>Port {resource.exposure.port} of {resource.exposure.to}, {resource.exposure.access === "quick" ? "through a quick public link" : resource.exposure.access === "domain" ? "on your own domain" : resource.exposure.access === "lan" ? "on this network" : resource.exposure.access}</dd></div> : null}
      {resource.retainedData ? <div><dt>Data</dt><dd>Kept when the setup is removed</dd></div> : null}
      {resource.drift ? <div><dt>Changed</dt><dd>{resource.drift}</dd></div> : null}
    </dl>
    {review ? <div className="setup-removal">
      <SetupReview plan={review.plan} agreed={agreed} onAgree={(id, on) => setAgreed(current => on ? [...current.filter(one => one !== id), id] : current.filter(one => one !== id))} />
      <p className="setup-note">{review.action === "detach" ? `Only this setup's use of ${resource.label} ends. ${resource.label} itself stays as it is, with its owner.` : `Its data is kept unless you delete it separately.`}</p>
      <div className="setup-actions">
        <Button size="xs" variant="destructive" disabled={Boolean(busy) || Boolean(review.plan.blockers?.length)} onClick={() => {
          const plan = review.plan, key = `${review.action}:${plan.digest}`
          const offered = new Set((plan.consents ?? []).map(consent => consent.id))
          void run(review.action === "detach" ? "Detaching" : "Removing", () => setupsApi.apply(plan, idFor(key), undefined, agreed.filter(id => offered.has(id))), key).then(done => { if (done) setReview(null) })
        }}>{review.action === "detach" ? `Detach ${resource.label}` : `Remove ${resource.label}`}</Button>
        <Button size="xs" variant="ghost" onClick={() => setReview(null)}>Keep it</Button>
      </div>
    </div> : <div className="setup-actions">
      {shown.map(action => <Button key={action} size="xs" variant={action === "remove" || action === "detach" ? "ghost" : "outline"} disabled={Boolean(busy)} onClick={() => act(action)}>{ACTION_WORDS[action]}</Button>)}
      {!shown.includes("logs") ? <Button size="xs" variant="ghost" onClick={onLogs}>See what happened</Button> : null}
      <Button size="xs" variant="ghost" onClick={onClose}>Close</Button>
    </div>}
    {!shown.some(action => action !== "logs") ? <p className="setup-note">{resource.owned
      ? "Yougori can't act on one part on its own yet. Start, stop or remove the whole setup from its Overview and Settings."
      : "A borrowed part can only be detached, and this build of Yougori can't detach one on its own yet. It is never removed by this setup."}</p> : null}
    {busy ? <p role="status" className="setup-note">{busy}…</p> : null}
    {error ? <p role="alert" className="grid-error">{error}</p> : null}
  </section>
}
