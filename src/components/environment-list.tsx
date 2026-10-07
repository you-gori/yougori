import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type CSSProperties, type KeyboardEvent, type MouseEvent, type ReactNode } from "react"
import { workspaceApi } from "@/api/workspace-api"
import { Button } from "@/components/ui/button"
import type { GraphEnvironment } from "@/components/graph-capabilities"
import { ModelNodeProgress } from "@/components/model-node-progress"
import { EnvironmentNodeMenu } from "@/components/environment-node-menu"
import { usePlatform } from "@/context/platform-context"
import { formatBytesFromGb, formatDateTime, formatRelativeTime } from "@/lib/domain"
import { environmentLabel } from "@/lib/environment-category"
import "@/components/environment-list.css"

export interface ListConnection { id: string; sourceId: string; targetId: string; direction: "oneWay" | "bidirectional"; active: boolean; enforcementStatus?: "enforced" | "pending" | "error" }

type SortKey = "name" | "type" | "status" | "cpu" | "memory" | "storage" | "links"
type StatusFilter = "all" | "running" | "stopped" | "attention"
type Group = "none" | "type" | "status"
interface Prefs { sort: SortKey; descending: boolean; status: StatusFilter; type: string; group: Group; density: "comfortable" | "compact" }

const prefsKey = "yougori.environment-list.v1"
const defaultPrefs: Prefs = { sort: "name", descending: false, status: "all", type: "all", group: "none", density: "comfortable" }
function readPrefs(): Prefs {
  try { return { ...defaultPrefs, ...JSON.parse(localStorage.getItem(prefsKey) ?? "{}") } } catch { return defaultPrefs }
}

const columns: Array<{ key: SortKey | null; label: string; className?: string }> = [
  { key: "name", label: "Environment" },
  { key: "status", label: "Status" },
  { key: "cpu", label: "CPU", className: "environment-list-metric" },
  { key: null, label: "GPU", className: "environment-list-metric" },
  { key: "memory", label: "Memory", className: "environment-list-metric" },
  { key: "storage", label: "Storage", className: "environment-list-metric" },
  { key: "links", label: "Connections" },
  { key: null, label: "Access" },
  { key: null, label: "Services" },
  { key: null, label: "Actions", className: "environment-list-actions-head" },
]
const columnCount = columns.length + 1

const needsAttention = (environment: GraphEnvironment, links: ListConnection[]) => environment.status === "error" || Boolean(environment.workspace?.notice) || links.some(link => link.active && link.enforcementStatus === "error")
function statusGroup(environment: GraphEnvironment, links: ListConnection[]) {
  if (needsAttention(environment, links)) return "Needs attention"
  if (environment.status === "provisioning") return "Creating"
  if (environment.status === "running") return environment.kind === "cloud" ? "Connected" : "Running"
  if (environment.status === "paused") return "Paused"
  return environment.kind === "cloud" ? "Disconnected" : "Stopped"
}
const statusRank = ["Needs attention", "Creating", "Running", "Connected", "Paused", "Stopped", "Disconnected"]

interface RowContext {
  environments: Map<string, GraphEnvironment>
  colors: Record<string, string>
  links: Map<string, ListConnection[]>
  expanded: Set<string>
  selected: Set<string>
  toggleExpanded(id: string): void
  toggleSelected(id: string, range: boolean): void
  onConnect(sourceId: string, targetId?: string): void
}
const ListContext = createContext<RowContext | null>(null)

export function EnvironmentList<T extends { id: string; data: { environment: GraphEnvironment; preview?: boolean } }>({ items, connections, colors, onConnect, children }: {
  items: T[]
  connections: ListConnection[]
  colors: Record<string, string>
  onConnect(sourceId: string, targetId?: string): void
  children(item: T): ReactNode
}) {
  const { setEnvironmentStatus, environmentActions } = usePlatform()
  const [prefs, setPrefs] = useState(readPrefs)
  const [query, setQuery] = useState("")
  const [expanded, setExpanded] = useState<Set<string>>(() => new Set())
  const [selected, setSelected] = useState<Set<string>>(() => new Set())
  const [bulkBusy, setBulkBusy] = useState(false)
  const searchRef = useRef<HTMLInputElement>(null)
  const bodyRef = useRef<HTMLDivElement>(null)
  const anchor = useRef<string | null>(null)
  const update = useCallback((change: Partial<Prefs>) => setPrefs(current => {
    const next = { ...current, ...change }
    try { localStorage.setItem(prefsKey, JSON.stringify(next)) } catch { /* Preferences stay in memory. */ }
    return next
  }), [])

  const environments = useMemo(() => items.map(item => item.data.environment), [items])
  const byId = useMemo(() => new Map(environments.map(environment => [environment.id, environment])), [environments])
  const previewIds = useMemo(() => new Set(items.filter(item => item.data.preview).map(item => item.id)), [items])
  const itemById = useMemo(() => new Map(items.map(item => [item.id, item])), [items])
  const links = useMemo(() => {
    const result = new Map<string, ListConnection[]>()
    for (const connection of connections) for (const id of [connection.sourceId, connection.targetId]) result.set(id, [...(result.get(id) ?? []), connection])
    return result
  }, [connections])
  const linksOf = useCallback((id: string) => links.get(id) ?? [], [links])

  const types = useMemo(() => [...new Set(environments.map(environment => environmentLabel(environment)))].sort(), [environments])
  const counts = useMemo(() => {
    const result = { all: environments.length, running: 0, stopped: 0, attention: 0 }
    for (const environment of environments) {
      if (needsAttention(environment, linksOf(environment.id))) result.attention++
      if (environment.status === "running") result.running++
      else if (environment.status !== "provisioning") result.stopped++
    }
    return result
  }, [environments, linksOf])

  const visible = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean)
    const filtered = environments.filter(environment => {
      const environmentLinks = linksOf(environment.id)
      if (prefs.status === "running" && environment.status !== "running") return false
      if (prefs.status === "stopped" && (environment.status === "running" || environment.status === "provisioning")) return false
      if (prefs.status === "attention" && !needsAttention(environment, environmentLinks)) return false
      if (prefs.type !== "all" && environmentLabel(environment) !== prefs.type) return false
      if (!terms.length) return true
      const haystack = [
        environment.name, environmentLabel(environment), environment.description, environment.provider ?? "", statusGroup(environment, environmentLinks),
        environment.kind === "cloud" ? "" : environment.runtime,
        ...(environment.workspace?.services ?? []).flatMap(service => [`:${service.port}`, String(service.port), service.name, service.protocol]),
        ...(environment.workspace?.publications ?? []).flatMap(publication => publication.urls),
        ...environmentLinks.map(link => byId.get(link.sourceId === environment.id ? link.targetId : link.sourceId)?.name ?? ""),
      ].join(" ").toLowerCase()
      return terms.every(term => haystack.includes(term))
    })
    const value = (environment: GraphEnvironment): string | number => {
      switch (prefs.sort) {
        case "type": return environmentLabel(environment)
        case "status": return statusRank.indexOf(statusGroup(environment, linksOf(environment.id)))
        case "cpu": return environment.kind === "cloud" ? -1 : environment.cpuUsage
        case "memory": return environment.kind === "cloud" ? -1 : environment.memoryUsageGb
        case "storage": return environment.kind === "cloud" ? -1 : environment.storageDeltaGb
        case "links": return linksOf(environment.id).length
        default: return environment.name.toLowerCase()
      }
    }
    return filtered.sort((a, b) => {
      const x = value(a), y = value(b)
      const order = typeof x === "number" && typeof y === "number" ? x - y : String(x).localeCompare(String(y), undefined, { numeric: true })
      return (prefs.descending ? -order : order) || a.name.localeCompare(b.name, undefined, { numeric: true })
    })
  }, [environments, byId, linksOf, prefs, query])

  const groups = useMemo(() => {
    if (prefs.group === "none") return [{ label: "", rows: visible }]
    const result = new Map<string, GraphEnvironment[]>()
    for (const environment of visible) {
      const label = prefs.group === "type" ? environmentLabel(environment) : statusGroup(environment, linksOf(environment.id))
      result.set(label, [...(result.get(label) ?? []), environment])
    }
    return [...result].map(([label, rows]) => ({ label, rows })).sort((a, b) => prefs.group === "status" ? statusRank.indexOf(a.label) - statusRank.indexOf(b.label) : a.label.localeCompare(b.label))
  }, [visible, prefs.group, linksOf])

  useEffect(() => {
    // Drop selections for environments that were deleted.
    setSelected(current => { const next = new Set([...current].filter(id => byId.has(id))); return next.size === current.size ? current : next })
  }, [byId])

  const toggleExpanded = useCallback((id: string) => setExpanded(current => { const next = new Set(current); if (!next.delete(id)) next.add(id); return next }), [])
  const toggleSelected = useCallback((id: string, range: boolean) => {
    if (previewIds.has(id)) return
    setSelected(current => {
      const next = new Set(current)
      const ids = visible.filter(environment => !previewIds.has(environment.id)).map(environment => environment.id)
      const from = anchor.current ? ids.indexOf(anchor.current) : -1
      const to = ids.indexOf(id)
      const checked = !current.has(id)
      if (range && from >= 0 && to >= 0) for (const item of ids.slice(Math.min(from, to), Math.max(from, to) + 1)) { if (checked) next.add(item); else next.delete(item) }
      else if (checked) next.add(id)
      else next.delete(id)
      return next
    })
    anchor.current = id
  }, [visible, previewIds])

  const selectableVisible = visible.filter(environment => !previewIds.has(environment.id))
  const selectedVisible = selectableVisible.filter(environment => selected.has(environment.id))
  const allSelected = selectableVisible.length > 0 && selectedVisible.length === selectableVisible.length
  const canStart = (environment: GraphEnvironment) => environment.kind !== "cloud" && environment.kind !== "computerBranch" && environment.provider !== "nativeSandbox" && (environment.status === "stopped" || environment.status === "paused") && !environmentActions[environment.id]
  const canStop = (environment: GraphEnvironment) => environment.kind !== "cloud" && environment.kind !== "computerBranch" && environment.provider !== "nativeSandbox" && (environment.status === "running" || environment.status === "paused") && !environmentActions[environment.id]
  const startable = selectedVisible.filter(canStart), stoppable = selectedVisible.filter(canStop)
  const bulk = async (targets: GraphEnvironment[], status: "running" | "stopped") => {
    setBulkBusy(true)
    try { await Promise.allSettled(targets.map(environment => setEnvironmentStatus(environment.id, status))) }
    finally { setBulkBusy(false) }
  }

  const running = environments.filter(environment => environment.status === "running" && environment.kind !== "cloud")
  const memory = running.reduce((total, environment) => total + environment.memoryUsageGb, 0)
  const storage = environments.reduce((total, environment) => total + (environment.kind === "cloud" ? 0 : environment.storageDeltaGb), 0)
  const filtered = query.trim() !== "" || prefs.status !== "all" || prefs.type !== "all"

  const sortBy = (key: SortKey) => update(prefs.sort === key ? { descending: !prefs.descending } : { sort: key, descending: key === "cpu" || key === "memory" || key === "storage" || key === "links" })
  const moveFocus = (event: KeyboardEvent<HTMLElement>) => {
    const target = event.target as HTMLElement
    if ((event.key !== "ArrowDown" && event.key !== "ArrowUp") || target.closest("input, textarea, select, [role=switch], [role=menu]")) return
    const row = target.closest<HTMLElement>("tr[data-environment-id]")
    const anchors = [...(bodyRef.current?.querySelectorAll<HTMLElement>("[data-list-focus]") ?? [])]
    if (!anchors.length) return
    event.preventDefault()
    const index = row ? anchors.findIndex(item => row.contains(item)) : -1
    anchors[Math.max(0, Math.min(anchors.length - 1, index + (event.key === "ArrowDown" ? 1 : -1)))]?.focus()
  }

  useEffect(() => {
    const focusSearch = (event: globalThis.KeyboardEvent) => {
      const target = event.target as HTMLElement | null
      if (event.key !== "/" || event.ctrlKey || event.metaKey || event.altKey || event.defaultPrevented || target?.closest("input, textarea, select, [contenteditable], [role=dialog], .xterm") || document.querySelector("[role=dialog]")) return
      if (!searchRef.current) return
      event.preventDefault()
      searchRef.current.focus()
    }
    window.addEventListener("keydown", focusSearch)
    return () => window.removeEventListener("keydown", focusSearch)
  }, [])

  const context = useMemo<RowContext>(() => ({ environments: byId, colors, links, expanded, selected, toggleExpanded, toggleSelected, onConnect }), [byId, colors, links, expanded, selected, toggleExpanded, toggleSelected, onConnect])

  return <ListContext.Provider value={context}>
    <div className="environment-list-view" data-density={prefs.density} onKeyDown={moveFocus}>
      {environments.length ? <div className="environment-list-toolbar" role="toolbar" aria-label="Filter and sort environments">
        {selectedVisible.length ? <div className="environment-list-bulk" role="group" aria-label="Selected environments">
          <strong>{selectedVisible.length} selected</strong>
          <Button size="xs" variant="outline" disabled={bulkBusy || !startable.length} onClick={() => void bulk(startable, "running")}>Start{startable.length ? ` ${startable.length}` : ""}</Button>
          <Button size="xs" variant="outline" disabled={bulkBusy || !stoppable.length} onClick={() => void bulk(stoppable, "stopped")}>Stop{stoppable.length ? ` ${stoppable.length}` : ""}</Button>
          <Button size="xs" variant="ghost" onClick={() => setSelected(new Set())}>Clear</Button>
        </div> : <>
          <label className="environment-list-search">
            <span className="sr-only">Search environments</span>
            <input ref={searchRef} type="search" value={query} placeholder="Search name, type, port, link…" onChange={event => setQuery(event.target.value)} onKeyDown={event => { if (event.key === "Escape" && query) { event.stopPropagation(); setQuery("") } }} />
            <kbd aria-hidden="true">/</kbd>
          </label>
          <div className="environment-list-segments" role="group" aria-label="Status filter">
            {([["all", "All"], ["running", "Running"], ["stopped", "Stopped"], ["attention", "Attention"]] as const).map(([value, label]) => value === "attention" && !counts.attention && prefs.status !== "attention" ? null :
              <button key={value} type="button" aria-pressed={prefs.status === value} data-tone={value === "attention" ? "attention" : undefined} onClick={() => update({ status: value })}>{label}<span>{counts[value]}</span></button>)}
          </div>
          {types.length > 1 ? <label className="environment-list-select"><span>Type</span><select value={prefs.type} onChange={event => update({ type: event.target.value })}><option value="all">All</option>{types.map(type => <option key={type} value={type}>{type}</option>)}</select></label> : null}
          <label className="environment-list-select"><span>Group</span><select value={prefs.group} onChange={event => update({ group: event.target.value as Group })}><option value="none">None</option><option value="type">Type</option><option value="status">Status</option></select></label>
          <div className="environment-list-segments" role="group" aria-label="Row density">
            <button type="button" aria-pressed={prefs.density === "comfortable"} onClick={() => update({ density: "comfortable" })}>Comfortable</button>
            <button type="button" aria-pressed={prefs.density === "compact"} onClick={() => update({ density: "compact" })}>Compact</button>
          </div>
        </>}
        <p className="environment-list-summary" aria-live="polite">
          <span>{filtered ? `${visible.length} of ${environments.length}` : `${environments.length} total`}</span>
          <span>{counts.running} running</span>
          {running.length ? <span>{formatBytesFromGb(memory)} memory</span> : null}
          <span>+{formatBytesFromGb(storage)} storage</span>
          {connections.length ? <span>{connections.length} {connections.length === 1 ? "link" : "links"}</span> : null}
        </p>
      </div> : null}
      <div className="environment-list-scroll" ref={bodyRef}>
        <table className="workspace-environment-list" aria-label="Environments" aria-rowcount={visible.length + 1}>
          <thead><tr>
            <th scope="col" className="environment-list-select-cell">{selectableVisible.length ? <input type="checkbox" aria-label="Select all shown environments" checked={allSelected} ref={input => { if (input) input.indeterminate = selectedVisible.length > 0 && !allSelected }} onChange={() => setSelected(allSelected ? new Set([...selected].filter(id => !visible.some(environment => environment.id === id))) : new Set([...selected, ...selectableVisible.map(environment => environment.id)]))} /> : null}</th>
            {columns.map(column => <th scope="col" key={column.label} className={column.className} aria-sort={column.key && prefs.sort === column.key ? prefs.descending ? "descending" : "ascending" : undefined}>
              {column.key ? <button type="button" className="environment-list-sort" data-active={prefs.sort === column.key || undefined} data-descending={prefs.sort === column.key && prefs.descending || undefined} onClick={() => sortBy(column.key!)} title={`Sort by ${column.label.toLowerCase()}`}>{column.label}</button> : column.label}
            </th>)}
          </tr></thead>
          {groups.map(group => <tbody key={group.label || "all"}>
            {group.label ? <tr className="environment-list-group"><th colSpan={columnCount} scope="rowgroup">
              <button type="button" onClick={() => setSelected(current => new Set([...current, ...group.rows.filter(environment => !previewIds.has(environment.id)).map(environment => environment.id)]))} title="Select this group">{group.label}</button><span>{group.rows.length}</span>
            </th></tr> : null}
            {group.rows.map(environment => children(itemById.get(environment.id)!))}
          </tbody>)}
          {environments.length && !visible.length ? <tbody><tr className="environment-list-nomatch"><td colSpan={columnCount}>
            No environments match. <Button size="xs" variant="link" onClick={() => { setQuery(""); update({ status: "all", type: "all" }) }}>Clear filters</Button>
          </td></tr></tbody> : null}
        </table>
      </div>
    </div>
  </ListContext.Provider>
}

function Meter({ label, value, max, text, total, dim }: { label: string; value: number; max?: number; text: string; total?: string; dim: boolean }) {
  const ratio = max && max > 0 ? Math.max(0, Math.min(1, value / max)) : null
  const high = ratio !== null && ratio >= 0.85 && !dim
  return <div className="environment-list-meter" data-dim={dim || undefined} data-high={high || undefined} title={high ? `${label} is near its limit` : undefined}>
    <span className="environment-list-meter-value">{text}{total ? <small> / {total}</small> : null}</span>
    {ratio !== null ? <span role="meter" aria-label={`${label} use`} aria-valuemin={0} aria-valuemax={max} aria-valuenow={Math.min(value, max!)} className="environment-list-meter-track"><span style={{ width: `${Math.max(ratio * 100, value > 0 ? 3 : 0)}%` }} /></span> : null}
  </div>
}

function LinkChip({ link, self }: { link: ListConnection; self: string }) {
  const context = useContext(ListContext)!
  const otherId = link.sourceId === self ? link.targetId : link.sourceId
  const other = context.environments.get(otherId)
  const arrow = link.direction === "bidirectional" ? "↔" : link.sourceId === self ? "→" : "←"
  const state = !link.active ? "off" : link.enforcementStatus === "error" ? "error" : link.enforcementStatus === "pending" ? "pending" : "on"
  const stateText = state === "off" ? "turned off" : state === "error" ? "needs attention" : state === "pending" ? "pending" : "active"
  return <button type="button" className="environment-list-link" data-state={state} style={{ "--link-accent": context.colors[otherId] ?? "var(--muted-foreground)" } as CSSProperties} onClick={() => context.onConnect(link.sourceId, link.targetId)} aria-label={`Connection ${arrow === "←" ? "from" : "to"} ${other?.name ?? otherId}, ${stateText}`} title={`${arrow === "↔" ? "Two-way" : "One-way"} · ${stateText}`}>
    <span aria-hidden="true">{arrow}</span>{other?.name ?? otherId}
  </button>
}

function GpuUsage({ environment }: { environment: GraphEnvironment }) {
  const { state } = usePlatform()
  if (!environment.gpuAccess) return <span className="text-muted-foreground">—</span>
  if (environment.status !== "running") return <span className="text-muted-foreground">{environment.status === "paused" ? "Paused" : "Not running"}</span>
  // Host telemetry is shared across GPU workloads; cloud usage is not measured by this PC.
  const local = environment.kind === "container" && environment.provider === "yougoriCuda"
  const usage = local ? state?.host.gpuUsagePercent : null
  return <div title={local ? "GPU access is enabled. Usage is measured across this computer, shared by its GPU workloads." : "GPU access is enabled; usage is not available for this environment."}>
    <span>{local ? "Running" : "Enabled"}</span>
    {typeof usage === "number" && Number.isFinite(usage) ? <>
      <Meter label="GPU on this computer" value={Math.max(0, Math.min(100, usage))} max={100} text={`${Math.round(Math.max(0, Math.min(100, usage)))}% shared`} dim={false} />
    </> : <span className="environment-list-subtitle">Usage unavailable</span>}
  </div>
}

export function EnvironmentListRow({ environment, preview = false, accent, canLink, busy, fileHovered, fileStatus, dropHint, status, access, services, actions, onConfigure, onDoubleClick }: {
  environment: GraphEnvironment
  preview?: boolean
  accent: string
  canLink: boolean
  busy: boolean
  fileHovered?: boolean
  fileStatus: ReactNode
  dropHint: string
  status: ReactNode
  access: ReactNode
  services: ReactNode
  actions: ReactNode
  onConfigure(): void
  onDoubleClick(event: MouseEvent<HTMLElement>): void
}) {
  const context = useContext(ListContext)!
  const links = context.links.get(environment.id) ?? []
  const expanded = context.expanded.has(environment.id)
  const selected = context.selected.has(environment.id)
  const cloud = environment.kind === "cloud"
  const dim = environment.status !== "running"
  const memoryLimit = environment.resourcePolicy?.memoryGb?.current || environment.resourcePolicy?.memoryGb?.max
  const subtitle = environment.description || (cloud || environment.runtime.startsWith("shared://") ? "" : environment.runtime)
  const detailsId = `environment-list-details-${environment.id}`
  return <>
    <EnvironmentNodeMenu environment={environment} disabled={preview} asChild>
    <tr data-tour-preview={preview || undefined} onClickCapture={preview ? event => { event.preventDefault(); event.stopPropagation() } : undefined} onPointerDownCapture={preview ? event => { event.preventDefault(); event.stopPropagation() } : undefined} className="workspace-list-row" onDoubleClick={onDoubleClick} data-environment-id={environment.id} data-selected={selected || undefined} data-expanded={expanded || undefined} data-file-drop-target={fileHovered || undefined} aria-busy={busy} aria-selected={selected} style={{ "--node-accent": accent } as CSSProperties}>
      <td className="environment-list-select-cell"><input type="checkbox" aria-label={`Select ${environment.name}`} disabled={preview} checked={selected} onChange={() => undefined} onClick={event => context.toggleSelected(environment.id, event.shiftKey)} /></td>
      <th scope="row" className="environment-list-name">
        <div className="environment-list-name-line">
          <button type="button" className="environment-list-disclosure" aria-expanded={expanded} aria-controls={expanded ? detailsId : undefined} aria-label={`${expanded ? "Hide" : "Show"} details for ${environment.name}`} onClick={() => context.toggleExpanded(environment.id)} />
          <button data-tour="node-configure" data-list-focus aria-label={`Configure ${environment.name}`} onClick={onConfigure} title={environment.name} type="button">{environment.name}</button>
        </div>
        <span className="environment-list-type">{environmentLabel(environment)}{environment.gpuAccess ? <span className="environment-list-tag">GPU</span> : null}</span>
        {subtitle ? <span className="environment-list-subtitle" title={subtitle}>{subtitle}</span> : null}
        {fileStatus}
        {fileHovered ? <span role="status" className="text-xs">{dropHint}</span> : null}
      </th>
      <td className="environment-list-status">{status}{environment.lastOpenedAt ? <span className="environment-list-subtitle" title={formatDateTime(environment.lastOpenedAt)}>Opened {formatRelativeTime(environment.lastOpenedAt)}</span> : null}</td>
      <td className="environment-list-number">{cloud ? <span className="text-muted-foreground">—</span> : <Meter label="CPU" value={environment.cpuUsage} max={100} text={`${Math.round(environment.cpuUsage)}%`} dim={dim} />}</td>
      <td className="environment-list-number"><GpuUsage environment={environment} /></td>
      <td className="environment-list-number">{cloud ? <span className="text-muted-foreground">—</span> : <Meter label="Memory" value={environment.memoryUsageGb} max={memoryLimit} text={`${environment.memoryUsageGb.toFixed(1)} GB`} total={memoryLimit ? `${memoryLimit} GB` : undefined} dim={dim} />}</td>
      <td className="environment-list-number">{cloud ? <span className="text-muted-foreground">—</span> : <Meter label="Storage" value={environment.storageDeltaGb} max={environment.storageLimitGb} text={`+${formatBytesFromGb(environment.storageDeltaGb)}`} total={environment.storageLimitGb ? `${environment.storageLimitGb} GB` : undefined} dim={false} />}</td>
      <td className="environment-list-links">
        {links.map(link => <LinkChip key={link.id} link={link} self={environment.id} />)}
        {canLink ? <button type="button" className="environment-list-link environment-list-link-add" data-tour="row-connect" aria-label={`Connect ${environment.name} to another environment`} onClick={() => context.onConnect(environment.id)}>+ Connect</button> : links.length ? null : <span className="text-muted-foreground">—</span>}
      </td>
      <td className="environment-list-access">{access ?? <span className="text-muted-foreground">—</span>}</td>
      <td className="environment-list-services">{services ?? <span className="text-muted-foreground">—</span>}</td>
      <td className="environment-list-actions">{actions}</td>
    </tr>
    </EnvironmentNodeMenu>
    {expanded ? <tr className="environment-list-detail" id={detailsId} style={{ "--node-accent": accent } as CSSProperties}><td colSpan={columnCount}><EnvironmentDetails environment={environment} links={links} /></td></tr> : null}
  </>
}

function EnvironmentDetails({ environment, links }: { environment: GraphEnvironment; links: ListConnection[] }) {
  const context = useContext(ListContext)!
  const [copied, setCopied] = useState<string | null>(null)
  const cloud = environment.kind === "cloud"
  const policy = environment.resourcePolicy
  const copy = (value: string) => { void navigator.clipboard?.writeText(value).then(() => { setCopied(value); window.setTimeout(() => setCopied(current => current === value ? null : current), 1500) }).catch(() => undefined) }
  const workspace = environment.workspace
  return <div className="environment-list-details">
    <section aria-label={`Overview of ${environment.name}`}>
      <h4>Overview</h4>
      <dl>
        <div><dt>Type</dt><dd>{environmentLabel(environment)}</dd></div>
        {environment.provider ? <div><dt>Runtime</dt><dd>{environment.provider}</dd></div> : null}
        {!cloud && environment.runtime && !environment.runtime.startsWith("shared://") ? <div><dt>Image</dt><dd className="environment-list-mono" title={environment.runtime}>{environment.runtime}</dd></div> : null}
        {environment.containerCommand ? <div><dt>Command</dt><dd className="environment-list-mono" title={environment.containerCommand}>{environment.containerCommand}</dd></div> : null}
        {environment.storageDrive ? <div><dt>Drive</dt><dd>{environment.storageDrive}</dd></div> : null}
        <div><dt>Created</dt><dd title={formatDateTime(environment.createdAt)}>{formatRelativeTime(environment.createdAt)}</dd></div>
        {environment.lastOpenedAt ? <div><dt>Last opened</dt><dd title={formatDateTime(environment.lastOpenedAt)}>{formatRelativeTime(environment.lastOpenedAt)}</dd></div> : null}
        {!cloud ? <div><dt>Internet</dt><dd>{environment.networkAccess ? "Allowed" : "Blocked"}</dd></div> : null}
        {environment.gpuAccess ? <div><dt>GPU</dt><dd>Attached</dd></div> : null}
      </dl>
    </section>
    {!cloud && policy ? <section aria-label={`Resources of ${environment.name}`}>
      <h4>Resources</h4>
      <dl>
        <div><dt>CPU now</dt><dd>{Math.round(environment.cpuUsage)}%</dd></div>
        <div><dt>CPU allocation</dt><dd>{policy.cpu.current || policy.cpu.preferred} cores <small>({policy.cpu.min}–{policy.cpu.max})</small></dd></div>
        <div><dt>Memory now</dt><dd>{environment.memoryUsageGb.toFixed(2)} GB</dd></div>
        <div><dt>Memory allocation</dt><dd>{policy.memoryGb.current || policy.memoryGb.preferred} GB <small>({policy.memoryGb.min}–{policy.memoryGb.max})</small></dd></div>
        <div><dt>Storage change</dt><dd>+{formatBytesFromGb(environment.storageDeltaGb)}{environment.storageLimitGb ? ` of ${environment.storageLimitGb} GB` : ""}</dd></div>
        <div><dt>Network in</dt><dd>{environment.networkRxMbps.toFixed(1)} Mbps</dd></div>
        <div><dt>Priority</dt><dd className="capitalize">{policy.priority}{policy.dynamic ? " · dynamic" : ""}</dd></div>
      </dl>
    </section> : null}
    <section aria-label={`Connections of ${environment.name}`}>
      <h4>Connections <span>{links.length}</span></h4>
      {links.length ? <ul>
        {links.map(link => {
          const otherId = link.sourceId === environment.id ? link.targetId : link.sourceId
          const other = context.environments.get(otherId)
          return <li key={link.id}>
            <button type="button" className="environment-list-detail-link" onClick={() => context.onConnect(link.sourceId, link.targetId)}>
              <span style={{ background: context.colors[otherId] }} aria-hidden="true" />
              {link.direction === "bidirectional" ? "Two-way with" : link.sourceId === environment.id ? "To" : "From"} {other?.name ?? otherId}
            </button>
            <small data-state={!link.active ? "off" : link.enforcementStatus ?? "enforced"}>{!link.active ? "Turned off" : link.enforcementStatus === "error" ? "Needs attention" : link.enforcementStatus === "pending" ? "Pending" : "Active"}{other ? ` · ${other.status}` : ""}</small>
          </li>
        })}
      </ul> : <p>No connections to other environments.</p>}
    </section>
    {!cloud ? <section aria-label={`Ports of ${environment.name}`}>
      <h4>Ports & publishing <span>{workspace?.services.length ?? 0}</span></h4>
      {workspace?.notice ? <p className="environment-list-notice">{workspace.notice}</p> : null}
      {workspace?.services.length ? <ul>
        {workspace.services.map(service => {
          const publications = workspace.publications.filter(publication => publication.port === service.port)
          return <li key={service.port}>
            <span className="environment-list-mono">:{service.port}</span> <small>{service.protocol.toUpperCase()}{service.name ? ` · ${service.name}` : ""}</small>
            {publications.flatMap(publication => publication.urls.map(url => <span className="environment-list-url" key={`${publication.id}-${url}`}>
              <small>{publication.kind === "cloudflare" ? "Cloudflare" : publication.kind === "local" ? "LAN" : "Public"}</small>
              <button type="button" className="environment-list-mono" onClick={() => void workspaceApi.openUrl(url).catch(() => undefined)} title={`Open ${url}`}>{url}</button>
              <Button size="xs" variant="ghost" onClick={() => copy(url)} aria-label={`Copy ${url}`}>{copied === url ? "Copied" : "Copy"}</Button>
            </span>))}
          </li>
        })}
      </ul> : <p>No listening ports detected.</p>}
    </section> : null}
    {!cloud && workspace?.shares.length ? <section aria-label={`Shared folders of ${environment.name}`}>
      <h4>Shared folders <span>{workspace.shares.length}</span></h4>
      <ul>{workspace.shares.map(share => <li key={share.id}><span className="environment-list-mono" title={share.path}>{share.path}</span> <small>{share.readOnly ? "Read-only" : "Read & write"}{share.mountPath ? ` · ${share.mountPath}` : ""}</small></li>)}</ul>
    </section> : null}
    {environment.description.startsWith("Hugging Face · ") ? <section aria-label={`Model of ${environment.name}`}><h4>Model</h4><ModelNodeProgress environment={environment} /></section> : null}
  </div>
}
