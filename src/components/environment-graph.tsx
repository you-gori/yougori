import { SharingPanel } from "@/components/sharing-panel"
import { EnvironmentDuplicateAction, type DuplicateDestination } from "@/components/environment-duplicate-action"
import { DuplicateEnvironmentDialog } from "@/components/dialogs/duplicate-environment-dialog"
import { ConfigurationHelp } from "@/components/configuration-help"
import { EnvironmentList, EnvironmentListRow } from "@/components/environment-list"
import type { ReactNode } from "react"
import { EyeIcon, EyeOffIcon, TerminalIcon, ListIcon, PlayIcon, PlusIcon, SquareIcon, SettingsIcon, XIcon } from "lucide-react"
import { lazy, Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { allCapabilities, capabilityEnabled, capabilityIssue, type GraphEnvironment, type CapabilityKind } from "@/components/graph-capabilities"
import { useWorkspaceFeatures } from "@/components/use-workspace-features"
import { useNodeFileDrop, fileDropIssue, type NodeFileCopy } from "@/components/use-node-file-drop"
import { neocloudApi } from "@/api/neocloud-api"
import { money, runpodApi, runpodExtra, stateLabel } from "@/api/runpod-api"
import { NodeFileCopyStatus } from "@/components/node-file-copy-status"
import { ModelWorkspace } from "@/components/model-workspace"
import { GraphWorkspaceDialogs } from "@/components/graph-workspace-dialogs"
import { PublicAccessPresets } from "@/components/public-access-presets"
import { readPublicAccessPresets } from "@/lib/public-access-presets"
import { Status } from "@/components/shared/status"
import { Button } from "@/components/ui/button"
import { Switch } from "@/components/ui/switch"
import { workspaceApi } from "@/api/workspace-api"
import { Spinner } from "@/components/ui/spinner"
import { Tooltip, TooltipPopup, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip"
import { usePlatform } from "@/context/platform-context"
import { environmentActionLabel } from "@/lib/environment-actions"
import { graphColors } from "@/lib/graph-colors"
import { supportsConnections } from "@/lib/environment-connections"
import { useInstructionsTour } from "@/lib/instructions-tour"
import { tourPreviewEnvironment } from "@/lib/tour-preview"
import type { Environment } from "@/types/platform"
import "@/components/dashboard-actions.css"

interface EnvironmentNodeData extends Record<string, unknown> {
  fileHovered?: boolean
  fileCopy?: NodeFileCopy
  preview?: boolean
  accent: string
  pending: boolean
  environment: GraphEnvironment
  onCapabilityChange(environmentId: string, capability: CapabilityKind, enabled: boolean): void
  onConnect(environmentId: string): void
  onOpen(environmentId: string): void
  onSelect(environmentId: string): void
  onService(environmentId: string, port: number): void
  onDuplicate(environmentId: string, destination: DuplicateDestination): void
  onShares(environmentId: string): void
}

type EnvironmentItem = { id: string; data: EnvironmentNodeData }

function NodeAction({ label, children }: { label: string; children: React.ReactElement }) {
  return (
    <Tooltip>
      <TooltipTrigger render={children} />
      <TooltipPopup>{label}</TooltipPopup>
    </Tooltip>
  )
}

function EnvironmentCard({ data }: { data: EnvironmentNodeData }) {
  const { state, refreshPlatform, setEnvironmentStatus, environmentActions } = usePlatform()
  const { environment } = data
  const action = environmentActions[environment.id]
  const busy = Boolean(action) || environment.status === "provisioning"
  const lifecyclePending = action === "starting" || action === "connecting" || action === "stopping" || action === "disconnecting"
  const cloud = environment.kind === "cloud"
  const neocloud = state?.neocloudDeployments?.[environment.id]
  const [neoBusy, setNeoBusy] = useState(false)
  const runpod = neocloud?.provider === "runpod" ? neocloud : undefined
  const runpodState = runpod ? stateLabel(runpod.state, runpod.product) : ""
  const podReady = runpod?.product === "pod" && runpodExtra(runpod).sshReady === true
  const neoStopped = /^(stopped|exited|paused|shutoff)$/i.test(neocloud?.state ?? "")
  const neoPending = /requested|pending|creating|starting|stopping/i.test(neocloud?.state ?? "")
  const neoPower = async () => {
    if (!neocloud || neoBusy || neoPending) return
    setNeoBusy(true)
    try { await (runpod ? runpodApi.action(environment.id, neoStopped ? "start" : "stop") : neocloudApi.action(environment.id, neoStopped ? "start" : "stop")) }
    catch { /* The provider error is persisted on the node and shown in configuration. */ }
    finally { await refreshPlatform().catch(() => undefined); setNeoBusy(false) }
  }
  const dropHint = fileDropIssue(environment) ?? (cloud ? "Drop to copy into this cloud account's home folder" : "Drop to copy here")
  const [addressVisible, setAddressVisible] = useState(false)
  const creating = environment.status === "provisioning"
  const isNativeApplication = environment.provider === "nativeSandbox" || environment.kind === "computerBranch"
  const canConnect = supportsConnections(environment) && neocloud?.product !== "serverless"
  const running = environment.status === "running"
  const needsNeoSsh = Boolean(neocloud && neocloud.provider !== "runpod" && neocloud.product !== "serverless" && environment.runtime.startsWith("Neocloud ·"))
  // A RunPod pod opens once Yougori has reached it over SSH; until then its details explain the wait.
  const runpodWaiting = Boolean(runpod && runpod.product === "pod" && !podReady && !running)
  const launchLabel = runpod ? (runpod.product === "serverless" ? "API" : running || podReady ? "Open" : runpodState === "Stopped" ? "Details" : runpodState === "Deleted" ? "Details" : "Starting…") : neocloud?.product === "serverless" ? "Model API" : needsNeoSsh ? "Set up SSH" : cloud ? "Open" : running ? "Stop" : environment.status === "paused" ? "Resume" : "Start"
  const configureOnDoubleClick = (event: React.MouseEvent<HTMLElement>) => {
    if (data.preview || (event.target as HTMLElement).closest("button, a, input, label, [role=switch]")) return
    data.onSelect(environment.id)
  }

  const statusSummary = action ? <span className="shrink-0 text-[10px] text-muted-foreground" role="status">{environmentActionLabel[action]}</span> : environment.status === "error" ? <span className="environment-needs-attention">Needs attention</span> : runpod ? <span className="text-[11px] text-muted-foreground">{running ? "Connected" : runpodState}{runpod.product === "pod" && runpodState === "Running" && runpodExtra(runpod).hourlyUsd ? ` · ${money(runpodExtra(runpod).hourlyUsd)}/hr` : ""}</span> : neocloud?.product === "serverless" ? <span className="text-[11px] text-muted-foreground">{neocloud.state}</span> : cloud ? <span className="text-[11px] text-muted-foreground">{environment.status === "running" ? "Connected" : "Disconnected"}</span> : <Status compact status={environment.status} />
  const services = !cloud && environment.workspace?.services.length ? <div aria-label={`Services in ${environment.name}`} className="nodrag flex flex-wrap gap-x-3 gap-y-4 border-b px-3 pb-2 pt-3">
        {environment.workspace.services.map(service => {
          return <div className="relative min-w-14" data-service-card={`${environment.id}:${service.port}`} key={service.port}>
            <Button aria-label={`Port ${service.port} in ${environment.name}`} className="h-6! w-full text-[10px]!" onClick={() => data.onService(environment.id, service.port)} size="xs" title={`${service.name} · ${service.protocol.toUpperCase()} ${service.port}`} variant="outline">:{service.port}</Button>
          </div>
        })}
      </div> : null
  const cloudAddress = environment.runtime.startsWith("shared://") ? <span className="text-[11px] text-muted-foreground">Hosted remotely</span> : cloud ? <div className="nodrag flex min-w-0 items-center gap-1 text-[11px] font-normal text-muted-foreground w-48 shrink-0">
    <span className={`min-w-0 flex-1 truncate ${addressVisible ? "" : "text-[20px] leading-none tracking-wide"}`}>{addressVisible ? environment.runtime : "••••••@••••••"}</span>
    <Button aria-label={addressVisible ? "Hide cloud address" : "Show cloud address"} aria-pressed={addressVisible} onClick={() => setAddressVisible(value => !value)} size="icon-xs" type="button" variant="ghost" className="shrink-0">
      {addressVisible ? <EyeOffIcon aria-hidden="true" /> : <EyeIcon aria-hidden="true" />}
    </Button>
  </div> : null
  const access = !cloud && !isNativeApplication ? <div className="nodrag environment-list-access-controls">
    {allCapabilities.map(({ capability }) => <label key={capability} data-tour={capability === "pc" ? "row-pc" : "row-internet"} title={capabilityIssue(environment, capability) ?? (capability === "pc" ? "Turn on to choose shared folders; turn off to disconnect them." : "Allow internet access")}>
      <Switch aria-label={`${capability === "internet" ? "Internet access" : "My PC access"} for ${environment.name}`} checked={capabilityEnabled(environment, capability)} disabled={busy || data.pending || Boolean(capabilityIssue(environment, capability))} onCheckedChange={enabled => data.onCapabilityChange(environment.id, capability, enabled)} />
      <span aria-hidden="true">{capability === "internet" ? "Internet" : "My PC"}{capability === "pc" && environment.workspace?.shares.length ? ` · ${environment.workspace.shares.length}` : ""}</span>
    </label>)}
  </div> : null
  const network = !cloud && !isNativeApplication ? <NodeAction label="Manage this environment's ports and local, LAN or public access"><Button data-tour="node-port" aria-label={`Ports & access for ${environment.name}`} className="node-chat" onClick={() => data.onService(environment.id, environment.workspace?.services[0]?.port ?? 0)} size="xs" type="button" variant="ghost">Ports &amp; access{environment.workspace?.publications.length ? ` · ${environment.workspace.publications.length}` : ""}</Button></NodeAction> : null
  const actions = (<div className="nodrag environment-card-actions flex items-center gap-1 border-t px-3 py-2 [&_button]:z-40">
        {!cloud ? <EnvironmentDuplicateAction name={environment.name} disabled={busy || data.preview} onSelect={destination => data.onDuplicate(environment.id, destination)} /> : null}
        <NodeAction label="Configuration">
          <Button aria-label={`Configuration for ${environment.name}`} className="shrink-0" onClick={() => data.onSelect(environment.id)} size="icon-xs" type="button" variant="ghost"><SettingsIcon aria-hidden="true" /></Button>
        </NodeAction>
        {!environment.runtime.startsWith("shared://") && !data.preview ? <SharingPanel environmentId={environment.id} compact /> : null}
        {cloud && !environment.runtime.startsWith("shared://") ? <EnvironmentDuplicateAction name={environment.name} disabled={busy || data.preview} onSelect={destination => data.onDuplicate(environment.id, destination)} /> : null}
        {neocloud && neocloud.state !== "Deleted" && (neocloud.resourceId || (neocloud.product === "serverless" && neoStopped)) ? <NodeAction label={runpod ? (runpod.product === "serverless" ? (neoStopped ? `Resume ${environment.name}` : `Pause ${environment.name}; it keeps its API address`) : neoStopped ? `Start ${environment.name}` : `Stop ${environment.name}. Its volume is kept and billed monthly.`) : neoStopped ? `Start ${environment.name} at ${neocloud.provider}` : neocloud.provider === "civo" ? `Power off ${environment.name}. Civo continues charging for stopped instances.` : `Stop ${environment.name} at ${neocloud.provider}. Storage charges may continue.`}><Button aria-label={`${neoStopped ? "Start" : "Stop"} provider compute for ${environment.name}`} disabled={busy || neoBusy || neoPending} loading={neoBusy} onClick={() => void neoPower()} size="xs" type="button" variant="outline">{runpod ? (runpod.product === "serverless" ? (neoStopped ? "Resume" : "Pause") : neoStopped ? "Start pod" : "Stop pod") : neocloud.product === "serverless" ? neoStopped ? "Create endpoint" : "Stop endpoint" : neoStopped ? "Start compute" : neocloud.provider === "civo" ? "Power off" : "Stop compute"}</Button></NodeAction> : null}
        {running && !cloud && !isNativeApplication ? (
          <NodeAction label={`Open ${environment.name}`}>
            <Button data-tour="node-open" aria-label="Open" disabled={busy} loading={action === "opening"} onClick={() => data.onOpen(environment.id)} size="icon-xs" type="button" variant="ghost"><TerminalIcon aria-hidden="true" /></Button>
          </NodeAction>
        ) : null}
        <Button data-tour="node-launch" className="node-launch ml-auto" data-running={running ? "true" : undefined} aria-label={!creating && !isNativeApplication && ["Start", "Resume", "Stop"].includes(launchLabel) ? launchLabel : undefined} aria-busy={creating || lifecyclePending || (cloud && action === "opening") || undefined} disabled={isNativeApplication || busy} loading={lifecyclePending || (cloud && action === "opening")} title={creating ? "Creating this environment. You can keep using Yougori." : action ? environmentActionLabel[action] : undefined} onClick={() => needsNeoSsh || neocloud?.product === "serverless" || runpodWaiting ? data.onSelect(environment.id) : !cloud && running ? void setEnvironmentStatus(environment.id, "stopped").catch(() => undefined) : data.onOpen(environment.id)} size="xs" type="button" variant={running ? "outline" : "default"}>
          {creating ? <><Spinner aria-hidden="true" />Creating…</> : isNativeApplication ? "Unavailable" : (launchLabel === "Start" || launchLabel === "Resume") ? <PlayIcon aria-hidden="true" /> : launchLabel === "Stop" ? <SquareIcon aria-hidden="true" /> : launchLabel}
        </Button>
        {!data.preview && !creating && environment.description.startsWith("Hugging Face · ") ? <ModelWorkspace environmentId={environment.id} compact /> : null}
      </div>)

  return <EnvironmentListRow
    preview={data.preview}
    environment={environment}
    accent={data.accent}
    canLink={canConnect}
    busy={Boolean(data.pending || busy || data.fileCopy?.busy)}
    fileHovered={data.fileHovered}
    fileStatus={<NodeFileCopyStatus copy={data.fileCopy} />}
    dropHint={dropHint}
    status={statusSummary}
    access={access}
    services={services || network || cloudAddress ? <div className="environment-list-services-controls">{services}{network}{cloudAddress}</div> : null}
    actions={actions}
    onConfigure={() => data.onSelect(environment.id)}
    onDoubleClick={configureOnDoubleClick}
  />

}

const HostCliView = lazy(() => import("@/components/host-cli-view"))

export function EnvironmentGraph({ environments, connections, errorContainer, onConnect, onOpen, onSelect, footer }: {
  footer?: (openEdit: () => void, disabled: boolean, editActive: boolean, toggleCli: () => void, cliActive: boolean) => ReactNode
  errorContainer: HTMLElement | null
  environments: Environment[]
  connections: Array<{ id: string; sourceId: string; targetId: string; direction: "oneWay" | "bidirectional"; active: boolean; enforcementStatus?: "enforced" | "pending" | "error" }>
  onConnect(sourceId: string, targetId?: string): void
  onOpen(environmentId: string): void
  onSelect(environmentId: string): void
}) {
  const { updateContainerNetwork } = usePlatform()
  const [duplicate, setDuplicate] = useState<{ environmentId: string; destination: DuplicateDestination } | null>(null)
  const openDuplicate = useCallback((environmentId: string, destination: DuplicateDestination) => setDuplicate({ environmentId, destination }), [])
  const duplicateSource = environments.find(environment => environment.id === duplicate?.environmentId)
  const tour = useInstructionsTour()
  const [preferredView, setPreferredView] = useState<"list" | "cli" | "edit">(() => {
    try { const saved = localStorage.getItem("yougori.workspace-view"); if (saved === "nodes") localStorage.setItem("yougori.workspace-view", "list"); return saved === "cli" || saved === "edit" ? saved : "list" } catch { return "list" }
  })
  const [cliMounted, setCliMounted] = useState(preferredView === "cli")
  const [editMounted, setEditMounted] = useState(preferredView === "edit")
  const view = tour?.active ? "list" : preferredView
  const preview = useMemo(() => tourPreviewEnvironment(tour), [tour])
  const graphContainerRef = useRef<HTMLDivElement>(null)
  const fileDrop = useNodeFileDrop(graphContainerRef, environments)
  const workspace = useWorkspaceFeatures(environments)
  const { decorated, openShares, openService, refresh } = workspace
  const colors = useMemo(() => {
    const accents = graphColors(environments.map(environment => environment.id))
    for (const environment of environments) {
      if (environment.runtime.startsWith("shared://")) accents[environment.id] = "#00B7CD"
      else if (environment.kind === "cloud") accents[environment.id] = "#FF9100"
    }
    return accents
  }, [environments])

  const setCapability = useCallback(async (environmentId: string, capability: CapabilityKind, enabled: boolean) => {
    const environment = environments.find((item) => item.id === environmentId)
    if (!environment) throw new Error("Environment not found")
    if (capability === "pc") {
      if (enabled) { openShares(environmentId); return }
      try {
        const { shares } = await workspaceApi.services(environmentId)
        for (const share of shares) await workspaceApi.unshare(share.id)
      } finally {
        await refresh(environmentId)
      }
      return
    }
    if (capability === "internet") return updateContainerNetwork(environmentId, enabled)
  }, [environments, openShares, refresh, updateContainerNetwork])

  const pendingRef = useRef(new Set<string>())
  const [pending, setPending] = useState(new Set<string>())
  const [feedback, setFeedback] = useState("")
  const change = useCallback(async (environmentId: string, capability: CapabilityKind, enabled: boolean) => {
    const environment = decorated.find(item => item.id === environmentId)
    if (!environment || pendingRef.current.has(environmentId)) return
    const issue = capabilityIssue(environment, capability)
    if (issue) { setFeedback(issue); return }
    if (capability !== "pc" && capabilityEnabled(environment, capability) === enabled) return
    pendingRef.current.add(environmentId); setPending(new Set(pendingRef.current)); setFeedback("")
    try { await setCapability(environmentId, capability, enabled) }
    catch (error) { setFeedback(error instanceof Error ? error.message : String(error)) }
    finally { pendingRef.current.delete(environmentId); setPending(new Set(pendingRef.current)) }
  }, [decorated, setCapability])

  const selectView = useCallback((mode: "list" | "cli" | "edit") => {
    if (mode === "cli") setCliMounted(true)
    else if (mode === "edit") setEditMounted(true)
    setPreferredView(mode)
    try { localStorage.setItem("yougori.workspace-view", mode) } catch { /* Storage may be unavailable. */ }
  }, [])
  const hideCli = useCallback(() => {
    selectView("list")
    document.getElementById("host-terminal-toggle")?.focus()
  }, [selectView])
  const hideEditor = useCallback(() => {
    selectView("list")
    document.getElementById("edit-app-toggle")?.focus()
  }, [selectView])
  useEffect(() => {
    const shortcut = (event: KeyboardEvent) => {
      if (!tour?.active && event.ctrlKey && !event.altKey && !event.metaKey && event.code === "Backquote" && !event.repeat) {
        event.preventDefault()
        selectView(preferredView === "cli" ? "list" : "cli")
      }
    }
    window.addEventListener("keydown", shortcut)
    return () => window.removeEventListener("keydown", shortcut)
  }, [preferredView, selectView, tour])

  const openEnvironmentService = useCallback((id: string, port: number) => openService(id, tour?.active && tour.step === "demo-port-open" ? 0 : port), [openService, tour])

  const [savedDomains, setSavedDomains] = useState(readPublicAccessPresets)
  useEffect(() => {
    const update = () => setSavedDomains(readPublicAccessPresets())
    window.addEventListener("yougori-public-presets-changed", update)
    return () => window.removeEventListener("yougori-public-presets-changed", update)
  }, [])
  // Every public link: account domains, quick links, and saved domains not yet connected.
  const domains = useMemo(() => {
    const found = new Map<string, { url: string; hostname: string; environment: string | null; port: number; live: boolean }>()
    for (const environment of decorated) for (const publication of environment.workspace?.publications ?? []) {
      if (publication.kind !== "cloudflare") continue
      for (const url of publication.urls) {
        const hostname = url.replace(/^https?:\/\//, "").replace(/\/.*$/, "")
        if (!found.has(hostname)) found.set(hostname, { url, hostname, environment: environment.name, port: publication.port, live: environment.status === "running" })
      }
    }
    for (const preset of savedDomains) if (!found.has(preset.hostname)) found.set(preset.hostname, { url: `https://${preset.hostname}`, hostname: preset.hostname, environment: null, port: preset.port, live: false })
    return [...found.values()]
  }, [decorated, savedDomains])
  const items = useMemo<EnvironmentItem[]>(() => [...(preview ? [preview] : []), ...decorated].map(environment => ({
    id: environment.id,
    data: { fileHovered: fileDrop.hovered === environment.id, fileCopy: fileDrop.copies[environment.id], preview: environment === preview, accent: colors[environment.id] ?? "#7194c2", pending: pending.has(environment.id), environment, onCapabilityChange: change, onConnect, onOpen, onSelect, onService: openEnvironmentService, onShares: openShares, onDuplicate: openDuplicate },
  })), [fileDrop.hovered, fileDrop.copies, preview, colors, pending, change, decorated, onConnect, onOpen, onSelect, openEnvironmentService, openShares, openDuplicate])


  return (
    <TooltipProvider delay={0}>
      {feedback && errorContainer ? createPortal(
        <div className="flex items-center gap-2 rounded-md border border-destructive/30 bg-background px-2 py-0.5 text-xs text-destructive-foreground" role="alert">
          <p className="min-w-0 flex-1 truncate" title={feedback}>{feedback}</p>
          <Button aria-label="Dismiss workspace error" onClick={() => setFeedback("")} size="icon-xs" type="button" variant="ghost"><XIcon aria-hidden="true" /></Button>
        </div>, errorContainer,
      ) : null}
      <div
        className="workspace-graph relative isolate w-full overflow-hidden rounded-lg border bg-background"
        data-environment-graph
        data-view={view}
        ref={graphContainerRef}
      >
        <div className="workspace-view-toolbar">
          <div className="flex items-center gap-2">
            <span>Environments</span>
            <div className="workspace-domains" role="group" aria-label="Domains">
              <span className="workspace-domains-label">Domains</span>
              {domains.length ? domains.map(domain => <button key={domain.hostname} className="workspace-domain-chip" type="button" title={domain.environment ? `${domain.url} · ${domain.environment} · port ${domain.port}` : `${domain.hostname} · saved for port ${domain.port} · not connected`} onClick={() => domain.environment ? void workspaceApi.openUrl(domain.url) : window.dispatchEvent(new Event("yougori-open-public-presets-manager"))}><i aria-hidden="true" data-active={domain.live || undefined} /><span className="truncate">{domain.hostname}</span><span className="workspace-domain-env">{domain.environment ?? "Not connected"}</span></button>) : <span className="workspace-domains-empty">None yet</span>}
              <Button aria-label="Add or manage saved domain setups" title="Add a domain" className="workspace-domain-add" size="icon-xs" variant="outline" onClick={() => window.dispatchEvent(new Event("yougori-open-public-presets-manager"))}><PlusIcon aria-hidden="true" /></Button>
            </div>
          </div>
          {view !== "list" ? <Button data-instruction-view="list" size="xs" variant="ghost" disabled={Boolean(tour?.active)} onClick={() => selectView("list")}><ListIcon aria-hidden="true" />Environments</Button> : null}
        </div>
        <div
          className="relative z-10 h-[clamp(460px,calc(100dvh-400px),1200px)]"
          data-environment-canvas
        >
          {cliMounted ? <div hidden={view !== "cli"} className="workspace-cli-view h-full min-h-0">
            <Suspense fallback={<div role="status" className="grid h-full place-items-center text-sm text-muted-foreground">Loading CLI…</div>}>
              <HostCliView visible={view === "cli"} onHide={hideCli} />
            </Suspense>
          </div> : null}
          {editMounted ? <div hidden={view !== "edit"} className="workspace-cli-view h-full min-h-0">
            <Suspense fallback={<div role="status" className="grid h-full place-items-center text-sm text-muted-foreground">Loading editor…</div>}>
              <HostCliView mode="edit" visible={view === "edit"} onHide={hideEditor} />
            </Suspense>
          </div> : null}
          {view === "list" ? <EnvironmentList items={items} connections={connections} colors={colors} onConnect={onConnect}>
            {item => <EnvironmentCard key={item.id} data={item.data} />}
          </EnvironmentList> : null}
          {view === "list" && !environments.length && !preview ? <div className="workspace-empty pointer-events-none absolute inset-0 flex flex-col items-center justify-center gap-2 px-6 text-center"><p className="text-base font-medium">Your workspace starts here</p><p className="max-w-sm text-sm leading-6 text-muted-foreground">Choose New environment above to create a container, VM or MicroVM.</p><p className="mt-2 text-xs text-muted-foreground">Then connect its files, network and service ports here.</p></div> : null}
        </div>
        <div className="workspace-graph-caption flex flex-wrap items-center justify-between gap-2 border-t px-4 py-2 text-[11px] text-muted-foreground">
          <span className="workspace-footer-counts"><span><strong>{environments.length}</strong> {environments.length === 1 ? "environment" : "environments"}</span><span aria-hidden="true">·</span><span><strong>{connections.length}</strong> {connections.length === 1 ? "connection" : "connections"}</span></span>
          {footer?.(() => selectView(view === "edit" ? "list" : "edit"), Boolean(tour?.active), view === "edit", () => selectView(view === "cli" ? "list" : "cli"), view === "cli")}
          <ConfigurationHelp label="Workspace controls">{view === "cli" ? "Ctrl+` toggles the CLI. Switch views to keep your terminal session running." : view === "edit" ? "Edit this app from a source checkout. Terminal sessions keep running when you switch views." : "Double-click a row to configure. Use the row controls to start, stop, or manage files and service ports."}</ConfigurationHelp>
        </div>
      </div>
      <PublicAccessPresets environments={decorated} refresh={refresh} />
      <GraphWorkspaceDialogs model={workspace} />
      {duplicate && duplicateSource ? <DuplicateEnvironmentDialog key={`${duplicate.environmentId}-${duplicate.destination}`} environment={duplicateSource} destination={duplicate.destination} onClose={() => setDuplicate(null)} /> : null}
    </TooltipProvider>
  )
}
