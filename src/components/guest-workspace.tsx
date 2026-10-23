import { ModelEnvironmentActions } from "@/components/model-environment-actions"
import { RemoteWorkspace } from "@/components/remote-workspace"
import { EnvironmentChanges } from "@/components/environment-changes"
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { BoxIcon, ChevronDownIcon, DownloadIcon, EllipsisIcon, FileCodeIcon, FolderIcon, GlobeIcon, GpuIcon, Maximize2Icon, Minimize2Icon, MonitorIcon, PanelsTopLeftIcon, PlayIcon, PlusIcon, PowerIcon, ScrollTextIcon, SquareArrowOutUpRightIcon, TerminalIcon, XIcon } from "lucide-react"
import { workspaceApi, type GuestWindow } from "@/api/workspace-api"
import { GuestScene } from "@/components/guest-desktop"
import { GuestAppLauncher } from "@/components/guest-app-launcher"
import { GuestAppView } from "@/components/guest-app-view"
import { GuestFiles } from "@/components/guest-files"
import { ConnectedFiles } from "@/components/connected-files"
import { GuestLogs } from "@/components/guest-logs"
import { GuestBrowser } from "@/components/guest-browser"
import { ConnectionSkillsDialog } from "@/components/connection-skills-dialog"
import { guestAppsApi } from "@/api/guest-apps-api"
import { Button } from "@/components/ui/button"
import { Menu, MenuSub, MenuSubTrigger, MenuSubPopup, MenuGroup, MenuGroupLabel, MenuItem, MenuPopup, MenuSeparator, MenuTrigger } from "@/components/ui/menu"
import { Select, SelectItem, SelectPopup, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Tabs, TabsList, TabsPanel, TabsTab } from "@/components/ui/tabs"
import { Tooltip, TooltipPopup, TooltipTrigger } from "@/components/ui/tooltip"
import { usePlatform } from "@/context/platform-context"
import { statusLabel } from "@/lib/domain"
import { environmentLabel } from "@/lib/environment-category"
import { environmentActionLabel } from "@/lib/environment-actions"
import { isTunnelShared, supportsConnections } from "@/lib/environment-connections"
import { cn } from "@/lib/utils"
import { fitWindowToGuestDisplay } from "@/lib/fit-guest-window"
import { terminalInstallers, type TerminalReadyHandler, type TerminalInstallerId } from "@/lib/terminal-installers"
import { ownsTour, prepareTourWindow, tourTerminalOpened, tourWindowFailed, useInstructionsTour } from "@/lib/instructions-tour"

type WorkspaceView = "files" | "logs" | "browser" | "shared"
interface WorkspaceTab { id: string; environmentId: string; number: number; appSessionId?: string; installer?: TerminalInstallerId; modelChat?: boolean; view?: WorkspaceView }
const newTab = (environmentId: string, number = 1): WorkspaceTab => ({ id: `tab-${crypto.randomUUID()}`, environmentId, number })
const viewLabel: Record<WorkspaceView, string> = { files: "Files", logs: "Logs", browser: "Browser", shared: "Shared files" }
const viewIcon: Record<WorkspaceView, typeof TerminalIcon> = { files: FileCodeIcon, logs: ScrollTextIcon, browser: GlobeIcon, shared: FolderIcon }

export function GuestWorkspace({ initialEnvironmentId, initialAppSessionId, onClose, embedded=false, compact=false, toolbarActions, onEnvironmentChange }: { initialEnvironmentId: string; initialAppSessionId?: string; embedded?: boolean; compact?: boolean; toolbarActions?: ReactNode; onEnvironmentChange?(id:string):void; onClose(): void }) {
  const tour = useInstructionsTour()
  const guided = ownsTour(tour)
  const { state, environmentActions, openEnvironmentWindow, setEnvironmentStatus } = usePlatform()
  const [tabs, setTabs] = useState<WorkspaceTab[]>(() => [{ ...newTab(initialEnvironmentId), appSessionId: initialAppSessionId }])
  const [activeId, setActiveId] = useState(() => tabs[0]!.id)
  const [windows, setWindows] = useState<GuestWindow[]>([])
  const [windowsLoading, setWindowsLoading] = useState(false)
  const [windowsError, setWindowsError] = useState("")
  const [fullscreen, setFullscreen] = useState(Boolean(document.fullscreenElement))
  const [error, setError] = useState("")
  const [autoResizeDisplay, setAutoResizeDisplay] = useState(true)
  const [toolbarAction, setToolbarAction] = useState<"window" | "focus" | "fullscreen" | null>(null)
  const toolbarLock = useRef(false)
  const [readyTerminals, setReadyTerminals] = useState<Record<string, boolean>>({})
  const installTabs = useRef(new Map<string, string>())
  const [installNotice, setInstallNotice] = useState<{ tabId: string; message: string } | null>(null)
  const registerReady: TerminalReadyHandler = useCallback((id, ready, finished) => {
    if (finished) for (const [environmentId, tabId] of installTabs.current) {
      if (tabId === id) installTabs.current.delete(environmentId)
    }
    setReadyTerminals(current => {
      if (current[id] === ready || (!ready && !current[id])) return current
      const next = { ...current }
      if (ready) next[id] = true; else delete next[id]
      return next
    })
  }, [])
  const tabStrip = useRef<HTMLDivElement>(null)
  const activeTab = tabs.find(tab => tab.id === activeId) ?? tabs[0]!
  const activeEnvironment = state?.environments.find(env => env.id === activeTab.environmentId)
  // A shared tunnel is one tab with its own remote views; local views and power do not apply.
  const remote = isTunnelShared(activeEnvironment)
  const cloudSharedFiles = !remote && activeEnvironment?.kind === "cloud" && state?.connections.some(connection => connection.active
    && (connection.sourceId === activeEnvironment.id || connection.targetId === activeEnvironment.id)
    && connection.permissions.some(permission => ["data", "files", "volumes"].includes(permission)))
  useEffect(()=>{
    if(!embedded)return
    const existing=tabs.find(tab=>tab.environmentId===initialEnvironmentId)
    if(existing)setActiveId(existing.id)
    else { const tab=newTab(initialEnvironmentId);setTabs(current=>[...current,tab]);setActiveId(tab.id) }
    // A parent selection is a navigation event; existing terminal tabs stay mounted.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  },[embedded,initialEnvironmentId])
  const environmentAction = environmentActions[activeTab.environmentId]
  const busy = Boolean(environmentAction || toolbarAction)
  const options = useMemo(() => (state?.environments ?? []).filter(env => env.kind !== "computerBranch").map(env => ({ value: env.id, label: env.name })), [state?.environments])
  const EnvironmentIcon = activeEnvironment?.provider === "yougoriCuda" ? GpuIcon : activeEnvironment?.kind === "fullVm" ? MonitorIcon : activeEnvironment?.kind === "microVm" ? TerminalIcon : BoxIcon

  useEffect(() => {
    const stopped = new Set(state?.environments.filter(env => env.status !== "running").map(env => env.id))
    for (const id of stopped) installTabs.current.delete(id)
    // Restarting a container must not re-run a previous installation attempt.
    setTabs(current => current.some(tab => tab.installer && stopped.has(tab.environmentId))
      ? current.map(tab => tab.installer && stopped.has(tab.environmentId) ? { ...tab, installer: undefined } : tab)
      : current)
  }, [state?.environments])

  useEffect(() => {
    const update = () => setFullscreen(Boolean(document.fullscreenElement))
    document.addEventListener("fullscreenchange", update)
    return () => document.removeEventListener("fullscreenchange", update)
  }, [])

  useEffect(() => {
    tabStrip.current?.querySelector('[role="tab"][aria-selected="true"]')?.scrollIntoView({ block: "nearest", inline: "nearest" })
  }, [activeId])

  useEffect(() => {
    if (!activeEnvironment) return
    document.title = `${activeEnvironment.name} — Yougori`
    if(!embedded)void workspaceApi.titleWindow(activeEnvironment.id).catch(() => undefined)
  }, [embedded,activeEnvironment?.id, activeEnvironment?.name, activeEnvironment])

  const refreshWindows = () => {
    setWindowsLoading(true)
    setWindowsError("")
    void workspaceApi.windows().then(setWindows).catch(() => setWindowsError("Couldn't load open windows. Close this menu and try again.")).finally(() => setWindowsLoading(false))
  }
  const addTab = (environmentId = activeTab.environmentId) => {
    const remoteTab = isTunnelShared(state?.environments.find(env => env.id === environmentId)) && tabs.find(tab => tab.environmentId === environmentId)
    if (remoteTab) { setActiveId(remoteTab.id); return }
    const number = Math.max(0, ...tabs.filter(tab => tab.environmentId === environmentId).map(tab => tab.number)) + 1
    const tab = newTab(environmentId, number); setTabs(current => [...current, tab]); setActiveId(tab.id)
    tourTerminalOpened(environmentId)
  }
  // Files, logs and the service browser open beside terminals and desktops, one
  // tab per view so an environment keeps them all available at once.
  const openView = (view: WorkspaceView, environmentId = activeTab.environmentId) => {
    if (isTunnelShared(state?.environments.find(env => env.id === environmentId))) return
    const existing = tabs.find(tab => tab.environmentId === environmentId && tab.view === view)
    if (existing) { setActiveId(existing.id); return }
    const number = Math.max(0, ...tabs.filter(tab => tab.environmentId === environmentId).map(tab => tab.number)) + 1
    const tab = { ...newTab(environmentId, number), view }
    setTabs(current => [...current, tab]); setActiveId(tab.id)
  }
  const openModelChat = () => {
    if (activeEnvironment?.status !== "running") return
    const tab = { ...newTab(activeEnvironment.id, Math.max(0, ...tabs.filter(t => t.environmentId === activeEnvironment.id).map(t => t.number)) + 1), modelChat: true }
    setTabs(current => [...current, tab]); setActiveId(tab.id)
  }
  const switchEnvironment = (id: string) => {
    if (guided && id !== tour?.environmentId) return
    const existing = tabs.find(tab => tab.environmentId === id)
    if (existing) setActiveId(existing.id); else addTab(id)
    onEnvironmentChange?.(id)
  }
  const closeTab = (id: string) => {
    for (const [environmentId, tabId] of installTabs.current) {
      if (tabId === id) installTabs.current.delete(environmentId)
    }
    if (tabs.length === 1) { onClose(); return }
    const remaining = tabs.filter(tab => tab.id !== id)
    setTabs(remaining)
    if (id === activeId) { const next=remaining[Math.max(0, tabs.findIndex(tab => tab.id === id) - 1)]??remaining[0]!;setActiveId(next.id);onEnvironmentChange?.(next.environmentId) }
  }
  const perform = async (action: () => Promise<unknown>, toolbar?: NonNullable<typeof toolbarAction>) => {
    if (toolbar && toolbarLock.current) return
    if (toolbar) { toolbarLock.current = true; setToolbarAction(toolbar) }
    setError("")
    try { await action() }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { if (toolbar) { toolbarLock.current = false; setToolbarAction(null) } }
  }
  const supportsInstallers = activeEnvironment?.kind === "container" || activeEnvironment?.kind === "microVm" && activeEnvironment.runtime === "builtin:alpine"
  const startInstaller = (id: TerminalInstallerId) => {
    setError("")
    try {
      if (activeEnvironment?.status !== "running" || !supportsInstallers) throw new Error("Start this environment before installing coding tools.")
      if (!activeEnvironment.networkAccess) throw new Error(compact ? "Enable Internet access under Access, then choose Install tools again." : "Connect Internet access to this environment from the graph, then click Install again.")
      const existing = installTabs.current.get(activeEnvironment.id)
      if (existing) { setActiveId(existing); return }
      if (!readyTerminals[activeId] && !activeTab.installer) throw new Error("Wait for this environment's terminal to connect.")
      const number = Math.max(0, ...tabs.filter(tab => tab.environmentId === activeEnvironment.id).map(tab => tab.number)) + 1
      const tab = { ...newTab(activeEnvironment.id, number), installer: id }
      installTabs.current.set(activeEnvironment.id, tab.id)
      setTabs(current => [...current, tab]); setActiveId(tab.id)
      setInstallNotice({ tabId: tab.id, message: `${terminalInstallers.find(tool => tool.id === id)!.name} installation starts automatically here. Other terminals are unchanged. ${id === "ollama" ? "No model is downloaded. When it finishes, open a new terminal and run ollama serve." : id === "openclaw" ? "When it finishes, open a new terminal and run openclaw onboard to configure your provider and permissions." : "When it finishes, open a new terminal to configure your account or provider."}` })
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
  }

  const openAnotherWindow = async () => {
    if (activeTab.appSessionId && !remote) return guestAppsApi.openWindow(activeTab.environmentId, activeTab.appSessionId)
    prepareTourWindow(activeTab.environmentId)
    try {
      const opened = await openEnvironmentWindow(activeTab.environmentId)
      if (!opened) tourWindowFailed(activeTab.environmentId)
      return opened
    } catch (reason) { tourWindowFailed(activeTab.environmentId); throw reason }
  }

  const installerMenu = activeEnvironment && supportsInstallers && !activeTab.appSessionId ? <Menu modal={!guided}>
          <MenuTrigger disabled={busy || activeEnvironment.status !== "running" || (!readyTerminals[activeId] && !activeTab.installer)} render={<Button data-tour="install-tools" type="button" size="sm" variant="ghost" aria-label="Install tools" title="Install AI tools in this environment" className="gap-1.5 rounded-md text-xs text-muted-foreground data-popup-open:bg-accent data-popup-open:text-foreground" />}>
            <DownloadIcon aria-hidden="true" /><span className="hidden sm:inline">Install tools</span><ChevronDownIcon aria-hidden="true" className="size-3" />
          </MenuTrigger>
          <MenuPopup data-tour="installer-menu" align="end" sideOffset={8} className="w-60 max-w-[calc(100vw-24px)]">
            <MenuGroup>
              <MenuGroupLabel className="px-2.5">Install in this environment</MenuGroupLabel>
              {terminalInstallers.map(tool => <MenuItem key={tool.id} aria-label={`Install ${tool.name}`} disabled={busy || activeEnvironment.status !== "running" || (!readyTerminals[activeId] && !activeTab.installer)} onClick={() => startInstaller(tool.id)} className="group justify-between rounded-md px-2.5 py-2 text-sm">
                <span>{tool.name}</span><DownloadIcon aria-hidden="true" className="size-3.5 text-muted-foreground opacity-40 group-data-highlighted:opacity-100" />
              </MenuItem>)}
            </MenuGroup>
            <MenuSeparator />
            <p className="px-2.5 py-2 text-[11px] leading-relaxed text-muted-foreground">Starts automatically in a new terminal tab.</p>
          </MenuPopup>
        </Menu> : null

  return <main className={`flex ${embedded?"h-full":"h-screen"} min-h-0 min-w-0 flex-col overflow-hidden bg-background text-foreground`} data-guest-workspace>
    {!compact ? <header className="flex h-11 shrink-0 items-center gap-2.5 border-b bg-muted/40 px-3" data-workspace-toolbar>
      <div className="hidden size-7 shrink-0 items-center justify-center rounded-lg bg-primary/10 text-primary sm:flex"><EnvironmentIcon aria-hidden="true" className="size-4" /></div>
      <div className="flex min-w-0 flex-1 items-center gap-2">
      <Select items={options} itemToStringValue={item => item.value} onValueChange={item => { if (item) switchEnvironment(item.value) }} value={options.find(item => item.value === activeTab.environmentId) ?? null}>
        <SelectTrigger data-tour="environment-switcher" aria-label="Switch environment" title={activeEnvironment?.name} size="sm" className="w-auto min-w-0 max-w-64 gap-2 rounded-md border-transparent bg-transparent px-1.5 text-[13px] font-semibold shadow-none before:hidden hover:bg-accent sm:text-[13px] dark:bg-transparent [&_[data-slot=select-icon]]:hidden"><SelectValue placeholder="Choose environment" /><ChevronDownIcon aria-hidden="true" className="size-3 text-muted-foreground" /></SelectTrigger>
        <SelectPopup alignItemWithTrigger={false} className="w-72 max-w-[min(24rem,90vw)]">
          <p className="px-3 py-2 text-[10px] font-medium tracking-widest text-muted-foreground uppercase">Environments</p>
          {options.map(item => {
            const env = state?.environments.find(environment => environment.id === item.value)
            const Icon = env?.provider === "yougoriCuda" ? GpuIcon : env?.kind === "fullVm" ? MonitorIcon : env?.kind === "microVm" ? TerminalIcon : BoxIcon
            return <SelectItem key={item.value} value={item} disabled={guided && item.value !== tour?.environmentId} aria-label={item.label} className="py-2">
              <span className="flex min-w-0 items-center gap-2.5"><span className="flex size-7 shrink-0 items-center justify-center rounded-md bg-muted"><Icon aria-hidden="true" className="size-3.5 text-muted-foreground" /></span><span className="flex min-w-0 flex-col gap-0.5"><span className="truncate text-xs font-medium">{item.label}</span>{env ? <span className="truncate text-[11px] text-muted-foreground">{environmentLabel(env)} · {env.kind === "cloud" ? env.status === "running" ? "Connected" : "Disconnected" : statusLabel[env.status]}</span> : null}</span></span>
            </SelectItem>
          })}
        </SelectPopup>
      </Select>
      {activeEnvironment ? <span className="hidden shrink-0 border-l pl-2 text-[11px] text-muted-foreground lg:inline">{environmentLabel(activeEnvironment)}</span> : null}
      {activeEnvironment ? <span role={environmentAction ? "status" : undefined} className={cn("hidden shrink-0 items-center gap-1.5 rounded-full px-2 py-0.5 text-[10px] font-medium sm:flex", activeEnvironment.status === "running" ? "bg-success/10 text-success-foreground" : "bg-muted text-muted-foreground")}><span aria-hidden="true" className={cn("size-1.5 rounded-full", activeEnvironment.status === "running" ? "bg-success" : activeEnvironment.status === "error" ? "bg-destructive" : "bg-muted-foreground/50")} />{environmentAction ? environmentActionLabel[environmentAction] : activeEnvironment.kind === "cloud" ? activeEnvironment.status === "running" ? "Connected" : "Disconnected" : statusLabel[activeEnvironment.status]}</span> : null}
      </div>
      <div className="flex shrink-0 items-center gap-1">
        {activeEnvironment ? <ModelEnvironmentActions key={`model-${activeEnvironment.id}`} environment={activeEnvironment} onChat={openModelChat} /> : null}
        {cloudSharedFiles ? <Button type="button" size="sm" variant="ghost" className="rounded-md text-xs" onClick={() => openView("shared")}><FolderIcon aria-hidden="true" />Shared files</Button> : null}
        {activeEnvironment && supportsConnections(activeEnvironment) ? <ConnectionSkillsDialog key={`skills-${activeEnvironment.id}`} environmentId={activeEnvironment.id} /> : null}
        {activeEnvironment?.kind === "container" && activeEnvironment.provider !== "yougoriCuda" || activeEnvironment?.kind === "microVm" && activeEnvironment.runtime === "builtin:alpine" ? <GuestAppLauncher key={`apps-${activeEnvironment.id}`} environment={activeEnvironment} /> : null}
        {installerMenu}
        <Button data-tour="new-window" type="button" aria-label="New window" title="Open this environment in a new window" disabled={busy || activeEnvironment?.status !== "running"} loading={toolbarAction === "window"} onClick={() => void perform(openAnotherWindow, "window")} size="sm" variant="ghost" className="rounded-md bg-primary/10 text-xs text-primary hover:bg-primary/15 sm:text-xs"><SquareArrowOutUpRightIcon aria-hidden="true" /><span className="hidden sm:inline">New window</span></Button>
        <Menu onOpenChange={open => { if (open) refreshWindows() }}>
          <MenuTrigger render={<Button data-tour="window-switcher" type="button" aria-label="Switch window" title="Switch window" disabled={busy} loading={toolbarAction === "focus"} size="sm" variant="ghost" className="rounded-md text-xs text-muted-foreground sm:text-xs" />}><PanelsTopLeftIcon aria-hidden="true" /><span className="hidden sm:inline">Windows</span><ChevronDownIcon aria-hidden="true" className="size-3" /></MenuTrigger>
          <MenuPopup align="end" className="w-72 max-w-[90vw]">
            <MenuGroup><MenuGroupLabel>Open windows</MenuGroupLabel>{windowsLoading ? <p className="px-2 py-3 text-xs text-muted-foreground" role="status">Loading windows…</p> : windowsError ? <p className="px-2 py-3 text-xs text-destructive-foreground" role="alert">{windowsError}</p> : windows.length ? windows.map((window, index) => <MenuItem key={window.label} className="gap-3 py-2" disabled={busy} onClick={() => void perform(() => workspaceApi.focusWindow(window.label), "focus")}><span className="flex size-8 shrink-0 items-center justify-center rounded-md border bg-muted/50"></span><span className="flex min-w-0 flex-col gap-0.5"><span className="truncate text-xs font-medium">{window.title}</span><span className="text-[10px] text-muted-foreground">Window {index + 1}</span></span></MenuItem>) : <div className="flex flex-col items-center gap-2 px-3 py-5 text-center"><PanelsTopLeftIcon aria-hidden="true" className="size-6 text-muted-foreground/60" /><p className="text-xs text-muted-foreground">No other windows open.</p></div>}</MenuGroup>
            <MenuSeparator />
            <MenuItem disabled={busy || activeEnvironment?.status !== "running"} onClick={() => void perform(openAnotherWindow, "window")}>New window for this environment</MenuItem>
          </MenuPopup>
        </Menu>
        <div aria-hidden="true" className="mx-1 h-4 w-px bg-border" />
        <Tooltip><TooltipTrigger render={<Button type="button" aria-label="Toggle fullscreen" aria-pressed={fullscreen} disabled={busy} loading={toolbarAction === "fullscreen"} onClick={() => void perform(() => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen(), "fullscreen")} size="icon-sm" variant="ghost" className="rounded-md text-muted-foreground" />}>{fullscreen ? <Minimize2Icon aria-hidden="true" /> : <Maximize2Icon aria-hidden="true" />}</TooltipTrigger><TooltipPopup side="bottom">{fullscreen ? "Exit fullscreen" : "Enter fullscreen"}</TooltipPopup></Tooltip>
        <Menu>
          <MenuTrigger render={<Button type="button" aria-label="Workspace actions" title="Workspace actions" disabled={busy} loading={environmentAction === "stopping"} size="icon-sm" variant="ghost" className="text-muted-foreground" />}><EllipsisIcon aria-hidden="true" /></MenuTrigger>
          <MenuPopup align="end" className="w-56">
            {!remote ? <><MenuGroup>
              <MenuGroupLabel>Open a view</MenuGroupLabel>
              <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("files")}>Files and code editor</MenuItem>
              {cloudSharedFiles ? <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("shared")}>Shared files</MenuItem> : null}
              <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("logs")}>Logs</MenuItem>
              <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("browser")}>Browser</MenuItem>
            </MenuGroup>
            <MenuSeparator /></> : null}
            {activeEnvironment?.kind === "fullVm" ? <MenuItem disabled={activeEnvironment.status !== "running" || Boolean(activeTab.appSessionId)} onClick={() => void perform(fitWindowToGuestDisplay)}>Fit window to desktop</MenuItem> : null}
            {activeEnvironment?.kind === "fullVm" ? <><MenuItem onClick={() => setAutoResizeDisplay(value => !value)}>{autoResizeDisplay ? "Keep guest resolution" : "Auto-resize guest resolution"}</MenuItem><p className="px-2 py-1.5 text-[11px] leading-relaxed text-muted-foreground">{autoResizeDisplay ? "Asks the guest to match the focused window. Requires a compatible guest display driver." : "Keeps the resolution set inside the guest."} The desktop is never stretched or cropped. Bars remain if the guest cannot match the window.</p><p className="px-2 py-1.5 text-[11px] leading-relaxed text-muted-foreground">Windows key is captured over the focused guest display; move the pointer out to release it.</p><MenuSeparator /></> : null}
            <MenuItem onClick={onClose}>Close window</MenuItem>
            {!remote ? <><MenuSeparator />
            <MenuItem variant="destructive" disabled={busy || activeEnvironment?.status !== "running"} onClick={() => void perform(() => setEnvironmentStatus(activeTab.environmentId, "stopped"))}>{activeEnvironment?.kind === "cloud" ? "Disconnect" : "Stop environment"}</MenuItem>
            <p className="px-2 py-1.5 text-[11px] leading-relaxed text-muted-foreground">{activeEnvironment?.kind === "cloud" ? "Disconnect closes these SSH terminals. The cloud server stays on." : "Stopping disconnects all windows using this environment."}</p></> : null}
          </MenuPopup>
        </Menu>
      </div>
    </header> : null}
    {error ? <div className="flex shrink-0 items-start gap-3 border-b bg-destructive/5 px-4 py-2 text-xs text-destructive-foreground" role="alert"><p className="min-w-0 flex-1 break-words py-1">{error}</p><Button type="button" aria-label="Dismiss error" size="icon-xs" variant="ghost" onClick={() => setError("")}><XIcon aria-hidden="true" /></Button></div> : null}
    {installNotice?.tabId === activeId ? <div className="flex shrink-0 items-center gap-2 border-b bg-muted/30 px-3 py-1 text-xs text-muted-foreground"><p role="status" className="min-w-0 flex-1">{installNotice.message}</p><Button type="button" size="icon-xs" variant="ghost" aria-label="Dismiss install notice" onClick={() => setInstallNotice(null)}><XIcon aria-hidden="true" /></Button></div> : null}
    <Tabs className="min-h-0 flex-1 gap-0" onValueChange={value => {setActiveId(String(value));const tab=tabs.find(t=>t.id===String(value));if(tab)onEnvironmentChange?.(tab.environmentId)}} value={activeId}>
      <div className="flex h-9 shrink-0 items-center gap-1 border-b bg-muted/20 px-3" data-workspace-tabs>
        <div className="min-w-0 overflow-x-auto [scrollbar-width:thin]" ref={tabStrip}>
          <TabsList aria-label="Environment screens" variant="underline" size="sm" className="h-9 gap-1 data-[orientation=horizontal]:py-0 [&_[data-slot=tab-indicator]]:hidden">
            {tabs.map(tab => { const env = state?.environments.find(item => item.id === tab.environmentId); const shared = isTunnelShared(env); const TabIcon = tab.view ? viewIcon[tab.view] : shared ? GlobeIcon : tab.appSessionId || env?.kind === "fullVm" ? MonitorIcon : TerminalIcon; const mode = tab.view ? viewLabel[tab.view] : shared ? "Shared" : tab.modelChat ? "Chat" : tab.installer ? `Install ${terminalInstallers.find(tool => tool.id === tab.installer)!.name}` : tab.appSessionId ? "App" : env?.kind === "fullVm" ? "Desktop" : "Terminal"; return <div className={cn("flex h-9 shrink-0 items-center rounded-t-md border-b-2 pr-1", tab.id === activeId ? "border-primary bg-primary/5 text-foreground" : "border-transparent text-muted-foreground hover:bg-accent/60")} key={tab.id}>
              <TabsTab value={tab.id} aria-label={`${env?.name ?? "Removed"} · ${mode} ${tab.number}`} title={`${env?.name ?? "Removed"} · ${mode} ${tab.number}`} className="h-7 min-w-0 gap-2 px-2.5 text-xs sm:text-xs"><TabIcon aria-hidden="true" className={cn("size-3.5", tab.id === activeId && "text-primary")} />{!compact ? <><span className="max-w-32 truncate">{env?.name ?? "Removed"}</span><span className="sr-only"> · </span></> : null}<span className="shrink-0 font-normal text-muted-foreground">{mode} {tab.number}</span></TabsTab>
              <Button type="button" aria-label={`Close ${env?.name ?? "removed environment"} tab ${tab.number}`} title="Close tab" onClick={() => closeTab(tab.id)} size="icon-xs" variant="ghost" className="text-muted-foreground hover:text-foreground"><XIcon aria-hidden="true" className="size-3" /></Button>
            </div> })}
          </TabsList>
        </div>
        <Tooltip><TooltipTrigger render={<Button data-tour="new-terminal" type="button" aria-label="New terminal or desktop tab" onClick={() => addTab()} size="icon-sm" variant="ghost" className="shrink-0 text-muted-foreground" />}><PlusIcon aria-hidden="true" /></TooltipTrigger><TooltipPopup side="bottom">New {activeEnvironment?.kind === "fullVm" ? "desktop" : "terminal"} tab</TooltipPopup></Tooltip>
        {compact ? <div className="ml-auto flex shrink-0 items-center gap-1">
          {toolbarActions}
          {activeEnvironment ? <ModelEnvironmentActions key={`model-${activeEnvironment.id}`} environment={activeEnvironment} onChat={openModelChat} /> : null}
          {cloudSharedFiles ? <Button type="button" size="sm" variant="ghost" className="rounded-md text-xs" onClick={() => openView("shared")}><FolderIcon aria-hidden="true" />Shared files</Button> : null}
          {!remote ? <EnvironmentChanges key={activeTab.environmentId} environmentId={activeTab.environmentId} /> : null}
          <ConnectionSkillsDialog environmentId={activeTab.environmentId} renderTrigger={openSkills => <Menu>
            <MenuTrigger render={<Button size="icon-sm" variant="ghost" aria-label="CLI actions" title="CLI actions" />}><EllipsisIcon aria-hidden="true" /></MenuTrigger>
            <MenuPopup align="end">
              <MenuItem onClick={openSkills}>Skills</MenuItem>
              {supportsInstallers ? <MenuSub>
                <MenuSubTrigger disabled={busy || activeEnvironment?.status !== "running" || (!readyTerminals[activeId] && !activeTab.installer)}><DownloadIcon aria-hidden="true" />Install tools</MenuSubTrigger>
                <MenuSubPopup>{terminalInstallers.map(tool => <MenuItem key={tool.id} aria-label={`Install ${tool.name}`} onClick={() => startInstaller(tool.id)}>{tool.name}</MenuItem>)}</MenuSubPopup>
              </MenuSub> : null}
              {!remote ? <><MenuSeparator />
              <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("files")}>Files</MenuItem>
              {cloudSharedFiles ? <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("shared")}>Shared files</MenuItem> : null}
              <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("logs")}>Logs</MenuItem>
              <MenuItem disabled={activeEnvironment?.status !== "running"} onClick={() => openView("browser")}>Browser</MenuItem></> : null}
              <MenuSeparator />
              <MenuItem onClick={() => void perform(() => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen(), "fullscreen")}>{fullscreen ? "Exit fullscreen" : "Fullscreen"}</MenuItem>
              <MenuItem onClick={onClose}>Hide CLI</MenuItem>
            </MenuPopup>
          </Menu>} />
        </div> : null}
      </div>
      {tabs.map(tab => { const env = state?.environments.find(item => item.id === tab.environmentId); return <TabsPanel className={`min-h-0 overflow-hidden ${tab.id !== activeId ? "hidden!" : ""}`} keepMounted key={tab.id} value={tab.id}>
        {env && (isTunnelShared(env) || env.runtime.startsWith("shared://desk/")) ? <RemoteWorkspace key={env.id} environment={env} initialAppSessionId={tab.appSessionId} onClose={() => closeTab(tab.id)} /> : env?.status === "running" ? (tab.view === "files" ? <GuestFiles environmentId={env.id} active={tab.id === activeId} /> : tab.view === "shared" ? <ConnectedFiles environmentId={env.id} active={tab.id === activeId} /> : tab.view === "logs" ? <GuestLogs environmentId={env.id} active={tab.id === activeId} /> : tab.view === "browser" ? <GuestBrowser environmentId={env.id} active={tab.id === activeId} /> : tab.appSessionId ? <GuestAppView environmentId={env.id} sessionId={tab.appSessionId} active={tab.id === activeId} /> : <GuestScene active={tab.id === activeId} environment={env} terminalSessionId={tab.id} onReady={registerReady} installer={tab.installer} modelChat={tab.modelChat} autoResizeDisplay={autoResizeDisplay} />) : <div className="grid h-full place-items-center overflow-auto p-6"><div className="flex w-full max-w-sm flex-col items-center gap-4 text-center"><div className="flex size-12 items-center justify-center rounded-xl border bg-muted/40 text-muted-foreground"><PowerIcon aria-hidden="true" className="size-5" /></div><div className="flex min-w-0 flex-col gap-2"><h1 className="break-words text-base font-semibold">{env ? env.name : "Environment removed"}</h1><p className="text-sm leading-relaxed text-muted-foreground">{env ? env.kind === "cloud" ? "Disconnected. Connect to resume access to this server." : `${statusLabel[env.status]}. Start this environment to continue your ${env.kind === "fullVm" ? "desktop" : "terminal"} session.` : "This environment is no longer available. Choose another one from the switcher above."}</p></div>{env ? <Button type="button" size="sm" disabled={env.status === "provisioning" || Boolean(environmentActions[env.id])} loading={environmentActions[env.id] === "starting" || environmentActions[env.id] === "connecting"} onClick={() => void perform(() => setEnvironmentStatus(env.id, "running"))}>{env.kind === "cloud" ? "Connect" : <><PlayIcon aria-hidden="true" />Start environment</>}</Button> : null}</div></div>}
      </TabsPanel> })}
    </Tabs>
  </main>
}
