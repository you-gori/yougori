import { useCallback, useEffect, useRef, useState } from "react"
import { CopyIcon, DownloadIcon, EllipsisIcon, FileCodeIcon, FolderOpenIcon, Maximize2Icon, PlusIcon, ShieldCheckIcon, TerminalIcon, Trash2Icon, XIcon } from "lucide-react"
import { hostTerminalApi, type HostTerminalInfo } from "@/api/host-terminal-api"
import { workspaceApi } from "@/api/workspace-api"
import { HostTerminalCanvas, type HostCanvasControls, type HostShellState, type HostTab } from "@/components/host-terminal-canvas"
import { Button } from "@/components/ui/button"
import { Dialog, DialogDescription, DialogHeader, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Menu, MenuItem, MenuPopup, MenuSeparator, MenuSub, MenuSubPopup, MenuSubTrigger, MenuTrigger } from "@/components/ui/menu"
import { Tabs, TabsList, TabsPanel, TabsTab } from "@/components/ui/tabs"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import { terminalInstallers, type TerminalInstallerId } from "@/lib/terminal-installers"
import { hostInstallerCommand } from "@/lib/host-terminal-installers"
import { cn } from "@/lib/utils"
import editAppSkill from "../../.agents/skills/edit-yougori/SKILL.md?raw"
import "./host-terminal-dock.css"

export default function HostCliView({ visible, onHide, mode = "cli" }: { visible: boolean; onHide(): void; mode?: "cli" | "edit" }) {
  const [info, setInfo] = useState<HostTerminalInfo | null>(null)
  const [tabs, setTabs] = useState<HostTab[]>([])
  const [activeId, setActiveId] = useState("")
  const [workingDirectory, setWorkingDirectory] = useState<string>()
  const [sourceCheckout, setSourceCheckout] = useState<string | null>(null)
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [retry, setRetry] = useState(0)
  const [busy, setBusy] = useState(false)
  const [accessOpen, setAccessOpen] = useState(false)
  const [skillsOpen, setSkillsOpen] = useState(false)
  const [ending, setEnding] = useState("")
  const [fullscreen, setFullscreen] = useState(Boolean(document.fullscreenElement))
  const counter = useRef(0)
  const controls = useRef(new Map<string, HostCanvasControls>())
  const operation = useRef(false)
  const canCreate = Boolean(info && !info.elevated && (mode === "cli" || sourceCheckout) && tabs.length + info.sessions.filter(session => !tabs.some(tab => tab.id === session.sessionId)).length < info.maxSessions && !busy)
  const editSkillPath = sourceCheckout ? [sourceCheckout, ".agents", "skills", "edit-yougori", "SKILL.md"].join(sourceCheckout.includes("\\") ? "\\" : "/") : "Choose a source checkout first"
  const addTab = useCallback((cwd: string, command?: string, name?: string) => {
    const tab: HostTab = { id: `${mode === "edit" ? "host-edit" : "host-cli"}-${crypto.randomUUID()}`, cwd, command, name: name ?? `Terminal ${++counter.current}`, state: "starting" }
    setTabs(current => [...current, tab]); setActiveId(tab.id)
  }, [mode])

  useEffect(() => {
    let active = true
    void hostTerminalApi.info().then(async result => {
      if (!active) return
      setInfo(result)
      const ownSessions = result.sessions.filter(session => mode === "edit" ? session.sessionId.startsWith("host-edit-") : !session.sessionId.startsWith("host-edit-"))
      let checkout = result.sourceCheckout ?? null
      if (mode === "edit") {
        const saved = localStorage.getItem("yougori.edit-source-checkout")
        if (saved) { try { checkout = await hostTerminalApi.validateEditFolder(saved) } catch { localStorage.removeItem("yougori.edit-source-checkout") } }
      }
      if (!active) return
      if (mode === "edit") setSourceCheckout(checkout)
      if (ownSessions.length) {
        const restored: HostTab[] = ownSessions.map(session => ({ id: session.sessionId, cwd: session.cwd, name: `Terminal ${++counter.current}`, reconnect: true, state: "starting" }))
        setTabs(restored); setActiveId(restored[0]?.id ?? "")
      } else if (!result.elevated && (mode === "cli" || checkout)) addTab(mode === "edit" ? checkout! : result.cwd)
    }).catch(reason => { if (active) setError(String(reason)) })
    return () => { active = false }
  }, [retry, addTab, mode])
  useEffect(() => {
    const update = () => setFullscreen(Boolean(document.fullscreenElement))
    document.addEventListener("fullscreenchange", update)
    return () => document.removeEventListener("fullscreenchange", update)
  }, [])
  const onState = useCallback((id: string, state: HostShellState) => setTabs(current => current.map(tab => tab.id === id ? { ...tab, state } : tab)), [])
  const onControls = useCallback((id: string, value: HostCanvasControls | null) => { if (value) controls.current.set(id, value); else controls.current.delete(id) }, [])
  const perform = async (action: () => Promise<void>) => {
    if (operation.current) return
    operation.current = true; setBusy(true); setError("")
    try { await action() } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { operation.current = false; setBusy(false) }
  }
  const start = (command?: string, name?: string) => { if (canCreate && info) addTab(mode === "edit" ? sourceCheckout! : workingDirectory ?? info.cwd, command, name) }
  const install = (id: TerminalInstallerId) => {
    if (!info || !canCreate) return
    const tool = terminalInstallers.find(item => item.id === id)!
    const command = hostInstallerCommand(id, info.shell === "PowerShell")
    if (command) start(command, `Install ${tool.name}`)
    else void perform(async () => { await workspaceApi.openUrl(id === "ollama" ? "https://ollama.com/download" : tool.docs); setNotice(`${tool.name} installation instructions opened for your computer.`) })
  }
  const chooseFolder = () => perform(async () => {
    const cwd = await hostTerminalApi.chooseFolder()
    if (cwd && mode === "edit") {
      const checkout = await hostTerminalApi.validateEditFolder(cwd)
      setSourceCheckout(checkout); localStorage.setItem("yougori.edit-source-checkout", checkout)
      if (info && !info.elevated && tabs.length + info.sessions.filter(session => !tabs.some(tab => tab.id === session.sessionId)).length < info.maxSessions) addTab(checkout)
    } else if (cwd && canCreate) { setWorkingDirectory(cwd); addTab(cwd) }
  })
  const closeTab = () => perform(async () => {
    await hostTerminalApi.terminal({ sessionId: ending, action: "close" })
    const remaining = tabs.filter(tab => tab.id !== ending)
    setTabs(remaining); if (activeId === ending) setActiveId(remaining[0]?.id ?? ""); setEnding("")
  })
  const feedback = <>
    {error ? <div role="alert" className="flex shrink-0 items-start gap-2 border-b px-4 py-2 text-xs text-destructive-foreground"><p className="min-w-0 flex-1 break-words">{error}</p>{!info ? <Button size="xs" onClick={() => { setError(""); setRetry(value => value + 1) }}>Retry</Button> : null}<Button size="icon-xs" variant="ghost" aria-label="Dismiss CLI error" onClick={() => setError("")}><XIcon /></Button></div> : null}
    {notice ? <div role="status" className="flex shrink-0 items-start gap-2 border-b px-4 py-2 text-xs text-muted-foreground"><p className="min-w-0 flex-1 break-words">{notice}</p><Button size="icon-xs" variant="ghost" aria-label="Dismiss CLI notice" onClick={() => setNotice("")}><XIcon /></Button></div> : null}
  </>

  return <section id={mode === "edit" ? "edit-app-terminal-panel" : "host-terminal-panel"} aria-label={mode === "edit" ? "Edit the App" : "Yougori CLI"} className="host-cli isolated-cli flex h-full min-h-0 flex-1 flex-col overflow-hidden bg-background">
    {!skillsOpen && !accessOpen && !ending ? feedback : null}
    {info?.elevated ? <p role="alert" className="px-4 py-2 text-xs">Reopen Yougori normally, not as administrator, to use the host terminal.</p> : null}
    {mode === "edit" ? <div className="flex shrink-0 items-center gap-2 border-b px-3 py-2 text-xs"><FileCodeIcon className="size-4 shrink-0 text-primary" /><span className="min-w-0 flex-1 truncate" title={sourceCheckout ?? undefined}>{sourceCheckout ?? "Choose a Yougori source checkout to edit the app"}</span><Button size="xs" variant="outline" disabled={busy} onClick={() => void chooseFolder()}><FolderOpenIcon />{sourceCheckout ? "Change folder" : "Choose folder"}</Button></div> : null}
    <Tabs value={activeId} onValueChange={value => setActiveId(String(value))} className="min-h-0 flex-1 gap-0">
      <div className="flex h-9 shrink-0 items-center gap-1 border-b bg-muted/20 px-3" data-workspace-tabs>
        <div className="min-w-0 overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
          <TabsList aria-label={mode === "edit" ? "App editing terminals" : "CLI terminals"} variant="underline" size="sm" className="h-9 gap-1 data-[orientation=horizontal]:py-0 [&_[data-slot=tab-indicator]]:hidden">
            {tabs.map(tab => <div key={tab.id} className={cn("flex h-9 shrink-0 items-center rounded-t-md border-b-2 pr-1", tab.id === activeId ? "border-primary bg-primary/5 text-foreground" : "border-transparent text-muted-foreground hover:bg-accent/60")}>
              <TabsTab value={tab.id} title={`${info?.shell ?? "Shell"} · ${tab.cwd}`} className="h-7 min-w-0 gap-2 px-2.5 text-xs sm:text-xs"><TerminalIcon aria-hidden="true" className={cn("size-3.5", tab.id === activeId && "text-primary")} /><span className="shrink-0 font-normal text-muted-foreground">{tab.name}</span></TabsTab>
              <Button size="icon-xs" variant="ghost" aria-label={`Close ${tab.name}`} title="Close tab" disabled={busy} onClick={() => setEnding(tab.id)} className="text-muted-foreground hover:text-foreground"><XIcon className="size-3" /></Button>
            </div>)}
          </TabsList>
        </div>
        <Button size="icon-sm" variant="ghost" aria-label="New terminal tab" title={canCreate ? "New terminal tab" : `Up to ${info?.maxSessions ?? 4} terminals`} disabled={!canCreate} onClick={() => start()} className="shrink-0 text-muted-foreground"><PlusIcon /></Button>
        <div className="ml-auto flex shrink-0 items-center gap-1">
          {mode === "edit" ? info?.agents.filter(agent => agent.available).map(agent => <Button key={agent.id} size="xs" variant="ghost" disabled={!canCreate} onClick={() => start(agent.id, agent.name)}>{agent.name}</Button>) : null}
          <Button size="xs" variant="ghost" className="gap-1.5 text-xs text-muted-foreground" aria-label="CLI access" onClick={() => setAccessOpen(true)}><ShieldCheckIcon />Access</Button>
          <Menu>
            <MenuTrigger render={<Button size="icon-sm" variant="ghost" aria-label="CLI actions" title="CLI actions" />}><EllipsisIcon /></MenuTrigger>
            <MenuPopup align="end">
              <MenuItem onClick={() => setSkillsOpen(true)}><FileCodeIcon />Skills</MenuItem>
              <MenuSub><MenuSubTrigger disabled={!canCreate}><DownloadIcon />Install tools</MenuSubTrigger><MenuSubPopup>{terminalInstallers.map(tool => <MenuItem key={tool.id} aria-label={`Install ${tool.name}`} title={tool.id === "ollama" || tool.id === "openclaw" ? "Open official installation instructions" : "Install on your computer in a new terminal"} onClick={() => install(tool.id)}>{tool.name}</MenuItem>)}</MenuSubPopup></MenuSub>
              <MenuSeparator />
              <MenuItem disabled={mode === "cli" && !canCreate} onClick={() => void chooseFolder()}><FolderOpenIcon />{mode === "edit" ? "Choose source checkout" : "Open folder in new terminal"}</MenuItem>
              <MenuItem disabled={!activeId} onClick={() => controls.current.get(activeId)?.clear()}><Trash2Icon />Clear terminal</MenuItem>
              <MenuSeparator />
              <MenuItem onClick={() => void perform(() => document.fullscreenElement ? document.exitFullscreen() : document.documentElement.requestFullscreen())}><Maximize2Icon />{fullscreen ? "Exit fullscreen" : "Fullscreen"}</MenuItem>
              <MenuItem onClick={onHide}><XIcon />Hide {mode === "edit" ? "editor" : "CLI"}</MenuItem>
            </MenuPopup>
          </Menu>
        </div>
      </div>
      {tabs.map(tab => <TabsPanel key={tab.id} value={tab.id} keepMounted className={`relative min-h-0 overflow-hidden bg-[#0c0c0c] ${tab.id !== activeId ? "hidden!" : ""}`}><HostTerminalCanvas tab={tab} active={visible && activeId === tab.id} onState={onState} onControls={onControls} /></TabsPanel>)}
      {!tabs.length ? <div className="grid flex-1 place-items-center p-6 text-sm text-muted-foreground">{info ? mode === "edit" && !sourceCheckout ? <Button size="sm" onClick={() => void chooseFolder()}>Choose Yougori source folder</Button> : <Button size="sm" disabled={!canCreate} onClick={() => start()}>New terminal</Button> : <span role="status">Starting {mode === "edit" ? "editor" : "CLI"}…</span>}</div> : null}
    </Tabs>
    <Dialog open={accessOpen} onOpenChange={setAccessOpen}>
      <DialogPopup className="max-w-2xl" bottomStickOnMobile={false}>
        <DialogHeader><DialogTitle>{mode === "edit" ? "App editing access" : "CLI access"}</DialogTitle><DialogDescription>This terminal runs on your computer using your signed-in account.</DialogDescription></DialogHeader>
        <div className="space-y-4 px-6 pb-6 text-sm"><div className="flex justify-between gap-4"><span>{mode === "edit" ? "Source files" : "Environments"}</span><span className="text-muted-foreground">{mode === "edit" ? "Your selected checkout" : "All local environments"}</span></div><div className="flex justify-between gap-4"><span>Internet and PC folders</span><span className="text-muted-foreground">Your computer’s access</span></div><div className="border-t pt-4"><p className="mb-1 text-xs text-muted-foreground">Starting folder</p><p className="break-all font-mono text-xs">{mode === "edit" ? sourceCheckout : workingDirectory ?? info?.cwd}</p></div></div>{feedback}
      </DialogPopup>
    </Dialog>
    <Dialog open={skillsOpen} onOpenChange={setSkillsOpen}>
      <DialogPopup className="max-w-2xl" bottomStickOnMobile={false}>
        <DialogHeader><DialogTitle>Skills</DialogTitle><DialogDescription>{mode === "edit" ? "Guidance for editing this checkout and managing its environments." : "Keep Yougori instructions in your workspace for any coding agent."}</DialogDescription></DialogHeader>
        <div className="space-y-4 px-6 pb-6">{mode === "edit" ? <div className="rounded-md border p-3 text-sm"><p className="font-medium">Edit Yougori</p><p className="mt-1 text-xs text-muted-foreground">This checkout includes an editing skill for source layout, tests, and builds.</p><p className="mt-2 break-all font-mono text-xs">{editSkillPath}</p></div> : null}<p className="text-sm text-muted-foreground">{info?.skill.message}</p><p className="break-all font-mono text-xs text-muted-foreground">{info?.skill.path}</p><p className="text-xs text-muted-foreground">{mode === "edit" ? "The Yougori management skill covers CLI operations. Ask your agent to read the editing skill in the checkout and the management skill in your workspace." : "Ask your agent to read skills/yougori/SKILL.md from your Yougori workspace, or copy the guide below."}</p><div className="flex flex-wrap gap-2">
          <Button size="sm" disabled={!info || busy || info.skill.state === "conflict" || info.skill.state === "ready"} onClick={() => void perform(async () => { const skill = await hostTerminalApi.setup(); setInfo(current => current ? { ...current, skill } : current); setNotice(skill.message) })}>{info?.skill.state === "ready" ? "Skill installed" : info?.skill.state === "updateAvailable" ? "Update skill" : "Install skill"}</Button>
          <Button size="sm" variant="outline" disabled={!info || busy} onClick={() => void perform(async () => { await terminalClipboard.writeText(mode === "edit" ? `${editAppSkill}\n\n${info!.agentInstructions}` : info!.agentInstructions); setNotice(mode === "edit" ? "Editing and CLI guides copied." : "Agent guide copied.") })}><CopyIcon />{mode === "edit" ? "Copy both guides" : "Copy agent guide"}</Button>
        </div></div>{feedback}
      </DialogPopup>
    </Dialog>
    <Dialog open={Boolean(ending)} onOpenChange={open => { if (!open && !busy) setEnding("") }}>
      <DialogPopup className="max-w-md"><DialogHeader><DialogTitle>Close terminal?</DialogTitle><DialogDescription>This stops its shell and any commands running in it.</DialogDescription></DialogHeader><div className="flex justify-end gap-2 px-6 pb-6"><Button size="sm" variant="ghost" disabled={busy} onClick={() => setEnding("")}>Cancel</Button><Button size="sm" disabled={busy} onClick={() => void closeTab()}>Close terminal</Button></div>{error ? feedback : null}</DialogPopup>
    </Dialog>
  </section>
}
