import { lazy, Suspense, useRef, useState } from "react"
import { modelsApi, type ArchitectureAgent, type ArchitectureTask } from "@/api/projects-api"
import { hostTerminalApi } from "@/api/host-terminal-api"
import type { HostTab, HostShellState } from "@/components/host-terminal-canvas"
import { Button } from "@/components/ui/button"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import { workspaceApi } from "@/api/workspace-api"

const agents: [ArchitectureAgent, string][] = [["claude", "Claude Code"], ["codex", "Codex"], ["kilo", "Kilo Code"], ["opencode", "OpenCode"], ["gemini", "Gemini CLI"]]
const AgentTerminal = lazy(async () => ({ default: (await import("@/components/host-terminal-canvas")).HostTerminalCanvas }))
const docs: Record<ArchitectureAgent,string> = {claude:"https://code.claude.com/docs/en/setup",codex:"https://developers.openai.com/codex/cli/",kilo:"https://kilo.ai/docs/code-with-ai/platforms/cli",opencode:"https://opencode.ai/docs/",gemini:"https://geminicli.com/docs/get-started/installation/"}
export function ModelArchitectureSupport({ model, quant, active }: { model: string; quant?: string; active: boolean }) {
  const [expanded, setExpanded] = useState(false)
  const [agent, setAgent] = useState<ArchitectureAgent>("codex")
  const [task, setTask] = useState<ArchitectureTask | null>(null)
  const [tab, setTab] = useState<HostTab | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const locked = useRef(false)
  const start = async () => {
    if (locked.current || tab) return
    locked.current = true; setBusy(true); setError("")
    try {
      const info = await hostTerminalApi.info()
      if (info.elevated) throw new Error("Reopen Yougori normally to start a coding agent.")
      if (info.sessions.length >= info.maxSessions) throw new Error("Close a host terminal before opening the coding agent.")
      const result = await modelsApi.supportTask(model, agent, quant)
      setTask(result)
      setTab({ id: `host-edit-architecture-${crypto.randomUUID()}`, cwd: result.path, name: agents.find(([id]) => id === agent)![1], command: result.launchCommand, state: "starting" })
    } catch (reason) { setError(String(reason)) }
    finally { locked.current = false; setBusy(false) }
  }
  const stop = async () => {
    if (!tab || locked.current) return
    locked.current = true; setBusy(true); setError("")
    try { await hostTerminalApi.terminal({ sessionId: tab.id, action: "close" }); setTab(null) }
    catch (reason) { setError(String(reason)) }
    finally { locked.current = false; setBusy(false) }
  }
  const onState = (_id: string, state: HostShellState) => setTab(current => current ? { ...current, state } : current)
  return <section aria-label="Implement model architecture" className="model-hint">
    {!expanded ? <Button variant="outline" size="sm" onClick={() => setExpanded(true)}>Implement architecture support with AI</Button> : <>
      <p>The agent gets a skill and this checkpoint’s details in a separate workspace. It implements and tests support before you install its build. Your agent account may charge for usage.</p>
      <div className="model-form-actions">
        <label>Coding agent <select aria-label="Coding agent" value={agent} disabled={busy || Boolean(tab)} onChange={event => setAgent(event.target.value as ArchitectureAgent)}>{agents.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>
        {!tab ? <><Button size="sm" disabled={busy} loading={busy} onClick={() => void start()}>Start {agents.find(([id]) => id === agent)![1]}</Button><Button variant="ghost" size="sm" disabled={busy} onClick={() => setExpanded(false)}>Cancel</Button></> : <Button variant="outline" size="sm" disabled={busy} onClick={() => void stop()}>Stop coding agent</Button>}
      </div>
      <Button size="xs" variant="ghost" onClick={() => void workspaceApi.openUrl(docs[agent]).catch(reason => setError(String(reason)))}>Agent installation and sign-in</Button>
      {task ? <><p>Task saved at <code>{task.path}</code>. Install and sign in to the selected agent if it is missing. Closing this dialog keeps its terminal available in Edit the App.</p><Button size="xs" variant="outline" onClick={() => void terminalClipboard.writeText(task.resumeCommand).catch(reason => setError(String(reason)))}>Copy launch command</Button></> : null}
      {tab ? <div className="host-terminal-pane" style={{ height: 380, minHeight: 280 }}><Suspense fallback={<p role="status">Opening agent terminal…</p>}><AgentTerminal tab={tab} active={active} onState={onState} onControls={() => undefined} /></Suspense></div> : null}
      {error ? <p role="alert" className="model-error">{error}</p> : null}
    </>}
  </section>
}
