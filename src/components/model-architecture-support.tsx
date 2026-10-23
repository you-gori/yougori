import { useRef, useState } from "react"
import { modelsApi, type ArchitectureAgent, type ArchitectureTask } from "@/api/projects-api"
import { Button } from "@/components/ui/button"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import { workspaceApi } from "@/api/workspace-api"

const agents: [ArchitectureAgent, string][] = [["claude", "Claude Code"], ["codex", "Codex"], ["kilo", "Kilo Code"], ["opencode", "OpenCode"], ["gemini", "Gemini CLI"]]
const docs: Record<ArchitectureAgent,string> = {claude:"https://code.claude.com/docs/en/setup",codex:"https://developers.openai.com/codex/cli/",kilo:"https://kilo.ai/docs/code-with-ai/platforms/cli",opencode:"https://opencode.ai/docs/",gemini:"https://geminicli.com/docs/get-started/installation/"}
export function ModelArchitectureSupport({ model, quant }: { model: string; quant?: string }) {
  const [expanded, setExpanded] = useState(false)
  const [agent, setAgent] = useState<ArchitectureAgent>("codex")
  const [task, setTask] = useState<ArchitectureTask | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const locked = useRef(false)
  // The saved command is PowerShell syntax on Windows.
  const shell = /Win/i.test(navigator.platform) ? "PowerShell" : "your own terminal"
  const prepare = async () => {
    if (locked.current) return
    locked.current = true; setBusy(true); setError("")
    try { setTask(await modelsApi.supportTask(model, agent, quant)) }
    catch (reason) { setError(String(reason)) }
    finally { locked.current = false; setBusy(false) }
  }
  return <section aria-label="Implement model architecture" className="model-hint">
    {!expanded ? <Button variant="outline" size="sm" onClick={() => setExpanded(true)}>Implement architecture support with AI</Button> : <>
      <p>The agent gets a skill and this checkpoint’s details in a separate workspace. It implements and tests support before you install its build. Your agent account may charge for usage.</p>
      <div className="model-form-actions">
        {/* A saved task is written for one agent, so choosing another clears it. */}
        <label>Coding agent <select aria-label="Coding agent" value={agent} disabled={busy} onChange={event => { setAgent(event.target.value as ArchitectureAgent); setTask(null) }}>{agents.map(([id, name]) => <option key={id} value={id}>{name}</option>)}</select></label>
        {!task ? <Button size="sm" disabled={busy} loading={busy} onClick={() => void prepare()}>Prepare task for {agents.find(([id]) => id === agent)![1]}</Button> : null}
        <Button variant="ghost" size="sm" disabled={busy} onClick={() => setExpanded(false)}>Cancel</Button>
      </div>
      <Button size="xs" variant="ghost" onClick={() => void workspaceApi.openUrl(docs[agent]).catch(reason => setError(String(reason)))}>Agent installation and sign-in</Button>
      {task ? <><p>Task saved at <code>{task.path}</code>. Install and sign in to the selected agent if it is missing, then run the launch command in {shell}.</p><Button size="xs" variant="outline" onClick={() => void terminalClipboard.writeText(task.resumeCommand).catch(reason => setError(String(reason)))}>Copy launch command</Button></> : null}
      {error ? <p role="alert" className="model-error">{error}</p> : null}
    </>}
  </section>
}
