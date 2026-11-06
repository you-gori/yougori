import { useCallback, useEffect, useId, useState } from "react"
import { platformApi } from "@/api/platform-api"
import { sandboxVmApi, visibleText, type RemoteVmRun, type SandboxSummary } from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"

const message = (error: unknown) => error instanceof Error ? error.message : String(error)
const inputClass = "min-w-0 rounded border px-2 py-1 text-xs"

/** Same VM workspace, existing SSH connections, and actual engine-owned runs. */
export function RemoteVmPanel({ parents }: { parents: SandboxSummary[] }) {
  const [open, setOpen] = useState(false)
  const [connections, setConnections] = useState<{ id: string; name: string }[]>([])
  const [runs, setRuns] = useState<RemoteVmRun[]>([])
  const [historyOpen, setHistoryOpen] = useState(false)
  const [cursor, setCursor] = useState<string | undefined>()
  const [nextAfter, setNextAfter] = useState<string | null>(null)
  const [archivedCount, setArchivedCount] = useState(0)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [connection, setConnection] = useState("")
  const [parent, setParent] = useState("")
  const [program, setProgram] = useState("/opt/yougori/yougori-engine")
  const [endpoint, setEndpoint] = useState("")
  const [hash, setHash] = useState("")
  const [pin, setPin] = useState("")
  const [memory, setMemory] = useState("1024")
  const id = useId()
  const refresh = useCallback(async () => {
    const answer = historyOpen ? await sandboxVmApi.remoteHistory(cursor) : await sandboxVmApi.remoteStatus()
    if (!("runs" in answer)) throw new Error("Unexpected remote status response.")
    setRuns(answer.runs)
    setArchivedCount(answer.archived_count ?? 0)
    setNextAfter(answer.next_after ?? null)
  }, [historyOpen, cursor])
  useEffect(() => {
    if (!open) return
    let active = true
    let polling = false
    void platformApi.getState().then(state => {
      if (active) setConnections(state.environments.filter(environment => environment.provider === "cloudSsh"))
    }).catch(reason => { if (active) setError(message(reason)) })
    const poll = async () => {
      if (polling) return
      polling = true
      try {
        const answer = historyOpen ? await sandboxVmApi.remoteHistory(cursor) : await sandboxVmApi.remoteStatus()
        if (active && "runs" in answer) {
          setRuns(answer.runs)
          setArchivedCount(answer.archived_count ?? 0)
          setNextAfter(answer.next_after ?? null)
        }
      } catch (reason) { if (active) setError(message(reason)) }
      finally { polling = false }
    }
    void poll()
    const timer = setInterval(() => { void poll() }, 2000)
    return () => { active = false; clearInterval(timer) }
  }, [open, historyOpen, cursor])
  const act = async (action: () => Promise<unknown>) => {
    if (busy) return
    setBusy(true); setError("")
    try { await action(); await refresh() }
    catch (reason) { setError(message(reason)) }
    finally { setBusy(false) }
  }
  const ready = parents.filter(item => item.phase === "ready" && item.state === "running")
  const valid = !!connection && ready.some(item => item.sandbox === parent) && !!program.trim() && !!endpoint.trim()
    && /^[a-fA-F0-9]{64}$/.test(hash.trim()) && Number.isInteger(Number(memory)) && Number(memory) >= 320 && Number(memory) <= 65536
  return <details className="space-y-3 rounded-md border px-3 py-2" onToggle={event => setOpen(event.currentTarget.open)}>
    <summary className="cursor-pointer text-xs font-medium">Remote VM sandboxes</summary>
    {open ? <>
      <p className="text-xs text-muted-foreground">Run a VM on an existing SSH server. Its parent VM must keep running here; the engine maintains the connection when you close this view. Stopping a run leaves the server running and does not change its billing.</p>
      <fieldset disabled={busy} className="grid grid-cols-[auto_minmax(0,1fr)] items-center gap-2 text-xs">
        <label htmlFor={`${id}-connection`}>SSH connection</label>
        <select id={`${id}-connection`} className={inputClass} value={connection} onChange={event => setConnection(event.target.value)}>
          <option value="">Choose a saved connection</option>
          {connections.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
        </select>
        <label htmlFor={`${id}-parent`}>Parent VM on this computer</label>
        <select id={`${id}-parent`} className={inputClass} value={parent} onChange={event => setParent(event.target.value)}>
          <option value="">Choose a running VM</option>
          {ready.map(item => <option key={item.sandbox} value={item.sandbox}>{item.sandbox}</option>)}
        </select>
        <label htmlFor={`${id}-program`}>Engine path on the server</label>
        <input id={`${id}-program`} className={inputClass} value={program} onChange={event => setProgram(event.target.value)} />
        <label htmlFor={`${id}-endpoint`}>Server engine endpoint</label>
        <input id={`${id}-endpoint`} className={inputClass} value={endpoint} onChange={event => setEndpoint(event.target.value)} />
        <label htmlFor={`${id}-hash`}>Server engine SHA-256</label>
        <input id={`${id}-hash`} className={inputClass} value={hash} onChange={event => setHash(event.target.value)} />
        <label htmlFor={`${id}-pin`}>Verified SSH fingerprint</label>
        <input id={`${id}-pin`} className={inputClass} value={pin} placeholder="SHA256:…" onChange={event => setPin(event.target.value)} />
        <label htmlFor={`${id}-memory`}>Reserved server memory (MiB)</label>
        <input id={`${id}-memory`} className={inputClass} type="number" min={320} max={65536} value={memory} onChange={event => setMemory(event.target.value)} />
      </fieldset>
      {!connections.length ? <p className="text-xs text-muted-foreground">Add an SSH server in Connections first. Its owner-only private key and .pub companion remain on this computer.</p> : null}
      {!ready.length ? <p className="text-xs text-muted-foreground">Launch a local parent VM above to authorize the remote run.</p> : null}
      <Button size="xs" disabled={busy || !valid} onClick={() => void act(() => sandboxVmApi.remoteLaunch({
        connection, parent, program: program.trim(), endpoint: endpoint.trim(), engine_sha256: hash.trim(),
        memory_mib: Number(memory), ...(pin.trim() ? { accept_host_key: pin.trim() } : {}),
      }))}>Launch remote VM</Button>
      <Button size="xs" variant="outline" disabled={busy || !connection || !pin.trim()}
        onClick={() => void act(() => sandboxVmApi.remoteTrust(connection, pin.trim()))}>Confirm server key</Button>
      <p className="text-xs text-muted-foreground">For a changed key, stop this server’s remote runs and update its saved connection first. Confirmation permits cleanup of earlier runs; it never resumes their work.</p>
      {error ? <p role="alert" className="text-xs text-destructive">{visibleText(error)}</p> : null}
      <div className="flex flex-wrap items-center gap-2">
        <Button size="xs" variant="outline" disabled={busy} onClick={() => { setCursor(undefined); setHistoryOpen(!historyOpen) }}>
          {historyOpen ? "Show current runs" : `Show archived runs (${archivedCount})`}
        </Button>
        {historyOpen && cursor ? <Button size="xs" variant="outline" disabled={busy} onClick={() => setCursor(undefined)}>First page</Button> : null}
        {historyOpen && nextAfter ? <Button size="xs" variant="outline" disabled={busy} onClick={() => setCursor(nextAfter)}>Next page</Button> : null}
      </div>
      {historyOpen ? <p className="text-xs text-muted-foreground">Archived runs keep their cleanup proofs and cannot run again. Up to 100 are shown per page. The archive keeps at most 4,096 runs or 32 MiB; it never automatically deletes replay protection.</p> : null}
      {runs.map(run => <RemoteRun key={run.run} run={run} busy={busy} act={act} />)}
    </> : null}
  </details>
}

function RemoteRun({ run, busy, act }: { run: RemoteVmRun; busy: boolean; act(action: () => Promise<unknown>): Promise<void> }) {
  const [script, setScript] = useState("")
  const [command, setCommand] = useState<number | null>(null)
  const [output, setOutput] = useState("")
  const [uncertain, setUncertain] = useState(false)
  const terminal = run.phase === "ended" || run.phase === "creation_cancelled"
  const start = async () => {
    const input = script; setScript(""); setOutput("")
    try { const result = await sandboxVmApi.remoteStart(run.run, input); setCommand(result.command) }
    catch (error) { setUncertain(true); throw error }
  }
  const read = async () => {
    if (command === null) return
    try {
      const result = await sandboxVmApi.remoteOutcome(run.run, command)
      if (result.state === "running") { setOutput("Command is still running."); return }
      if (result.source !== "guest_report" || !result.outcome || !/^(?:[0-9a-fA-F]{2})*$/.test(result.outcome.output)) throw new Error("Invalid guest output response.")
      const bytes = Uint8Array.from(result.outcome.output.match(/.{2}/g) ?? [], value => parseInt(value, 16))
      setOutput(`Exit: ${result.outcome.exit_code ?? result.outcome.end.end}\n${visibleText(new TextDecoder().decode(bytes))}`)
      setCommand(null)
    } catch (error) { setUncertain(true); throw error }
  }
  return <article className="space-y-2 rounded border p-3 text-xs">
    <p className="font-medium">{visibleText(run.host)}:{run.port} · {run.phase.replaceAll("_", " ")}</p>
    <p className="break-all font-mono text-muted-foreground">{run.run}</p>
    {run.archived ? <p className="text-muted-foreground">Archived · original identity and cleanup proof retained</p> : null}
    {run.detail ? <p>{visibleText(run.detail)}</p> : null}
    {run.phase === "ready" ? <>
      <label className="block">Guest shell script<textarea className={`${inputClass} mt-1 block h-20 w-full font-mono`} value={script} onChange={event => setScript(event.target.value)} /></label>
      <Button size="xs" disabled={busy || !script.trim() || command !== null || uncertain} onClick={() => void act(start)}>Run script once</Button>
      {command !== null ? <span className="ml-2 inline-flex gap-2">
        <Button size="xs" variant="outline" disabled={busy || uncertain} onClick={() => void act(read)}>Read command {command}</Button>
        <Button size="xs" variant="outline" disabled={busy} onClick={() => void act(() => sandboxVmApi.remoteCancel(run.run, command))}>Cancel command</Button>
      </span> : null}
    </> : null}
    {uncertain ? <p role="alert">The command outcome is uncertain. It has not been repeated. Check the run status before starting further work.</p> : null}
    {output ? <pre aria-label="Remote guest output" className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-muted p-2">{output}</pre> : null}
    {!terminal ? <Button size="xs" variant="outline" disabled={busy} onClick={() => void act(() => run.phase === "unconfirmed" ? sandboxVmApi.remoteReconcile(run.run) : sandboxVmApi.remoteStop(run.run))}>{run.phase === "unconfirmed" ? "Reconcile cleanup" : "Stop remote run"}</Button> : null}
    {terminal && !run.archived ? <Button size="xs" variant="outline" disabled={busy} onClick={() => void act(() => sandboxVmApi.remoteArchive(run.run))}>Archive ended run</Button> : null}
  </article>
}
