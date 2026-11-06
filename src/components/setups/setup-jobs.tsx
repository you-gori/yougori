import { useCallback, useEffect, useState } from "react"
import { isTauri } from "@tauri-apps/api/core"
import { Button } from "@/components/ui/button"
import type { ResourceView } from "@/api/setups/types"
import { errorText, isUnavailable, setupsApi, type JobAttemptLog, type ModelUsage, type SetupArtifact } from "@/api/setups/setups-api"
import { formatBytesFromGb } from "@/lib/domain"

const formatBytes = (bytes: number) => formatBytesFromGb(bytes / 1024 ** 3)

/** A setup's jobs and what they made, and what its sandboxes print. The same things
 *  `yougori template jobs|artifacts|logs` read; nothing here changes a setup except settling a job
 *  whose outcome nobody knows, which the person does after looking at what it printed. */

const when = (seconds: number | null | undefined) => seconds ? new Date(seconds * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" }) : ""

const UNAVAILABLE = "This build of Yougori can't show that yet."

/** A job of a setup: its state, what its last attempts printed, and, when nobody knows whether it
 *  did its work, the three ways a person can settle it. */
function Job({ setupId, part, moving }: { setupId: string; part: ResourceView; moving: boolean }) {
  const [logs, setLogs] = useState<JobAttemptLog[] | null>(null)
  const [said, setSaid] = useState("")
  const [busy, setBusy] = useState(false)
  const unknown = part.observed === "unknown"
  const read = async () => {
    setBusy(true)
    setSaid("")
    try { setLogs(await setupsApi.jobLogs(setupId, part.resourceId)) }
    catch (reason) { setSaid(isUnavailable(reason) ? UNAVAILABLE : errorText(reason)) }
    finally { setBusy(false) }
  }
  const settle = async (outcome: "succeeded" | "failed" | "run_again") => {
    setBusy(true)
    setSaid("")
    try {
      const { state } = await setupsApi.settleJob(setupId, part.resourceId, outcome)
      setSaid(outcome === "run_again" ? "It will run again." : `Settled: it is ${state} now.`)
    } catch (reason) { setSaid(isUnavailable(reason) ? UNAVAILABLE : errorText(reason)) }
    finally { setBusy(false) }
  }
  return <li>
    <strong>{part.label}</strong>
    <span className="setup-note"> — {unknown ? "nobody knows yet whether it did its work" : part.observed === "running" ? "running or waiting for room" : part.observed === "present" ? "finished" : part.observed === "stopped" ? "ended without finishing" : "not checked yet"}</span>
    <div className="setup-actions">
      <Button size="xs" variant="outline" disabled={busy} onClick={() => void read()}>What it printed</Button>
      {unknown ? <>
        <Button size="xs" variant="outline" disabled={busy || moving} onClick={() => void settle("succeeded")}>It did its work</Button>
        <Button size="xs" variant="outline" disabled={busy || moving} onClick={() => void settle("failed")}>It didn't</Button>
        <Button size="xs" variant="ghost" disabled={busy || moving} onClick={() => void settle("run_again")}>Run it again</Button>
      </> : null}
    </div>
    {said ? <p className="setup-note" role="status">{said}</p> : null}
    {logs ? logs.length ? logs.map(log => <details key={`${log.attempt}-${log.at}`} className="setup-log">
      <summary>Attempt {log.attempt.slice(0, 12)}{log.at ? `, ended ${when(log.at)}` : ""}</summary>
      <pre aria-label={`What attempt ${log.attempt} printed`}>{log.text || "It printed nothing."}</pre>
    </details>) : <p className="setup-note">No attempt has printed anything yet.</p> : null}
  </li>
}

export function SetupJobs({ setupId, parts, moving = false }: { setupId: string; parts: ResourceView[]; moving?: boolean }) {
  const jobs = parts.filter(part => part.kind === "job" && part.owned)
  if (!jobs.length) return null
  return <section aria-label="Jobs">
    <h3 className="setup-panel-title">Jobs</h3>
    <ul className="setup-group-list">{jobs.map(part => <Job key={part.resourceId} setupId={setupId} part={part} moving={moving} />)}</ul>
  </section>
}

/** What the setup's jobs handed back, with a checked copy to a folder of this computer. */
export function SetupArtifacts({ setupId }: { setupId: string }) {
  const [found, setFound] = useState<SetupArtifact[] | null>(null)
  const [said, setSaid] = useState("")
  const [saving, setSaving] = useState<string | null>(null)
  const read = useCallback(async () => {
    try { setFound(await setupsApi.artifacts(setupId)) }
    catch (reason) { setFound([]); setSaid(isUnavailable(reason) ? UNAVAILABLE : errorText(reason)) }
  }, [setupId])
  useEffect(() => { void read() }, [read])
  const save = async (artifact: SetupArtifact) => {
    if (!isTauri()) { setSaid("Saving a result needs Yougori Desktop."); return }
    const { open } = await import("@tauri-apps/plugin-dialog")
    const folder = await open({ directory: true, multiple: false, title: "Choose where to save the result" })
    if (typeof folder !== "string") return
    setSaving(artifact.id)
    setSaid("")
    try {
      const copy = await setupsApi.saveArtifact(setupId, artifact.id, folder)
      setSaid(`Saved ${formatBytes(copy.bytes)} to ${copy.path}. Its checksum matched.`)
    } catch (reason) { setSaid(isUnavailable(reason) ? UNAVAILABLE : errorText(reason)) }
    finally { setSaving(null) }
  }
  if (!found) return null
  return <section aria-label="Results">
    <h3 className="setup-panel-title">Results</h3>
    {found.length ? <ul className="setup-group-list" aria-label="Results its jobs handed back">
      {found.map(artifact => <li key={artifact.id}>
        <strong>{artifact.name}</strong>
        <span className="setup-note"> — {artifact.resource ? `from ${artifact.resource}, ` : ""}{formatBytes(artifact.bytes)}, kept {when(artifact.recordedAt)}</span>
        {artifact.removed ? <span className="setup-note"> · removed by the store's retention{artifact.removedBecause ? `: ${artifact.removedBecause}` : ""}</span>
          : <Button size="xs" variant="outline" disabled={saving !== null} loading={saving === artifact.id} onClick={() => void save(artifact)}>Save…</Button>}
      </li>)}
    </ul> : <p className="setup-note">No job has handed anything back yet.</p>}
    {said ? <p className="setup-note" role="status">{said}</p> : null}
  </section>
}

/** What each of the setup's own sandboxes printed lately, one at a time, on request. */
export function SetupSandboxLogs({ setupId, parts }: { setupId: string; parts: ResourceView[] }) {
  const sandboxes = parts.filter(part => part.kind === "environment" && part.owned)
  const [open, setOpen] = useState<string | null>(null)
  const [text, setText] = useState<{ text: string; truncated: boolean } | null>(null)
  const [said, setSaid] = useState("")
  const [busy, setBusy] = useState(false)
  const show = async (resource: string) => {
    setOpen(resource)
    setBusy(true)
    setSaid("")
    setText(null)
    try { setText(await setupsApi.sandboxLogs(setupId, resource)) }
    catch (reason) { setSaid(isUnavailable(reason) ? UNAVAILABLE : errorText(reason)) }
    finally { setBusy(false) }
  }
  if (!sandboxes.length) return null
  return <section aria-label="Sandbox logs">
    <h3 className="setup-panel-title">Logs</h3>
    <div className="setup-actions">
      {sandboxes.map(part => <Button key={part.resourceId} size="xs" variant={open === part.resourceId ? "default" : "outline"} disabled={busy} onClick={() => void show(part.resourceId)}>{part.label}</Button>)}
      {open ? <Button size="xs" variant="ghost" disabled={busy} onClick={() => void show(open)}>Read again</Button> : null}
    </div>
    {said ? <p className="setup-note" role="status">{said}</p> : null}
    {text ? <>
      {text.truncated ? <p className="setup-note">Only the end is shown.</p> : null}
      <pre className="setup-log" aria-label={`What ${open} printed`}>{text.text || "It has printed nothing yet."}</pre>
    </> : null}
  </section>
}

/** What the setup's cloud models cost this month, as their gateway counts it, against its budget. */
export function SetupModelUsage({ setupId }: { setupId: string }) {
  const [found, setFound] = useState<ModelUsage[] | null>(null)
  const [said, setSaid] = useState("")
  useEffect(() => {
    let live = true
    setupsApi.usage(setupId)
      .then(models => { if (live) setFound(models) })
      .catch(reason => { if (live) { setFound([]); setSaid(isUnavailable(reason) ? UNAVAILABLE : errorText(reason)) } })
    return () => { live = false }
  }, [setupId])
  if (!found) return null
  return <section aria-label="Model use">
    <h3 className="setup-panel-title">This month</h3>
    {found.length ? <ul className="setup-group-list">{found.map(model => <li key={model.resource}>
      <strong>{model.model || model.resource}</strong>
      {model.error ? <span className="setup-note"> — {model.error}</span> : <span className="setup-note"> — ${(model.spentUsd ?? 0).toFixed(4)}{model.budgetUsd ? ` of $${model.budgetUsd.toFixed(2)}` : ""} spent, {model.requests ?? 0} requests, {model.refused ?? 0} refused{model.freeOnly ? ", free models only" : ""}</span>}
      {model.budgetUsd && (model.spentUsd ?? 0) >= model.budgetUsd * 0.8 ? <p className="setup-note" role="status">It is close to its budget. A request that could pass it is refused until next month.</p> : null}
    </li>)}</ul> : <p className="setup-note">This setup uses no hosted model.</p>}
    {said ? <p className="setup-note" role="status">{said}</p> : null}
  </section>
}
