import { useEffect, useState } from "react"
import { money, runpodApi, runpodExtra, RUNPOD_CONSOLE, stateLabel, type RunpodAction } from "@/api/runpod-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"
import { CloudEnvironmentDialog } from "@/components/dialogs/cloud-environment-dialog"
import { WebLink } from "@/components/dialogs/neocloud-ui"
import { terminalClipboard } from "@/lib/terminal-clipboard"

function sshDefaults(hint: string, address: string) {
  const port = hint.match(/-p\s+(\d+)/)
  return { host: address, username: "root", port: port ? Number(port[1]) : 22, identityFile: "" }
}

function Copy({ text, label }: { text: string; label: string }) {
  const [done, setDone] = useState(false)
  const [error, setError] = useState("")
  return <span>
    <Button size="xs" variant="ghost" aria-label={`Copy ${label}`} onClick={() => {
      setError(""); setDone(false)
      void terminalClipboard.writeText(text)
        .then(() => { setDone(true); window.setTimeout(() => setDone(false), 1500) })
        .catch(() => setError("Couldn't copy. Try selecting the text."))
    }}>{done ? "Copied" : "Copy"}</Button>
    {error ? <span role="alert" className="neo-note">{error}</span> : null}
  </span>
}

const samples: Record<string, string> = {
  language: JSON.stringify({ prompt: "Write a haiku about GPUs", sampling_params: { max_tokens: 100 } }, null, 2),
  image: JSON.stringify({ prompt: "a red fox in the snow, photograph" }, null, 2),
  audio: JSON.stringify({ text: "Hello from Yougori" }, null, 2),
  embedding: JSON.stringify({ input: "Hello from Yougori" }, null, 2),
}

const tone = (label: string) => label === "Running" || label === "Ready" ? "good" : label === "Starting" || label === "Stopping" || label === "Deploying" ? "busy" : "idle"

/** Neocloud controls for a node: power, price, links, logs, and for endpoints their API. */
export function NeocloudNodeCard({ environmentId }: { environmentId: string }) {
  const { state, refreshPlatform } = usePlatform()
  const deployment = state?.neocloudDeployments?.[environmentId]
  const environment = state?.environments.find(e => e.id === environmentId)
  const [busy, setBusy] = useState<RunpodAction | "">("")
  const [error, setError] = useState("")
  const [confirmation, setConfirmation] = useState("")
  const [links, setLinks] = useState<{ links: { name: string; port: number; url: string }[]; console: string } | null>(null)
  const [logs, setLogs] = useState<{ source: string; line: string }[] | null>(null)
  const [configure, setConfigure] = useState(false)
  const extra = runpodExtra(deployment)
  const endpoint = deployment?.product === "serverless"
  const label = deployment ? stateLabel(deployment.state, deployment.product) : ""
  useEffect(() => {
    if (!deployment?.resourceId || endpoint) return
    let alive = true
    void runpodApi.links(environmentId).then(l => { if (alive) setLinks(l) }).catch(() => undefined)
    return () => { alive = false }
  }, [deployment?.resourceId, endpoint, environmentId])
  // Opening the details refreshes the state; a starting pod keeps being followed until it connects.
  useEffect(() => {
    if (!deployment?.resourceId || deployment.state === "Deleted") return
    void runpodApi.action(environmentId, "inspect").then(() => refreshPlatform()).catch(() => undefined)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [environmentId])
  if (!deployment || !environment) return null

  const perform = async (action: RunpodAction) => {
    if (busy) return
    setBusy(action); setError("")
    try { await runpodApi.action(environmentId, action, action === "delete" ? confirmation : undefined); await refreshPlatform() }
    catch (e) { setError(String(e instanceof Error ? e.message : e)); await refreshPlatform().catch(() => undefined) }
    finally { setBusy("") }
  }
  const showLogs = async () => {
    setLogs([])
    try { setLogs(await runpodApi.logs(environmentId)) } catch (e) { setLogs([{ source: "yougori", line: String(e) }]) }
  }
  const deleted = deployment.state === "Deleted"
  const stopped = label === "Stopped" || label === "Paused"
  const moving = label === "Starting" || label === "Stopping" || label === "Deploying"
  const title = endpoint ? extra.title ?? "Serverless endpoint" : extra.compute === "cpu" ? "CPU pod" : `${extra.gpuCount ?? 1} × ${extra.gpuId?.replace(/^NVIDIA (GeForce )?/, "") ?? "GPU"}`

  return <section aria-label="Neocloud" className="neo-card">
    <div className="neo-card-head">
      <div>
        <p className="neo-h3">{endpoint ? "Neocloud endpoint" : "Neocloud pod"}</p>
        <h3 className="neo-h2" style={{ fontSize: 17, marginTop: 2 }}>{title}</h3>
        <p className="neo-status" data-tone={tone(label)} role="status">{label}{!endpoint && extra.hourlyUsd && !stopped && !deleted ? ` · ${money(extra.hourlyUsd)}/hr` : ""}</p>
      </div>
      {!deleted && deployment.resourceId ? <div className="neo-row" style={{ gap: 6 }}>
        {stopped ? <Button size="sm" loading={busy === "start"} disabled={Boolean(busy)} onClick={() => void perform("start")}>{endpoint ? "Resume" : "Start pod"}</Button> : null}
        {!stopped && !moving ? <Button size="sm" variant="outline" loading={busy === "stop"} disabled={Boolean(busy)} onClick={() => void perform("stop")}>{endpoint ? "Pause" : "Stop pod"}</Button> : null}
        {!endpoint && label === "Running" ? <Button size="sm" variant="ghost" loading={busy === "restart"} disabled={Boolean(busy)} onClick={() => void perform("restart")}>Restart</Button> : null}
        <Button size="sm" variant="ghost" loading={busy === "inspect"} disabled={Boolean(busy)} onClick={() => void perform("inspect")}>Refresh</Button>
      </div> : null}
    </div>

    {!deployment.resourceId && !deleted ? <div className="neo-panel">
      <p className="neo-note">Neocloud did not confirm this {endpoint ? "endpoint" : "pod"} was created, so Yougori has no ID for it and cannot stop or delete it from here. Choose Check again to look for it by name: if it is in your Neocloud account, it is attached here. If your account has no such {endpoint ? "endpoint" : "pod"}, type {deployment.name} to confirm, and this node can then be removed.</p>
      <span className="neo-row">
        <Button size="sm" loading={busy === "inspect"} disabled={Boolean(busy)} onClick={() => void perform("inspect")}>Check again</Button>
        <Input className="neo-input" aria-label={`Name to confirm there is no such ${endpoint ? "endpoint" : "pod"}`} value={confirmation} onChange={e => setConfirmation(e.target.value)} />
        <Button size="sm" variant="destructive" disabled={Boolean(busy) || confirmation !== deployment.name} loading={busy === "delete"} onClick={() => void perform("delete")}>Mark as not created</Button>
      </span>
    </div> : null}

    {!endpoint && !deleted && deployment.resourceId ? <>
      <div className="neo-card-grid">
        {extra.compute !== "cpu" ? <div className="neo-stat"><small>GPU</small><strong>{title}</strong></div> : null}
        <div className="neo-stat"><small>Price</small><strong>{extra.hourlyUsd ? `${money(extra.hourlyUsd)}/hr` : "Shown once running"}</strong></div>
        {extra.cloud ? <div className="neo-stat"><small>Cloud</small><strong>{extra.cloud === "secure" ? "Secure" : "Community"}</strong></div> : null}
        <div className="neo-stat"><small>Location</small><strong>{deployment.location || "Anywhere"}</strong></div>
        <div className="neo-stat"><small>Saved files</small><strong>{extra.networkVolumeId ? "Network volume" : extra.volumeGb ? `${extra.volumeGb} GB at ${extra.mountPath ?? "/workspace"}` : "None"}</strong></div>
      </div>
      <p className="neo-note">
        {extra.sshReady ? <>Terminal and files are ready. Choose <strong>Open</strong> below.</>
          : label === "Starting" ? `Starting${extra.statusReason ? ` (${extra.statusReason.replace(/_/g, " ").toLowerCase()})` : ""}. Yougori connects the terminal and files by itself as soon as the pod answers; large software can take a few minutes.`
          : stopped ? `Stopped. ${extra.volumeGb ? `The ${extra.volumeGb} GB saved volume is kept and costs a little each month; ` : ""}the system disk was cleared.` : null}
      </p>
      {extra.sshNote ? <p className="neo-note">{extra.sshNote} <button type="button" className="neo-link" onClick={() => setConfigure(true)}>Set up the connection yourself</button></p> : null}
      <p className="neo-links">
        {links && label === "Running" ? links.links.map(l => <WebLink key={l.port} url={l.url}>{l.name === "Jupyter Notebook" ? "Open Jupyter" : `Open ${l.name}`}</WebLink>) : null}
        <WebLink url={links?.console ?? `${RUNPOD_CONSOLE}/pods`}>Open in the console</WebLink>
      </p>
    </> : null}

    {endpoint && !deleted && deployment.resourceId ? <EndpointDetails environmentId={environmentId} category={extra.category ?? ""} /> : null}

    {!deleted && deployment.resourceId ? <details className="neo-details" onToggle={event => { if ((event.target as HTMLDetailsElement).open && logs === null) void showLogs() }}>
      <summary>Logs</summary>
      <div>
        <pre className="neo-code">{logs === null || !logs.length ? (logs === null ? "" : "No log lines yet.") : logs.map(l => `${l.source === "system" ? "[platform] " : ""}${l.line}`).join("\n")}</pre>
        <span><Button size="xs" variant="ghost" onClick={() => void showLogs()}>Reload</Button></span>
      </div>
    </details> : null}

    {!deleted && deployment.resourceId ? <details className="neo-details">
      <summary>Delete</summary>
      <div>
        <p className="neo-note">{endpoint ? "This deletes the endpoint and its API address." : "This deletes the pod and its saved volume, with every file on them. Network volumes are kept."} Type {deployment.name} to confirm.</p>
        <span className="neo-row"><Input className="neo-input" aria-label="Name to confirm deletion" value={confirmation} onChange={e => setConfirmation(e.target.value)} /><Button size="sm" variant="destructive" disabled={Boolean(busy) || confirmation !== deployment.name} loading={busy === "delete"} onClick={() => void perform("delete")}>Delete</Button></span>
      </div>
    </details> : deleted ? <p className="neo-note">{deployment.resourceId ? "Deleted." : "Nothing was created."} You can remove this node.</p> : null}

    {error || deployment.lastError ? <p role="alert" className="neo-error" style={{ whiteSpace: "pre-wrap" }}>{error || deployment.lastError}</p> : null}
    {configure ? <CloudEnvironmentDialog key={environmentId} open={configure} onOpenChange={value => { setConfigure(value); if (!value) void refreshPlatform() }} environmentId={environmentId} initialProfile={{ name: environment.name, vendor: "other", ...sshDefaults(deployment.sshHint, deployment.address) }} /> : null}
  </section>
}

function EndpointDetails({ environmentId, category }: { environmentId: string; category: string }) {
  const { state } = usePlatform()
  const extra = runpodExtra(state?.neocloudDeployments?.[environmentId])
  const [input, setInput] = useState(samples[category] ?? JSON.stringify({ prompt: "Hello" }, null, 2))
  const [sending, setSending] = useState(false)
  const [answer, setAnswer] = useState("")
  const urls = extra.urls
  const workers = extra.health?.workers ?? {}
  const jobs = extra.health?.jobs ?? {}
  const busyWorkers = Object.entries(workers).filter(([, n]) => n).map(([k, n]) => `${n} ${k}`).join(", ")
  const send = async () => {
    let parsed: Record<string, unknown>
    try { parsed = JSON.parse(input) as Record<string, unknown> } catch { setAnswer("The request is not valid JSON."); return }
    setSending(true); setAnswer("")
    try {
      const result = await runpodApi.runEndpoint(environmentId, parsed)
      setAnswer(JSON.stringify(result.job.output ?? result.job, null, 2))
    } catch (e) { setAnswer(String(e instanceof Error ? e.message : e)) }
    finally { setSending(false) }
  }
  const curl = urls ? `curl -X POST ${urls.runsync} \\\n  -H "Authorization: Bearer $API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"input": ${input.replace(/\s+/g, " ")}}'` : ""
  return <>
    <div className="neo-card-grid">
      <div className="neo-stat"><small>Workers</small><strong>Up to {extra.workersMax ?? "?"}{extra.workersMin ? `, ${extra.workersMin} always on` : ""}</strong></div>
      <div className="neo-stat"><small>Busy now</small><strong>{busyWorkers || "None"}</strong></div>
      <div className="neo-stat"><small>Stays ready</small><strong>{extra.idleTimeout ?? 5} s after a request</strong></div>
      {jobs.completed ? <div className="neo-stat"><small>Answered</small><strong>{jobs.completed} requests</strong></div> : null}
    </div>
    {urls ? <div className="neo-stack" style={{ gap: 6 }}>
      {([["Run and wait for the answer", urls.runsync], ["Queue a job", urls.run], ...(urls.openai ? [["OpenAI-compatible base URL", urls.openai]] : [])] as [string, string][]).map(([name, url]) =>
        <div key={name} className="neo-url"><span><small>{name}</small><code>{url}</code></span><Copy text={url} label={name} /></div>)}
      <p className="neo-note">Send your API key as a Bearer token. <WebLink url={`${RUNPOD_CONSOLE}/user/settings`}>API keys</WebLink></p>
    </div> : null}
    <details className="neo-details" open>
      <summary>Try it</summary>
      <div>
        <Textarea aria-label="Request input (JSON)" rows={5} value={input} spellCheck={false} className="font-mono text-[11px]" onChange={e => setInput(e.target.value)} />
        <span className="neo-row"><Button size="sm" loading={sending} disabled={sending} onClick={() => void send()}>Send request</Button><span className="neo-note">The first request can take a minute while a worker starts.</span></span>
        {answer ? <pre className="neo-code">{answer}</pre> : null}
        {curl ? <div className="neo-row" style={{ alignItems: "flex-start", flexWrap: "nowrap" }}><pre className="neo-code" style={{ flex: 1 }}>{curl}</pre><Copy text={curl} label="curl command" /></div> : null}
      </div>
    </details>
  </>
}
