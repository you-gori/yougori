import { useId, useState } from "react"
import { HostAccessBox } from "./host-access-box"
import {
  sandboxVmApi, visibleText,
  type ExecResult, type NormalizedResult, type NormalizeFormat, type Promotion, type PublicationAudience,
  type DrillReport, type PublishResult, type SandboxConnections, type SandboxPublications, type SandboxVmStatus, type WorkspaceReview,
  type WorkspaceSummary,
} from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"
import { workspaceApi } from "@/api/workspace-api"
import { FLAG, stateText } from "./workspace-text"
import { useSandboxVms } from "./sandbox-vm-context"
import { RemoteVmPanel } from "./remote-vm-panel"
import { GridHostingBox } from "./grid-hosting-box"
import { TemplateCodeGuide } from "@/components/setups/template-code-guide"

function Problem({ text }: { text: string }) {
  return <p role="alert" className="text-xs text-destructive">{text}</p>
}

function errorText(reason: unknown) {
  return reason instanceof Error ? reason.message : String(reason)
}

/** Detail controls for an environment selected in the shared workspace list. */
export function SandboxVmPanel({ sandbox }: { sandbox?: string }) {
  const { status, error, refresh } = useSandboxVms()
  const [busy, setBusy] = useState("")
  const [problem, setProblem] = useState("")
  const act = async (label: string, action: () => Promise<unknown>) => {
    if (busy) return
    setBusy(label); setProblem("")
    try { await action() }
    catch (reason) { setProblem(errorText(reason)) }
    finally { setBusy(""); void refresh() }
  }
  return <div aria-busy={busy !== ""} className="space-y-4">
    {error || problem ? <Problem text={problem || error} /> : null}
    {busy ? <p role="status" className="text-xs text-muted-foreground">{busy}…</p> : null}
    <Button size="xs" variant="outline" onClick={() => void refresh()}>Refresh environment</Button>
    {status ? <>
      <SandboxList status={status} selected={sandbox} disabled={busy !== ""} onStop={id => act("Stopping the sandbox", () => sandboxVmApi.stop(id))} onChanged={() => void refresh()} />
      <WorkspaceList workspaces={status.workspaces.filter(workspace => !sandbox || workspace.sandbox === sandbox)} disabled={busy !== ""} onDiscard={id => act("Discarding the workspace", () => sandboxVmApi.discard(id))} onChanged={() => void refresh()} />
      <TemplateCodeGuide />
      <details><summary className="cursor-pointer text-xs font-medium">Advanced tools</summary>
        <ConnectionDrillBox disabled={busy !== ""} onChanged={() => void refresh()} />
        <RemoteVmPanel parents={status.sandboxes} />
      </details>
    </> : !error ? <p role="status">Reading the environment…</p> : null}
  </div>
}

function SupervisorLine({ status, running }: { status: SandboxVmStatus; running: number }) {
  const supervisor = status.supervisor
  if (!supervisor || !running) return null
  if (!supervisor.running) return <p className="text-xs text-muted-foreground">The lifetime supervisor is not running; Yougori starts another at its next check.</p>
  const held = supervisor.held.length
  return <p className="text-xs text-muted-foreground">A separate lifetime supervisor holds {held} VM{held === 1 ? "" : "s"}: it ends {held === 1 ? "it" : "them"} if Yougori quits or stops answering for two minutes.</p>
}

function SandboxList({ status, selected, disabled, onStop, onChanged }: { status: SandboxVmStatus; selected?: string; disabled: boolean; onStop(sandbox: string): void; onChanged(): void }) {
  const running = status.sandboxes.filter(sandbox => sandbox.phase === "ready")
  if (!running.some(vm => !selected || vm.sandbox === selected)) return <p className="text-xs text-muted-foreground">This Sandbox VM is stopped. Its saved workspace can still be reviewed below.</p>
  return <>
    <SupervisorLine status={status} running={running.length} />
    <ul aria-label="Running VM sandboxes" className="space-y-2">
    {running.filter(sandbox => !selected || sandbox.sandbox === selected).map(sandbox => {
      const publications = status.publications?.[sandbox.sandbox]
      const connections = status.connections?.[sandbox.sandbox]
      const image = status.images?.find(image => image.sandbox === sandbox.sandbox)
      const others = running
        .filter(other => other.sandbox !== sandbox.sandbox)
        .map(other => ({ sandbox: other.sandbox, services: (status.publications?.[other.sandbox]?.declared ?? []).map(port => port.service) }))
        .filter(other => other.services.length)
      return <li key={sandbox.sandbox} className="space-y-1 rounded-md border px-3 py-2 text-xs">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <span className="font-mono">{sandbox.sandbox}</span>
          <Button type="button" size="xs" variant="outline" disabled={disabled} onClick={() => onStop(sandbox.sandbox)}>Stop</Button>
        </div>
        <CommandBox sandbox={sandbox.sandbox} />
        <GridHostingBox sandbox={sandbox.sandbox} disabled={disabled} />
        <HostAccessBox sandbox={sandbox.sandbox} />
        {image ? <div className="space-y-1 rounded border p-2">
          <p>Image <span className="font-mono">{visibleText(image.id.slice(0, 23))}</span> · {image.command !== null ? "Entrypoint running" : image.outcome ? `Entrypoint ended (exit ${image.outcome.exit_code ?? "unavailable"})` : "No entrypoint"}</p>
          {image.outcome ? <pre className="max-h-48 overflow-auto whitespace-pre-wrap">{visibleText(image.outcome.output_text)}</pre> : null}
          <Button type="button" size="xs" variant="ghost" onClick={onChanged}>Refresh image status</Button>
        </div> : null}
        {publications ? <PublicationsBox sandbox={sandbox.sandbox} publications={publications} disabled={disabled} onChanged={onChanged} /> : null}
        {connections ? <ConnectionsBox sandbox={sandbox.sandbox} connections={connections} others={others} disabled={disabled} onChanged={onChanged} /> : null}
      </li>
    })}
    </ul>
  </>
}

const STATE: Record<string, string> = {
  active: "served",
  response_budget_spent: "its budget is spent",
  expired: "expired",
  withdrawn: "withdrawn",
  authority_ended: "ended with the sandbox",
  policy_changed: "ended: the sandbox's policy changed",
  grant_revoked: "ended: its grant was revoked",
}

/** A running sandbox's declared guest services and their publications (M14): served on this
 *  computer's loopback only, to its owner (an address carrying a token, shown once) or, after a
 *  confirmation, to anyone on this computer; each answer under a sandboxed policy. */
export function PublicationsBox({ sandbox, publications, disabled, onChanged }: { sandbox: string; publications: SandboxPublications; disabled: boolean; onChanged(): void }) {
  const [problem, setProblem] = useState("")
  const [working, setWorking] = useState(false)
  const [opened, setOpened] = useState<PublishResult | null>(null)
  const [confirmPublic, setConfirmPublic] = useState<string | null>(null)
  const act = async (action: () => Promise<unknown>) => {
    setWorking(true)
    setProblem("")
    try {
      await action()
    } catch (reason) {
      setProblem(errorText(reason))
    } finally {
      setWorking(false)
      onChanged()
    }
  }
  const publish = (service: string, audience: PublicationAudience) => act(async () => {
    setConfirmPublic(null)
    setOpened(await sandboxVmApi.publish(sandbox, service, audience))
  })
  const live = publications.publications.filter(publication => publication.state !== "withdrawn")
  return <div role="group" aria-label="Published services" className="space-y-1 rounded border px-2 py-1">
    <p className="font-medium">Guest services</p>
    {publications.declared.map(port => <div key={port.service} className="flex flex-wrap items-center gap-2">
      <span className="font-mono">{port.service}</span>
      <span className="text-muted-foreground">guest port {port.port}</span>
      <Button type="button" size="xs" variant="outline" disabled={disabled || working} onClick={() => void publish(port.service, "owner")}>Publish to me</Button>
      {confirmPublic === port.service
        ? <>
          <span className="text-amber-700 dark:text-amber-400">Anyone and anything on this computer can open it.</span>
          <Button type="button" size="xs" variant="destructive" disabled={disabled || working} onClick={() => void publish(port.service, "public")}>Publish to anyone on this computer</Button>
          <Button type="button" size="xs" variant="ghost" onClick={() => setConfirmPublic(null)}>Back</Button>
        </>
        : <Button type="button" size="xs" variant="ghost" disabled={disabled || working} onClick={() => setConfirmPublic(port.service)}>Publish to anyone…</Button>}
    </div>)}
    {opened ? <div aria-label="Publication address" className="space-y-1">
      <p>{opened.audience === "owner" ? "Its address carries its key: whoever has it can open the preview until it ends." : "Anyone on this computer can open it until it ends."}</p>
      <div className="flex flex-wrap items-center gap-2">
        <span className="font-mono">{visibleText(opened.url)}</span>
        <Button type="button" size="xs" variant="outline" onClick={() => void workspaceApi.openUrl(opened.url).catch(reason => setProblem(errorText(reason)))}>Open</Button>
        <Button type="button" size="xs" variant="ghost" onClick={() => setOpened(null)}>Hide</Button>
      </div>
    </div> : null}
    {live.length ? <ul aria-label="Publications" className="space-y-1">
      {live.map(publication => <li key={publication.publication} className="flex flex-wrap items-center gap-2">
        <span className="font-mono">{publication.service}</span>
        <span>{publication.audience === "owner" ? "you only, with its address" : "anyone on this computer"}</span>
        <span className="text-muted-foreground">{STATE[publication.state] ?? publication.state} · {publication.response_budget.used_bytes} of {publication.response_budget.limit_bytes} bytes answered · {Math.ceil(publication.expires_in_seconds / 60)} min left</span>
        {publication.state === "active" ? <Button type="button" size="xs" variant="ghost" disabled={disabled || working} onClick={() => void act(() => sandboxVmApi.withdraw(sandbox, publication.publication))}>Withdraw</Button> : null}
      </li>)}
    </ul> : null}
    <p className="text-muted-foreground">Answered so far: {publications.released_bytes} bytes; a sandbox's publications answer 8 MiB at most in all.</p>
    {problem ? <Problem text={problem} /> : null}
  </div>
}

/** A running sandbox's connection endpoints (M14): names its programs reach on their own port,
 *  each reaching nothing until it is granted a service another sandbox declared; and the grants
 *  other sandboxes hold to its own services. Every grant expires. */
export function ConnectionsBox({ sandbox, connections, others, disabled, onChanged }: {
  sandbox: string
  connections: SandboxConnections
  /** The other running sandboxes and the services their launches declared. */
  others: { sandbox: string; services: string[] }[]
  disabled: boolean
  onChanged(): void
}) {
  const [problem, setProblem] = useState("")
  const [working, setWorking] = useState(false)
  const [targets, setTargets] = useState<Record<string, string>>({})
  const choices = others.flatMap(other => other.services.map(service => ({ value: `${other.sandbox} ${service}`, label: `${service} of ${other.sandbox}` })))
  const act = async (action: () => Promise<unknown>) => {
    setWorking(true)
    setProblem("")
    try {
      await action()
    } catch (reason) {
      setProblem(errorText(reason))
    } finally {
      setWorking(false)
      onChanged()
    }
  }
  const connect = (endpoint: string) => act(async () => {
    const chosen = targets[endpoint] ?? choices[0]?.value
    if (!chosen) throw new Error("No other running sandbox declared a service to reach.")
    const space = chosen.indexOf(" ")
    await sandboxVmApi.connect(sandbox, endpoint, chosen.slice(0, space), chosen.slice(space + 1))
  })
  return <div role="group" aria-label="Sandbox connections" className="space-y-1 rounded border px-2 py-1">
    <p className="font-medium">Connections to other sandboxes</p>
    {connections.endpoints.map(endpoint => <div key={endpoint.name} className="flex flex-wrap items-center gap-2">
      <span className="font-mono">{endpoint.name}:{endpoint.port}</span>
      {endpoint.granted?.state === "active"
        ? <>
          <span>reaches {endpoint.granted.service} of <span className="font-mono">{endpoint.granted.sandbox}</span></span>
          <span className="text-muted-foreground">{endpoint.granted.connections_opened} connection{endpoint.granted.connections_opened === 1 ? "" : "s"} · {Math.ceil(endpoint.granted.expires_in_seconds / 60)} min left</span>
          <Button type="button" size="xs" variant="ghost" disabled={disabled || working} onClick={() => void act(() => sandboxVmApi.disconnect(sandbox, endpoint.name))}>Disconnect</Button>
        </>
        : choices.length
          ? <>
            {endpoint.granted ? <span className="text-muted-foreground">its grant to {endpoint.granted.service} of {endpoint.granted.sandbox} expired</span> : null}
            <select aria-label={`Service for ${endpoint.name}`} className="rounded border px-1 py-0.5" value={targets[endpoint.name] ?? choices[0]?.value ?? ""} onChange={event => setTargets({ ...targets, [endpoint.name]: event.target.value })}>
              {choices.map(choice => <option key={choice.value} value={choice.value}>{choice.label}</option>)}
            </select>
            <Button type="button" size="xs" variant="outline" disabled={disabled || working} onClick={() => void connect(endpoint.name)}>Connect</Button>
          </>
          : <span className="text-muted-foreground">reaches nothing: no other running sandbox declared a service</span>}
    </div>)}
    {connections.callers.map(caller => <p key={`${caller.sandbox} ${caller.endpoint}`}>
      <span className="font-mono">{caller.sandbox}</span> reaches its {caller.service} as {caller.endpoint} · {Math.ceil(caller.expires_in_seconds / 60)} min left
    </p>)}
    <p className="text-muted-foreground">Open now: {connections.open_connections}; refused: {connections.refused_connections}. A connection carries 8 MiB at most each way, and the other sandbox's answers count toward its release bound.</p>
    {problem ? <Problem text={problem} /> : null}
  </div>
}

const DRILL_CASES: Record<string, string> = {
  ungranted: "no grant",
  granted: "under its grant",
  other_service: "to a service not granted",
  revoked: "after the grant was withdrawn",
  expired: "after the grant expired",
  transitive: "through another sandbox's grant",
  transitive_control: "the other sandbox's own grant",
}

/** The doctor's VM-CP-29 drill (M08): three throwaway VMs of its own, connections under each grant
 *  state, judged from the host's counters, then stopped. Run only when asked, after a confirmation. */
export function ConnectionDrillBox({ disabled, onChanged }: { disabled: boolean; onChanged(): void }) {
  const [confirming, setConfirming] = useState(false)
  const [working, setWorking] = useState(false)
  const [report, setReport] = useState<DrillReport | null>(null)
  const [problem, setProblem] = useState("")
  const run = async () => {
    setConfirming(false)
    setWorking(true)
    setProblem("")
    try {
      setReport(await sandboxVmApi.drill())
    } catch (reason) {
      setProblem(errorText(reason))
    } finally {
      setWorking(false)
      onChanged()
    }
  }
  return <div role="group" aria-label="Connection drill" className="space-y-1 rounded-md border px-3 py-2 text-xs">
    <p className="font-medium">Connection drill (VM-CP-29)</p>
    <p className="text-muted-foreground">Launches three throwaway VM sandboxes, tries connections between them with no grant, under one, after a withdrawal and an expiry and through another sandbox's grant, judges each from this computer's own counts, then stops them. Your sandboxes are not touched.</p>
    {confirming
      ? <div className="flex flex-wrap items-center gap-2">
        <span>It reserves about 1.2 GB of memory for a few minutes.</span>
        <Button type="button" size="xs" disabled={disabled || working} onClick={() => void run()}>Run the drill</Button>
        <Button type="button" size="xs" variant="ghost" onClick={() => setConfirming(false)}>Back</Button>
      </div>
      : <Button type="button" size="xs" variant="outline" disabled={disabled || working} onClick={() => setConfirming(true)}>{working ? "Drilling…" : "Run the connection drill…"}</Button>}
    {report ? <div aria-label="Drill result" className="space-y-1">
      <p>{report.as_expected ? "Every connection went as the grants say." : "A connection did not go as the grants say."} {report.doctor}</p>
      <ul className="space-y-0.5">
        {report.cases.map(item => <li key={item.case}>{DRILL_CASES[item.case] ?? item.case}: {item.judged}{item.as_expected ? "" : ` (expected: ${item.expected})`}</li>)}
      </ul>
      <p className="text-muted-foreground">Shared state between the drill's VMs: {report.shared_state === null ? "not known" : report.shared_state ? "yes" : "none"}. Stopped: {report.stopped.filter(one => one.stopped).length} of {report.stopped.length}.</p>
    </div> : null}
    {problem ? <Problem text={problem} /> : null}
  </div>
}

function CommandBox({ sandbox }: { sandbox: string }) {
  const [input, setInput] = useState("")
  const [result, setResult] = useState<ExecResult | null>(null)
  const [problem, setProblem] = useState("")
  const [running, setRunning] = useState(false)
  const id = useId()
  const runCommand = async () => {
    if (!input.trim() || running) return
    setRunning(true)
    setProblem("")
    try {
      setResult(await sandboxVmApi.exec(sandbox, input))
    } catch (reason) {
      setProblem(errorText(reason))
    } finally {
      setRunning(false)
    }
  }
  return <div className="space-y-1">
    <div className="flex items-center gap-2">
      <label htmlFor={id} className="shrink-0">Command</label>
      <input id={id} className="flex-1 rounded border px-2 py-1 font-mono" value={input} placeholder="ls $WORKSPACE" onChange={event => setInput(event.target.value)} onKeyDown={event => { if (event.key === "Enter") void runCommand() }} />
      <Button type="button" size="xs" variant="outline" disabled={running} onClick={() => void runCommand()}>{running ? "Running…" : "Run"}</Button>
    </div>
    {problem ? <Problem text={problem} /> : null}
    {result ? <div aria-label="Command output">
      <p className="text-muted-foreground">The guest reported exit code {result.exit_code ?? "none"}.</p>
      <pre className="max-h-48 overflow-auto whitespace-pre-wrap rounded bg-muted px-2 py-1">{visibleText(result.output_text)}</pre>
    </div> : null}
  </div>
}

function WorkspaceList({ workspaces, disabled, onDiscard, onChanged }: { workspaces: WorkspaceSummary[]; disabled: boolean; onDiscard(sandbox: string): void; onChanged(): void }) {
  if (!workspaces.length) return <p className="text-xs text-muted-foreground">No staged workspace.</p>
  return <ul aria-label="Staged workspaces" className="space-y-2">
    {workspaces.map(workspace => <WorkspaceItem key={workspace.sandbox} workspace={workspace} disabled={disabled} onDiscard={onDiscard} onChanged={onChanged} />)}
  </ul>
}

function WorkspaceItem({ workspace, disabled, onDiscard, onChanged }: { workspace: WorkspaceSummary; disabled: boolean; onDiscard(sandbox: string): void; onChanged(): void }) {
  const [review, setReview] = useState<WorkspaceReview | null>(null)
  const [problem, setProblem] = useState("")
  const [reviewing, setReviewing] = useState(false)
  const [confirmDiscard, setConfirmDiscard] = useState(false)
  const [reading, setReading] = useState(false)
  const startReview = async () => {
    setReviewing(true)
    setProblem("")
    try {
      setReview(await sandboxVmApi.review(workspace.sandbox))
    } catch (reason) {
      setProblem(errorText(reason))
    } finally {
      setReviewing(false)
      onChanged()
    }
  }
  return <li className="space-y-2 rounded-md border px-3 py-2 text-xs">
    <div className="flex flex-wrap items-center justify-between gap-2">
      <div>
        <p className="font-medium" title={workspace.folder}>{visibleText(workspace.folder)}</p>
        <p className="text-muted-foreground">Sandbox <span className="font-mono">{workspace.sandbox}</span> · {workspace.sandbox_running ? "running" : "not running"} · {workspace.files} files imported{workspace.excluded ? `, ${workspace.excluded} credential locations left out` : ""}{workspace.skipped ? `, ${workspace.skipped} entries skipped` : ""}</p>
        <p>{stateText(workspace.state)}</p>
      </div>
      <div className="flex gap-2">
        <Button type="button" size="xs" variant="outline" disabled={disabled || reviewing} onClick={() => void startReview()}>{reviewing ? "Reviewing…" : "Review changes"}</Button>
        <Button type="button" size="xs" variant="outline" aria-expanded={reading} onClick={() => setReading(value => !value)}>Read a file safely</Button>
        {confirmDiscard
          ? <Button type="button" size="xs" variant="destructive" disabled={disabled} onClick={() => { setConfirmDiscard(false); onDiscard(workspace.sandbox) }}>Delete the copy and its changes</Button>
          : <Button type="button" size="xs" variant="ghost" disabled={disabled} onClick={() => setConfirmDiscard(true)}>Discard</Button>}
      </div>
    </div>
    {problem ? <Problem text={problem} /> : null}
    {reading ? <NormalizeView sandbox={workspace.sandbox} disabled={disabled} /> : null}
    {review ? <ReviewView sandbox={workspace.sandbox} folder={workspace.folder} review={review} onPromoted={onChanged} /> : null}
  </li>
}

const FORMATS: { value: NormalizeFormat; label: string }[] = [
  { value: "html", label: "Web page (HTML)" },
  { value: "archive", label: "Archive (zip, tar, tar.gz): list its entries" },
  { value: "plain_text", label: "Plain text" },
]

/** Parses one file of the staged workspace in a throwaway VM with no network, credential or
 *  host folder (VM-W58), and shows the text it kept as untrusted text: never rendered as a page,
 *  every hidden character made visible, and labelled as normalized, never as safe. */
export function NormalizeView({ sandbox, disabled }: { sandbox: string; disabled: boolean }) {
  const [file, setFile] = useState("")
  const [format, setFormat] = useState<NormalizeFormat>("html")
  const [markdown, setMarkdown] = useState(false)
  const [keepRaw, setKeepRaw] = useState(true)
  const [running, setRunning] = useState(false)
  const [problem, setProblem] = useState("")
  const [result, setResult] = useState<NormalizedResult | null>(null)
  const start = async () => {
    setRunning(true)
    setProblem("")
    setResult(null)
    try {
      // Markdown is offered for a page only; a choice made before switching formats is dropped.
      const target = format === "html" && markdown ? "markdown" : "plain_text"
      setResult(await sandboxVmApi.normalize(sandbox, { file: file.trim(), format, target, keepRaw }))
    } catch (reason) {
      setProblem(errorText(reason))
    } finally {
      setRunning(false)
    }
  }
  return <div role="group" aria-label="Read a file safely" className="space-y-2 rounded border px-2 py-2">
    <p className="text-muted-foreground">A throwaway VM with no network, no credential and no folder of yours parses the file; only its text comes back. Hidden instructions in the file can still be in that text.</p>
    <div className="flex flex-wrap items-end gap-2">
      <label className="flex flex-col gap-1">File in the workspace
        <input className="rounded border bg-background px-2 py-1 font-mono" value={file} placeholder="docs/page.html" onChange={event => setFile(event.target.value)} />
      </label>
      <label className="flex flex-col gap-1">What it is
        <select className="rounded border bg-background px-2 py-1" value={format} onChange={event => setFormat(event.target.value as NormalizeFormat)}>
          {FORMATS.map(option => <option key={option.value} value={option.value}>{option.label}</option>)}
        </select>
      </label>
      {format === "html" ? <label className="flex items-center gap-1"><input type="checkbox" checked={markdown} onChange={event => setMarkdown(event.target.checked)} />Keep headings and lists (Markdown)</label> : null}
      <label className="flex items-center gap-1"><input type="checkbox" checked={keepRaw} onChange={event => setKeepRaw(event.target.checked)} />Keep the original beside the text</label>
      <Button type="button" size="xs" disabled={disabled || running || !file.trim()} onClick={() => void start()}>{running ? "Reading in a throwaway VM…" : "Read it"}</Button>
    </div>
    {problem ? <Problem text={problem} /> : null}
    {result ? <div aria-label="Normalized text" className="space-y-1">
      <p className="text-amber-700 dark:text-amber-400">Untrusted text: {result.label}.</p>
      <pre className="max-h-64 overflow-auto whitespace-pre-wrap rounded bg-muted px-2 py-1">{visibleText(result.output_text)}</pre>
      {result.output_truncated ? <p className="text-muted-foreground">Only the beginning is shown; the whole text is kept.</p> : null}
      <p className="text-muted-foreground">{result.artifact.output.size_bytes} bytes of {result.artifact.format === "markdown" ? "Markdown" : "text"} by {result.artifact.provenance.normalizer.name} {result.artifact.provenance.normalizer.version} in {result.took_ms} ms; kept in {visibleText(result.stored)}{result.artifact.raw.raw === "kept_separately" ? " with the original" : ", without the original"}. The throwaway VM was stopped{result.normalizer_sandbox.copy_removed ? " and its copy removed" : ""}.</p>
    </div> : null}
  </div>
}

export function ReviewView({ sandbox, folder, review, onPromoted }: { sandbox: string; folder: string; review: WorkspaceReview; onPromoted(): void }) {
  const [approved, setApproved] = useState<Set<string>>(new Set())
  const [confirming, setConfirming] = useState(false)
  const [promotion, setPromotion] = useState<Promotion | null>(null)
  const [problem, setProblem] = useState("")
  const [promoting, setPromoting] = useState(false)
  const changed = review.files.filter(file => file.change !== "unchanged")
  if (!review.review || !changed.length) {
    return <div className="space-y-1">
      <p>Nothing in the workspace differs from the folder.</p>
      {review.deleted.length ? <p className="text-muted-foreground">Deleted in the workspace, never applied: {review.deleted.map(visibleText).join(", ")}</p> : null}
    </div>
  }
  const toggle = (name: string, on: boolean) => setApproved(current => {
    const next = new Set(current)
    if (on) next.add(name)
    else next.delete(name)
    return next
  })
  const promote = async () => {
    setPromoting(true)
    setProblem("")
    try {
      setPromotion(await sandboxVmApi.promote(sandbox, review.review!, [...approved]))
      setConfirming(false)
      onPromoted()
    } catch (reason) {
      setProblem(errorText(reason))
    } finally {
      setPromoting(false)
    }
  }
  if (promotion) {
    return <div aria-label="Promotion result" className="space-y-1">
      <p>Written into {visibleText(promotion.folder)}:</p>
      <ul className="list-disc pl-5">
        {promotion.promoted.applied.map(file => <li key={file.name}><span className="font-mono">{visibleText(file.name)}</span> ({file.applied}{file.original_kept_at ? `; the original is kept as ${visibleText(file.original_kept_at)}` : ""})</li>)}
      </ul>
    </div>
  }
  return <div aria-label="Review" className="space-y-2">
    <p className="text-muted-foreground">Choose the files to write into {visibleText(folder)}. Each is written exactly as shown; if it changes before you promote, nothing is written.</p>
    <ul className="space-y-2">
      {changed.map(file => <li key={file.name} className="space-y-1 rounded border px-2 py-1">
        <label className="flex flex-wrap items-center gap-2">
          <input type="checkbox" checked={approved.has(file.name)} onChange={event => toggle(file.name, event.target.checked)} />
          <span className="font-mono">{visibleText(file.name)}</span>
          <span className="text-muted-foreground">{file.change === "add" ? "new" : "changed"} · {file.size_bytes} bytes</span>
        </label>
        {file.flags.length ? <p className="text-amber-700 dark:text-amber-400">Look closely: {file.flags.map(flag => FLAG[flag]).join(", ")}</p> : null}
        {file.folder_changed_since_import ? <p className="text-amber-700 dark:text-amber-400">The file in your folder changed since the copy was made; promoting replaces your change (the original is kept).</p> : null}
        {file.diff ? <details><summary>Show the change</summary><pre className="max-h-64 overflow-auto whitespace-pre rounded bg-muted px-2 py-1">{visibleText(file.diff)}</pre></details> : <p className="text-muted-foreground">No text diff (binary or large).</p>}
      </li>)}
    </ul>
    {review.deleted.length ? <p className="text-muted-foreground">Deleted in the workspace, never applied: {review.deleted.map(visibleText).join(", ")}</p> : null}
    {problem ? <Problem text={problem} /> : null}
    {confirming
      ? <div className="flex flex-wrap items-center gap-2">
        <span>Write {approved.size} file{approved.size === 1 ? "" : "s"} into your folder?</span>
        <Button type="button" size="xs" disabled={promoting} onClick={() => void promote()}>{promoting ? "Writing…" : "Write them"}</Button>
        <Button type="button" size="xs" variant="ghost" disabled={promoting} onClick={() => setConfirming(false)}>Back</Button>
      </div>
      : <Button type="button" size="xs" disabled={!approved.size} onClick={() => setConfirming(true)}>Promote {approved.size} approved file{approved.size === 1 ? "" : "s"}</Button>}
  </div>
}
