import { useState } from "react"
import { ClosedBountyDialog } from "@/components/closed-bounty-dialog"
import { PrivateBountyHost } from "@/components/private-bounty-host"
import { SwarmWorkerWorkspace } from "@/components/swarm-worker-workspace"
import { SwarmRentedGpus } from "@/components/swarm-rented-gpu"
import { SwarmPromptsEditor } from "@/components/swarm-prompts"
import type { PrivatePreview } from "@/api/bounty-api"
import { ChevronDownIcon } from "lucide-react"
import { Spinner } from "@/components/ui/spinner"
import { swarmApi, type SwarmWorker } from "@/api/swarm-api"
import { workerStatus, workerBusy } from "@/lib/swarm-status"
import { forgetResearch, readResearch, researchSentence } from "@/lib/research-authorisation"
import { AcceptBountyDialog } from "@/components/swarm-dialogs"
import { useArmed } from "@/components/use-armed"
import { useWorkspaceActions } from "@/components/use-workspace-actions"
import { useSwarmActions } from "@/components/use-swarm-actions"
import { PageHeader, PillButton } from "@/components/prompx"
import { workspaceApi } from "@/api/workspace-api"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import "@/components/neo-grid.css"
import "@/components/swarm.css"

type Run = (job: string, work: () => Promise<unknown>, done?: string) => Promise<void>

function WorkerRow({ worker, run, onAccept }: { worker: SwarmWorker; run: Run; onAccept(worker: SwarmWorker): void }) {
  const { armed, arm, disarm } = useArmed()
  const [open, setOpen] = useState(false)
  const status = workerStatus(worker)
  const leaving = armed === worker.id
  const clearing = armed === `${worker.id}:history`
  const working = !worker.error && workerBusy(worker)
  return <>
    <div className="grid-line grid-computer">
      <i aria-hidden="true" className="grid-dot" data-online={status.tone === "ok" || status.tone === "busy" || undefined} />
      <span className="grid-computer-main">
        <strong>{worker.name}</strong>
        <span className="grid-status" data-tone={status.tone} style={{ display: "inline-flex", alignItems: "center", gap: "0.35rem" }}>
          {!worker.error && workerBusy(worker) ? <Spinner aria-hidden="true" className="size-3.5 shrink-0" /> : null}
          <span>{status.text}{worker.completedAttempts ? ` · ${worker.completedAttempts} done` : ""}</span>
        </span>
      </span>
      <span className="grid-meta" title={`${worker.model}${worker.gpu ? ` · ${worker.gpu}` : ""}`}>{worker.model.replace(/^hf\.co\//, "")}</span>
      <span className="grid-line-actions">
        {worker.error ? <Button size="xs" onClick={() => void run(`Retrying ${worker.name}`, () => swarmApi.resume(worker.id), `${worker.name} is retrying`)}>Retry</Button> : null}
        {status.waiting && worker.networkMode !== "closed" ? <Button size="xs" onClick={() => onAccept(worker)}>Choose bounty</Button> : null}
        {worker.state === "paused"
          ? <Button size="xs" variant="outline" onClick={() => void run(`Resuming ${worker.name}`, () => swarmApi.resume(worker.id))}>{worker.developmentApiModel ? "Start" : "Resume"}</Button>
          : !worker.error && (workerBusy(worker) || status.waiting) ? <Button size="xs" variant="ghost" onClick={() => void run(`Pausing ${worker.name}`, () => swarmApi.pause(worker.id), worker.rentedGpu ? `${worker.name} paused. Its rented GPU keeps running and is billed until you stop it under Rented GPUs.` : undefined)}>Pause</Button> : null}
        <Button size="icon-xs" variant="ghost" aria-expanded={open} aria-label={open ? `Hide ${worker.name} activity` : `Show ${worker.name} activity`} onClick={() => setOpen(value => !value)}>
          <ChevronDownIcon aria-hidden="true" className="grid-chevron" data-open={open || undefined} />
        </Button>
        <Button size="xs" variant={leaving ? "destructive" : "ghost"} aria-label={`Remove ${worker.name}`} onClick={() => leaving ? (disarm(), void run(`Removing ${worker.name}`, () => swarmApi.remove(worker.id), worker.rentedGpu ? `${worker.name} removed. Its rented GPU is being stopped; starting it again is yours to do in NeoCloud.` : `${worker.name} removed`)) : arm(worker.id)}>{leaving ? "Confirm" : "Remove"}</Button>
      </span>
    </div>
    {open ? <div className="swarm-detail">
      {worker.bountyId ? <p className="grid-note">Bounty <code>{worker.bountyId}</code></p> : null}
      {worker.summary ? <p className="grid-note">{worker.summary}</p> : null}
      <dl className="swarm-stats">
        <div className="swarm-stat"><dt>State</dt><dd>{!worker.error && workerBusy(worker) ? <span className="swarm-stat-dot" aria-hidden="true" /> : null}{status.text}</dd></div>
        <div className="swarm-stat"><dt>Attempts</dt><dd>{worker.completedAttempts ?? 0}</dd></div>
        <div className="swarm-stat"><dt>Reports</dt><dd>{worker.reviewReports?.length ?? 0}</dd></div>
        <div className="swarm-stat"><dt>Mode</dt><dd>{worker.networkMode === "closed" ? "Private" : "Public"}</dd></div>
        {worker.gpu ? <div className="swarm-stat"><dt>Compute</dt><dd>{worker.developmentApiModel ? "External API · development test" : worker.gpu}</dd></div> : null}
      </dl>
      <p className="grid-note swarm-history">
        <span>{clearing ? "Clears this worker's activity and its attempt count. Reports, receipts and the bounty stay." : working ? "Pause the worker to clear its history." : null}</span>
        <Button size="xs" variant={clearing ? "destructive" : "ghost"} disabled={working} onClick={() => clearing ? (disarm(), void run(`Clearing ${worker.name}'s history`, () => swarmApi.clearHistory(worker.id), `${worker.name}'s history cleared`)) : arm(`${worker.id}:history`)}>{clearing ? "Confirm" : "Clear history"}</Button>
      </p>
      <SwarmWorkerWorkspace workerId={worker.id} hasBounty={Boolean(worker.bountyId)} onChanged={() => void run("Refreshing reports", () => swarmApi.status(worker.id))} />
    </div> : null}
  </>
}

/** The Swarm Mining page: the headline with the account, its actions, then the workers. */
export function SwarmMiningPage() {
  const { workers, swarmError: loadError, refreshSwarm: refresh, network, website, openNetwork, openSetup } = useWorkspaceActions()
  const [showPrompts, setShowPrompts] = useState(false)
  const [joining, setJoining] = useState(false)
  const [connection, setConnection] = useState<PrivatePreview | undefined>()
  const [hostVersion, setHostVersion] = useState(0)
  const { busy, run } = useSwarmActions(refresh)
  const [accepting, setAccepting] = useState<SwarmWorker | null>(null)
  // What somebody authorised in the Grids wizard, which is what a worker made here starts
  // with. It is read once, because it only changes when the wizard is used again.
  const [authorised, setAuthorised] = useState(() => readResearch())

  const ready = (text: string) => { setHostVersion(value => value + 1); toastManager.add({ title: text, type: "success" }); void refresh() }

  const account = network.status
  const running = workers.filter(worker => workerBusy(worker)).length
  return <section className="app-page" aria-label="Swarm Mining workspace" aria-busy={Boolean(busy)}>
    <PageHeader
      title="Swarm Mining."
      lead="Workers on this computer hunt the bounties you choose, or work a source you own."
      aside={account?.signedIn
        ? <Button size="xs" variant="ghost" className="swarm-account" aria-label="Your Yougori account" onClick={openNetwork}><i aria-hidden="true" className="grid-dot" data-online /> {account.account?.email ?? "Signed in"}</Button>
        : <Button size="xs" variant="outline" aria-label="Sign in to your Yougori account" onClick={openNetwork}>Sign in</Button>}
      actions={<>
        <PillButton tone="dark" title="Run a worker on the public Yougori bounty board; you choose its bounties." onClick={() => openSetup("join")}>Join bounty hunting</PillButton>
        <PillButton tone="light" title="A worker works a source you own, on this computer or your LAN." onClick={() => openSetup("closed")}>Create closed bounty</PillButton>
        <PillButton tone="light" onClick={() => { setConnection(undefined); setJoining(true) }}>Join closed bounty</PillButton>
        <PillButton tone="light" title="Post a bounty on the public board for the swarm to hunt." onClick={() => void workspaceApi.openUrl(`${website}/swarm`)}>Create bounty in Yougori</PillButton>
      </>}
    />
    <div className="app-page-body">
      {authorised ? <div className="grid-sheet">
        <section className="grid-part" aria-label="What you authorised">
          <p className="grid-part-title">What you authorised <span>a worker made here starts with this</span></p>
          <p className="grid-line"><span>{researchSentence(authorised)}</span></p>
          {authorised.sources.length ? <p className="grid-line grid-muted"><span>{authorised.sources.map(source => source.value).join(" · ")}</span></p> : null}
          <p className="grid-line grid-muted">
            <span>A worker gets {authorised.worker.cpu} cores, {authorised.worker.memoryGb} GB of memory and {authorised.worker.diskGb} GB of disk.</span>
            <span className="grid-line-actions"><Button size="xs" variant="ghost" onClick={() => { forgetResearch(); setAuthorised(null) }}>Forget this</Button></span>
          </p>
        </section>
      </div> : null}
      <PrivateBountyHost refreshKey={hostVersion} onConnect={preview => { setConnection(preview); setJoining(true) }} />
      <SwarmRentedGpus run={run} refreshKey={workers} />
      {workers.length || loadError ? <div className="grid-board">
        {busy ? <p role="status" className="grid-muted">{busy}…</p> : null}
        {loadError ? <p role="alert" className="grid-error">{loadError}</p> : null}
        {workers.length ? <div className="grid-sheet">
          <section className="grid-part" aria-label="Workers">
            <p className="grid-part-title">Workers <span>{running} working</span></p>
            {workers.map(worker => <WorkerRow key={worker.id} worker={worker} run={run} onAccept={setAccepting} />)}
          </section>
        </div> : null}
      </div> : <div className="grid-empty">
        <p className="grid-empty-title">Hunt a bounty with a worker</p>
        <p className="grid-empty-hint">Join the public bounty board and let a worker on this computer hunt bounties you choose, run a closed bounty against a source you own, or post a bounty on Yougori for the swarm to hunt. Workers show up here.</p>
      </div>}
      <div className="swarm-prompts-panel">
        <button type="button" className="swarm-prompts-toggle" aria-expanded={showPrompts} onClick={() => setShowPrompts(value => !value)}>
          {showPrompts ? "Hide" : "Edit"} prompts &amp; guardrails
        </button>
        {showPrompts ? <SwarmPromptsEditor /> : null}
      </div>
    </div>
    <ClosedBountyDialog open={joining} onOpenChange={setJoining} onReady={ready} join connection={connection} />
    <AcceptBountyDialog worker={accepting} onOpenChange={value => { if (!value) setAccepting(null) }} onAccepted={ready} />
  </section>
}
