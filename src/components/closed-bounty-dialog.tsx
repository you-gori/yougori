import { useCallback, useEffect, useMemo, useRef, useState } from "react"
import { bountyApi, type PrivatePreview, type ProjectImport, type ProjectTarget } from "@/api/bounty-api"
import { modelsApi } from "@/api/projects-api"
import { Terms } from "./swarm-terms"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"
import { usePlatformOptional } from "@/context/platform-context"
import { storageDrives, driveLabel } from "@/lib/storage-drives"
import { ModelPlacement, RentedGpuPermission } from "@/components/swarm-rented-gpu"
import { placementProblem, placementSetup, type Placement } from "@/lib/rented-gpu"
import { LIVE_TARGETS } from "@/lib/distribution"

/** The least room a model's runtime and weights need, matching the check the worker makes before
 *  it downloads anything. A worker refused here is refused there too, so this is where a person
 *  finds out, while they can still pick another drive or a smaller model. */
const MODEL_FLOOR_GB = 12

const initialTarget: ProjectTarget = { kind: "source", setupCommand: "", startCommand: "", testCommand: "", port: 3000, healthPath: "/", installNetwork: false, baseUrl: "" }
const message = (error: unknown) => error instanceof Error ? error.message : String(error)
export function ClosedBountyDialog({ open, onOpenChange, onReady, join = false, connection }: { open: boolean; onOpenChange(open: boolean): void; onReady(message: string): void; join?: boolean; connection?: PrivatePreview }) {
  const [project, setProject] = useState<ProjectImport | null>(null)
  const [target, setTarget] = useState<ProjectTarget>(initialTarget)
  const [title, setTitle] = useState("")
  const [instructions, setInstructions] = useState("Find reproducible security defects. Focus on authentication, access control, input handling and business logic. Explain impact and a fix.")
  const [authorization, setAuthorization] = useState("")
  const [visibility, setVisibility] = useState("local")
  const [address, setAddress] = useState("")
  const [password, setPassword] = useState("")
  const [invite, setInvite] = useState("")
  const [preview, setPreview] = useState<PrivatePreview | null>(connection ?? null)
  const [confirmed, setConfirmed] = useState(false)
  const [model, setModel] = useState("")
  const [name, setName] = useState("Private worker")
  const [budget, setBudget] = useState(60)
  const [cpu, setCpu] = useState(4)
  const [memory, setMemory] = useState(8)
  const [memoryEdited, setMemoryEdited] = useState(false)
  const [modelMemoryGb, setModelMemoryGb] = useState<number | null>(null)
  const localMemory = memoryEdited ? memory : (modelMemoryGb ?? memory)
  const [disk, setDisk] = useState(20)
  const [modelStorage, setModelStorage] = useState(24)
  const [drive, setDrive] = useState("")
  // What the model itself needs, learned from a preflight that creates no worker. Null until a
  // model is checked, or when the check could not reach the model.
  const [modelNeedsGb, setModelNeedsGb] = useState<number | null>(null)
  const [modelNote, setModelNote] = useState("")
  const [modelProblem, setModelProblem] = useState(false)
  const [checkingModel, setCheckingModel] = useState(false)
  const [reportPolicy, setReportPolicy] = useState("review")
  // The host's permission to send the code to a rented GPU: off unless ticked, and never kept for
  // the next bounty. Where this worker's model runs: this computer unless a rented GPU is chosen.
  const [rentedGpu, setRentedGpu] = useState(false)
  const [placement, setPlacement] = useState<Placement | null>(null)
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const machine = usePlatformOptional()?.state?.host
  const drives = useMemo(() => (machine ? storageDrives(machine) : []), [machine])
  // Default the model's drive to the one with the most room, so the first offer is one that fits.
  useEffect(() => {
    if (!drive && drives.length) setDrive(drives.reduce((best, d) => (d.freeGb > best.freeGb ? d : best)).path)
  }, [drive, drives])
  const chosen = drives.find(d => d.path === drive) ?? drives[0] ?? null
  const freeGb = chosen ? Math.floor(chosen.freeGb) : null
  // The same rule the worker uses, run here so a doomed worker is never created: the model needs
  // at least the floor, and no more than the drive has free.
  const storageProblem = chosen === null
    ? ""
    : chosen.readOnly
    ? `${driveLabel(chosen.path)} is read-only. Choose a drive the model can be written to.`
    : modelStorage < MODEL_FLOOR_GB
    ? `A model needs at least ${MODEL_FLOOR_GB} GB for its runtime and weights.`
    : modelNeedsGb !== null && freeGb !== null && modelNeedsGb > freeGb
    ? `This model needs about ${modelNeedsGb} GB but ${driveLabel(chosen.path)} has ${freeGb} GB free. Pick a roomier drive or a smaller quantization.`
    : freeGb !== null && modelStorage > freeGb
    ? `This asks for ${modelStorage} GB but ${driveLabel(chosen.path)} has ${freeGb} GB free. Pick a roomier drive or a smaller quantization.`
    : ""
  useEffect(() => { if (open) { setError(""); setConfirmed(false); setRentedGpu(false); setPlacement(null); setPreview(connection ?? null); void bountyApi.suggestedAddress().then(value => setAddress(value ?? "")).catch(() => {}) } }, [open, connection])
  const execute = async (label: string, work: () => Promise<void>) => {
    if (busy) return
    setBusy(label); setError("")
    try { await work() } catch (reason) { setError(message(reason)) } finally { setBusy("") }
  }
  const choose = (directory: boolean) => execute("Reading project", async () => {
    const path = await bountyApi.choosePath(directory)
    if (!path) return
    const imported = await bountyApi.inspect(path)
    setProject(imported); setTarget(imported.suggestedTarget); setTitle(imported.name); setConfirmed(false)
  })
  const change = <K extends keyof ProjectTarget>(key: K, value: ProjectTarget[K]) => { setTarget(current => ({ ...current, [key]: value })); setConfirmed(false) }
  const host = () => execute("Creating private host", async () => {
    if (!LIVE_TARGETS && target.kind === "url") throw new Error("Import source code and test its isolated sandbox in the public edition.")
    const result = await bountyApi.host({ importId: project?.importId, title, name: title, instructions, authorization, visibility, address, password, target, confirmed, rentedGpu })
    setPreview(result.preview); setPassword(""); setConfirmed(false); onReady(`${title} is hosted ${visibility === "local" ? "on this computer" : "on your LAN"}`)
  })
  const connect = () => execute("Connecting", async () => { setPreview(await bountyApi.connect(invite, password, name)); setPassword(""); setConfirmed(false) })
  // Every check gets a number, and a keystroke moves the number on, so an answer that arrives
  // after the person has typed something else is recognised as stale and ignored. Comparing the
  // model text instead does not work: the callbacks below see the text from the same render that
  // started the check, so it always matches itself.
  const checkSeq = useRef(0)
  // Ask the model what it needs before anything is created. A worker is never made here; this is
  // the same preflight the worker runs, so what it says now is what the worker would find.
  const checkModel = useCallback(() => {
    const mine = ++checkSeq.current
    setModelMemoryGb(null)
    const chosenModel = model.trim()
    if (!chosenModel) { setModelNeedsGb(null); setModelNote(""); setModelProblem(false); setCheckingModel(false); return }
    const asked = /^(hf\.co\/|https?:\/\/)/.test(chosenModel) ? chosenModel : `hf.co/${chosenModel}`
    setCheckingModel(true); setModelNote(""); setModelProblem(false)
    void modelsApi.preflight(asked)
      .then(result => {
        if (checkSeq.current !== mine) return
        if (!result.supported) { setModelNeedsGb(null); setModelProblem(true); setModelNote(result.reason || "This model is not supported for a worker."); return }
        const suggestedMemory = result.resources.workerMemoryGbRecommended
        setModelMemoryGb(typeof suggestedMemory === "number" && Number.isFinite(suggestedMemory) ? suggestedMemory : null)
        const needs = result.resources.storageGbRecommended
        setModelNeedsGb(typeof needs === "number" ? Math.ceil(needs) : null)
        setModelProblem(typeof needs !== "number")
        setModelNote(typeof needs === "number"
          ? `This model needs about ${Math.ceil(needs)} GB for its weights and runtime${result.resources.estimateOnly ? ", estimated" : ""}.`
          : "This model's size could not be measured. Set the storage yourself.")
        if (typeof needs === "number") setModelStorage(current => Math.max(current, Math.ceil(needs)))
      })
      .catch(() => { if (checkSeq.current === mine) { setModelNeedsGb(null); setModelProblem(true); setModelNote("The model could not be checked from here. Set the storage yourself.") } })
      .finally(() => { if (checkSeq.current === mine) setCheckingModel(false) })
  }, [model])
  // Check a moment after typing stops, so a person sees it happen without clicking away.
  useEffect(() => {
    if (!model.trim()) return
    const timer = setTimeout(() => checkModel(), 700)
    return () => clearTimeout(timer)
  }, [checkModel, model])
  const start = () => execute("Creating worker", async () => {
    if (!preview) return
    if (!placement && storageProblem) { setError(storageProblem); return }
    const where = placement ? placementSetup(placement) : { model: /^(hf\.co\/|https?:\/\/)/.test(model) ? model : `hf.co/${model}` }
    await bountyApi.start(preview, { name, ...where, resources: placement ? { cpu, memoryGb: memory } : { cpu, memoryGb: memoryEdited || modelMemoryGb !== null ? localMemory : undefined, storageGb: modelStorage, storageDrive: drive || undefined }, workspaceQuotaGb: disk }, budget, reportPolicy)
    onReady(placement ? `${name} is starting its model on your rented GPU and preparing its sandbox` : `${name} is preparing its model and sandbox`); onOpenChange(false)
  })
  const invalidHost = (!LIVE_TARGETS && target.kind === "url") || (!project && target.kind !== "url") || !title.trim() || !authorization.trim() || !confirmed || (visibility === "lan" && (!address || password.length < 12)) || ((target.kind === "web" || target.kind === "api") && (!target.startCommand.trim() || target.port < 1024 || target.port > 65535)) || (target.kind === "url" && !target.baseUrl.trim())
  return <Dialog open={open} onOpenChange={value => { if (!busy) { if (!value && preview) void bountyApi.discard(preview.ticket).catch(() => {}); onOpenChange(value) } }}>
    <DialogPopup className="grid-dialog swarm-accept" bottomStickOnMobile={false}>
      <DialogHeader>
        <DialogTitle>{preview ? "Start a private worker" : join ? "Join a closed bounty" : "Create a closed bounty"}</DialogTitle>
        <DialogDescription>{preview ? "Review the project and choose where its model runs. Every worker runs its own isolated copy." : join ? "Connect to the owner's private host with its invitation and password." : "Choose a project, describe how it runs, and host the bounty on this computer or your LAN."}</DialogDescription>
      </DialogHeader>
      <DialogPanel scrollFade={false}>
        <div className="grid-form">
          {!preview && !join ? <>
            <div className="grid-field"><label>Project{target.kind === "url" ? " (optional)" : ""}</label><div className="swarm-project-actions"><Button variant="outline" disabled={!!busy} onClick={() => void choose(true)}>Choose folder</Button><Button variant="outline" disabled={!!busy} onClick={() => void choose(false)}>Choose ZIP or file</Button></div>
              <p className="grid-hint">{target.kind === "url" ? "Optional for a live URL: add the source to also get a white-box code review alongside the live probing. Leave it out for a pure black-box test of the URL below." : "Choose your source project. For a code security review that's all you need — no server to run, no boot. For a website or API, the sandbox (Linux with Node.js and Python) can install dependencies and start it; include a test database and fixtures if needed."}</p>
              {project ? <details open><summary>{project.name} · {project.fileCount} files · {(project.bytes / 1048576).toFixed(1)} MiB</summary><pre className="swarm-file-list">{project.files.join("\n")}</pre>{project.excluded.length ? <p className="grid-hint">Excluded: {project.excluded.join(", ")}. Review the snapshot before sharing it with participants.</p> : null}</details> : null}
            </div>
            <div className="grid-field"><label htmlFor="closed-title">Bounty name</label><Input id="closed-title" value={title} disabled={!!busy} onChange={event => setTitle(event.target.value)} /></div>
            <div className="grid-field"><label htmlFor="closed-kind">What are you testing?</label><select id="closed-kind" value={target.kind} disabled={!!busy} onChange={event => change("kind", event.target.value as ProjectTarget["kind"])}><option value="source">Source / code security review — no server to run</option>{LIVE_TARGETS ? <option value="url">Live URL — my own running service, attacked over the network</option> : null}<option value="web">Website or web application (booted in the sandbox)</option><option value="api">API service (booted in the sandbox)</option></select></div>
            {target.kind !== "url" ? <>
              <div className="grid-field"><label htmlFor="closed-setup">Install / setup command</label><Input id="closed-setup" value={target.setupCommand} disabled={!!busy} placeholder="npm ci" onChange={event => change("setupCommand", event.target.value)} /><p className="grid-hint">Commands run at the imported project root inside the sandbox.</p></div>
              {target.setupCommand ? <label className="swarm-check"><input type="checkbox" checked={target.installNetwork} disabled={!!busy} onChange={event => change("installNetwork", event.target.checked)} /><span>Allow internet access during setup to download dependencies. Research runs with external networking disabled.</span></label> : null}
            </> : null}
            {LIVE_TARGETS && target.kind === "url" ? <>
              <div className="grid-field"><label htmlFor="closed-base-url">Live service URL</label><Input id="closed-base-url" value={target.baseUrl} disabled={!!busy} placeholder="https://staging.example.com" onChange={event => change("baseUrl", event.target.value)} /><p className="grid-hint">Your own running service. Agents reach this origin over the network with internet access on — nothing is booted from source. Only this origin is in scope. Use a staging or test instance, not production.</p></div>
              <div className="grid-field"><label htmlFor="closed-url-health">Health check path</label><Input id="closed-url-health" value={target.healthPath} disabled={!!busy} placeholder="/health" onChange={event => change("healthPath", event.target.value)} /><p className="grid-hint">A path that answers when the service is up. Any response confirms it is reachable.</p></div>
            </> : null}
            {target.kind === "web" || target.kind === "api" ? <>
              <div className="grid-field"><label htmlFor="closed-start">Start command</label><Input id="closed-start" value={target.startCommand} disabled={!!busy} placeholder="npm start" onChange={event => change("startCommand", event.target.value)} /><p className="grid-hint">Run in the foreground. The sandbox provides PORT and HOST. Agents start after the health check responds.</p></div>
              <div className="grid-fields">
                <div className="grid-field"><label htmlFor="closed-port">Service port</label><Input id="closed-port" type="number" min={1024} max={65535} value={target.port} disabled={!!busy} onChange={event => change("port", Number(event.target.value))} /></div>
                <div className="grid-field"><label htmlFor="closed-health">Health check path</label><Input id="closed-health" value={target.healthPath} disabled={!!busy} placeholder="/health" onChange={event => change("healthPath", event.target.value)} /></div>
              </div>
            </> : null}
            {target.kind !== "url" ? <div className="grid-field"><label htmlFor="closed-test">Test command (optional)</label><Input id="closed-test" value={target.testCommand} disabled={!!busy} placeholder="npm test" onChange={event => change("testCommand", event.target.value)} /></div> : null}
            <div className="grid-field"><label htmlFor="closed-instructions">What should agents investigate?</label><textarea id="closed-instructions" className="grid-textarea swarm-prose" rows={3} value={instructions} disabled={!!busy} onChange={event => setInstructions(event.target.value)} /></div>
            <div className="grid-field"><label htmlFor="closed-authorization">Authorized scope and test accounts</label><textarea id="closed-authorization" className="grid-textarea swarm-prose" rows={3} value={authorization} disabled={!!busy} placeholder="We own this application. Test the imported copy using seeded test accounts. Focus on tenant isolation. No production credentials." onChange={event => setAuthorization(event.target.value)} /></div>
            <div className="grid-field"><label htmlFor="closed-visibility">Who can join?</label><select id="closed-visibility" value={visibility} disabled={!!busy} onChange={event => setVisibility(event.target.value)}><option value="local">Workers on this computer</option><option value="lan">Computers on my private LAN / cluster</option></select></div>
            {visibility === "lan" ? <><div className="grid-field"><label htmlFor="closed-address">This computer's LAN address</label><Input id="closed-address" value={address} disabled={!!busy} onChange={event => setAddress(event.target.value)} /></div><div className="grid-field"><label htmlFor="closed-password">Shared password (at least 12 characters)</label><Input id="closed-password" type="password" value={password} disabled={!!busy} onChange={event => setPassword(event.target.value)} /></div><p className="grid-hint">Keep the host running. Participants use its invitation and password; port 7462 must be reachable on your LAN.</p></> : null}
            <RentedGpuPermission checked={rentedGpu} onChange={setRentedGpu} disabled={!!busy} />
            <label className="swarm-check"><input type="checkbox" checked={confirmed} disabled={!!busy} onChange={event => setConfirmed(event.target.checked)} /><span>I authorize testing this project{target.kind === "url" ? ", attest that I own or am permitted to test the live service at this URL," : ""} and approve its commands and sharing scope.</span></label>
          </> : null}
          {!preview && join ? <><div className="grid-field"><label htmlFor="closed-invite">Private bounty invitation</label><textarea id="closed-invite" className="grid-textarea" value={invite} disabled={!!busy} onChange={event => setInvite(event.target.value)} /></div><div className="grid-field"><label htmlFor="join-password">Password</label><Input id="join-password" type="password" value={password} disabled={!!busy} onChange={event => setPassword(event.target.value)} /></div></> : null}
          {preview ? <>
            <p><strong>{preview.policy.title}</strong> · {preview.policy.sourceRevision}</p><p className="grid-hint">{preview.policy.objective}</p><p className="grid-hint">{preview.policy.authorization}</p>
            <Terms value={preview.policy.target as unknown as Record<string, unknown>} />
            <div className="grid-field"><label htmlFor="private-name">Worker name</label><Input id="private-name" value={name} disabled={!!busy} onChange={event => setName(event.target.value)} /></div>
            <ModelPlacement title={preview.policy.title} allowed={preview.policy.rentedGpu === true} value={placement} onChange={setPlacement} disabled={!!busy} />
            {placement ? null : <div className="grid-field"><label htmlFor="private-model">Hugging Face GGUF model</label><Input id="private-model" value={model} disabled={!!busy} placeholder="owner/model-GGUF" onChange={event => { checkSeq.current += 1; setModel(event.target.value); setModelNeedsGb(null); setModelMemoryGb(null); setModelNote(""); setModelProblem(false); setCheckingModel(false) }} />
              <p className="grid-hint">Choose a model that supports tool calls. Its size is checked here before anything is created.</p>
              {checkingModel
                ? <p role="status" className="grid-hint" style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}><Spinner aria-hidden="true" className="size-4 shrink-0" />Checking {model.trim() || "the model"} on Hugging Face and measuring how much room its weights need…</p>
                : modelNote
                ? <p role="status" className={modelProblem ? "grid-error" : "grid-hint"}>{modelNote}</p>
                : null}</div>}
            <div className="grid-field"><label htmlFor="private-budget">Work budget (minutes)</label><Input id="private-budget" type="number" min={1} max={1440} value={budget} disabled={!!busy} onChange={event => setBudget(Number(event.target.value))} /></div>
            <details open><summary>Worker resources</summary><p className="grid-hint">The model, the research agent and the target sandbox each need room. The model and its weights go on the drive you choose below, checked against that drive's free space before the worker is created.</p>
              <div className="grid-field"><label htmlFor="private-cpu">CPU cores</label><Input id="private-cpu" type="number" min={4} max={255} value={cpu} disabled={!!busy} onChange={event => setCpu(Number(event.target.value))} /></div>
              <div className="grid-field"><label htmlFor="private-memory">Memory (GiB)</label><Input id="private-memory" type="number" min={8} max={1024} value={placement ? memory : localMemory} disabled={!!busy} onChange={event => { setMemory(Number(event.target.value)); setMemoryEdited(true) }} />
                {!placement ? <p className="grid-hint">{modelMemoryGb === null && !memoryEdited ? "RAM is sized from the selected model when checked." : `${localMemory - 4} GiB for the model and 4 GiB for the agent and test sandboxes. GPU memory is separate.`}</p> : null}
                {!placement && memoryEdited && modelMemoryGb !== null && memory < modelMemoryGb ? <p className="grid-hint">This model's estimated recommendation is {modelMemoryGb} GiB total. A smaller allocation may run out of system RAM.</p> : null}
              </div>
              {placement ? null : <><div className="grid-field"><label htmlFor="private-drive">Model storage drive</label><select id="private-drive" value={drive} disabled={!!busy || !drives.length} onChange={event => setDrive(event.target.value)}>
                {drives.length ? drives.map(d => <option key={d.path} value={d.path}>{driveLabel(d.path)} — {Math.floor(d.freeGb)} GB free of {Math.floor(d.totalGb)} GB{d.readOnly ? " (read-only)" : ""}</option>) : <option value="">No drive reported yet</option>}
              </select>{chosen ? <p className="grid-hint">{driveLabel(chosen.path)} has {freeGb} GB free. A worker's model and weights are written here.</p> : null}</div>
              <div className="grid-field"><label htmlFor="private-model-storage">Model storage (GiB)</label><Input id="private-model-storage" type="number" min={MODEL_FLOOR_GB} max={freeGb ?? 2048} value={modelStorage} disabled={!!busy} onChange={event => setModelStorage(Number(event.target.value))} /><p className="grid-hint">How much the model's runtime and weights may use. A 27-billion-parameter model needs roughly 16 to 28 GB depending on its quantization; at least {MODEL_FLOOR_GB} GB.</p></div></>}
              <div className="grid-field"><label htmlFor="private-disk">Sandbox storage (GiB)</label><Input id="private-disk" type="number" min={4} max={1024} value={disk} disabled={!!busy} onChange={event => setDisk(Number(event.target.value))} /><p className="grid-hint">Room for a checked-out copy of the target the agent tests against.</p></div>
              {storageProblem && !placement ? <p className="grid-error" role="alert">{storageProblem}</p> : null}
            </details>
            <div className="grid-field"><label htmlFor="private-report">Findings</label><select id="private-report" value={reportPolicy} disabled={!!busy} onChange={event => setReportPolicy(event.target.value)}><option value="review">Review each report before sharing with the owner</option><option value="automatic">Send supported reports to the owner automatically</option></select></div>
            <label className="swarm-check"><input type="checkbox" checked={confirmed} disabled={!!busy} onChange={event => setConfirmed(event.target.checked)} /><span>I approve this project, its commands and testing scope. Shared agent updates are visible to participants and the bounty owner.</span></label>
          </> : null}
          {busy ? <p role="status">{busy}…</p> : null}{error ? <p className="grid-error" role="alert">{error}</p> : null}
        </div>
      </DialogPanel>
      <DialogFooter><DialogClose render={<Button variant="outline" disabled={!!busy} />}>{preview ? "Done" : "Cancel"}</DialogClose>
        {preview ? <Button disabled={!!busy || !confirmed || (placement ? Boolean(placementProblem(placement)) : !model.trim()) || !name.trim() || !Number.isInteger(budget) || budget < 1 || budget > 1440 || (!placement && Boolean(storageProblem))} onClick={() => void start()}>Start worker</Button> : join ? <Button disabled={!!busy || !invite.trim() || !password} onClick={() => void connect()}>Connect and review</Button> : <Button disabled={!!busy || invalidHost} onClick={() => void host()}>Host bounty</Button>}
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
