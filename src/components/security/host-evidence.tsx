import { useEffect, useId, useState } from "react"
import {
  hostEvidenceApi, isHostEvidenceUnavailable,
  type Backend, type Capability, type CudaRuntimeFacts, type Digest, type DriverModel, type Duration, type EvidenceRefusal, type EvidenceStatus,
  type ExecutionCategory, type GpuDevice, type HostEvidencePlan, type HostEvidenceRefresh, type HostInventory, type HypervisorKind, type InventoryProblem,
  type MigMode, type ObservationResult, type OsKind, type PeerPath, type Query, type QueryDescription, type Remedy, type SourceClass, type StatusEntry, type Subject,
  type SupportDetail, type UnknownReason, type UnsupportedReason, type Verdict,
} from "@/api/host-evidence-api"
import { Button } from "@/components/ui/button"
import { formatBytesFromGb } from "@/lib/domain"

/** This computer's host evidence (S01, CORE-01): what the engine's bounded, read-only host queries
 *  last observed (the machine, its operating system, its NVIDIA GPUs and its CUDA runtime), every
 *  capability observed from that with its subject, source, freshness, configuration and verdict,
 *  the remedy of a refused one, and the capabilities other tasks own. The VM sandbox doctor names
 *  this computer from the same inventory.
 *
 *  Reading the status or the plan runs nothing. A refresh runs the plan's queries once, and only
 *  after the user confirms it. The words follow the engine's: not tested is never a pass. */

const CAPABILITY: Record<Capability, string> = {
  cuda_ipc_legacy: "legacy CUDA IPC", cuda_ipc_vmm_shareable_handle: "CUDA VMM shareable handles", gpu_direct_storage: "GPUDirect Storage",
  cuda_checkpoint: "CUDA checkpoint", io_uring: "io_uring", zero_copy_preload: "zero-copy preload", sleep_weight_offload: "sleep-mode weight offloading",
  hypervisor_available: "hypervisor availability", provider_container: "provider container", runtime_category: "runtime category",
  cuda_vmm_allocation: "CUDA VMM allocation", compute_platform: "compute platform", sleep_weight_discard: "sleep-mode weight discarding",
  gpu_peer_access: "GPU peer access", checkpoint_compatibility: "checkpoint compatibility", gpu_free_memory: "free GPU memory",
  peer_topology: "GPU peer topology", execute_while_load: "execute-while-load", perimeter_rule_enforced: "perimeter rule enforcement",
  hypervisor_configuration_matches: "approved hypervisor configuration", hypervisor_confined: "hypervisor confinement",
  booted_image_matches_manifest: "booted image matching its signed manifest", destination_policy_enforced: "destination policy enforcement",
  no_guest_network_device: "no guest network device", credential_absent_from_scanned_locations: "credential absent from the scanned locations",
  clone_identity_reset: "clone identity reset", device_assignment_isolated: "isolated GPU assignment", kv_growth: "KV growth in increments",
  adapter_limits: "unmerged adapter limits",
}
const SOURCE: Record<SourceClass, string> = {
  fixture: "test fixture", recorded_declaration: "recorded declaration", guest_report: "guest report", provider_api: "provider API report", host_probe: "host probe",
}
const UNSUPPORTED: Record<UnsupportedReason, string> = {
  operation_failed: "the operation failed when it was exercised",
  feature_absent: "the platform, driver or kernel lacks it",
  disabled_by_policy: "the runtime's policy turns it off",
  hypervisor_unavailable: "no usable hypervisor is available on this host",
  not_a_provider_container: "the provider does not run this resource as a container",
  different_category: "the runtime is not the category it was offered as",
  not_enforced: "the probe got through with the rule in place",
  configuration_not_approved: "the hypervisor configuration differs from the approved profile or exposes an undeclared device, share or listener",
  not_confined: "the hypervisor process lacks a restriction its profile requires",
  image_not_as_signed: "the booted image or kernel record differs from the signed manifest, or a changed component set was not refused at launch",
  destination_not_refused: "the transport broker let a forbidden answer, name or address form through",
  guest_network_path: "the host saw a packet from the VM, so it has a network path",
  credential_exposed: "within the scanned locations, the fixture credential was found outside the executor's request, or not in it",
  clone_identity_shared: "clones of one snapshot share an identity or accept an approval from before it",
  device_not_isolated: "the GPU's IOMMU group, display ownership, reset or ACS state does not allow assignment",
}
const UNKNOWN: Record<UnknownReason, string> = {
  not_tested: "it was not tested", inconclusive: "the check was inconclusive", unreachable: "the subject could not be reached",
  inconsistent_report: "the check's report did not fit what was checked",
}
const REMEDY: Record<Exclude<Remedy["action"], "obtain_stronger_evidence">, string> = {
  run_check: "run the check",
  run_check_again: "run the check again",
  recheck_current_configuration: "run the check again under the current configuration",
  choose_supported_runtime: "choose a runtime or device that supports it",
  enable_hypervisor_yourself: "turn on hardware virtualization and the platform hypervisor yourself, or use a remote VM; Yougori does not change host settings",
  choose_allowed_category: "choose a runtime of a category this request allows",
  use_ordinary_loader: "continue with the ordinary loader, or remove the requirement for this optimization",
  use_one_mode_at_a_time: "use one of these modes at a time",
  use_recorded_backend_release: "use a backend release whose support for this mode is recorded",
  keep_within_authorized_runtime: "keep the fallback within the authorized runtime; anything else needs a new, separately authorized request",
  repair_perimeter: "repair or reinstall the host perimeter, which takes one elevated install step, then run the must-probe again",
}
/** The remedies a refresh carries out for this computer's own queries. */
const RERUN = new Set<Remedy["action"]>(["run_check", "run_check_again", "recheck_current_configuration"])
const PROBLEM: Record<InventoryProblem["problem"], string> = {
  tool_missing: "the query's program is not installed", query_failed: "the query failed", timed_out: "the query timed out and was stopped",
  output_too_long: "the query's output exceeded its bound", not_utf8: "the query's output is not text", machine_identity: "the machine identity is unavailable",
  os_build: "the operating system build is unavailable", malformed_gpu_row: "a GPU row is malformed", too_many_gpus: "more than 64 GPUs were reported",
  repeated_gpu: "a GPU was reported twice", not_on_this_platform: "the query does not exist on this platform",
}
const OS: Record<OsKind, string> = { windows: "Windows", linux: "Linux", macos: "macOS", wsl2: "WSL2" }
const CATEGORY: Record<ExecutionCategory, string> = {
  vm_sandbox: "VM sandbox", shared_kernel_gpu_runtime: "GPU runtime (shared kernel), not a sandbox",
  provider_container_runtime: "remote runtime (provider container), not a sandbox", host_process_model_runtime: "model runtime (host process, sandbox profile), not a sandbox",
}
const BACKEND: Record<Backend, string> = { vllm: "vLLM", llama_cpp: "llama.cpp", transformers: "Transformers" }
const HYPERVISOR: Record<HypervisorKind, string> = {
  kvm: "KVM", whpx: "Windows Hypervisor Platform", hcs: "Windows Host Compute Service", hvf: "Hypervisor.framework", vz: "Virtualization.framework",
}
const DRIVER_MODEL: Record<DriverModel, string> = { wddm: "WDDM driver model", tcc: "TCC driver model", mcdm: "MCDM driver model", not_reported: "driver model not reported" }
const MIG: Record<MigMode, string> = { enabled: "MIG enabled", disabled: "MIG disabled", not_supported: "MIG not supported" }
const LINK: Record<PeerPath["link"], string> = { nv_link: "NVLink", pcie_switch: "a shared PCIe switch", pcie_host_bridge: "the PCIe host bridge", cross_socket: "a link between CPU sockets" }
const QUERY: Record<Query, string> = { machine_identity: "Machine identity", os_build: "Operating system build", gpus: "NVIDIA GPUs" }
const VERDICT: Record<Verdict["verdict"], string> = { satisfied: "Satisfied", refused: "Refused", not_collected: "Not collected" }

/** A word from one of the tables above, or the engine's own name when this build has no word for it. */
const named = <K extends string>(words: Record<K, string>, key: K) => words[key] ?? String(key).replaceAll("_", " ")
const sentence = (text: string) => text ? text.charAt(0).toUpperCase() + text.slice(1) : text
/** A capability's name as a heading; a code name such as io_uring keeps its case. */
const capabilityHeading = (capability: Capability) => {
  const name = named(CAPABILITY, capability)
  return /^[a-z]+_/.test(name) ? name : sentence(name)
}
const short = (digest: Digest) => `${String(digest).slice(0, 12)}…`
const bytes = (value: number) => formatBytesFromGb(value / 1024 ** 3)
const millis = (duration: Duration) => duration.secs * 1000 + duration.nanos / 1e6
const NANOS_PER_MS = 1e6

/** A span of time in plain words, rounded to what a person can use. */
function durationText(ms: number) {
  if (!Number.isFinite(ms) || ms < 0) return "an unknown time"
  if (ms < 1000) return ms === 0 ? "0 s" : "under 1 s"
  const seconds = Math.round(ms / 1000)
  if (seconds < 60) return `${seconds} s`
  const minutes = Math.floor(seconds / 60)
  if (minutes < 60) return seconds % 60 ? `${minutes} min ${seconds % 60} s` : `${minutes} min`
  const hours = Math.floor(minutes / 60)
  return minutes % 60 ? `${hours} h ${minutes % 60} min` : `${hours} h`
}

function problemText(problem: InventoryProblem) {
  if (problem.problem === "malformed_gpu_row") return `GPU row ${problem.row} is malformed`
  return named(PROBLEM, problem.problem)
}

function subjectText(subject: Subject, machine?: Digest) {
  switch (subject.kind) {
    case "gpu_device": return `GPU ${short(subject.device)}${machine && subject.machine !== machine ? ` on machine ${short(subject.machine)}` : ""}`
    case "runtime": return `${named(BACKEND, subject.release.backend)} ${subject.release.version} runtime ${short(subject.instance)}, ${named(CATEGORY, subject.category)}`
    case "host": return `machine ${short(subject.machine)}`
    default: return String(subject.kind).replaceAll("_", " ")
  }
}

function detailText(detail: SupportDetail) {
  switch (detail.kind) {
    case "gpu_memory": return `${bytes(detail.free_bytes)} free of ${bytes(detail.total_bytes)}`
    case "compute_platform": return detail.platform === "cpu" ? "the CPU only" : detail.platform === "cuda" ? "CUDA on an NVIDIA GPU" : "Apple Metal"
    case "runtime_category": return named(CATEGORY, detail.category)
    case "peer_topology": return `${detail.device_count} GPUs; ${detail.paths.length ? detail.paths.map(path => `${path.from} to ${path.to} over ${named(LINK, path.link)}, ${path.access}`).join("; ") : "no peer paths"}`
    case "hypervisor": return named(HYPERVISOR, detail.hypervisor)
    default: return ""
  }
}

function resultText(result: ObservationResult) {
  switch (result.outcome) {
    case "supported": {
      const detail = detailText(result.detail)
      return detail ? `supported: ${detail}` : "supported"
    }
    case "unsupported": return `unsupported: ${named(UNSUPPORTED, result.reason)}`
    case "unknown": return `unknown: ${named(UNKNOWN, result.reason)}`
    default: return "not known"
  }
}

function remedyText(remedy: Remedy) {
  if (remedy.action === "obtain_stronger_evidence") return `obtain evidence from a ${named(SOURCE, remedy.required)} or a stronger source`
  return named(REMEDY, remedy.action)
}

/** A refusal in the engine's words, without the remedy, which is shown on its own. */
function refusalText(refusal: EvidenceRefusal) {
  const capability = named(CAPABILITY, refusal.capability)
  switch (refusal.refusal) {
    case "missing": return `there is no ${capability} evidence for this subject`
    case "source_too_weak": return refusal.required === "host_probe"
      ? `${capability} needs a host probe, and a ${named(SOURCE, refusal.observed)} never satisfies a host-only requirement`
      : `${capability} needs evidence from a ${named(SOURCE, refusal.required)} or a stronger source, but this evidence is a ${named(SOURCE, refusal.observed)}`
    case "fingerprint_changed": return `the configuration changed after ${capability} was checked, so that evidence no longer applies`
    case "stale": {
      const { staleness } = refusal
      if (staleness.kind === "too_old") return `the ${capability} evidence is ${durationText(millis(staleness.age))} old, beyond its ${durationText(millis(staleness.limit))} limit`
      if (staleness.kind === "other_clock") return `the ${capability} evidence was recorded on another clock, such as before a restart`
      return `the ${capability} evidence is dated after the current time`
    }
    case "unsupported": return `${capability} is not supported: ${named(UNSUPPORTED, refusal.reason)}`
    case "unknown": return `${capability} is unknown because ${named(UNKNOWN, refusal.reason)}, and an inconclusive check never passes`
    default: return "the evidence cannot be used"
  }
}

/** The engine's clock at the reading, when the status lets us know it. */
function readingTime(status: EvidenceStatus) {
  const { inventory, inventoryAgeMs } = status
  return inventory && typeof inventoryAgeMs === "number" ? inventory.startedAt + inventoryAgeMs * NANOS_PER_MS : null
}

function freshnessText(entry: StatusEntry, now: number | null) {
  const evidence = entry.evidence
  if (!evidence) return "No observation yet"
  const fresh = `fresh for ${durationText(millis(evidence.fresh_for))} after it was observed`
  if (now === null || now < evidence.observed_at) return sentence(fresh)
  return `Observed ${durationText((now - evidence.observed_at) / NANOS_PER_MS)} before this reading; ${fresh}`
}

function configurationText(entry: StatusEntry) {
  const observed = entry.evidence?.configuration
  if (!entry.configuration) return observed ? `None in force yet; observed under ${short(observed)}` : "None in force yet"
  if (observed && observed !== entry.configuration) return `${short(entry.configuration)} in force; observed under ${short(observed)}`
  return `${short(entry.configuration)}, the one in force`
}

function verdictText(verdict: Verdict) {
  switch (verdict.verdict) {
    case "satisfied": return "The latest observation meets the requirement: a strong enough source, fresh, and under the configuration in force."
    case "refused": return `${sentence(refusalText(verdict.refusal))}.`
    case "not_collected": return "No inventory has been collected, so no configuration is known to require."
    default: return "Not known."
  }
}

function Entry({ entry, now, machine }: { entry: StatusEntry; now: number | null; machine?: Digest }) {
  const titleId = useId()
  const subject = subjectText(entry.subject, machine)
  const verdict = entry.verdict
  return <article aria-labelledby={titleId} className="space-y-1 rounded-lg border px-3 py-2">
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h4 id={titleId} className="text-sm font-semibold">{capabilityHeading(entry.capability)}: {subject}</h4>
      <span className="text-xs font-medium">{named(VERDICT, verdict.verdict)}</span>
    </div>
    <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
      <dt className="text-muted-foreground">Subject</dt><dd>{subject}</dd>
      <dt className="text-muted-foreground">Source</dt><dd>{entry.evidence ? sentence(named(SOURCE, entry.evidence.source)) : "None yet"}</dd>
      <dt className="text-muted-foreground">Observed</dt><dd>{entry.evidence ? sentence(resultText(entry.evidence.result)) : "Not yet"}</dd>
      <dt className="text-muted-foreground">Freshness</dt><dd>{freshnessText(entry, now)}</dd>
      <dt className="text-muted-foreground">Configuration</dt><dd>{configurationText(entry)}</dd>
      <dt className="text-muted-foreground">Verdict</dt><dd>{verdictText(verdict)}</dd>
      {verdict.verdict === "refused" ? <><dt className="text-muted-foreground">Remedy</dt><dd>
        {sentence(remedyText(verdict.remedy))}.{RERUN.has(verdict.remedy.action) ? " A refresh observes it again." : ""}
      </dd></> : null}
    </dl>
  </article>
}

function gpuText(gpu: GpuDevice) {
  const compute = gpu.computeCapability ? `compute capability ${gpu.computeCapability}` : "compute capability not reported"
  return `GPU ${short(gpu.device)}: driver ${gpu.driverVersion}, ${compute}, ${named(DRIVER_MODEL, gpu.driverModel)}, ${named(MIG, gpu.mig)}; ${bytes(gpu.freeBytes)} free of ${bytes(gpu.totalBytes)}, ${bytes(gpu.usedBytes)} used`
}

function cudaText(cuda: CudaRuntimeFacts | null) {
  if (!cuda) return "Not reported on this computer."
  if (!cuda.supported) return "This computer does not meet its prerequisites."
  const state = !cuda.installed ? "Supported, not installed" : cuda.running ? "Installed and running" : "Installed, not running"
  return `${state}.${cuda.updateAvailable ? " An update is available." : ""}`
}

function osText(inventory: HostInventory) {
  const os = inventory.os
  if (!os) return "Not read."
  return `${named(OS, os.kind)}, ${os.build ? `build ${os.build}` : "build not read"}, ${os.architecture}`
}

function Inventory({ status }: { status: EvidenceStatus }) {
  const titleId = useId()
  const { inventory } = status
  return <section aria-labelledby={titleId}>
    <h3 id={titleId} className="text-sm font-semibold">This computer as last collected</h3>
    {inventory ? <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 gap-y-0.5 text-xs">
      <dt className="text-muted-foreground">Machine</dt>
      <dd>{inventory.machine.state === "known" ? `Named by the digest ${short(inventory.machine.machine)}; its raw identity never leaves the engine.` : `Unavailable: ${problemText(inventory.machine.problem)}. No GPU can be named without it.`}</dd>
      <dt className="text-muted-foreground">Operating system</dt><dd>{osText(inventory)}</dd>
      <dt className="text-muted-foreground">NVIDIA GPUs</dt>
      <dd>{inventory.gpus.state === "unavailable" ? `Not read: ${problemText(inventory.gpus.problem)}.`
        : inventory.gpus.devices.length ? <ul aria-label="NVIDIA GPUs found" className="space-y-0.5">{inventory.gpus.devices.map(gpu => <li key={gpu.device}>{gpuText(gpu)}</li>)}</ul>
          : "None found."}</dd>
      <dt className="text-muted-foreground">CUDA runtime</dt><dd>{cudaText(inventory.cudaRuntime)}</dd>
      <dt className="text-muted-foreground">Collected</dt><dd>{typeof status.inventoryAgeMs === "number" ? `${durationText(status.inventoryAgeMs)} before this reading.` : "At an unknown time."}</dd>
    </dl> : <p className="mt-1 text-xs">No inventory has been collected since the engine started. A refresh runs the queries once.</p>}
  </section>
}

/** One `status` answer: the inventory, every observed capability, and what is left to others. */
export function HostEvidenceStatusView({ status }: { status: EvidenceStatus }) {
  const observedId = useId()
  const uncoveredId = useId()
  const unboundId = useId()
  const now = readingTime(status)
  const machine = status.inventory?.machine.state === "known" ? status.inventory.machine.machine : undefined
  const uncovered = status.uncovered ?? []
  const unbound = status.unboundRuntimes ?? []
  return <div className="space-y-3">
    <Inventory status={status} />
    <section aria-labelledby={observedId} className="space-y-2">
      <h3 id={observedId} className="text-sm font-semibold">Observed capabilities</h3>
      {status.entries.length ? <>
        <p className="text-xs text-muted-foreground">Verdicts are as of this reading.</p>
        {status.entries.map((entry, index) => <Entry key={`${entry.capability}-${index}`} entry={entry} now={now} machine={machine} />)}
      </> : <p className="text-xs">{status.inventory
        ? "The last collection named no GPU, and no local runtime is bound, so nothing is observed here."
        : "Nothing is observed until an inventory is collected."}</p>}
    </section>
    {unbound.length ? <section aria-labelledby={unboundId} className="space-y-1">
      <h3 id={unboundId} className="text-sm font-semibold">Running local runtimes not bound</h3>
      <p className="text-xs text-muted-foreground">The model runner is running these but could not bind them to this evidence, so their compute platform, category and GPUs are not observed here.</p>
      <ul aria-label="Running local runtimes not bound" className="space-y-1 text-xs">
        {unbound.map(item => <li key={item.environmentId}>
          <span className="font-medium">{item.environmentId}</span>: {item.reason}
        </li>)}
      </ul>
    </section> : null}
    <section aria-labelledby={uncoveredId} className="space-y-1">
      <h3 id={uncoveredId} className="text-sm font-semibold">Left to other tasks</h3>
      <p className="text-xs text-muted-foreground">This computer's queries do not observe these capabilities, or these parts of them. Each waits for the open task named; until then it is not tested here.</p>
      {uncovered.length ? <details className="text-xs">
        <summary className="cursor-pointer">{uncovered.length} capabilities</summary>
        <ul aria-label="Capabilities left to other tasks" className="mt-1 space-y-1">
          {uncovered.map((item, index) => <li key={`${item.capability}-${index}`}>
            <span className="font-medium">{capabilityHeading(item.capability)}</span> ({item.scope}): open task {item.openTask}. {item.reason}
          </li>)}
        </ul>
      </details> : <p className="text-xs">None.</p>}
    </section>
  </div>
}

function QueryView({ query }: { query: QueryDescription }) {
  return <li className="space-y-0.5 rounded-md border px-2 py-1 text-xs">
    <p><span className="font-medium">{named(QUERY, query.query)}</span>: {query.purpose}</p>
    {query.reads ? <>
      <p>Reads <code>{[query.reads, ...query.arguments].join(" ")}</code></p>
      <p className="text-muted-foreground">Stopped after {durationText(query.timeoutMs)} or {query.maxOutputBytes.toLocaleString("en-US")} bytes of output.</p>
    </> : <p className="text-muted-foreground">Not available on this platform; a refresh records it as such and runs nothing for it.</p>}
  </li>
}

/** The queries a refresh would run on this computer, without running any. */
export function HostEvidencePlanView({ plan }: { plan: HostEvidencePlan }) {
  const titleId = useId()
  return <section aria-labelledby={titleId} className="space-y-2">
    <h3 id={titleId} className="text-sm font-semibold">Queries a refresh would run</h3>
    <p className="text-xs text-muted-foreground">Each is started directly, without a shell or a window, and only reads. Listing them runs none.</p>
    <ol aria-label="Planned queries" className="space-y-1">{plan.queries.map(query => <QueryView key={query.query} query={query} />)}</ol>
  </section>
}

function RefreshReport({ report }: { report: HostEvidenceRefresh["refresh"] }) {
  if (report.superseded) return <p>A newer collection was already in force, so this one was not installed.</p>
  return <>
    <p>Refreshed: {report.observed} {report.observed === 1 ? "observation" : "observations"} made; {report.droppedEvidence} earlier {report.droppedEvidence === 1 ? "observation" : "observations"} dropped ({report.removedSubjects} {report.removedSubjects === 1 ? "subject" : "subjects"} gone, {report.changedConfigurations} {report.changedConfigurations === 1 ? "configuration" : "configurations"} changed).</p>
    {report.refused.length ? <ul aria-label="Observations the registry refused" className="ml-4 list-disc">
      {report.refused.map(([capability, why], index) => <li key={`${capability}-${index}`}>{capabilityHeading(capability)}: {why}</li>)}
    </ul> : null}
  </>
}

type Trouble = { unavailable: boolean; text: string }
const trouble = (reason: unknown): Trouble => ({
  unavailable: isHostEvidenceUnavailable(reason),
  text: reason instanceof Error ? reason.message : String(reason),
})

function TroubleText({ value }: { value: Trouble }) {
  return value.unavailable
    ? <p role="status" className="text-xs text-muted-foreground">{value.text}</p>
    : <p role="alert" className="text-xs text-destructive">{value.text}</p>
}

/** Host evidence as a panel: it reads the status when shown, which runs nothing; the plan is read
 *  only when opened; a refresh runs the queries once, after the user confirms it. */
export function HostEvidence() {
  const titleId = useId()
  const planId = useId()
  const confirmId = useId()
  const [revision, setRevision] = useState(0)
  const [status, setStatus] = useState<EvidenceStatus | null>(null)
  const [reading, setReading] = useState(true)
  const [problem, setProblem] = useState<Trouble | null>(null)
  const [confirming, setConfirming] = useState(false)
  const [refreshing, setRefreshing] = useState(false)
  const [report, setReport] = useState<HostEvidenceRefresh["refresh"] | null>(null)
  const [refreshProblem, setRefreshProblem] = useState<Trouble | null>(null)
  const [planOpen, setPlanOpen] = useState(false)
  const [plan, setPlan] = useState<HostEvidencePlan | null>(null)
  const [planProblem, setPlanProblem] = useState<Trouble | null>(null)

  useEffect(() => {
    let active = true
    setReading(true)
    setProblem(null)
    hostEvidenceApi.status()
      .then(next => { if (active) setStatus(next) })
      .catch(reason => { if (active) setProblem(trouble(reason)) })
      .finally(() => { if (active) setReading(false) })
    return () => { active = false }
  }, [revision])

  useEffect(() => {
    if (!planOpen) return
    let active = true
    setPlan(null)
    setPlanProblem(null)
    hostEvidenceApi.plan()
      .then(next => { if (active) setPlan(next) })
      .catch(reason => { if (active) setPlanProblem(trouble(reason)) })
    return () => { active = false }
  }, [planOpen])

  const refresh = async () => {
    setConfirming(false)
    setRefreshing(true)
    setReport(null)
    setRefreshProblem(null)
    try {
      const answer = await hostEvidenceApi.refresh()
      setStatus(answer.status)
      setProblem(null)
      setReport(answer.refresh)
    } catch (reason) {
      setRefreshProblem(trouble(reason))
    } finally {
      setRefreshing(false)
    }
  }

  const unavailable = !!problem?.unavailable
  return <section aria-labelledby={titleId} aria-busy={reading || refreshing} className="space-y-3 rounded-lg border px-4 py-3">
    <div className="space-y-1">
      <h2 id={titleId} className="text-sm font-semibold">Host evidence</h2>
      <p className="text-xs text-muted-foreground">What Yougori's host queries last observed about this computer, how fresh it is, and what other checks still owe. Reading it runs nothing.</p>
    </div>
    <div className="flex flex-wrap items-center gap-3">
      <Button type="button" size="xs" variant="outline" disabled={reading || refreshing || confirming || unavailable} loading={refreshing} aria-expanded={confirming} aria-controls={confirming ? confirmId : undefined} onClick={() => setConfirming(true)}>Refresh…</Button>
      <Button type="button" size="xs" variant="ghost" aria-expanded={planOpen} aria-controls={planOpen ? planId : undefined} onClick={() => setPlanOpen(open => !open)}>{planOpen ? "Hide the queries" : "Show the queries"}</Button>
      {problem && !problem.unavailable ? <Button type="button" size="xs" variant="ghost" disabled={reading} onClick={() => setRevision(value => value + 1)}>Read again</Button> : null}
    </div>
    {confirming ? <div id={confirmId} role="group" aria-labelledby={`${confirmId}-title`} className="space-y-2 rounded-md border px-3 py-2 text-xs">
      <p id={`${confirmId}-title`} className="font-medium">Refresh the host evidence now?</p>
      <p>This runs bounded, read-only host queries once: the machine identity, the operating system build and the NVIDIA GPU inventory. Each is started directly, without a shell, with a deadline and an output bound, and is stopped if it exceeds either. Nothing on this computer is changed.</p>
      <div className="flex gap-2">
        <Button type="button" size="xs" onClick={() => void refresh()}>Run the queries</Button>
        <Button type="button" size="xs" variant="ghost" onClick={() => setConfirming(false)}>Cancel</Button>
      </div>
    </div> : null}
    {refreshing ? <p role="status" className="text-xs text-muted-foreground">Running the host queries…</p> : null}
    {report ? <div role="status" className="space-y-1 text-xs"><RefreshReport report={report} /></div> : null}
    {refreshProblem ? <TroubleText value={refreshProblem} /> : null}
    {reading && !status ? <p role="status" className="text-xs text-muted-foreground">Reading the host evidence…</p> : null}
    {problem ? <TroubleText value={problem} /> : null}
    {status ? <HostEvidenceStatusView status={status} /> : null}
    {planOpen ? <div id={planId}>
      {plan ? <HostEvidencePlanView plan={plan} />
        : planProblem ? <TroubleText value={planProblem} />
          : <p role="status" className="text-xs text-muted-foreground">Reading the plan…</p>}
    </div> : null}
  </section>
}
