import { Fragment, useEffect, useId, useState } from "react"
import {
  isDoctorUnavailable, sandboxDoctorApi,
  type BackendKind, type CandidateReport, type CandidateRole, type CheckExplanation, type CorroboratingFact, type DoctorChange,
  type DoctorLabel, type DoctorPlan, type DoctorStatus, type HostBuild, type OsKind, type PlanNote, type PlannedCheck,
  type PlannedObservation, type RunProfile, type Side, type StatusKind, type StatusText,
} from "@/api/sandbox-doctor-api"
import { Button } from "@/components/ui/button"

/** The VM sandbox doctor of this computer (VM-W23): which VM backends it could run sandboxes on,
 *  each one's section 7.1 label, its required boundary checks by status, the checks that block its
 *  run profiles, why and what each expects here, the GPU VM path when one is asked for, what changed
 *  since the previous report (which the engine keeps across restarts), and a plan of every check.
 *  The same report `yougori doctor` summarizes.
 *
 *  Nothing here runs a check, starts a VM or changes the computer. Every status reason, every
 *  check's expectations, the GPU VM path and the history notes are the engine's own sentences, shown
 *  as it sends them: a backend is validated, experimental or unavailable, never scored, and not
 *  tested is never a pass. */

const OS: Record<OsKind, string> = { windows: "Windows", linux: "Linux", macos: "macOS", wsl2: "WSL2" }
const BACKEND: Record<BackendKind, string> = {
  fake: "Fake backend", firecracker: "Firecracker", qemu: "QEMU", cloud_hypervisor: "Cloud Hypervisor",
  hcs: "Host Compute Service (HCS)", virtualization_framework: "Virtualization.framework",
}
const ROLE: Record<CandidateRole, string> = { primary: "Primary", fallback: "Fallback", alternative: "Alternative" }
const PROFILE: Record<RunProfile, string> = {
  strict: "strict", transport: "transport", pool: "pool", gpu_vm: "GPU VM", remote: "remote",
  confidential: "confidential", drill: "drill", release: "release", research: "research",
}
/** Section 7.1: "Until validated, label it experimental or unavailable." */
const LABEL: Record<DoctorLabel, { name: string; means: string }> = {
  validated: { name: "Validated", means: "Every check its run profiles require passed on this computer." },
  experimental: { name: "Experimental", means: "Some required checks passed and none failed or was refused; the others are still open." },
  unavailable: { name: "Unavailable", means: "No required check has passed on this computer yet, or one failed or was refused." },
}
const COUNTS: { key: StatusKind; name: string }[] = [
  { key: "passed", name: "Passed" }, { key: "failed", name: "Failed" }, { key: "inconclusive", name: "Inconclusive" },
  { key: "not_tested", name: "Not tested" }, { key: "refused", name: "Refused" },
]
/** A status kind's name, for a check the engine sent no sentence for. */
const STATUS = Object.fromEntries(COUNTS.map(({ key, name }) => [key, name])) as Record<StatusKind, string>
const FACT: Record<CorroboratingFact, string> = {
  booted_root_image: "the booted root image digest matching the signed manifest",
  kernel_build_record: "the kernel build record (CONFIG_IO_URING absent) matching the signed manifest",
  no_guest_network_device: "no packet from the VM, because it has no network device",
  clone_identities: "distinct generation and boot ids of the two clones",
  pre_snapshot_approval_refused: "a pre-snapshot approval refused in both clones by the host's executor",
}
const SIDE: Record<Side["side"], string> = {
  host_observed: "host-observed", host_observed_with_stated_coverage: "host-observed with stated coverage",
  host_observed_on_gpu_hardware: "host-observed on GPU hardware", guest_reported_with_host_corroboration: "guest-reported plus host corroboration",
  controlled_external: "controlled external", remote_and_host: "remote and host", research_tier: "research tier", end_to_end: "end to end",
}
const NOTE: Record<PlanNote, string> = {
  golden_file_versioned_with_backend: "The golden file is versioned with the backend.",
  target_not_guarantee: "The engineering target of section 6.5 is reported as a target, not a guarantee.",
  unsupported_reset_falls_back_to_cold_boot: "An unsupported reset falls back to cold boot, and the record says so.",
}
const GPU_PROFILES: readonly RunProfile[] = ["strict", "gpu_vm"]

/** A word from one of the tables above, or the engine's own name when this build has no word for it. */
const named = <K extends string>(words: Record<K, string>, key: K) => words[key] ?? String(key).replaceAll("_", " ")
const sentence = (text: string) => text ? text.charAt(0).toUpperCase() + text.slice(1) : text
/** The engine's sentence as a whole sentence: capitalized, with its closing period. */
const whole = (text: string) => { const said = sentence(text.trim()); return /[.!?]$/.test(said) ? said : `${said}.` }
const hostText = (host: HostBuild) => `${named(OS, host.os)} ${host.build} (${host.architecture})`
const profilesText = (profiles: RunProfile[]) => profiles.map(profile => named(PROFILE, profile)).join(", ") || "none"
/** A status in the engine's words, or the name of its kind when the engine sent none. */
const statusText = (status: StatusText) => status.reason || named(STATUS, status.status)

/** Text from the engine, with its `command` spans shown as code. */
function Said({ text }: { text: string }) {
  return <>{text.split("`").map((piece, index) => <Fragment key={index}>{index % 2 ? <code>{piece}</code> : piece}</Fragment>)}</>
}

/** The blocking checks of a backend in the engine's words, grouped by their status reason so a long
 *  list stays readable. */
function blockingGroups(candidate: CandidateReport, explained: Map<string, CheckExplanation>) {
  const groups = new Map<string, string[]>()
  for (const check of candidate.blocking) {
    const explanation = explained.get(check)
    const entry = explanation ? undefined : candidate.report.entries.find(item => item.check === check)
    const reason = sentence(explanation ? statusText(explanation) : entry ? named(STATUS, entry.status.status) : "not in the report")
    groups.set(reason, [...(groups.get(reason) ?? []), check])
  }
  return [...groups]
}

function ExpectedObservation({ observation }: { observation: PlannedObservation }) {
  const role = observation.role === "positive_control" ? "Positive control: " : observation.part === "corroboration" ? "Host corroboration: " : ""
  return <li>{role}{observation.says}</li>
}

/** What each blocking check expects on this computer, in the plan's words, folded away until asked. */
function BlockingExpectations({ name, checks }: { name: string; checks: CheckExplanation[] }) {
  if (!checks.length) return null
  return <details className="text-xs">
    <summary className="cursor-pointer">What these checks expect on this computer</summary>
    <ul aria-label={`What the blocking checks of ${name} expect`} className="mt-1 space-y-1">
      {checks.map(check => <li key={check.check}>
        <span className="font-medium">{check.check}</span>
        {check.expects.length
          ? <ul className="ml-4 list-disc">{check.expects.map(observation => <ExpectedObservation key={observation.id} observation={observation} />)}</ul>
          : <p>No observation of it applies on this computer.</p>}
      </li>)}
    </ul>
  </details>
}

function GpuPathText({ candidate }: { candidate: CandidateReport }) {
  const gpu = candidate.report.gpu
  if (!gpu || gpu.gpu === "not_requested") return null
  return <div>
    <h5 className="text-xs font-semibold">GPU VM path</h5>
    <p className="text-xs">{gpu.gpu === "available"
      ? "Available: VM-CP-31 passed on this computer."
      : `Unavailable. ${whole(gpu.why)}`}</p>
  </div>
}

function Backend({ candidate }: { candidate: CandidateReport }) {
  const titleId = useId()
  const name = named(BACKEND, candidate.candidate.backend)
  const label = LABEL[candidate.label] ?? LABEL.unavailable
  const required = COUNTS.reduce((total, { key }) => total + (candidate.required[key] ?? 0), 0)
  const explained = new Map((candidate.not_passed ?? []).map(item => [item.check, item] as const))
  const groups = blockingGroups(candidate, explained)
  const expecting = candidate.blocking.flatMap(check => explained.get(check) ?? [])
  const unsatisfied = candidate.report.unsatisfied ?? []
  return <article aria-labelledby={titleId} className="space-y-2 rounded-lg border px-3 py-2">
    <div className="flex flex-wrap items-baseline justify-between gap-2">
      <h4 id={titleId} className="text-sm font-semibold">{name}</h4>
      <span className="text-xs text-muted-foreground">{named(ROLE, candidate.candidate.role)} · <span className="font-medium text-foreground">{label.name}</span></span>
    </div>
    <p className="text-xs">{label.means}</p>
    {candidate.candidate.basis ? <p className="text-xs text-muted-foreground">Why it is examined: {candidate.candidate.basis}</p> : null}
    <p className="text-xs">{candidate.required.passed} of {required} required boundary checks passed.</p>
    <dl aria-label={`Required checks of ${name} by status`} className="grid grid-cols-[auto_1fr] gap-x-3 text-xs">
      {COUNTS.map(({ key, name: status }) => <Fragment key={key}><dt className="text-muted-foreground">{status}</dt><dd>{candidate.required[key] ?? 0}</dd></Fragment>)}
    </dl>
    {groups.length ? <div>
      <h5 className="text-xs font-semibold">Blocking checks</h5>
      <p className="text-xs text-muted-foreground">The run profiles asked refuse to start on {name} until each of these passes on this computer.</p>
      <ul aria-label={`Blocking checks of ${name}`} className="mt-1 space-y-1 text-xs">
        {groups.map(([reason, checks]) => <li key={reason}><span className="font-medium">{reason}</span>: {checks.join(", ")}</li>)}
      </ul>
      <BlockingExpectations name={name} checks={expecting} />
    </div> : <p className="text-xs">No required check blocks the run profiles asked on {name}.</p>}
    {unsatisfied.length ? <p className="text-xs text-muted-foreground">Facets left unsatisfied: {unsatisfied.map(item => String(item.facet).replaceAll("_", " ")).join(", ")}.</p> : null}
    <GpuPathText candidate={candidate} />
  </article>
}

function Change({ change }: { change: DoctorChange }) {
  const name = named(BACKEND, change.backend)
  if (change.change === "host") return <li><span className="font-medium">{name}</span>: this computer changed from {hostText(change.before)} to {hostText(change.after)}, so earlier results say nothing about it.</li>
  if (change.change !== "report") return null
  const { changes } = change
  return <li><span className="font-medium">{name}</span>
    <ul className="ml-4 list-disc">
      {changes.configuration_changed ? <li>The host configuration changed, so earlier results no longer apply.</li> : null}
      {changes.launch_allowed_before !== changes.launch_allowed_now ? <li>{changes.launch_allowed_now
        ? "No required check blocks its run profiles now; before, one did."
        : "A required check blocks its run profiles now; before, none did."}</li> : null}
      {changes.checks.map(item => <li key={item.check}>{item.check} went from “{statusText(item.before)}” to “{statusText(item.after)}”.</li>)}
    </ul>
  </li>
}

/** One `status` answer of the doctor: the report, or why it has not examined this computer yet. */
export function DoctorReportView({ result }: { result: DoctorStatus }) {
  const titleId = useId()
  const changesId = useId()
  if (!result.examined) return <div className="space-y-1 text-xs">
    <p className="font-medium">This computer has not been examined yet.</p>
    <p>{result.reason}</p>
    {result.next ? <p><Said text={result.next} /></p> : null}
  </div>
  const { report } = result
  const boundaryNotice = report.candidates[0]?.report.notice
  const history = report.history
  return <div className="space-y-3">
    <section aria-labelledby={titleId}>
      <h3 id={titleId} className="text-sm font-semibold">This computer</h3>
      <dl className="mt-1 grid grid-cols-[auto_1fr] gap-x-3 text-xs">
        <dt className="text-muted-foreground">Operating system</dt><dd>{named(OS, report.host.os)}</dd>
        <dt className="text-muted-foreground">Build</dt><dd>{report.host.build}</dd>
        <dt className="text-muted-foreground">Architecture</dt><dd>{report.host.architecture}</dd>
        <dt className="text-muted-foreground">Run profiles</dt><dd>{profilesText(report.profiles)}</dd>
        <dt className="text-muted-foreground">Check results given</dt><dd>{report.results}</dd>
      </dl>
      {result.checkRunner ? <p className="mt-1 text-xs text-muted-foreground">{result.checkRunner}</p> : null}
    </section>
    {report.no_backend ? <p className="text-xs">{report.no_backend}</p>
      : report.candidates.length ? <div className="space-y-2">{report.candidates.map(candidate => <Backend key={candidate.candidate.backend} candidate={candidate} />)}</div>
        : <p className="text-xs">No VM backend was examined on this computer.</p>}
    <section aria-labelledby={changesId}>
      <h3 id={changesId} className="text-sm font-semibold">Since the previous report</h3>
      {history?.ignored ? <p className="text-xs">{whole(history.ignored)}</p> : null}
      {report.changes.length
        ? <ul className="mt-1 space-y-1 text-xs">{report.changes.map((change, index) => <Change key={`${change.backend}-${index}`} change={change} />)}</ul>
        : <p className="text-xs text-muted-foreground">{history?.compared?.length ? "Nothing changed since the previous report." : "There is no previous report to compare with."}</p>}
      {history?.not_kept ? <p className="text-xs">{whole(history.not_kept)}</p> : null}
    </section>
    <p className="text-xs text-muted-foreground">{report.notice}</p>
    {boundaryNotice ? <p className="text-xs text-muted-foreground">Each backend's report is {boundaryNotice}{boundaryNotice.endsWith(".") ? "" : "."}</p> : null}
  </div>
}

function PlannedCheckView({ check, os }: { check: PlannedCheck; os: OsKind }) {
  const observations = check.observes.filter(item => item.role !== "positive_control")
  const side = check.side?.side ? named(SIDE, check.side.side) : ""
  const facts = check.side?.side === "guest_reported_with_host_corroboration" ? check.side.corroboration.map(fact => named(FACT, fact)) : []
  return <details className="rounded-md border px-2 py-1 text-xs">
    <summary className="cursor-pointer">
      <span className="font-medium">{check.check}</span> · {check.required ? "required" : "not required for these run profiles"}{side ? ` · ${side}` : ""}{check.runs_here ? "" : ` · cannot run on a ${named(OS, os)} host`}
    </summary>
    <div className="mt-1 space-y-1">
      {check.families.length ? <p className="text-muted-foreground">Scenario families: {check.families.join(", ")}</p> : null}
      {facts.length ? <p>The guest's report counts only with the host observing {facts.join(" and ")}.</p> : null}
      {check.runs_here ? null : <p>The plan gives it no observation for a {named(OS, os)} host, so it cannot run on this computer.</p>}
      {observations.length ? <>
        <p>It would observe:</p>
        <ul aria-label={`What ${check.check} would observe`} className="ml-4 list-disc">
          {observations.map(item => <ExpectedObservation key={item.id} observation={item} />)}
        </ul>
      </> : <p>No observation of it applies on this computer.</p>}
      {check.control ? <p>Positive control: {check.control}</p>
        : check.note ? <p>{named(NOTE, check.note)} The plan lists no positive control.</p>
          : <p>The plan lists no positive control.</p>}
    </div>
  </details>
}

/** The doctor's plan: every check as it would run on this computer, and what it would observe. */
export function DoctorPlanView({ plan }: { plan: DoctorPlan }) {
  const titleId = useId()
  const required = plan.checks.filter(check => check.required).length
  return <section aria-labelledby={titleId} className="space-y-2">
    <h3 id={titleId} className="text-sm font-semibold">Plan of the checks</h3>
    <p className="text-xs text-muted-foreground">{plan.notice}</p>
    <p className="text-xs">For a {named(OS, plan.os)} host and the run profiles {profilesText(plan.profiles)}, {required} of {plan.checks.length} checks are required.</p>
    <ol aria-label="Planned checks" className="space-y-1">
      {plan.checks.map(check => <li key={check.check}><PlannedCheckView check={check} os={plan.os} /></li>)}
    </ol>
  </section>
}

type Trouble = { unavailable: boolean; text: string }
const trouble = (reason: unknown): Trouble => ({
  unavailable: isDoctorUnavailable(reason),
  text: reason instanceof Error ? reason.message : String(reason),
})

function TroubleText({ value }: { value: Trouble }) {
  return value.unavailable
    ? <p role="status" className="text-xs text-muted-foreground">{value.text}</p>
    : <p role="alert" className="text-xs text-destructive">{value.text}</p>
}

/** The doctor as a panel: it examines this computer when shown, and again on request, for the
 *  strict run profile or, when asked, the GPU VM profile too. The plan is read only when opened. */
export function SandboxDoctor() {
  const titleId = useId()
  const planId = useId()
  const [gpu, setGpu] = useState(false)
  const [revision, setRevision] = useState(0)
  const [status, setStatus] = useState<DoctorStatus | null>(null)
  const [checking, setChecking] = useState(true)
  const [problem, setProblem] = useState<Trouble | null>(null)
  const [planOpen, setPlanOpen] = useState(false)
  const [plan, setPlan] = useState<DoctorPlan | null>(null)
  const [planProblem, setPlanProblem] = useState<Trouble | null>(null)
  const profiles = gpu ? GPU_PROFILES : undefined

  useEffect(() => {
    let active = true
    setChecking(true)
    setProblem(null)
    setStatus(null)
    sandboxDoctorApi.status(profiles)
      .then(next => { if (active) setStatus(next) })
      .catch(reason => { if (active) setProblem(trouble(reason)) })
      .finally(() => { if (active) setChecking(false) })
    return () => { active = false }
  }, [profiles, revision])

  useEffect(() => {
    if (!planOpen) return
    let active = true
    setPlan(null)
    setPlanProblem(null)
    sandboxDoctorApi.plan(profiles)
      .then(next => { if (active) setPlan(next) })
      .catch(reason => { if (active) setPlanProblem(trouble(reason)) })
    return () => { active = false }
  }, [planOpen, profiles, revision])

  return <section aria-labelledby={titleId} aria-busy={checking} className="space-y-3 rounded-lg border px-4 py-3">
    <div className="space-y-1">
      <h2 id={titleId} className="text-sm font-semibold">VM sandbox doctor</h2>
      <p className="text-xs text-muted-foreground">Which VM backends this computer could run sandboxes on, and the boundary checks each one still needs. Looking changes no setting on this computer.</p>
    </div>
    <div className="flex flex-wrap items-center gap-3">
      <label className="flex items-center gap-2 text-xs"><input type="checkbox" checked={gpu} onChange={event => setGpu(event.target.checked)} />Include the GPU VM run profile</label>
      <Button type="button" size="xs" variant="outline" disabled={checking} onClick={() => setRevision(value => value + 1)}>{checking ? "Examining…" : "Check again"}</Button>
      <Button type="button" size="xs" variant="ghost" aria-expanded={planOpen} aria-controls={planOpen ? planId : undefined} onClick={() => setPlanOpen(open => !open)}>{planOpen ? "Hide the plan" : "Show the plan"}</Button>
    </div>
    {checking && !status ? <p role="status" className="text-xs text-muted-foreground">Examining this computer…</p> : null}
    {problem ? <TroubleText value={problem} /> : null}
    {status ? <DoctorReportView result={status} /> : null}
    {planOpen ? <div id={planId}>
      {plan ? <DoctorPlanView plan={plan} />
        : planProblem ? <TroubleText value={planProblem} />
          : <p role="status" className="text-xs text-muted-foreground">Reading the plan…</p>}
    </div> : null}
  </section>
}
