import { run } from "@/api/platform-api"

/** The engine's VM sandbox doctor, the desktop command `sandbox_doctor`: which VM backends this
 *  computer could run sandboxes on, the boundary report of each for the run profiles asked, its
 *  section 7.1 label, every check that did not pass with its reason and what it expects here, what
 *  changed since the previous report, and a plan of every check. Nothing it answers runs a check,
 *  starts a VM or changes the computer; the engine keeps only its own previous reports, across
 *  restarts.
 *
 *  The types follow the engine's serialized `sandbox::doctor` report and plan, field for field. A
 *  report is never made up here: a browser preview, or a build without the command, says so. */

export type OsKind = "windows" | "linux" | "macos" | "wsl2"
export type Architecture = "x86_64" | "aarch64"
export type BackendKind = "fake" | "firecracker" | "qemu" | "cloud_hypervisor" | "hcs" | "virtualization_framework"
/** The run profiles whose "must for" checks a host must pass. Strict is examined when none is asked. */
export type RunProfile = "strict" | "transport" | "pool" | "gpu_vm" | "remote" | "confidential" | "drill" | "release" | "research"
/** A backend's standing on this host, in section 7.1's words: until validated, it is experimental or
 *  unavailable. */
export type DoctorLabel = "validated" | "experimental" | "unavailable"
/** Why a backend is examined: the one the plan names first for this operating system, the one used
 *  when that is not available, or a further profile the plan keeps. */
export type CandidateRole = "primary" | "fallback" | "alternative"
/** A check of the boundary table, `VM-CP-01` to `VM-CP-35`. */
export type CheckId = string
/** A scenario family, `VM-P01` to `VM-P50`. */
export type ScenarioFamily = string
/** The name of one expected observation, such as `cp01.accelerator`. */
export type ExpectationId = string
export type Facet = "isolation" | "hypervisor_confinement" | "network_authority" | "credential_exposure" | "persistence" | "device_exposure" | "operator_confidentiality" | "evidence"
export type CorroboratingFact = "booted_root_image" | "kernel_build_record" | "no_guest_network_device" | "clone_identities" | "pre_snapshot_approval_refused"
export type SourceKind = "host" | "guest" | "controlled_external"
export type TestTier = "process_integration" | "disposable_vm" | "hardware_or_provider" | "independent_assessment"
/** Which part of a check an outcome is about: its own observation, or a host fact corroborating it. */
export type Part = { part: "primary" } | { part: "corroboration"; fact: CorroboratingFact }

export interface HostBuild { os: OsKind; build: string; architecture: Architecture }
/** A Rust `Duration` as the engine serializes it. */
export interface Duration { secs: number; nanos: number }

export type Staleness = { kind: "too_old"; age: Duration; limit: Duration } | { kind: "other_clock" } | { kind: "observed_after_now" }
export type ObservationProblem =
  | { problem: "other_configuration"; observed_under: string; current: string }
  | { problem: "stale"; staleness: Staleness }
export type NotTestedReason =
  | { reason: "not_run" }
  | { reason: "unavailable_hardware" }
  | { reason: "needs_tier"; tier: TestTier }
  | { reason: "no_observation_for_host"; os: OsKind }
export type RunnerInconclusive = "timed_out" | "unreachable" | "interrupted"
export type ObservationError =
  | { error: "wrong_kind"; expected: string; found: string }
  | { error: "too_few_identities"; found: number }
/** One check of the VM-CP-05 confinement verdict, such as `{ check: "no_new_privs" }`. */
export interface ConfinementCheck { check: string; [detail: string]: unknown }
export type Failure = { failed: "expectation"; id: ExpectationId; part: Part } | { failed: "confinement"; check: ConfinementCheck }
export type InconclusiveReason =
  | { inconclusive: "runner"; part: Part; reason: RunnerInconclusive }
  | { inconclusive: "missing_observation"; id: ExpectationId }
  | { inconclusive: "inconsistent_observation"; id: ExpectationId; error: ObservationError }
  | { inconclusive: "guest_skipped"; id: ExpectationId }
  | { inconclusive: "guest_inconclusive"; id: ExpectationId }
  | { inconclusive: "no_positive_control"; id: ExpectationId }
  | { inconclusive: "control_failed"; id: ExpectationId }
  | { inconclusive: "confinement"; check: ConfinementCheck }
  | { inconclusive: "confinement_verdict_inconsistent" }
export type CheckRefusal =
  | { refusal: "wrong_source"; part: Part; required: SourceKind; found: SourceKind }
  | { refusal: "not_current"; part: Part; problem: ObservationProblem }
  | { refusal: "uncorroborated"; fact: CorroboratingFact }
  | { refusal: "other_check" }
  | { refusal: "duplicate_part"; part: Part }
  | { refusal: "guest_reported_only" }
/** The status of one check. Only `passed` passes: inconclusive and not tested never do. */
export type CheckStatus =
  | { status: "passed" }
  | { status: "failed"; failure: Failure }
  | { status: "inconclusive"; reason: InconclusiveReason }
  | { status: "not_tested"; reason: NotTestedReason }
  | { status: "refused"; refusal: CheckRefusal }

/** The kind of a check's status. */
export type StatusKind = CheckStatus["status"]
/** A check's status with its reason, in the engine's own words, such as "not tested: it was not run". */
export interface StatusText { status: StatusKind; reason: string }
/** A check that did not pass on this computer: its status and reason in the engine's words, and what
 *  it expects here, its positive control included, in the plan's words. */
export interface CheckExplanation extends StatusText {
  check: CheckId
  /** Whether the run profiles refuse to start until it passes. */
  required: boolean
  expects: PlannedObservation[]
}

/** How many checks have each status. */
export interface StatusCounts { passed: number; failed: number; inconclusive: number; not_tested: number; refused: number }
/** One backend examined on this host, with the plan's reason in its words. */
export interface Candidate { backend: BackendKind; role: CandidateRole; basis: string }
export interface CheckEntry { check: CheckId; families: ScenarioFamily[]; applicability: "required" | "not_required"; status: CheckStatus }
/** A facet that a required check which did not pass leaves unsatisfied. */
export interface UnsatisfiedFacet { facet: Facet; because: CheckId[] }
/** The GPU VM path of the run profiles: asked for or not, and when unavailable, why. */
export type GpuPath = { gpu: "not_requested" } | { gpu: "available" } | { gpu: "unavailable"; status: CheckStatus; why: string }
/** The boundary report of one backend on this host: every check with its status. */
export interface BoundaryReport {
  identity: string
  notice: string
  profile: { host: HostBuild; backend: BackendKind; profiles: RunProfile[] }
  configuration: string
  clock: string
  assembled_at: number
  max_age: Duration
  entries: CheckEntry[]
  unsatisfied: UnsatisfiedFacet[]
  gpu: GpuPath
}
export interface CandidateReport {
  candidate: Candidate
  label: DoctorLabel
  /** The checks the run profiles require, by status. */
  required: StatusCounts
  /** Every check, by status. */
  all: StatusCounts
  /** The required checks that did not pass, in check order: the run profiles refuse to start
   *  while any remains. */
  blocking: CheckId[]
  /** Every check that did not pass, required or not, in check order, in the engine's words. */
  not_passed: CheckExplanation[]
  report: BoundaryReport
}
/** One check whose status changed since the previous report, both in the engine's words. */
export interface StatusChange { check: CheckId; before: StatusText; after: StatusText }
export interface BackendChanges { configuration_changed: boolean; launch_allowed_before: boolean; launch_allowed_now: boolean; checks: StatusChange[] }
/** What changed for one backend since its previous report. */
export type DoctorChange =
  | { change: "report"; backend: BackendKind; changes: BackendChanges }
  | { change: "host"; backend: BackendKind; before: HostBuild; after: HostBuild }
/** What the examination was compared with, and whether the engine kept it for the next one. Each
 *  text is a whole sentence from the engine. */
export interface DoctorHistory {
  /** The backends whose previous report this one was compared with. */
  compared: BackendKind[]
  /** Why the previous reports the engine kept were ignored: they could not be read or were damaged. */
  ignored: string | null
  /** Why this report could not be kept for the next examination. */
  not_kept: string | null
}
export interface DoctorReport {
  notice: string
  host: HostBuild
  profiles: RunProfile[]
  /** How many check results the examination was given. */
  results: number
  /** Why this host has no candidate backend, when it has none. */
  no_backend: string | null
  candidates: CandidateReport[]
  changes: DoctorChange[]
  history: DoctorHistory
}
/** `status`: the report, or why the engine has not examined this computer and what to do first. */
export type DoctorStatus =
  | { examined: true; checkRunner?: string | null; report: DoctorReport }
  | { examined: false; reason: string; next?: string | null }

/** A check's side and source, as the boundary table's column names it. */
export type Side =
  | { side: "host_observed" | "host_observed_with_stated_coverage" | "host_observed_on_gpu_hardware" | "controlled_external" | "remote_and_host" | "research_tier" | "end_to_end" }
  | { side: "guest_reported_with_host_corroboration"; corroboration: CorroboratingFact[] }
/** A remark of the plan where a check lists no positive control. */
export type PlanNote = "golden_file_versioned_with_backend" | "target_not_guarantee" | "unsupported_reset_falls_back_to_cold_boot"
/** One observation a check would make on this host, with what the plan expects in its words. */
export type PlannedObservation = { id: ExpectationId; role: "observation" | "positive_control"; says: string } & Part
export interface PlannedCheck {
  check: CheckId
  families: ScenarioFamily[]
  side: Side
  /** Whether the run profiles refuse to start without it. */
  required: boolean
  /** Whether it can run on this host's operating system at all. */
  runs_here: boolean
  /** What its positive control must show, when the plan lists one. */
  control: string | null
  note: PlanNote | null
  /** The observations that apply on this host, its positive control included. */
  observes: PlannedObservation[]
}
/** `plan`: every check as it would run on this host, without running any. */
export interface DoctorPlan { notice: string; os: OsKind; profiles: RunProfile[]; checks: PlannedCheck[] }

/** The command is not in this build of Yougori, or this is not the desktop app. */
export class DoctorUnavailableError extends Error {
  constructor(message = "This build of Yougori can't show the VM sandbox doctor yet.") {
    super(message)
    this.name = "DoctorUnavailableError"
  }
}

export const isDoctorUnavailable = (reason: unknown): reason is DoctorUnavailableError => reason instanceof DoctorUnavailableError

/** Tauri's own refusal of a command this build does not register, or does not allow. */
const MISSING = /^\s*command \S+ not (?:found|allowed)\b/i
const AGAIN = "Yougori could not read the VM sandbox doctor. Try again."

/** Keeps the engine's sentence (an unknown run profile, say) and reads a missing command as
 *  unavailable, never as a failure of the computer. */
export function doctorError(reason: unknown): Error {
  if (reason instanceof DoctorUnavailableError) return reason
  const text = reason instanceof Error ? reason.message : typeof reason === "string" ? reason : ""
  if (MISSING.test(text)) return new DoctorUnavailableError()
  return new Error(text.trim() || AGAIN)
}

async function ask<T>(action: "status" | "plan", profiles?: readonly RunProfile[]): Promise<T> {
  try {
    // A browser preview has no computer to examine, so it answers nothing rather than a made-up report.
    return await run<T>("sandbox_doctor", { action, profiles: profiles?.length ? [...profiles] : null }, () => {
      throw new DoctorUnavailableError("The VM sandbox doctor needs Yougori Desktop.")
    })
  } catch (reason) {
    throw doctorError(reason)
  }
}

export const sandboxDoctorApi = {
  /** Examines this computer for the run profiles given (strict when none). */
  status: (profiles?: readonly RunProfile[]) => ask<DoctorStatus>("status", profiles),
  /** Describes every check for this computer and the run profiles given, without running any. */
  plan: (profiles?: readonly RunProfile[]) => ask<DoctorPlan>("plan", profiles),
}
