import { run } from "@/api/platform-api"

/** The engine's host evidence, the desktop command `host_evidence` (S01, CORE-01): what its
 *  bounded, read-only host queries last observed about this computer, each observed capability
 *  with its verdict and remedy, and every capability left to another task with the task that owns
 *  it. `status` and `plan` run nothing; `refresh` runs the plan's queries once.
 *
 *  The types follow the engine's serialized `host_evidence` status, plan and refresh, field for
 *  field. An answer is never made up here: a browser preview, or a build without the command, says
 *  so. */

/** A capability a typed probe adapter observes. */
export type Capability =
  | "cuda_ipc_legacy" | "cuda_ipc_vmm_shareable_handle" | "gpu_direct_storage" | "cuda_checkpoint" | "io_uring"
  | "zero_copy_preload" | "sleep_weight_offload" | "hypervisor_available" | "provider_container" | "runtime_category"
  | "cuda_vmm_allocation" | "compute_platform" | "sleep_weight_discard" | "gpu_peer_access" | "checkpoint_compatibility"
  | "gpu_free_memory" | "peer_topology" | "execute_while_load" | "perimeter_rule_enforced" | "hypervisor_configuration_matches"
  | "hypervisor_confined" | "booted_image_matches_manifest" | "destination_policy_enforced" | "no_guest_network_device"
  | "credential_absent_from_scanned_locations" | "clone_identity_reset" | "device_assignment_isolated" | "kv_growth" | "adapter_limits"
/** Where an observation came from, weakest first: a guest can fabricate its report, and a fixture
 *  never certifies a real backend. */
export type SourceClass = "fixture" | "recorded_declaration" | "guest_report" | "provider_api" | "host_probe"
/** A 64-digit hexadecimal digest; raw machine and GPU identifiers never leave the engine. */
export type Digest = string
/** The digest of the configuration an observation depends on. */
export type ConfigurationFingerprint = string
/** Nanoseconds on the evidence service's clock, which starts with the engine. */
export type MonotonicTime = number
/** A Rust `Duration` as the engine serializes it. */
export interface Duration { secs: number; nanos: number }
export type OsKind = "windows" | "linux" | "macos" | "wsl2"
export type ExecutionCategory = "vm_sandbox" | "shared_kernel_gpu_runtime" | "provider_container_runtime" | "host_process_model_runtime"
export type Backend = "vllm" | "llama_cpp" | "transformers"
export interface BackendRelease { backend: Backend; version: string }
export type HypervisorKind = "kvm" | "whpx" | "hcs" | "hvf" | "vz"

/** What an observation is about. This host's adapters observe GPUs and the runtimes the engine
 *  runs locally; the other kinds belong to other producers and are shown by kind only. */
export type Subject =
  | { kind: "host"; machine: Digest }
  | { kind: "gpu_device"; machine: Digest; device: Digest }
  | { kind: "runtime"; category: ExecutionCategory; release: BackendRelease; instance: Digest }
  | {
    kind: "hypervisor" | "operating_system" | "provider" | "gpu_pair" | "model_checkpoint" | "cuda_allocation" | "perimeter_rule"
      | "sandbox_boot" | "hypervisor_process" | "transport_broker" | "credential_scan" | "snapshot_clones"
    [field: string]: unknown
  }

export type ComputePlatform = "cuda" | "metal" | "cpu"
export interface PeerPath { from: number; to: number; link: "nv_link" | "pcie_switch" | "pcie_host_bridge" | "cross_socket"; access: "verified" | "unavailable" }
/** The typed detail of a supported observation. */
export type SupportDetail =
  | { kind: "plain" | "cuda_ipc_legacy" | "gpu_peer_access" | "execute_while_load" | "perimeter_rule_enforced" }
  | { kind: "cuda_ipc_vmm_shareable_handle"; handle: "posix_file_descriptor" | "win32_handle" | "fabric" }
  | { kind: "hypervisor"; hypervisor: HypervisorKind }
  | { kind: "provider_container"; gvisor: boolean; nvproxy: boolean }
  | { kind: "backend_mode"; release: BackendRelease }
  | { kind: "runtime_category"; category: ExecutionCategory }
  | { kind: "cuda_vmm_allocation"; granularity_bytes: number }
  | { kind: "compute_platform"; platform: ComputePlatform }
  | { kind: "checkpoint_compatibility"; record: Digest }
  | { kind: "gpu_memory"; free_bytes: number; total_bytes: number }
  | { kind: "peer_topology"; device_count: number; paths: PeerPath[] }
  | { kind: "kv_growth"; release: BackendRelease; increment_bytes: number }
  | { kind: "adapter_limits"; release: BackendRelease; max_rank: number; max_resident: number; max_bytes: number }
export type UnsupportedReason =
  | "operation_failed" | "feature_absent" | "disabled_by_policy" | "hypervisor_unavailable" | "not_a_provider_container"
  | "different_category" | "not_enforced" | "configuration_not_approved" | "not_confined" | "image_not_as_signed"
  | "destination_not_refused" | "guest_network_path" | "credential_exposed" | "clone_identity_shared" | "device_not_isolated"
/** Why a check could not decide; an unknown result fails every requirement. */
export type UnknownReason = "not_tested" | "inconclusive" | "unreachable" | "inconsistent_report"
export type ObservationResult =
  | { outcome: "supported"; detail: SupportDetail }
  | { outcome: "unsupported"; reason: UnsupportedReason }
  | { outcome: "unknown"; reason: UnknownReason }
/** One observation of one capability on one subject, as the engine's registry stamped it. */
export interface EvidenceEnvelope {
  schema_version: number
  capability: Capability
  subject: Subject
  configuration: ConfigurationFingerprint
  source: SourceClass
  /** The clock session the observation time was read on. */
  clock: string
  observed_at: MonotonicTime
  /** How long after `observed_at` the observation stays usable. */
  fresh_for: Duration
  result: ObservationResult
}

export type Staleness = { kind: "too_old"; age: Duration; limit: Duration } | { kind: "other_clock" } | { kind: "observed_after_now" }
/** Why the latest evidence does not satisfy the requirement the engine states for it. */
export type EvidenceRefusal =
  | { refusal: "missing"; capability: Capability }
  | { refusal: "source_too_weak"; capability: Capability; observed: SourceClass; required: SourceClass }
  | { refusal: "fingerprint_changed"; capability: Capability; observed_under: ConfigurationFingerprint; current: ConfigurationFingerprint }
  | { refusal: "stale"; capability: Capability; staleness: Staleness }
  | { refusal: "unsupported"; capability: Capability; reason: UnsupportedReason }
  | { refusal: "unknown"; capability: Capability; reason: UnknownReason }
/** What a refusal asks of the user. Yougori carries none of these out itself. */
export type Remedy =
  | { action: "run_check" | "run_check_again" | "recheck_current_configuration" | "choose_supported_runtime" | "enable_hypervisor_yourself"
    | "choose_allowed_category" | "use_ordinary_loader" | "use_one_mode_at_a_time" | "use_recorded_backend_release"
    | "keep_within_authorized_runtime" | "repair_perimeter" }
  | { action: "obtain_stronger_evidence"; required: SourceClass }
export type Verdict =
  | { verdict: "satisfied" }
  | { verdict: "refused"; refusal: EvidenceRefusal; remedy: Remedy }
  /** No inventory has been collected, so no configuration is known to require. */
  | { verdict: "not_collected" }
/** One capability of one subject. */
export interface StatusEntry {
  capability: Capability
  subject: Subject
  /** The configuration in force for the subject; `null` before an inventory names one. */
  configuration: ConfigurationFingerprint | null
  /** The latest observation, if any. */
  evidence: EvidenceEnvelope | null
  verdict: Verdict
}
/** A capability, or part of one, this host's probes do not observe, with the open task that owns it. */
export interface Uncovered { capability: Capability; scope: string; openTask: string; reason: string }

/** Why part of an inventory could not be read; it names what was wrong, never the raw value. */
export type InventoryProblem =
  | { problem: "tool_missing" | "query_failed" | "timed_out" | "output_too_long" | "not_utf8" | "machine_identity" | "os_build" | "too_many_gpus" | "repeated_gpu" | "not_on_this_platform" }
  | { problem: "malformed_gpu_row"; row: number }
export type MachineIdentity = { state: "known"; machine: Digest } | { state: "unavailable"; problem: InventoryProblem }
export interface OsFacts { kind: OsKind; architecture: string; build: string | null }
export type DriverModel = "wddm" | "tcc" | "mcdm" | "not_reported"
export type MigMode = "enabled" | "disabled" | "not_supported"
export interface GpuDevice {
  device: Digest
  driverVersion: string
  computeCapability: string | null
  driverModel: DriverModel
  mig: MigMode
  totalBytes: number
  usedBytes: number
  freeBytes: number
}
export type GpuInventory = { state: "devices"; devices: GpuDevice[] } | { state: "unavailable"; problem: InventoryProblem }
/** The local CUDA runtime as the engine reports it. */
export interface CudaRuntimeFacts { supported: boolean; installed: boolean; running: boolean; updateAvailable: boolean }
/** One collection: the machine, its operating system, its GPUs and its CUDA runtime. */
export interface HostInventory {
  machine: MachineIdentity
  os: OsFacts | null
  gpus: GpuInventory
  cudaRuntime: CudaRuntimeFacts | null
  /** When the collection started, on the evidence service's clock. */
  startedAt: MonotonicTime
}
/** A local runtime the model runner is running but could not bind to this evidence, and why; its
 *  compute platform, category and GPUs are not observed until it is bound. */
export interface UnboundRuntime { environmentId: string; reason: string }
/** `status`: everything this host's probes observe, and what they leave to others. Runs nothing. */
export interface EvidenceStatus {
  inventory: HostInventory | null
  /** How long before this answer the inventory's collection started. */
  inventoryAgeMs: number | null
  entries: StatusEntry[]
  uncovered: Uncovered[]
  /** Absent from engines that do not report it. */
  unboundRuntimes?: UnboundRuntime[]
}

export type Query = "machine_identity" | "os_build" | "gpus"
/** One query a refresh would run: the program or file it reads (`null` where the query does not
 *  exist on this platform), its arguments, its deadline and its output bound. */
export interface QueryDescription { query: Query; purpose: string; reads: string | null; arguments: string[]; timeoutMs: number; maxOutputBytes: number }
/** `plan`: the queries a refresh would run on this computer, without running any. */
export interface HostEvidencePlan { queries: QueryDescription[] }
/** What one refresh did to the evidence. */
export interface InstallReport {
  /** The collection started before the inventory in force, so it was not installed. */
  superseded: boolean
  removedSubjects: number
  changedConfigurations: number
  droppedEvidence: number
  observed: number
  /** Observations the registry refused, with why. */
  refused: [Capability, string][]
}
/** `refresh`: what the collection changed, and the status after it. */
export interface HostEvidenceRefresh { refresh: InstallReport; status: EvidenceStatus }

/** The command is not in this build of Yougori, or this is not the desktop app. */
export class HostEvidenceUnavailableError extends Error {
  constructor(message = "This build of Yougori can't show host evidence yet.") {
    super(message)
    this.name = "HostEvidenceUnavailableError"
  }
}

export const isHostEvidenceUnavailable = (reason: unknown): reason is HostEvidenceUnavailableError => reason instanceof HostEvidenceUnavailableError

/** Tauri's own refusal of a command this build does not register, or does not allow. */
const MISSING = /^\s*command \S+ not (?:found|allowed)\b/i
const AGAIN = "Yougori could not read the host evidence. Try again."

/** Keeps the engine's sentence (an unknown action, say) and reads a missing command as
 *  unavailable, never as a failure of the computer. */
export function hostEvidenceError(reason: unknown): Error {
  if (reason instanceof HostEvidenceUnavailableError) return reason
  const text = reason instanceof Error ? reason.message : typeof reason === "string" ? reason : ""
  if (MISSING.test(text)) return new HostEvidenceUnavailableError()
  return new Error(text.trim() || AGAIN)
}

async function ask<T>(action: "status" | "refresh" | "plan"): Promise<T> {
  try {
    // A browser preview has no computer to observe, so it answers nothing rather than made-up evidence.
    return await run<T>("host_evidence", { action }, () => {
      throw new HostEvidenceUnavailableError("Host evidence needs Yougori Desktop.")
    })
  } catch (reason) {
    throw hostEvidenceError(reason)
  }
}

export const hostEvidenceApi = {
  /** What the engine holds now. Runs nothing. */
  status: () => ask<EvidenceStatus>("status"),
  /** The queries a refresh would run on this computer. Runs nothing. */
  plan: () => ask<HostEvidencePlan>("plan"),
  /** Runs the plan's bounded, read-only queries once and installs what they observed. */
  refresh: () => ask<HostEvidenceRefresh>("refresh"),
}
