// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import type {
  Capability, EvidenceEnvelope, EvidenceStatus, HostEvidencePlan, HostEvidenceRefresh, HostInventory, InstallReport, ObservationResult, StatusEntry, Subject, Uncovered, Verdict,
} from "@/api/host-evidence-api"

const api = vi.hoisted(() => ({ status: vi.fn(), plan: vi.fn(), refresh: vi.fn() }))
vi.mock("@/api/host-evidence-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/host-evidence-api")>()), hostEvidenceApi: api }))

import { HostEvidenceUnavailableError } from "@/api/host-evidence-api"
import { HostEvidence, HostEvidencePlanView, HostEvidenceStatusView } from "./host-evidence"

afterEach(() => {
  cleanup()
  api.status.mockReset()
  api.plan.mockReset()
  api.refresh.mockReset()
})

// Digests as the engine sends them: 64 hexadecimal digits, never a raw identifier.
const MACHINE = "4d2f9a10c3b7".padEnd(64, "0")
const GPU_A = "9e81c0d2f4a6".padEnd(64, "1")
const GPU_B = "b07a3c5d1e92".padEnd(64, "2")
const INSTANCE = "71c9e3a0b5d8".padEnd(64, "3")
const CONFIG = "c0ffee5e1d42".padEnd(64, "4")
const OLD_CONFIG = "0ddba11c0de5".padEnd(64, "5")
const CLOCK = "6f2c1d1e-0000-4000-8000-000000000000"
/** The collection started 40 s after the engine did, on the evidence service's clock. */
const STARTED = 40_000_000_000
const GIB = 1024 ** 3

const UNCOVERED: Uncovered[] = [
  { capability: "hypervisor_available", scope: "every hypervisor", openTask: "M08", reason: "The sandbox probes' hypervisor adapter (H06) runs through M08's host check runner." },
  { capability: "peer_topology", scope: "runtimes with more than one GPU", openTask: "O07", reason: "Peer access must be exercised between the GPUs, never assumed (FAST-02)." },
  { capability: "io_uring", scope: "every runtime", openTask: "O06", reason: "Needs the runtime's own kernel to set up a ring; the WSL kernel is not the host's." },
]

const gpu = (device: string, free: number) => ({
  device, driverVersion: "592.01", computeCapability: "8.9", driverModel: "wddm" as const, mig: "disabled" as const, totalBytes: 16 * GIB, usedBytes: 16 * GIB - free, freeBytes: free,
})
const windows = (over: Partial<HostInventory> = {}): HostInventory => ({
  machine: { state: "known", machine: MACHINE }, os: { kind: "windows", architecture: "x86_64", build: "26200" },
  gpus: { state: "devices", devices: [gpu(GPU_A, 12 * GIB)] }, cudaRuntime: { supported: true, installed: true, running: true, updateAvailable: false }, startedAt: STARTED, ...over,
})
const gpuSubject = (device: string): Subject => ({ kind: "gpu_device", machine: MACHINE, device })
const RUNTIME: Subject = { kind: "runtime", category: "shared_kernel_gpu_runtime", release: { backend: "vllm", version: "0.31.0" }, instance: INSTANCE }
const RUNTIME_NAME = "vLLM 0.31.0 runtime 71c9e3a0b5d8…, GPU runtime (shared kernel), not a sandbox"
const satisfied: Verdict = { verdict: "satisfied" }

function envelope(capability: Capability, subject: Subject, result: ObservationResult, over: Partial<EvidenceEnvelope> = {}): EvidenceEnvelope {
  return {
    schema_version: 1, capability, subject, configuration: CONFIG, source: "host_probe", clock: CLOCK,
    observed_at: STARTED + 200_000_000, fresh_for: { secs: 4, nanos: 800_000_000 }, result, ...over,
  }
}
function entry(capability: Capability, subject: Subject, result: ObservationResult, verdict: Verdict, over: Partial<EvidenceEnvelope> = {}): StatusEntry {
  return { capability, subject, configuration: CONFIG, evidence: envelope(capability, subject, result, over), verdict }
}
const status = (over: Partial<EvidenceStatus> = {}): EvidenceStatus => ({ inventory: windows(), inventoryAgeMs: 1500, entries: [], uncovered: UNCOVERED, ...over })
const freeMemory = (device: string, free: number, verdict: Verdict = satisfied) =>
  entry("gpu_free_memory", gpuSubject(device), { outcome: "supported", detail: { kind: "gpu_memory", free_bytes: free, total_bytes: 16 * GIB } }, verdict)

const OBSERVED = status({
  entries: [
    freeMemory(GPU_A, 12 * GIB),
    entry("compute_platform", RUNTIME, { outcome: "supported", detail: { kind: "compute_platform", platform: "cuda" } }, satisfied, { fresh_for: { secs: 599, nanos: 800_000_000 } }),
    entry("peer_topology", RUNTIME, { outcome: "unknown", reason: "not_tested" },
      { verdict: "refused", refusal: { refusal: "unknown", capability: "peer_topology", reason: "not_tested" }, remedy: { action: "run_check" } }, { fresh_for: { secs: 0, nanos: 0 } }),
  ],
})

const REG = "C:\\Windows\\System32\\reg.exe"
const PLAN: HostEvidencePlan = {
  queries: [
    { query: "machine_identity", purpose: "Names this computer by a digest of its machine identity, as host admission does.", reads: REG, arguments: ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"], timeoutMs: 5000, maxOutputBytes: 16384 },
    { query: "os_build", purpose: "Reads the operating system build that evidence depends on.", reads: REG, arguments: ["query", "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion", "/v", "CurrentBuildNumber"], timeoutMs: 5000, maxOutputBytes: 16384 },
    { query: "gpus", purpose: "Lists NVIDIA GPUs with driver, compute capability, driver model, MIG mode and memory.", reads: "nvidia-smi", arguments: ["--query-gpu=uuid,driver_version,compute_cap,driver_model.current,mig.mode.current,memory.total,memory.used,memory.free", "--format=csv,noheader,nounits"], timeoutMs: 5000, maxOutputBytes: 16384 },
  ],
}
const report = (over: Partial<InstallReport> = {}): InstallReport => ({ superseded: false, removedSubjects: 0, changedConfigurations: 0, droppedEvidence: 0, observed: 1, refused: [], ...over })

it("reads the status when shown, says nothing has been collected yet, and runs no query", async () => {
  api.status.mockResolvedValue(status({ inventory: null, inventoryAgeMs: null }))
  render(<HostEvidence />)
  const panel = screen.getByRole("region", { name: "Host evidence" })
  const inventory = await within(panel).findByRole("region", { name: "This computer as last collected" })
  expect(inventory).toHaveTextContent("No inventory has been collected since the engine started. A refresh runs the queries once.")
  expect(within(panel).getByRole("region", { name: "Observed capabilities" })).toHaveTextContent("Nothing is observed until an inventory is collected.")
  expect(api.status).toHaveBeenCalledTimes(1)
  expect(api.plan).not.toHaveBeenCalled()
  expect(api.refresh).not.toHaveBeenCalled()
  expect(within(panel).queryByRole("alert")).not.toBeInTheDocument()
})

it("shows each observed capability with its subject, source, freshness, configuration and verdict, never as a score", () => {
  const { container } = render(<HostEvidenceStatusView status={OBSERVED} />)
  const inventory = screen.getByRole("region", { name: "This computer as last collected" })
  expect(inventory).toHaveTextContent("MachineNamed by the digest 4d2f9a10c3b7…; its raw identity never leaves the engine.")
  expect(inventory).toHaveTextContent("Operating systemWindows, build 26200, x86_64")
  expect(within(inventory).getByRole("list", { name: "NVIDIA GPUs found" })).toHaveTextContent(
    "GPU 9e81c0d2f4a6…: driver 592.01, compute capability 8.9, WDDM driver model, MIG disabled; 12.0 GB free of 16.0 GB, 4.00 GB used")
  expect(inventory).toHaveTextContent("CUDA runtimeInstalled and running.")
  expect(inventory).toHaveTextContent("Collected2 s before this reading.")

  const memory = screen.getByRole("article", { name: "Free GPU memory: GPU 9e81c0d2f4a6…" })
  expect(memory).toHaveTextContent("Satisfied")
  expect(memory).toHaveTextContent("SubjectGPU 9e81c0d2f4a6…")
  expect(memory).toHaveTextContent("SourceHost probe")
  expect(memory).toHaveTextContent("ObservedSupported: 12.0 GB free of 16.0 GB")
  expect(memory).toHaveTextContent("FreshnessObserved 1 s before this reading; fresh for 5 s after it was observed")
  expect(memory).toHaveTextContent("Configurationc0ffee5e1d42…, the one in force")
  expect(memory).toHaveTextContent("VerdictThe latest observation meets the requirement: a strong enough source, fresh, and under the configuration in force.")
  expect(memory).not.toHaveTextContent("Remedy")

  const platform = screen.getByRole("article", { name: `Compute platform: ${RUNTIME_NAME}` })
  expect(platform).toHaveTextContent("ObservedSupported: CUDA on an NVIDIA GPU")
  expect(platform).toHaveTextContent("fresh for 10 min after it was observed")

  const topology = screen.getByRole("article", { name: `GPU peer topology: ${RUNTIME_NAME}` })
  expect(topology).toHaveTextContent("Refused")
  expect(topology).toHaveTextContent("ObservedUnknown: it was not tested")
  expect(topology).toHaveTextContent("VerdictGPU peer topology is unknown because it was not tested, and an inconclusive check never passes.")
  expect(topology).toHaveTextContent("RemedyRun the check. A refresh observes it again.")
  expect(container.textContent).not.toMatch(/score|\bsecure\b|\bsafe\b|\d+\s*%/i)
})

it("words stale, changed and unsupported evidence as the engine does, each with its remedy", () => {
  render(<HostEvidenceStatusView status={status({
    inventoryAgeMs: 9000,
    entries: [
      freeMemory(GPU_A, 12 * GIB, { verdict: "refused", refusal: { refusal: "stale", capability: "gpu_free_memory", staleness: { kind: "too_old", age: { secs: 8, nanos: 800_000_000 }, limit: { secs: 4, nanos: 800_000_000 } } }, remedy: { action: "run_check_again" } }),
      entry("compute_platform", RUNTIME, { outcome: "supported", detail: { kind: "compute_platform", platform: "cuda" } },
        { verdict: "refused", refusal: { refusal: "fingerprint_changed", capability: "compute_platform", observed_under: OLD_CONFIG, current: CONFIG }, remedy: { action: "recheck_current_configuration" } }, { configuration: OLD_CONFIG }),
      entry("runtime_category", RUNTIME, { outcome: "unsupported", reason: "different_category" },
        { verdict: "refused", refusal: { refusal: "unsupported", capability: "runtime_category", reason: "different_category" }, remedy: { action: "choose_allowed_category" } }),
      entry("gpu_free_memory", gpuSubject(GPU_B), { outcome: "supported", detail: { kind: "gpu_memory", free_bytes: GIB, total_bytes: 8 * GIB } },
        { verdict: "refused", refusal: { refusal: "source_too_weak", capability: "gpu_free_memory", observed: "guest_report", required: "host_probe" }, remedy: { action: "obtain_stronger_evidence", required: "host_probe" } }, { source: "guest_report" }),
    ],
  })} />)
  const stale = screen.getByRole("article", { name: "Free GPU memory: GPU 9e81c0d2f4a6…" })
  expect(stale).toHaveTextContent("FreshnessObserved 9 s before this reading; fresh for 5 s after it was observed")
  expect(stale).toHaveTextContent("VerdictThe free GPU memory evidence is 9 s old, beyond its 5 s limit.")
  expect(stale).toHaveTextContent("RemedyRun the check again. A refresh observes it again.")
  const changed = screen.getByRole("article", { name: `Compute platform: ${RUNTIME_NAME}` })
  expect(changed).toHaveTextContent("Configurationc0ffee5e1d42… in force; observed under 0ddba11c0de5…")
  expect(changed).toHaveTextContent("VerdictThe configuration changed after compute platform was checked, so that evidence no longer applies.")
  expect(changed).toHaveTextContent("RemedyRun the check again under the current configuration. A refresh observes it again.")
  const category = screen.getByRole("article", { name: `Runtime category: ${RUNTIME_NAME}` })
  expect(category).toHaveTextContent("ObservedUnsupported: the runtime is not the category it was offered as")
  expect(category).toHaveTextContent("VerdictRuntime category is not supported: the runtime is not the category it was offered as.")
  expect(category).toHaveTextContent("RemedyChoose a runtime of a category this request allows.")
  expect(category).not.toHaveTextContent("A refresh observes it again.")
  const weak = screen.getByRole("article", { name: "Free GPU memory: GPU b07a3c5d1e92…" })
  expect(weak).toHaveTextContent("SourceGuest report")
  expect(weak).toHaveTextContent("VerdictFree GPU memory needs a host probe, and a guest report never satisfies a host-only requirement.")
  expect(weak).toHaveTextContent("RemedyObtain evidence from a host probe or a stronger source.")
})

it("says a runtime observed before any collection is not collected, with no configuration in force", () => {
  render(<HostEvidenceStatusView status={status({
    inventory: null, inventoryAgeMs: null,
    entries: [{ capability: "compute_platform", subject: RUNTIME, configuration: null, evidence: envelope("compute_platform", RUNTIME, { outcome: "unknown", reason: "not_tested" }, { configuration: OLD_CONFIG, fresh_for: { secs: 0, nanos: 0 } }), verdict: { verdict: "not_collected" } }],
  })} />)
  const platform = screen.getByRole("article", { name: `Compute platform: ${RUNTIME_NAME}` })
  expect(platform).toHaveTextContent("Not collected")
  expect(platform).toHaveTextContent("FreshnessFresh for 0 s after it was observed")
  expect(platform).toHaveTextContent("ConfigurationNone in force yet; observed under 0ddba11c0de5…")
  expect(platform).toHaveTextContent("VerdictNo inventory has been collected, so no configuration is known to require.")
  expect(platform).not.toHaveTextContent("Remedy")
})

it("says which parts of the inventory could not be read, without naming any raw value", () => {
  const { rerender } = render(<HostEvidenceStatusView status={status({
    inventory: windows({ machine: { state: "unavailable", problem: { problem: "machine_identity" } }, os: { kind: "windows", architecture: "x86_64", build: null }, gpus: { state: "unavailable", problem: { problem: "tool_missing" } }, cudaRuntime: null }),
  })} />)
  const inventory = screen.getByRole("region", { name: "This computer as last collected" })
  expect(inventory).toHaveTextContent("MachineUnavailable: the machine identity is unavailable. No GPU can be named without it.")
  expect(inventory).toHaveTextContent("Operating systemWindows, build not read, x86_64")
  expect(inventory).toHaveTextContent("NVIDIA GPUsNot read: the query's program is not installed.")
  expect(inventory).toHaveTextContent("CUDA runtimeNot reported on this computer.")
  expect(screen.getByRole("region", { name: "Observed capabilities" })).toHaveTextContent("The last collection named no GPU, and no local runtime is bound, so nothing is observed here.")
  rerender(<HostEvidenceStatusView status={status({
    inventory: windows({ os: { kind: "linux", architecture: "aarch64", build: "6.8.0-45" }, gpus: { state: "unavailable", problem: { problem: "malformed_gpu_row", row: 2 } }, cudaRuntime: { supported: true, installed: false, running: false, updateAvailable: false } }),
  })} />)
  const linux = screen.getByRole("region", { name: "This computer as last collected" })
  expect(linux).toHaveTextContent("Operating systemLinux, build 6.8.0-45, aarch64")
  expect(linux).toHaveTextContent("NVIDIA GPUsNot read: GPU row 2 is malformed.")
  expect(linux).toHaveTextContent("CUDA runtimeSupported, not installed.")
})

it("lists the capabilities left to other tasks with the open task that owns each", () => {
  render(<HostEvidenceStatusView status={OBSERVED} />)
  const left = screen.getByRole("region", { name: "Left to other tasks" })
  expect(left).toHaveTextContent("3 capabilities")
  const items = within(within(left).getByRole("list", { name: "Capabilities left to other tasks" })).getAllByRole("listitem")
  expect(items).toHaveLength(3)
  expect(items[0]).toHaveTextContent("Hypervisor availability (every hypervisor): open task M08. The sandbox probes' hypervisor adapter (H06) runs through M08's host check runner.")
  expect(items[1]).toHaveTextContent("GPU peer topology (runtimes with more than one GPU): open task O07.")
  expect(items[2]).toHaveTextContent("io_uring (every runtime): open task O06.")
})

it("lists the running local runtimes the engine could not bind, with why", () => {
  render(<HostEvidenceStatusView status={status({ unboundRuntimes: [{ environmentId: "llm-a", reason: "no GPU was admitted for it" }, { environmentId: "llm-b", reason: "its vLLM release is not the pinned one" }] })} />)
  const unbound = screen.getByRole("region", { name: "Running local runtimes not bound" })
  expect(unbound).toHaveTextContent("could not bind them to this evidence")
  const items = within(within(unbound).getByRole("list", { name: "Running local runtimes not bound" })).getAllByRole("listitem")
  expect(items.map(item => item.textContent)).toEqual(["llm-a: no GPU was admitted for it", "llm-b: its vLLM release is not the pinned one"])
})

it("shows no unbound section when the engine reports none or does not report them", () => {
  render(<HostEvidenceStatusView status={status({ unboundRuntimes: [] })} />)
  expect(screen.queryByRole("region", { name: "Running local runtimes not bound" })).not.toBeInTheDocument()
  cleanup()
  render(<HostEvidenceStatusView status={OBSERVED} />)
  expect(screen.queryByRole("region", { name: "Running local runtimes not bound" })).not.toBeInTheDocument()
})

it("lists the queries a refresh would run, read only when opened, and runs none of them", async () => {
  api.status.mockResolvedValue(OBSERVED)
  api.plan.mockResolvedValue(PLAN)
  const user = userEvent.setup()
  render(<HostEvidence />)
  await screen.findByRole("article", { name: "Free GPU memory: GPU 9e81c0d2f4a6…" })
  expect(api.plan).not.toHaveBeenCalled()
  const toggle = screen.getByRole("button", { name: "Show the queries" })
  expect(toggle).toHaveAttribute("aria-expanded", "false")
  await user.click(toggle)
  const plan = await screen.findByRole("region", { name: "Queries a refresh would run" })
  expect(api.plan).toHaveBeenCalledTimes(1)
  expect(screen.getByRole("button", { name: "Hide the queries" })).toHaveAttribute("aria-expanded", "true")
  expect(plan).toHaveTextContent("Listing them runs none.")
  const queries = within(within(plan).getByRole("list", { name: "Planned queries" })).getAllByRole("listitem")
  expect(queries).toHaveLength(3)
  expect(queries[0]).toHaveTextContent("Machine identity: Names this computer by a digest of its machine identity, as host admission does.")
  expect(within(queries[0]!).getByText(`${REG} query HKLM\\SOFTWARE\\Microsoft\\Cryptography /v MachineGuid`).tagName).toBe("CODE")
  expect(queries[0]).toHaveTextContent("Stopped after 5 s or 16,384 bytes of output.")
  expect(queries[2]).toHaveTextContent("NVIDIA GPUs: Lists NVIDIA GPUs")
  expect(api.refresh).not.toHaveBeenCalled()
  await user.click(screen.getByRole("button", { name: "Hide the queries" }))
  expect(screen.queryByRole("region", { name: "Queries a refresh would run" })).not.toBeInTheDocument()
})

it("says when a query does not exist on this platform", () => {
  render(<HostEvidencePlanView plan={{ queries: [{ query: "machine_identity", purpose: "Names this computer by a digest of its machine identity, as host admission does.", reads: null, arguments: [], timeoutMs: 5000, maxOutputBytes: 16384 }] }} />)
  expect(screen.getByRole("listitem")).toHaveTextContent("Not available on this platform; a refresh records it as such and runs nothing for it.")
})

it("refreshes only after the user confirms, saying it runs bounded, read-only host queries, and then shows the new status", async () => {
  api.status.mockResolvedValue(status({ inventory: null, inventoryAgeMs: null }))
  const refreshed: HostEvidenceRefresh = { refresh: report({ observed: 1 }), status: status({ inventoryAgeMs: 300, entries: [freeMemory(GPU_A, 12 * GIB)] }) }
  api.refresh.mockResolvedValue(refreshed)
  const user = userEvent.setup()
  render(<HostEvidence />)
  await screen.findByText(/No inventory has been collected since the engine started/)
  const button = screen.getByRole("button", { name: "Refresh…" })
  await user.click(button)
  const confirm = screen.getByRole("group", { name: "Refresh the host evidence now?" })
  expect(button).toHaveAttribute("aria-expanded", "true")
  expect(confirm).toHaveTextContent("This runs bounded, read-only host queries once: the machine identity, the operating system build and the NVIDIA GPU inventory.")
  expect(confirm).toHaveTextContent("Nothing on this computer is changed.")
  expect(api.refresh).not.toHaveBeenCalled()
  await user.click(within(confirm).getByRole("button", { name: "Cancel" }))
  expect(screen.queryByRole("group", { name: "Refresh the host evidence now?" })).not.toBeInTheDocument()
  expect(api.refresh).not.toHaveBeenCalled()

  await user.click(screen.getByRole("button", { name: "Refresh…" }))
  await user.click(within(screen.getByRole("group", { name: "Refresh the host evidence now?" })).getByRole("button", { name: "Run the queries" }))
  expect(await screen.findByText("Refreshed: 1 observation made; 0 earlier observations dropped (0 subjects gone, 0 configurations changed).")).toBeInTheDocument()
  expect(api.refresh).toHaveBeenCalledTimes(1)
  expect(api.status).toHaveBeenCalledTimes(1)
  expect(screen.getByRole("article", { name: "Free GPU memory: GPU 9e81c0d2f4a6…" })).toHaveTextContent("Satisfied")
  expect(screen.queryByRole("group", { name: "Refresh the host evidence now?" })).not.toBeInTheDocument()
})

it("reports a superseded collection, and the observations the registry refused", async () => {
  api.status.mockResolvedValue(OBSERVED)
  api.refresh.mockResolvedValueOnce({ refresh: report({ superseded: true, observed: 0 }), status: OBSERVED })
  api.refresh.mockResolvedValueOnce({ refresh: report({ observed: 3, droppedEvidence: 2, removedSubjects: 1, changedConfigurations: 1, refused: [["peer_topology", "the adapter's report did not fit its subject"]] }), status: OBSERVED })
  const user = userEvent.setup()
  render(<HostEvidence />)
  await user.click(await screen.findByRole("button", { name: "Refresh…" }))
  await user.click(screen.getByRole("button", { name: "Run the queries" }))
  expect(await screen.findByText("A newer collection was already in force, so this one was not installed.")).toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Refresh…" }))
  await user.click(screen.getByRole("button", { name: "Run the queries" }))
  expect(await screen.findByText("Refreshed: 3 observations made; 2 earlier observations dropped (1 subject gone, 1 configuration changed).")).toBeInTheDocument()
  expect(screen.queryByText("A newer collection was already in force, so this one was not installed.")).not.toBeInTheDocument()
  expect(screen.getByRole("list", { name: "Observations the registry refused" })).toHaveTextContent("GPU peer topology: the adapter's report did not fit its subject")
  expect(api.refresh).toHaveBeenCalledTimes(2)
})

it("says plainly when this build has no host evidence, and offers no refresh", async () => {
  api.status.mockRejectedValue(new HostEvidenceUnavailableError())
  render(<HostEvidence />)
  expect(await screen.findByText("This build of Yougori can't show host evidence yet.")).toHaveAttribute("role", "status")
  expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Refresh…" })).toBeDisabled()
  expect(screen.queryByRole("button", { name: "Read again" })).not.toBeInTheDocument()
})

it("shows the engine's refusal as an error, reads again on request, and keeps the status when a refresh fails", async () => {
  api.status.mockRejectedValueOnce(new Error("Host evidence is unavailable: an adapter was registered twice"))
  api.status.mockResolvedValueOnce(OBSERVED)
  api.refresh.mockRejectedValueOnce(new Error("Unknown host evidence action 'refresh'. Use status, refresh or plan."))
  const user = userEvent.setup()
  render(<HostEvidence />)
  expect(await screen.findByRole("alert")).toHaveTextContent("Host evidence is unavailable: an adapter was registered twice")
  await user.click(screen.getByRole("button", { name: "Read again" }))
  await screen.findByRole("article", { name: "Free GPU memory: GPU 9e81c0d2f4a6…" })
  expect(api.status).toHaveBeenCalledTimes(2)
  expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  await user.click(screen.getByRole("button", { name: "Refresh…" }))
  await user.click(screen.getByRole("button", { name: "Run the queries" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Unknown host evidence action 'refresh'.")
  expect(screen.getByRole("article", { name: "Free GPU memory: GPU 9e81c0d2f4a6…" })).toBeInTheDocument()
})
