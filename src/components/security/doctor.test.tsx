// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import type {
  BackendKind, CandidateReport, CandidateRole, CheckEntry, CheckExplanation, CheckStatus, DoctorHistory, DoctorLabel, DoctorPlan, DoctorReport, DoctorStatus,
  GpuPath, HostBuild, PlannedObservation, RunProfile,
} from "@/api/sandbox-doctor-api"

const api = vi.hoisted(() => ({ status: vi.fn(), plan: vi.fn() }))
vi.mock("@/api/sandbox-doctor-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/sandbox-doctor-api")>()), sandboxDoctorApi: api }))

import { DoctorUnavailableError } from "@/api/sandbox-doctor-api"
import { DoctorPlanView, DoctorReportView, SandboxDoctor } from "./doctor"

afterEach(() => {
  cleanup()
  api.status.mockReset()
  api.plan.mockReset()
})

// The engine's own notices (sandbox::doctor::DOCTOR_NOTICE, sandbox::probes::REPORT_NOTICE, PLAN_NOTICE).
const DOCTOR_NOTICE = "This report changes nothing on the host. A check without a result is not tested and never passes. A backend is validated on this host only when every check its run profiles require passed here; until then it is experimental or unavailable (section 7.1)."
const REPORT_NOTICE = "an evidence record of named checks at one time; it is not a security certificate and does not show that no secret or unknown escape exists"
const PLAN_NOTICE = "A plan describes the checks; it runs none of them and changes nothing on the host."
const NO_RUNNER = "No boundary check has run on this computer: running them needs a hardware VM backend (M02) and the host check runner (M08), so every check is not tested and no backend is validated."

const id = (number: number) => `VM-CP-${String(number).padStart(2, "0")}`
/** The checks no strict VM sandbox requires; VM-CP-31 is the GPU VM profile's. */
const NOT_STRICT = new Set([14, 21, 24, 30, 31, 32, 34])
const requiredFor = (number: number, profiles: RunProfile[]) => !NOT_STRICT.has(number) || number === 31 && profiles.includes("gpu_vm")

/** A check's status as the engine serializes it, with the sentence its `Display` gives it. */
type Said = { status: CheckStatus; reason: string }
const NOT_RUN = "not tested: it was not run"
const notRun: Said = { status: { status: "not_tested", reason: { reason: "not_run" } }, reason: NOT_RUN }
const passed: Said = { status: { status: "passed" }, reason: "passed" }
/** What a check expects on the host, as the report carries it for a check that did not pass. */
const expectsOf = (number: number): PlannedObservation[] => [
  { id: `cp${String(number).padStart(2, "0")}.observation`, part: "primary", role: "observation", says: `observation ${number} holds on the host` },
  { id: `cp${String(number).padStart(2, "0")}.control`, part: "primary", role: "positive_control", says: `control ${number} holds in the same run` },
]

/** One backend's examination as the engine serializes it, its counts, blocking list and
 *  explanations derived from the entries the way `Doctor::examine` does. */
function candidate(backend: BackendKind, role: CandidateRole, label: DoctorLabel, host: HostBuild, profiles: RunProfile[], said: (check: number) => Said = () => notRun, gpu: GpuPath = { gpu: "not_requested" }): CandidateReport {
  const numbers = Array.from({ length: 35 }, (_, index) => index + 1)
  const entries: CheckEntry[] = numbers.map(number => ({
    check: id(number), families: [`VM-P${String(number).padStart(2, "0")}`], applicability: requiredFor(number, profiles) ? "required" : "not_required", status: said(number).status,
  }))
  const not_passed: CheckExplanation[] = numbers.filter(number => said(number).status.status !== "passed").map(number => ({
    check: id(number), required: requiredFor(number, profiles), status: said(number).status.status, reason: said(number).reason, expects: expectsOf(number),
  }))
  const count = (list: CheckEntry[]) => ({
    passed: list.filter(entry => entry.status.status === "passed").length,
    failed: list.filter(entry => entry.status.status === "failed").length,
    inconclusive: list.filter(entry => entry.status.status === "inconclusive").length,
    not_tested: list.filter(entry => entry.status.status === "not_tested").length,
    refused: list.filter(entry => entry.status.status === "refused").length,
  })
  const required = entries.filter(entry => entry.applicability === "required")
  const blocking = required.filter(entry => entry.status.status !== "passed").map(entry => entry.check)
  return {
    candidate: { backend, role, basis: `the plan's reason for ${backend}` },
    label, required: count(required), all: count(entries), blocking, not_passed,
    report: {
      identity: "ab".repeat(32), notice: REPORT_NOTICE, profile: { host, backend, profiles }, configuration: "cd".repeat(32),
      clock: "6f2c1d1e-0000-4000-8000-000000000000", assembled_at: 1_000_000, max_age: { secs: 900, nanos: 0 }, entries,
      unsatisfied: blocking.length ? [{ facet: "isolation", because: [blocking[0]!] }, { facet: "evidence", because: blocking }] : [], gpu,
    },
  }
}

const WINDOWS: HostBuild = { os: "windows", build: "26200", architecture: "x86_64" }
const LINUX: HostBuild = { os: "linux", build: "6.8.0-45", architecture: "x86_64" }

const FIRST_LOOK: DoctorHistory = { compared: [], ignored: null, not_kept: null }

function examined(host: HostBuild, candidates: CandidateReport[], over: Partial<DoctorReport> = {}): DoctorStatus {
  return { examined: true, checkRunner: NO_RUNNER, report: { notice: DOCTOR_NOTICE, host, profiles: ["strict"], results: 0, no_backend: null, candidates, changes: [], history: FIRST_LOOK, ...over } }
}

const windows = () => examined(WINDOWS, [
  candidate("hcs", "primary", "unavailable", WINDOWS, ["strict"]),
  candidate("qemu", "fallback", "unavailable", WINDOWS, ["strict"]),
])
const STRICT_REQUIRED = Array.from({ length: 35 }, (_, index) => index + 1).filter(number => requiredFor(number, ["strict"])).map(id)

it("says why the doctor has not examined this computer and what to run first, and examines nothing else", async () => {
  api.status.mockResolvedValue({ examined: false, reason: "Host evidence has not collected this computer's inventory yet.", next: "Run `yougori call host_evidence --action refresh` first; it runs bounded, read-only queries and changes nothing." })
  render(<SandboxDoctor />)
  const panel = screen.getByRole("region", { name: "VM sandbox doctor" })
  expect(await within(panel).findByText("Host evidence has not collected this computer's inventory yet.")).toBeInTheDocument()
  expect(within(panel).getByText("This computer has not been examined yet.")).toBeInTheDocument()
  expect(within(panel).getByText("yougori call host_evidence --action refresh").tagName).toBe("CODE")
  expect(api.status).toHaveBeenCalledTimes(1)
  expect(api.status).toHaveBeenCalledWith(undefined)
  expect(api.plan).not.toHaveBeenCalled()
  expect(within(panel).queryByRole("alert")).not.toBeInTheDocument()
})

it("shows a Windows report: HCS and QEMU unavailable, every required check not tested and blocking, never as a score", () => {
  const { container } = render(<DoctorReportView result={windows()} />)
  const host = screen.getByRole("region", { name: "This computer" })
  expect(host).toHaveTextContent("Operating systemWindows")
  expect(host).toHaveTextContent("Build26200")
  expect(host).toHaveTextContent("Architecturex86_64")
  expect(host).toHaveTextContent("Run profilesstrict")
  expect(host).toHaveTextContent("Check results given0")
  expect(host).toHaveTextContent(NO_RUNNER)
  for (const [name, role] of [["Host Compute Service (HCS)", "Primary"], ["QEMU", "Fallback"]] as const) {
    const backend = screen.getByRole("article", { name })
    expect(backend).toHaveTextContent(`${role} · Unavailable`)
    expect(backend).toHaveTextContent("No required check has passed on this computer yet, or one failed or was refused.")
    expect(backend).toHaveTextContent(`0 of ${STRICT_REQUIRED.length} required boundary checks passed.`)
    const counts = within(backend).getByLabelText(`Required checks of ${name} by status`)
    expect(counts).toHaveTextContent(`Passed0Failed0Inconclusive0Not tested${STRICT_REQUIRED.length}Refused0`)
    const blocking = within(backend).getByRole("list", { name: `Blocking checks of ${name}` })
    const groups = within(blocking).getAllByRole("listitem")
    expect(groups).toHaveLength(1)
    expect(groups[0]).toHaveTextContent(`Not tested: it was not run: ${STRICT_REQUIRED.join(", ")}`)
    // What each blocking check expects here, in the plan's words, from the report itself.
    const expecting = within(backend).getByRole("list", { name: `What the blocking checks of ${name} expect` })
    expect(expecting.children).toHaveLength(STRICT_REQUIRED.length)
    expect(expecting.children[0]).toHaveTextContent("VM-CP-01observation 1 holds on the hostPositive control: control 1 holds in the same run")
    expect(backend).toHaveTextContent("Facets left unsatisfied: isolation, evidence.")
    // No GPU VM was asked for, so no GPU path is explained.
    expect(within(backend).queryByText("GPU VM path")).not.toBeInTheDocument()
  }
  expect(screen.getByRole("region", { name: "Since the previous report" })).toHaveTextContent("There is no previous report to compare with.")
  expect(screen.getByText(DOCTOR_NOTICE)).toBeInTheDocument()
  expect(screen.getByText(`Each backend's report is ${REPORT_NOTICE}.`)).toBeInTheDocument()
  expect(container.textContent).not.toMatch(/score|\bsecure\b|\bsafe\b|\d+\s*%/i)
})

it("labels a backend validated only when every required check passed, and gives each still-open check its reason", () => {
  const report = examined(LINUX, [
    candidate("firecracker", "primary", "validated", LINUX, ["strict"], () => passed),
    candidate("qemu", "alternative", "experimental", LINUX, ["strict"], number =>
      number === 1 ? { status: { status: "inconclusive", reason: { inconclusive: "missing_observation", id: "cp01.accelerator" } }, reason: "inconclusive: cp01.accelerator was not observed" }
        : number === 33 ? { status: { status: "not_tested", reason: { reason: "needs_tier", tier: "disposable_vm" } }, reason: "not tested: it runs only at DisposableVm in an authorized environment" }
          : passed),
  ], { results: 66 })
  render(<DoctorReportView result={report} />)
  const firecracker = screen.getByRole("article", { name: "Firecracker" })
  expect(firecracker).toHaveTextContent("Primary · Validated")
  expect(firecracker).toHaveTextContent("Every check its run profiles require passed on this computer.")
  expect(firecracker).toHaveTextContent(`${STRICT_REQUIRED.length} of ${STRICT_REQUIRED.length} required boundary checks passed.`)
  expect(firecracker).toHaveTextContent("No required check blocks the run profiles asked on Firecracker.")
  expect(within(firecracker).queryByRole("list", { name: /Blocking checks/ })).not.toBeInTheDocument()
  const qemu = screen.getByRole("article", { name: "QEMU" })
  expect(qemu).toHaveTextContent("Alternative · Experimental")
  const blocking = within(within(qemu).getByRole("list", { name: "Blocking checks of QEMU" })).getAllByRole("listitem")
  expect(blocking.map(item => item.textContent)).toEqual([
    "Inconclusive: cp01.accelerator was not observed: VM-CP-01",
    "Not tested: it runs only at DisposableVm in an authorized environment: VM-CP-33",
  ])
  expect(within(firecracker).queryByRole("list", { name: /What the blocking checks/ })).not.toBeInTheDocument()
  expect(screen.getByRole("region", { name: "This computer" })).toHaveTextContent("Check results given66")
})

it("shows failed and refused checks in the engine's own words, never its own rewording", () => {
  const report = examined(WINDOWS, [candidate("hcs", "primary", "unavailable", WINDOWS, ["strict"], number =>
    number === 2 ? { status: { status: "failed", failure: { failed: "expectation", id: "cp02.console", part: { part: "primary" } } }, reason: "failed: expected that no console" }
      : number === 3 ? { status: { status: "refused", refusal: { refusal: "not_current", part: { part: "primary" }, problem: { problem: "stale", staleness: { kind: "too_old", age: { secs: 1200, nanos: 0 }, limit: { secs: 900, nanos: 0 } } } } }, reason: "evidence refused: the check's own observation: the observation is 1200s old, beyond its 900s limit" }
        : number === 5 ? { status: { status: "refused", refusal: { refusal: "uncorroborated", fact: "booted_root_image" } }, reason: "evidence refused: a guest report is never sufficient alone, and the host did not corroborate it with the booted root image digest matching the signed manifest" }
          : number === 6 ? { status: notRun.status, reason: "not tested: a sentence only the engine knows" }
            : passed)])
  render(<DoctorReportView result={report} />)
  const backend = screen.getByRole("article", { name: "Host Compute Service (HCS)" })
  const items = within(within(backend).getByRole("list", { name: "Blocking checks of Host Compute Service (HCS)" })).getAllByRole("listitem").map(item => item.textContent)
  expect(items).toEqual([
    "Failed: expected that no console: VM-CP-02",
    "Evidence refused: the check's own observation: the observation is 1200s old, beyond its 900s limit: VM-CP-03",
    "Evidence refused: a guest report is never sufficient alone, and the host did not corroborate it with the booted root image digest matching the signed manifest: VM-CP-05",
    "Not tested: a sentence only the engine knows: VM-CP-06",
  ])
  const expecting = within(backend).getByRole("list", { name: "What the blocking checks of Host Compute Service (HCS) expect" })
  expect(Array.from(expecting.children, item => item.firstChild?.textContent)).toEqual(["VM-CP-02", "VM-CP-03", "VM-CP-05", "VM-CP-06"])
})

it("names a blocking check's status kind when the engine sent no sentence for it, and says when a check expects nothing here", () => {
  const hcs = candidate("hcs", "primary", "unavailable", WINDOWS, ["strict"], number => number === 4 ? notRun : passed)
  const report = examined(WINDOWS, [{ ...hcs, not_passed: [] }, {
    ...candidate("qemu", "fallback", "unavailable", WINDOWS, ["strict"], number => number === 4 ? notRun : passed),
    not_passed: [{ check: "VM-CP-04", required: true, status: "not_tested", reason: NOT_RUN, expects: [] }],
  }])
  render(<DoctorReportView result={report} />)
  const hcsBackend = screen.getByRole("article", { name: "Host Compute Service (HCS)" })
  expect(within(hcsBackend).getByRole("list", { name: "Blocking checks of Host Compute Service (HCS)" })).toHaveTextContent("Not tested: VM-CP-04")
  expect(within(hcsBackend).queryByRole("list", { name: /What the blocking checks/ })).not.toBeInTheDocument()
  const qemu = screen.getByRole("article", { name: "QEMU" })
  expect(within(qemu).getByRole("list", { name: "What the blocking checks of QEMU expect" })).toHaveTextContent("VM-CP-04No observation of it applies on this computer.")
})

it("explains the GPU VM path when the GPU VM profile is asked for, and asks the engine for it", async () => {
  const profiles: RunProfile[] = ["strict", "gpu_vm"]
  api.status.mockResolvedValueOnce(examined(LINUX, [candidate("firecracker", "primary", "unavailable", LINUX, ["strict"])]))
  const noHardware: CheckStatus = { status: "not_tested", reason: { reason: "unavailable_hardware" } }
  api.status.mockResolvedValueOnce(examined(LINUX, [
    candidate("firecracker", "primary", "unavailable", LINUX, profiles, () => notRun, { gpu: "unavailable", status: notRun.status, why: "not tested: it was not run; no GPU VM is offered until VM-CP-31 passes" }),
    candidate("qemu", "alternative", "unavailable", LINUX, profiles, number => number === 31 ? { status: noHardware, reason: "not tested: the hardware it needs is not on this host" } : notRun,
      { gpu: "unavailable", status: noHardware, why: "not tested: this host has no GPU hardware the check can use, so no GPU VM is offered; a CPU VM or a remote VM remains" }),
  ], { profiles }))
  const user = userEvent.setup()
  render(<SandboxDoctor />)
  expect(await screen.findByRole("article", { name: "Firecracker" })).toBeInTheDocument()
  expect(screen.queryByText("GPU VM path")).not.toBeInTheDocument()
  await user.click(screen.getByRole("checkbox", { name: "Include the GPU VM run profile" }))
  expect(api.status).toHaveBeenLastCalledWith(["strict", "gpu_vm"])
  const firecracker = await screen.findByRole("article", { name: "Firecracker" })
  expect(screen.getByRole("region", { name: "This computer" })).toHaveTextContent("Run profilesstrict, GPU VM")
  expect(firecracker).toHaveTextContent("GPU VM pathUnavailable. Not tested: it was not run; no GPU VM is offered until VM-CP-31 passes.")
  expect(within(firecracker).getByRole("list", { name: "Blocking checks of Firecracker" })).toHaveTextContent("VM-CP-31")
  expect(screen.getByRole("article", { name: "QEMU" })).toHaveTextContent("GPU VM pathUnavailable. Not tested: this host has no GPU hardware the check can use, so no GPU VM is offered; a CPU VM or a remote VM remains.")
})

it("says what changed since the previous report: the host, the configuration, the launch and each check", () => {
  const after: HostBuild = { ...WINDOWS, build: "26300" }
  const report = examined(after, [
    candidate("hcs", "primary", "unavailable", after, ["strict"]),
    candidate("qemu", "fallback", "experimental", after, ["strict"], number => number === 1 ? passed : notRun),
  ], {
    changes: [
      { change: "host", backend: "hcs", before: WINDOWS, after },
      { change: "report", backend: "qemu", changes: { configuration_changed: true, launch_allowed_before: true, launch_allowed_now: false, checks: [
        { check: "VM-CP-01", before: { status: "not_tested", reason: NOT_RUN }, after: { status: "passed", reason: "passed" } },
        { check: "VM-CP-02", before: { status: "passed", reason: "passed" }, after: { status: "failed", reason: "failed: expected that no console" } },
      ] } },
    ],
    history: { compared: ["hcs", "qemu"], ignored: null, not_kept: null },
  })
  render(<DoctorReportView result={report} />)
  const changes = screen.getByRole("region", { name: "Since the previous report" })
  expect(changes).toHaveTextContent("Host Compute Service (HCS): this computer changed from Windows 26200 (x86_64) to Windows 26300 (x86_64), so earlier results say nothing about it.")
  expect(changes).toHaveTextContent("The host configuration changed, so earlier results no longer apply.")
  expect(changes).toHaveTextContent("A required check blocks its run profiles now; before, none did.")
  expect(changes).toHaveTextContent("VM-CP-01 went from “not tested: it was not run” to “passed”.")
  expect(changes).toHaveTextContent("VM-CP-02 went from “passed” to “failed: expected that no console”.")
  expect(changes).not.toHaveTextContent("Nothing changed")
  expect(changes).not.toHaveTextContent("no previous report")
})

it("says whether there was a previous report, and repeats the engine's notes on a history it ignored or could not keep", () => {
  const unchanged = examined(WINDOWS, [candidate("hcs", "primary", "unavailable", WINDOWS, ["strict"])], { history: { compared: ["hcs"], ignored: null, not_kept: null } })
  const { rerender } = render(<DoctorReportView result={unchanged} />)
  const region = () => screen.getByRole("region", { name: "Since the previous report" })
  expect(region()).toHaveTextContent("Nothing changed since the previous report.")
  const ignored = "The previous reports were ignored, and nothing is compared with them: the kept history's digest does not match the reports it keeps."
  const notKept = "This report could not be kept for the next examination: the store could not keep it (no space left)."
  rerender(<DoctorReportView result={examined(WINDOWS, [candidate("hcs", "primary", "unavailable", WINDOWS, ["strict"])], { history: { compared: [], ignored, not_kept: notKept } })} />)
  expect(region()).toHaveTextContent(ignored)
  expect(region()).toHaveTextContent("There is no previous report to compare with.")
  expect(region()).toHaveTextContent(notKept)
  expect(screen.queryByRole("alert")).not.toBeInTheDocument()
})

it("explains a host with no VM backend instead of listing any", () => {
  const wsl: HostBuild = { os: "wsl2", build: "6.6.87.2", architecture: "x86_64" }
  render(<DoctorReportView result={examined(wsl, [], { no_backend: "No VM sandbox backend runs inside WSL2: sandboxes run on the Windows host, and nested virtualization is a separate experiment (VM-W20)." })} />)
  expect(screen.getByText(/No VM sandbox backend runs inside WSL2/)).toBeInTheDocument()
  expect(screen.queryByRole("article")).not.toBeInTheDocument()
  expect(screen.getByRole("region", { name: "This computer" })).toHaveTextContent("Operating systemWSL2")
})

const PLAN: DoctorPlan = {
  notice: PLAN_NOTICE, os: "windows", profiles: ["strict"],
  checks: [
    {
      check: "VM-CP-01", families: ["VM-P01", "VM-P42"], side: { side: "host_observed" }, required: true, runs_here: true,
      control: "a normal launch on the same host succeeds and records the accelerator", note: null,
      observes: [
        { id: "cp01.accelerator", part: "primary", role: "observation", says: "the backend's launch record names an accelerator in {kvm, whpx, hvf, vz}" },
        { id: "cp01.no-tcg-hypervisor", part: "primary", role: "observation", says: "the host process list shows no hypervisor running with a TCG argument" },
        { id: "cp01.normal-launch-records-accelerator", part: "primary", role: "positive_control", says: "a normal launch on the same host succeeds and records the accelerator" },
      ],
    },
    {
      check: "VM-CP-02", families: ["VM-P02"], side: { side: "host_observed" }, required: true, runs_here: true, control: null, note: "golden_file_versioned_with_backend",
      observes: [{ id: "cp02.console", part: "primary", role: "observation", says: "no console" }],
    },
    { check: "VM-CP-04", families: ["VM-P04"], side: { side: "host_observed" }, required: true, runs_here: false, control: null, note: null, observes: [] },
    {
      check: "VM-CP-05", families: ["VM-P05"], side: { side: "guest_reported_with_host_corroboration", corroboration: ["booted_root_image", "kernel_build_record"] }, required: true, runs_here: true,
      control: "an image with io_uring enabled fails the kernel check", note: null,
      observes: [{ id: "cp05.root-image", part: "corroboration", fact: "booted_root_image", role: "observation", says: "the booted root image digest matches the signed manifest" }],
    },
    { check: "VM-CP-31", families: ["VM-P39"], side: { side: "host_observed_on_gpu_hardware" }, required: false, runs_here: true, control: "a qualifying device assigns and nvidia-smi runs in the guest", note: null, observes: [] },
  ],
}

it("lists each planned check with what it would observe, read only when the plan is opened", async () => {
  api.status.mockResolvedValue(windows())
  api.plan.mockResolvedValue(PLAN)
  const user = userEvent.setup()
  render(<SandboxDoctor />)
  await screen.findByRole("article", { name: "QEMU" })
  expect(api.plan).not.toHaveBeenCalled()
  const toggle = screen.getByRole("button", { name: "Show the plan" })
  expect(toggle).toHaveAttribute("aria-expanded", "false")
  await user.click(toggle)
  expect(api.plan).toHaveBeenCalledWith(undefined)
  const plan = await screen.findByRole("region", { name: "Plan of the checks" })
  expect(screen.getByRole("button", { name: "Hide the plan" })).toHaveAttribute("aria-expanded", "true")
  expect(plan).toHaveTextContent(PLAN_NOTICE)
  expect(plan).toHaveTextContent("For a Windows host and the run profiles strict, 4 of 5 checks are required.")
  const checks = within(within(plan).getByRole("list", { name: "Planned checks" })).getAllByRole("listitem").filter(item => item.parentElement?.getAttribute("aria-label") === "Planned checks")
  expect(checks).toHaveLength(5)
  expect(checks[0]).toHaveTextContent("VM-CP-01 · required · host-observed")
  expect(checks[0]).toHaveTextContent("Scenario families: VM-P01, VM-P42")
  expect(within(checks[0]!).getByRole("list", { name: "What VM-CP-01 would observe" }).children).toHaveLength(2)
  expect(checks[0]).toHaveTextContent("the host process list shows no hypervisor running with a TCG argument")
  expect(checks[0]).toHaveTextContent("Positive control: a normal launch on the same host succeeds and records the accelerator")
  expect(checks[1]).toHaveTextContent("The golden file is versioned with the backend. The plan lists no positive control.")
  expect(checks[2]).toHaveTextContent("VM-CP-04 · required · host-observed · cannot run on a Windows host")
  expect(checks[2]).toHaveTextContent("No observation of it applies on this computer.")
  expect(checks[3]).toHaveTextContent("guest-reported plus host corroboration")
  expect(checks[3]).toHaveTextContent("The guest's report counts only with the host observing the booted root image digest matching the signed manifest and the kernel build record (CONFIG_IO_URING absent) matching the signed manifest.")
  expect(checks[3]).toHaveTextContent("Host corroboration: the booted root image digest matches the signed manifest")
  expect(checks[4]).toHaveTextContent("VM-CP-31 · not required for these run profiles · host-observed on GPU hardware")
  await user.click(screen.getByRole("button", { name: "Hide the plan" }))
  expect(screen.queryByRole("region", { name: "Plan of the checks" })).not.toBeInTheDocument()
})

it("renders a plan on its own, the same as in the panel", () => {
  render(<DoctorPlanView plan={PLAN} />)
  expect(screen.getByRole("region", { name: "Plan of the checks" })).toHaveTextContent("VM-CP-05 · required · guest-reported plus host corroboration")
})

it("says plainly when this build has no doctor, and shows the engine's refusal as an error otherwise", async () => {
  api.status.mockRejectedValueOnce(new DoctorUnavailableError())
  const user = userEvent.setup()
  render(<SandboxDoctor />)
  expect(await screen.findByText("This build of Yougori can't show the VM sandbox doctor yet.")).toHaveAttribute("role", "status")
  expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  expect(screen.queryByRole("article")).not.toBeInTheDocument()
  api.status.mockRejectedValueOnce(new Error("Host evidence could not read this computer's operating system build."))
  await user.click(screen.getByRole("button", { name: "Check again" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Host evidence could not read this computer's operating system build.")
  expect(api.status).toHaveBeenCalledTimes(2)
})
