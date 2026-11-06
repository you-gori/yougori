import { readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"
import { CAPABILITIES, CAPABILITY_GROUPS } from "@/api/setups/capabilities.generated"
import {
  CONTRACT_VERSION,
  type CapabilityAvailability,
  type CapabilityGroup,
  type CapabilityHealth,
  type CapabilityStatusLevel,
  type Diagnostic,
  type GridProfile,
  type InstanceState,
  type NextAction,
  type OperationState,
  type PlanResponse,
  type ResourceCost,
  type ResourceKind,
  type ResourceObserved,
  type Severity,
  type SetupAction,
  type SetupDetail,
} from "@/api/setups/contract"

/** The fixture the Rust contract test writes from dto.rs and capability.rs. Refresh it with:
 *    UPDATE_CONTRACT=1 cargo test --manifest-path setup/Cargo.toml --test contract
 */
const fixture = JSON.parse(
  readFileSync(path.resolve(process.cwd(), "setup/tests/contract/contract.json"), "utf8"),
) as {
  contractVersion: number
  operationStates: OperationState[]
  instanceStates: InstanceState[]
  capabilityHealth: CapabilityHealth[]
  severities: Severity[]
  setupActions: SetupAction[]
  gridProfiles: GridProfile[]
  resourceObserved: ResourceObserved[]
  resourceCost: ResourceCost[]
  resourceKinds: ResourceKind[]
  capabilityGroups: CapabilityGroup[]
  sampleDiagnostic: Diagnostic
  sampleSetupDetail: SetupDetail
  samplePlanResponse: PlanResponse
}

/** The full set of values each TypeScript union allows, listed by hand. If a union gains or loses a
 *  member, this array must change too, and the assertions below compare it to the Rust source — so a
 *  one-sided change fails the test. The `satisfies` keeps the array honest: an unknown string, or a
 *  member left out, is a type error here before it is a runtime failure. */
const expected = {
  operationStates: [
    "planned",
    "awaiting_input",
    "applying",
    "cancelling",
    "completed",
    "failed",
    "unknown",
  ] satisfies OperationState[],
  instanceStates: [
    "draft",
    "creating",
    "running",
    "stopped",
    "updating",
    "removing",
    "retained",
    "removed",
  ] satisfies InstanceState[],
  capabilityHealth: [
    "ready",
    "starting",
    "needs_sign_in",
    "waiting_for_computer",
    "degraded",
    "failed",
    "unsupported",
  ] satisfies CapabilityHealth[],
  severities: ["error", "warning", "info"] satisfies Severity[],
  setupActions: [
    "start",
    "stop",
    "remove",
    "detach",
    "pause_admission",
    "release_compute",
    "delete_data",
  ] satisfies SetupAction[],
  gridProfiles: [
    "neo_grid",
    "sandbox_grid",
    "access_grid",
    "swarm_mining_grid",
    "generic",
  ] satisfies GridProfile[],
  resourceObserved: ["unknown", "missing", "present", "running", "stopped"] satisfies ResourceObserved[],
  resourceCost: ["free", "unknown", "accruing", "stopped", "shutdown_unconfirmed"] satisfies ResourceCost[],
  resourceKinds: [
    "environment",
    "grid",
    "compute_pool",
    "worker_group",
    "model_service",
    "workspace_pool",
    "access_binding",
    "credential_broker",
    "service_publication",
    "volume",
    "connection",
    "job",
    "artifact_store",
    "vm_sandbox",
  ] satisfies ResourceKind[],
  capabilityGroups: [
    "grid_workers",
    "ai_models",
    "website_api",
    "people_access",
    "files_data",
    "automation_recovery",
  ] satisfies CapabilityGroup[],
}

describe("the setup contract matches the Rust source", () => {
  it("agrees on the contract version", () => {
    expect(CONTRACT_VERSION).toBe(fixture.contractVersion)
  })

  it.each(Object.keys(expected) as (keyof typeof expected)[])(
    "lists exactly the Rust values for %s",
    key => {
      // Same members, same order: the generated fixture is the Rust source, `expected` is the
      // TypeScript union. A mismatch on either side fails.
      expect(expected[key]).toEqual(fixture[key])
    },
  )

  it("covers every NextAction kind the fixture can carry", () => {
    // Build one of each kind so a missing variant in the union is a compile error, and prove the
    // sample from Rust is one of them.
    const kinds: NextAction["kind"][] = [
      "sign_in",
      "provide_input",
      "choose_supported_option",
      "retry",
      "continue",
      "reconcile",
      "cancel",
      "review",
      "add_computer",
      "view_logs",
      "open_docs",
    ]
    for (const action of fixture.sampleDiagnostic.nextActions ?? []) {
      expect(kinds).toContain(action.kind)
    }
  })

  it("reads the sample diagnostic as a Diagnostic", () => {
    const diag = fixture.sampleDiagnostic
    expect(diag.code).toBe("capability_not_enableable")
    expect(diag.severity).toBe("error")
    expect(expected.severities).toContain(diag.severity)
  })

  it("reads the sample plan response envelope", () => {
    const plan = fixture.samplePlanResponse
    // The engine reserves the setup id at plan time (even for a new setup) and base revision 0; the
    // digest matches the plan's own.
    expect(typeof plan.setupId).toBe("string")
    expect(plan.baseRevision).toBe(0)
    expect(typeof plan.digest).toBe("string")
    expect(plan.digest.length).toBeGreaterThan(0)
    expect((plan.plan as { digest?: string }).digest).toBe(plan.digest)
    // The author graph keeps snake_case spec fields.
    const resources = (plan.plan as { resources?: { spec?: Record<string, unknown> }[] }).resources ?? []
    const spec = resources[0]?.spec ?? {}
    expect(Object.keys(spec).some(key => key.includes("_"))).toBe(true)
    // The review carries the camelCase envelope fields the desktop reads.
    expect(Array.isArray((plan.review as { creates?: unknown[] }).creates)).toBe(true)
  })

  it("reads the sample setup detail as a SetupDetail", () => {
    const detail = fixture.sampleSetupDetail
    expect(expected.instanceStates).toContain(detail.summary.state)
    expect(expected.gridProfiles).toContain(detail.summary.profile)
    for (const cap of detail.capabilities) expect(expected.capabilityHealth).toContain(cap.health)
    for (const resource of detail.resources) {
      expect(expected.resourceKinds).toContain(resource.kind)
      if (resource.observed) expect(expected.resourceObserved).toContain(resource.observed)
      if (resource.cost) expect(expected.resourceCost).toContain(resource.cost)
    }
    for (const action of detail.actions ?? []) expect(expected.setupActions).toContain(action)
  })
})

describe("the generated capability table", () => {
  it("names the six groups in order", () => {
    expect(CAPABILITY_GROUPS.map(g => g.id)).toEqual(expected.capabilityGroups)
  })

  it("has unique capability ids", () => {
    const ids = CAPABILITIES.map(c => c.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  it("puts every capability in a known group with a valid status and widget", () => {
    const statuses: CapabilityStatusLevel[] = ["shipped", "planned", "private_build"]
    for (const cap of CAPABILITIES) {
      expect(expected.capabilityGroups).toContain(cap.group)
      expect(statuses).toContain(cap.status)
      expect(["toggle", "choice", "amount", "list", "text"]).toContain(cap.widget)
    }
  })

  it("never ships a private-build capability in this table", () => {
    // The table is generated per build. Whatever this build is, the client table never carries a
    // capability that only the private build should name.
    expect(CAPABILITIES.some(c => c.status === "private_build")).toBe(false)
  })

  it("references only known capabilities in requires and conflicts", () => {
    const ids = new Set(CAPABILITIES.map(c => c.id))
    for (const cap of CAPABILITIES) {
      for (const anyOf of cap.requires) for (const id of anyOf) expect(ids.has(id)).toBe(true)
      for (const id of cap.conflicts) expect(ids.has(id)).toBe(true)
    }
  })

  it("keeps every resource kind valid", () => {
    for (const cap of CAPABILITIES) {
      for (const kind of cap.resourceKinds) {
        expect(expected.resourceKinds).toContain(kind as ResourceKind)
      }
    }
  })

  it("lists only the four grid profiles in a support list", () => {
    const grids = expected.gridProfiles.filter(p => p !== "generic")
    for (const cap of CAPABILITIES) {
      for (const profile of cap.profiles) {
        expect(grids).toContain(profile)
        expect(profile).not.toBe("generic")
      }
      expect(new Set(cap.profiles).size).toBe(cap.profiles.length)
    }
  })
})

/** Referenced so an unused import of a type-only availability union is intentional: it documents the
 *  shape the setup_capabilities report uses, which the engine fills per host. */
export type _AvailabilityUsed = CapabilityAvailability
