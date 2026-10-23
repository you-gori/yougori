// @vitest-environment jsdom
import { describe, expect, it } from "vitest"
import type { GridStatus } from "@/api/grid-api"
import { desksApi, type Desk, type DesksStatus } from "@/api/desks-api"
import { gridApi } from "@/api/grid-api"
import { swarmApi, type SwarmWorker } from "@/api/swarm-api"
import { bountyApi } from "@/api/bounty-api"
import { accessApi } from "@/api/access-api"
import {
  DESK_STATE_FROM_WORKSPACE, LEGACY_METHODS, STAGE_FROM_WORKER, WORKER_STATES_CORE_CANNOT_HOLD,
  WORKSPACE_STATE_FROM_DESK, seconds, toResearchJob, toWorkspace,
} from "@/api/grids/compat"
import { toModelsStatus } from "@/api/grids/profiles/models"
import { toWorkspacesStatus } from "@/api/grids/profiles/workspaces"

/** Today's answer from grid_status, written out, so a rename anywhere fails here. */
const gridStatus: GridStatus = {
  hub: {
    id: "g1", name: "Acme", address: "192.168.1.20", port: 7460, url: "https://192.168.1.20:7460/v1",
    fingerprint: "AB:CD", createdAt: "2026-10-18T09:00:00Z",
    computers: { total: 2, capable: 2, online: 1 },
    plans: [{ id: "p1", model: "hf.co/acme/assistant", quant: "Q4", percent: 50, rules: "always on", computers: 2, target: 1, ready: 1, scope: { kind: "computers", members: ["m1"] }, names: ["Design laptop"] }],
    planWarning: "One computer has no room",
    members: [{ id: "m1", name: "Design laptop", platform: "windows", joinedAt: "2026-10-18T09:05:00Z", capable: true, excluded: false, planId: "p1", jobs: 3, online: true, lastSeenSeconds: 2, address: "192.168.1.30", appVersion: "1.0.21", running: 1, models: [{ model: "hf.co/acme/assistant", state: "serving" }] }],
    queue: { waiting: 1, running: 2 },
    harnesses: [{ id: "h1", name: "review", model: "swarm/review", strategy: "plan", lead: "a", workers: ["b"], computers: 2, tasks: 3, rounds: 2, ready: true }],
    invite: "grid-invite:eyJ2IjoxfQ",
    closing: null,
  },
  hubError: null,
  member: {
    gridId: "g2", grid: "Other", hub: "https://grid.other.test", fingerprint: "EF:01", memberId: "m9",
    joinedAt: "2026-10-18T10:00:00Z", connected: true, error: null, capable: true, backend: "cuda",
    assignment: { model: "hf.co/acme/assistant", quant: "Q4" }, rules: "always on", state: "serving",
    reason: null, progress: { phase: "downloading", done: 1, total: 2, rate: 10 }, jobs: 12, failures: 0, lastError: null,
  },
  memberError: null,
}

const desk: Desk = {
  id: "d1", name: "Dana's desk", spec: { kind: "vm", cpu: 4, memoryGb: 16, diskGb: 120, gpu: false, image: "ubuntu" },
  summary: "Ubuntu desktop", personId: "p1", person: "Dana", username: "dana", state: "building",
  note: "Building on Studio PC", hostId: "m2", host: "Studio PC", hostOnline: true, reachable: false,
  environmentId: null, attempts: 1, createdAt: 10, updatedAt: 20,
}

const desksStatus: DesksStatus = {
  hub: {
    id: "s1", name: "Acme", address: "192.168.1.20", port: 7463, fingerprint: "AB:CD", createdAt: "2026-10-18T09:00:00Z",
    computers: { total: 1, capable: 1, online: 1 },
    members: [{
      id: "m2", name: "Studio PC", platform: "windows", joinedAt: "2026-10-18T09:05:00Z", capable: true,
      excluded: false, planId: null, jobs: 0, online: true, lastSeenSeconds: 1, address: "192.168.1.31",
      appVersion: "1.0.21", running: 0, models: [],
      capacity: { cpu: 16, cpuUsedPercent: 70, memoryGb: 64, usedMemoryGb: 40, freeDiskGb: 80, gpu: true, gpuUsedPercent: 55, onBattery: false, inUse: true },
      share: { cpu: 2, memoryGb: 8, diskGb: 50, gpu: true, idleOnly: true }, shareSet: true, desks: 1,
    }],
    desks: [desk],
    people: [{ id: "p1", username: "dana", name: "Dana", adminRole: "administrator", mfa: true, createdAt: 5, lastLoginAt: 9, desks: ["d1"] }],
  },
  hubError: null,
  member: null,
  memberError: null,
  hosting: [{ id: "d1", name: "Dana's desk", environmentId: "e1", shared: true }],
  desk: {
    gridId: "s1", grid: "Acme", username: "dana", personId: "p1", name: "Dana", signedInAt: 11, adminRole: "operator", mfa: true,
    desks: [{ id: "d1", name: "Dana's desk", state: "building", note: "", host: "Studio PC", environmentId: null, address: null }],
    connections: [{ id: "c1", name: "Citrix", provider: "citrix", url: "https://citrix.acme.test", roleIds: [] }],
  },
}

const worker: SwarmWorker = {
  id: "w1", name: "Keen heron", model: "hf.co/acme/model", state: "paused", stage: "Working on the bounty",
  gpu: "NVIDIA", resources: { cpu: 4, memoryGb: 16 }, workspaceQuotaGb: 20, keepResident: false,
  error: null, summary: "Reading the source", completedAttempts: 2, bountyId: "bounty-7", quant: "Q4",
  networkMode: "closed", createdAt: 100,
}

describe("the legacy answer, turned into Grid Core's shape", () => {
  it("keeps everything the Closed Neo Grid page reads, including what a membership says about its model", () => {
    const status = toModelsStatus(gridStatus)
    expect(status.profile).toBe("models")
    expect(status.hub).toMatchObject({ id: "g1", name: "Acme", port: 7460, profile: "models", invite: "grid-invite:eyJ2IjoxfQ" })
    expect(status.hosts[0]).toMatchObject({ id: "m1", name: "Design laptop", platform: "windows", capable: true, excluded: false, draining: false, planId: "p1", jobs: 3, running: 1 })
    expect(status.hosts[0]!.joinedAt).toBe(seconds("2026-10-18T09:05:00Z"))
    expect(status.plans[0]).toMatchObject({ id: "p1", model: "hf.co/acme/assistant", quant: "Q4", percent: 50, wanted: 1, ready: 1, computers: 2, rules: "always on", names: ["Design laptop"] })
    expect(status.plans[0]!.target).toEqual({ kind: "hosts", hosts: ["m1"] })
    expect(status.planWarning).toBe("One computer has no room")
    expect(status.queue).toEqual({ waiting: 1, running: 2 })
    expect(status.harnesses[0]!.model).toBe("swarm/review")
    expect(status.member).toMatchObject({ realmId: "g2", realm: "Other", deviceId: "m9", connected: true })
    expect(status.assignment).toEqual({
      model: "hf.co/acme/assistant", quant: "Q4", rules: "always on", state: "serving", reason: null,
      progress: { phase: "downloading", done: 1, total: 2, rate: 10 }, jobs: 12, failures: 0, lastError: null,
    })
  })

  it("keeps everything the Sandbox Grid pages read, including a desk that is building and a share", () => {
    const status = toWorkspacesStatus(desksStatus)
    expect(status.hub).toMatchObject({ id: "s1", port: 7463, profile: "workspaces" })
    expect(status.hosts[0]).toMatchObject({
      id: "m2", commitment: "share", offerSet: true, workspaces: 1,
      capacity: { cpu: 16, memoryGb: 64, diskGb: 80, gpu: true },
      offered: { cpu: 2, memoryGb: 8, diskGb: 50, gpu: true, idleOnly: true },
      load: { cpuUsedPercent: 70, usedMemoryGb: 40, freeDiskGb: 80, gpuUsedPercent: 55, onBattery: false, inUse: true },
    })
    expect(status.workspaces[0]).toMatchObject({
      id: "d1", name: "Dana's desk", ownerId: "p1", owner: "Dana", username: "dana", kind: "vm", image: "ubuntu",
      access: "standard", state: "provisioning", productState: "building", host: "Studio PC", hostOnline: true, reachable: false,
    })
    expect(status.people[0]).toMatchObject({ id: "p1", username: "dana", roles: ["realmAdmin"], twoStep: true })
    expect(status.me).toMatchObject({ realm: "Acme", strong: true })
    expect(status.me?.principal.roles).toEqual(["operator"])
    expect(status.mine[0]).toMatchObject({ id: "d1", state: "building" })
    expect(status.connections[0]).toEqual({ id: "c1", name: "Citrix", provider: "citrix", url: "https://citrix.acme.test" })
    expect(status.hosting[0]).toMatchObject({ id: "d1", shared: true })
  })

  it("says so plainly when Grid Core has no state for a desk, rather than losing the product's own word", () => {
    expect(WORKSPACE_STATE_FROM_DESK).toEqual({ planned: "requested", building: "provisioning", ready: "ready", failed: "failed", moving: "draining" })
    expect(DESK_STATE_FROM_WORKSPACE.assigned).toBe("ready")
    expect(DESK_STATE_FROM_WORKSPACE.archived).toBe("failed")
    for (const state of ["planned", "building", "ready", "failed", "moving"] as const) {
      expect(toWorkspace({ ...desk, state }, "s1").productState).toBe(state)
    }
  })

  it("keeps a paused worker paused, which core stages cannot say at all", () => {
    const job = toResearchJob(worker, "research")
    expect(job.state).toBe("paused")
    expect(job.stage).toBeNull()
    expect(job).toMatchObject({
      id: "w1", name: "Keen heron", model: "hf.co/acme/model", quant: "Q4", summary: "Reading the source",
      step: "Working on the bounty", gpu: "NVIDIA", workspaceQuotaGb: 20, network: "closed", attempts: 2,
      subjectId: "bounty-7", startedAt: 100,
    })
    for (const state of WORKER_STATES_CORE_CANNOT_HOLD) expect(STAGE_FROM_WORKER[state]).toBeNull()
    expect(STAGE_FROM_WORKER.running).toBe("running")
  })

  it("reads a time whichever of the two ways a product answers with one", () => {
    expect(seconds(1_760_000_000)).toBe(1_760_000_000)
    expect(seconds("2026-10-18T09:00:00Z")).toBe(Math.floor(Date.parse("2026-10-18T09:00:00Z") / 1000))
    expect(seconds("")).toBe(0)
    expect(seconds("not a time")).toBe(0)
  })
})

describe("the table of what replaces what", () => {
  const surfaces: Record<string, Record<string, unknown>> = {
    "grid-api": gridApi, "desks-api": desksApi, "swarm-api": swarmApi, "bounty-api": bountyApi, "access-api": accessApi,
  }

  it("names a method that is really there, for every row", () => {
    for (const row of LEGACY_METHODS) {
      const [surface, method] = row.legacy.split(".") as [string, string]
      const object = surfaces[row.module]
      expect(object, `${row.module} is not a module this table knows`).toBeTruthy()
      expect(typeof object?.[method], `${row.legacy} is gone`).toBe("function")
      expect(surface).toBeTruthy()
    }
  })

  it("covers every method the four modules still export", () => {
    for (const [module, object] of Object.entries(surfaces)) {
      const covered = new Set(LEGACY_METHODS.filter(row => row.module === module).map(row => row.legacy.split(".")[1]))
      for (const [name, value] of Object.entries(object)) {
        if (typeof value === "function") expect(covered.has(name), `${module}.${name} is in no row of LEGACY_METHODS`).toBe(true)
      }
    }
  })
})
