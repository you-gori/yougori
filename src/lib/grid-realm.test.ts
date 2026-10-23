// @vitest-environment jsdom
import { expect, it } from "vitest"
import { gridRealms, gridsHint, modelsRealm, researchRealm, workspacesRealm } from "@/lib/grid-realm"
import type { GridStatus } from "@/api/grid-api"
import type { DesksStatus } from "@/api/desks-api"
import type { SwarmWorker } from "@/api/swarm-api"

const hub = {
  id: "g1", name: "Acme", address: "192.168.1.20", port: 7460, url: "https://192.168.1.20:7460/v1",
  fingerprint: "AB:CD", createdAt: "", computers: { total: 2, capable: 2, online: 1 },
  plans: [], planWarning: null, members: [], queue: { waiting: 1, running: 2 }, harnesses: [],
}
const models: GridStatus = { hub, hubError: null, member: null, memberError: null }
const nothing: GridStatus = { hub: null, hubError: null, member: null, memberError: null }

const desks: DesksStatus = {
  hub: {
    id: "d1", name: "Acme", address: "192.168.1.20", port: 7463, fingerprint: "AB:CD", createdAt: "",
    computers: { total: 2, capable: 2, online: 2 }, members: [], desks: [], people: [],
  },
  hubError: null, member: null, memberError: null, hosting: [], desk: null,
}

const worker = { id: "w1", name: "Keen heron", model: "hf.co/acme/model-GGUF", state: "running", stage: "", gpu: "", resources: {}, workspaceQuotaGb: 20, keepResident: false, error: null, summary: "Reading the source", createdAt: 0 } as unknown as SwarmWorker

it("says Not set up, in the words every other row of this app uses", () => {
  expect(modelsRealm(nothing, "Studio PC").hint).toBe("Not set up")
  expect(workspacesRealm(null, "Studio PC").hint).toBe("Not set up")
  expect(modelsRealm(nothing, "Studio PC").present).toBe(false)
  expect(gridsHint([modelsRealm(nothing, "Studio PC")])).toBe("Not set up")
})

it("keeps each grid's own line exactly as it was", () => {
  expect(modelsRealm(models, "Studio PC").hint).toBe("1 of 2 computers online")
  expect(workspacesRealm(desks, "Studio PC").hint).toBe("0 desks · 2 of 2 computers online")
  expect(researchRealm([worker], "Studio PC").hint).toBe("1 working · 1 worker")
  expect(researchRealm([], "Studio PC").hint).toBe("No workers")
})

it("says what a grid is in a sentence, with the computer's name and never a path", () => {
  const realm = modelsRealm(models, "Studio PC")
  expect(realm.name).toBe("Acme")
  expect(realm.state).toBe("Open, hosted on Studio PC, with 1 of 2 computers online.")
  expect(realm.reach).toBe("192.168.1.20:7460 on your own network")
  expect(realm.keyHolder).toBe("Studio PC")
  expect(realm.work).toEqual({ queued: 1, running: 2, finished: 0 })
  expect(realm.capabilities).toEqual(["models"])
})

it("gives a member of somebody else's grid the member's view and nothing more", () => {
  const member: GridStatus = {
    hub: null, hubError: null, memberError: null,
    member: {
      gridId: "g1", grid: "Acme", hub: "https://grid.acme.com", fingerprint: "AB:CD", memberId: "m9",
      joinedAt: "", connected: true, error: null, capable: true, jobs: 0, failures: 0, lastError: null,
    } as GridStatus["member"],
  }
  const realm = modelsRealm(member, "Studio PC")
  expect(realm.role).toBe("member")
  expect(realm.hint).toBe("Member of Acme")
  expect(realm.reach).toBeNull()
  expect(realm.held.roles).toEqual(["user"])
})

it("lists every grid on this computer, and counts only the ones that are really there", () => {
  const realms = gridRealms({ grid: models, desks, access: null, workers: [], thisComputer: "Studio PC" })
  expect(realms.map(realm => realm.key)).toEqual(["workspaces", "models", "research", "credentials"])
  expect(realms.filter(realm => realm.present).map(realm => realm.key)).toEqual(["workspaces", "models"])
  expect(gridsHint(realms)).toBe("2 grids")
})
