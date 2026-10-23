// @vitest-environment jsdom
//
// Every method of the four profiles, proved against the command and the arguments the product
// pages reach today. The transport is replaced throughout, so nothing here reaches an engine:
// no grid is created, no desk is built, and no research worker is prepared, paused or run.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"

const accessCalls: Array<{ method: string; args: unknown[] }> = []
const accessAnswer: { status: unknown; manage: unknown } = { status: {}, manage: {} }
const spy = (method: string, pick: "status" | "manage" = "manage") =>
  vi.fn(async (...args: unknown[]) => { accessCalls.push({ method, args }); return accessAnswer[pick] })

vi.mock("@/api/access-api", () => ({
  accessApi: {
    status: spy("status", "status"),
    create: spy("create", "status"),
    delete: spy("delete"),
    restore: spy("restore"),
    signIn: spy("signIn", "status"),
    signInSso: spy("signInSso", "status"),
    signOut: spy("signOut"),
    manage: spy("manage"),
    account: spy("account"),
    backup: spy("backup"),
    restoreBackup: spy("restoreBackup", "status"),
  },
  TWO_STEP_MESSAGE: "Enter the six-digit code from your authenticator app",
}))

const { grids } = await import("@/api/grids")
const { CliOnlyError, NotAllowedError } = await import("@/api/grids/errors")
const { resetTransport, setTransport } = await import("@/api/grids/wire")

let sent: Array<{ command: string; args: Record<string, unknown> }> = []
let answer: unknown = {}

beforeEach(() => {
  sent = []
  accessCalls.length = 0
  answer = {}
  accessAnswer.status = { hub: { id: "a1", company: "Acme", address: "1.2.3.4", port: 7465, fingerprint: "AB", createdAt: 1, tunnelPort: null, owner: null, people: 1, credentials: 0, rules: 0, waiting: 0, signedIn: 1, sso: false, requireTwoStep: false }, hubError: null, member: null, memberError: null, me: null, suggestedAddress: "1.2.3.4", mcp: { command: "yougori", args: ["access", "mcp"] } }
  accessAnswer.manage = {}
  setTransport(async (command, args) => { sent.push({ command, args }); return answer as never })
})

afterEach(() => { resetTransport() })

const only = () => {
  expect(sent).toHaveLength(1)
  return sent[0]!
}

describe("the models profile", () => {
  beforeEach(async () => {
    answer = { hub: { id: "g1", name: "Acme", address: "1.2.3.4", port: 7460, url: "", fingerprint: "AB", createdAt: "", computers: { total: 0, capable: 0, online: 0 }, plans: [], planWarning: null, members: [], queue: { waiting: 0, running: 0 }, harnesses: [] }, hubError: null, member: null, memberError: null }
    await grids.models.status()
    sent = []
    answer = {}
  })

  it("reads the hub and this computer's membership", async () => {
    answer = { hub: null, hubError: null, member: null, memberError: null }
    const status = await grids.models.status()
    expect(only().command).toBe("grid_status")
    expect(status.profile).toBe("models")
    expect(status.hub).toBeNull()
  })

  it("asks for this computer's address to host on", async () => {
    answer = "192.168.1.20"
    await grids.models.suggestedAddress()
    expect(only()).toEqual({ command: "grid_suggested_address", args: {} })
  })

  it("hosts, joins, leaves, schedules a deletion and takes it back", async () => {
    answer = { hub: null, hubError: null, member: null, memberError: null }
    await grids.models.host("Acme", "192.168.1.20", "pass", "quick")
    await grids.models.join("grid-invite:x", "pass")
    answer = {}
    await grids.models.leave()
    await grids.models.scheduleDeletion("later")
    await grids.models.restore()
    expect(sent.map(entry => entry.command)).toEqual(["grid_create", "grid_join", "grid_leave", "grid_delete", "grid_restore"])
    expect(sent[0]!.args).toEqual({ name: "Acme", address: "192.168.1.20", password: "pass", tunnel: "quick" })
    expect(sent[1]!.args).toEqual({ invite: "grid-invite:x", password: "pass" })
    expect(sent[3]!.args).toEqual({ when: "later" })
  })

  it("hosts on a saved domain when that is the reach", async () => {
    answer = { hub: null, hubError: null, member: null, memberError: null }
    await grids.models.host("Acme", "192.168.1.20", "pass", { domain: "grid.acme.test" })
    expect(only().args).toMatchObject({ tunnel: "grid.acme.test" })
  })

  it("orders a model both ways round, with the arguments the engine reads", async () => {
    await grids.models.addPlan({ model: "hf.co/acme/a", target: { kind: "all", percent: 50 } })
    await grids.models.addPlan({ model: "hf.co/acme/a", quant: "Q4", target: { kind: "hosts", hosts: ["m1", "m2"] } })
    expect(sent[0]!.args).toEqual({ model: "hf.co/acme/a", scope: "all", percent: 50, computers: null, quant: null })
    expect(sent[1]!.args).toEqual({ model: "hf.co/acme/a", computers: ["m1", "m2"], scope: null, percent: null, quant: "Q4" })
  })

  it("removes a plan, and leaves a computer out and brings it back", async () => {
    await grids.models.removePlan("p1")
    await grids.models.removeHost("m1")
    await grids.models.drainHost("m1")
    await grids.models.bringHostBack("m1")
    expect(sent.map(entry => entry.command)).toEqual(["grid_plan_remove", "grid_member_remove", "grid_member_exclude", "grid_member_include"])
    expect(sent[2]!.args).toEqual({ memberId: "m1" })
  })

  it("reads the rented GPUs, adds one, removes one and stops them all", async () => {
    answer = { hosting: true, max: 8, hourlyUsd: 0, members: [], candidates: [], notice: null }
    expect((await grids.models.rentedGpus()).max).toBe(8)
    answer = {}
    await grids.models.addRentedGpu("pod-1")
    await grids.models.removeRentedGpu("pod-1")
    await grids.models.stopRentedGpus()
    expect(sent.map(entry => entry.command)).toEqual(["grid_neocloud_status", "grid_neocloud_add", "grid_neocloud_remove", "grid_neocloud_stop_all"])
    expect(sent[1]!.args).toEqual({ environmentId: "pod-1" })
    expect(sent[2]!.args).toEqual({ environmentId: "pod-1" })
  })

  it("offers rented GPUs only on the computer that runs the hub", async () => {
    answer = { hub: null, hubError: null, member: null, memberError: null }
    await grids.models.status()
    sent = []
    expect(() => grids.models.addRentedGpu("pod-1")).toThrow(NotAllowedError)
    expect(() => grids.models.removeRentedGpu("pod-1")).toThrow(NotAllowedError)
    expect(() => grids.models.stopRentedGpus()).toThrow(NotAllowedError)
    expect(sent).toHaveLength(0)
  })

  it("adds, removes and runs a team of models", async () => {
    await grids.models.addHarness({ name: "review", strategy: "plan", lead: "a", workers: ["b"], computers: 2, rounds: 2 })
    await grids.models.removeHarness("h1")
    await grids.models.runHarness("review", "Look at this")
    expect(sent.map(entry => entry.command)).toEqual(["grid_swarm_add", "grid_swarm_remove", "grid_swarm_run"])
    expect(sent[0]!.args).toMatchObject({ name: "review", tasks: null })
    expect(sent[2]!.args).toEqual({ harness: "review", prompt: "Look at this" })
  })

  it("filters and pages the computers without asking the engine twice for one page", async () => {
    answer = { hub: { id: "g1", name: "Acme", address: "", port: 7460, url: "", fingerprint: "", createdAt: "", computers: { total: 2, capable: 2, online: 1 }, plans: [], planWarning: null, queue: { waiting: 0, running: 0 }, harnesses: [], members: [
      { id: "m1", name: "Design laptop", platform: "windows", joinedAt: "", capable: true, excluded: false, planId: null, jobs: 0, online: true, lastSeenSeconds: 1, address: null, appVersion: null, running: 0, models: [] },
      { id: "m2", name: "Studio PC", platform: "windows", joinedAt: "", capable: true, excluded: true, planId: null, jobs: 0, online: false, lastSeenSeconds: null, address: null, appVersion: null, running: 0, models: [] },
    ] }, hubError: null, member: null, memberError: null }
    const online = await grids.models.hosts({ online: true })
    expect(online.items.map(host => host.id)).toEqual(["m1"])
    expect(online.total).toBe(1)
    const found = await grids.models.hosts({ search: "studio" })
    expect(found.items.map(host => host.name)).toEqual(["Studio PC"])
    expect(sent).toHaveLength(2)
  })

  it("names the command line for what only the command line can do, rather than pretending", () => {
    const lines = [
      () => grids.models.changePlan(),
      () => grids.models.changePassword(),
      () => grids.models.addKey(),
      () => grids.models.revokeKey(),
    ]
    for (const line of lines) expect(line).toThrow(CliOnlyError)
    expect(() => grids.models.changePassword()).toThrow("yougori grid password --yes")
    expect(() => grids.models.revokeKey()).toThrow("yougori grid revoke-key KEY_ID --yes")
    expect(sent).toHaveLength(0)
  })

  it("reads a company out of an invite without asking anything", () => {
    const code = "grid-invite:" + btoa(JSON.stringify({ v: 1, c: "Acme", a: "https://grid.acme.test", f: "ab:cd" })).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")
    expect(grids.models.readInvite(code)).toEqual({ company: "Acme", address: "https://grid.acme.test", fingerprint: "ABCD" })
    expect(grids.models.readInvite("desk-invite:x")).toBeNull()
    expect(sent).toHaveLength(0)
  })
})

describe("the workspaces profile", () => {
  const hub = { id: "s1", name: "Acme", address: "1.2.3.4", port: 7463, fingerprint: "AB", createdAt: "", computers: { total: 0, capable: 0, online: 0 }, members: [], desks: [], people: [] }

  beforeEach(async () => {
    answer = { hub, hubError: null, member: null, memberError: null, hosting: [], desk: null }
    await grids.workspaces.status()
    sent = []
    answer = {}
  })

  it("reaches every one of the sandbox grid's commands with the names it reads", async () => {
    answer = { hub, hubError: null, member: null, memberError: null, hosting: [], desk: null }
    await grids.workspaces.status()
    await grids.workspaces.host("Acme", "1.2.3.4", "pass")
    await grids.workspaces.join("desk-invite:x", "pass", "Studio PC")
    answer = {}
    await grids.workspaces.leave()
    await grids.workspaces.scheduleDeletion("now")
    await grids.workspaces.restore()
    await grids.workspaces.removeHost("m1")
    await grids.workspaces.setOffer("m1", { cpu: 2, memoryGb: 8, diskGb: 50, gpu: true, idleOnly: true })
    await grids.workspaces.suggestOffer("m1")
    await grids.workspaces.adoptMembership({ any: "thing" })
    expect(sent.map(entry => entry.command)).toEqual([
      "desks_status", "desks_create", "desks_join", "desks_leave", "desks_delete", "desks_restore",
      "desks_member_remove", "desks_member_share", "desks_member_share", "desks_adopt_membership",
    ])
    expect(sent[2]!.args).toEqual({ invite: "desk-invite:x", password: "pass", name: "Studio PC" })
    expect(sent[7]!.args).toEqual({ memberId: "m1", cpu: 2, memoryGb: 8, diskGb: 50, gpu: true, idleOnly: true })
    expect(sent[8]!.args).toEqual({ memberId: "m1", suggested: true })
  })

  it("adds a person and orders their workspace in the same step", async () => {
    await grids.workspaces.addPerson({ username: "dana", name: "Dana", password: "pass", workspace: { kind: "vm", cpu: 4, memoryGb: 16, diskGb: 120, gpu: false } })
    expect(only()).toEqual({ command: "desks_person_add", args: { username: "dana", name: "Dana", password: "pass", kind: "vm", cpu: 4, memoryGb: 16, diskGb: 120, gpu: false } })
  })

  it("orders, gives out, retries and removes a workspace", async () => {
    await grids.workspaces.order({ name: "Dana's desk", ownerId: "p1", kind: "container", shape: { cpu: 2, memoryGb: 8, diskGb: 40, gpu: false } })
    await grids.workspaces.assign("d1", "p1")
    await grids.workspaces.assign("d1", null)
    await grids.workspaces.retry("d1")
    await grids.workspaces.remove("d1")
    expect(sent.map(entry => entry.command)).toEqual(["desks_add", "desks_assign", "desks_assign", "desks_retry", "desks_remove"])
    expect(sent[0]!.args).toEqual({ name: "Dana's desk", person: "p1", kind: "container", cpu: 2, memoryGb: 8, diskGb: 40, gpu: false, image: null })
    expect(sent[2]!.args).toEqual({ desk: "d1", person: null })
  })

  it("signs a person in, refreshes and signs them out", async () => {
    answer = { gridId: "s1", grid: "Acme", username: "dana", personId: "p1", name: "Dana", signedInAt: 1, desks: [] }
    const me = await grids.workspaces.signIn("desk-invite:x", "dana", "pass", "123456")
    await grids.workspaces.signInSso("desk-invite:x")
    await grids.workspaces.refresh()
    answer = {}
    await grids.workspaces.signOut()
    expect(me.principal.username).toBe("dana")
    expect(sent.map(entry => entry.command)).toEqual(["desk_login", "desk_login", "desk_refresh", "desk_logout"])
    expect(sent[0]!.args).toEqual({ invite: "desk-invite:x", username: "dana", password: "pass", code: "123456" })
    expect(sent[1]!.args).toEqual({ invite: "desk-invite:x", sso: true })
  })

  it("sends an admin action through the one door it already has, with its name unchanged", async () => {
    await grids.workspaces.manage({ action: "personAdd", username: "dana" })
    expect(only()).toEqual({ command: "desks_manage", args: { request: { action: "personAdd", username: "dana" } } })
  })

  it("refuses before it asks when the person signed in may not do it, and says so in words", async () => {
    answer = { hub: null, hubError: null, member: null, memberError: null, hosting: [], desk: { gridId: "s1", grid: "Acme", username: "dana", personId: "p1", name: "Dana", signedInAt: 1, adminRole: "user", desks: [] } }
    await grids.workspaces.status()
    sent = []
    expect(grids.workspaces.who().roles).toEqual(["user"])
    expect(() => grids.workspaces.order({ name: "x", kind: "vm", shape: { cpu: 1, memoryGb: 1, diskGb: 1, gpu: false } })).toThrow(NotAllowedError)
    expect(() => grids.workspaces.order({ name: "x", kind: "vm", shape: { cpu: 1, memoryGb: 1, diskGb: 1, gpu: false } })).toThrow("This account may not manage workspaces in this grid")
    expect(sent).toHaveLength(0)
  })
})

describe("the research profile", () => {
  it("reads, saves and resets worker prompts through the engine", async () => {
    answer = { agents: { value: "Line one\nLine two", default: "Default", custom: true } }
    expect(await grids.research.prompts()).toEqual(answer)
    await grids.research.savePrompts({ agents: "Updated", rules: "" })
    await grids.research.resetPrompts()
    expect(sent).toEqual([
      { command: "swarm_dispatch", args: { request: { action: "promptsGet" } } },
      { command: "swarm_dispatch", args: { request: { action: "promptsSet", agents: "Updated", rules: "" } } },
      { command: "swarm_dispatch", args: { request: { action: "promptsReset" } } },
    ])
  })
  const paused = { id: "w1", name: "Keen heron", model: "m", state: "paused", stage: "", gpu: "", resources: {}, workspaceQuotaGb: 20, keepResident: false, error: null, summary: "", createdAt: 1 }

  it("is one request per action, and starts nothing on its own", async () => {
    answer = { workers: [] }
    await grids.research.status()
    answer = { worker: paused }
    await grids.research.job("w1")
    answer = { worker: paused, events: [], latest: 3 }
    await grids.research.steps("w1", 2)
    expect(sent.map(entry => entry.command)).toEqual(["swarm_dispatch", "swarm_dispatch", "swarm_dispatch"])
    expect(sent[0]!.args).toEqual({ request: { action: "workers" } })
    expect(sent[1]!.args).toEqual({ request: { action: "status", workerId: "w1" } })
    expect(sent[2]!.args).toEqual({ request: { action: "activity", workerId: "w1", after: 2 } })
  })

  it("keeps the worker's own word for what it is doing, where Grid Core has no stage for it", async () => {
    answer = { workers: [{ id: "w1", name: "Keen heron", model: "m", state: "paused", stage: "Holding", gpu: "", resources: {}, workspaceQuotaGb: 20, keepResident: false, error: null, summary: "", createdAt: 1 }] }
    const page = await grids.research.jobs()
    expect(page.items[0]).toMatchObject({ state: "paused", stage: null, step: "Holding" })
    expect(page.total).toBe(1)
  })

  it("records exactly what a person agreed to when a bounty is accepted", async () => {
    answer = { worker: {} }
    await grids.research.accept("w1", {
      id: "offer-1", termsVersion: 3, termsDigest: "td", sourceRevision: "rev", authorizationDigest: "ad",
      bounty: { id: "bounty-7", terms: { sourceDigest: "sd", serviceRules: { version: 5, digest: "rd" } } },
    }, 30)
    expect(only().args).toEqual({ request: {
      action: "accept", workerId: "w1", bountyId: "bounty-7", termsVersion: 3, termsDigest: "td",
      sourceRevision: "rev", sourceDigest: "sd", authorizationAccepted: true, authorizationDigest: "ad",
      directPaymentAccepted: true, rulesAccepted: true, rulesVersion: 5, rulesDigest: "rd",
      reportPolicy: "review", budgetMinutes: 30, confirmed: true,
    } })
  })

  it("leaves a bounty's terms and a report's document exactly as they arrived", async () => {
    const terms = { objective: "Find logic flaws", authorization: { token: "a sentence, not a secret" }, serviceRules: { text: "Line one\nLine two" } }
    answer = { offers: [{ id: "offer-1", termsVersion: 1, termsDigest: "d", bounty: { id: "b1", authorization: "Acme authorizes this.", scope: "only here", terms } }] }
    const offers = await grids.research.offers("w1")
    expect(offers[0]!.bounty.terms).toEqual(terms)
    expect(offers[0]!.bounty.authorization).toBe("Acme authorizes this.")
    answer = { reports: [{ id: "r1", title: "Findings", state: "draft", document: { value: "kept", token: "kept" } }] }
    const reports = await grids.research.reports("w1")
    expect(reports.items[0]!.document).toEqual({ value: "kept", token: "kept" })
  })

  it("reads the rented GPUs and stops one job's, or all of them, one request each", async () => {
    answer = { workers: [], candidates: [], hourlyUsd: 0, notices: [] }
    await grids.research.rentedGpus()
    answer = { message: "stopped" }
    await grids.research.stopRentedGpu("w1")
    await grids.research.stopRentedGpus()
    expect(sent.map(entry => entry.args)).toEqual([
      { request: { action: "rentedGpus" } },
      { request: { action: "stopRentedGpu", workerId: "w1" } },
      { request: { action: "stopRentedGpus" } },
    ])
  })

  it("reaches the closed bounty's own command for a bounty a company hosts itself", async () => {
    answer = { host: null }
    await grids.research.closed.status()
    answer = {}
    await grids.research.closed.inspect("C:/project")
    await grids.research.closed.connect("bounty-invite:x", "pass", "Studio PC")
    await grids.research.closed.connectHere()
    await grids.research.closed.discard("ticket-1")
    await grids.research.closed.removeHunter("m1")
    await grids.research.closed.unpublish()
    expect(sent.map(entry => entry.command)).toEqual([
      "bounty_dispatch", "bounty_dispatch", "bounty_dispatch", "bounty_dispatch", "bounty_dispatch",
      "bounty_member_remove", "bounty_delete",
    ])
    expect(sent[1]!.args).toEqual({ request: { action: "inspectProject", path: "C:/project" } })
  })
})

describe("the credentials profile", () => {
  it("calls the Access Grid's own module and never an access command string", async () => {
    await grids.credentials.status()
    await grids.credentials.signOut()
    await grids.credentials.account.twoStepStart()
    expect(accessCalls.map(entry => entry.method)).toEqual(["status", "signOut", "account"])
    expect(sent).toEqual([])
  })

  it("names each manage action, leaving that module's door exactly where it is", async () => {
    await grids.credentials.add({ name: "Stripe", shape: "bearer", destinations: ["https://api.stripe.com"], value: "sk-live-1" })
    await grids.credentials.rotate("c1", "sk-live-2")
    await grids.credentials.retire("c1")
    await grids.credentials.allow({ credentialId: "c1", who: "everyone", methods: ["GET"], path: "/v1", decision: "ask" })
    await grids.credentials.takeBack("r1")
    await grids.credentials.decide("q1", { kind: "hours", hours: 8 })
    await grids.credentials.decide("q2", { kind: "denied", reason: "Not this one" })
    const actions = accessCalls.map(entry => (entry.args[0] as { action: string }).action)
    expect(actions).toEqual(["credentialAdd", "credentialUpdate", "credentialRemove", "ruleAdd", "ruleRemove", "decide", "decide"])
    expect(accessCalls[5]!.args[0]).toEqual({ action: "decide", request: "q1", approve: true, hours: 8 })
    expect(accessCalls[6]!.args[0]).toEqual({ action: "decide", request: "q2", approve: false, reason: "Not this one" })
    expect(sent).toEqual([])
  })

  it("says whether the history is whole in a sentence a person can read", async () => {
    accessAnswer.manage = { ok: true, entries: 42 }
    expect(await grids.credentials.verifyHistory()).toEqual({ whole: true, brokenAt: null, message: "All 42 entries are whole and in order." })
    accessAnswer.manage = { ok: false, brokenAt: 7, reason: "Entry 7 does not match its seal" }
    expect(await grids.credentials.verifyHistory()).toEqual({ whole: false, brokenAt: 7, message: "Entry 7 does not match its seal" })
  })

  it("names the command line for the three things that live on the wire only", () => {
    expect(() => grids.credentials.use()).toThrow(CliOnlyError)
    expect(() => grids.credentials.check()).toThrow("yougori access check REQUEST_ID")
    expect(() => grids.credentials.reveal()).toThrow(CliOnlyError)
    expect(sent).toEqual([])
    expect(accessCalls).toEqual([])
  })
})
