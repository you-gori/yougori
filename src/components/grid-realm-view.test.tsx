// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { GridRealmView } from "./grid-realm-view"
import type { GridRealm } from "@/lib/grid-realm"
import type { Role } from "@/api/grids/types"

vi.mock("@/components/access-dialogs", () => ({
  AccessBackupDialog: () => null,
  AccessRestoreDialog: () => null,
}))

afterEach(cleanup)

const realm = (over: Partial<GridRealm>): GridRealm => ({
  key: "models",
  capabilities: ["models"],
  name: "Acme",
  present: true,
  role: "host",
  lifecycle: "open",
  hint: "2 of 2 computers online",
  state: "Open, hosted on Studio PC, with 2 of 2 computers online.",
  reach: "192.168.1.20:7460 on your own network",
  keyHolder: "Studio PC",
  actor: "Studio PC",
  closing: null,
  problem: "",
  invite: null,
  held: { roles: ["realmAdmin"] as readonly Role[] },
  hosts: [{
    id: "m1", realmId: "g1", name: "Design laptop", platform: "windows", joinedAt: 0, online: true,
    lastSeenSeconds: 2, address: null, appVersion: null, capable: true, excluded: false, draining: false,
    running: 0, jobs: 0, models: [],
  }],
  plans: [{ id: "p1", realmId: "g1", model: "acme/assistant", quant: null, percent: 100, target: { kind: "all", percent: 100 }, computers: 2, wanted: 2, ready: 1, names: [], rules: "always on" }],
  workspaces: [],
  credentials: [],
  approvals: [],
  people: [],
  jobs: [],
  work: { queued: 0, running: 0, finished: 0 },
  history: null,
  ...over,
})

const view = (one: GridRealm) =>
  render(<GridRealmView realm={one} run={vi.fn().mockResolvedValue(true)} done={vi.fn()} onOpenPage={vi.fn()} />)

it("shows only the panels this grid's capabilities allow", () => {
  view(realm({}))
  expect(screen.getByRole("region", { name: "Models" })).toHaveTextContent("acme/assistant")
  expect(screen.getByRole("region", { name: "Computers" })).toHaveTextContent("Design laptop")
  expect(screen.queryByRole("region", { name: "Credentials" })).not.toBeInTheDocument()
  expect(screen.queryByRole("region", { name: "Desks" })).not.toBeInTheDocument()
  expect(screen.queryByRole("region", { name: "Waiting for approval" })).not.toBeInTheDocument()
})

it("shows a credentials grid its own panels and never a model plan", () => {
  view(realm({
    key: "credentials",
    capabilities: ["credentials"],
    plans: [],
    credentials: [{
      id: "c1", realmId: "g1", name: "Deploy key", shape: "bearer", field: "", destinations: ["https://api.github.com"],
      note: "", hint: "", ownerId: "p1", createdAt: 0, updatedAt: 0, rules: 1,
    }],
    approvals: [{
      id: "r1", realmId: "g1", action: "use", resourceId: "c1", resource: "Deploy key", requestedBy: "grace",
      requestedAt: 0, expiresAt: 0, state: "waiting", decidedBy: null, why: "Waits because past the hourly limit.",
    }],
    history: [],
  }))
  expect(screen.getByRole("region", { name: "Credentials" })).toHaveTextContent("Deploy key")
  expect(screen.getByRole("region", { name: "Waiting for approval" })).toHaveTextContent("grace")
  expect(screen.queryByRole("region", { name: "Models" })).not.toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Agree once" })).toBeInTheDocument()
})

it("offers an auditor nothing to change, and still shows them what happened", () => {
  view(realm({
    key: "credentials",
    capabilities: ["credentials"],
    plans: [],
    held: { roles: ["auditor"] as readonly Role[] },
    credentials: [],
    approvals: [{
      id: "r1", realmId: "g1", action: "use", resourceId: "c1", resource: "Deploy key", requestedBy: "grace",
      requestedAt: 0, expiresAt: 0, state: "waiting", decidedBy: null, why: "Waits for a person.",
    }],
    history: [{ id: "1", at: 0, realmId: "g1", principal: "grace", action: "credential.sent", decision: "allowed", reason: "Allowed by a rule." }],
  }))
  expect(screen.getByRole("region", { name: "History" })).toHaveTextContent("A credential was used on a request.")
  expect(screen.getByRole("region", { name: "Waiting for approval" })).toHaveTextContent("grace")
  expect(screen.queryByRole("button", { name: "Agree once" })).not.toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Delete grid" })).not.toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Back up" })).not.toBeInTheDocument()
})

it("offers nothing to change to a person whose grid somebody else hosts", () => {
  view(realm({ role: "member", held: { roles: ["user"] as readonly Role[] } }))
  expect(screen.queryByRole("region", { name: "Computers" })).not.toBeInTheDocument()
  expect(screen.queryByRole("button", { name: "Delete grid" })).not.toBeInTheDocument()
  expect(screen.queryByRole("region", { name: "Models" })).not.toBeInTheDocument()
})

it("says who holds the key and where the grid answers, in words", () => {
  view(realm({}))
  const sheet = screen.getByRole("region", { name: "This grid" }).parentElement as HTMLElement
  expect(sheet).toHaveTextContent("Studio PC holds this grid's key")
  expect(sheet).toHaveTextContent("192.168.1.20:7460 on your own network")
  expect(sheet.textContent).not.toMatch(/\.db\b/)
})

it("turns a refusal into a line a person reads, in the error tone", () => {
  view(realm({
    key: "credentials",
    capabilities: ["credentials"],
    plans: [],
    people: [{ id: "person-9f31ac", realmId: "g1", kind: "person", name: "Ada Lovelace", roles: ["user"], createdAt: 0 }],
    history: [{ id: "1", at: 0, realmId: "g1", principal: "person-9f31ac", action: "capability.refused", decision: "refused", reason: "This grid does not broker credentials." }],
  }))
  const history = screen.getByRole("region", { name: "History" })
  expect(history).toHaveTextContent("Ada Lovelace. Something this grid does was refused. This grid does not broker credentials.")
  expect(history.textContent).not.toContain("person-9f31ac")
  expect(history.textContent).not.toContain("capability.refused")
})

it("says what a research worker is doing, rather than the word the worker keeps it under", () => {
  view(realm({
    key: "research",
    capabilities: ["research"],
    plans: [],
    // A worker that was just made has no summary yet, which is the ordinary case.
    jobs: [
      { id: "w1", realmId: "g1", name: "Keen heron", model: "acme/assistant", quant: null, stage: null, state: "ready_waiting", summary: "", step: "", gpu: "", resources: {}, workspaceQuotaGb: 40, keepResident: false, network: "closed", error: null, startedAt: 0, attempts: 0 },
      { id: "w2", realmId: "g1", name: "Wise otter", model: "acme/assistant", quant: null, stage: null, state: "awaiting_review", summary: "", step: "", gpu: "", resources: {}, workspaceQuotaGb: 40, keepResident: false, network: "closed", error: null, startedAt: 0, attempts: 0 },
    ],
    work: { queued: 2, running: 0, finished: 0 },
  }))
  const work = screen.getByRole("region", { name: "Work" })
  expect(work).toHaveTextContent("Keen heron")
  expect(work).toHaveTextContent("Ready · waiting for a bounty to accept")
  expect(work).toHaveTextContent("Report ready for your review")
  expect(work.textContent).not.toContain("ready_waiting")
  expect(work.textContent).not.toContain("awaiting_review")
})
