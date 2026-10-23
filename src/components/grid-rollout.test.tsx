// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it } from "vitest"
import { GridRollout } from "./grid-rollout"
import { resetTransport, setTransport, type Transport } from "@/api/grids/wire"
import type { ProductMeta } from "@/api/grids/rollout"

/** Where the four profiles stand. Each product is at a different stage, so a test can tell that
 *  the panel reads a profile's own stage rather than showing one for all four. */
const standing = {
  rollout: 1,
  updatedAt: 100,
  profiles: [
    { profile: "models", stage: "observation", since: 1, keptUntil: null, notes: [] },
    { profile: "workspaces", stage: "rehearsal", since: 1, keptUntil: null, notes: [] },
    { profile: "research", stage: "backup", since: 1, keptUntil: null, notes: [] },
    { profile: "credentials", stage: "freeze", since: 1, keptUntil: null, notes: [] },
  ],
}

/** A comparison with a stop under assignments and under workloads, and a note under permissions.
 *  Every subject, hub and core is an identifier a grid minted, on purpose: none of them may reach
 *  the screen. */
const passes = [
  {
    profile: "models", at: 200, observations: [
      { at: 200, profile: "models", heading: "assignments", subject: "plan-keen-otter-9a3f", hub: "host-aaaa1111", core: "host-bbbb2222", verdict: { verdict: "stop" } },
      { at: 200, profile: "models", heading: "plans", subject: "plan-keen-otter-9a3f", hub: "always on", core: "always on", verdict: { verdict: "agrees" } },
      { at: 200, profile: "models", heading: "workloads", subject: "job-cccc3333", hub: "worker-dddd4444 running", core: "queued", verdict: { verdict: "stop", because: "the hub says worker-dddd4444 running and the core says queued, and nothing this bridge wrote explains it" } },
    ],
  },
  {
    profile: "credentials", at: 200, observations: [
      { at: 200, profile: "credentials", heading: "permissions", subject: "cred-eeee5555", hub: "credential administrator, auditor", core: "credential administrator", verdict: { verdict: "noted", because: "the core allows less here than the hub did: it does not grant adding and removing accounts" } },
    ],
  },
]

const report = {
  rehearsal: 2, takenAt: 300, appVersion: "1.0.21", frozen: [],
  trials: [
    { product: "Closed Neo Grid", wrote: [["computers", 3], ["model plans", 2]], auditVerified: true, returnedClean: true, differences: [], kept: [], refusal: null },
  ],
  refusals: [], notRehearsed: [], notes: [],
}

function makeTransport(opts: { rehearse?: () => Promise<unknown>; standing?: typeof standing } = {}): Transport {
  const handler = async (command: string, args: Record<string, unknown>) => {
    expect(command).toBe("grids_rollout")
    const verb = (args.request as { do: string }).do
    if (verb === "status") return { said: "", found: opts.standing ?? standing }
    if (verb === "observe") return { said: "", found: passes }
    if (verb === "rehearse") return opts.rehearse ? await opts.rehearse() : { said: "", found: report }
    if (verb === "backup") return { said: "", found: {} }
    if (verb === "advance" || verb === "back") return { said: "", found: standing }
    throw new Error(`the test did not expect the verb ${verb}`)
  }
  return handler as unknown as Transport
}

/** Waits for the one-time spinner that shows while the first read is in flight to go away. */
async function loaded() {
  await screen.findByRole("region", { name: "Closed Neo Grid" })
  await waitFor(() => expect(screen.queryByText("Reading where the rollout stands…")).toBeNull())
}

/** Arms a control by its verb and confirms it. */
function confirm(verb: string) {
  fireEvent.click(screen.getByRole("button", { name: verb }))
  fireEvent.click(screen.getByRole("button", { name: "Confirm" }))
}

beforeEach(() => { setTransport(makeTransport()) })
afterEach(() => { resetTransport(); cleanup() })

it("shows each product, its bridge and the stage its own profile is at", async () => {
  render(<GridRollout />)
  await loaded()
  for (const name of ["Closed Neo Grid", "Sandbox Grid", "Swarm Mining", "Access Grid"]) {
    const block = screen.getByRole("region", { name })
    expect(block).toHaveTextContent("Has a bridge onto Grid Core")
  }
  // Each profile shows its own stage, not one shared stage.
  expect(screen.getByRole("region", { name: "Closed Neo Grid" })).toHaveTextContent("Observing")
  expect(screen.getByRole("region", { name: "Sandbox Grid" })).toHaveTextContent("Rehearsed")
  expect(screen.getByRole("region", { name: "Swarm Mining" })).toHaveTextContent("Backed up")
  expect(screen.getByRole("region", { name: "Access Grid" })).toHaveTextContent("Frozen")
})

it("says once what every product has in common, rather than on every card", async () => {
  const frozen = { ...standing, profiles: standing.profiles.map(state => ({ ...state, stage: "freeze" })) }
  setTransport(makeTransport({ standing: frozen }))
  render(<GridRollout />)
  await loaded()
  // Every profile is frozen, so what frozen means is said once, above the four cards.
  expect(screen.getAllByText(/The record shapes are written down/)).toHaveLength(1)
  for (const name of ["Closed Neo Grid", "Sandbox Grid", "Swarm Mining", "Access Grid"]) {
    expect(screen.getByRole("region", { name })).toHaveTextContent("Frozen")
  }
  // Nothing has been rehearsed yet, which is said once rather than four times.
  expect(screen.getAllByText("Not rehearsed in this session yet.")).toHaveLength(1)
})

it("never renders a raw identifier, even when the comparison is full of them", async () => {
  render(<GridRollout />)
  await loaded()
  confirm("Begin observing")
  await waitFor(() => expect(screen.getByRole("region", { name: "Closed Neo Grid" })).toHaveTextContent(/disagree/i))
  for (const token of ["9a3f", "aaaa1111", "bbbb2222", "cccc3333", "dddd4444", "eeee5555", "worker-dddd4444", "plan-keen-otter"]) {
    expect(document.body).not.toHaveTextContent(token)
  }
})

it("says whether the two paths agree, and shows a disagreement in a person's words", async () => {
  render(<GridRollout />)
  await loaded()
  confirm("Begin observing")
  const neo = await screen.findByRole("region", { name: "Closed Neo Grid" })
  await waitFor(() => expect(neo).toHaveTextContent(/disagree/i))
  // The placement difference is said in words, not by naming either computer.
  expect(neo).toHaveTextContent("which computer each thing runs on")
  expect(neo).toHaveTextContent("any difference in placement stops the rollout")
  // The workloads difference keeps the real words and drops only the identifier.
  expect(neo).toHaveTextContent("queued")
  expect(neo).toHaveTextContent("something it named")
  // A note is shown as a sentence, under the heading in a person's words.
  const access = screen.getByRole("region", { name: "Access Grid" })
  expect(access).toHaveTextContent("what each person may do")
  expect(access).toHaveTextContent("does not grant adding and removing accounts")
})

it("shows a product with no bridge as unavailable, with the reason, rather than hiding it", async () => {
  const products: ProductMeta[] = [
    { profile: "models", word: "neo", product: "Closed Neo Grid", hasBridge: true, bridgeReason: null },
    { profile: "research", word: "swarm", product: "Swarm Mining", hasBridge: false, bridgeReason: "it has no bridge in this build" },
  ]
  render(<GridRollout products={products} />)
  await loaded()
  const swarm = screen.getByRole("region", { name: "Swarm Mining" })
  expect(swarm).toHaveTextContent("No bridge yet")
  expect(swarm).toHaveTextContent("Bringing it across is unavailable: it has no bridge in this build")
  // Nothing offers to move a product that cannot be moved.
  expect(within(swarm).queryByRole("button", { name: /Enable this profile|Move to/ })).toBeNull()
})

it("shows a spinner while a rehearsal is running, then the result", async () => {
  let release: () => void = () => {}
  const pending = new Promise<void>(resolve => { release = resolve })
  setTransport(makeTransport({ rehearse: () => pending.then(() => ({ said: "", found: report })) }))
  render(<GridRollout />)
  await loaded()

  confirm("Rehearse")
  const spinner = await screen.findByRole("status")
  expect(spinner).toHaveTextContent("Rehearsing the whole move on copies")

  release()
  await waitFor(() => expect(screen.queryByText(/Rehearsing the whole move/)).toBeNull())
  expect(screen.getByRole("region", { name: "Closed Neo Grid" })).toHaveTextContent("Would move across 3 computers, 2 model plans")
})
