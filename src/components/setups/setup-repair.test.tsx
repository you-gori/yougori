// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import type { SetupPlan } from "@/api/setups/types"
import { SetupRepair } from "./setup-repair"

afterEach(cleanup)

/** A repair review as the engine returns it: the missing parts to put back, and nothing else. */
const plan = (over: Partial<SetupPlan> = {}): SetupPlan => ({
  setupId: "s1", digest: "rp-1", baseRevision: 4, intent: "repair", headline: "Puts 1 missing part back.",
  resources: [{ resourceId: "pool", label: "Desk pool", kind: "workspace_pool", owned: true, action: "create" }],
  ...over,
})

it("shows the review before the button, and the button puts only the reviewed parts back", async () => {
  const onRepair = vi.fn()
  const user = userEvent.setup()
  render(<SetupRepair name="Acme" plan={plan()} agreed={[]} busy={false} onAgree={() => undefined} onRepair={onRepair} onKeep={() => undefined} />)
  const panel = screen.getByRole("region", { name: "Repair Acme" })
  // The plan is reviewed in full: the missing part and what would happen to it.
  const review = within(panel).getByRole("region", { name: "What will happen" })
  expect(within(review).getByText("Puts 1 missing part back.")).toBeInTheDocument()
  expect(within(review).getByText("Desk pool")).toBeInTheDocument()
  const said = within(panel).getByText(/Only the parts above are put back\./)
  const button = within(panel).getByRole("button", { name: "Repair Acme" })
  // The words come before the button that acts on them, and nothing has happened yet.
  expect(said.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  expect(onRepair).not.toHaveBeenCalled()
  await user.click(button)
  expect(onRepair).toHaveBeenCalledTimes(1)
})

it("says there is nothing to put back, and offers nothing to apply, when nothing is out of place", () => {
  render(<SetupRepair name="Acme" plan={plan({ resources: [], steps: [], changes: [], headline: null })} agreed={[]} busy={false} onAgree={() => undefined} onRepair={() => undefined} onKeep={() => undefined} />)
  const panel = screen.getByRole("region", { name: "Repair Acme" })
  expect(within(panel).getByText(/Nothing is missing or out of place/)).toBeInTheDocument()
  expect(within(panel).getByRole("button", { name: "Repair Acme" })).toBeDisabled()
})

it("never repairs while the plan is blocked", () => {
  render(<SetupRepair name="Acme" plan={plan({ blockers: [{ code: "busy", message: "Another change is running.", severity: "error", retryable: false }] })} agreed={[]} busy={false} onAgree={() => undefined} onRepair={() => undefined} onKeep={() => undefined} />)
  expect(screen.getByRole("button", { name: "Repair Acme" })).toBeDisabled()
})

it("does nothing but close when the person chooses not now", async () => {
  const onKeep = vi.fn()
  const onRepair = vi.fn()
  const user = userEvent.setup()
  render(<SetupRepair name="Acme" plan={plan()} agreed={[]} busy={false} onAgree={() => undefined} onRepair={onRepair} onKeep={onKeep} />)
  await user.click(screen.getByRole("button", { name: "Not now" }))
  expect(onKeep).toHaveBeenCalledTimes(1)
  expect(onRepair).not.toHaveBeenCalled()
})
