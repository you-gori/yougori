// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { useState } from "react"
import { afterEach, expect, it, vi } from "vitest"
import type { SetupPlan } from "@/api/setups/types"
import { SetupRemoval } from "./setup-removal"

afterEach(cleanup)

const OFFER = "Also delete data: everything on it and its 3 backups in Yougori's data folder on this computer. This can't be undone."
const plan = (over: Partial<SetupPlan> = {}): SetupPlan => ({
  setupId: "s1", digest: "rm-1", baseRevision: 4, intent: "remove",
  notes: ["The data of data is kept unless you tick its deletion below, and so are its 3 backups."],
  consents: [{ id: "delete_data:data", message: OFFER }],
  ...over,
})

/** The panel with real ticking, as both of its callers wire it. */
function Panel({ given, onRemove }: { given: SetupPlan; onRemove(agreed: string[]): void }) {
  const [agreed, setAgreed] = useState<string[]>([])
  return <SetupRemoval
    name="Acme" plan={given} agreed={agreed} busy={false}
    onAgree={(id, on) => setAgreed(current => on ? [...current.filter(one => one !== id), id] : current.filter(one => one !== id))}
    onRemove={() => onRemove(agreed)} onKeep={() => undefined}
  />
}

it("keeps the data unless its deletion is ticked, and says so before the button", async () => {
  const onRemove = vi.fn()
  render(<Panel given={plan()} onRemove={onRemove} />)
  const panel = screen.getByRole("region", { name: "Remove Acme" })
  const offer = within(panel).getByRole("checkbox", { name: OFFER })
  expect(offer).not.toBeChecked()
  expect(within(panel).getByText("Borrowed resources are never touched. Data is kept unless you delete it separately.")).toBeInTheDocument()
  await userEvent.click(within(panel).getByRole("button", { name: "Remove Acme" }))
  expect(onRemove).toHaveBeenCalledWith([])
})

it("names exactly what goes, and that it can't be undone, once a deletion is ticked", async () => {
  const onRemove = vi.fn()
  const user = userEvent.setup()
  render(<Panel given={plan()} onRemove={onRemove} />)
  const panel = screen.getByRole("region", { name: "Remove Acme" })
  await user.click(within(panel).getByRole("checkbox", { name: OFFER }))
  const said = within(panel).getByText(/^Borrowed resources are never touched\. data and its backups are deleted/)
  expect(said).toHaveTextContent("data and its backups are deleted, and that can't be undone. All other data is kept.")
  const button = within(panel).getByRole("button", { name: "Remove Acme and delete data" })
  // The words come before the button that acts on them.
  expect(said.compareDocumentPosition(button) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  await user.click(button)
  expect(onRemove).toHaveBeenCalledWith(["delete_data:data"])
  // Unticked again, nothing is deleted and the button says so.
  await user.click(within(panel).getByRole("checkbox", { name: OFFER }))
  expect(within(panel).getByRole("button", { name: "Remove Acme" })).toBeInTheDocument()
})

it("never counts a deletion the review did not offer", () => {
  render(<SetupRemoval name="Acme" plan={plan({ consents: [] })} agreed={["delete_data:data"]} busy={false} onAgree={() => undefined} onRemove={() => undefined} onKeep={() => undefined} />)
  expect(screen.getByRole("button", { name: "Remove Acme" })).toBeInTheDocument()
  expect(screen.getByText("Borrowed resources are never touched. Data is kept unless you delete it separately.")).toBeInTheDocument()
})

it("names a grid ticked for deleting now just as plainly", async () => {
  const user = userEvent.setup()
  const grid = plan({ consents: [
    { id: "delete_grid:company", message: "Also delete the Sandbox Grid Acme now instead of pausing it for three days. This can't be undone." },
    { id: "write_folder:app/code", message: "Let app change files in the folder you chose for code." },
  ] })
  render(<Panel given={grid} onRemove={() => undefined} />)
  await user.click(screen.getByRole("checkbox", { name: /^Also delete the Sandbox Grid Acme now/ }))
  expect(screen.getByText("Borrowed resources are never touched. company is deleted, and that can't be undone. All other data is kept.")).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Remove Acme and delete company" })).toBeInTheDocument()
  // A consent that deletes nothing is not counted as a deletion.
  await user.click(screen.getByRole("checkbox", { name: /^Also delete the Sandbox Grid Acme now/ }))
  await user.click(screen.getByRole("checkbox", { name: /^Let app change files/ }))
  expect(screen.getByRole("button", { name: "Remove Acme" })).toBeInTheDocument()
})

it("names every volume ticked, and nothing while a removal is blocked", async () => {
  const user = userEvent.setup()
  const two = plan({ consents: [{ id: "delete_data:data", message: "Delete data." }, { id: "delete_data:cache", message: "Delete cache." }] })
  render(<Panel given={two} onRemove={() => undefined} />)
  await user.click(screen.getByRole("checkbox", { name: "Delete data." }))
  await user.click(screen.getByRole("checkbox", { name: "Delete cache." }))
  expect(screen.getByRole("button", { name: "Remove Acme and delete data, cache" })).toBeInTheDocument()
  expect(screen.getByText(/data, cache and their backups are deleted/)).toBeInTheDocument()
  cleanup()
  render(<SetupRemoval name="Acme" plan={plan({ blockers: [{ code: "in_use", message: "Another setup uses data.", severity: "error", retryable: false }] })} agreed={[]} busy={false} onAgree={() => undefined} onRemove={() => undefined} onKeep={() => undefined} />)
  expect(screen.getByRole("button", { name: "Remove Acme" })).toBeDisabled()
})
