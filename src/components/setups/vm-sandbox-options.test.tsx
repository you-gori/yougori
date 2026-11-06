// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { useState } from "react"
import { afterEach, expect, it } from "vitest"
import { CATALOGUE, withAvailability } from "@/api/setups/catalogue"
import type { CapabilityReport, SetupDraft } from "@/api/setups/types"
import { CapabilityBoard } from "./capability-board"
import { SetupReview } from "./setup-views"

afterEach(cleanup)

/** The real catalogue, every shipped capability usable here, as the engine reports it on a
 *  computer that can run the VM sandbox. */
const everything: CapabilityReport[] = CATALOGUE.filter(one => one.status !== "planned").map(one => ({ id: one.id, availability: "available" as const }))

function Board({ statuses }: { statuses: CapabilityReport[] }) {
  const [draft, setDraft] = useState<SetupDraft>({ name: "Agent box", recipe: null, capabilities: {} })
  return <CapabilityBoard entries={withAvailability(CATALOGUE, statuses, "generic", { switchable: true })} draft={draft} mode="create" diagnostics={[]} secrets={{}} onDraft={setDraft} onSecret={() => {}} onGoTo={() => {}} />
}

const group = (name: string) => screen.getByRole("heading", { level: 4, name: new RegExp(name) }).closest("section") as HTMLElement

/** PROVES the VM sandbox, its staged workspace and its routes are shown where people look for
 *  them, each saying what it is, what it needs and what it is allowed to do, from the registry's
 *  own words; and that a workspace or routes chosen alone say they need the VM sandbox and offer
 *  to add it. */
it("shows the VM sandbox options in their groups, with what each needs and is allowed to do", async () => {
  const user = userEvent.setup({ delay: null })
  render(<Board statuses={everything} />)
  const grid = group("Grid & workers")
  expect(within(grid).getByText(/a restricted VM on it/)).toBeInTheDocument()
  const vm = within(grid).getByRole("article", { name: "VM sandbox" })
  expect(within(vm).getByText(/pinned minimal Linux guest with no network and none of your files/)).toBeInTheDocument()
  expect(within(vm).getByText(/Allowed to: run vm sandbox/)).toBeInTheDocument()

  const workspace = within(group("Files & data")).getByRole("article", { name: "Staged workspace" })
  expect(within(workspace).getByText(/reach your folder only when you review them and approve each file/)).toBeInTheDocument()
  expect(within(workspace).getByText("Needs VM sandbox.")).toBeInTheDocument()

  const routes = within(group("AI tools & models")).getByRole("article", { name: "Declared routes" })
  expect(within(routes).getByText(/credential the host adds and the sandbox never sees/)).toBeInTheDocument()

  // Chosen alone, the workspace says what it still needs and adds it only when asked.
  await user.click(within(workspace).getByRole("checkbox", { name: "Staged workspace" }))
  expect(within(workspace).getByText(/Staged workspace also needs VM sandbox/)).toBeInTheDocument()
  await user.click(within(workspace).getByRole("button", { name: "Add VM sandbox" }))
  expect(within(vm).getByRole("checkbox", { name: "VM sandbox" })).toBeChecked()
  expect(within(workspace).queryByText(/also needs/)).toBeNull()
})

/** PROVES a computer that can't run the VM sandbox shows the options, says why, and keeps them off. */
it("keeps the VM sandbox options visible but off where this computer can't run them, and says why", () => {
  const reason = "This computer cannot run the VM sandbox yet: it runs on Windows with the Windows Hypervisor Platform turned on, with the guest that comes with Yougori."
  const statuses = everything.map(one => one.id.startsWith("sandbox.") ? { id: one.id, availability: "unsupported" as const, reason } : one)
  render(<Board statuses={statuses} />)
  const vm = within(group("Grid & workers")).getByRole("article", { name: "VM sandbox" })
  expect(within(vm).getByRole("checkbox", { name: "VM sandbox" })).toBeDisabled()
  expect(within(vm).getByText(reason)).toBeInTheDocument()
})

/** PROVES the review says a staged folder is a copy that changes only with approved files. */
it("says on the review that a staged folder is a copy the sandbox never writes", () => {
  render(<SetupReview names={{}} plan={{
    setupId: "s-box", digest: "d", baseRevision: 0, headline: "Creates Agent box on this computer.",
    resources: [{ resourceId: "vm", label: "vm", kind: "vm_sandbox", owned: true, action: "create" }],
    review: { pcAccess: [{ environment: "vm", path: "/home/sam/project", target: "/run/yougori/workspace", readOnly: true, staged: true }] },
  } as never} />)
  expect(screen.getByText(/a copy: the folder changes only with files you approve after a review/)).toBeInTheDocument()
  expect(screen.queryByText(/it can change files there/)).toBeNull()
})

it("makes remote VM execution visible and requires its local parent", async () => {
  const user = userEvent.setup({ delay: null })
  render(<Board statuses={everything} />)
  const remote = within(group("Grid & workers")).getByRole("article", { name: "Remote VM via SSH" })
  expect(within(remote).getByText(/billing unchanged/)).toBeInTheDocument()
  expect(within(remote).getByText("Needs VM sandbox.")).toBeInTheDocument()
  await user.click(within(remote).getByRole("checkbox", { name: "Remote VM via SSH" }))
  await user.click(within(remote).getByRole("button", { name: "Add VM sandbox" }))
  expect(within(group("Grid & workers")).getByRole("checkbox", { name: "VM sandbox" })).toBeChecked()
})
