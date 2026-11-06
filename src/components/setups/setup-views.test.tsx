// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import { afterEach, expect, it } from "vitest"
import type { SetupPlan } from "@/api/setups/types"
import { SetupReview } from "./setup-views"

afterEach(cleanup)

const plan = (over: Partial<SetupPlan> = {}): SetupPlan => ({
  setupId: "s1", digest: "d1", baseRevision: 0,
  notes: ["The question \"old_size\" was removed in the new version; your answer no longer applies."],
  warnings: ["web can read docs on this computer."],
  ...over,
})

it("reads what a new version changes about your choices before anything else", () => {
  render(<SetupReview plan={plan({ intent: "update", conflicts: [
    { code: "question_removed", message: "The question \"old_size\" was removed in the new version; your answer no longer applies.", subject: "old_size", action: "review" },
  ] })} names={{}} />)
  const first = screen.getByRole("list", { name: "What this version changes about your setup" })
  expect(first).toHaveTextContent("old_size")
  // It is above the warnings, not below them.
  const warning = screen.getByText("web can read docs on this computer.")
  expect(first.compareDocumentPosition(warning) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
})

it("says before anyone agrees when the Hub page describes a version differently from its files", () => {
  // The engine compares the page with the files when it plans a Hub package, and the review shows
  // what it found above everything else: the page is what the person read, the files are what runs.
  render(<SetupReview plan={plan({ page: { compared: true, differs: true, differences: ["what it is allowed to do", "what it may cost"] } })} names={{}} />)
  const said = screen.getByRole("list", { name: "The Hub page describes this version differently from its files" })
  expect(said).toHaveTextContent("what it is allowed to do; what it may cost")
  expect(said).toHaveTextContent("built from the files themselves")
  const warning = screen.getByText("web can read docs on this computer.")
  expect(said.compareDocumentPosition(warning) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
})

it("tells a page that was not compared apart from one that matched", () => {
  // "No differences" and "never compared" look the same to anyone reading a review; one of them
  // means nobody checked, so it is said, and a page that matched says nothing at all.
  const { unmount } = render(<SetupReview plan={plan({ page: { compared: false, differs: false, differences: [], reason: "The Hub did not send a page for this version, so the files could not be checked against what it says." } })} names={{}} />)
  expect(screen.getByText(/did not send a page/)).toBeInTheDocument()
  expect(screen.queryByRole("list", { name: "The Hub page describes this version differently from its files" })).toBeNull()
  unmount()
  render(<SetupReview plan={plan({ page: { compared: true, differs: false, differences: [] } })} names={{}} />)
  expect(screen.queryByText(/Hub page/)).toBeNull()
})

it("keeps a removal's notes first, as before", () => {
  render(<SetupReview plan={plan({ intent: "remove" })} names={{}} />)
  expect(screen.getByRole("list", { name: "Before you remove it" })).toBeInTheDocument()
})

it("leaves notes where they were when a change alters none of your choices", () => {
  render(<SetupReview plan={plan({ intent: "update", conflicts: [] })} names={{}} />)
  expect(screen.queryByRole("list", { name: "What this version changes about your setup" })).toBeNull()
  expect(screen.queryByRole("list", { name: "Before you remove it" })).toBeNull()
  expect(screen.getByText(/old_size/)).toBeInTheDocument()
})

it("shows the downloads a plan would fetch, with their sizes and where they come from", () => {
  render(<SetupReview plan={plan({
    downloads: [{ name: "node:24", bytes: 120_000_000 }],
    review: { downloads: [{ kind: "model", name: "a-model", from: "huggingface" }] },
  })} names={{}} />)
  expect(screen.getByRole("heading", { name: "Downloads" })).toBeInTheDocument()
  expect(screen.getByText(/node:24/)).toBeInTheDocument()
  expect(screen.getByText(/a-model from huggingface/)).toBeInTheDocument()
})

it("shows what the setup is allowed to do", () => {
  render(<SetupReview plan={plan({ permissions: ["Run containers on this computer.", "Open a public web address for this setup."] })} names={{}} />)
  expect(screen.getByRole("heading", { name: "What it is allowed to do" })).toBeInTheDocument()
  expect(screen.getByText("Run containers on this computer.")).toBeInTheDocument()
  expect(screen.getByText("Open a public web address for this setup.")).toBeInTheDocument()
})

it("lists what the plan's chosen capabilities ask for from the engine's document, each as requested", () => {
  // The plan's CORE-07 document (`product` on `setup_plan`), the one `yougori template plan` shows.
  const product = { contract_version: 2, subject: { kind: "setup", id: "s1" }, shown_at: { clock: "c", at: 1, configuration: "f" }, permissions: [
    { kind: "run_containers", text: "Run containers on this computer.", status: { status: "requested" } },
    { kind: "reserve_storage", text: "Reserve storage on a drive you choose.", status: { status: "requested" } },
  ] }
  const { unmount } = render(<SetupReview plan={plan({ product })} names={{}} />)
  const asked = within(screen.getByRole("list", { name: "What its capabilities ask for" })).getAllByRole("listitem").map(item => item.textContent)
  expect(asked).toEqual(["Run containers on this computer. (requested; asking grants nothing)", "Reserve storage on a drive you choose. (requested; asking grants nothing)"])
  expect(screen.queryByText(/permitted|approved/)).toBeNull()
  unmount()
  // A plan the engine could make no document for says why; one from an engine that sends none
  // reads as before.
  const { unmount: again } = render(<SetupReview plan={plan({ productUnavailable: "the engine's evidence clock is not available: starting" })} names={{}} />)
  expect(screen.getByText("Yougori can't show this setup's product view: the engine's evidence clock is not available: starting.")).toBeInTheDocument()
  again()
  render(<SetupReview plan={plan()} names={{}} />)
  expect(screen.queryByRole("region", { name: "Product view" })).toBeNull()
  expect(screen.queryByText(/product view/)).toBeNull()
})

it("shows a cost line, and an unknown amount as such, while an empty costs list shows no Costs heading", () => {
  // No costs: no Costs section at all.
  const { unmount } = render(<SetupReview plan={plan({ costs: [] })} names={{}} />)
  expect(screen.queryByRole("heading", { name: "Costs" })).toBeNull()
  unmount()
  // A cost with an amount, and one whose amount the engine could not work out, both shown plainly.
  render(<SetupReview plan={plan({ costs: [{ label: "Cloud GPU", amount: "$2/hour" }, { label: "Rented pod", amount: null }] })} names={{}} />)
  expect(screen.getByRole("heading", { name: "Costs" })).toBeInTheDocument()
  expect(screen.getByText("Cloud GPU: $2/hour")).toBeInTheDocument()
  expect(screen.getByText("Rented pod: not known yet")).toBeInTheDocument()
})

it("shows every line a tool runs in its sandbox, cleaned of what could disguise it", () => {
  // A Hub tool's install lines run in the sandbox when the plan is applied. They are in the
  // review itself, as they will run, rather than only the addresses they fetch from.
  render(<SetupReview plan={plan({ review: { installs: [
    { resource: "web", tool: "acme/httpie", commands: ["pip install httpie\u001b[2K", "echo ‮ok"], check: "http --version" },
    { resource: "web", tool: "ready", commands: [] },
  ] } })} names={{}} />)
  expect(screen.getByRole("heading", { name: "What its tools run" })).toBeInTheDocument()
  expect(screen.getByText("$ pip install httpie [2K")).toBeInTheDocument()
  expect(screen.getByText("$ echo ok")).toBeInTheDocument()
  expect(screen.getByText("http --version")).toBeInTheDocument()
  expect(screen.getByText(/installs nothing; its check must already pass/)).toBeInTheDocument()
})
