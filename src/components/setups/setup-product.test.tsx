// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { readFileSync } from "node:fs"
import path from "node:path"
import { cleanup, render, screen, within } from "@testing-library/react"
import { afterEach, expect, it } from "vitest"
import type { SetupDetailView, SetupPermissions } from "@/api/setups/types"
import { SetupProduct } from "./setup-product"

afterEach(cleanup)

it("renders malformed documents as unavailable and escapes control text without interpreting HTML", () => {
  render(<SetupProduct detail={{ product: { contract_version: 2, subject: { kind: "setup", id: "shop" }, shown_at: { clock: "c", at: 1, configuration: "f" }, permissions: [null] } }} />)
  expect(screen.getByText(/not in a shape/)).toBeInTheDocument()
  cleanup()
  const { container } = render(<SetupProduct detail={{ productUnavailable: "<img src=x>\u202eapproved\u001b[2J" }} />)
  expect(container.querySelector("img")).toBeNull()
  expect(container.textContent).toContain("<img src=x>\\u{202e}approved\\u{1b}[2J")
})

const golden = JSON.parse(readFileSync(path.resolve(process.cwd(), "src-tauri/src/foundation/product/fixtures/v2/migration_needs_decision.json"), "utf8")) as unknown
const detail = (over: Partial<SetupDetailView> = {}) => ({ resources: [], ...over }) as unknown as SetupDetailView

it("shows the engine's migration inventory, saying nothing has changed, and what needs the person", () => {
  render(<SetupProduct detail={detail({ product: golden })} />)
  const move = screen.getByRole("list", { name: "Move to VM sandboxes" })
  expect(screen.getByText("Move to VM sandboxes (an inventory; nothing has changed)")).toBeInTheDocument()
  const items = within(move).getAllByRole("listitem").map(item => item.textContent)
  expect(items[0]).toBe("web (vm): stays a VM sandbox")
  expect(items[2]).toBe("trainer (gpu): a decision is needed before it moves: a VM sandbox or GPU runtime (shared kernel), not a sandbox")
  const needs = within(screen.getByRole("list", { name: "What needs you" })).getAllByRole("listitem")
  expect(needs).toHaveLength(2)
  expect(needs[0]).toHaveTextContent("\"trainer\": the old setup ran this GPU sandbox")
  expect(needs[0]).toHaveTextContent("What you can do: choose one of the listed options; nothing is chosen for you.")
  expect(screen.queryByText(/verified/)).not.toBeInTheDocument()
})

it("lists what the capabilities ask for as requested, never as granted", () => {
  const product = { contract_version: 2, subject: { kind: "setup", id: "shop" }, shown_at: { clock: "c", at: 1, configuration: "f" },
    permissions: [{ kind: "run_containers", text: "Run containers on this computer.", status: { status: "requested" } }] }
  render(<SetupProduct detail={detail({ product })} />)
  expect(within(screen.getByRole("list", { name: "What its capabilities ask for" })).getByRole("listitem"))
    .toHaveTextContent("Run containers on this computer. (requested; asking grants nothing)")
  expect(screen.queryByRole("list", { name: "Move to VM sandboxes" })).not.toBeInTheDocument()
})

it("says why there is no document, and says nothing for an engine that sends none", () => {
  render(<SetupProduct detail={detail({ productUnavailable: "the engine's evidence clock is not available: starting" })} />)
  expect(screen.getByText("Yougori can't show this setup's product view: the engine's evidence clock is not available: starting.")).toBeInTheDocument()
  cleanup()
  const { container } = render(<SetupProduct detail={detail()} />)
  expect(container).toBeEmptyDOMElement()
  cleanup()
  render(<SetupProduct detail={detail({ product: { contract_version: 3 } })} />)
  expect(screen.getByText("The setup's product document was written by a newer Yougori. Update Yougori to read it.")).toBeInTheDocument()
})

it("heads a setup's read-back permissions as what its capabilities request, never as enforced", () => {
  // `product` on `setup_permissions`, as the permissions panel passes it.
  const permissions: SetupPermissions = { setupId: "shop", known: true, version: "1.0.0", permissions: ["Run containers on this computer."], product: {
    contract_version: 2, subject: { kind: "setup", id: "shop" }, shown_at: { clock: "c", at: 1, configuration: "f" },
    permissions: [{ kind: "run_containers", text: "Run containers on this computer.", status: { status: "requested" } }],
  } }
  render(<SetupProduct detail={permissions} lines="declares" />)
  expect(screen.getByRole("heading", { name: "Declared permissions" })).toBeInTheDocument()
  expect(screen.getByText("Capability declarations grant no access. Approval and enforcement are checked separately.")).toBeInTheDocument()
  expect(within(screen.getByRole("list", { name: "What its capabilities request" })).getByRole("listitem"))
    .toHaveTextContent("Run containers on this computer. (requested; asking grants nothing)")
  expect(screen.queryByRole("heading", { name: "Asks for" })).not.toBeInTheDocument()
})
