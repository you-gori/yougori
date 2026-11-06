// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { CapabilityDescriptor } from "@/api/setups/types"

const api = vi.hoisted(() => ({
  capabilities: vi.fn(), validate: vi.fn(), plan: vi.fn(), apply: vi.fn(), list: vi.fn(), get: vi.fn(), operation: vi.fn(), cancel: vi.fn(), action: vi.fn(), reviewRemoval: vi.fn(),
}))
// The registry's own grid kinds: what belongs to one grid is offered with that grid.
const catalogue = vi.hoisted(() => {
  const capability = (over: Partial<CapabilityDescriptor>): CapabilityDescriptor => ({
    id: "x", version: 1, group: "grid_workers", name: "X", summary: "A capability.", examples: [], resourceKinds: [], requires: [], conflicts: [],
    aliases: [], permissions: [], actions: [], widget: "toggle", status: "shipped", profiles: [], requiresWaivedFor: [], ...over,
  })
  const grids = ["neo_grid", "sandbox_grid", "access_grid", "swarm_mining_grid"] as CapabilityDescriptor["profiles"]
  return [
    capability({ id: "grid.local_only", name: "Run on this computer only", conflicts: ["grid.create"] }),
    capability({ id: "grid.create", name: "Create a grid", conflicts: ["grid.local_only"], profiles: grids }),
    capability({ id: "models.team", group: "ai_models", name: "AI team", profiles: ["neo_grid"] }),
    capability({ id: "people.mfa", group: "people_access", name: "Two-step sign-in", profiles: ["access_grid", "sandbox_grid"] }),
    capability({ id: "web.site", group: "website_api", name: "Website" }),
  ]
})
vi.mock("@/api/setups/setups-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/setups-api")>()), setupsApi: api }))
vi.mock("@/api/setups/catalogue", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/catalogue")>()), CATALOGUE: catalogue }))
vi.mock("@/context/platform-context", () => ({ usePlatformOptional: () => null }))

import { SetupUnavailableError } from "@/api/setups/setups-api"
import { TemplateBuilder } from "./template-builder"

beforeEach(() => {
  api.capabilities.mockResolvedValue(catalogue.map(one => ({ id: one.id, availability: "available" as const })))
  api.validate.mockResolvedValue({ manifest: "format_version: 2\nname: Acme\n", diagnostics: [] })
  api.list.mockRejectedValue(new SetupUnavailableError("setup_list"))
})
afterEach(() => { cleanup(); vi.clearAllMocks() })

async function toCapabilities() {
  const user = userEvent.setup({ delay: null })
  render(<TemplateBuilder intent={{ mode: "create" }} open onClose={vi.fn()} onShowSetups={vi.fn()} />)
  await user.type(screen.getByLabelText("Template name"), "Acme")
  await user.click(screen.getByRole("button", { name: "Next" }))
  await screen.findByRole("heading", { name: "Choose what it can do" })
  return user
}

const card = (name: string) => screen.getByRole("article", { name })

it("lets a fresh template become a grid, and asks which kind, Swarm Mining Grid among them", async () => {
  const user = await toCapabilities()
  const create = await screen.findByRole("checkbox", { name: "Create a grid" })
  expect(create).toBeEnabled()
  expect(within(card("Create a grid")).getByText("Needs another kind of grid")).toBeInTheDocument()
  expect(screen.queryByText("Unsupported here")).not.toBeInTheDocument()
  await user.click(create)
  expect(create).toBeChecked()
  expect(screen.getAllByRole("radio", { name: /Grid/ }).map(radio => radio.closest("label")?.querySelector(".grid-choice-label")?.textContent)).toEqual(["Sandbox Grid", "Neo Grid", "Access Grid", "Swarm Mining Grid"])
})

it("makes the template the one kind of grid a capability belongs to when it is turned on", async () => {
  const user = await toCapabilities()
  await user.click(await screen.findByRole("checkbox", { name: "AI team" }))
  expect(screen.getByRole("checkbox", { name: "AI team" })).toBeChecked()
  expect(screen.getByRole("checkbox", { name: "Create a grid" })).toBeChecked()
  expect(screen.getByRole("radio", { name: /Neo Grid/ })).toBeChecked()
  expect(within(card("AI team")).getByText("Available")).toBeInTheDocument()
})

it("says which choices a kind of grid can't hold, and turns them off only when asked", async () => {
  const user = await toCapabilities()
  await user.click(await screen.findByRole("checkbox", { name: "AI team" }))
  // Two-step sign-in is a Sandbox or Access Grid's, so the kind is asked again, each saying what it leaves out.
  await user.click(screen.getByRole("checkbox", { name: "Two-step sign-in" }))
  expect(screen.getByRole("radio", { name: /Neo Grid/ })).not.toBeChecked()
  expect(screen.getByRole("radio", { name: /Neo Grid/ }).closest("label")).toHaveTextContent("Can't hold what you chose: Two-step sign-in.")
  expect(screen.getByRole("radio", { name: /Sandbox Grid/ }).closest("label")).toHaveTextContent("Can't hold what you chose: AI team.")
  await user.click(screen.getByRole("radio", { name: /Sandbox Grid/ }))
  const note = screen.getByText(/A Sandbox Grid can't hold AI team/)
  expect(screen.getByRole("checkbox", { name: "AI team" })).toBeChecked()
  await user.click(within(note).getByRole("button", { name: "Turn it off" }))
  expect(screen.getByRole("checkbox", { name: "AI team" })).not.toBeChecked()
  expect(screen.getByRole("checkbox", { name: "Two-step sign-in" })).toBeChecked()
  expect(screen.queryByText(/can't hold/)).not.toBeInTheDocument()
})

it("turns off keeping it to this computer when a grid capability is chosen", async () => {
  const user = await toCapabilities()
  await user.click(await screen.findByRole("checkbox", { name: "Run on this computer only" }))
  await user.click(screen.getByRole("checkbox", { name: "AI team" }))
  expect(screen.getByRole("checkbox", { name: "Run on this computer only" })).not.toBeChecked()
  expect(screen.getByRole("checkbox", { name: "Create a grid" })).toBeChecked()
})
