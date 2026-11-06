import { expect, it } from "vitest"
import { GRID_KINDS } from "@/api/setups/capabilities.generated"
import type { SetupDraft } from "@/api/setups/types"
import { gridKindProblem, gridKinds, needsGridKind, profileOfRecipe, withGridKind } from "./draft"

const draft = (capabilities: string[], recipe?: SetupDraft["recipe"]): SetupDraft => ({
  name: "x", recipe, capabilities: Object.fromEntries(capabilities.map(id => [id, { selected: true, mode: "default", runnerEditable: true, settings: {} }])),
})

it("offers the kinds of grid the shared registry generates, in its order and words, and nothing of its own", () => {
  // The desktop has no table of its own: what it shows is the registry's, through the generated
  // catalogue, so the builder and the CLI's `template new` cannot say different things.
  expect(gridKinds()).toBe(GRID_KINDS)
  expect(GRID_KINDS.map(kind => kind.slug)).toEqual(["sandbox-grid", "neo-grid", "access-grid", "swarm-mining-grid"])
  for (const kind of GRID_KINDS) {
    expect(kind.name).toMatch(/ Grid$/)
    expect(kind.hint).toMatch(/\.$/)
    expect(profileOfRecipe(kind.slug)).toBe(kind.profile)
  }
})

it("reads a draft's profile from its kind of grid, including the one a setup can be read with but not made as", () => {
  expect(profileOfRecipe("swarm-mining-grid")).toBe("swarm_mining_grid")
  expect(profileOfRecipe(null)).toBeNull()
  expect(profileOfRecipe("")).toBeNull()
  expect(profileOfRecipe("toString")).toBeNull()
  expect(profileOfRecipe("neo_grid")).toBeNull()
})

it("asks for a kind of grid only while a grid is chosen, and lets the answer go with the grid", () => {
  expect(needsGridKind(draft(["grid.local_only"]))).toBe(false)
  expect(gridKindProblem(draft(["grid.local_only"]))).toBe("")
  for (const grid of ["grid.create", "grid.join"]) {
    expect(needsGridKind(draft([grid]))).toBe(true)
    expect(gridKindProblem(draft([grid]))).toMatch(/Sandbox Grid, Neo Grid, Access Grid or Swarm Mining Grid/)
    expect(gridKindProblem(draft([grid], "neo-grid"))).toBe("")
  }
  const answered = draft(["grid.create"], "neo-grid")
  expect(withGridKind(answered)).toBe(answered)
  expect(withGridKind(draft(["web.site"], "neo-grid")).recipe).toBeNull()
  const none = draft(["web.site"])
  expect(withGridKind(none)).toBe(none)
})
