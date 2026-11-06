import { expect, it } from "vitest"
import { GROUPS, selectable, withAvailability } from "./catalogue"
import type { CapabilityDescriptor } from "./types"

const capability = (over: Partial<CapabilityDescriptor>): CapabilityDescriptor => ({
  id: "x", version: 1, group: "grid_workers", name: "X", summary: "", examples: [], resourceKinds: [], requires: [], conflicts: [],
  aliases: [], permissions: [], actions: [], widget: "toggle", status: "shipped", profiles: [], requiresWaivedFor: [], ...over,
})

it("keeps the six groups in the builder's order, Grid & workers first", () => {
  expect(GROUPS.map(group => group.id)).toEqual(["grid_workers", "ai_models", "website_api", "people_access", "files_data", "automation_recovery"])
  expect(GROUPS.every(group => group.lead && group.words.length)).toBe(true)
})

it("shows what the engine said, and never more than it said", () => {
  const catalogue = [
    capability({ id: "a" }),
    capability({ id: "b" }),
    capability({ id: "planned", status: "planned" }),
    capability({ id: "missing" }),
    capability({ id: "neo-only", profiles: ["neo_grid"] }),
  ]
  const shown = withAvailability(catalogue, [
    { id: "a", availability: "available" },
    { id: "b", availability: "needs_configuration", reason: "Choose a storage drive first." },
    { id: "planned", availability: "available" },
    { id: "neo-only", availability: "available" },
  ], "sandbox_grid")
  expect(shown.map(entry => [entry.descriptor.id, entry.availability])).toEqual([
    ["a", "available"], ["b", "needs_configuration"], ["planned", "planned"], ["missing", "unsupported"], ["neo-only", "unsupported"],
  ])
  expect(shown[1]!.reason).toBe("Choose a storage drive first.")
  expect(shown[4]!.reason).toBe("Works in Neo Grid setups for now, not in Sandbox Grid setups.")
  expect(withAvailability(catalogue, null).map(entry => entry.availability)).toEqual(["unknown", "unknown", "planned", "unknown", "unsupported"])
  expect(withAvailability([capability({ id: "neo-only", profiles: ["neo_grid"] })], [{ id: "neo-only", availability: "available" }], "neo_grid")[0]!.availability).toBe("available")
  expect(["available", "needs_configuration"].every(state => selectable(state as never))).toBe(true)
  // Nothing can be turned on before this computer has been checked for it.
  expect(["unsupported", "planned", "unknown"].some(state => selectable(state as never))).toBe(false)
})

it("lets a template include what the engine can't set up yet, but never a setup made here", () => {
  const catalogue = [capability({ id: "later" })]
  const report = [{ id: "later", availability: "available" as const, engineReady: false, engineReason: "Yougori can't set this up on this computer yet." }]
  const authoring = withAvailability(catalogue, report)[0]!
  expect(authoring.availability).toBe("available")
  expect(authoring.reason).toBe("Yougori can't set this up on this computer yet. A template can still include it.")
  const running = withAvailability(catalogue, report, "generic", { running: true })[0]!
  expect(running.availability).toBe("unsupported")
  expect(running.reason).toBe("Yougori can't set this up on this computer yet.")
})

it("offers what belongs to another kind of grid while a template's kind can still change, and only if this computer can run it", () => {
  const catalogue = [
    capability({ id: "neo-only", profiles: ["neo_grid"] }),
    capability({ id: "people", profiles: ["sandbox_grid", "access_grid"] }),
    capability({ id: "anywhere" }),
    capability({ id: "neo-broken", profiles: ["neo_grid"] }),
  ]
  const report = [
    { id: "neo-only", availability: "available" as const },
    { id: "people", availability: "needs_configuration" as const },
    { id: "anywhere", availability: "available" as const },
    { id: "neo-broken", availability: "unsupported" as const, reason: "This computer cannot run containers yet." },
  ]
  const making = withAvailability(catalogue, report, "generic", { switchable: true })
  expect(making.map(entry => entry.availability)).toEqual(["other_grid", "other_grid", "available", "unsupported"])
  expect(making[0]!.reason).toBe("It belongs to a Neo Grid. Turning it on makes this setup a Neo Grid.")
  expect(making[1]!.reason).toBe("It belongs to a Sandbox Grid or an Access Grid. Turning it on makes this setup a grid, and asks which kind.")
  expect(making[3]!.reason).toBe("This computer cannot run containers yet.")
  const sandbox = withAvailability(catalogue, report, "sandbox_grid", { switchable: true })
  expect(sandbox[0]!.reason).toBe("It belongs to a Neo Grid, not a Sandbox Grid. Turning it on makes this setup a Neo Grid.")
  expect(sandbox[1]!.availability).toBe("needs_configuration")
  // A setup that exists keeps its kind, so there it is simply not offered.
  expect(withAvailability(catalogue, report, "sandbox_grid")[0]!.availability).toBe("unsupported")
  expect(selectable("other_grid")).toBe(false)
})
