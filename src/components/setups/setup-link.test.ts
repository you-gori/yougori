import { expect, it } from "vitest"
import { appLocationFromSearch, hubRefFrom } from "./setup-link"
import { findSetupMatches } from "./setup-search"
import type { CapabilityDescriptor } from "@/api/setups/types"

const nowhere = { page: "sandboxes", setupId: null, builder: null }

it("opens the three destinations and a setup by name, and the older words for all the grids open My setups", () => {
  expect(appLocationFromSearch("?page=setups").page).toBe("setups")
  expect(appLocationFromSearch("?page=my-setups").page).toBe("setups")
  expect(appLocationFromSearch("?page=hub").page).toBe("hub")
  expect(appLocationFromSearch("?page=computer").page).toBe("sandboxes")
  for (const word of ["grids", "all-grids", "grid", "neo", "sandbox", "desks", "access", "swarm", "research", "credentials", "models", "workspaces"]) {
    expect(appLocationFromSearch(`?page=${word}`)).toEqual({ ...nowhere, page: "setups" })
  }
  expect(appLocationFromSearch("?grid=access&show=status")).toEqual({ ...nowhere, page: "setups" })
  expect(appLocationFromSearch("?setup=setup-01")).toEqual({ ...nowhere, page: "setups", setupId: "setup-01" })
})

it("opens the builder on a Hub template, and an older recipe address on My setups without reading the word", () => {
  expect(appLocationFromSearch("?template=ana/my-api@1.0.0")).toEqual({ ...nowhere, page: "hub", builder: { mode: "run", hubRef: "hub/ana/my-api@1.0.0" } })
  expect(appLocationFromSearch("?run=hub/ana/my-api")).toEqual({ ...nowhere, page: "hub", builder: { mode: "run", hubRef: "hub/ana/my-api" } })
  expect(appLocationFromSearch("?create=template")).toEqual({ ...nowhere, page: "hub", builder: { mode: "create" } })
  expect(appLocationFromSearch("?create=template&template=ana/my-api")).toEqual({ ...nowhere, page: "hub", builder: { mode: "create", hubRef: "hub/ana/my-api", entry: "hub" } })
  // There are no starter recipes any more: an address that named one opens My setups, where a
  // template is run, and the word is never read, whatever it is.
  for (const search of ["?recipe=sandbox-grid", "?recipe=neo", "?recipe=%3Cscript%3E"]) {
    expect(appLocationFromSearch(search)).toEqual({ ...nowhere, page: "setups" })
  }
  expect(appLocationFromSearch("?create=template&recipe=neo")).toEqual({ ...nowhere, page: "hub", builder: { mode: "create" } })
  // A template named by a word rather than an address is looked for on the Hub.
  expect(appLocationFromSearch("?template=bounty")).toEqual({ ...nowhere, page: "hub" })
  expect(appLocationFromSearch("?template=not a ref")).toEqual({ ...nowhere, page: "hub" })
})

it("never lands on nothing: an unknown or unsafe address opens My computer", () => {
  for (const search of ["", "?page=nonsense", "?setup=../../etc", "?recipe=", "?template="]) {
    expect(appLocationFromSearch(search)).toEqual(nowhere)
  }
  expect(hubRefFrom("hub/Ana/x")).toBeNull()
  expect(hubRefFrom("ana/x")).toBe("hub/ana/x")
})

const capability = (over: Partial<CapabilityDescriptor>): CapabilityDescriptor => ({
  id: "x", version: 1, group: "grid_workers", name: "X", summary: "", examples: [], resourceKinds: [], requires: [], conflicts: [],
  aliases: [], permissions: [], actions: [], widget: "toggle", status: "shipped", profiles: [], requiresWaivedFor: [], ...over,
})

it("finds capability groups for plain words, and capabilities by name or alias", () => {
  const catalogue = [capability({ id: "data.backup", group: "automation_recovery", name: "Backups", aliases: ["snapshot"] }), capability({ id: "data.db", group: "files_data", name: "Database" })]
  const groupsFor = (query: string) => findSetupMatches(query, catalogue).groups.map(group => group.group)
  expect(groupsFor("gpu")).toContain("grid_workers")
  expect(groupsFor("team")).toContain("people_access")
  expect(groupsFor("API")).toContain("website_api")
  expect(groupsFor("agent")).toContain("ai_models")
  expect(findSetupMatches("snapshot", catalogue).groups).toEqual([{ group: "automation_recovery", capabilities: [catalogue[0]] }])
  expect(findSetupMatches("database", catalogue).groups.find(group => group.group === "files_data")?.capabilities).toEqual([catalogue[1]])
  expect(findSetupMatches("x", catalogue)).toEqual({ groups: [] })
})

it("finds no starter recipe for the old grid names, only the groups their plain words belong to", () => {
  // The old aliases (desks, bounty, private worker…) named recipes that are gone; the words that
  // name a group of capabilities still find it.
  for (const old of ["Sandbox Grid", "desks", "bounty", "private worker", "Swarm Mining"]) {
    const found = findSetupMatches(old, [])
    expect(Object.keys(found)).toEqual(["groups"])
    expect(found.groups).toEqual([])
  }
  expect(findSetupMatches("grid", []).groups.map(group => group.group)).toEqual(["grid_workers"])
  expect(findSetupMatches("access", []).groups.map(group => group.group)).toEqual(["people_access"])
})
