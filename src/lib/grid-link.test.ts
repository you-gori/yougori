import { expect, it } from "vitest"
import { gridFocusFromSearch, gridSearchFor } from "@/lib/grid-link"

it("still opens each of the four grids from the address it had before", () => {
  expect(gridFocusFromSearch("?page=grid")).toEqual({ kind: "page", grid: "models" })
  expect(gridFocusFromSearch("?page=desks")).toEqual({ kind: "page", grid: "workspaces" })
  expect(gridFocusFromSearch("?page=access")).toEqual({ kind: "page", grid: "credentials" })
  expect(gridFocusFromSearch("?page=swarm")).toEqual({ kind: "page", grid: "research" })
})

it("reads the new spelling, by the grid's own word and never by an identifier", () => {
  expect(gridFocusFromSearch("?grid=neo")).toEqual({ kind: "page", grid: "models" })
  expect(gridFocusFromSearch("?grid=sandbox&show=status")).toEqual({ kind: "status", grid: "workspaces" })
  expect(gridFocusFromSearch("?grid=access&show=status")).toEqual({ kind: "status", grid: "credentials" })
  expect(gridSearchFor({ kind: "status", grid: "models" })).toBe("?grid=neo&show=status")
  expect(gridSearchFor({ kind: "page", grid: "research" })).toBe("?grid=research")
  expect(gridSearchFor(null)).toBe("")
})

it("leaves the area on its list when the address names nothing it knows", () => {
  expect(gridFocusFromSearch("")).toBeNull()
  expect(gridFocusFromSearch("?environment=env-1")).toBeNull()
  expect(gridFocusFromSearch("?grid=realm-4f2a9c")).toBeNull()
  expect(gridFocusFromSearch("?page=sandboxes")).toBeNull()
})

it("reads an address written with a different case or spacing", () => {
  expect(gridFocusFromSearch("?grid=%20Neo%20")).toEqual({ kind: "page", grid: "models" })
  expect(gridFocusFromSearch("?grid=ACCESS")).toEqual({ kind: "page", grid: "credentials" })
})
