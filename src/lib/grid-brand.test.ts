// @vitest-environment jsdom
import { afterEach, expect, it } from "vitest"
import { brandedName, readGridBrand, writeGridBrand } from "@/lib/grid-brand"

afterEach(() => window.localStorage.clear())

it("shows a company's own name where it gave one, and the grid's name where it did not", () => {
  expect(brandedName("Acme", { company: "", support: "" })).toBe("Acme")
  expect(brandedName("Acme", { company: "Acme Research", support: "" })).toBe("Acme Research")
})

it("keeps a brand for one grid and never lets it show on another", () => {
  writeGridBrand("credentials", { company: "Acme Research", support: "Ask Grace in Security." })
  expect(readGridBrand("credentials")).toEqual({ company: "Acme Research", support: "Ask Grace in Security." })
  expect(readGridBrand("models")).toEqual({ company: "", support: "" })
})

it("leaves nothing behind when a brand is cleared", () => {
  writeGridBrand("models", { company: "Acme", support: "" })
  writeGridBrand("models", { company: " ", support: " " })
  expect(window.localStorage.getItem("yougori.grid.brand.models")).toBeNull()
  expect(readGridBrand("models")).toEqual({ company: "", support: "" })
})

it("reads nothing out of a brand somebody has broken", () => {
  window.localStorage.setItem("yougori.grid.brand.workspaces", "not json at all")
  expect(readGridBrand("workspaces")).toEqual({ company: "", support: "" })
})
