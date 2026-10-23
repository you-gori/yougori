import { describe, expect, it } from "vitest"
import { MOST, mentions, paginate, where } from "@/api/grids/page"

const rows = Array.from({ length: 120 }, (_, at) => ({ id: `row-${at}`, name: at % 2 ? "Design laptop" : "Studio PC", on: at % 3 === 0 }))
const key = (row: { id: string }) => row.id

describe("paging", () => {
  it("asking for no page asks for the whole list, so a method that returned everything still does", () => {
    const page = paginate(rows, {}, key)
    expect(page.items).toHaveLength(120)
    expect(page.next).toBeNull()
    expect(page.total).toBe(120)
  })

  it("resumes exactly after the item the cursor names", () => {
    const first = paginate(rows, { limit: 50 }, key)
    expect(first.items).toHaveLength(50)
    expect(first.next).toBe("row-49")
    const second = paginate(rows, { after: first.next, limit: 50 }, key)
    expect(second.items[0]!.id).toBe("row-50")
    const last = paginate(rows, { after: second.next, limit: 50 }, key)
    expect(last.items).toHaveLength(20)
    expect(last.next).toBeNull()
  })

  it("gives nothing back when the cursor names something that is no longer there", () => {
    expect(paginate(rows, { after: "row-gone", limit: 10 }, key).items).toEqual([])
  })

  it("will not be talked into asking for everything in the name of paging", () => {
    expect(paginate(rows, { limit: 9000 }, key).items).toHaveLength(Math.min(120, MOST))
    expect(paginate(rows, { limit: 0 }, key).items).toHaveLength(1)
  })

  it("keeps only what every test agrees with, and a filter left out narrows nothing", () => {
    const kept = where(rows, [row => row.on, row => row.name === "Studio PC"])
    expect(kept.every(row => row.on && row.name === "Studio PC")).toBe(true)
    expect(where(rows, [])).toHaveLength(120)
  })

  it("matches a search without minding case, and matches everything when there is none", () => {
    expect(mentions("design", "Design laptop", null)).toBe(true)
    expect(mentions("DESIGN", "Design laptop")).toBe(true)
    expect(mentions("studio", "Design laptop", "192.168.1.30")).toBe(false)
    expect(mentions(undefined, "anything")).toBe(true)
    expect(mentions("   ", "anything")).toBe(true)
  })
})
