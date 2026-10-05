// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { createRef } from "react"
import { afterEach, expect, it, vi } from "vitest"
import { DialogHeader, DialogPanel } from "./ui/dialog"
import { SheetHeader, SheetPanel } from "./ui/sheet"

afterEach(cleanup)

it.each([
  { name: "dialog header", Component: DialogHeader, panel: false },
  { name: "sheet header", Component: SheetHeader, panel: false },
  { name: "dialog panel", Component: DialogPanel, panel: true },
  { name: "sheet panel", Component: SheetPanel, panel: true },
])("preserves caller HTML props, render element, ref and events in $name", ({ Component, panel }) => {
  const ref = createRef<HTMLDivElement>()
  const callerClick = vi.fn(), renderedClick = vi.fn()
  render(
    <Component
      slot="assigned-slot"
      data-slot="caller-slot"
      className="caller-class"
      ref={ref}
      onClick={callerClick}
      render={<section className="rendered-class" onClick={renderedClick} />}
    >Content</Component>,
  )
  const section = screen.getByText("Content")
  expect(section.tagName).toBe("SECTION")
  expect(section.getAttribute("slot")).toBe("assigned-slot")
  expect(section.getAttribute("data-slot")).toBe("caller-slot")
  expect(section.classList.contains("caller-class")).toBe(true)
  expect(section.classList.contains("rendered-class")).toBe(true)
  expect(ref.current).toBe(section)
  fireEvent.click(section)
  expect(callerClick).toHaveBeenCalledTimes(1)
  expect(renderedClick).toHaveBeenCalledTimes(1)
  const viewport = section.closest("[data-slot=scroll-area-viewport]")
  expect(Boolean(viewport)).toBe(panel)
  if (viewport) {
    expect(viewport.className).toContain("overscroll-y-contain")
    expect(viewport.className).toContain("mask-t-from-")
  }
})

it.each([
  { name: "dialog", Component: DialogPanel },
  { name: "sheet", Component: SheetPanel },
])("keeps the $name panel scroll wrapper when fades are disabled", ({ Component }) => {
  render(<Component scrollFade={false}>Content</Component>)
  const viewport = screen.getByText("Content").closest("[data-slot=scroll-area-viewport]")
  expect(viewport).not.toBeNull()
  expect(viewport!.className).toContain("overscroll-y-contain")
  expect(viewport!.className).not.toContain("mask-t-from-")
})
