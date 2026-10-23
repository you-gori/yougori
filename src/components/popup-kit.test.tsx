// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { useState } from "react"
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, expect, it } from "vitest"
import { ChoiceCards, ReachCards, StillNeeded, type ReachKind } from "./popup-kit"

afterEach(cleanup)

function Reach({ address }: { address: string }) {
  const [value, setValue] = useState<ReachKind>("network")
  return <ReachCards who="computers" value={value} onPick={setValue} address={address} port={7463} />
}

it("shows the address people will use under each way to reach a hub, naming Cloudflare", () => {
  render(<Reach address="192.168.1.20" />)
  const network = screen.getByRole("radio", { name: "This network only" })
  const anywhere = screen.getByRole("radio", { name: "Anywhere, through Cloudflare" })
  expect(network).toHaveAttribute("aria-checked", "true")
  // The network card shows this computer's real address and the hub's port.
  expect(network).toHaveAccessibleDescription(/192\.168\.1\.20:7463/)
  // The quick link card says it is Cloudflare, and shows the shape of the address it hands out.
  expect(anywhere).toHaveAccessibleDescription(/Cloudflare's free quick tunnel/)
  // The words Cloudflare fills in are their own element, so the description spaces them out.
  expect(anywhere).toHaveAccessibleDescription(/https:\/\/\s?random-words\s?\.trycloudflare\.com/)
})

it("says where the address goes before one is typed, rather than inventing one", () => {
  render(<Reach address="  " />)
  expect(screen.getByRole("radio", { name: "This network only" })).toHaveAccessibleDescription(/This computer's address, port 7463/)
})

it("moves between cards with the arrow keys, keeping one tab stop", () => {
  render(<Reach address="10.0.0.5" />)
  const network = screen.getByRole("radio", { name: "This network only" })
  const anywhere = screen.getByRole("radio", { name: "Anywhere, through Cloudflare" })
  expect(network).toHaveAttribute("tabindex", "0")
  expect(anywhere).toHaveAttribute("tabindex", "-1")
  fireEvent.keyDown(network, { key: "ArrowDown" })
  expect(anywhere).toHaveAttribute("aria-checked", "true")
  expect(anywhere).toHaveAttribute("tabindex", "0")
  expect(anywhere).toHaveFocus()
  fireEvent.keyDown(anywhere, { key: "ArrowDown" })
  expect(network).toHaveAttribute("aria-checked", "true")
})

it("skips a choice that cannot be picked", () => {
  function Pick() {
    const [value, setValue] = useState<"a" | "b" | "c">("a")
    return <ChoiceCards label="Pick" value={value} onPick={setValue} options={[
      { value: "a", title: "First", detail: "One" },
      { value: "b", title: "Second", detail: "Two", disabled: true },
      { value: "c", title: "Third", detail: "Three" },
    ]} />
  }
  render(<Pick />)
  fireEvent.keyDown(screen.getByRole("radio", { name: "First" }), { key: "ArrowRight" })
  expect(screen.getByRole("radio", { name: "Third" })).toHaveAttribute("aria-checked", "true")
})

it("says what is still needed, and nothing when nothing is", () => {
  const { rerender } = render(<StillNeeded>Add the company name to continue.</StillNeeded>)
  expect(screen.getByText("Add the company name to continue.")).toBeInTheDocument()
  rerender(<StillNeeded>{""}</StillNeeded>)
  expect(screen.queryByText("Add the company name to continue.")).toBeNull()
})
