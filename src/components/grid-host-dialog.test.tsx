// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { GridHostDialog } from "./grid-host-dialog"
import { desksApi } from "@/api/desks-api"

vi.mock("@/api/desks-api", () => ({ desksApi: { suggestedAddress: vi.fn(), create: vi.fn() } }))
vi.mock("@/api/grid-api", () => ({ gridApi: { suggestedAddress: vi.fn(), create: vi.fn() } }))

beforeEach(() => {
  vi.mocked(desksApi.suggestedAddress).mockResolvedValue("192.168.1.20")
  vi.mocked(desksApi.create).mockResolvedValue({ message: "Hosted" } as never)
})
afterEach(() => { cleanup(); vi.resetAllMocks() })

const dialog = () => screen.getByRole("dialog", { name: "Host a sandbox grid" })

it("previews the address computers will use, and names Cloudflare for the public link", async () => {
  render(<GridHostDialog open variant="desks" onOpenChange={vi.fn()} onHosted={vi.fn()} />)
  await waitFor(() => expect(screen.getByLabelText("This computer's address")).toHaveValue("192.168.1.20"))
  expect(screen.getByRole("radio", { name: "This network only" })).toHaveAccessibleDescription(/192\.168\.1\.20:7463/)
  fireEvent.click(screen.getByRole("radio", { name: /Anywhere/ }))
  expect(dialog()).toHaveTextContent("Cloudflare picks the words when the hub starts")
  expect(within(dialog()).getByRole("note", { name: "When you host" })).toHaveTextContent("desk-invite:")
})

it("says beside the button what is still needed, then hosts with what was typed", async () => {
  const onHosted = vi.fn()
  render(<GridHostDialog open variant="desks" onOpenChange={vi.fn()} onHosted={onHosted} />)
  const host = screen.getByRole("button", { name: "Host grid" })
  expect(host).toBeDisabled()
  expect(dialog()).toHaveTextContent("Add the company name to continue.")
  fireEvent.change(screen.getByLabelText("Company name"), { target: { value: "Acme" } })
  await waitFor(() => expect(screen.getByLabelText("This computer's address")).toHaveValue("192.168.1.20"))
  expect(dialog()).toHaveTextContent("The password needs at least 10 characters.")
  fireEvent.change(screen.getByLabelText("Company password"), { target: { value: "correct horse battery" } })
  fireEvent.change(screen.getByLabelText("Type it again"), { target: { value: "correct horse battery" } })
  expect(host).toBeEnabled()
  fireEvent.click(host)
  await waitFor(() => expect(onHosted).toHaveBeenCalledWith("Hosted"))
  expect(desksApi.create).toHaveBeenCalledWith("Acme", "192.168.1.20", "correct horse battery", "network")
})
