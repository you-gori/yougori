// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"

const api = vi.hoisted(() => ({ privateOutputs: vi.fn(), reveal: vi.fn() }))
vi.mock("@/api/setups/setups-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/setups-api")>()), setupsApi: api }))

import { SetupCommandError, SetupUnavailableError } from "@/api/setups/setups-api"
import { PrivateOutputs } from "./setup-private-outputs"

afterEach(() => { cleanup(); vi.clearAllMocks() })

it("names each private output and shows its value only when asked, then lets it go", async () => {
  const user = userEvent.setup()
  api.privateOutputs.mockResolvedValue([{ key: "invite", label: "Grid invite" }])
  api.reveal.mockResolvedValue("desk-invite:abc")
  render(<PrivateOutputs setupId="s1" revision={3} />)
  const list = await screen.findByLabelText("Private outputs")
  expect(within(list).getByText("Grid invite")).toBeInTheDocument()
  expect(list).not.toHaveTextContent("desk-invite")
  expect(api.reveal).not.toHaveBeenCalled()
  await user.click(within(list).getByRole("button", { name: "Show Grid invite" }))
  expect(api.reveal).toHaveBeenCalledWith("s1", "invite")
  expect(await within(list).findByText("desk-invite:abc")).toBeInTheDocument()
  await user.click(within(list).getByRole("button", { name: "Hide Grid invite" }))
  expect(list).not.toHaveTextContent("desk-invite")
  // Shown again, it is asked of the product again: nothing was kept.
  await user.click(within(list).getByRole("button", { name: "Show Grid invite" }))
  expect(api.reveal).toHaveBeenCalledTimes(2)
})

it("says plainly when a value isn't there yet, and shows nothing at all without private outputs", async () => {
  const user = userEvent.setup()
  api.privateOutputs.mockResolvedValue([{ key: "invite", label: "Grid invite" }])
  api.reveal.mockRejectedValue(new SetupCommandError("The grid is paused, so it has no invite right now.", { code: "output_not_ready", retryable: true }))
  render(<PrivateOutputs setupId="s1" />)
  await user.click(await screen.findByRole("button", { name: "Show Grid invite" }))
  expect(await screen.findByText("The grid is paused, so it has no invite right now.")).toBeInTheDocument()
  cleanup()
  api.privateOutputs.mockRejectedValue(new SetupUnavailableError("setup_reveal"))
  const { container } = render(<PrivateOutputs setupId="s1" />)
  await vi.waitFor(() => expect(api.privateOutputs).toHaveBeenCalledTimes(2))
  expect(container).toBeEmptyDOMElement()
})
