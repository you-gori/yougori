// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it } from "vitest"
import { defaultNetworkOptions } from "./network-options"
import { NetworkOptionsForm } from "./network-options-form"
afterEach(cleanup)

// The engine's filter holds a Sandbox VM's network card to the public internet
// (src-tauri/src/sandbox/qemu_host/network_filter.rs); a GPU VM's card is the Windows NAT's,
// which the filter does not see.
it("says outgoing access reaches the public internet, and without a GPU never this computer or its network", () => {
  render(<NetworkOptionsForm value={{ ...defaultNetworkOptions(), internet: true }} onChange={() => {}} disabled={false} gridHosting={false} />)
  const outgoing = screen.getByRole("switch", { name: "Outgoing — allow all" })
  expect(outgoing).toBeChecked()
  expect(outgoing).toHaveAccessibleDescription("Let apps use websites, APIs, and downloads on the public internet. Without GPU acceleration, they cannot reach your computer or your local network. Replies to these connections are allowed.")
  expect(screen.queryByText(/services on your local network/)).toBeNull()
})
