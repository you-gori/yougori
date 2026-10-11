// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { PublicAccessPresets } from "./public-access-presets"
import { workspaceApi, type SetupTunnelConnection } from "@/api/workspace-api"

afterEach(() => { cleanup(); localStorage.clear(); vi.restoreAllMocks() })

const setup = { id: "a92e7be0-285b-413e-bf58-dc43ad13b790", hostname: "app.example.com", port: 3000, hostPort: 45000, credentialEnvironmentId: "public-presets" }
function openSetups() {
  localStorage.setItem("yougori.public-access-presets.v1", JSON.stringify([setup]))
  render(<PublicAccessPresets environments={[]} refresh={vi.fn()} />)
  act(() => window.dispatchEvent(new Event("yougori-open-public-presets-manager")))
}

it("connects a setup without an environment, waits for registration, and shows routing and stop controls", async () => {
  let finish!: (value: SetupTunnelConnection) => void
  const start = vi.spyOn(workspaceApi, "startSetupTunnel").mockImplementation(() => new Promise(resolve => { finish = resolve }))
  const stop = vi.spyOn(workspaceApi, "stopSetupTunnel").mockResolvedValue()
  openSetups()
  const button = await screen.findByRole("button", { name: "Connect for tunnel setup: app.example.com" })
  expect(button).toBeVisible()
  expect(screen.getByText(/No environment needs to be running/)).toBeVisible()
  fireEvent.click(button)
  expect(start).toHaveBeenCalledWith(setup.id)
  expect(button).toBeDisabled()
  expect(screen.getByRole("status")).toHaveTextContent("Connecting app.example.com to Cloudflare")
  expect(screen.queryByText(/Connection is on/)).not.toBeInTheDocument()
  await act(async () => finish({ hostname: setup.hostname, hostPort: setup.hostPort, status: "connected", servingApp: false }))
  expect(await screen.findByText(/Connection is on/)).toBeInTheDocument()
  expect(screen.getByText("http://localhost:45000", { selector: "dd code" })).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Stop setup tunnel" }))
  await waitFor(() => expect(stop).toHaveBeenCalledWith(setup.id))
  expect(await screen.findByText("Setup connection is off. Your saved setup is kept.")).toBeInTheDocument()
})

it("keeps the setup and offers retry when the tunnel fails to connect", async () => {
  vi.spyOn(workspaceApi, "startSetupTunnel").mockRejectedValue(new Error("Cloudflare is unreachable"))
  openSetups()
  fireEvent.click(await screen.findByRole("button", { name: "Connect for tunnel setup: app.example.com" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Your setup is saved, but the tunnel could not connect: Cloudflare is unreachable")
  expect(screen.queryByText(/Connection is on/)).not.toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Connect for tunnel setup: app.example.com" })).toBeEnabled()
  expect(JSON.parse(localStorage.getItem("yougori.public-access-presets.v1")!)).toEqual([setup])
})

it("saves a new setup before connecting and retains it if connection fails", async () => {
  const save = vi.spyOn(workspaceApi, "saveCloudflarePreset").mockResolvedValue()
  const start = vi.spyOn(workspaceApi, "startSetupTunnel").mockImplementation(async domain => {
    expect(JSON.parse(localStorage.getItem("yougori.public-access-presets.v1")!)).toContainEqual(expect.objectContaining({ id: domain, hostname: "new.example.com" }))
    throw new Error("Connection timed out")
  })
  openSetups()
  fireEvent.change(await screen.findByRole("textbox", { name: "App port" }), { target: { value: "8000" } })
  fireEvent.change(screen.getByRole("textbox", { name: "Domain" }), { target: { value: "new.example.com" } })
  fireEvent.change(screen.getByRole("textbox", { name: "Local tunnel port" }), { target: { value: "45001" } })
  fireEvent.change(screen.getByLabelText("Cloudflare tunnel token"), { target: { value: "test-token" } })
  fireEvent.click(screen.getByRole("button", { name: "Save and connect tunnel" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Connection timed out")
  expect(save).toHaveBeenCalledTimes(1)
  expect(start).toHaveBeenCalledWith(expect.any(String))
  expect(screen.getByText("new.example.com · :8000")).toBeInTheDocument()
  expect(screen.getByLabelText("Cloudflare tunnel token")).toHaveValue("")
})
