// @vitest-environment jsdom
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest"
import { GuestTerminal } from "./guest-terminal"
import { workspaceApi, type TerminalOutput } from "@/api/workspace-api"

const terminalState = vi.hoisted(() => ({ input: undefined as ((data: string) => void) | undefined, options: {} as { disableStdin?: boolean }, osc: {} as Record<number, (data: string) => boolean> }))
const clipboard = vi.hoisted(() => ({ writeText: vi.fn(), readText: vi.fn() }))
vi.mock("@xterm/xterm", () => ({ Terminal: class {
  options = terminalState.options
  cols = 80
  rows = 24
  buffer = { active: { length: 0 } }
  parser = { registerOscHandler: (id: number, handler: (data: string) => boolean) => { terminalState.osc[id] = handler; return { dispose() {} } } }
  open() {}
  loadAddon() {}
  focus() {}
  attachCustomKeyEventHandler() {}
  onData(handler: (data: string) => void) { terminalState.input = handler; return { dispose() { terminalState.input = undefined } } }
  onResize() { return { dispose() {} } }
  write() {}
  writeln() {}
  dispose() {}
} }))
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }))
vi.mock("@/components/terminal-link-cards", () => ({ TerminalLinkCards: () => null }))
vi.mock("@/api/workspace-api", () => ({ workspaceApi: { terminal: vi.fn(), prepareInstaller: vi.fn() } }))
vi.mock("@/lib/terminal-clipboard", async importOriginal => ({
  ...await importOriginal<typeof import("@/lib/terminal-clipboard")>(),
  terminalClipboard: clipboard,
  osc52CopyText: (data: string) => atob(data.slice(data.indexOf(";") + 1)),
}))
function deferred<T>() {
  let resolve!: (value: T) => void
  const promise = new Promise<T>(yes => { resolve = yes })
  return { promise, resolve }
}
const output: TerminalOutput = { data: "", offset: 0, done: false }
beforeEach(() => {
  vi.resetAllMocks()
  terminalState.options = {}
  vi.stubGlobal("ResizeObserver", class { observe() {} disconnect() {} })
  vi.mocked(workspaceApi.terminal).mockImplementation((_environment, _session, action) => action === "read" ? new Promise(() => {}) : Promise.resolve(output))
})
afterEach(() => { cleanup(); vi.unstubAllGlobals() })

describe("guest terminal lifecycle", () => {
  it("closes the owned session after installer preparation fails instead of leaving an unusable live shell", async () => {
    vi.mocked(workspaceApi.prepareInstaller).mockRejectedValue(new Error("Installer unavailable"))
    const ready = vi.fn()
    const { unmount } = render(<GuestTerminal environmentId="alpha" sessionId="tab-1" active installer="codex" onReady={ready} />)
    expect((await screen.findByRole("alert")).textContent).toContain("Installer unavailable")
    expect(ready).toHaveBeenLastCalledWith("tab-1", false, true)
    expect(workspaceApi.terminal).toHaveBeenCalledWith("alpha", expect.stringMatching(/^term-/), "close")
    expect(terminalState.options.disableStdin).toBe(true)
    unmount()
    expect(vi.mocked(workspaceApi.terminal).mock.calls.filter(call => call[2] === "close")).toHaveLength(1)
  })

  it("cancels remaining pasted chunks when the tab closes", async () => {
    const firstWrite = deferred<TerminalOutput>()
    vi.mocked(workspaceApi.terminal).mockImplementation((_environment, _session, action) => action === "read" ? new Promise(() => {}) : action === "write" ? firstWrite.promise : Promise.resolve(output))
    const ready = vi.fn()
    const { unmount } = render(<GuestTerminal environmentId="alpha" sessionId="tab-1" active onReady={ready} />)
    await waitFor(() => expect(ready).toHaveBeenCalledWith("tab-1", true))
    act(() => { terminalState.input!("x".repeat(40_000)) })
    await waitFor(() => expect(vi.mocked(workspaceApi.terminal).mock.calls.filter(call => call[2] === "write")).toHaveLength(1))
    unmount()
    await act(async () => { firstWrite.resolve(output); await firstWrite.promise })
    expect(vi.mocked(workspaceApi.terminal).mock.calls.filter(call => call[2] === "write")).toHaveLength(1)
  })

  it("asks before a guest program copies to the clipboard and remembers a block", async () => {
    clipboard.writeText.mockResolvedValue(undefined)
    const ready = vi.fn()
    render(<GuestTerminal environmentId="alpha" sessionId="tab-1" active onReady={ready} />)
    await waitFor(() => expect(ready).toHaveBeenCalledWith("tab-1", true))
    act(() => { terminalState.osc[52]!("c;" + btoa("first")) })
    expect(clipboard.writeText).not.toHaveBeenCalled()
    fireEvent.click(screen.getByRole("button", { name: "Copy" }))
    expect(clipboard.writeText).toHaveBeenCalledExactlyOnceWith("first")
    act(() => { terminalState.osc[52]!("c;" + btoa("second")) })
    fireEvent.click(screen.getByRole("button", { name: "Block" }))
    act(() => { terminalState.osc[52]!("c;" + btoa("third")) })
    expect(screen.queryByRole("group", { name: "Clipboard request" })).toBeNull()
    expect(clipboard.writeText).toHaveBeenCalledOnce()
  })

  it("copies without asking again once allowed for this terminal", async () => {
    clipboard.writeText.mockResolvedValue(undefined)
    const ready = vi.fn()
    render(<GuestTerminal environmentId="alpha" sessionId="tab-1" active onReady={ready} />)
    await waitFor(() => expect(ready).toHaveBeenCalledWith("tab-1", true))
    act(() => { terminalState.osc[52]!("c;" + btoa("first")) })
    fireEvent.click(screen.getByRole("button", { name: "Always allow here" }))
    act(() => { terminalState.osc[52]!("c;" + btoa("second")) })
    expect(clipboard.writeText.mock.calls).toEqual([["first"], ["second"]])
    expect(screen.queryByRole("group", { name: "Clipboard request" })).toBeNull()
  })

  it("does not let pasted input race the installer command in its dedicated shell", async () => {
    const preparation = deferred<string>()
    vi.mocked(workspaceApi.prepareInstaller).mockReturnValue(preparation.promise)
    const ready = vi.fn()
    render(<GuestTerminal environmentId="alpha" sessionId="tab-1" active installer="codex" onReady={ready} />)
    await waitFor(() => expect(workspaceApi.prepareInstaller).toHaveBeenCalledOnce())
    act(() => { terminalState.input!("unrelated command\r") })
    expect(vi.mocked(workspaceApi.terminal).mock.calls.filter(call => call[2] === "write")).toHaveLength(0)
    await act(async () => { preparation.resolve("exec sh '/tmp/yougori-install.codex/install.sh'"); await preparation.promise })
    await waitFor(() => expect(terminalState.options.disableStdin).toBe(false))
    expect(vi.mocked(workspaceApi.terminal).mock.calls.filter(call => call[2] === "write")).toHaveLength(1)
  })
})


it("launches model chat only in its fresh terminal and keeps input locked until delivery", async () => {
  const firstWrite = deferred<TerminalOutput>()
  vi.mocked(workspaceApi.terminal).mockImplementation((_env, _session, action) => action === "read" ? new Promise(() => {}) : action === "write" ? firstWrite.promise : Promise.resolve(output))
  render(<GuestTerminal environmentId="model-a" sessionId="chat-tab" active modelChat />)
  await waitFor(() => expect(workspaceApi.terminal).toHaveBeenCalledWith("model-a", expect.stringMatching(/^term-/), "write", expect.anything()))
  expect(terminalState.options.disableStdin).toBe(true)
  act(() => { terminalState.input!("unrelated command\r") })
  await act(async () => { firstWrite.resolve(output); await firstWrite.promise })
  await waitFor(() => expect(terminalState.options.disableStdin).toBe(false))
  const writes = vi.mocked(workspaceApi.terminal).mock.calls.filter(call => call[2] === "write")
  const command = writes.map(call => atob(call[3]!.data!)).join("")
  expect(command).toContain("python -c '")
  expect(command).not.toContain("unrelated command")
  expect(command.endsWith("\r")).toBe(true)
  expect(Math.max(...command.split("\n").map(line => line.length))).toBeLessThan(1024)
  expect(new Set(writes.map(call => call[1])).size).toBe(1)
})
