// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { ModelArchitectureSupport } from "./model-architecture-support"
const mocks=vi.hoisted(()=>({prepare:vi.fn(),copy:vi.fn()}))
vi.mock("@/api/projects-api",()=>({modelsApi:{supportTask:mocks.prepare}}))
vi.mock("@/lib/terminal-clipboard",()=>({terminalClipboard:{writeText:mocks.copy}}))
afterEach(()=>{cleanup();vi.resetAllMocks()})
it("requires a deliberate agent choice and saves its isolated task with a launch command",async()=>{
  mocks.prepare.mockResolvedValue({path:"C:/Tasks/support-1",launchCommand:"kilo --prompt safe",resumeCommand:"safe resume"})
  mocks.copy.mockResolvedValue(undefined)
  render(<ModelArchitectureSupport model="hf.co/example/model" />)
  expect(mocks.prepare).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button",{name:"Implement architecture support with AI"}))
  expect(screen.getAllByRole("option")).toHaveLength(5)
  fireEvent.change(screen.getByLabelText("Coding agent"),{target:{value:"kilo"}})
  fireEvent.click(screen.getByRole("button",{name:"Prepare task for Kilo Code"}))
  await waitFor(()=>expect(mocks.prepare).toHaveBeenCalledWith("hf.co/example/model","kilo",undefined))
  expect(await screen.findByText("C:/Tasks/support-1")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button",{name:"Copy launch command"}))
  expect(mocks.copy).toHaveBeenCalledWith("safe resume")
  fireEvent.change(screen.getByLabelText("Coding agent"),{target:{value:"codex"}})
  expect(screen.queryByText("C:/Tasks/support-1")).toBeNull()
  expect(screen.getByRole("button",{name:"Prepare task for Codex"})).toBeInTheDocument()
})
it("names PowerShell for the saved command on Windows",async()=>{
  vi.spyOn(navigator,"platform","get").mockReturnValue("Win32")
  mocks.prepare.mockResolvedValue({path:"C:/Tasks/support-2",launchCommand:"codex",resumeCommand:"Set-Location x; codex"})
  render(<ModelArchitectureSupport model="hf.co/example/model" />)
  fireEvent.click(screen.getByRole("button",{name:"Implement architecture support with AI"}))
  fireEvent.click(screen.getByRole("button",{name:"Prepare task for Codex"}))
  expect(await screen.findByText(/run the launch command in PowerShell/)).toBeInTheDocument()
  vi.restoreAllMocks()
})
it("cancel leaves the task unprepared",()=>{
  render(<ModelArchitectureSupport model="hf.co/example/model" />)
  fireEvent.click(screen.getByRole("button",{name:"Implement architecture support with AI"}))
  fireEvent.click(screen.getByRole("button",{name:"Cancel"}))
  expect(mocks.prepare).not.toHaveBeenCalled()
  expect(screen.getByRole("button",{name:"Implement architecture support with AI"})).toBeInTheDocument()
})
