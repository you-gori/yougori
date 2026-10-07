// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { ModelArchitectureSupport } from "./model-architecture-support"
const mocks=vi.hoisted(()=>({prepare:vi.fn(),info:vi.fn(),terminal:vi.fn(),copy:vi.fn()}))
vi.mock("@/api/projects-api",()=>({modelsApi:{supportTask:mocks.prepare}}))
vi.mock("@/api/host-terminal-api",()=>({hostTerminalApi:{info:mocks.info,terminal:mocks.terminal}}))
vi.mock("@/lib/terminal-clipboard",()=>({terminalClipboard:{writeText:mocks.copy}}))
vi.mock("@/components/host-terminal-canvas",()=>({HostTerminalCanvas:({tab}:{tab:{cwd:string;command:string}})=><div data-testid="agent-terminal">{tab.cwd} {tab.command}</div>}))
afterEach(()=>{cleanup();vi.resetAllMocks()})
it("requires a deliberate agent choice and starts in its isolated task folder",async()=>{
  mocks.info.mockResolvedValue({elevated:false,sessions:[],maxSessions:4})
  mocks.prepare.mockResolvedValue({path:"C:/Tasks/support-1",launchCommand:"kilo --prompt safe",resumeCommand:"safe resume"})
  mocks.terminal.mockResolvedValue({})
  render(<ModelArchitectureSupport model="hf.co/example/model" active />)
  expect(mocks.prepare).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button",{name:"Implement architecture support with AI"}))
  expect(screen.getAllByRole("option")).toHaveLength(5)
  fireEvent.change(screen.getByLabelText("Coding agent"),{target:{value:"kilo"}})
  fireEvent.click(screen.getByRole("button",{name:"Start Kilo Code"}))
  await waitFor(()=>expect(mocks.prepare).toHaveBeenCalledWith("hf.co/example/model","kilo",undefined))
  expect(await screen.findByTestId("agent-terminal")).toHaveTextContent("C:/Tasks/support-1 kilo --prompt safe")
  fireEvent.click(screen.getByRole("button",{name:"Stop coding agent"}))
  await waitFor(()=>expect(mocks.terminal).toHaveBeenCalledWith({action:"close",sessionId:expect.stringContaining("host-edit-architecture-")}))
})
it("cancel and an elevated terminal leave the task and agent unstarted",async()=>{
  mocks.info.mockResolvedValue({elevated:true,sessions:[],maxSessions:4})
  render(<ModelArchitectureSupport model="hf.co/example/model" active />)
  fireEvent.click(screen.getByRole("button",{name:"Implement architecture support with AI"}))
  fireEvent.click(screen.getByRole("button",{name:"Cancel"}))
  expect(mocks.prepare).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button",{name:"Implement architecture support with AI"}))
  fireEvent.click(screen.getByRole("button",{name:"Start Codex"}))
  expect(await screen.findByRole("alert")).toHaveTextContent("Reopen Yougori normally")
  expect(mocks.prepare).not.toHaveBeenCalled()
})
