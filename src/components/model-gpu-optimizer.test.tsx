// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ModelGpuOptimizer } from "./model-gpu-optimizer"
const { optimizer, status } = vi.hoisted(() => ({ optimizer: vi.fn(), status: vi.fn() }))
vi.mock("@/api/projects-api", () => ({ modelsApi: { optimizer, status } }))
beforeEach(() => { vi.stubGlobal("PointerEvent", MouseEvent) })
afterEach(() => { cleanup(); vi.resetAllMocks(); vi.unstubAllGlobals() })
const settings = { supported:true,enabled:true,pinned:false,resident:false,loading:false,active:0,pending:2,idleTimeoutSeconds:120,allocatedBytes:0 }
// The panel reads the whole model status (the optimizer beside the context and the runner's facts).
const health = (optimizerValue: object, rest: object = {}) => ({ status: "idle", model: "acme/model", error: null, optimizer: optimizerValue, ...rest })
it("shows on-demand state and saves pinning without stopping the environment", async () => {
  status.mockResolvedValue(health(settings)); optimizer.mockResolvedValue(settings)
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByText(/On demand.*2 waiting/)).toBeVisible()
  fireEvent.click(screen.getByRole("switch", { name:"Prevent automatic model switching" }))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{pinned:true}))
  fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value:"30"}})
  fireEvent.click(screen.getByRole("button",{name:"Save"}))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{idleTimeoutSeconds:30}))
})
it("saves keep-loaded mode and rejects invalid idle timeouts", async () => {
  status.mockResolvedValue(health(settings)); optimizer.mockResolvedValue(settings)
  render(<ModelGpuOptimizer environmentId="env-one" />)
  await screen.findByLabelText("Unload after idle seconds")
  fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value:"0"}})
  fireEvent.click(screen.getByRole("button",{name:"Save"}))
  await waitFor(() => expect(optimizer).toHaveBeenCalledWith("env-one",{idleTimeoutSeconds:0}))
  await waitFor(() => expect(screen.getByRole("button",{name:"Save"})).toBeEnabled())
  for (const value of ["", "-1", "1", "9", "3601", "10.5"]) {
    fireEvent.change(screen.getByLabelText("Unload after idle seconds"),{target:{value}})
    expect(screen.getByRole("button",{name:"Save"})).toBeDisabled()
  }
})
it("explains residency until the next requested model", async () => {
  status.mockResolvedValue(health({...settings,idleTimeoutSeconds:0}))
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByText(/current model stays loaded until another model needs the GPU/)).toBeVisible()
})
it("shows uncertain memory release instead of Ready and clears it after recovery", async () => {
  status.mockResolvedValue(health({ ...settings, resident: true, releaseUncertain: true }))
  optimizer.mockResolvedValue({ ...settings, resident: true, releaseUncertain: false })
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByRole("status")).toHaveTextContent("Memory release unconfirmed")
  expect(screen.getByRole("status")).not.toHaveTextContent("Ready")
  expect(screen.getByRole("alert")).toHaveTextContent("Restart this model environment")
  fireEvent.click(screen.getByRole("switch", { name: "Prevent automatic model switching" }))
  await waitFor(() => expect(screen.getByRole("status")).toHaveTextContent("Ready"))
  expect(screen.queryByRole("alert")).not.toBeInTheDocument()
})
it("keeps the ready status for older runners without the optional release flag", async () => {
  status.mockResolvedValue(health({ ...settings, resident: true }))
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByRole("status")).toHaveTextContent("Ready")
  expect(screen.queryByRole("alert")).not.toBeInTheDocument()
  // Without a grant the panel says so, and an older runner reports no capability facts.
  expect(screen.getByLabelText("GPU memory limits")).toHaveTextContent("One resident model at a time; no shared GPU grant for this model.")
  expect(screen.queryByLabelText("Runner capabilities")).not.toBeInTheDocument()
})
it("shows the shared GPU grant, its covered context, the runner's peak and what the runner does not support", async () => {
  status.mockResolvedValue(health(
    { ...settings, resident: true, allocatedBytes: 1_073_741_824, peakAllocatedBytes: 15_032_385_536, reservedBytes: 16_106_127_360, capacityBytes: 22_583_493_552, capacityContext: 9728 },
    { context: 9728, capabilities: {
      kvGrowth: { supported: false, detail: "The Transformers runner's cache grows per generated token inside its grant (the grant covers 9728 tokens); it is not mapped in increments the host ledger could reclaim." },
      adapters: { supported: false, detail: "The Transformers runner loads no unmerged adapters (LoRA); only the checkpoint's own weights are served." },
    } }))
  render(<ModelGpuOptimizer environmentId="env-one" />)
  const limits = await screen.findByLabelText("GPU memory limits")
  expect(limits).toHaveTextContent("Shared GPU grant of 21.0 GB, covering 9,728 tokens of context. The runner holds its allocator to the grant and refuses a longer conversation.")
  expect(limits).toHaveTextContent("Context window9,728 tokens")
  expect(limits).toHaveTextContent("1.0 GB allocated · peak 14.0 GB since the last unload · 15.0 GB reserved by the allocator")
  const capabilities = screen.getByLabelText("Runner capabilities")
  expect(capabilities).toHaveTextContent("KV growth in increments: not supported by this runner · The Transformers runner's cache grows per generated token")
  expect(capabilities).toHaveTextContent("Unmerged adapters (LoRA): not supported by this runner · The Transformers runner loads no unmerged adapters")
})
it("says why the model waits for the GPU while it waits", async () => {
  const reason = "Qwen2.5-0.5B-Instruct-2 is using the GPU. This model loads once it is free."
  status.mockResolvedValue(health({ ...settings, pending: 1, waitingFor: reason }))
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByLabelText("Why this model waits for the GPU")).toHaveTextContent(`Waiting for GPU · ${reason}`)
})
it("names the grant the engine reserves for a GGUF or vLLM model, which its runner does not report", async () => {
  status.mockResolvedValue(health({ ...settings, resident: true }, { admission: { profile: "local-single-llama-cpp-v1", bytes: 1424976384 } }))
  render(<ModelGpuOptimizer environmentId="env-one" />)
  expect(await screen.findByLabelText("GPU memory limits")).toHaveTextContent("Shared GPU grant of 1.3 GB: the model's weights, the KV cache of its context and llama.cpp's buffers")
  cleanup()
  status.mockResolvedValue(health({ ...settings, resident: true }, { admission: { profile: "local-single-vllm-v1", bytes: 4294967296 } }))
  render(<ModelGpuOptimizer environmentId="env-two" />)
  expect(await screen.findByLabelText("GPU memory limits")).toHaveTextContent("vLLM's GPU grant: at least 90% of the GPU")
})
it("names KV reuse and a launch's adapters as the runner reports them", async () => {
  status.mockResolvedValue(health({ ...settings, resident: true }, { capabilities: {
    adapters: { supported: true, detail: "LoRA adapters attach at runtime: 2 slot(s), rank up to 16; a request names one as its model; attached: fin." },
    kvReuse: { supported: true, detail: "vLLM reuses the KV of a shared prompt prefix, keyed by adapter." } } }))
  render(<ModelGpuOptimizer environmentId="env-three" />)
  const facts = await screen.findByLabelText("Runner capabilities")
  expect(facts).toHaveTextContent("KV reuse across requests: supported")
  expect(facts).toHaveTextContent("Unmerged adapters (LoRA): supported · LoRA adapters attach at runtime: 2 slot(s)")
})
