// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { ModelGenerate } from "./model-generate"
import type { MediaJob, ModelStatus } from "@/api/projects-api"

const { generate, job, jobs, file, saveJob, folder } = vi.hoisted(() => ({ generate: vi.fn(), job: vi.fn(), jobs: vi.fn(), file: vi.fn(), saveJob: vi.fn(), folder: vi.fn() }))
vi.mock("@/api/projects-api", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/projects-api")>()), modelsApi: { generate, job, jobs, file, saveJob } }))
vi.mock("@/api/model-registry-api", () => ({ registryApi: { folder } }))
afterEach(() => { cleanup(); vi.resetAllMocks() })

const status = (task: string, extra: Partial<ModelStatus> = {}): ModelStatus => ({ status: "ready", model: "owner/model", error: null, task, gpu: "RTX", pipeline: "FakePipeline", queue: { waiting: 0, running: 0, limit: 16 }, outputs: { keptHours: 24, capGb: 20, bytes: 0, jobs: 0 }, ...extra })
const done = (id: string, files: MediaJob["output"]): MediaJob => ({ id, object: "job", status: "succeeded", task: "text-to-image", model: "owner/model", created: 1, started: 1, finished: 2, progress: 1, input: { prompt: "a red bicycle" }, error: null, output: files, usage: { images: 1, compute_seconds: 2.5 }, expires: 9 })

it("submits an image job from the form and shows its files once it ends", async () => {
  jobs.mockResolvedValueOnce({ data: [] })
  generate.mockResolvedValue({ id: "job_1", status: "queued" })
  const finished = done("job_" + "a".repeat(24), { files: [{ name: "image-1.png", file: "job_" + "a".repeat(24) + ".1", url: "/v1/files/x", content_type: "image/png", bytes: 10, width: 512, height: 512 }], seed: 7 })
  jobs.mockResolvedValue({ data: [finished] })
  file.mockResolvedValue({ fileId: finished.output!.files![0]!.file, contentType: "image/png", bytes: 10, base64: "AAAA" })
  render(<ModelGenerate environmentId="model-one" status={status("text-to-image")} />)
  expect(await screen.findByText(/No jobs yet/)).toBeInTheDocument()
  fireEvent.change(screen.getByLabelText("Prompt"), { target: { value: "a red bicycle" } })
  fireEvent.change(screen.getByLabelText("Images"), { target: { value: "2" } })
  fireEvent.change(screen.getByLabelText("Size"), { target: { value: "512x512" } })
  fireEvent.change(screen.getByLabelText("Seed"), { target: { value: "7" } })
  fireEvent.click(screen.getByRole("button", { name: "Generate" }))
  await waitFor(() => expect(generate).toHaveBeenCalledWith("model-one", { prompt: "a red bicycle", count: 2, width: 512, height: 512, seed: 7 }))
  expect(await screen.findByText("Done")).toBeInTheDocument()
  const image = await screen.findByRole("img", { name: /image-1.png 512×512/ })
  expect(image).toHaveAttribute("src", "data:image/png;base64,AAAA")
  expect(screen.getByText(/1 image · 2.5 s on the GPU · seed 7/)).toBeInTheDocument()
  folder.mockResolvedValue("D:/outputs")
  saveJob.mockResolvedValue({ jobId: finished.id, folder: "D:/outputs", files: [] })
  fireEvent.click(screen.getByRole("button", { name: "Save to folder" }))
  await waitFor(() => expect(saveJob).toHaveBeenCalledWith("model-one", finished.id, "D:/outputs"))
  expect(await screen.findByText("Saved in D:/outputs")).toBeInTheDocument()
})

it("follows a running job and can stop it; speech and video forms ask for their own inputs", async () => {
  const running: MediaJob = { ...done("job_" + "b".repeat(24), null), status: "running", progress: 0.4, finished: null, usage: null }
  jobs.mockResolvedValue({ data: [running] })
  job.mockResolvedValue({ ...running, status: "cancelled" })
  render(<ModelGenerate environmentId="model-one" status={status("text-to-video", { queue: { waiting: 1, running: 1, limit: 16 } })} />)
  expect(await screen.findByText("Generating 40%")).toBeInTheDocument()
  expect(screen.getByLabelText("Seconds")).toHaveValue(2)
  expect(screen.getByLabelText("Frames per second")).toBeInTheDocument()
  expect(screen.getByText(/1 waiting · 1 generating · files kept 24 h/)).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Stop" }))
  await waitFor(() => expect(job).toHaveBeenCalledWith("model-one", running.id, "cancel"))
  cleanup()
  jobs.mockResolvedValue({ data: [] })
  render(<ModelGenerate environmentId="model-one" status={status("text-to-speech")} />)
  fireEvent.change(await screen.findByLabelText("Text"), { target: { value: "Hello there" } })
  fireEvent.change(screen.getByLabelText("Voice (optional)"), { target: { value: "v2/en_speaker_6" } })
  expect(screen.queryByLabelText("Size")).not.toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Generate" }))
  await waitFor(() => expect(generate).toHaveBeenCalledWith("model-one", { text: "Hello there", voice: "v2/en_speaker_6" }))
})

it("waits for an input image before an image-to-video job and for the model before any", async () => {
  jobs.mockResolvedValue({ data: [] })
  render(<ModelGenerate environmentId="model-one" status={status("image-to-video")} />)
  expect(await screen.findByLabelText("Input image")).toBeInTheDocument()
  fireEvent.click(screen.getByRole("button", { name: "Generate" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Choose the input image first.")
  expect(generate).not.toHaveBeenCalled()
  cleanup()
  jobs.mockClear()
  render(<ModelGenerate environmentId="model-one" status={status("text-to-image", { status: "downloading", download: { receivedBytes: 1, totalBytes: 2, bytesPerSecond: 1, transport: "xet" } })} />)
  expect(screen.getByRole("button", { name: "Generate" })).toBeDisabled()
  expect(screen.getByText(/Jobs appear here once the model is ready/)).toBeInTheDocument()
  expect(jobs).not.toHaveBeenCalled()
})
