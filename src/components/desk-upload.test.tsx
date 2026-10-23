// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { DeskUpload } from "./desk-upload"
import { remoteAccessApi } from "@/api/remote-access-api"
vi.mock("@/api/remote-access-api", () => ({ remoteAccessApi: { upload: vi.fn() } }))
afterEach(() => { cleanup(); vi.resetAllMocks() })
it("uses only the inbound upload API, including for empty files", async () => {
  vi.mocked(remoteAccessApi.upload).mockResolvedValue({ uploadId: "upload-test" })
  render(<DeskUpload environmentId="env-desk" />)
  fireEvent.change(screen.getByLabelText("Upload into workspace", { selector: "input" }), { target: { files: [new File([], "empty.txt")] } })
  await waitFor(() => expect(remoteAccessApi.upload).toHaveBeenCalledWith("env-desk", { action: "finish", uploadId: "upload-test" }))
  expect(screen.queryByRole("button", { name: /download/i })).not.toBeInTheDocument()
  expect(await screen.findByText(/Files added/)).toBeInTheDocument()
})
it("does not report success if the host refuses delivery", async () => {
  vi.mocked(remoteAccessApi.upload).mockImplementation(async (_id, request) => { if (request.action === "finish") throw new Error("Assignment revoked"); return { uploadId: "upload-test" } })
  render(<DeskUpload environmentId="env-desk" />)
  fireEvent.change(screen.getByLabelText("Upload into workspace", { selector: "input" }), { target: { files: [new File([], "empty.txt")] } })
  expect(await screen.findByRole("alert")).toHaveTextContent("Assignment revoked")
  expect(screen.queryByText(/Files added/)).not.toBeInTheDocument()
  await waitFor(() => expect(remoteAccessApi.upload).toHaveBeenCalledWith("env-desk", { action: "cancel", uploadId: "upload-test" }))
})

it("preserves nested folder paths in an inbound batch", async () => {
  vi.mocked(remoteAccessApi.upload).mockResolvedValue({ uploadId: "folder-test" })
  const file = new File([], "notes.txt")
  Object.defineProperty(file, "webkitRelativePath", { value: "research/experiment/notes.txt" })
  render(<DeskUpload environmentId="env-desk" />)
  fireEvent.change(screen.getByLabelText("Upload folder into workspace"), { target: { files: [file] } })
  await waitFor(() => expect(remoteAccessApi.upload).toHaveBeenCalledWith("env-desk", { action: "begin", files: [{ path: "research/experiment/notes.txt", size: 0 }] }))
  await waitFor(() => expect(remoteAccessApi.upload).toHaveBeenCalledWith("env-desk", { action: "finish", uploadId: "folder-test" }))
})
