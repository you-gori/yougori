// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { HuggingfaceAccess } from "./huggingface-access"
const api = vi.hoisted(() => ({ huggingface: vi.fn(async () => ({ configured: false })), saveHuggingfaceToken: vi.fn(), forgetHuggingfaceToken: vi.fn() }))
vi.mock("@/api/projects-api", () => ({ modelsApi: api }))
afterEach(() => { cleanup(); vi.clearAllMocks(); localStorage.clear() })
it("masks a read token, saves it through protected IPC and clears the input", async () => {
  render(<HuggingfaceAccess />)
  const field = screen.getByLabelText("Read token")
  expect(field).toHaveAttribute("type", "password")
  fireEvent.change(field, { target: { value: "hf_test_read_secret" } })
  fireEvent.click(screen.getByRole("button", { name: "Save token", hidden: true }))
  await waitFor(() => expect(api.saveHuggingfaceToken).toHaveBeenCalledExactlyOnceWith("hf_test_read_secret"))
  expect(field).toHaveValue("")
  expect(localStorage.length).toBe(0)
  expect(await screen.findByText(/Read token saved/)).toBeInTheDocument()
})
