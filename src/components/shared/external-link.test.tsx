// @vitest-environment jsdom
import { cleanup, fireEvent, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { workspaceApi } from "@/api/workspace-api"
import { ExternalLink } from "./external-link"

vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn() } }))
afterEach(() => { cleanup(); vi.clearAllMocks() })

it("opens provider web addresses through the validated native command", () => {
  vi.mocked(workspaceApi.openUrl).mockResolvedValue()
  render(<ExternalLink href="https://api.example.test/v1">Model API</ExternalLink>)
  const link = screen.getByRole("link", { name: "Model API" })
  expect(link).not.toHaveProperty("target", "_blank")
  expect(fireEvent.click(link)).toBe(false)
  expect(workspaceApi.openUrl).toHaveBeenCalledExactlyOnceWith("https://api.example.test/v1")
})

it("renders other schemes and embedded credentials as plain text", () => {
  for (const href of ["javascript:alert(1)", "file:///C:/secret.txt", "http://user:pass@example.test/", "not a url"]) {
    const view = render(<ExternalLink href={href}>Address</ExternalLink>)
    expect(screen.queryByRole("link")).toBeNull()
    view.unmount()
  }
})

it("reports a failed open instead of dropping it", async () => {
  vi.mocked(workspaceApi.openUrl).mockRejectedValue(new Error("Only web URLs can be opened"))
  const onError = vi.fn()
  render(<ExternalLink href="http://localhost:8000" onError={onError}>Local</ExternalLink>)
  fireEvent.click(screen.getByRole("link", { name: "Local" }))
  await vi.waitFor(() => expect(onError).toHaveBeenCalledWith("Only web URLs can be opened"))
})
