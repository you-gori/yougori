// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { DesksPage } from "./desks-page"
import type { DesksStatus } from "@/api/desks-api"

let status: DesksStatus | null = null
vi.mock("@/components/use-workspace-actions", () => ({
  useWorkspaceActions: () => ({ desks: status, desksError: null, refreshDesks: vi.fn(), openDesksHost: vi.fn(), openDesksJoin: vi.fn(), openDeskLogin: vi.fn() }),
}))
vi.mock("@/components/sandbox-grid-admin", () => ({ SandboxGridAdmin: () => null }))
vi.mock("@/components/desk-portal", () => ({ DeskPortal: () => null }))

afterEach(() => { cleanup(); status = null })

const base: DesksStatus = { hub: null, hubError: null, member: null, memberError: null, hosting: [], desk: null }

it("keeps the cloud computers a deleted grid created in sight until they are removed", () => {
  status = { ...base, cloudFallback: { computers: 1, error: "Cloud computer yougori-desk-1 could not be deleted: aws CLI: expired token. It may still cost money; delete it in Cloud deployments.", note: "This sandbox grid was deleted, so the cloud computer it created is being removed.", retryAfter: null, held: false } }
  render(<DesksPage />)
  expect(screen.getByRole("alert")).toHaveTextContent("yougori-desk-1 could not be deleted")
  expect(screen.getByRole("status")).toHaveTextContent("the cloud computer it created is being removed")
  expect(screen.queryByText("Host or join a sandbox grid")).toBeNull()
})

it("shows nothing about cloud computers when there is nothing to tell", () => {
  status = { ...base, cloudFallback: { computers: 0, error: null, note: null, retryAfter: null, held: false } }
  render(<DesksPage />)
  expect(screen.queryByRole("alert")).toBeNull()
  expect(screen.getByText("Host or join a sandbox grid")).toBeInTheDocument()
})
