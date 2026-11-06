// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
vi.mock("./overview-page", () => ({ OverviewPage: () => <h1>My computer</h1> }))
vi.mock("./hub-page", () => ({ HubPage: () => <p>Community templates and tools</p> }))
vi.mock("@/components/setups/setup-detail", () => ({ SetupDetailView: () => <p>Selected setup</p> }))
import { WorkspacePage } from "./workspace-page"
afterEach(cleanup)
it("keeps the computer workspace mounted while Hub opens and closes in a popup", async () => {
  const props = { highlight: null, onClosePopup: vi.fn(), onOpenEnvironment: vi.fn(), onSelectEnvironment: vi.fn() }
  const view = render(<WorkspacePage {...props} page="sandboxes" />)
  expect(screen.getByRole("heading", { name: "My computer" })).toBeVisible()
  expect(screen.queryByRole("dialog")).toBeNull()
  view.rerender(<WorkspacePage {...props} page="hub" />)
  expect(await screen.findByText("Community templates and tools")).toBeVisible()
  expect(screen.getByRole("dialog", { name: "Hub" })).toBeVisible()
  expect(screen.getByText("My computer")).toBeInTheDocument()
  view.rerender(<WorkspacePage {...props} page="sandboxes" />)
  expect(screen.queryByRole("dialog")).toBeNull()
  expect(screen.getByRole("heading", { name: "My computer" })).toBeVisible()
})
