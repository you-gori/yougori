// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { GuestFiles } from "./guest-files"

const files = vi.hoisted(() => ({ list: vi.fn(), remove: vi.fn(), read: vi.fn(), create: vi.fn(), write: vi.fn() }))
vi.mock("@/api/guest-files-api", async importOriginal => ({ ...await importOriginal<typeof import("@/api/guest-files-api")>(), guestFilesApi: files }))
vi.mock("@/api/file-import-api", () => ({ fileImportApi: { copy: vi.fn() } }))
vi.mock("@/api/file-export-api", () => ({ fileExportApi: { chooseDestination: vi.fn(), copy: vi.fn(), between: vi.fn() } }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { environments: [] } }) }))
afterEach(() => { cleanup(); vi.resetAllMocks() })

it("acts on the listed folder, not on a folder path that was typed but never opened", async () => {
  files.list.mockImplementation(async (_: string, path: string) => ({ path: path === "." ? "/app" : path, entries: [{ name: "config.json", directory: false }] }))
  files.remove.mockResolvedValue(undefined)
  render(<GuestFiles environmentId="env-test" active />)
  expect(await screen.findByRole("button", { name: "Delete config.json" })).toBeEnabled()
  fireEvent.change(screen.getByLabelText("Folder path"), { target: { value: "/data" } })
  fireEvent.click(screen.getByRole("button", { name: "Delete config.json" }))
  await waitFor(() => expect(files.remove).toHaveBeenCalledWith("env-test", "/app/config.json", false))
  expect(files.list).toHaveBeenLastCalledWith("env-test", "/app")
  fireEvent.keyDown(screen.getByLabelText("Folder path"), { key: "Enter" })
  await waitFor(() => expect(files.list).toHaveBeenLastCalledWith("env-test", "/data"))
})
