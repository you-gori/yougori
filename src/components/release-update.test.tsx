// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { StrictMode } from "react"
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { ReleaseUpdateNotice, ReleaseUpdateSettings } from "./release-update"
const { check, remindLater, openDownloads, prepare, install, quit } = vi.hoisted(() => ({ check: vi.fn(), remindLater: vi.fn(), openDownloads: vi.fn(), prepare: vi.fn(), install: vi.fn(), quit: vi.fn() }))
vi.mock("@/api/release-api", () => ({ releaseApi: { check, remindLater, openDownloads, prepare, install, quit } }))
const available = { current: "1.0.1", latest: "1.0.2", channel: "preview", platform: "windows-x86_64", updateAvailable: true, downloadAvailable: true, notes: "Fixes", remindLater: false }
beforeEach(() => {
  vi.resetAllMocks()
  check.mockResolvedValue(available)
  remindLater.mockResolvedValue(undefined)
  openDownloads.mockResolvedValue(undefined)
  prepare.mockResolvedValue({ ready: true, unsigned: true })
  install.mockResolvedValue({ installing: "1.0.2" })
  quit.mockResolvedValue(undefined)
})
afterEach(() => { cleanup(); vi.useRealTimers() })

it("offers the newer release once under StrictMode and asks before installing anything", async () => {
  render(<StrictMode><ReleaseUpdateNotice /></StrictMode>)
  expect(await screen.findByRole("complementary", { name: "Yougori update available" })).toHaveTextContent("Yougori 1.0.2")
  expect(screen.getByText(/Preview release without a publisher signature/)).toBeVisible()
  expect(check).toHaveBeenCalledTimes(1)
  fireEvent.click(screen.getByRole("button", { name: "Update" }))
  expect(await screen.findByRole("button", { name: "Install and restart" })).toBeEnabled()
  expect(prepare).toHaveBeenCalledExactlyOnceWith("1.0.2")
  expect(screen.getByText("Yougori closes, installs 1.0.2 and opens again. Running environments stop first.")).toBeVisible()
  expect(screen.getByText(/no publisher signature yet: Yougori checks the download against the SHA-256 published on yougori.com/)).toBeVisible()
  expect(install).not.toHaveBeenCalled()
  expect(openDownloads).not.toHaveBeenCalled()
  expect(quit).not.toHaveBeenCalled()
})

it("installs in place once confirmed, then quits so the installer runs and opens Yougori again", async () => {
  render(<ReleaseUpdateNotice />)
  fireEvent.click(await screen.findByRole("button", { name: "Update" }))
  fireEvent.click(await screen.findByRole("button", { name: "Install and restart" }))
  expect(await screen.findByText("Yougori is closing to install 1.0.2. It opens again in about a minute.")).toBeVisible()
  expect(install).toHaveBeenCalledExactlyOnceWith("1.0.2")
  await waitFor(() => expect(quit).toHaveBeenCalledTimes(1))
  // A missing call reads NaN, which fails the comparison.
  expect(Number(install.mock.invocationCallOrder[0])).toBeLessThan(Number(quit.mock.invocationCallOrder[0]))
  expect(screen.queryByRole("button")).toBeNull()
})

it("a signed release needs no unsigned warning, and Cancel goes back without installing", async () => {
  prepare.mockResolvedValue({ ready: true, unsigned: false })
  render(<ReleaseUpdateNotice />)
  fireEvent.click(await screen.findByRole("button", { name: "Update" }))
  await screen.findByRole("button", { name: "Install and restart" })
  expect(screen.queryByText(/no publisher signature/)).toBeNull()
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }))
  expect(screen.getByRole("button", { name: "Update" })).toBeEnabled()
  expect(install).not.toHaveBeenCalled()
})

it("a failed download or check keeps Yougori running and offers the installer page", async () => {
  install.mockRejectedValue(new Error("The download does not match the published SHA-256; nothing was installed"))
  render(<ReleaseUpdateNotice />)
  fireEvent.click(await screen.findByRole("button", { name: "Update" }))
  fireEvent.click(await screen.findByRole("button", { name: "Install and restart" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("does not match the published SHA-256")
  expect(quit).not.toHaveBeenCalled()
  expect(screen.getByRole("button", { name: "Install and restart" })).toBeEnabled()
  fireEvent.click(screen.getByRole("button", { name: "Get installer" }))
  await waitFor(() => expect(openDownloads).toHaveBeenCalledTimes(1))
})

it("says the update installs when Yougori quits if quitting failed", async () => {
  quit.mockRejectedValue(new Error("Dashboard window not found"))
  render(<ReleaseUpdateNotice />)
  fireEvent.click(await screen.findByRole("button", { name: "Update" }))
  fireEvent.click(await screen.findByRole("button", { name: "Install and restart" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("Dashboard window not found")
  expect(screen.getByText("Quit Yougori to install 1.0.2; it opens again afterwards.")).toBeVisible()
})

it("sends the person to the installer page when this Yougori cannot update itself", async () => {
  prepare.mockResolvedValue({ ready: false, reason: "This Yougori was installed from the MSI package or by hand, which `yougori update` does not replace." })
  render(<ReleaseUpdateNotice />)
  fireEvent.click(await screen.findByRole("button", { name: "Update" }))
  expect(await screen.findByText(/installed from the MSI package/)).toBeVisible()
  fireEvent.click(screen.getByRole("button", { name: "Get installer" }))
  await waitFor(() => expect(openDownloads).toHaveBeenCalledTimes(1))
  expect(install).not.toHaveBeenCalled()
})

it("defers a release and keeps working even if saving the reminder fails", async () => {
  remindLater.mockRejectedValue(new Error("read only"))
  render(<ReleaseUpdateNotice />)
  fireEvent.click(await screen.findByRole("button", { name: "Later" }))
  expect(screen.queryByRole("complementary")).toBeNull()
  await waitFor(() => expect(remindLater).toHaveBeenCalledExactlyOnceWith("1.0.2"))
  expect(openDownloads).not.toHaveBeenCalled()
})

it.each([
  ["current", { ...available, updateAvailable: false }],
  ["deferred", { ...available, remindLater: true }],
  ["browser preview", null],
])("does not prompt when %s", async (_name, value) => {
  check.mockResolvedValue(value)
  render(<ReleaseUpdateNotice />)
  await act(async () => {})
  expect(screen.queryByRole("complementary")).toBeNull()
})

it("does not display background network errors", async () => {
  check.mockRejectedValue(new Error("offline"))
  render(<ReleaseUpdateNotice />)
  await act(async () => {})
  expect(screen.queryByRole("alert")).toBeNull()
  expect(screen.queryByRole("complementary")).toBeNull()
})

it("rechecks a running app every 12 hours and clears the timer when closed", async () => {
  vi.useFakeTimers()
  check.mockResolvedValueOnce({ ...available, updateAvailable: false }).mockResolvedValue(available)
  const view = render(<ReleaseUpdateNotice />)
  await act(async () => {})
  expect(screen.queryByRole("complementary")).toBeNull()
  await act(async () => { vi.advanceTimersByTime(12 * 60 * 60 * 1000) })
  expect(screen.getByRole("complementary")).toHaveTextContent("1.0.2")
  view.unmount()
  await act(async () => { vi.advanceTimersByTime(24 * 60 * 60 * 1000) })
  expect(check).toHaveBeenCalledTimes(2)
})

it("retries quietly after 15 minutes if the app starts offline", async () => {
  vi.useFakeTimers()
  check.mockRejectedValueOnce(new Error("offline")).mockResolvedValue(available)
  render(<ReleaseUpdateNotice />)
  await act(async () => {})
  expect(screen.queryByRole("complementary")).toBeNull()
  await act(async () => { vi.advanceTimersByTime(15 * 60 * 1000) })
  expect(screen.getByRole("complementary")).toHaveTextContent("1.0.2")
  expect(check).toHaveBeenCalledTimes(2)
})

it("shows an actionable error if the installer page cannot open", async () => {
  prepare.mockResolvedValue({ ready: false, reason: "Get the new version at https://yougori.com/#download." })
  openDownloads.mockRejectedValue(new Error("No browser found. Open https://yougori.com/#download"))
  render(<ReleaseUpdateNotice />)
  fireEvent.click(await screen.findByRole("button", { name: "Update" }))
  fireEvent.click(await screen.findByRole("button", { name: "Get installer" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("No browser found")
  expect(screen.getByRole("button", { name: "Get installer" })).toBeEnabled()
})

it("manual checks bypass reminders and show current, offline and available results", async () => {
  check.mockResolvedValueOnce({ ...available, updateAvailable: false }).mockRejectedValueOnce(new Error("Try again when online")).mockResolvedValueOnce({ ...available, remindLater: true })
  render(<ReleaseUpdateSettings />)
  const button = screen.getByRole("button", { name: "Check for updates" })
  expect(check).not.toHaveBeenCalled()
  fireEvent.click(button)
  expect(await screen.findByRole("status")).toHaveTextContent("1.0.1 is up to date")
  fireEvent.click(button)
  expect(await screen.findByRole("status")).toHaveTextContent("Try again when online")
  fireEvent.click(button)
  expect(await screen.findByRole("button", { name: "Update" })).toBeEnabled()
  expect(check.mock.calls).toEqual([[true], [true], [true]])
})
