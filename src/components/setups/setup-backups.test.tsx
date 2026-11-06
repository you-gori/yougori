// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { act, cleanup, render, screen, waitFor, within } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import type { BackupList, BackupVolume, RestoreReview } from "@/api/setups/backups"

const api = vi.hoisted(() => ({ list: vi.fn(), check: vi.fn(), reviewRestore: vi.fn(), restore: vi.fn(), backUpNow: vi.fn() }))
const feed = vi.hoisted(() => ({ refresh: vi.fn(() => Promise.resolve()) }))
vi.mock("@/api/setups/backups", async importOriginal => ({ ...(await importOriginal<typeof import("@/api/setups/backups")>()), backupsApi: api }))
vi.mock("@/api/setups/progress", () => ({ setupFeed: feed }))

import { SetupCommandError, SetupUnavailableError } from "@/api/setups/setups-api"
import { SetupBackups } from "./setup-backups"

const LIMITS = "A backup holds what is in the volume and nothing else."
const NEWER = { id: "backup-2", at: 2, when: "2026-10-26 02:00", files: 12, bytes: 4096, consistency: "stop" as const, describe: "2026-10-26 02:00 — 12 files, 4 KB, taken with its sandboxes stopped" }
const OLDER = { id: "backup-1", at: 1, when: "2026-10-25 02:00", files: 11, bytes: 4000, consistency: "live" as const, describe: "2026-10-25 02:00 — 11 files, 4 KB, taken while everything kept running" }

const listed = (over: Partial<BackupVolume> = {}): BackupList => ({
  setupId: "acme",
  volumes: [{
    resource: "data", through: "backup", schedule: "every day at 02:00, this computer's time zone", keep: 7,
    consistency: "stop", consistencyWords: "Before each backup the sandboxes that write to data are stopped.", paused: false,
    nextWhen: "2026-10-27 02:00", lastOutcome: "done", lastDetail: "", lastWhen: "2026-10-26 02:00", lastFinishedAt: 1_761_444_000, backups: [NEWER, OLDER],
    ...over,
  }],
  limits: LIMITS,
})

const reviewOf = (overwrites: boolean): RestoreReview => ({
  setupId: "acme", resource: "data", backupId: "backup-2", overwrites,
  review: overwrites
    ? ["The backup from 2026-10-26 02:00 holds 12 files, 4 KB.", "Everything now on data is replaced by what this backup holds. Anything written to it since 2026-10-26 02:00 is gone, and this cannot be undone.", LIMITS]
    : ["The backup from 2026-10-26 02:00 holds 12 files, 4 KB.", "The files are put in a new folder inside backup, which nothing uses yet. data itself is not changed.", LIMITS],
  confirm: overwrites ? "restore-original" : "restore-copy",
})

beforeEach(() => {
  api.list.mockResolvedValue(listed())
  api.reviewRestore.mockImplementation(async (_setup: string, _volume: string, _backup: string, overOriginal: boolean) => reviewOf(overOriginal))
})

afterEach(() => {
  cleanup()
  for (const call of Object.values(api)) call.mockReset()
  feed.refresh.mockClear()
})

/** Opens the restore of the newer copy and waits for its review. */
async function openRestore(user: ReturnType<typeof userEvent.setup>) {
  await user.click(await screen.findByRole("button", { name: "Restore the backup from 2026-10-26 02:00" }))
  const panel = await screen.findByRole("region", { name: "Restore data from the backup of 2026-10-26 02:00" })
  await within(panel).findByRole("list", { name: "Before you restore it" })
  return panel
}

it("lists each volume's times, its last run and every copy kept, in the CLI's words, and changes nothing", async () => {
  render(<SetupBackups setupId="acme" name="Acme" />)
  const copies = await screen.findByRole("list", { name: "Backups kept of data" })
  expect(api.list).toHaveBeenCalledWith("acme")
  expect(within(copies).getAllByRole("listitem")).toHaveLength(2)
  expect(within(copies).getByText(NEWER.describe)).toBeInTheDocument()
  expect(within(copies).getByText(OLDER.describe)).toBeInTheDocument()
  expect(screen.getByText("Every day at 02:00, this computer's time zone, keeping the newest 7.")).toBeInTheDocument()
  expect(screen.getByText("2026-10-27 02:00")).toBeInTheDocument()
  expect(screen.getByText("Done at 2026-10-26 02:00")).toBeInTheDocument()
  expect(screen.getByText("Before each backup the sandboxes that write to data are stopped.")).toBeInTheDocument()
  expect(screen.getByText(LIMITS)).toBeInTheDocument()
  expect(api.check).not.toHaveBeenCalled()
  expect(api.reviewRestore).not.toHaveBeenCalled()
  expect(api.restore).not.toHaveBeenCalled()
})

it("says when backups are paused or none is kept yet, and when a setup backs nothing up", async () => {
  api.list.mockResolvedValueOnce(listed({ paused: true, keep: 1, lastOutcome: "never_run", lastWhen: null, backups: [] }))
  render(<SetupBackups setupId="acme" name="Acme" />)
  expect(await screen.findByText("Paused while the setup is stopped. Starting the setup resumes it.")).toBeInTheDocument()
  expect(screen.getByText("Every day at 02:00, this computer's time zone, keeping only the newest copy.")).toBeInTheDocument()
  expect(screen.getByText("None yet")).toBeInTheDocument()
  expect(screen.getByText("Nothing kept yet.")).toBeInTheDocument()
  cleanup()

  api.list.mockResolvedValueOnce({ setupId: "acme", volumes: [], limits: LIMITS })
  render(<SetupBackups setupId="acme" name="Acme" />)
  expect(await screen.findByText("This setup backs nothing up. A template gives a volume a schedule; this one gave none.")).toBeInTheDocument()
  expect(screen.queryByText(LIMITS)).toBeNull()
})

it("checks a copy without changing anything, and says why a copy can't be used", async () => {
  api.check.mockResolvedValueOnce({ resource: "data", backupId: "backup-1", files: 11, bytes: 4000, when: "2026-10-25 02:00", consistency: "live", note: "" })
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  await user.click(await screen.findByRole("button", { name: "Check the backup from 2026-10-25 02:00" }))
  expect(api.check).toHaveBeenCalledWith("acme", "data", "backup-1")
  expect(await screen.findByText("This backup is complete and unchanged: 11 files, taken 2026-10-25 02:00.")).toBeInTheDocument()
  expect(screen.getByText("It was taken while everything kept running, so a file being written then may be half-written.")).toBeInTheDocument()
  expect(screen.getByText("Nothing was changed.")).toBeInTheDocument()

  api.check.mockRejectedValueOnce(new SetupCommandError("This backup's files have changed since it was made, so Yougori won't restore from it. Choose another backup.", { code: "backup_unusable" }))
  await user.click(screen.getByRole("button", { name: "Check the backup from 2026-10-26 02:00" }))
  expect(await screen.findByRole("alert")).toHaveTextContent("This backup's files have changed since it was made, so Yougori won't restore from it.")
  expect(screen.getAllByText("Nothing was changed.")).toHaveLength(2)
  expect(api.reviewRestore).not.toHaveBeenCalled()
  expect(api.restore).not.toHaveBeenCalled()
})

it("restores into a new folder by default, and only once its review has been read", async () => {
  api.restore.mockResolvedValueOnce({ restoredTo: "copy", folder: "/tmp/yougori-restore-x/files", next: "The files are in /tmp/yougori-restore-x/files inside backup. data is unchanged. Copy across what you need, then delete that folder." })
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  const panel = await openRestore(user)
  expect(api.reviewRestore).toHaveBeenCalledWith("acme", "data", "backup-2", false)
  expect(within(panel).getByText(/^Restoring data of Acme from the backup/)).toHaveTextContent("Restoring data of Acme from the backup backup-2.")
  expect(within(panel).getByRole("radio", { name: /^Into a new folder inside backup\. data itself is not touched\. Practise with this\./ })).toBeChecked()
  expect(within(panel).getByRole("radio", { name: /^Over data itself\./ })).not.toBeChecked()

  // The review is read before the button that acts on it, and nothing is restored by reading it.
  const notes = within(panel).getByRole("list", { name: "Before you restore it" })
  expect(notes).toHaveTextContent("The files are put in a new folder inside backup")
  const go = within(panel).getByRole("button", { name: "Put the files in a new folder" })
  expect(notes.compareDocumentPosition(go) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  expect(within(panel).queryByRole("button", { name: /Replace everything/ })).toBeNull()
  expect(api.restore).not.toHaveBeenCalled()

  await user.click(go)
  expect(api.restore).toHaveBeenCalledTimes(1)
  expect(api.restore).toHaveBeenCalledWith(reviewOf(false))
  expect(await screen.findByText(/^The files are in \/tmp\/yougori-restore-x\/files inside backup\./)).toBeInTheDocument()
  expect(screen.queryByRole("region", { name: /^Restore data/ })).toBeNull()
  await waitFor(() => expect(api.list).toHaveBeenCalledTimes(2))
  expect(feed.refresh).toHaveBeenCalledWith("acme")
  await waitFor(() => expect(screen.getByRole("button", { name: "Restore the backup from 2026-10-26 02:00" })).toHaveFocus())
})

it("replaces what is on the volume only when that is chosen by name, after its own review", async () => {
  api.restore.mockResolvedValueOnce({ restoredTo: "original", folder: null, next: "data now holds what the backup from 2026-10-26 02:00 held. The setup's sandboxes are running again." })
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  const panel = await openRestore(user)
  await user.click(within(panel).getByRole("radio", { name: /^Over data itself\./ }))
  expect(api.reviewRestore).toHaveBeenLastCalledWith("acme", "data", "backup-2", true)
  const replace = await within(panel).findByRole("button", { name: "Replace everything on data" })
  expect(within(panel).queryByRole("button", { name: "Put the files in a new folder" })).toBeNull()
  expect(within(panel).getByRole("list", { name: "Before you restore it" })).toHaveTextContent("this cannot be undone")
  expect(api.restore).not.toHaveBeenCalled()

  await user.click(replace)
  expect(api.restore).toHaveBeenCalledTimes(1)
  expect(api.restore).toHaveBeenCalledWith(reviewOf(true))
  expect(await screen.findByText(/^data now holds what the backup from 2026-10-26 02:00 held\./)).toBeInTheDocument()
})

it("never shows the review of a choice the person has since changed", async () => {
  let answerCopy: (review: RestoreReview) => void = () => undefined
  api.reviewRestore.mockReset()
  api.reviewRestore
    .mockImplementationOnce(() => new Promise<RestoreReview>(resolve => { answerCopy = resolve }))
    .mockImplementationOnce(async () => reviewOf(true))
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  await user.click(await screen.findByRole("button", { name: "Restore the backup from 2026-10-26 02:00" }))
  const panel = await screen.findByRole("region", { name: "Restore data from the backup of 2026-10-26 02:00" })
  expect(within(panel).getByRole("status")).toHaveTextContent("Working out what would be restored…")
  await user.click(within(panel).getByRole("radio", { name: /^Over data itself\./ }))
  await within(panel).findByRole("button", { name: "Replace everything on data" })

  // The first answer, for a new folder, arrives late: it is not the choice on screen any more.
  await act(async () => { answerCopy(reviewOf(false)) })
  expect(within(panel).queryByRole("button", { name: "Put the files in a new folder" })).toBeNull()
  expect(within(panel).getByRole("button", { name: "Replace everything on data" })).toBeInTheDocument()
  expect(within(panel).getByRole("radio", { name: /^Over data itself\./ })).toBeChecked()
})

it("leaves everything as it was on Not now, and puts focus back on Restore", async () => {
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  const panel = await openRestore(user)
  await user.click(within(panel).getByRole("button", { name: "Not now" }))
  expect(screen.queryByRole("region", { name: /^Restore data/ })).toBeNull()
  await waitFor(() => expect(screen.getByRole("button", { name: "Restore the backup from 2026-10-26 02:00" })).toHaveFocus())
  expect(api.restore).not.toHaveBeenCalled()
})

it("says plainly when the engine refuses, keeps the review, and puts nothing back", async () => {
  api.restore.mockRejectedValueOnce(new SetupCommandError("Another change is running.", { code: "setup_busy", retryable: true }))
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  const panel = await openRestore(user)
  await user.click(within(panel).getByRole("button", { name: "Put the files in a new folder" }))
  expect(await within(panel).findByRole("alert")).toHaveTextContent("Another change to this setup is still running, so nothing was put back.")
  expect(within(panel).getByRole("button", { name: "Put the files in a new folder" })).toBeEnabled()
  expect(feed.refresh).not.toHaveBeenCalled()
})

it("reads the review again when a confirmation no longer matches it", async () => {
  api.restore.mockRejectedValueOnce(new SetupCommandError("That confirmation was for a different restore.", { code: "confirmation_stale" }))
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  const panel = await openRestore(user)
  await user.click(within(panel).getByRole("button", { name: "Put the files in a new folder" }))
  expect(await within(panel).findByRole("alert")).toHaveTextContent("That confirmation was for a different restore, so nothing was put back.")
  await waitFor(() => expect(api.reviewRestore).toHaveBeenCalledTimes(2))
  expect(api.reviewRestore).toHaveBeenLastCalledWith("acme", "data", "backup-2", false)
  expect(await within(panel).findByRole("button", { name: "Put the files in a new folder" })).toBeInTheDocument()
  expect(api.restore).toHaveBeenCalledTimes(1)
})

it("says so when the copy being restored is no longer kept", async () => {
  api.list.mockReset()
  api.list.mockResolvedValueOnce(listed()).mockResolvedValue(listed({ backups: [OLDER] }))
  api.restore.mockRejectedValueOnce(new SetupCommandError("That backup is not one Yougori kept. Choose one from the list.", { code: "backup_not_found" }))
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  const panel = await openRestore(user)
  await user.click(within(panel).getByRole("button", { name: "Put the files in a new folder" }))
  expect(await screen.findByText("The backup you were restoring is no longer kept, so nothing was put back. Choose another one.")).toBeInTheDocument()
  expect(screen.queryByRole("region", { name: /^Restore data/ })).toBeNull()
  expect(within(screen.getByRole("list", { name: "Backups kept of data" })).getAllByRole("listitem")).toHaveLength(1)
})

it("offers no restore while a change to the setup is running, but still lets a copy be checked", async () => {
  render(<SetupBackups setupId="acme" name="Acme" moving />)
  expect(await screen.findByRole("button", { name: "Restore the backup from 2026-10-26 02:00" })).toBeDisabled()
  expect(screen.getByRole("button", { name: "Check the backup from 2026-10-26 02:00" })).toBeEnabled()
})

it("says calmly when backups can't be read, and offers to try again only when that could help", async () => {
  api.list.mockReset()
  api.list.mockRejectedValue(new SetupUnavailableError("setup_backups"))
  render(<SetupBackups setupId="acme" name="Acme" />)
  expect(await screen.findByRole("alert")).toHaveTextContent("Backups can't be read in this build of Yougori yet.")
  expect(screen.queryByRole("button", { name: "Try again" })).toBeNull()
  cleanup()

  api.list.mockReset()
  api.list.mockRejectedValueOnce(new SetupCommandError("Backups are still starting. Try again in a moment.", { code: "setups_starting", retryable: true })).mockResolvedValue(listed())
  const user = userEvent.setup()
  render(<SetupBackups setupId="acme" name="Acme" />)
  expect(await screen.findByRole("alert")).toHaveTextContent("Backups are still starting. Try again in a moment.")
  await user.click(screen.getByRole("button", { name: "Try again" }))
  expect(await screen.findByRole("list", { name: "Backups kept of data" })).toBeInTheDocument()
})

it("takes a backup now when asked, says it started, and offers none while the setup is stopped", async () => {
  const user = userEvent.setup()
  api.backUpNow.mockResolvedValue("A backup of data starts now. It shows in the list when it finishes, and the regular times stay as they are.")
  render(<SetupBackups setupId="acme" name="Acme" />)
  const now = await screen.findByRole("button", { name: "Back up data now" })
  await user.click(now)
  expect(api.backUpNow).toHaveBeenCalledWith("acme", "data")
  expect(await screen.findByText(/^A backup of data starts now\./)).toBeInTheDocument()
  // Asked once: the button waits for that backup rather than asking again.
  expect(screen.getByRole("button", { name: "Back up data now" })).toBeDisabled()
  await waitFor(() => expect(api.list.mock.calls.length).toBeGreaterThan(1))
  cleanup()
  api.list.mockResolvedValue(listed({ paused: true }))
  render(<SetupBackups setupId="acme" name="Acme" />)
  expect(await screen.findByRole("button", { name: "Back up data now" })).toBeDisabled()
  expect(screen.getByText("Start the setup to back it up.")).toBeInTheDocument()
})

it("says why a backup can't be taken now, and leaves the regular times alone", async () => {
  const user = userEvent.setup()
  api.backUpNow.mockRejectedValue(new SetupCommandError("A backup of data is being taken right now. It shows in the list when it finishes.", { code: "backup_running" }))
  render(<SetupBackups setupId="acme" name="Acme" />)
  await user.click(await screen.findByRole("button", { name: "Back up data now" }))
  expect(await screen.findByText("A backup of data is being taken right now. It shows in the list when it finishes.")).toBeInTheDocument()
  expect(screen.getByRole("button", { name: "Back up data now" })).toBeEnabled()
})
