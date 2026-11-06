import { useCallback, useEffect, useRef, useState } from "react"
import { Button } from "@/components/ui/button"
import { backupsApi, type BackupCheck, type BackupList, type BackupOutcome, type BackupVolume, type KeptBackup, type RestoreReview } from "@/api/setups/backups"
import { setupFeed } from "@/api/setups/progress"
import { errorText, isUnavailable, SetupCommandError } from "@/api/setups/setups-api"
import { StateLabel, type StateTone } from "./setup-marks"
import { plural } from "./setup-words"

/** The backups a setup keeps, on its Automation tab: each volume's times, how its last backup
 *  went and every copy kept, with a check for each copy and a reviewed restore. `yougori setup
 *  backups` reads the same copies and says the same things.
 *
 *  Restoring is reviewed exactly as removing a setup is: what it would replace is read first, and
 *  nothing is put back until that review is confirmed. The files go into a new folder unless the
 *  person chooses, by name, to replace what is on the volume.
 */

/** How often the list is read again while it is open: the setup feed's own pace. */
const READ_AGAIN_MS = 60_000
/** How often, while a backup asked for now is being taken, the list is read again to show it. */
const WATCH_MS = 3_000
/** How long a backup asked for now is watched for before the list goes back to its own pace. */
const WATCH_FOR_MS = 10 * 60_000
const REVIEWING = "Working out what would be restored"
const PUTTING = "Putting the backup back"

const LAST_RUN: Record<BackupOutcome, { text: string; tone: StateTone }> = {
  never_run: { text: "None yet", tone: "unknown" },
  done: { text: "Done", tone: "ok" },
  failed: { text: "Failed", tone: "attention" },
  skipped: { text: "Skipped", tone: "off" },
}

/** Refusals after which the review on screen no longer describes a restore that can be made. */
const REVIEW_GONE = new Set(["backup_not_found", "no_backups"])

type Checked = { state: "checking" } | { state: "checked"; result: BackupCheck } | { state: "refused"; message: string }

/** One copy of one volume, as the list names it. */
interface Copy {
  resource: string
  backupId: string
}

/** The restore being reviewed, and where the person wants the files put. */
interface Restoring extends Copy {
  /** False, a new folder, until the person chooses the volume itself. */
  overOriginal: boolean
  /** The engine's review of exactly that choice, once it has answered. */
  review: RestoreReview | null
}

const same = (a: Copy | null, b: Copy) => Boolean(a && a.resource === b.resource && a.backupId === b.backupId)
const keyOf = (copy: Copy) => `${copy.resource}\n${copy.backupId}`
const domId = (...parts: string[]) => parts.join("-").replace(/[^A-Za-z0-9_-]/g, "-")
const restoreButton = (section: string, copy: Copy) => domId(section, copy.resource, copy.backupId, "restore")
const isKept = (list: BackupList, copy: Copy) =>
  list.volumes.some(volume => volume.resource === copy.resource && volume.backups.some(backup => backup.id === copy.backupId))

function said(reason: unknown, unavailable: string) {
  if (isUnavailable(reason)) return unavailable
  if (reason instanceof SetupCommandError && reason.code === "setup_busy") return "Another change to this setup is still running, so nothing was put back. Try again when it has finished."
  if (reason instanceof SetupCommandError && reason.code === "confirmation_stale") return "That confirmation was for a different restore, so nothing was put back. Read what restoring would do again before you go ahead."
  return errorText(reason)
}

/** The times in a sentence: `Every day at 02:00, this computer's time zone, keeping the newest 7.` */
function times(volume: BackupVolume) {
  const when = volume.schedule ? volume.schedule.charAt(0).toUpperCase() + volume.schedule.slice(1) : "No times set"
  if (volume.keep <= 0) return `${when}.`
  return `${when}, keeping ${volume.keep === 1 ? "only the newest copy" : `the newest ${volume.keep}`}.`
}

export function SetupBackups(props: { setupId: string; name: string; moving?: boolean }) {
  // Another setup starts afresh: nothing checked, reviewed or said about the one before.
  return <Backups key={props.setupId} {...props} />
}

function Backups({ setupId, name, moving = false }: {
  setupId: string
  name: string
  /** A change to the setup is running. The engine refuses a restore then, so none is offered. */
  moving?: boolean
}) {
  const [shown, setShown] = useState<BackupList | null>(null)
  const [readError, setReadError] = useState<{ text: string; again: boolean } | null>(null)
  const [reads, setReads] = useState(0)
  const [checks, setChecks] = useState<Record<string, Checked>>({})
  const [restoring, setRestoring] = useState<Restoring | null>(null)
  const [working, setWorking] = useState("")
  const [error, setError] = useState("")
  const [done, setDone] = useState<(Copy & { text: string }) | null>(null)
  // A backup asked for now: which volume, what was said, and when it was asked, so the list is
  // read more often until it shows.
  const [now, setNow] = useState<{ resource: string; text: string; tone: StateTone; since: number } | null>(null)
  // The latest review asked for. An answer to an earlier one is dropped: the person has since
  // chosen something else, or closed it.
  const asked = useRef(0)
  const id = domId("setup", setupId, "backups")
  const putting = working === PUTTING

  useEffect(() => {
    let live = true
    const read = () => backupsApi.list(setupId).then(
      found => { if (live) { setShown(found); setReadError(null) } },
      reason => { if (live) setReadError({ text: said(reason, "Backups can't be read in this build of Yougori yet."), again: !isUnavailable(reason) }) },
    )
    void read()
    const timer = window.setInterval(() => void read(), now && now.tone === "ok" ? WATCH_MS : READ_AGAIN_MS)
    return () => { live = false; window.clearInterval(timer) }
  }, [setupId, reads, now])

  // A backup asked for now is watched until the volume's last run is newer than the ask, then
  // the list goes back to its own pace.
  useEffect(() => {
    if (!now || now.tone !== "ok") return
    const volume = shown?.volumes.find(one => one.resource === now.resource)
    const finished = volume && volume.lastOutcome !== "never_run" && (volume.lastFinishedAt ?? 0) * 1000 >= now.since
    if (finished || Date.now() - now.since > WATCH_FOR_MS) setNow(null)
  }, [shown, now])

  const backUp = useCallback(async (resource: string) => {
    setNow({ resource, text: "Asking for a backup…", tone: "unknown", since: Date.now() })
    try {
      const text = await backupsApi.backUpNow(setupId, resource)
      setNow({ resource, text, tone: "ok", since: Date.now() })
      setReads(count => count + 1)
    } catch (reason) {
      setNow({ resource, text: said(reason, "Backing up on demand isn't in this build of Yougori yet. The regular times still run."), tone: "attention", since: Date.now() })
    }
  }, [setupId])

  const check = useCallback(async (copy: Copy) => {
    const key = keyOf(copy)
    setChecks(current => ({ ...current, [key]: { state: "checking" } }))
    try {
      const result = await backupsApi.check(setupId, copy.resource, copy.backupId)
      setChecks(current => ({ ...current, [key]: { state: "checked", result } }))
    } catch (reason) {
      setChecks(current => ({ ...current, [key]: { state: "refused", message: said(reason, "Checking backups isn't in this build of Yougori yet.") } }))
    }
  }, [setupId])

  /** Asks what restoring this copy would do, for the target the person chose. Nothing changes. */
  const review = useCallback(async (copy: Copy, overOriginal: boolean, notice = "") => {
    const ask = ++asked.current
    const { resource, backupId } = copy
    setRestoring({ resource, backupId, overOriginal, review: null })
    setWorking(REVIEWING)
    setError(notice)
    setDone(null)
    try {
      const found = await backupsApi.reviewRestore(setupId, resource, backupId, overOriginal)
      if (asked.current === ask) setRestoring({ resource, backupId, overOriginal, review: found })
    } catch (reason) {
      if (asked.current === ask) setError(said(reason, "Restoring backups isn't in this build of Yougori yet. Nothing was changed."))
    } finally {
      if (asked.current === ask) setWorking("")
    }
  }, [setupId])

  /** Restores exactly the review on screen: its copy, its target and its word, nothing else. */
  const confirm = useCallback(async () => {
    const reviewed = restoring?.review
    if (!reviewed || working) return
    const ask = ++asked.current
    const copy = { resource: reviewed.resource, backupId: reviewed.backupId }
    setWorking(PUTTING)
    setError("")
    try {
      const result = await backupsApi.restore(reviewed)
      if (asked.current !== ask) return
      setRestoring(null)
      setDone({ ...copy, text: result.next })
      setReads(count => count + 1)
      // Restoring over the volume stops and starts the sandboxes that use it.
      void setupFeed.refresh(setupId).catch(() => undefined)
      requestAnimationFrame(() => document.getElementById(restoreButton(id, copy))?.focus())
    } catch (reason) {
      if (asked.current !== ask) return
      if (reason instanceof SetupCommandError && reason.code === "confirmation_stale") {
        void review(copy, reviewed.overwrites, said(reason, ""))
        return
      }
      if (reason instanceof SetupCommandError && REVIEW_GONE.has(reason.code)) {
        setRestoring(current => current && { ...current, review: null })
        setReads(count => count + 1)
      }
      setError(said(reason, "Restoring backups isn't in this build of Yougori yet. Nothing was changed."))
    } finally {
      if (asked.current === ask) setWorking("")
    }
  }, [restoring, working, setupId, review, id])

  const keep = (copy: Copy) => {
    asked.current += 1
    setRestoring(null)
    setWorking("")
    setError("")
    requestAnimationFrame(() => document.getElementById(restoreButton(id, copy))?.focus())
  }

  const checkLine = (checked: Checked | undefined) => {
    if (!checked) return null
    if (checked.state === "checking") return <p role="status" className="setup-note">Checking the backup…</p>
    if (checked.state === "refused") return <div>
      <p role="alert" className="grid-error">{checked.message}</p>
      <p className="setup-note">Nothing was changed.</p>
    </div>
    const { result } = checked
    return <div role="status">
      <StateLabel tone="ok">This backup is complete and unchanged: {plural(result.files, "file")}, taken {result.when}.</StateLabel>
      {result.consistency === "live" ? <p className="setup-note">It was taken while everything kept running, so a file being written then may be half-written.</p> : null}
      {result.note ? <p className="setup-note">{result.note}</p> : null}
      <p className="setup-note">Nothing was changed.</p>
    </div>
  }

  const panel = (volume: BackupVolume, backup: KeptBackup, open: Restoring) => {
    const reviewed = open.review
    const copy = { resource: volume.resource, backupId: backup.id }
    const target = domId(id, volume.resource, backup.id, "target")
    return <section className="setup-removal" aria-label={`Restore ${volume.resource} from the backup of ${backup.when}`}>
      <p className="setup-review-headline">Restoring {volume.resource} of {name} from the backup <span className="setup-path">{backup.id}</span>.</p>
      <fieldset className="setup-options" disabled={putting}>
        <legend>Where the files go</legend>
        <label className="setup-radio">
          <input type="radio" name={target} checked={!open.overOriginal} onChange={() => void review(copy, false)} />
          <span>Into a new folder inside {volume.through || "its sandbox"}. {volume.resource} itself is not touched. Practise with this.</span>
        </label>
        <label className="setup-radio">
          <input type="radio" name={target} checked={open.overOriginal} onChange={() => void review(copy, true)} />
          <span><strong>Over {volume.resource} itself.</strong> Everything now on it is replaced by what the backup holds, and anything written since is gone. The backup is checked first, and a backup that does not match is refused.</span>
        </label>
      </fieldset>
      {reviewed ? <>
        <p className="setup-note">Nothing has changed yet. This is what restoring it would do.</p>
        <ul className="setup-callout" aria-label="Before you restore it">{reviewed.review.map((line, index) => <li key={index}>{line}</li>)}</ul>
      </> : null}
      {working ? <p role="status" className="setup-note">{working}…</p> : null}
      {error ? <p role="alert" className="grid-error">{error}</p> : null}
      {moving && reviewed ? <p className="setup-note">Another change to this setup is running. You can restore this when it has finished.</p> : null}
      <div className="setup-actions">
        {reviewed ? <Button size="xs" variant={reviewed.overwrites ? "destructive" : "default"} disabled={Boolean(working) || moving} onClick={() => void confirm()}>
          {reviewed.overwrites ? `Replace everything on ${volume.resource}` : "Put the files in a new folder"}
        </Button> : null}
        <Button size="xs" variant="ghost" disabled={putting} onClick={() => keep(copy)}>Not now</Button>
      </div>
    </section>
  }

  const row = (volume: BackupVolume, backup: KeptBackup) => {
    const copy = { resource: volume.resource, backupId: backup.id }
    const checked = checks[keyOf(copy)]
    const open = restoring && same(restoring, copy) ? restoring : null
    return <li key={backup.id} className="setup-panel-section">
      <div className="setup-confirm">
        <span>{backup.describe}</span>
        <span className="setup-actions">
          <Button size="xs" variant="outline" aria-label={`Check the backup from ${backup.when}`} onClick={() => { if (checked?.state !== "checking") void check(copy) }}>Check</Button>
          <Button id={restoreButton(id, copy)} size="xs" variant="ghost" aria-label={`Restore the backup from ${backup.when}`} disabled={moving || putting} onClick={() => { if (!open) void review(copy, false) }}>Restore…</Button>
        </span>
      </div>
      {checkLine(checked)}
      {done && same(done, copy) ? <p role="status"><StateLabel tone="ok">{done.text}</StateLabel></p> : null}
      {open ? panel(volume, backup, open) : null}
    </li>
  }

  // A copy the schedule has since let go: its row is gone from the list, so what happened to it
  // is said here instead.
  const gone = !putting && restoring && shown && !isKept(shown, restoring)
  const doneElsewhere = done && shown && !isKept(shown, done) ? done : null
  return <section className="setup-panel-section" aria-labelledby={id}>
    <h3 className="setup-panel-title" id={id}>Backups</h3>
    {!shown && !readError ? <p role="status" className="setup-note">Reading the backups…</p> : null}
    {readError && !shown ? <>
      <p role="alert" className="grid-error">{readError.text}</p>
      {readError.again ? <div className="setup-actions"><Button size="xs" variant="outline" onClick={() => { setReadError(null); setReads(count => count + 1) }}>Try again</Button></div> : null}
    </> : null}
    {shown && !shown.volumes.length ? <p className="setup-note">This setup backs nothing up. A template gives a volume a schedule; this one gave none.</p> : null}
    {gone ? <p role="status" className="setup-callout">The backup you were restoring is no longer kept, so nothing was put back. Choose another one.</p> : null}
    {doneElsewhere ? <p role="status"><StateLabel tone="ok">{doneElsewhere.text}</StateLabel></p> : null}
    {shown?.volumes.map(volume => {
      const heading = domId(id, volume.resource)
      const last = LAST_RUN[volume.lastOutcome]
      return <section key={volume.resource} className="setup-part" aria-labelledby={heading}>
        <h4 id={heading}>{volume.resource}</h4>
        <dl className="setup-outputs">
          <div><dt>Times</dt><dd>{times(volume)}</dd></div>
          <div><dt>Next backup</dt><dd>{volume.paused ? "Paused while the setup is stopped. Starting the setup resumes it." : volume.nextWhen ?? "No next backup worked out yet."}</dd></div>
          <div><dt>Last run</dt><dd>
            <StateLabel tone={last.tone}>{last.text}{volume.lastOutcome !== "never_run" && volume.lastWhen ? ` at ${volume.lastWhen}` : ""}</StateLabel>
            {volume.lastDetail ? <span className="setup-note"> {volume.lastDetail}</span> : null}
          </dd></div>
          {volume.consistencyWords ? <div><dt>How it is copied</dt><dd>{volume.consistencyWords}</dd></div> : null}
        </dl>
        <div className="setup-actions">
          <Button size="xs" variant="outline" aria-label={`Back up ${volume.resource} now`} disabled={volume.paused || moving || putting || now?.resource === volume.resource && now.tone !== "attention"} onClick={() => void backUp(volume.resource)}>Back up now</Button>
          {volume.paused ? <span className="setup-note">Start the setup to back it up.</span> : null}
        </div>
        {now?.resource === volume.resource ? <p role="status"><StateLabel tone={now.tone}>{now.text}</StateLabel></p> : null}
        {volume.backups.length
          ? <ul className="setup-step-list" aria-label={`Backups kept of ${volume.resource}`}>{volume.backups.map(backup => row(volume, backup))}</ul>
          : <p className="setup-note">Nothing kept yet.</p>}
      </section>
    })}
    {shown?.volumes.length && shown.limits ? <p className="setup-note">{shown.limits}</p> : null}
  </section>
}
