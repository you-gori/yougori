import { useCallback, useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import {
  humanSentence, nextStage, previousStage, rollout, ROLLOUT_PRODUCTS, ROLLOUT_STAGES, stageInfo,
  type Band, type ObservationReading, type ProductMeta, type RehearsalReading,
  type RolloutStage, type RolloutStanding, type StageInfo,
} from "@/api/grids/rollout"
import "@/components/neo-grid.css"
import "@/components/grids.css"

/** A reason a person reads, with any home folder in a backend error folded away. */
const message = (reason: unknown) => humanSentence(reason instanceof Error ? reason.message : String(reason))

const BAND_WORD: Record<Band, string> = { agrees: "Agrees", noted: "Noted", stop: "Stops", unobserved: "Not asked" }

/** What a person reads while one of the long actions runs, so there is a spinner on every wait. */
const BUSY_WORD: Record<string, string> = {
  rehearse: "Rehearsing the whole move on copies",
  backup: "Copying every record into a stamped folder",
  observe: "Comparing both paths on a throwaway copy",
}

function busyWord(key: string): string {
  if (BUSY_WORD[key]) return BUSY_WORD[key]
  if (key.startsWith("enable-")) return "Moving this profile to its next stage"
  if (key.startsWith("back-")) return "Rolling this profile back a stage"
  return "Working"
}

/** The eight stages as one bar, filled up to the stage a profile is at. The words beside it say the
 *  same thing, so the bar is hidden from screen readers; each segment names its stage on hover. */
function StageTrack({ at }: { at: StageInfo }) {
  return <span className="rollout-track" aria-hidden="true">
    {ROLLOUT_STAGES.map(stage => <i key={stage.word} title={stage.title} data-reached={stage.order <= at.order || undefined} />)}
  </span>
}

/** The rollout and migration view: per product, whether it has a bridge, where it stands, what a
 *  rehearsal would move and what a comparison found, with the controls that move it, each behind a
 *  confirmation that states its scope.
 *
 *  What is the same for every product is said once: the three actions across the whole move sit
 *  above the products, and when every profile is at one stage, that stage is explained once rather
 *  than on every card.
 *
 *  `products` is the four shipped products and whether each has a bridge, which is a compile-time
 *  fact of this build. It is a prop so that a product added later without a bridge can be shown as
 *  unavailable rather than hidden, and defaults to what this build actually ships.
 */
export function GridRollout({ products = ROLLOUT_PRODUCTS }: { products?: readonly ProductMeta[] }) {
  const [standing, setStanding] = useState<RolloutStanding | null>(null)
  const [rehearsal, setRehearsal] = useState<RehearsalReading | null>(null)
  const [observation, setObservation] = useState<ObservationReading | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState("")
  const [note, setNote] = useState("")
  const [armed, setArmed] = useState("")

  useEffect(() => {
    let live = true
    rollout.status()
      .then(read => { if (live) setStanding(read) })
      .catch(reason => { if (live) setError(message(reason)) })
      .finally(() => { if (live) setLoading(false) })
    return () => { live = false }
  }, [])

  // Escape closes an open confirmation, the way Escape closes a dialog in the browser.
  useEffect(() => {
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setArmed("") }
    window.addEventListener("keydown", onKey)
    return () => window.removeEventListener("keydown", onKey)
  }, [])

  const act = useCallback(async (key: string, label: string, work: () => Promise<void>) => {
    setArmed("")
    setNote("")
    setBusy(key)
    try {
      await work()
    } catch (reason) {
      setNote(`${label} did not finish. ${message(reason)}`)
    } finally {
      setBusy("")
    }
  }, [])

  const doRehearse = () => act("rehearse", "The rehearsal", async () => {
    setRehearsal(await rollout.rehearse())
    setStanding(await rollout.status())
  })
  const doBackUp = () => act("backup", "The backup", async () => {
    await rollout.backUp()
    setStanding(await rollout.status())
    setNote("Every record was copied into a stamped folder on this computer. Carry it off this computer before the next stage.")
  })
  const doObserve = () => act("observe", "Comparing both paths", async () => {
    setObservation(await rollout.observe())
    setStanding(await rollout.status())
  })
  const doEnable = (meta: ProductMeta) => act(`enable-${meta.profile}`, `Moving ${meta.product} on`, async () => {
    setStanding(await rollout.advance(meta.profile))
  })
  const doRollBack = (meta: ProductMeta) => act(`back-${meta.profile}`, `Rolling ${meta.product} back`, async () => {
    setStanding(await rollout.rollBack(meta.profile))
  })

  const stageOf = (profile: string): RolloutStage =>
    standing?.profiles.find(state => state.profile === profile)?.stage ?? "freeze"

  // When every profile is at one stage, what that stage means is said once, above the cards.
  const stages = products.map(meta => stageOf(meta.profile))
  const shared = stages.length > 1 && stages.every(stage => stage === stages[0]) ? stageInfo(stages[0] ?? "freeze") : null

  // The honest gaps, read so they are a real part of the page and not a hypothetical. The engine
  // has no verb that hands back a stored result without re-running the work.
  const unwired = [rollout.lastRehearsal(), rollout.lastObservations()].filter(gap => !gap.wired)

  const arm = (id: string) => { setArmed(id); setNote("") }

  /** What a control is about to do, said in its place, with a Confirm and a Back. One confirmation
   *  is open at a time. */
  const confirmation = (scope: string, tone: "default" | "outline", confirm: () => void) =>
    <div className="rollout-confirm">
      <p>{scope}</p>
      <span className="rollout-actions">
        <Button size="xs" variant={tone} onClick={confirm}>Confirm</Button>
        <Button size="xs" variant="ghost" onClick={() => setArmed("")}>Back</Button>
      </span>
    </div>

  /** One of the three things done across the whole move: what it is, what it does, where it stands
   *  and its control. */
  const step = (id: string, title: string, verb: string, does: string, scope: string, said: string | null, confirm: () => void) =>
    <article className="rollout-step" aria-label={title} key={id}>
      <h4 className="rollout-step-title">{title}</h4>
      <p className="rollout-text">{does}</p>
      {said ? <p className="rollout-said">{said}</p> : null}
      {armed === id
        ? confirmation(scope, "default", confirm)
        : <span className="rollout-actions">
          <Button size="xs" variant="outline" loading={busy === id} disabled={Boolean(busy)} onClick={() => arm(id)}>{verb}</Button>
        </span>}
    </article>

  const rehearsalSentence = (meta: ProductMeta): string | null => {
    if (!rehearsal) return null
    const slice = rehearsal.products.find(entry => entry.profile === meta.profile)
    if (!slice) return "Not part of the last rehearsal, which rehearses only the records this computer holds."
    const moved = slice.moves.length ? slice.moves.map(move => `${move.count} ${move.kind}`).join(", ") : "nothing"
    let said = `Would move across ${moved}. The history ${slice.historyVerified ? "verified" : "did not verify"}, and the realm ${slice.returnedClean ? "came back exactly as it was" : "did not come back as it was"}.`
    if (slice.kept.length) said += ` What the realm would not let an undo delete: ${slice.kept.map(name => name.replace(/_/g, " ")).join(", ")}.`
    if (slice.refusal) said += ` It would refuse: ${slice.refusal}`
    return said
  }

  /** One product: its stage as a bar and in words, what the last rehearsal and comparison found for
   *  it, and the controls that move it one stage on or back. */
  const product = (meta: ProductMeta) => {
    const info = stageInfo(stageOf(meta.profile))
    const next = nextStage(info.word)
    const previous = previousStage(info.word)
    const rehearsed = rehearsalSentence(meta)
    const observed = observation?.profiles.find(entry => entry.profile === meta.profile)
    const differs = observed?.lines.filter(line => line.band === "noted" || line.band === "stop") ?? []
    const enable = `enable-${meta.profile}`
    const back = `back-${meta.profile}`
    return <section className="rollout-card" aria-label={meta.product} key={meta.profile}>
      <header className="rollout-card-head">
        <h4 className="rollout-card-name">{meta.product}</h4>
        <span className="rollout-tag">{info.title}</span>
      </header>
      <StageTrack at={info} />
      <p className="rollout-said">
        Stage {info.order + 1} of {ROLLOUT_STAGES.length} · {meta.hasBridge ? "Has a bridge onto Grid Core" : "No bridge yet"}
      </p>
      {shared ? null : <p className="rollout-text">{info.changes}</p>}
      {rehearsed ? <p className="rollout-text">{rehearsed}</p> : null}
      {observed ? <div className="rollout-found">
        <p className="rollout-text">
          {observed.agree
            ? "The two paths agree so far."
            : `The two paths disagree on ${observed.noted + observed.stopped} of the ${observed.lines.length} questions; nothing was applied.`}
        </p>
        <p className="rollout-said">
          {observed.agreed} agreed · {observed.noted} noted · {observed.stopped} stopped · {observed.unobserved} could not be asked
        </p>
        {differs.length ? <ul className="rollout-differs">
          {differs.map((line, at) => <li key={at}>
            <span className="rollout-tag" data-tone={line.band}>{BAND_WORD[line.band]}</span>
            <span className="rollout-differ">
              <span className="rollout-differ-what">{line.headingPhrase}</span>
              <span className="rollout-text">{line.detail}</span>
            </span>
          </li>)}
        </ul> : null}
      </div> : null}
      <div className="rollout-card-foot">
        {!meta.hasBridge
          ? <p className="rollout-said">Bringing it across is unavailable: {meta.bridgeReason ?? "it has no bridge."}</p>
          : next && armed === enable
            ? confirmation(`Moving ${meta.product} to the ${next.title.toLowerCase()} stage. ${next.changes} It can be rolled back.`, "default", () => doEnable(meta))
            : previous && armed === back
              ? confirmation(`Rolling ${meta.product} back to the ${previous.title.toLowerCase()} stage. What still has to be undone by hand: ${info.undoneBy}`, "outline", () => doRollBack(meta))
              : <span className="rollout-actions">
                {next ? <Button size="xs" variant="outline" loading={busy === enable} disabled={Boolean(busy)} onClick={() => arm(enable)}>
                  {next.word === "cutover" ? "Enable this profile" : `Move to ${next.title.toLowerCase()}`}
                </Button> : null}
                {previous ? <Button size="xs" variant="ghost" loading={busy === back} disabled={Boolean(busy)} onClick={() => arm(back)}>Roll back</Button> : null}
              </span>}
      </div>
    </section>
  }

  return <section className="rollout" aria-label="Moving onto Grid Core" aria-busy={Boolean(busy) || loading}>
    <header className="grids-head">
      <h2 className="grids-heading">Moving onto Grid Core <span>one backend for every grid</span></h2>
      <p className="grids-lead">
        Every grid this company runs can move onto one backend, one profile at a time. Each step runs
        on this computer and can be undone, and nothing changes what a grid holds until its profile
        is enabled.
      </p>
    </header>

    {loading ? <p role="status" className="rollout-status">Reading where the rollout stands…</p> : null}
    {busy ? <p role="status" className="rollout-status">{busyWord(busy)}…</p> : null}
    {error ? <p role="alert" className="rollout-callout" data-tone="error">{error}</p> : null}
    {note ? <p className="rollout-callout">{note}</p> : null}

    <section className="rollout-group" aria-label="Across the whole move">
      <h3 className="rollout-group-title">Across the whole move <span>on this computer, nothing applied</span></h3>
      <div className="rollout-steps">
        {step(
          "rehearse", "Rehearsal", "Rehearse",
          "Run the whole move on copies to see what it would do. Nothing it holds changes.",
          "Copies every record and realm on this computer, runs the move on the copies, verifies it, then undoes it. Nothing it holds changes.",
          rehearsal ? "Rehearsed in this session. Each grid below shows what would move across." : "Not rehearsed in this session yet.",
          doRehearse,
        )}
        {step(
          "backup", "Backup", "Back up",
          "Copy every product's record into a stamped folder on this computer and read it back.",
          "Copies every record into a stamped folder and reads each one back. Carry that folder off this computer afterwards.",
          null,
          doBackUp,
        )}
        {step(
          "observe", "Comparison", "Begin observing",
          "Ask the hub and the core the same questions and write down every difference.",
          "The hub keeps deciding while the core answers the same questions beside it, on a throwaway copy. Every difference is written down and nothing is applied.",
          observation ? "Compared in this session. Each grid below shows where the two paths differ." : "Not compared in this session yet.",
          doObserve,
        )}
      </div>
    </section>

    {loading ? null : <section className="rollout-group" aria-label="Each grid">
      <h3 className="rollout-group-title">Each grid <span>{ROLLOUT_STAGES.length} stages, moved one at a time</span></h3>
      {shared ? <p className="rollout-text">Every grid is at the {shared.title.toLowerCase()} stage. {shared.changes}</p> : null}
      <div className="rollout-cards">{products.map(product)}</div>
    </section>}

    {unwired.length ? <div className="rollout-foot">
      {unwired.map(gap => <p key={gap.line}>{gap.reason} Run <code>{gap.line}</code> instead.</p>)}
    </div> : null}
  </section>
}
