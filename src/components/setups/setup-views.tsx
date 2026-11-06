import { useState } from "react"
import { Button } from "@/components/ui/button"
import type { OperationView } from "@/api/setups/progress"
import type { CapabilityStatus, Diagnostic, NextAction, OperationBrief, OperationEvent, Output, SetupPlan } from "@/api/setups/types"
import { errorText, setupsApi } from "@/api/setups/setups-api"
import { workspaceApi } from "@/api/workspace-api"
import { fieldLabel } from "./draft"
import { StateLabel } from "./setup-marks"
import { SetupProduct } from "./setup-product"
import { healthOf, nextActionText, operationOf, plural, resourceActionOf, termsToAgree } from "./setup-words"

/** The three views every setup shares, in the builder and on My setups alike: the review of a
 *  plan before anything changes, the progress of an operation, and readiness by capability. */

const list = <T,>(value: T[] | null | undefined): T[] => Array.isArray(value) ? value : []
/** A line from a template's or a Hub tool's files, shown as it will run: control characters become
 *  spaces and invisible ones that could reorder or hide part of it are left out, as the CLI does. */
const shown = (line: unknown) => typeof line === "string" ? line.replace(/\p{Cc}/gu, " ").replace(/\p{Cf}/gu, "") : ""

function size(bytes: number | null | undefined) {
  if (bytes == null || !Number.isFinite(bytes)) return "size not known yet"
  if (bytes < 1024 * 1024) return `${Math.max(1, Math.round(bytes / 1024))} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(0)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(1)} GB`
}

export function DiagnosticList({ diagnostics, names, onGoTo, label = "Problems" }: {
  diagnostics: Diagnostic[]
  names?: Record<string, string>
  onGoTo?(field: string): void
  label?: string
}) {
  if (!diagnostics.length) return null
  return <ul className="setup-diagnostics" aria-label={label}>
    {diagnostics.map((diagnostic, index) => <li key={`${diagnostic.code}-${index}`} data-severity={diagnostic.severity}>
      <StateLabel tone={diagnostic.severity === "info" ? "unknown" : "attention"}>
        {diagnostic.severity === "error" ? "Must be fixed" : diagnostic.severity === "warning" ? "Worth a look" : "Note"}
      </StateLabel>
      <span className="setup-diagnostic-text">{diagnostic.message}</span>
      {diagnostic.field && onGoTo ? <Button size="xs" variant="link" onClick={() => onGoTo(diagnostic.field!)}>Go to {fieldLabel(diagnostic.field, names)}</Button> : null}
    </li>)}
  </ul>
}

/** Everything a plan would do, before it does any of it. Parts the engine did not send are left
 *  out rather than guessed; a cost the engine could not work out says so instead of saying zero. */
/** What a setup shows of itself (an address, a grid's name), each under its template's label. An
 *  address opens in the browser. Private outputs are never here; they are revealed on request. */
export function SetupOutputs({ outputs }: { outputs: Output[] | undefined }) {
  if (!outputs?.length) return null
  return <dl className="setup-outputs">{outputs.map(output => <div key={output.key}>
    <dt>{output.label}</dt>
    <dd>{/^https?:\/\//.test(output.value) ? <button type="button" className="hub-link" onClick={() => { void workspaceApi.openUrl(output.value).catch(() => undefined) }}>{output.value}</button> : output.value}</dd>
  </div>)}</dl>
}

export function SetupReview({ plan, names, onGoTo, agreed, onAgree }: {
  plan: SetupPlan
  names?: Record<string, string>
  onGoTo?(field: string): void
  /** The consents ticked so far. Each one is unticked until the person ticks it. */
  agreed?: string[]
  onAgree?(id: string, on: boolean): void
}) {
  const review = plan.review ?? {}
  const unique = (lines: string[]) => lines.filter((line, index) => typeof line === "string" && lines.indexOf(line) === index)
  const placements = new Map([...list(review.creates), ...list(review.borrows)].map(item => [item.id, item.placement]))
  const resources = list(plan.resources).map(resource => ({ ...resource, placement: resource.placement ?? placements.get(resource.resourceId ?? resource.id ?? "") ?? null }))
  const downloads = [...list(plan.downloads).map(download => `${download.name} · ${size(download.bytes)}`), ...list(review.downloads).map(download => `${download.name}${download.from ? ` from ${download.from}` : ""}`)]
  const permissions = unique([...list(plan.permissions), ...list(review.permissions)])
  const installs = list(review.installs)
  const limits = list(review.limits)
  const costs = unique([...list(plan.costs).map(cost => `${cost.label}: ${cost.amount ?? "not known yet"}`), ...list(review.costs)])
  const changes = list(plan.changes), retained = list(plan.retained), steps = list(plan.steps)
  const warnings = unique([...list(review.warnings), ...list(plan.warnings)]), notes = unique([...list(review.notes), ...list(plan.notes)])
  const folders = list(review.pcAccess), published = list(review.public), totals = review.totals
  const blockers = list(plan.blockers)
  const consents = list(plan.consents).filter(consent => consent && typeof consent.id === "string" && typeof consent.message === "string")
  // A removal's notes say what really happens to the data and when, and an update's say what the
  // new version does to the choices this setup already has. Both are read before anything else.
  const changesChoices = list(plan.conflicts).length > 0
  const notesFirst = plan.intent === "remove" || changesChoices
  // The Hub page against the files, as the engine compared them: a page that promises less than
  // the files grant is said here, before the person agrees, and a page that could not be compared
  // says why rather than passing as checked.
  const page = plan.page ?? null
  const pageDiffers = Boolean(page?.compared && page.differs && list(page.differences).length)
  return <section className="setup-review" aria-label="What will happen">
    {plan.headline ? <p className="setup-review-headline">{plan.headline}</p> : null}
    <p className="setup-note">Nothing has changed yet. This is what applying it would do.</p>
    {pageDiffers ? <ul className="setup-callout" aria-label="The Hub page describes this version differently from its files">
      <li>The Hub page for this version describes it differently from the files that were downloaded: {list(page!.differences).join("; ")}.</li>
      <li>What follows is built from the files themselves, which is what would run.</li>
    </ul> : null}
    {page && !page.compared && page.reason ? <p className="setup-note" data-page-check="not-compared">{page.reason}</p> : null}
    {notesFirst && notes.length ? <ul className="setup-callout" aria-label={changesChoices ? "What this version changes about your setup" : "Before you remove it"}>{notes.map((note, index) => <li key={index}>{note}</li>)}</ul> : null}
    {blockers.length ? <div role="alert"><DiagnosticList diagnostics={blockers} names={names} onGoTo={onGoTo} label="What stops it" /></div> : null}
    {warnings.length ? <ul className="setup-callout" aria-label="Warnings">{warnings.map((warning, index) => <li key={index}>{warning}</li>)}</ul> : null}
    {resources.length ? <>
      <h4>What it creates or uses</h4>
      <div className="setup-table-wrap">
        <table className="setup-table">
          <thead><tr><th scope="col">Name</th><th scope="col">Kind</th><th scope="col">What happens</th><th scope="col">Where</th><th scope="col">Ownership</th></tr></thead>
          <tbody>{resources.map((resource, index) => <tr key={index}>
            <th scope="row">{resource.label ?? resource.name ?? resource.resourceId ?? resource.id}{resource.detail ? <span className="setup-note"> {resource.detail}</span> : null}</th>
            <td>{resource.kind.replace(/_/g, " ")}</td>
            <td>{resourceActionOf(resource.action)}</td>
            <td>{resource.placement ?? "—"}</td>
            <td>{resource.owned ? "Owned by this setup" : "Borrowed, never removed by it"}</td>
          </tr>)}</tbody>
        </table>
      </div>
    </> : null}
    {steps.length ? <><h4>In this order</h4><ol className="setup-plain-list">{steps.map((step, index) => <li key={index}>{step.title}{step.detail ? <span className="setup-note"> {step.detail}</span> : null}</li>)}</ol></> : null}
    {totals ? <dl className="setup-totals" aria-label="What it uses in all">
      <div><dt>Sandboxes</dt><dd>{totals.environments}</dd></div>
      <div><dt>CPU</dt><dd>{totals.cpu}</dd></div>
      <div><dt>Memory</dt><dd>{totals.memoryGb} GB</dd></div>
      <div><dt>Disk</dt><dd>{totals.storageGb} GB</dd></div>
      <div><dt>GPU</dt><dd>{totals.gpu && totals.gpu !== "none" ? totals.gpu : "No"}</dd></div>
    </dl> : null}
    {folders.length ? <><h4>Folders on this computer it can use</h4><ul className="setup-plain-list">{folders.map((folder, index) => <li key={index}>
      <span className="setup-path">{folder.path}</span> in {folder.environment}{folder.target ? ` at ${folder.target}` : ""} · {folder.staged ? "a copy: the folder changes only with files you approve after a review" : folder.readOnly ? "read only" : <strong>it can change files there</strong>}
    </li>)}</ul></> : null}
    {published.length ? <><h4>Reachable from outside</h4><ul className="setup-plain-list">{published.map((entry, index) => <li key={index}>{entry.resource}, port {entry.port}: {entry.access === "quick" ? "a quick public link" : entry.access === "domain" ? "your own domain" : entry.access === "lan" ? "this network" : entry.access === "private" ? "this computer only, at 127.0.0.1" : entry.access}</li>)}</ul></> : null}
    {downloads.length ? <><h4>Downloads</h4><ul className="setup-plain-list">{downloads.map((download, index) => <li key={index}>{download}</li>)}</ul></> : null}
    {installs.length ? <><h4>What its tools run</h4><ul className="setup-plain-list">{installs.map((install, index) => <li key={index}>
      {shown(install.tool)} in {shown(install.resource)}
      {list(install.commands).length ? <ul className="setup-plain-list">{list(install.commands).map((command, line) => <li key={line} className="setup-path">$ {shown(command)}</li>)}</ul> : <span className="setup-note"> installs nothing; its check must already pass</span>}
      {install.check ? <div className="setup-note">Checked with <span className="setup-path">{shown(install.check)}</span></div> : null}
    </li>)}</ul></> : null}
    {limits.length ? <><h4>Its limits</h4><ul className="setup-plain-list">{limits.map((limit, index) => <li key={index}>{shown(limit)}</li>)}</ul></> : null}
    {permissions.length ? <><h4>What it is allowed to do</h4><ul className="setup-plain-list">{permissions.map((permission, index) => <li key={index}>{permission}</li>)}</ul></> : null}
    <SetupProduct detail={plan} />
    {costs.length ? <><h4>Costs</h4><ul className="setup-plain-list">{costs.map((cost, index) => <li key={index}>{cost}</li>)}</ul></> : null}
    {changes.length ? <><h4>Changes to what you already have</h4><ul className="setup-plain-list">{changes.map((change, index) => <li key={index}>{change}</li>)}</ul></> : null}
    {retained.length ? <><h4>Kept afterwards</h4><ul className="setup-plain-list">{retained.map((kept, index) => <li key={index}>{kept}</li>)}</ul></> : null}
    {!notesFirst && notes.length ? <ul className="setup-plain-list setup-note">{notes.map((note, index) => <li key={index}>{note}</li>)}</ul> : null}
    {consents.length ? <fieldset className="setup-consents">
      <legend>Only if you agree</legend>
      {consents.map(consent => <label key={consent.id} className="setup-radio">
        <input type="checkbox" checked={Boolean(agreed?.includes(consent.id))} disabled={!onAgree} onChange={event => onAgree?.(consent.id, event.target.checked)} />
        <span>{consent.message}</span>
      </label>)}
      <p className="setup-note">Anything left unticked is not done. You can do it yourself later.</p>
    </fieldset> : null}
  </section>
}

/** The steps an operation has been through, from its events: each step tag once, in the order it
 *  first appeared. Only the latest one can still be working. */
function stepsFrom(events: OperationEvent[], moving: boolean) {
  const order: { step: string; message: string; failed: boolean }[] = []
  for (const event of events) {
    const at = order.findIndex(one => one.step === event.step)
    const failed = event.diagnostic?.severity === "error"
    if (at === -1) order.push({ step: event.step, message: event.message, failed })
    else order[at] = { step: event.step, message: event.message, failed: order[at]!.failed || failed }
  }
  return order.map((one, index) => ({ ...one, state: one.failed ? "failed" as const : moving && index === order.length - 1 ? "working" as const : "done" as const }))
}

const STEP_WORDS = { done: { text: "Done", tone: "ok" }, working: { text: "Working", tone: "busy" }, failed: { text: "Did not finish", tone: "attention" } } as const

/** Agreeing to exactly the terms a joined review showed, from the window. */
function AgreeToTerms({ setupId, operationId, agreed }: { setupId: string; operationId: string; agreed: string }) {
  const [busy, setBusy] = useState(false)
  const [said, setSaid] = useState("")
  const agree = async () => {
    setBusy(true)
    setSaid("")
    try { await setupsApi.agreeToTerms(setupId, operationId, agreed) }
    catch (reason) { setSaid(errorText(reason)) }
    finally { setBusy(false) }
  }
  return <div className="setup-actions">
    <Button size="xs" disabled={busy} loading={busy} onClick={() => void agree()}>Agree to these terms</Button>
    {said ? <p className="grid-error" role="alert">{said}</p> : null}
  </div>
}

/** How far an operation is, in words. There is no bar: the engine reports steps as they happen,
 *  not a total to count towards, and a bar would claim more than it knows. */
export function SetupProgress({ operation, onAction, busy = false, idPrefix = "setup-progress", handles, announce = true, agreeFor }: {
  operation: OperationView
  /** The setup and operation this is, so terms a joined review asks for can be agreed to here. */
  agreeFor?: { setupId: string; operationId: string } | null
  /** Whether changes are read out. A list of many setups leaves this to the one being looked at,
   *  so a screen reader isn't flooded when several move at once. */
  announce?: boolean
  onAction?(action: NextAction): void
  busy?: boolean
  /** Starts each action button's id, so focus can come back to it after a confirmation. */
  idPrefix?: string
  /** The next-action kinds `onAction` carries out. Only these are buttons; the rest are said. */
  handles?: ReadonlySet<string>
}) {
  const cancelled = operation.state === "failed" && operation.error?.code === "operation_cancelled"
  const state = cancelled ? { text: "Cancelled", tone: "off" as const } : operationOf(operation.state)
  const moving = state.tone === "busy"
  const steps = stepsFrom(operation.events, moving)
  const done = steps.filter(step => step.state === "done").length
  const offered = [
    ...list(operation.error?.nextActions),
    // A moving operation can always be cancelled; the engine keeps what is already done.
    ...(operation.state === "applying" || operation.state === "awaiting_input" ? [{ kind: "cancel" } as NextAction] : []),
  ].filter((action, index, all) => all.findIndex(one => one.kind === action.kind) === index)
  // What can be done from here is a button; anything else, such as a sign-in, is said in words.
  const doable = (action: NextAction) => Boolean(onAction && handles?.has(action.kind))
  const actions = offered.filter(doable)
  const told = offered.filter(action => !doable(action))
  return <section className="setup-progress" aria-label="Progress" aria-busy={moving}>
    <p className="setup-progress-head" role={announce ? "status" : undefined}>
      <StateLabel tone={state.tone}>{state.text}</StateLabel>
      {steps.length ? <span className="setup-note">{plural(done, "step")} done{moving ? " so far" : ""}</span> : null}
    </p>
    {operation.error && !cancelled ? <p className="grid-error" role="alert">{operation.error.message}</p> : null}
    {agreeFor && operation.state === "awaiting_input" && termsToAgree(operation.error) ? <AgreeToTerms setupId={agreeFor.setupId} operationId={agreeFor.operationId} agreed={termsToAgree(operation.error)!} /> : null}
    {steps.length ? <ol className="setup-step-list">
      {steps.map((step, index) => <li key={index} data-state={step.state}>
        <StateLabel tone={STEP_WORDS[step.state].tone}><span className="setup-visually-hidden">{STEP_WORDS[step.state].text}: </span>{step.message}</StateLabel>
      </li>)}
    </ol> : moving ? <p className="setup-note">Starting…</p> : null}
    {operation.truncated ? <p className="setup-note">Earlier steps were not kept, so this list starts part way through.</p> : null}
    {told.length ? <ul className="setup-plain-list">{told.map(action => <li key={action.kind}>Next: {nextActionText(action)}.</li>)}</ul> : null}
    {actions.length && onAction ? <div className="setup-actions">
      {actions.map(action => <Button key={action.kind} id={`${idPrefix}-${action.kind}`} size="xs" variant="outline" disabled={busy} onClick={() => onAction(action)}>{nextActionText(action)}</Button>)}
    </div> : null}
  </section>
}

/** The last change on a setup that ended without finishing, so a failure stays in sight after the
 *  engine has let go of it. Retry continues only the steps that did not finish. */
export function LastFailure({ operation, busy, onRetry, onDetails }: { operation: OperationBrief; busy: boolean; onRetry(): void; onDetails(): void }) {
  const cancelled = operation.error?.code === "operation_cancelled"
  const retryable = operation.error ? operation.error.retryable || list(operation.error.nextActions).some(action => action.kind === "retry") : true
  return <section className="setup-progress" aria-label="The last change">
    <p className="setup-progress-head">
      <StateLabel tone={cancelled ? "off" : "attention"}>{cancelled ? "The last change was cancelled" : "The last change did not finish"}</StateLabel>
    </p>
    {operation.error && !cancelled ? <p role="alert" className="grid-error">{operation.error.message}</p> : null}
    {cancelled ? <p className="setup-note">Everything it had already done is still kept.</p> : null}
    <div className="setup-actions">
      {retryable ? <Button size="xs" variant="outline" disabled={busy} onClick={onRetry}>Try again</Button> : null}
      <Button size="xs" variant="ghost" onClick={onDetails}>What happened</Button>
    </div>
  </section>
}

/** Each capability on its own line, so a ready page with a missing model says which part is missing. */
export function SetupReadiness({ capabilities, names = {}, label = "Readiness", onAction }: {
  capabilities: CapabilityStatus[]
  names?: Record<string, string>
  label?: string
  /** Carries out a capability's next action, such as a sign-in. Without it they are not offered. */
  onAction?(action: NextAction): void
}) {
  if (!capabilities.length) return <p className="setup-note">No capabilities reported yet.</p>
  return <ul className="setup-readiness" aria-label={label}>
    {capabilities.map((capability, index) => {
      const health = healthOf(capability.health)
      const name = names[capability.id] ?? capability.id
      return <li key={index}>
        <span className="setup-readiness-name">{name}</span>
        <StateLabel tone={health.tone}>{health.text}</StateLabel>
        {capability.detail ? <span className="setup-note">{capability.detail}</span> : null}
        {onAction ? list(capability.nextActions).map(action => <Button key={action.kind} size="xs" variant="outline" aria-label={`${nextActionText(action)}: ${name}`} onClick={() => onAction(action)}>{nextActionText(action)}</Button>) : null}
      </li>
    })}
  </ul>
}
