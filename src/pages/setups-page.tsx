import { useState } from "react"
import { PageHeader, PillButton } from "@/components/prompx"
import { Button } from "@/components/ui/button"
import { CATALOGUE } from "@/api/setups/catalogue"
import { isMoving, useSetupFeed, type OperationView } from "@/api/setups/progress"
import type { NextAction, SetupDetailView, SetupSummary, SourceRef } from "@/api/setups/types"
import { SetupBuilderScope } from "@/components/setups/setup-builder-provider"
import { useSetupBuilder } from "@/components/setups/builder-context"
import { SetupDetailView as SetupDetailShell, type DetailTab } from "@/components/setups/setup-detail"
import { StateLabel } from "@/components/setups/setup-marks"
import { SetupOutputs, SetupProgress, SetupReadiness } from "@/components/setups/setup-views"
import { SetupRemoval } from "@/components/setups/setup-removal"
import { lifecycleOf, healthOf } from "@/components/setups/setup-words"
import { lastFailure, stoppedPartWay, useSetupActions } from "@/components/setups/use-setup-actions"
import { ALL_ACTIONS, GENERAL_ACTIONS, useNextActions } from "@/components/setups/use-next-actions"
import { LastFailure } from "@/components/setups/setup-views"
import "@/components/setups/setups.css"

/** My setups: every template set up on this computer.
 *
 *  Each setup says where it is in its life, how each of its capabilities is doing, how far the
 *  operation on it is, and what can be done next, and opens into its own view with Overview, its
 *  capabilities, Activity and Settings. Everything here is read from the engine's one shared feed;
 *  nothing on this page asks on its own timer.
 */

const NAMES = Object.fromEntries(CATALOGUE.map(capability => [capability.id, capability.name]))

function sourceLine(source: SourceRef | null | undefined) {
  if (!source) return null
  if (source.kind === "hub") return `From hub/${source.publisher}/${source.name}@${source.version}`
  if (source.kind === "local_folder") return "From a folder on this computer"
  return "From another setup"
}

type Opened = { setupId: string; tab?: DetailTab }

function Outputs({ detail }: { detail: SetupDetailView | undefined }) {
  return <SetupOutputs outputs={detail?.outputs} />
}

function SetupItem({ summary, detail, operation, onOpen }: {
  summary: SetupSummary
  detail: SetupDetailView | undefined
  operation: OperationView | null
  onOpen(tab?: DetailTab): void
}) {
  const builder = useSetupBuilder()
  const actions = useSetupActions(summary, detail)
  const [cancelling, setCancelling] = useState(false)
  const configure = () => builder.open({ mode: "configure", setupId: summary.setupId, setupName: summary.name })
  const next = useNextActions({ onActivity: () => onOpen("activity"), onConfigure: configure })
  const failed = lastFailure(summary, detail)
  const state = stoppedPartWay(summary) ? { text: "Stopped part way", tone: "attention" as const } : lifecycleOf(summary.state)
  const health = summary.health ? healthOf(summary.health) : null
  // The engine says which actions a setup offers now; until its detail is read, none are offered.
  const may = (action: "start" | "stop" | "remove") => detail?.actions?.includes(action) ?? false
  const moving = isMoving(operation)
  const operationId = summary.currentOperation?.operationId ?? null

  function onOperation(action: NextAction) {
    if (GENERAL_ACTIONS.has(action.kind)) { next.act(action); return }
    if (!operationId) return
    if (action.kind === "cancel") { setCancelling(true); return }
    if (action.kind === "review") { configure(); return }
    const target = (action.kind === "continue" || action.kind === "reconcile") && action.operation ? action.operation : operationId
    void actions.lifecycle(action.kind === "reconcile" ? "reconcile" : "retry", action.kind === "reconcile" ? "Checking what happened" : "Trying again", target)
  }

  return <article className="setup-item" aria-labelledby={`setup-${summary.setupId}-name`}>
    <div className="setup-item-head">
      <h3 className="setup-item-name" id={`setup-${summary.setupId}-name`}>{summary.name}</h3>
      <StateLabel tone={state.tone}>{state.text}</StateLabel>
      {health && health.tone !== "ok" ? <StateLabel tone={health.tone}>{health.text}</StateLabel> : null}
      <p className="setup-item-source">{sourceLine(summary.source)}</p>
    </div>
    {detail ? <SetupReadiness capabilities={detail.capabilities} names={NAMES} label={`Readiness of ${summary.name}`} onAction={next.act} /> : <p role="status" className="setup-note">Reading how it is doing…</p>}
    {operation && (moving || operation.state === "failed") ? <SetupProgress operation={operation} onAction={onOperation} handles={ALL_ACTIONS} busy={Boolean(actions.busy)} idPrefix={`setup-${summary.setupId}-operation`} announce={false} agreeFor={operationId ? { setupId: summary.setupId, operationId } : null} /> : null}
    {failed ? <LastFailure operation={failed} busy={Boolean(actions.busy)} onRetry={() => void actions.lifecycle("retry", "Trying again", failed.operationId)} onDetails={() => onOpen("activity")} /> : null}
    {cancelling && operationId ? <p className="setup-confirm" role="group" aria-label={`Cancel the change to ${summary.name}?`}>
      <span>Cancel it? What is already done is kept.</span>
      <Button size="xs" variant="destructive-outline" onClick={() => { setCancelling(false); void actions.cancel(operationId) }}>Cancel the change</Button>
      <Button size="xs" variant="ghost" onClick={() => { document.getElementById(`setup-${summary.setupId}-operation-cancel`)?.focus(); setCancelling(false) }}>Keep going</Button>
    </p> : null}
    <Outputs detail={detail} />
    {next.said ? <p role="status" className="setup-callout">{next.said}</p> : null}
    {actions.error ? <p role="alert" className="grid-error">{actions.error}</p> : null}
    {actions.busy ? <p role="status" className="setup-note">{actions.busy}…</p> : null}
    {actions.removal ? <SetupRemoval
      name={summary.name} plan={actions.removal} names={NAMES} agreed={actions.agreed} onAgree={actions.agree} busy={Boolean(actions.busy)}
      onRemove={() => void actions.confirmRemoval()}
      onKeep={() => { actions.keep(); requestAnimationFrame(() => document.getElementById(`setup-${summary.setupId}-remove`)?.focus()) }}
    /> : <div className="setup-actions">
      <Button size="xs" data-setup-open={summary.setupId} onClick={() => onOpen()} aria-label={`Open ${summary.name}`}>Open</Button>
      <Button size="xs" variant="outline" disabled={moving} onClick={configure}>Configure</Button>
      <Button size="xs" variant="outline" disabled={moving} onClick={() => builder.open({ mode: "configure", setupId: summary.setupId, setupName: summary.name, addCapability: true })}>Add capability</Button>
      {may("start") ? <Button size="xs" variant="outline" disabled={Boolean(actions.busy) || moving} onClick={() => void actions.lifecycle("start", "Starting")}>Start</Button> : null}
      {may("stop") ? <Button size="xs" variant="outline" disabled={Boolean(actions.busy) || moving} onClick={() => void actions.lifecycle("stop", "Stopping")}>Stop</Button> : null}
      {may("remove") ? <Button id={`setup-${summary.setupId}-remove`} size="xs" variant="ghost" disabled={Boolean(actions.busy) || moving} onClick={() => void actions.reviewRemoval()}>Remove…</Button> : null}
    </div>}
  </article>
}

function SetupsBody({ highlight, highlightTab }: { highlight: string | null; highlightTab?: DetailTab }) {
  const builder = useSetupBuilder()
  const feed = useSetupFeed()
  // A linked setup opens straight into its own view.
  const [opened, setOpened] = useState<Opened | null>(() => highlight ? { setupId: highlight, tab: highlightTab } : null)
  const setups = (feed.setups ?? []).filter(setup => !setup.adoptedLegacy)
  const nothing = feed.setups !== null || feed.unavailable ? !setups.length : false

  if (opened) {
    return <section className="app-page" aria-label="My setups">
      <div className="app-page-body">
        <SetupDetailShell
          key={opened.setupId}
          setupId={opened.setupId}
          initialTab={opened.tab}
          onBack={() => {
            const back = opened.setupId
            setOpened(null)
            requestAnimationFrame(() => document.querySelector<HTMLElement>(`[data-setup-open="${back}"]`)?.focus())
          }}
        />
      </div>
    </section>
  }

  return <section className="app-page" aria-label="My setups">
    <PageHeader
      title="My setups."
      lead="The templates you've set up on this computer. Each one shows what is ready and what needs you."
      actions={<>
        <PillButton tone="dark" onClick={() => builder.open({ mode: "run" })}>Run a template</PillButton>
        <PillButton tone="light" onClick={() => builder.open({ mode: "create" })}>Create template</PillButton>
      </>}
    />
    <div className="app-page-body">
      {feed.unavailable ? <p className="setup-callout" role="note">Setups made from templates aren't available in this build of Yougori yet. Your sandboxes work as before.</p> : null}
      {/* While the engine keeps failing, the feed waits longer between tries and says so in one
          line, instead of the error on every try. */}
      {feed.breaker?.open && feed.breaker.message ? <p role="status" className="setup-callout">{feed.breaker.message}</p>
        : feed.error ? <p role="alert" className="grid-error">Yougori couldn't read your setups: {feed.error} It tries again by itself.</p> : null}
      {nothing ? <div className="grid-empty">
        <p className="grid-empty-title">Nothing set up yet</p>
        <p className="grid-empty-hint">Run a template to set up a whole working setup, or create your own. Single sandboxes stay under My computer.</p>
        <div className="setup-actions">
          <PillButton tone="dark" onClick={() => builder.open({ mode: "run" })}>Run a template</PillButton>
          <PillButton tone="light" onClick={() => builder.open({ mode: "create" })}>Create template</PillButton>
        </div>
      </div> : <div className="setups-sections">
        {feed.setups === null && !feed.unavailable && !feed.error ? <p role="status" className="setup-note">Reading your setups…</p> : null}
        {setups.length ? <section className="setups-section" aria-labelledby="setups-heading">
          <h2 id="setups-heading" className="grids-heading">Setups <span>{setups.length === 1 ? "one on this computer" : `${setups.length} on this computer`}</span></h2>
          <div className="setups-list">
            {setups.map(setup => <SetupItem
              key={setup.setupId}
              summary={setup}
              detail={feed.details[setup.setupId]}
              operation={setup.currentOperation ? feed.operations[setup.currentOperation.operationId] ?? null : null}
              onOpen={tab => setOpened({ setupId: setup.setupId, tab })}
            />)}
          </div>
        </section> : null}
      </div>}
    </div>
  </section>
}

export function SetupsPage({ highlight = null, highlightTab }: {
  highlight?: string | null
  highlightTab?: DetailTab
}) {
  return <SetupBuilderScope><SetupsBody key={`${highlight ?? ""}:${highlightTab ?? ""}`} highlight={highlight} highlightTab={highlightTab} /></SetupBuilderScope>
}
