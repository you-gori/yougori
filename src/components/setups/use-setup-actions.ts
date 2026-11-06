import { useCallback, useRef, useState } from "react"
import { setupFeed } from "@/api/setups/progress"
import { errorText, isUnavailable, newOperationId, SetupCommandError, setupsApi, type SetupLifecycleAction } from "@/api/setups/setups-api"
import type { OperationBrief, SetupDetailView, SetupPlan, SetupSummary } from "@/api/setups/types"

/** Start, stop, refresh and remove for one setup, shared by its card and its own view.
 *
 *  Start and stop act at once and keep data. Remove first asks the engine for its review and
 *  removes only when that review is confirmed. Every action carries the revision it was read at,
 *  so two windows can't race each other, and its own operation id: made for that action (and that
 *  reviewed plan), sent again only when the same thing is retried after a failure that may be
 *  retried, so a retry joins the first try instead of starting a second one.
 */
export function useSetupActions(summary: SetupSummary, detail: SetupDetailView | undefined) {
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const [removal, setRemoval] = useState<SetupPlan | null>(null)
  const [repair, setRepair] = useState<SetupPlan | null>(null)
  const [agreed, setAgreed] = useState<string[]>([])
  const ids = useRef(new Map<string, string>())

  /** The id for one action: the same one while that action is being retried. */
  const idFor = (key: string) => {
    const known = ids.current.get(key)
    if (known) return known
    const made = newOperationId()
    ids.current.set(key, made)
    return made
  }

  const act = useCallback(async (label: string, work: () => Promise<unknown>, key?: string) => {
    if (busy) return false
    setBusy(label)
    setError("")
    try {
      await work()
      if (key) ids.current.delete(key)
      await setupFeed.refresh(summary.setupId)
      return true
    } catch (reason) {
      if (key && !(reason instanceof SetupCommandError && reason.retryable)) ids.current.delete(key)
      setError(isUnavailable(reason) ? "This isn't available in this build of Yougori yet. Nothing was changed."
        : reason instanceof SetupCommandError && reason.code === "setup_busy" ? "Another change to this setup is still running. Nothing new was started."
        : reason instanceof SetupCommandError && reason.code === "legacy_managed" ? "Change this grid from its own tab; setup actions can't change it yet."
        : errorText(reason))
      return false
    } finally {
      setBusy("")
    }
  }, [busy, summary.setupId])

  const lifecycle = useCallback((action: SetupLifecycleAction, label: string, operationId?: string) => {
    // Retry and reconcile act on an operation that already exists; start and stop make one.
    if (operationId) return act(label, () => setupsApi.action(summary.setupId, action, { operationId }))
    const key = `${action}:${detail?.revision ?? ""}`
    return act(label, () => setupsApi.action(summary.setupId, action, { expectedRevision: detail?.revision ?? null, operationId: idFor(key) }), key)
  }, [act, summary.setupId, detail?.revision])

  const reviewRemoval = useCallback(async () => {
    if (busy) return
    setBusy("Working out what removing it does")
    setError("")
    try {
      setRemoval(await setupsApi.reviewRemoval(summary.setupId, detail?.revision ?? null))
      setAgreed([])
    } catch (reason) {
      setError(isUnavailable(reason) ? "Removing setups isn't available in this build of Yougori yet. Nothing was changed." : errorText(reason))
    } finally {
      setBusy("")
    }
  }, [busy, summary.setupId, detail?.revision])

  const confirmRemoval = useCallback(async () => {
    const plan = removal
    if (!plan) return
    const key = `remove:${plan.digest}`
    const offered = new Set((plan.consents ?? []).map(consent => consent.id))
    if (await act("Removing", () => setupsApi.apply(plan, idFor(key), undefined, agreed.filter(id => offered.has(id))), key)) setRemoval(null)
  }, [act, removal, agreed])

  const reviewRepair = useCallback(async () => {
    if (busy) return
    setBusy("Working out what repairing it does")
    setError("")
    try {
      setRepair(await setupsApi.reviewRepair(summary.setupId, detail?.revision ?? null))
      setAgreed([])
    } catch (reason) {
      setError(isUnavailable(reason) ? "Repairing setups isn't available in this build of Yougori yet. Nothing was changed." : errorText(reason))
    } finally {
      setBusy("")
    }
  }, [busy, summary.setupId, detail?.revision])

  const confirmRepair = useCallback(async () => {
    const plan = repair
    if (!plan) return
    const key = `repair:${plan.digest}`
    const offered = new Set((plan.consents ?? []).map(consent => consent.id))
    if (await act("Repairing", () => setupsApi.apply(plan, idFor(key), undefined, agreed.filter(id => offered.has(id))), key)) setRepair(null)
  }, [act, repair, agreed])

  const agree = useCallback((id: string, on: boolean) => setAgreed(current => on ? [...current.filter(one => one !== id), id] : current.filter(one => one !== id)), [])

  const cancel = useCallback((operationId: string) => act("Cancelling", () => setupsApi.cancel(operationId)), [act])

  return {
    busy, error, removal, repair, agreed, agree, act, lifecycle,
    reviewRemoval, confirmRemoval, keep: () => setRemoval(null),
    reviewRepair, confirmRepair, keepRepair: () => setRepair(null), cancel,
  }
}

/** The change that last ended on a setup without finishing, when nothing is running on it now.
 *  The engine clears a setup's current operation when it ends, so this is where a failure is
 *  still seen: in its record of recent operations. */
export function lastFailure(summary: SetupSummary, detail: SetupDetailView | undefined): OperationBrief | null {
  if (summary.currentOperation) return null
  const latest = detail?.operations?.[0]
  return latest && latest.state === "failed" ? latest : null
}

/** A setup left part way: being created, changed or removed, with nothing running on it. */
export const stoppedPartWay = (summary: SetupSummary) =>
  !summary.currentOperation && (summary.state === "creating" || summary.state === "updating" || summary.state === "removing")
