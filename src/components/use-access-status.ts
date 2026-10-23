import { useCallback, useEffect, useRef, useSyncExternalStore } from "react"
import { accessApi, type AccessStatus } from "@/api/access-api"
import { toastManager } from "@/components/ui/toast"

/** The Access Grid's status, shared by the sidebar and the page so the hub is asked once: each
 *  user says how often it wants news, and the most eager one sets the pace. */
interface Snapshot { status: AccessStatus | null; error: string }

let snapshot: Snapshot = { status: null, error: "" }
const listeners = new Set<() => void>()
const paces = new Map<symbol, number>()
let timer = 0
let pending: Promise<void> | null = null

function publish(next: Snapshot) {
  snapshot = next
  for (const listener of listeners) listener()
}

function refresh(): Promise<void> {
  pending ??= accessApi.status()
    .then(status => publish({ status, error: "" }))
    .catch((reason: unknown) => publish({ status: snapshot.status, error: reason instanceof Error ? reason.message : String(reason) }))
    .finally(() => { pending = null })
  return pending
}

function schedule() {
  window.clearTimeout(timer)
  if (!paces.size) return
  timer = window.setTimeout(() => { void refresh().finally(schedule) }, Math.min(...paces.values()))
}

function subscribe(listener: () => void) {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

export function useAccessStatus(every: number) {
  const current = useSyncExternalStore(subscribe, () => snapshot)
  useEffect(() => {
    const key = Symbol("access-status")
    paces.set(key, every)
    void refresh()
    schedule()
    return () => { paces.delete(key); schedule() }
  }, [every])
  const again = useCallback(() => refresh(), [])
  return { status: current.status, error: current.error, refresh: again }
}

/** The sidebar's line under "Access Grid". */
export function accessHint(status: AccessStatus | null) {
  const waiting = status?.me?.overview?.waiting.length ?? 0
  if (status?.hub) return `${status.hub.people} ${status.hub.people === 1 ? "person" : "people"} · ${status.hub.credentials} ${status.hub.credentials === 1 ? "credential" : "credentials"}${waiting ? ` · ${waiting} waiting` : ""}`
  if (status?.member) return waiting ? `${waiting} waiting for approval` : `Signed in to ${status.member.company}`
  return "Not set up"
}

/** Tells an approver once about each request that starts waiting for them, wherever they are in the app. */
export function useAccessApprovalNotices(status: AccessStatus | null) {
  const told = useRef(new Set<string>())
  useEffect(() => {
    const me = status?.me
    const decides = me?.person.permission === "approver" || me?.person.permission === "admin"
    if (!me || !decides) return
    for (const request of me.overview?.waiting ?? []) {
      if (told.current.has(request.id)) continue
      told.current.add(request.id)
      if (request.person === me.person.username && !me.canApproveOwn) continue
      const what = request.kind === "reveal" ? `to see the value of ${request.credential}` : `to ${request.method} with ${request.credential}`
      toastManager.add({ title: `${request.person}'s agent is waiting for approval`, description: `${request.agent || "An agent"} asks ${what}. Decide in Access Grid.`, type: "warning" })
    }
  }, [status])
}
