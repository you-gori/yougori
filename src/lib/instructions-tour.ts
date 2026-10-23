import { useSyncExternalStore } from "react"

export const overviewSteps = ["welcome", "stats", "graph", "node-controls", "configuration", "service-ports", "connections", "my-pc", "internet-overview", "local-network", "public-access", "backups", "cloud", "theme", "settings", "environment-types", "windows-overview"] as const
export const practiceSteps = ["create-open", "create-type", "create-name", "create-image", "create-resources", "create-submit", "created", "internet-connect", "start", "first-window", "terminal", "tabs", "install", "install-running", "new-terminal", "run-codex", "new-window", "second-window", "window-switcher", "environment-switcher", "demo-start", "demo-return", "demo-port-open", "demo-port-add", "demo-publish", "demo-link", "demo-visit", "done"] as const
export const tourSteps = [...overviewSteps, ...practiceSteps] as const
export type TourStep = typeof tourSteps[number]
export interface InstructionsTour {
  version: 1; run: string; step: TourStep; owner: string; home: string; updated: number; revision: number; active: boolean
  environmentId?: string; pendingName?: string; handoffAt?: number
}
export const tourStorageKey = "yougori.instructions.v1"
export const instructionsSeenKey = "yougori.instructions.seen.v1"
let firstLaunchChecked = false
const eventName = "yougori-instructions-change"
const nativeEventName = "yougori:instructions"
const born = Date.now()
export const tourWindowId = typeof window === "undefined" ? "server" : crypto.randomUUID()
const listeners = new Set<() => void>()
let snapshot: InstructionsTour | null = null
let loaded = false

export function parseTour(value: unknown, now = Date.now()): InstructionsTour | null {
  if (!value || typeof value !== "object") return null
  const v = value as InstructionsTour
  if (v.version !== 1 || !tourSteps.includes(v.step) || typeof v.active !== "boolean" || !Number.isSafeInteger(v.updated) || v.updated > now + 60_000 || now - v.updated > 24 * 60 * 60 * 1000 || !Number.isSafeInteger(v.revision) || v.revision < 0) return null
  for (const id of [v.run, v.owner, v.home]) if (typeof id !== "string" || !/^[\w-]{1,80}$/.test(id)) return null
  if (v.environmentId !== undefined && (typeof v.environmentId !== "string" || !/^[\w-]{1,128}$/.test(v.environmentId))) return null
  if (v.pendingName !== undefined && (typeof v.pendingName !== "string" || v.pendingName.length > 80)) return null
  if (v.handoffAt !== undefined && (!Number.isSafeInteger(v.handoffAt) || v.handoffAt > now + 60_000)) return null
  return { version: 1, run: v.run, step: v.step, owner: v.owner, home: v.home, updated: v.updated, revision: v.revision, active: v.active, environmentId: v.environmentId, pendingName: v.pendingName, handoffAt: v.handoffAt }
}
function readSaved() {
  try { return parseTour(JSON.parse(localStorage.getItem(tourStorageKey) || "null")) } catch { return null }
}
export function getTour() {
  if (!loaded && typeof window !== "undefined") { loaded = true; snapshot = readSaved() }
  return snapshot
}
function receive(value: unknown) {
  const next = parseTour(value), previous = getTour()
  if (!next || (previous && (previous.run === next.run ? previous.revision >= next.revision : previous.updated > next.updated))) return
  snapshot = next
  for (const notify of listeners) notify()
}
function changed(event: Event) { receive((event as CustomEvent).detail) }
function storage(event: StorageEvent) { if (event.key === tourStorageKey) receive(readSaved()) }
function subscribe(notify: () => void) {
  listeners.add(notify)
  if (listeners.size === 1) { window.addEventListener(eventName, changed); window.addEventListener("storage", storage) }
  return () => { listeners.delete(notify); if (!listeners.size) { window.removeEventListener(eventName, changed); window.removeEventListener("storage", storage) } }
}
export function useInstructionsTour() { return useSyncExternalStore(subscribe, getTour, () => null) }
export function ownsTour(tour: InstructionsTour | null) { return Boolean(tour?.active && tour.owner === tourWindowId) }
function write(next: InstructionsTour) {
  snapshot = next; loaded = true
  try { localStorage.setItem(tourStorageKey, JSON.stringify(next)) } catch { /* The current-window tour still works if storage is unavailable. */ }
  for (const notify of listeners) notify()
  if ("__TAURI_INTERNALS__" in window) void import("@tauri-apps/api/event").then(({ emit }) => emit(nativeEventName, next)).catch(() => undefined)
}
export function startInstructions() {
  try { localStorage.setItem(instructionsSeenKey, "1") } catch { /* Replay remains available without storage. */ }
  write({ version: 1, run: crypto.randomUUID(), step: "welcome", owner: tourWindowId, home: tourWindowId, active: true, updated: Date.now(), revision: 0 })
}
// Called only after the main dashboard mounts, never from a guest window.
export function startFirstLaunchInstructions() {
  if (firstLaunchChecked) return
  firstLaunchChecked = true
  try {
    const seen = localStorage.getItem(instructionsSeenKey) === "1"
    // Older versions saved tours without a separate permanent seen marker.
    const previousTour = localStorage.getItem(tourStorageKey) !== null
    localStorage.setItem(instructionsSeenKey, "1")
    if (seen || previousTour) return
  } catch { /* Show once in this window if persistence is unavailable. */ }
  startInstructions()
}
export function changeTour(changes: Partial<Pick<InstructionsTour, "step" | "active" | "environmentId" | "pendingName" | "handoffAt" | "owner">>) {
  const current = getTour()
  if (!current?.active) return
  write({ ...current, ...changes, updated: Date.now(), revision: current.revision + 1 })
}
export function stopInstructions() { changeTour({ active: false }) }
export function skipInstructions() {
  const tour = getTour()
  if (!tour?.active) return
  if ((overviewSteps as readonly string[]).includes(tour.step)) changeTour({ step: practiceSteps[0] })
  else stopInstructions()
}
export function trackTourCreation(name: string) {
  const tour = getTour()
  if (ownsTour(tour) && tour?.step.startsWith("create-")) changeTour({ pendingName: name })
}
export function tourEnvironmentCreated(id: string, name: string) {
  const tour = getTour()
  if (ownsTour(tour) && tour?.step.startsWith("create-") && tour.pendingName === name) changeTour({ step: "created", environmentId: id, pendingName: undefined })
}
export function tourEnvironmentCreationFailed(name: string) {
  const tour = getTour()
  if (ownsTour(tour) && tour?.step.startsWith("create-") && tour.pendingName === name) changeTour({ pendingName: undefined })
}
export function prepareTourWindow(id: string) {
  const tour = getTour()
  if (!ownsTour(tour) || tour?.environmentId !== id) return
  if (tour.step === "start" || tour.step === "new-window") changeTour({ step: tour.step === "start" ? "first-window" : "second-window", handoffAt: Date.now() })
}
export function tourWindowFailed(id: string) {
  const tour = getTour()
  if (!ownsTour(tour) || tour?.environmentId !== id) return
  if (tour.step === "first-window" || tour.step === "second-window") changeTour({ step: tour.step === "first-window" ? "start" : "new-window", handoffAt: undefined })
}
export function claimWindowTour(id: string) {
  const tour = getTour()
  // Only the newly opened window may claim a handoff, never another existing
  // viewer of the same environment or an unrelated node's window.
  if (!tour?.active || tour.environmentId !== id || tour.owner === tourWindowId || !tour.handoffAt || born < tour.handoffAt) return
  if (tour.step === "first-window" || tour.step === "second-window") changeTour({ step: tour.step === "first-window" ? "terminal" : "window-switcher", owner: tourWindowId, handoffAt: undefined })
}
export function tourInstallerStarted(id: string, installer: string) {
  const tour = getTour()
  if (ownsTour(tour) && tour?.environmentId === id && tour.step === "install" && installer === "codex") changeTour({ step: "install-running" })
}
export function tourTerminalOpened(id: string) {
  const tour = getTour()
  if (ownsTour(tour) && tour?.environmentId === id && tour.step === "new-terminal") changeTour({ step: "run-codex" })
}
export function returnTourHome() {
  const tour = getTour()
  if (ownsTour(tour) && tour?.step === "demo-return") changeTour({ owner: tour.home, step: "demo-port-open", handoffAt: undefined })
}
export function isWebsiteTour(id: string, ...steps: TourStep[]) {
  const tour = getTour()
  return Boolean(ownsTour(tour) && tour?.environmentId === id && steps.includes(tour.step))
}
export function tourPortAdded(id: string, port: number) {
  if (port === 3000 && isWebsiteTour(id, "demo-port-add")) changeTour({ step: "demo-publish" })
}
export function tourWebsitePublished(id: string, publication: { port: number; kind: string; status: string; cloudflareAccount?: boolean; urls: string[] }) {
  if (isWebsiteTour(id, "demo-publish") && publication.port === 3000 && publication.kind === "cloudflare" && !publication.cloudflareAccount && publication.status === "active" && publication.urls.some(url => url.startsWith("https://"))) changeTour({ step: "demo-link" })
}
export function tourWebsiteOpened(id: string, port: number, quick: boolean) {
  if (port === 3000 && quick && isWebsiteTour(id, "demo-link")) changeTour({ step: "demo-visit" })
}
export async function connectNativeTourEvents() {
  if (!("__TAURI_INTERNALS__" in window)) return () => undefined
  const { listen } = await import("@tauri-apps/api/event")
  return listen(nativeEventName, event => receive(event.payload))
}

// Closing/reloading the home page ends its guide without leaving a phantom owner.
// A guide handed to a guest window remains active there.
if (typeof window !== "undefined") window.addEventListener("pagehide", () => {
  const tour = getTour()
  if (ownsTour(tour) && tour?.home === tourWindowId && !tour.handoffAt) stopInstructions()
})
