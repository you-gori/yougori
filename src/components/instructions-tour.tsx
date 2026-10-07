import { useCallback, useEffect, useLayoutEffect, useRef, useState } from "react"
import { createPortal } from "react-dom"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { platformApi } from "@/api/platform-api"
import { buildHelloWebsite } from "@/lib/tour-website"
import { returnTourHome } from "@/lib/instructions-tour"
import { changeTour, claimWindowTour, connectNativeTourEvents, getTour, overviewSteps, ownsTour, practiceSteps, skipInstructions, startInstructions, stopInstructions, tourWindowId, useInstructionsTour, type InstructionsTour } from "@/lib/instructions-tour"
import { clipTourRect, placeTourCard, type TourRect } from "@/lib/tour-position"
import { tourExplanation } from "./instructions-tour-content"
import "./instructions-tour.css"

function visible(element: Element): element is HTMLElement {
  return element instanceof HTMLElement && element.getClientRects().length > 0 && !element.closest('[hidden], [inert], [aria-hidden="true"]') && getComputedStyle(element).visibility !== "hidden"
}
function find(selector: string) { return [...document.querySelectorAll(selector)].find(visible) }
const focusable = 'button:not(:disabled), input:not(:disabled), textarea:not(:disabled), [role="slider"], [role="menuitem"], [role="option"], [tabindex="0"]'

export default function InstructionsTourHost({ environmentId, onCreate }: { environmentId?: string; onCreate?(): void }) {
  const tour = useInstructionsTour()
  useEffect(() => {
    let disposed = false, unlisten = () => undefined as void
    void connectNativeTourEvents().then(stop => { if (disposed) stop(); else unlisten = stop }).catch(() => undefined)
    return () => { disposed = true; unlisten() }
  }, [])
  useEffect(() => { if (environmentId) claimWindowTour(environmentId) }, [environmentId, tour])
  if (!tour?.active) return null
  if (!ownsTour(tour)) return (!environmentId && tour.home === tourWindowId) || (environmentId === tour.environmentId && tour.owner === tour.home) ? <div className="tour-away" role="status" data-tour-ui><span>{tour.owner === tour.home ? "Continue in the main Yougori window. Your website runs in the container." : "Instructions continued in your container window."}</span><Button size="sm" variant="ghost" onClick={skipInstructions}>{(overviewSteps as readonly string[]).includes(tour.step) ? "Skip to hands-on" : "Skip"}</Button></div> : null
  return <TourOverlay key={tour.run} tour={tour} onCreate={onCreate} />
}

function TourOverlay({ tour, onCreate }: { tour: InstructionsTour; onCreate?(): void }) {
  const { state } = usePlatform()
  const creating = tour.step === "create-submit" && Boolean(tour.pendingName)
  const pendingEnvironment = creating ? state?.environments.find(e => e.name === tour.pendingName) : undefined
  const copy: ReturnType<typeof tourExplanation> = creating ? {
    title: "Creating your container", body: "Your container is being prepared. Its node shows the progress, and this guide will continue when it is ready.",
    target: pendingEnvironment ? `[data-environment-id="${pendingEnvironment.id}"]` : "[data-environment-canvas]", next: "Creating…",
    hint: "You can Skip to keep using Yougori while creation finishes.",
  } : tourExplanation(tour.step, tour)
  const card = useRef<HTMLDivElement>(null)
  const targets = useRef<HTMLElement[]>([])
  const [layout, setLayout] = useState<{ rects: TourRect[]; width: number; height: number; cardHeight: number }>({ rects: [], width: window.innerWidth, height: window.innerHeight, cardHeight: 290 })
  const [revision, setRevision] = useState(0)
  const [missing, setMissing] = useState(false)
  const [checking, setChecking] = useState(false)
  const [websiteError, setWebsiteError] = useState("")
  const [websiteAttempt, setWebsiteAttempt] = useState(0)
  const previousFocus = useRef(document.activeElement instanceof HTMLElement ? document.activeElement : null)
  const environment = state?.environments.find(e => e.id === tour.environmentId)
  const explanation = useRef(copy); explanation.current = copy
  const lastStep = useRef("")

  useEffect(() => () => {
    // A form opened during the guide must keep its draft when Skip restores
    // modal behavior. Focusing the old toolbar trigger would dismiss the form.
    const target = document.querySelector<HTMLElement>('[data-create-environment] input:not(:disabled), [data-add-service-port] input:not(:disabled), [data-service-options] button:not(:disabled)') ?? (previousFocus.current?.isConnected ? previousFocus.current : document.querySelector<HTMLElement>('[data-tour="instructions"]'))
    if (target?.isConnected) target.focus({ preventScroll: true })
  }, [])

  useLayoutEffect(() => {
    let frame = 0, disposed = false, scrolled: Element | undefined
    const refresh = () => {
      frame = 0
      if (disposed) return
      const main = find(explanation.current.target)
      const extras = (explanation.current.extra ?? []).map(find).filter((e): e is HTMLElement => Boolean(e))
      const fallback = find('[data-create-environment]') ?? find('[data-environment-canvas]') ?? find('[data-workspace-toolbar]')
      const elements = [...new Set([main ?? fallback, ...extras].filter((e): e is HTMLElement => Boolean(e)))]
      targets.current = [...new Set([main, ...extras].filter((e): e is HTMLElement => Boolean(e)))]
      const anchor = main ?? fallback
      // Scroll only on step entry / first late target, not on telemetry or each
      // drag frame. A user can still scroll a long dialog while reading a tip.
      if (anchor && scrolled !== anchor) {
        scrolled = anchor
        const rect = anchor.getBoundingClientRect()
        if (rect.top < 72 || rect.bottom > window.innerHeight - 12) anchor.scrollIntoView({ block: rect.height > window.innerHeight / 2 ? "start" : "center", inline: "nearest", behavior: "instant" })
      }
      const width = window.innerWidth, height = window.visualViewport?.height ?? window.innerHeight
      const rects = elements.map(e => clipTourRect(e.getBoundingClientRect(), width, height)).filter(r => r.width > 1 && r.height > 1)
        .filter((r, index, all) => !all.some((other, j) => index !== j && other.left <= r.left && other.top <= r.top && other.left + other.width >= r.left + r.width && other.top + other.height >= r.top + r.height && (other.width > r.width || other.height > r.height || j < index)))
      const next = { rects, width, height, cardHeight: card.current?.getBoundingClientRect().height ?? 290 }
      setLayout(current => JSON.stringify(current) === JSON.stringify(next) ? current : next)
      setMissing(!main)
      setRevision(value => value + 1)
    }
    const schedule = () => { if (!frame) frame = requestAnimationFrame(refresh) }
    const resized = () => { scrolled = undefined; schedule() }
    const mutations = new MutationObserver(records => { if (records.some(r => !(r.target instanceof Element && r.target.closest('[data-tour-ui]')))) schedule() })
    mutations.observe(document.body, { childList: true, subtree: true, attributes: true, attributeFilter: ["style", "class", "aria-pressed", "aria-expanded", "hidden", "data-create-kind"] })
    const resize = new ResizeObserver(schedule)
    if (card.current) resize.observe(card.current)
    document.addEventListener("scroll", schedule, true); document.addEventListener("input", schedule, true); document.addEventListener("change", schedule, true)
    window.addEventListener("resize", resized); window.visualViewport?.addEventListener("resize", resized)
    refresh()
    return () => { disposed = true; cancelAnimationFrame(frame); mutations.disconnect(); resize.disconnect(); document.removeEventListener("scroll", schedule, true); document.removeEventListener("input", schedule, true); document.removeEventListener("change", schedule, true); window.removeEventListener("resize", resized); window.visualViewport?.removeEventListener("resize", resized) }
  }, [tour.step])

  useEffect(() => {
    if (lastStep.current !== tour.step) { lastStep.current = tour.step; card.current?.focus({ preventScroll: true }) }
    const allow = (target: EventTarget | null) => target instanceof Element && (target.closest('[data-tour-ui]') || (explanation.current.interactive && targets.current.some(el => el.contains(target))))
    const pointer = (event: Event) => { if (!allow(event.target)) { event.preventDefault(); event.stopImmediatePropagation() } }
    const key = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        // Let an open picker/menu close first. Escape follows the visible Skip
        // action; holding it must not skip both stages with one keypress.
        if (find('[data-slot="combobox-popup"], [data-tour="installer-menu"]')) return
        event.preventDefault(); event.stopImmediatePropagation(); if (!event.repeat) skipInstructions(); return
      }
      if (event.key !== "Tab") return
      const areas = [...(explanation.current.interactive ? targets.current : []), card.current].filter((e): e is HTMLElement => Boolean(e))
      const items = [...new Set(areas.flatMap(el => [el.matches(focusable) ? el : null, ...el.querySelectorAll<HTMLElement>(focusable)].filter((e): e is HTMLElement => Boolean(e) && visible(e!) && e!.tabIndex >= 0)))]
      if (!items.length) { event.preventDefault(); card.current?.focus(); return }
      const index = items.indexOf(document.activeElement as HTMLElement)
      event.preventDefault(); event.stopImmediatePropagation()
      items[(index + (event.shiftKey ? -1 : 1) + items.length) % items.length]?.focus()
    }
    document.addEventListener("pointerdown", pointer, true); document.addEventListener("click", pointer, true); document.addEventListener("keydown", key, true)
    return () => { document.removeEventListener("pointerdown", pointer, true); document.removeEventListener("click", pointer, true); document.removeEventListener("keydown", key, true) }
  }, [tour.step])

  // Follow the actual form/port controls.
  useEffect(() => {
    if (tour.step === "create-open" && find('[data-create-environment]')) changeTour({ step: "create-type" })
    if (tour.step === "demo-port-open" && find(`[data-add-service-port="${tour.environmentId}"]`)) changeTour({ step: "demo-port-add" })
  }, [tour.step, tour.environmentId, revision])

  useEffect(() => {
    if (tour.step !== "demo-start" || !tour.environmentId || environment?.status !== "running") return
    if (environment.kind !== "container" || environment.provider !== "yougoriOci") {
      setWebsiteError("Use the default tutorial container to build this website.")
      return
    }
    let disposed = false
    setChecking(true); setWebsiteError("")
    void buildHelloWebsite(platformApi.executeEnvironmentCommand, tour.environmentId, tour.run).then(() => {
      const current = getTour()
      if (!disposed && ownsTour(current) && current?.run === tour.run && current.environmentId === tour.environmentId && current.step === "demo-start") changeTour({ step: "demo-return" })
    }).catch(error => {
      if (!disposed) setWebsiteError(error instanceof Error ? error.message : String(error))
    }).finally(() => { if (!disposed) setChecking(false) })
    return () => { disposed = true }
  }, [tour.step, tour.run, tour.environmentId, environment?.status, environment?.kind, environment?.provider, websiteAttempt])
  const inOverview = (overviewSteps as readonly string[]).includes(tour.step)
  const stageSteps = inOverview ? overviewSteps : practiceSteps
  const index = (stageSteps as readonly string[]).indexOf(tour.step)
  const formBack = !creating && ["create-name", "create-image", "create-resources", "create-submit"].includes(tour.step)
  const selectedType = document.querySelector('[data-create-environment]')?.getAttribute("data-create-kind")
  const name = (document.querySelector('[data-tour="create-name"] input') as HTMLInputElement | null)?.value.trim() ?? ""
  const missingEnvironment = Boolean(tour.environmentId && !environment)
  const needsForm = !creating && tour.step.startsWith("create-") && tour.step !== "create-open"
  const missingForm = needsForm && !document.querySelector('[data-create-environment]')
  const waiting = ["create-open", "create-submit", "start", "first-window", "install", "new-terminal", "new-window", "second-window", "demo-start", "demo-port-open", "demo-port-add", "demo-publish", "demo-link"].includes(tour.step)
  const blocked = waiting || missingEnvironment || missingForm || (tour.step === "create-type" && selectedType !== "container") || (tour.step === "create-name" && (name.length < 2 || Boolean(state?.environments.some(e => e.name.toLowerCase() === name.toLowerCase())))) || (tour.step === "internet-connect" && !environment?.networkAccess)
  const next = useCallback(() => {
    const current = getTour()
    if (!current || current.step !== tour.step || blocked) return
    if (tour.step === "done") { stopInstructions(); window.dispatchEvent(new Event("yougori-open-instruction-guides")); return }
    if (tour.step === "demo-return") { returnTourHome(); return }
    const all = [...overviewSteps, ...practiceSteps]
    changeTour({ step: all[all.indexOf(tour.step) + 1]! })
  }, [tour.step, blocked])
  const position = placeTourCard(layout.rects, layout, { width: 348, height: layout.cardHeight })
  const status = missingEnvironment ? "This tutorial's container was removed. Start over to create another, or Skip to leave the guide."
    : missingForm ? "The creation form was closed. Reopen it to continue; any draft is handled by the form."
    : tour.step === "internet-connect" && environment?.networkAccess ? "Internet access is connected. You can continue."
    : tour.step === "create-submit" ? creating ? "Preparing the container…" : "Press Create environment to begin."
    : tour.step === "create-type" && selectedType !== "container" ? "Choose Container to follow this walkthrough, or Skip to use a different type."
    : tour.step === "start" && environment?.lastError ? environment.lastError.slice(0, 400)
    : missing && tour.step === "service-ports" ? "Ports & access appears after you create a container, MicroVM or VM. Cloud environments do not use these publishing controls."
    : missing && ["node-controls", "configuration", "connections"].includes(tour.step) ? "No environment yet? These controls appear in each row after creation."
    : null
  return createPortal(<div className="tour-layer" data-tour-ui data-tour-step={tour.step}>
    <svg className="tour-dimmer" aria-hidden="true"><defs><mask id="tour-spotlight"><rect width="100%" height="100%" fill="white" />{layout.rects.map((r, i) => <rect key={i} x={r.left} y={r.top} width={r.width} height={r.height} rx={9} fill="black" />)}</mask></defs><rect width="100%" height="100%" fill="rgba(0,0,0,.62)" mask="url(#tour-spotlight)" /></svg>
    {layout.rects.map((r, i) => <div key={i} className="tour-ring" style={r} data-tour-highlight aria-hidden="true" />)}
    <div className="tour-card" ref={card} tabIndex={-1} role="dialog" aria-modal="false" aria-labelledby="tour-title" aria-describedby="tour-description" style={{ left: position.left, top: position.top, width: position.width, maxHeight: layout.height - 24 }}>
      {position.arrow ? <span className="tour-arrow" data-side={position.arrow.side} style={position.arrow.side === "left" || position.arrow.side === "right" ? { top: position.arrow.offset } : { left: position.arrow.offset }} aria-hidden="true" /> : null}
      <div className="tour-copy">
        <div className="tour-meta"><span>{inOverview ? "Look around" : "Hands-on"}</span><span>{index + 1} / {stageSteps.length}</span></div>
        <div className="tour-progress" aria-hidden="true"><span data-current={inOverview} /><span data-current={!inOverview} /></div>
        <h2 id="tour-title">{copy.title}</h2><p id="tour-description">{copy.body}</p>
        {copy.hint ? <p className="tour-hint">{copy.hint}</p> : null}
        {tour.step === "demo-start" ? <div className="tour-website">
          <p className="tour-status" role="status">{checking ? `Setting up and starting your website in ${environment?.name}…` : "One website, in your tutorial container."}</p>
          {websiteError ? <p className="tour-status" role="alert">{websiteError}</p> : null}
          {environment?.status !== "running" ? <p className="tour-status" role="status">The tutorial container is stopped. Start it from the main window; setup will continue automatically.</p> : null}
        </div> : null}
        {status ? <p className="tour-status" role="status">{status}</p> : null}
      </div>
      <div className="tour-actions">
        <Button type="button" variant="ghost" onClick={skipInstructions}>{inOverview ? "Skip to hands-on" : "Skip"}</Button>
        {(inOverview && index > 0) || formBack ? <Button type="button" variant="ghost" onClick={() => changeTour({ step: stageSteps[index - 1]! })}>Back</Button> : null}
        {missingEnvironment ? <Button type="button" className="tour-next" onClick={startInstructions}>Start over</Button> : missingForm ? <Button type="button" className="tour-next" onClick={() => { changeTour({ step: "create-open" }); onCreate?.() }}>Reopen form</Button> : tour.step === "demo-start" ? <Button type="button" className="tour-next" loading={checking} disabled={checking || !websiteError || environment?.status !== "running"} onClick={() => setWebsiteAttempt(value => value + 1)}>{websiteError ? "Retry website setup" : "Building website…"}</Button> : <Button type="button" className="tour-next" disabled={blocked} onClick={next}>{copy.next ?? "Next"}</Button>}
      </div>
    </div>
  </div>, document.body)
}
