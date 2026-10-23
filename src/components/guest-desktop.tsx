import type RFB from "@novnc/novnc"
import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react"
import { platformApi } from "@/api/platform-api"
import { Button } from "@/components/ui/button"
import { Dialog, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Spinner } from "@/components/ui/spinner"
import { GuestTerminal } from "@/components/guest-terminal"
import type { TerminalReadyHandler, TerminalInstallerId } from "@/lib/terminal-installers"
import { TerminalLinkCards } from "@/components/terminal-link-cards"
import { extractTerminalLinks } from "@/lib/terminal-links"
import { bindGuestKeyboard } from "@/lib/guest-keyboard"
import { bindGuestDisplaySizing } from "@/lib/guest-display-sizing"
import { usePlatform } from "@/context/platform-context"
import { cn } from "@/lib/utils"
import type { Environment, GuestSession } from "@/types/platform"

const loadSnapshotDialog = () => import("@/components/dialogs/snapshot-dialog")
const SnapshotDialog = lazy(async () => ({ default: (await loadSnapshotDialog()).SnapshotDialog }))

function HeadlessSerialConsole({ environment, message }: { environment: Environment; message: string }) {
  const [output, setOutput] = useState("")
  const [error, setError] = useState("")
  const outputRef = useRef<HTMLPreElement>(null)
  const links = useMemo(() => extractTerminalLinks(output), [output])

  useEffect(() => {
    let disposed = false
    let timer = 0
    const refresh = () => {
      platformApi.readEnvironmentConsole(environment.id)
        .then((nextOutput) => {
          if (!disposed) {
            setOutput((current) => current === nextOutput ? current : nextOutput)
            setError("")
          }
        })
        .catch((reason: unknown) => {
          if (!disposed) setError(reason instanceof Error ? reason.message : String(reason))
        })
        .finally(() => {
          if (!disposed) timer = window.setTimeout(refresh, document.visibilityState === "hidden" ? 5_000 : 1_500)
        })
    }
    refresh()
    return () => {
      disposed = true
      window.clearTimeout(timer)
    }
  }, [environment.id])

  useEffect(() => {
    const target = outputRef.current
    if (target) target.scrollTop = target.scrollHeight
  }, [output])

  return (
    <div className="flex size-full flex-col bg-[#0c0d0f] font-mono text-[#e9e9e9]">
      <div className="flex h-10 shrink-0 items-center justify-between border-b border-white/10 px-5 text-xs text-white/55">
        <span>Serial · {environment.name}</span>
        <span>{message}</span>
      </div>
      <pre className="flex-1 overflow-auto whitespace-pre-wrap px-6 py-5 text-[12px] leading-5 text-white/75" ref={outputRef} role="log">
        {output || "Waiting for guest output…"}
        {error ? `\n${error}` : ""}
      </pre>
      <TerminalLinkCards links={links} />
    </div>
  )
}

export function VncDesktop({ websocketUrl, password, autoResize = false, captureKeyboard = false }: { websocketUrl: string; password: string; autoResize?: boolean; captureKeyboard?: boolean }) {
  const targetRef = useRef<HTMLDivElement>(null)
  const clientRef = useRef<RFB | undefined>(undefined)
  const [keyboardError, setKeyboardError] = useState("")
  const [status, setStatus] = useState<"connecting" | "connected" | "error">("connecting")
  const [message, setMessage] = useState("Connecting to the local guest display…")
  const [attempt, setAttempt] = useState(0)

  useEffect(() => {
    const target = targetRef.current
    if (!target) return
    let disposed = false
    let failed = false
    let client: RFB | undefined
    let releaseKeyboard: (() => void) | undefined
    setStatus("connecting")
    setKeyboardError("")
    setMessage("Connecting to the local guest display…")
    const fail = (reason: string) => {
      if (disposed || failed) return
      failed = true
      window.clearTimeout(connectionTimer)
      releaseKeyboard?.()
      releaseKeyboard = undefined
      setStatus("error")
      setMessage(reason)
      client?.disconnect()
    }
    const connectionTimer = window.setTimeout(() => fail("The guest display did not connect within 30 seconds. Check that the environment is running, then reconnect."), 30_000)
    const connect = async () => {
      try {
        const { default: RfbClient } = await import("@novnc/novnc")
        if (disposed || failed) return
        client = new RfbClient(target, websocketUrl, { shared: true, credentials: { password } })
        clientRef.current = client
        client.scaleViewport = true
        // Proportional scaling is always the fallback. Real guest resizing is
        // enabled only after connection, and only for the foreground viewer.
        client.resizeSession = false
        client.showDotCursor = true
        client.viewOnly = false
        client.background = "#0c0d0f"
        client.addEventListener("connect", () => {
          if (disposed || failed) return
          window.clearTimeout(connectionTimer)
          setStatus("connected")
          setMessage("Connected")
          client?.focus()
          if (captureKeyboard && client) releaseKeyboard = bindGuestKeyboard(target, client, setKeyboardError)
        })
        client.addEventListener("disconnect", (event) => {
          const clean = (event as CustomEvent<{ clean?: boolean }>).detail?.clean
          fail(clean ? "Guest display disconnected." : "The guest display connection was interrupted.")
        })
        client.addEventListener("securityfailure", (event) => {
          const detail = (event as CustomEvent<{ reason?: string }>).detail
          fail(detail?.reason || "The guest rejected the display connection.")
        })
      } catch (reason) {
        fail(reason instanceof Error ? reason.message : String(reason))
      }
    }
    void connect()
    return () => {
      disposed = true
      window.clearTimeout(connectionTimer)
      releaseKeyboard?.()
      clientRef.current = undefined
      client?.disconnect()
    }
  }, [password, websocketUrl, captureKeyboard, attempt])

  useEffect(() => {
    if (status === "connected" && clientRef.current) return bindGuestDisplaySizing(clientRef.current, autoResize)
  }, [status, autoResize, websocketUrl])

  return (
    <div className="relative size-full overflow-hidden bg-[#0c0d0f]">
      <div className="size-full [&_canvas]:outline-none" data-guest-display data-display-sizing={autoResize ? "auto" : "fit"} ref={targetRef} />
      {keyboardError ? <p role="alert" className="absolute inset-x-0 top-0 bg-black/85 px-3 py-2 text-xs text-amber-200">{keyboardError}</p> : null}
      {status !== "connected" ? (
        <div className="absolute inset-0 grid place-items-center bg-[#0c0d0f] text-center text-sm text-white/60">
          <div className="flex max-w-md flex-col items-center gap-3" role={status === "error" ? "alert" : "status"}>
            {status === "connecting" ? <Spinner className="text-white/55" /> : null}
            <p>{message}</p>
            {status === "error" ? <><Button type="button" variant="outline" onClick={() => setAttempt(current => current + 1)}>Reconnect display</Button><p className="text-xs">Reconnects this viewer without restarting the environment.</p></> : null}
          </div>
        </div>
      ) : null}
    </div>
  )
}

export function GuestScene({ environment, terminalSessionId, active = true, onReady, installer, modelChat, autoResizeDisplay = true }: { environment: Environment; terminalSessionId?: string; active?: boolean; onReady?: TerminalReadyHandler; installer?: TerminalInstallerId; modelChat?: boolean; autoResizeDisplay?: boolean }) {
  const [fallbackSessionId] = useState(() => `scene-${crypto.randomUUID()}`)
  const [session, setSession] = useState<GuestSession | null>(null)
  const [error, setError] = useState("")

  useEffect(() => {
    let active = true
    setSession(null)
    setError("")
    platformApi.getGuestSession(environment.id)
      .then((value) => { if (active) setSession(value) })
      .catch((reason: unknown) => { if (active) { setError(reason instanceof Error ? reason.message : String(reason)); if (terminalSessionId) onReady?.(terminalSessionId, false, true) } })
    return () => { active = false }
  }, [environment.id, terminalSessionId, onReady])

  if (error) return <div className="grid size-full place-items-center bg-[#0c0d0f] p-8 text-center text-sm text-white/60"><p className="max-w-lg">{error}</p></div>
  if (!session) return <div className="grid size-full place-items-center bg-[#0c0d0f]"><Spinner className="text-white/60" /></div>
  if (session.kind === "containerTerminal" || session.kind === "headlessTerminal") {
    return <GuestTerminal key={environment.id} environmentId={environment.id} sessionId={terminalSessionId ?? fallbackSessionId} active={active} onReady={onReady} installer={installer} modelChat={modelChat} />
  }
  if (session.kind === "headlessSerial") return <HeadlessSerialConsole environment={environment} message={session.message} />
  if (!session.websocketUrl) return <div className="grid size-full place-items-center bg-[#0c0d0f] text-sm text-white/60">The runtime did not provide a guest display endpoint.</div>
  if (!session.password) return <div className="grid size-full place-items-center bg-[#0c0d0f] text-sm text-white/60">The runtime did not provide secure display credentials.</div>
  return active ? <VncDesktop password={session.password} websocketUrl={session.websocketUrl} autoResize={autoResizeDisplay} captureKeyboard /> : null
}

export function GuestDesktop({ environment, onClose, standalone = false }: { environment: Environment; onClose(): void; standalone?: boolean }) {
  const { setEnvironmentStatus, environmentActions } = usePlatform()
  const stopping = environmentActions[environment.id] === "stopping"
  const [controlsVisible, setControlsVisible] = useState(true)
  const [snapshotOpen, setSnapshotOpen] = useState(false)
  const [snapshotMounted, setSnapshotMounted] = useState(false)
  const [fullscreen, setFullscreen] = useState(false)
  const timer = useRef<number | undefined>(undefined)

  const revealControls = () => {
    setControlsVisible(true)
    window.clearTimeout(timer.current)
    timer.current = window.setTimeout(() => setControlsVisible(false), 2400)
  }

  useEffect(() => {
    revealControls()
    const syncFullscreen = () => setFullscreen(Boolean(document.fullscreenElement))
    document.addEventListener("fullscreenchange", syncFullscreen)
    return () => {
      window.clearTimeout(timer.current)
      document.removeEventListener("fullscreenchange", syncFullscreen)
    }
  }, [])

  const toggleFullscreen = async () => {
    if (document.fullscreenElement) await document.exitFullscreen()
    else await document.documentElement.requestFullscreen()
  }

  const closeGuest = async () => {
    if (document.fullscreenElement) await document.exitFullscreen()
    onClose()
  }

  const shutDown = async () => {
    try {
      await setEnvironmentStatus(environment.id, "stopped")
      onClose()
    } catch { /* PlatformProvider keeps the error visible and unlocks retry. */ }
  }

  const openSnapshot = () => {
    void loadSnapshotDialog()
    setSnapshotMounted(true)
    setSnapshotOpen(true)
  }

  const guestContent = (
    <>
        <GuestScene environment={environment} />
        <div className={cn("absolute left-1/2 top-4 flex -translate-x-1/2 items-center gap-1 rounded-lg border border-white/10 bg-black/70 p-1 text-white shadow-lg backdrop-blur-md transition-all duration-200", controlsVisible || stopping ? "translate-y-0 opacity-100" : "pointer-events-none -translate-y-2 opacity-0", "focus-within:pointer-events-auto focus-within:translate-y-0 focus-within:opacity-100")}>
          <span className="max-w-48 truncate px-2 text-xs text-white/70">{environment.name}</span>
          <Button aria-label="Create restore point" className="text-white hover:bg-white/10 hover:text-white" onClick={openSnapshot} size="sm" type="button" variant="ghost">Restore point</Button>
          <Button aria-label={fullscreen ? "Exit full screen" : "Enter full screen"} className="text-white hover:bg-white/10 hover:text-white" onClick={toggleFullscreen} size="sm" type="button" variant="ghost">{fullscreen ? "Exit full screen" : "Full screen"}</Button>
          <Button aria-label="Shut down environment" disabled={Boolean(environmentActions[environment.id])} loading={stopping} className="text-white hover:bg-white/10 hover:text-white *:data-[slot=button-loading-indicator]:text-white" onClick={shutDown} size="sm" type="button" variant="ghost">Shut down</Button>
          <span className="mx-0.5 h-4 w-px bg-white/15" />
          <Button aria-label="Close guest view" className="text-white hover:bg-white/10 hover:text-white" onClick={closeGuest} size="sm" type="button" variant="ghost">Close</Button>
        </div>
        {snapshotMounted ? (
          <Suspense fallback={null}>
            <SnapshotDialog environmentId={environment.id} environmentName={environment.name} onOpenChange={setSnapshotOpen} open={snapshotOpen} />
          </Suspense>
        ) : null}
    </>
  )

  if (standalone) {
    return (
      <main className="relative h-screen w-screen overflow-hidden bg-black" onMouseMove={revealControls}>
        <h1 className="sr-only">{environment.name} guest session</h1>
        {guestContent}
      </main>
    )
  }

  return (
    <Dialog onOpenChange={(open) => { if (!open) void closeGuest() }} open>
      <DialogPopup
        bottomStickOnMobile={false}
        className="row-start-1 row-span-3 h-[calc(100vh-1rem)] w-[calc(100vw-1rem)] max-w-none self-center overflow-hidden rounded-lg border-white/10 bg-black p-0 shadow-none before:hidden"
        onMouseMove={revealControls}
        showCloseButton={false}
      >
        <DialogTitle className="sr-only">{environment.name} guest session</DialogTitle>
        {guestContent}
      </DialogPopup>
    </Dialog>
  )
}
