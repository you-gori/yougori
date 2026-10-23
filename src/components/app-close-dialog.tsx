import { useEffect, useRef, useState } from "react"
import { isTauri, invoke } from "@tauri-apps/api/core"
import { listen } from "@tauri-apps/api/event"
import { getCurrentWindow } from "@tauri-apps/api/window"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Spinner } from "@/components/ui/spinner"
import { Dialog, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"

type ClosePhase = "idle" | "checking" | "confirm" | "closing" | "hiding"

export function AppCloseDialog() {
  const { state } = usePlatform()
  const [phase, setPhase] = useState<ClosePhase>("idle")
  const [error, setError] = useState("")
  const submitted = useRef(false)
  const busy = phase === "checking" || phase === "closing" || phase === "hiding"

  useEffect(() => {
    if (!isTauri()) return
    let disposed = false
    const confirmation = listen("app-close-requested", () => {
      if (!disposed && !submitted.current) {
        setError("")
        setPhase("confirm")
      }
    })
    // Observe the native title-bar, Alt+F4 and tray close requests. Rust still
    // owns confirmation and shutdown; this listener only shows their progress.
    const requested = getCurrentWindow().listen("tauri://close-requested", () => {
      if (!disposed) setPhase(current => current === "idle" ? "checking" : current)
    })
    return () => {
      disposed = true
      void confirmation.then(unlisten => unlisten())
      void requested.then(unlisten => unlisten())
    }
  }, [])

  const close = async (keepRunning: boolean) => {
    if (submitted.current) return
    submitted.current = true
    setPhase(keepRunning ? "hiding" : "closing")
    setError("")
    try {
      await invoke("finish_app_close", { keepRunning })
      if (keepRunning) {
        // The dashboard stays mounted in the background. Clear the dialog so
        // reopening Yougori shows the workspace and allows another close.
        submitted.current = false
        setPhase("idle")
      }
      // Full shutdown schedules exit. Keep progress visible while native
      // cleanup finishes, including after this promise has resolved.
    } catch (reason) {
      submitted.current = false
      setError(String(reason))
      setPhase("confirm")
    }
  }

  const active = state?.environments.filter(environment => ["running", "paused", "provisioning"].includes(environment.status)) ?? []
  return <Dialog open={phase !== "idle"} onOpenChange={value => { if (!busy && !value) setPhase("idle") }}>
    <DialogPopup showCloseButton={!busy} className={busy ? "max-w-md" : undefined}>
      <DialogHeader>
        <DialogTitle>{busy ? <span className="flex items-center gap-3"><Spinner aria-hidden="true" className="size-5 shrink-0" />Closing Yougori…</span> : "Environments are still active"}</DialogTitle>
        <DialogDescription>{phase === "hiding" ? "Closing the windows. Your environments will keep running." : busy ? "Please wait while Yougori finishes closing." : "Choose what happens before closing Yougori."}</DialogDescription>
      </DialogHeader>
      {busy ? <span className="sr-only" role="status">Closing Yougori. Please wait.</span> : <>
        <DialogPanel className="space-y-4">
          {active.length ? <ul aria-label="Active environments" className="divide-y rounded-xl border text-sm">{active.map(environment => <li key={environment.id} className="flex items-center justify-between gap-3 px-3 py-2"><span className="min-w-0 truncate">{environment.name}</span><span className="shrink-0 text-xs text-muted-foreground">{environment.status}</span></li>)}</ul> : null}
          <div className="space-y-2 rounded-xl border p-3">
            <Button className="w-full" onClick={() => void close(true)}>Close app, keep environments running</Button>
            <p className="text-xs leading-relaxed text-muted-foreground">Environments, shared folders and published services keep running in the background. Reopen Yougori from the tray, or with <code>yougori app show</code>.</p>
          </div>
          <div className="space-y-2 rounded-xl border p-3">
            <Button className="w-full" variant="outline" onClick={() => void close(false)}>Stop environments and quit</Button>
            <p className="text-xs leading-relaxed text-muted-foreground">Local environments stop and their shared folders and published services disconnect.</p>
          </div>
          {error ? <p role="alert" className="text-sm text-destructive-foreground">{error}</p> : null}
        </DialogPanel>
        <DialogFooter>
          <Button variant="ghost" onClick={() => setPhase("idle")}>Cancel</Button>
        </DialogFooter>
      </>}
    </DialogPopup>
  </Dialog>
}
