import { useEffect, useRef, useState } from "react"
import type RFB from "@novnc/novnc"
import { remoteAccessApi } from "@/api/remote-access-api"
import { RemoteDisplayChannel } from "@/lib/remote-display-channel"
import { Button } from "@/components/ui/button"

export function RemoteDisplay({ environmentId, appSessionId }: { environmentId: string; appSessionId?: string }) {
  const target = useRef<HTMLDivElement>(null)
  const [error, setError] = useState(""), [ready, setReady] = useState(false), [attempt, setAttempt] = useState(0)
  useEffect(() => {
    let disposed = false; let channel: RemoteDisplayChannel | undefined; let client: RFB | undefined
    setReady(false); setError("")
    void (async () => {
      const { default: Rfb } = await import("@novnc/novnc")
      if (disposed) return
      const display = await remoteAccessApi.desktop<{ displayId: string; password: string }>(environmentId, { action: "create", appSessionId })
      channel = new RemoteDisplayChannel(environmentId, display.displayId, error => { if (!disposed) { setError(String(error)); setReady(false) } })
      if (disposed || !target.current) { channel.close(); return }
      // The remote display session exists now; close it if the viewer cannot start.
      try { client = new Rfb(target.current, channel, { shared: true, credentials: { password: display.password } }) }
      catch (error) { channel.close(); throw error }
      client.scaleViewport = true
      client.addEventListener("connect", () => { if (!disposed) setReady(true) })
      client.addEventListener("disconnect", () => { if (!disposed) setReady(false) })
      channel.open()
    })().catch(error => { if (!disposed) setError(String(error)) })
    return () => { disposed = true; client?.disconnect(); channel?.close() }
  }, [environmentId, appSessionId, attempt])
  return <section className="flex h-full min-h-96 flex-col gap-2"><div className="flex items-center gap-2 text-xs"><span className="flex-1" role="status">{error || (ready ? "Remote display · keyboard and mouse enabled" : "Connecting to the remote display…")}</span><Button size="xs" variant="outline" onClick={() => setAttempt(value => value + 1)}>Reconnect display</Button></div><div ref={target} className="min-h-80 flex-1 overflow-hidden rounded border bg-black" /></section>
}
