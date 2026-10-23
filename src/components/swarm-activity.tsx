import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { swarmApi, type SwarmActivity } from "@/api/swarm-api"
import { mergeActivity } from "@/lib/swarm-activity"

/** One activity event as a monitoring row: a short category tag, and its HH:MM:SS time. */
const two = (value: number) => String(value).padStart(2, "0")
const eventTime = (at?: number) => {
  if (!at) return ""
  const when = new Date(at)
  return `${two(when.getHours())}:${two(when.getMinutes())}:${two(when.getSeconds())}`
}
const eventTag = (event: SwarmActivity) => {
  if (event.kind === "action" && event.tool) return event.tool
  const label: Record<string, string> = { thinking: "think", turnEnd: "turn" }
  return label[event.kind ?? ""] ?? event.kind ?? "·"
}

export function WorkerActivity({ workerId, active = true }: { workerId: string; active?: boolean }) {
  const [events, setEvents] = useState<SwarmActivity[]>([])
  const after = useRef(0)
  const box = useRef<HTMLDivElement>(null)
  const [error, setError] = useState(false)
  useEffect(() => {
    after.current = 0
    setEvents([])
    let alive = true
    let timer: number
    const poll = async () => {
      let caughtUp = true
      try {
        const log = await swarmApi.activity(workerId, after.current)
        if (!alive) return
        setError(false)
        if (log.latest !== undefined && log.latest < after.current) { after.current = 0; setEvents([]) }
        const next = (log.events ?? []).filter(event => (event.seq ?? 0) > after.current)
        if (next.length) {
          after.current = next[next.length - 1]!.seq ?? after.current
          setEvents(current => mergeActivity(current, next))
        }
        caughtUp = (log.latest ?? after.current) <= after.current
      } catch { if (alive) setError(true) }
      // Never overlap slow reads; drain historical pages before waiting for new text.
      if (alive) timer = window.setTimeout(() => void poll(), caughtUp ? 750 : 0)
    }
    void poll()
    return () => { alive = false; window.clearTimeout(timer) }
  }, [workerId])
  // Hidden tabs have no scroll height. Position after the selected panel is
  // visible, and follow every new snapshot while it is open.
  useLayoutEffect(() => {
    if (active) box.current?.scrollTo({ top: box.current.scrollHeight, behavior: "instant" })
  }, [active, events])
  return <>
    {error ? <p role="status" className="grid-note">Activity connection interrupted. Reconnecting…</p> : null}
    <div className="swarm-activity" ref={box} role="log" aria-live="off" aria-label="Worker activity">
    {!events.length ? <span className="grid-note">No activity yet. Text appears here as the worker writes.</span> : null}
    {events.map(event => {
      const raw = event as SwarmActivity & { input?: unknown; output?: unknown }
      const io = raw.output ?? raw.input
      const body = io === undefined || io === null ? "" : typeof io === "string" ? io : JSON.stringify(io, null, 2)
      const head = event.text ?? event.detail ?? (event.kind === "action"
        ? [event.target, event.status].filter(Boolean).join(" · ")
        : [event.tool, event.target, event.status].filter(Boolean).join(" · "))
      return <p key={event.streamId ?? event.seq} data-kind={event.kind}>
        <span className="swarm-evt">{eventTag(event)}</span>
        <span className="swarm-evt-body">{event.stage ? <strong>{event.stage}: </strong> : null}{head}</span>
        <span className="swarm-evt-time">{eventTime(event.at)}</span>
        {body ? <span className="swarm-activity-io">{body.length > 2000 ? `${body.slice(0, 2000)}…` : body}</span> : null}
      </p>
    })}
    </div>
  </>
}
