import { useEffect, useRef, useState } from "react"
import { modelsApi, type ModelUsage, type UsageOutcome } from "@/api/projects-api"
import { Button } from "@/components/ui/button"
import { averageSpeed, sumDays, usageByDay } from "@/lib/model-usage"
import "@/components/model-workspace.css"

const RANGES = [7, 30, 90] as const
const OUTCOMES: Record<UsageOutcome, string> = { ok: "Completed", cancelled: "Stopped", busy: "GPU busy", invalid: "Invalid request", error: "Failed", rejected: "Wrong API key" }
const number = (n: number) => n.toLocaleString()
const compact = (n: number) => n >= 1_000_000 ? `${(n / 1_000_000).toFixed(1)}M` : n >= 10_000 ? `${Math.round(n / 1000)}k` : n.toLocaleString()
const dayLabel = (date: Date) => date.toLocaleDateString(undefined, { month: "short", day: "numeric" })

export function ModelUsagePanel({ environmentId }: { environmentId: string }) {
  const [usage, setUsage] = useState<ModelUsage | null>(null)
  const [error, setError] = useState("")
  const [range, setRange] = useState<(typeof RANGES)[number]>(7)
  const [hovered, setHovered] = useState<number | null>(null)
  const [confirmReset, setConfirmReset] = useState(false)
  const [busy, setBusy] = useState(false)
  const alive = useRef(true)
  useEffect(() => {
    alive.current = true
    let timer = 0
    const refresh = async () => {
      try { const next = await modelsApi.usage(environmentId); if (alive.current) { setUsage(next); setError("") } }
      catch (reason) { if (alive.current) setError(String(reason)) }
      finally { if (alive.current) timer = window.setTimeout(refresh, 10000) }
    }
    void refresh()
    return () => { alive.current = false; window.clearTimeout(timer) }
  }, [environmentId])
  const reset = async () => {
    setBusy(true)
    try { const next = await modelsApi.usage(environmentId, true); if (alive.current) { setUsage(next); setConfirmReset(false) } }
    catch (reason) { if (alive.current) setError(String(reason)) }
    finally { if (alive.current) setBusy(false) }
  }

  if (!usage) return <section className="model-usage" aria-label="Model usage">{error ? <p role="alert" className="model-error">{error}</p> : <p className="model-hint">Loading usage…</p>}</section>
  const days = usageByDay(usage, range)
  const totals = sumDays(days)
  const inputSpeed = usage.speedMetric === "input_tokens"
  const speedField = inputSpeed ? "prompt_tokens" : "completion_tokens"
  const speed = averageSpeed(usage.recent, speedField)
  const peak = Math.max(1, ...days.map(day => day.requests))
  const recent = [...usage.recent].reverse().slice(0, 25)
  const tip = hovered === null ? null : days[hovered]!

  return <section className="model-usage" aria-label="Model usage">
    <div className="model-usage-bar">
      <div className="model-tabs" role="group" aria-label="Time range">
        {RANGES.map(days => <button key={days} type="button" aria-pressed={range === days} onClick={() => setRange(days)}>{days} days</button>)}
      </div>
      <span className="model-hint">Since {new Date(usage.since * 1000).toLocaleDateString()} · updates every 10 seconds</span>
    </div>
    {error ? <p role="alert" className="model-error">{error}</p> : null}

    <div className="model-usage-tiles">
      <div><span className="model-label">Requests</span><strong>{number(totals.requests)}</strong><small>{number(totals.yougori ?? 0)} chat · {number(totals.api ?? 0)} API</small></div>
      <div><span className="model-label">Tokens in</span><strong>{compact(totals.prompt_tokens)}</strong><small>Prompts and history</small></div>
      <div><span className="model-label">Tokens out</span><strong>{compact(totals.completion_tokens)}</strong><small>Generated replies</small></div>
      <div><span className="model-label">Speed</span><strong>{speed === null ? "—" : `${speed.toFixed(1)}`}</strong><small>{inputSpeed ? "Input tokens per second" : "Tokens per second"}</small></div>
      <div><span className="model-label">Problems</span><strong>{number(totals.errors + totals.rejected)}</strong><small>{number(totals.errors)} failed · {number(totals.rejected)} wrong key</small></div>
    </div>

    <figure className="model-usage-chart">
      <figcaption>Requests per day</figcaption>
      <div className="model-usage-plot" onMouseLeave={() => setHovered(null)}>
        {days.map((day, i) => <button key={day.date.getTime()} type="button" className="model-usage-column" data-active={hovered === i || undefined}
          aria-label={`${dayLabel(day.date)}: ${day.requests} requests, ${day.prompt_tokens} tokens in, ${day.completion_tokens} tokens out`}
          onMouseEnter={() => setHovered(i)} onFocus={() => setHovered(i)} onBlur={() => setHovered(null)}>
          <span style={{ height: day.requests ? `max(3px, ${(day.requests / peak) * 100}%)` : 0 }} />
        </button>)}
        {tip ? <div className="model-usage-tip" style={{ left: `${((hovered! + 0.5) / days.length) * 100}%` }} role="presentation">
          <strong>{dayLabel(tip.date)}</strong>
          <span>{number(tip.requests)} requests · {number(tip.yougori ?? 0)} chat · {number(tip.api ?? 0)} API</span>
          <span>{number(tip.prompt_tokens)} in · {number(tip.completion_tokens)} out</span>
          {tip.errors || tip.rejected ? <span>{number(tip.errors)} failed · {number(tip.rejected)} wrong key</span> : null}
        </div> : null}
      </div>
      <div className="model-usage-axis"><span>{dayLabel(days[0]!.date)}</span><span>peak {number(peak)} / day</span><span>Today</span></div>
    </figure>

    <div className="model-usage-recent">
      <h3>Recent requests</h3>
      {recent.length ? <div className="md-table"><table>
        <thead><tr><th>Time</th><th>From</th><th>Result</th><th>In</th><th>Out</th><th>Speed</th><th>Duration</th></tr></thead>
        <tbody>{recent.map((request, i) => <tr key={`${request.time}-${i}`}>
          <td>{new Date(request.time * 1000).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit", second: "2-digit" })}</td>
          <td>{request.source === "yougori" ? "Chat" : "API"}</td>
          <td data-outcome={request.outcome}>{OUTCOMES[request.outcome] ?? request.outcome}</td>
          <td>{number(request.prompt_tokens)}</td>
          <td>{number(request.completion_tokens)}</td>
          <td>{request.outcome === "ok" && request[speedField] && request.seconds ? `${(request[speedField] / request.seconds).toFixed(1)} ${inputSpeed ? "input " : ""}tok/s` : "—"}</td>
          <td>{request.seconds ? `${request.seconds.toFixed(1)} s` : "—"}</td>
        </tr>)}</tbody>
      </table></div> : <p className="model-hint">No requests yet. Chat with the model or call its API to see usage here.</p>}
    </div>

    <div className="model-usage-footer">
      <p className="model-hint">{usage.listen?.enabled ? <>Free-provider recording is on. Prompts and replies are saved in the container at <code>{usage.listen.path}</code>. {usage.listen.error ?? ""}</> : "Recording is off. Usage contains counts and token totals only."} "Wrong API key" counts calls that were refused.</p>
      {confirmReset
        ? <div className="model-api-enable"><Button size="sm" variant="ghost" disabled={busy} onClick={() => setConfirmReset(false)}>Cancel</Button><Button size="sm" variant="destructive" loading={busy} onClick={() => void reset()}>Clear usage history</Button></div>
        : <Button size="sm" variant="ghost" onClick={() => setConfirmReset(true)}>Reset usage</Button>}
    </div>
  </section>
}
