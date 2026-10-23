import { useEffect, useLayoutEffect, useRef, useState } from "react"
import { swarmApi, type SwarmMessage, type SwarmReport } from "@/api/swarm-api"
import { Button } from "./ui/button"
import { Terms } from "./swarm-terms"

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)
export function SwarmWorkerDetail({ workerId, onChanged, active = true }: { workerId: string; onChanged(): void; active?: boolean }) {
  const [messages, setMessages] = useState<SwarmMessage[]>([])
  const [reports, setReports] = useState<SwarmReport[]>([])
  const [content, setContent] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const cursor = useRef(0)
  const logBox = useRef<HTMLDivElement>(null)
  // What a Send or Submit said stays on screen until the next one; only the poll's own
  // messages are cleared when it next succeeds.
  const fromAction = useRef(false)
  const fail = (reason: unknown) => { fromAction.current = true; setError(message(reason)) }
  useEffect(() => {
    let alive = true
    let timer: number
    cursor.current = 0; setMessages([]); setReports([])
    const poll = async () => {
      const results = await Promise.allSettled([swarmApi.messages(workerId, cursor.current), swarmApi.reports(workerId)])
      if (!alive) return
      const [conversation, findings] = results
      if (conversation.status === "fulfilled") {
        const fresh = conversation.value.messages.filter(row => row.sequence > cursor.current)
        if (fresh.length) { cursor.current = Math.max(...fresh.map(row => row.sequence)); setMessages(current => [...current, ...fresh].slice(-200)) }
      }
      if (findings.status === "fulfilled") setReports(findings.value.reports ?? [])
      const failure = results.find(result => result.status === "rejected")
      if (failure?.status === "rejected") { fromAction.current = false; setError(message(failure.reason)) }
      else if (!fromAction.current) setError("")
      timer = window.setTimeout(() => void poll(), 3000)
    }
    void poll()
    return () => { alive = false; window.clearTimeout(timer) }
  }, [workerId])
  // Keep the thread pinned to its newest message, the way a chat does.
  useLayoutEffect(() => {
    if (active) logBox.current?.scrollTo({ top: logBox.current.scrollHeight, behavior: "instant" })
  }, [active, messages])
  const send = async () => {
    if (busy || !content.trim()) return
    setBusy(true); fromAction.current = false; setError("")
    try { await swarmApi.chat(workerId, content.trim()); setContent("") } catch (reason) { fail(reason) } finally { setBusy(false) }
  }
  const submit = async (report: SwarmReport) => {
    setBusy(true); fromAction.current = false; setError("")
    try { await swarmApi.submitReport(workerId, report.id); setReports(current => current.map(row => row.id === report.id ? { ...row, state: "complete_received" } : row)); onChanged() } catch (reason) { fail(reason) } finally { setBusy(false) }
  }
  return <div className="swarm-conversation">
    <section className="swarm-chat" aria-label="Private worker conversation">
      <div role="log" aria-label="Conversation with the worker" className="swarm-chat-log" ref={logBox}>
        {messages.length
          ? messages.map(row => <div key={row.id} className="swarm-msg" data-role={row.role === "human" ? "you" : "worker"}>
              <span className="swarm-msg-role">{row.role === "human" ? "You" : "Worker"}</span>
              <div className="swarm-msg-bubble">{row.content}</div>
            </div>)
          : <p className="swarm-chat-empty">No messages yet. Ask about progress or suggest a test within the accepted scope. The worker replies at a checkpoint; a paused worker replies after it resumes.</p>}
      </div>
      <form onSubmit={event => { event.preventDefault(); void send() }} className="swarm-chat-form">
        <textarea className="grid-textarea swarm-chat-input" aria-label="Message the worker" placeholder="Message the worker…" value={content} maxLength={8000} rows={1} disabled={busy} onChange={event => setContent(event.target.value)} onKeyDown={event => { if (event.key === "Enter" && !event.shiftKey) { event.preventDefault(); void send() } }} />
        <Button type="submit" disabled={busy || !content.trim()}>Send</Button>
      </form>
      {error ? <p role="alert" className="grid-error swarm-chat-error">{error}</p> : null}
    </section>
    <section className="swarm-reports" aria-label="Finding reports">
      <h3>Finding reports</h3>
    {reports.length ? reports.map(report => <details key={report.id} className="swarm-report"><summary>{report.title} · {report.state.replaceAll("_", " ")}</summary>{report.document ? <Terms value={report.document} /> : <p className="grid-hint">This report has no detail yet.</p>}{report.state === "draft" ? <Button disabled={busy} onClick={() => void submit(report)}>Submit this report to the bounty owner</Button> : null}</details>) : <p className="grid-hint">Supported findings appear here. A candidate is not a verified vulnerability.</p>}
    </section>
  </div>
}
