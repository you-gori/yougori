import { useEffect, useRef, useState } from "react"
import { modelsApi, type ModelStatus } from "@/api/projects-api"
import { Button } from "@/components/ui/button"
import { modelProgress } from "@/lib/model-progress"
import { parseChats, serializeChats, titleFor, type ChatStore } from "@/lib/model-chat"

const QUESTIONS = JSON.stringify({ route: { type: "choice", instructions: "Which team should handle this event?", criteria: { technical: "Technical problem or outage", billing: "Payment or invoice problem" } } }, null, 2)

export function ModelDecisions({ environmentId, status }: { environmentId: string; status: ModelStatus }) {
  const [state, setState] = useState("Our checkout started returning errors and orders are blocked.")
  const [questions, setQuestions] = useState(QUESTIONS)
  const [result, setResult] = useState<unknown>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const lock = useRef(false)
  const edited = useRef(false)
  const [history, setHistory] = useState<ChatStore>(() => parseChats(null))
  useEffect(() => {
    let alive = true
    void modelsApi.history(environmentId).then(value => {
      if (!alive) return
      const saved = parseChats(value); setHistory(saved)
      if (edited.current) return
      const active = saved.conversations.find(c => c.id === saved.activeId)
      const request = active?.messages.slice().reverse().find(m => m.role === "user")
      try {
        const json = JSON.parse(request?.content ?? "")
        if (json.questions && Object.hasOwn(json, "state")) {
          setState(typeof json.state === "string" ? json.state : JSON.stringify(json.state, null, 2))
          setQuestions(JSON.stringify(json.questions, null, 2))
          const answer = active?.messages.slice().reverse().find(m => m.role === "assistant")
          if (answer) setResult(JSON.parse(answer.content))
        }
      } catch { /* Legacy chat history is still kept, but is not a decision draft. */ }
    }).catch(() => undefined)
    return () => { alive = false }
  }, [environmentId])
  const decide = async () => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError("")
    try {
      let value: unknown = state
      try { value = JSON.parse(state) } catch { /* A state can be plain text. */ }
      const schema: unknown = JSON.parse(questions)
      if (!schema || Array.isArray(schema) || typeof schema !== "object") throw new Error("Questions must be a JSON object")
      const content = JSON.stringify({ state: value, questions: schema })
      const started = performance.now()
      const response = await modelsApi.chat(environmentId, [{ role: "user", content }], { maxTokens: 1, temperature: 0 })
      const answer = response.choices[0]?.message.content
      if (!answer) throw new Error("The decision model returned no answer")
      setResult(JSON.parse(answer))
      try {
        const saved = parseChats(await modelsApi.history(environmentId))
        let active = saved.conversations.find(c => c.id === saved.activeId)
        if (!active) { active = { id: crypto.randomUUID(), title: titleFor(state), messages: [], updatedAt: Date.now() }; saved.conversations.push(active); saved.activeId = active.id }
        active.messages.push({ id: crypto.randomUUID(), role: "user", content }, { id: crypto.randomUUID(), role: "assistant", content: answer,
          stats: { tokens: 0, inputTokens: response.usage?.prompt_tokens, seconds: (performance.now() - started) / 1000, finish: "stop" } })
        active.updatedAt = Date.now()
        const next = serializeChats(saved); await modelsApi.saveHistory(environmentId, next); setHistory(next)
      } catch (reason) { setError(`Decision completed, but history was not saved: ${String(reason)}`) }
    } catch (reason) { setError(String(reason)) }
    finally { setBusy(false); lock.current = false }
  }
  return <section className="model-form" aria-label="Model decisions">
    <h3>Decisions</h3>
    <p role="status" className="model-hint">{modelProgress(status)}{status.gpu ? ` · ${status.gpu}` : ""}{status.precision ? ` · ${status.precision}` : ""}</p>
    <p className="model-hint">Supply a state and typed questions. Choice returns option probabilities; score returns a weighted level; noul returns the probability of true.</p>
    {status.precision && status.precision !== "original" ? <p className="model-hint">Quantized inference can change probabilities. Calibrate thresholds on your own examples.</p> : null}
    <label className="model-label" htmlFor="decision-state">State (text or JSON)</label>
    <textarea id="decision-state" value={state} rows={4} disabled={busy} maxLength={24576} onChange={event => { edited.current = true; setState(event.target.value) }} />
    <label className="model-label" htmlFor="decision-questions">Questions (JSON)</label>
    <textarea id="decision-questions" value={questions} rows={8} disabled={busy} maxLength={8192} onChange={event => { edited.current = true; setQuestions(event.target.value) }} />
    <Button disabled={busy || !(status.status === "ready" || status.optimizer?.enabled && ["idle", "queued", "freeing_memory", "loading"].includes(status.status)) || !state.trim() || !questions.trim()} loading={busy} onClick={() => void decide()}>Run decision</Button>
    {error || status.error ? <p role="alert" className="model-error">{error || status.error}</p> : null}
    {result ? <pre aria-label="Decision result" className="model-decision-result">{JSON.stringify(result, null, 2)}</pre> : null}
    {history.conversations.length ? <details><summary>Saved requests · shared with the CLI</summary>{history.conversations.map(c => <details key={c.id}><summary>{c.title} · {c.messages.filter(m => m.role === "user").length} requests</summary>{c.messages.map(m => <pre key={m.id}>{m.content}</pre>)}</details>)}</details> : null}
    <p className="model-hint">CLI: <code>yougori model decide {environmentId} --file request.json</code>. API: <code>POST /v1/systemone</code>, authenticated with this model’s API key.</p>
  </section>
}
