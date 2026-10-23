import { useEffect, useState } from "react"
import { swarmApi, type SwarmPrompts } from "@/api/swarm-api"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import { Spinner } from "@/components/ui/spinner"

type Field = "agents" | "rules" | "liveTask" | "sourceTask" | "chatReply"

const FIELDS: { key: Field; title: string; help: string }[] = [
  {
    key: "agents",
    title: "Agent core instructions",
    help: "The agent's own system prompt inside the sandbox — the deepest control over how it reasons and behaves. Changing this re-prepares running workers so they pick it up.",
  },
  {
    key: "rules",
    title: "Worker rules & guardrails",
    help: "The rules handed to the agent as context on every turn — scope, what it may and may not do, and how it must report.",
  },
  {
    key: "liveTask",
    title: "Live website task",
    help: "Sent each turn when the target is a live URL. This is where you tell it what counts as a finding and what does not.",
  },
  {
    key: "sourceTask",
    title: "Source review task",
    help: "Sent each turn when the target is a source project you gave it.",
  },
  {
    key: "chatReply",
    title: "Chat reply prompt",
    help: "The system prompt used when you message a private worker directly.",
  },
]

/** Edits the prompts and guardrails the workers use. Saved overrides are read from disk at runtime,
 *  so a change takes effect on the next turn — no rebuild. Clearing a field restores its default. */
export function SwarmPromptsEditor() {
  const [prompts, setPrompts] = useState<SwarmPrompts | null>(null)
  const [drafts, setDrafts] = useState<Record<Field, string>>({ agents: "", rules: "", liveTask: "", sourceTask: "", chatReply: "" })
  const [busy, setBusy] = useState<string | null>("load")
  const [loadError, setLoadError] = useState("")
  const [loadAttempt, setLoadAttempt] = useState(0)

  const apply = (next: SwarmPrompts, field?: Field) => {
    setPrompts(next)
    setDrafts(current => field ? { ...current, [field]: next[field].value } : {
      agents: next.agents.value, rules: next.rules.value, liveTask: next.liveTask.value,
      sourceTask: next.sourceTask.value, chatReply: next.chatReply.value,
    })
  }

  useEffect(() => {
    let alive = true
    setBusy("load")
    setLoadError("")
    swarmApi.prompts()
      .then(result => { if (alive) apply(result) })
      .catch(reason => { if (alive) setLoadError(reason instanceof Error ? reason.message : String(reason)) })
      .finally(() => { if (alive) setBusy(null) })
    return () => { alive = false }
  }, [loadAttempt])

  const save = (field: Field) => {
    setBusy(field)
    swarmApi.savePrompts({ [field]: drafts[field] })
      .then(result => { apply(result, field); toastManager.add({ title: "Saved. It takes effect on the next turn.", type: "success" }) })
      .catch(reason => toastManager.add({ title: "Could not save", description: String(reason), type: "error" }))
      .finally(() => setBusy(null))
  }

  const resetField = (field: Field) => {
    setBusy(field)
    swarmApi.savePrompts({ [field]: "" })
      .then(result => { apply(result, field); toastManager.add({ title: "Restored the default", type: "success" }) })
      .catch(reason => toastManager.add({ title: "Could not reset", description: String(reason), type: "error" }))
      .finally(() => setBusy(null))
  }

  const resetAll = () => {
    setBusy("all")
    swarmApi.resetPrompts()
      .then(result => { apply(result); toastManager.add({ title: "All prompts restored to their defaults", type: "success" }) })
      .catch(reason => toastManager.add({ title: "Could not reset", description: String(reason), type: "error" }))
      .finally(() => setBusy(null))
  }

  if (!prompts) {
    if (loadError) return <div className="swarm-prompts-loading">
      <p role="alert">Could not load the prompts: {loadError}</p>
      <Button size="xs" onClick={() => setLoadAttempt(value => value + 1)}>Retry</Button>
    </div>
    return <div className="swarm-prompts-loading"><Spinner /> Loading the prompts…</div>
  }

  return (
    <div className="swarm-prompts">
      <div className="swarm-prompts-intro">
        <p>These are the exact instructions and guardrails every worker on this computer follows. Edits are saved to this machine and sent to each worker's selected model from the next turn. Leave a box empty to use the built-in default.</p>
        <Button size="xs" variant="ghost" disabled={!!busy} onClick={resetAll}>Reset all to defaults</Button>
      </div>
      {FIELDS.map(({ key, title, help }) => {
        const prompt = prompts[key]
        const changed = drafts[key] !== prompt.value
        const placeholders = key === "liveTask" ? prompts.placeholders.liveTask : key === "sourceTask" ? prompts.placeholders.sourceTask : []
        return (
          <div className="swarm-prompt-field" key={key}>
            <div className="swarm-prompt-head">
              <label htmlFor={`swarm-prompt-${key}`}>{title}</label>
              <span className={prompt.custom ? "swarm-prompt-badge custom" : "swarm-prompt-badge"}>{prompt.custom ? "Custom" : "Default"}</span>
            </div>
            <p className="grid-hint">{help}</p>
            {placeholders.length ? (
              <p className="grid-hint">Placeholders you can use: {placeholders.map(p => <code key={p}>{p}</code>)}. Each is replaced with the real value at run time.</p>
            ) : null}
            <textarea
              id={`swarm-prompt-${key}`}
              className="grid-textarea swarm-prose"
              rows={key === "rules" ? 14 : 8}
              value={drafts[key]}
              disabled={busy === key || busy === "all"}
              onChange={event => setDrafts(current => ({ ...current, [key]: event.target.value }))}
            />
            <div className="swarm-prompt-actions">
              <Button size="xs" disabled={!changed || !!busy} onClick={() => save(key)}>{busy === key ? "Saving…" : "Save"}</Button>
              <Button size="xs" variant="outline" disabled={!prompt.custom || !!busy} onClick={() => resetField(key)}>Reset to default</Button>
              {changed ? <span className="swarm-prompt-dirty">Unsaved changes</span> : null}
            </div>
          </div>
        )
      })}
    </div>
  )
}
