import { memo, useCallback, useEffect, useLayoutEffect, useRef, useState } from "react"
import { GuestLogs } from "@/components/guest-logs"
import { ModelDecisions } from "@/components/model-decisions"
import { modelProgress } from "@/lib/model-progress"
import { Markdown } from "@/components/chat-markdown"
import { modelsApi, type ChatMessage, type ChatOptions, type ModelStatus } from "@/api/projects-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import { defaultSettings, fitConversation, legacyChatKey, legacyChats, parseChats, serializeChats, titleFor, type ChatStore, type Conversation, type StoredMessage } from "@/lib/model-chat"
import "@/components/model-workspace.css"

const STARTERS = ["Explain how large language models work, simply.", "Write a Python function that removes duplicates from a list while keeping order.", "Give me three ideas for a weekend project."]
const newId = () => crypto.randomUUID()
const NO_MESSAGES: StoredMessage[] = []
const formatTokens = (n: number) => n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : String(n)
const ago = (time: number) => {
  const minutes = Math.round((Date.now() - time) / 60000)
  return minutes < 1 ? "now" : minutes < 60 ? `${minutes}m` : minutes < 1440 ? `${Math.round(minutes / 60)}h` : `${Math.round(minutes / 1440)}d`
}
// Replies left empty by an interrupted generation are removed.
const withoutEmptyReplies = (store: ChatStore): ChatStore => ({ ...store, conversations: store.conversations.map(c => ({ ...c, messages: c.messages.filter(m => m.role !== "assistant" || m.content || m.error) })) })

export function ModelChat({ environmentId }: { environmentId: string }) {
  const { state, setEnvironmentStatus, environmentActions } = usePlatform()
  const environment = state?.environments.find(e => e.id === environmentId)
  const environmentStatus = environment?.status
  const canCheckHealth = !environmentStatus || environmentStatus === "running"
  const [status, setStatus] = useState<ModelStatus | null>(null)
  const [store, setStore] = useState<ChatStore>(() => ({ conversations: [], activeId: null, settings: defaultSettings }))
  // Saving waits until the saved history loaded, so an unreadable engine never gets overwritten with an empty chat.
  const [historyLoad, setHistoryLoad] = useState<"loading" | "saved" | "unsaved">("loading")
  const loaded = historyLoad === "saved"
  // Edits wait for the saved history so loading it can't overwrite them.
  const settled = historyLoad !== "loading"
  const savedJson = useRef("")
  const pendingSave = useRef<string | null>(null)
  const saveTask = useRef<Promise<void> | null>(null)
  const [saveError, setSaveError] = useState("")
  const [saveRetry, setSaveRetry] = useState(0)
  const persistHistory = useCallback((json: string) => {
    const save = async () => {
      if (json !== savedJson.current) {
        await modelsApi.saveHistory(environmentId, JSON.parse(json))
        savedJson.current = json
      }
      if (pendingSave.current === json) pendingSave.current = null
    }
    // Older saves must finish before newer ones, even after a transient failure.
    const task = saveTask.current ? saveTask.current.catch(() => undefined).then(save) : save()
    saveTask.current = task
    const finished = () => { if (saveTask.current === task) saveTask.current = null }
    void task.then(finished, finished)
    return task
  }, [environmentId])
  const streamingRef = useRef(false)
  const [draft, setDraft] = useState("")
  const [streaming, setStreaming] = useState<string | null>(null)
  const [editing, setEditing] = useState<{ id: string; text: string } | null>(null)
  const [showSettings, setShowSettings] = useState(false)
  const [error, setError] = useState("")
  const generation = useRef<{ active: boolean; controller: AbortController | null }>({ active: false, controller: null })
  const log = useRef<HTMLDivElement>(null)
  const composer = useRef<HTMLTextAreaElement>(null)
  const stick = useRef(true)
  const historyList = useRef<HTMLUListElement>(null)
  const ready = Boolean(status && (status.status === "ready" || status.optimizer?.enabled && ["idle", "queued", "freeing_memory", "loading"].includes(status.status))) && !status?.sourceOnly && canCheckHealth && settled
  const active = store.conversations.find(c => c.id === store.activeId) ?? null
  const messages = active?.messages ?? NO_MESSAGES
  const settings = store.settings
  const replyLimit = Math.min(status?.stream ? 4096 : 2048, status?.context ? Math.floor(status.context / 2) : 4096)

  useEffect(() => {
    const scope = { active: true, controller: null as AbortController | null }; generation.current = scope
    setStatus(null); setError(""); setStreaming(null); setStore(withoutEmptyReplies)
    if (!canCheckHealth) return () => { scope.active = false; scope.controller?.abort() }
    let alive = true
    let timer = 0
    const refresh = async () => {
      try { const next = await modelsApi.status(environmentId); if (alive) { setStatus(next); setError(next.error ?? "") } }
      catch (reason) { if (alive) setError(String(reason)) }
      finally { if (alive) timer = window.setTimeout(refresh, 5000) }
    }
    void refresh()
    return () => { alive = false; scope.active = false; scope.controller?.abort(); window.clearTimeout(timer) }
  }, [environmentId, canCheckHealth])
  // Saving on every streamed token would be wasteful; persist once the reply settles.
  useEffect(() => {
    let alive = true
    const load = async (initial: boolean) => {
      try {
        let value = await modelsApi.history(environmentId)
        // One-time move of chats that older versions kept in this window's storage.
        const legacy = initial && !value && "__TAURI_INTERNALS__" in window ? legacyChats(environmentId) : null
        if (legacy) { value = serializeChats(legacy); await modelsApi.saveHistory(environmentId, value); localStorage.removeItem(legacyChatKey(environmentId)) }
        const next = parseChats(value)
        const json = JSON.stringify(serializeChats(next))
        if (!alive || (!initial && (json === savedJson.current || streamingRef.current || pendingSave.current !== null))) return
        savedJson.current = json
        setStore(next)
        if (initial) setHistoryLoad("saved")
      } catch { if (alive && initial) setHistoryLoad("unsaved") /* Chatting still works; this session just isn't saved. */ }
    }
    void load(true)
    // Conversations continued from the CLI appear here without reopening the chat.
    let stop: (() => void) | undefined
    if ("__TAURI_INTERNALS__" in window) void import("@tauri-apps/api/event").then(({ listen }) => listen<string>("yougori-model-chat-history", event => { if (event.payload === environmentId) void load(false) })).then(unlisten => { if (alive) stop = unlisten; else unlisten() })
    return () => { alive = false; stop?.() }
  }, [environmentId])
  useEffect(() => { streamingRef.current = Boolean(streaming) }, [streaming])
  // Saving on every streamed token would be wasteful; persist once the reply settles.
  useEffect(() => {
    if (!loaded || streaming) return
    const json = JSON.stringify(serializeChats(store))
    if (json === savedJson.current && !saveTask.current) { pendingSave.current = null; return }
    pendingSave.current = json
    let alive = true
    const timer = window.setTimeout(() => {
      void persistHistory(json)
        .then(() => { if (alive) setSaveError("") })
        .catch(() => { if (alive) setSaveError("Chat history couldn't be saved. Keep this window open and retry.") })
    }, 400)
    return () => { alive = false; window.clearTimeout(timer) }
  }, [store, streaming, loaded, saveRetry, persistHistory])
  // Closing the chat right after a reply still saves it.
  useEffect(() => () => { if (pendingSave.current) void persistHistory(pendingSave.current).catch(() => undefined) }, [persistHistory])
  useLayoutEffect(() => { if (stick.current && log.current) log.current.scrollTop = log.current.scrollHeight }, [messages])
  // Keep the open conversation visible in the sidebar, including new chats that appear at the top.
  useLayoutEffect(() => {
    const list = historyList.current, item = list?.querySelector<HTMLElement>("[data-active]")
    if (!list || !item) return
    const bounds = list.getBoundingClientRect(), row = item.getBoundingClientRect()
    if (row.top < bounds.top) list.scrollTop -= bounds.top - row.top
    else if (row.bottom > bounds.bottom) list.scrollTop += row.bottom - bounds.bottom
  }, [store.activeId, active?.updatedAt])
  useLayoutEffect(() => {
    const input = composer.current
    if (!input) return
    input.style.height = "auto"; input.style.height = `${Math.min(input.scrollHeight, 220)}px`
  }, [draft])

  const updateConversation = (id: string, change: (c: Conversation) => Conversation) =>
    setStore(s => ({ ...s, conversations: s.conversations.map(c => c.id === id ? change(c) : c) }))
  const updateMessage = (conversationId: string, messageId: string, change: (m: StoredMessage) => StoredMessage) =>
    updateConversation(conversationId, c => ({ ...c, messages: c.messages.map(m => m.id === messageId ? change(m) : m) }))

  /** Generates a reply to `history`, which must end with the user's message. */
  const generate = async (conversationId: string, history: StoredMessage[]) => {
    const scope = generation.current
    if (!scope.active || scope.controller || !ready) return
    const controller = new AbortController(); scope.controller = controller
    const replyId = newId()
    const current = () => scope.active && scope.controller === controller
    let fitted: { messages: ChatMessage[]; dropped: number }
    try { fitted = fitConversation([...(settings.system.trim() ? [{ role: "system" as const, content: settings.system.trim() }] : []), ...history.map(({ role, content }) => ({ role, content }))]) }
    catch (e) { scope.controller = null; setError(e instanceof Error ? e.message : String(e)); return }
    setError(""); stick.current = true
    updateConversation(conversationId, c => ({ ...c, updatedAt: Date.now(), messages: [...history, { id: replyId, role: "assistant", content: "" }] }))
    setStreaming(replyId)
    const options: ChatOptions = { maxTokens: Math.min(settings.maxTokens, replyLimit), temperature: settings.temperature }
    const started = performance.now()
    try {
      let finish: "stop" | "length" | "cancelled" = "stop"
      let usage
      if (status?.stream) {
        const reply = await modelsApi.stream(environmentId, fitted.messages, options, text => updateMessage(conversationId, replyId, m => ({ ...m, content: m.content + text })), controller.signal)
        finish = reply.finishReason; usage = reply.usage
      } else {
        const reply = await modelsApi.chat(environmentId, fitted.messages, options)
        if (!current()) return
        const choice = reply.choices[0]
        updateMessage(conversationId, replyId, m => ({ ...m, content: choice?.message.content ?? "" }))
        finish = choice?.finish_reason === "length" ? "length" : "stop"; usage = reply.usage
      }
      if (!current()) return
      const seconds = (performance.now() - started) / 1000
      updateMessage(conversationId, replyId, m => ({ ...m, stats: { tokens: usage?.completion_tokens, seconds, finish } }))
      updateConversation(conversationId, c => ({ ...c, usage: usage ?? c.usage, dropped: fitted.dropped + (usage?.truncated_messages ?? 0) }))
    } catch (e) {
      if (!current()) return
      const message = e instanceof Error ? e.message : String(e)
      updateMessage(conversationId, replyId, m => ({ ...m, error: message, stats: { seconds: (performance.now() - started) / 1000, finish: "error" } }))
    } finally {
      if (scope.controller === controller) scope.controller = null
      if (scope.active) setStreaming(s => s === replyId ? null : s)
    }
  }

  const send = (text = draft) => {
    const content = text.trim()
    if (!content || !ready || generation.current.controller) return
    const message: StoredMessage = { id: newId(), role: "user", content }
    let conversation = active
    if (!conversation) {
      conversation = { id: newId(), title: titleFor(content), messages: [], updatedAt: Date.now() }
      const created = conversation
      setStore(s => ({ ...s, activeId: created.id, conversations: [created, ...s.conversations] }))
    }
    setDraft("")
    void generate(conversation.id, [...conversation.messages.filter(m => m.content), message])
  }
  const stop = () => {
    const scope = generation.current
    scope.controller?.abort()
    // Without streaming the server can't be interrupted, so the pending reply is discarded.
    if (!status?.stream && scope.controller) { scope.controller = null; setStreaming(null); setStore(withoutEmptyReplies) }
  }
  const regenerate = (messageId: string) => {
    if (!active) return
    const index = active.messages.findIndex(m => m.id === messageId)
    void generate(active.id, active.messages.slice(0, index))
  }
  const saveEdit = () => {
    if (!active || !editing?.text.trim()) return
    const index = active.messages.findIndex(m => m.id === editing.id)
    setEditing(null)
    void generate(active.id, [...active.messages.slice(0, index), { ...active.messages[index]!, content: editing.text.trim() }])
  }
  const selectConversation = (id: string | null) => {
    if (streaming) return
    setEditing(null); setError(""); stick.current = true
    setStore(s => ({ ...s, activeId: id }))
    composer.current?.focus()
  }
  const actions = useRef({ regenerate, edit: (message: StoredMessage) => setEditing({ id: message.id, text: message.content }), continue: () => send("Continue.") })
  actions.current = { regenerate, edit: (message: StoredMessage) => setEditing({ id: message.id, text: message.content }), continue: () => send("Continue.") }
  const onAction = useCallback((action: "regenerate" | "edit" | "continue", message: StoredMessage) => action === "edit" ? actions.current.edit(message) : action === "regenerate" ? actions.current.regenerate(message.id) : actions.current.continue(), [])
  const deleteConversation = (id: string) => setStore(s => ({ ...s, activeId: s.activeId === id ? null : s.activeId, conversations: s.conversations.filter(c => c.id !== id) }))

  const phase = environmentStatus === "provisioning" ? "Downloading and preparing container image" : environmentStatus && environmentStatus !== "running" ? environmentStatus : status ? modelProgress(status) : "Starting"
  const contextWindow = active?.usage?.context_window ?? status?.context
  const contextUsed = active?.usage ? active.usage.prompt_tokens + active.usage.completion_tokens : 0
  const modelName = status?.model?.split("/").pop() ?? "Model"
  const last = messages[messages.length - 1]
  const history = [...store.conversations].sort((a, b) => b.updatedAt - a.updatedAt)
  if (status?.sourceOnly) return <section className="model-card" aria-label="Source-only model"><h3>Source files ready</h3><p>This folder has no model weights. You can publish and download its source files through Neo Grid. Chat and inference API become available when a runnable checkpoint is supplied.</p></section>
  if (status?.task === "structured-decision") return <ModelDecisions environmentId={environmentId} status={status} />

  return <section className="model-chat" aria-label="Model chat">
    <nav className="model-chat-history" aria-label="Conversations">
      <Button size="sm" variant="outline" disabled={Boolean(streaming)} onClick={() => selectConversation(null)}>New chat</Button>
      <ul ref={historyList}>{history.map(c => <li key={c.id} data-active={c.id === store.activeId || undefined}>
        <button type="button" disabled={Boolean(streaming)} aria-current={c.id === store.activeId || undefined} onClick={() => selectConversation(c.id)}><span>{c.title}</span><time>{ago(c.updatedAt)}</time></button>
        <button type="button" className="model-chat-delete" disabled={Boolean(streaming) && c.id === store.activeId} aria-label={`Delete ${c.title}`} onClick={() => deleteConversation(c.id)}>Delete</button>
      </li>)}</ul>
    </nav>

    <div className="model-chat-main">
      <div className="model-chat-bar">
        <span role="status"><strong>{status?.model}</strong>{status?.model ? " · " : ""}{phase}{status?.gpu ? ` · ${status.gpu}` : ""}{status?.precision ? ` · ${status.precision}` : ""}</span>
        <div className="model-chat-bar-actions">
          {contextWindow && contextUsed ? <span className="model-context" title={`${contextUsed.toLocaleString()} of ${contextWindow.toLocaleString()} tokens`}>
            <span className="model-context-meter"><span style={{ width: `${Math.min(100, (contextUsed / contextWindow) * 100)}%` }} /></span>
            {formatTokens(contextUsed)} / {formatTokens(contextWindow)}
          </span> : null}
          <Button size="xs" variant={showSettings ? "secondary" : "ghost"} aria-expanded={showSettings} onClick={() => setShowSettings(v => !v)}>Settings</Button>
        </div>
      </div>

      {showSettings ? <div className="model-settings">
        <label className="model-settings-system">
          <span className="model-label">System prompt</span>
          <textarea aria-label="System prompt" disabled={!settled} rows={3} maxLength={8000} placeholder="You are a helpful assistant." value={settings.system} onChange={e => { const system = e.target.value; setStore(s => ({ ...s, settings: { ...s.settings, system } })) }} />
        </label>
        <label>
          <span className="model-label">Temperature <output>{settings.temperature.toFixed(1)}</output></span>
          <input aria-label="Temperature" disabled={!settled} type="range" min={0} max={2} step={0.1} value={settings.temperature} onChange={e => { const temperature = Number(e.target.value); setStore(s => ({ ...s, settings: { ...s.settings, temperature } })) }} />
          <small>{settings.temperature === 0 ? "Deterministic" : settings.temperature < 0.5 ? "Focused" : settings.temperature <= 1 ? "Balanced" : "Creative"}</small>
        </label>
        <label>
          <span className="model-label">Max reply length <output>{Math.min(settings.maxTokens, replyLimit).toLocaleString()} tokens</output></span>
          <input aria-label="Max reply length" disabled={!settled} type="range" min={64} max={replyLimit} step={64} value={Math.min(settings.maxTokens, replyLimit)} onChange={e => { const maxTokens = Number(e.target.value); setStore(s => ({ ...s, settings: { ...s.settings, maxTokens } })) }} />
          <small>{status && !status.stream ? "Run this model again from Hugging Face for streaming and longer replies." : "Longer replies leave less room for history."}</small>
        </label>
      </div> : null}

      <div ref={log} role="log" aria-live="polite" aria-busy={Boolean(streaming)} className="model-chat-log" onScroll={e => { const el = e.currentTarget; stick.current = el.scrollHeight - el.scrollTop - el.clientHeight < 48 }}>
        {messages.length ? <>
          {active?.dropped ? <p className="model-chat-notice">{active.dropped} earlier {active.dropped === 1 ? "message no longer fits" : "messages no longer fit"} in the model's context and {active.dropped === 1 ? "was" : "were"} left out.</p> : null}
          {messages.map(message => editing?.id === message.id
            ? <form key={message.id} className="model-message model-message-edit" data-role="user" onSubmit={e => { e.preventDefault(); saveEdit() }}>
              <textarea aria-label="Edit message" autoFocus value={editing.text} maxLength={16000} onChange={e => setEditing({ id: message.id, text: e.target.value })} onKeyDown={e => { if (e.key === "Escape") setEditing(null); else if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); saveEdit() } }} />
              <div className="model-message-actions"><Button size="xs" variant="ghost" type="button" onClick={() => setEditing(null)}>Cancel</Button><Button size="xs" type="submit" disabled={!editing.text.trim() || !ready}>Save and send</Button></div>
            </form>
            : <ChatMessageView key={message.id} message={message} modelName={modelName} streaming={streaming === message.id} busy={Boolean(streaming)} ready={ready} isLast={message === last} onAction={onAction} />)}
        </> : <div className="model-chat-empty">
          {ready ? <>
            <p>Ask {modelName} anything.</p>
            <div className="model-starters">{STARTERS.map(text => <button key={text} type="button" onClick={() => send(text)}>{text}</button>)}</div>
          </> : <p>First launch downloads the model. Progress shows in the logs below.</p>}
        </div>}
      </div>

      {status?.chatWarning ? <p role="status" className="model-chat-notice">{status.chatWarning}{status.chatModelSuggestion ? <> Suggested: <code>hf.co/{status.chatModelSuggestion}</code></> : null}</p> : null}
      {environment?.lastError ? <p role="alert" className="model-error">{environment.lastError}</p> : null}
      {environmentStatus === "stopped" || environmentStatus === "error" ? <Button disabled={Boolean(environmentActions[environmentId])} onClick={() => void setEnvironmentStatus(environmentId, "running").catch(() => undefined)}>Start model</Button> : null}
      {error ? <p role="alert" className="model-error">{error}</p> : null}
      {saveError ? <div role="alert" className="model-error"><p>{saveError}</p><Button size="xs" variant="outline" onClick={() => { setSaveError(""); setSaveRetry(value => value + 1) }}>Retry saving</Button></div> : null}

      <form className="model-composer" onSubmit={event => { event.preventDefault(); send() }}>
        <textarea ref={composer} aria-label="Message your model" placeholder={ready ? `Message ${modelName}…` : "Waiting for the model…"} rows={1} value={draft} maxLength={16000}
          onChange={e => setDraft(e.target.value)}
          onKeyDown={e => {
            if (e.key === "Escape" && streaming) { e.preventDefault(); stop() }
            else if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) { e.preventDefault(); send() }
          }} />
        {streaming
          ? <Button type="button" variant="outline" onClick={stop} aria-label="Stop generating">Stop</Button>
          : <Button type="submit" disabled={!draft.trim() || !ready} aria-label="Send message">Send</Button>}
      </form>
      <p className="model-composer-hint">Enter to send · Shift+Enter for a new line{streaming ? " · Esc to stop" : ""}</p>

      <details open={status?.status !== "ready"} className="model-logs">
        <summary>Startup logs</summary>
        <div className="h-56"><GuestLogs environmentId={environmentId} active /></div>
      </details>
    </div>
  </section>
}

const ChatMessageView = memo(function ChatMessageView({ message, modelName, streaming, busy, ready, isLast, onAction }: {
  message: StoredMessage; modelName: string; streaming: boolean; busy: boolean; ready: boolean; isLast: boolean
  onAction: (action: "regenerate" | "edit" | "continue", message: StoredMessage) => void
}) {
  const [copied, setCopied] = useState(false)
  const copy = () => void terminalClipboard.writeText(message.content).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) }).catch(() => undefined)
  const user = message.role === "user"
  const stats = message.stats
  return <div className="model-message" data-role={user ? "user" : "assistant"} data-streaming={streaming || undefined}>
    <span>{user ? "You" : modelName}</span>
    {user ? <p>{message.content}</p>
      : message.content ? <Markdown text={message.content} />
      : streaming ? <p className="model-chat-pending">Thinking…</p> : null}
    {message.error ? <p role="alert" className="model-error">{message.error}</p> : null}
    {!streaming ? <div className="model-message-footer">
      {!user && stats && (stats.inputTokens ?? stats.tokens) ? <span className="model-message-stats">{(stats.inputTokens ?? stats.tokens)!.toLocaleString()} {stats.inputTokens != null ? "input " : ""}tokens · {((stats.inputTokens ?? stats.tokens)! / Math.max(stats.seconds, 0.001)).toFixed(1)} {stats.inputTokens != null ? "input " : ""}tok/s</span> : null}
      {!user && stats?.finish === "cancelled" ? <span className="model-message-stats">Stopped</span> : null}
      {!user && stats?.finish === "length" ? <span className="model-message-stats">Reached the reply length limit</span> : null}
      <div className="model-message-actions">
        {message.content ? <button type="button" onClick={copy}>{copied ? "Copied" : "Copy"}</button> : null}
        {user ? <button type="button" disabled={busy || !ready} onClick={() => onAction("edit", message)}>Edit</button> : null}
        {!user && isLast ? <button type="button" disabled={busy || !ready} onClick={() => onAction("regenerate", message)}>{message.error ? "Retry" : "Regenerate"}</button> : null}
        {!user && isLast && stats?.finish === "length" ? <button type="button" disabled={busy || !ready} onClick={() => onAction("continue", message)}>Continue</button> : null}
      </div>
    </div> : null}
  </div>
})
