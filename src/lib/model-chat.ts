import type { ChatMessage, ChatUsage } from "@/api/projects-api"

// Minimal Markdown for model replies.
export type Block =
  | { kind: "code"; lang: string; text: string }
  | { kind: "heading"; level: number; text: string }
  | { kind: "list"; ordered: boolean; start: number; items: string[] }
  | { kind: "quote"; text: string }
  | { kind: "table"; head: string[]; rows: string[][] }
  | { kind: "rule" }
  | { kind: "paragraph"; text: string }

const fence = /^\s*(```|~~~)\s*([\w+#.-]*)\s*$/
const bullet = /^\s*[-*+]\s+(.*)$/
const numbered = /^\s*(\d+)[.)]\s+(.*)$/
const cells = (line: string) => line.trim().replace(/^\||\|$/g, "").split("|").map(cell => cell.trim())

export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n")
  const blocks: Block[] = []
  let i = 0
  while (i < lines.length) {
    const line = lines[i]!
    const open = fence.exec(line)
    if (open) {
      const body: string[] = []
      i++
      // An unclosed fence (mid-stream) runs to the end of the reply.
      while (i < lines.length && !(lines[i]!.trim().startsWith(open[1]!) && lines[i]!.trim().replace(/[`~]/g, "") === "")) body.push(lines[i++]!)
      i++
      blocks.push({ kind: "code", lang: open[2] ?? "", text: body.join("\n") })
      continue
    }
    if (!line.trim()) { i++; continue }
    const heading = /^\s*(#{1,6})\s+(.*?)\s*#*\s*$/.exec(line)
    if (heading) { blocks.push({ kind: "heading", level: heading[1]!.length, text: heading[2]! }); i++; continue }
    if (/^\s*([-*_])(\s*\1){2,}\s*$/.test(line)) { blocks.push({ kind: "rule" }); i++; continue }
    if (line.trim().startsWith("|") && i + 1 < lines.length && /^\s*\|?\s*:?-{2,}:?\s*(\|\s*:?-{2,}:?\s*)*\|?\s*$/.test(lines[i + 1]!)) {
      const head = cells(line)
      const rows: string[][] = []
      i += 2
      while (i < lines.length && lines[i]!.trim().startsWith("|")) rows.push(cells(lines[i++]!))
      blocks.push({ kind: "table", head, rows })
      continue
    }
    if (/^\s*>/.test(line)) {
      const body: string[] = []
      while (i < lines.length && /^\s*>/.test(lines[i]!)) body.push(lines[i++]!.replace(/^\s*>\s?/, ""))
      blocks.push({ kind: "quote", text: body.join("\n") })
      continue
    }
    const listStart = bullet.exec(line) ?? numbered.exec(line)
    if (listStart) {
      const ordered = !bullet.test(line)
      const start = ordered ? Number(numbered.exec(line)![1]) : 1
      const items: string[] = []
      while (i < lines.length) {
        const current = lines[i]!
        const item = ordered ? numbered.exec(current) : bullet.exec(current)
        if (item) { items.push(ordered ? item[2]! : item[1]!); i++; continue }
        // Indented continuation lines belong to the previous item.
        if (items.length && /^\s{2,}\S/.test(current) && !fence.test(current)) { items[items.length - 1] += "\n" + current.trim(); i++; continue }
        break
      }
      blocks.push({ kind: "list", ordered, start, items })
      continue
    }
    const body: string[] = []
    while (i < lines.length && lines[i]!.trim() && !fence.test(lines[i]!) && !/^\s*(#{1,6}\s|>)/.test(lines[i]!) && !bullet.test(lines[i]!) && !numbered.test(lines[i]!)) body.push(lines[i++]!)
    if (!body.length) body.push(lines[i++]!)
    blocks.push({ kind: "paragraph", text: body.join("\n") })
  }
  return blocks
}


export interface ChatStats { tokens?: number; inputTokens?: number; seconds: number; finish: "stop" | "length" | "cancelled" | "error" }
export interface StoredMessage extends ChatMessage { id: string; stats?: ChatStats; error?: string }
export interface Conversation { id: string; title: string; messages: StoredMessage[]; updatedAt: number; usage?: ChatUsage; dropped?: number }
export interface ChatSettings { system: string; temperature: number; maxTokens: number }
export interface ChatStore { conversations: Conversation[]; activeId: string | null; settings: ChatSettings }

export const defaultSettings: ChatSettings = { system: "", temperature: 0.7, maxTokens: 1024 }
export const legacyChatKey = (environmentId: string) => `yougori.model-chat.v1:${environmentId}`
const MAX_CONVERSATIONS = 40

/** Reads a stored chat history (engine JSON or an older browser copy), dropping anything malformed. */
export function parseChats(value: unknown): ChatStore {
  const stored = value && typeof value === "object" ? value as Partial<ChatStore> : null
  const conversations = Array.isArray(stored?.conversations) ? stored.conversations.filter(c => c && typeof c.id === "string" && Array.isArray(c.messages)) : []
  const settings = { ...defaultSettings, ...stored?.settings }
  return { conversations, activeId: conversations.some(c => c.id === stored?.activeId) ? stored!.activeId! : null, settings }
}

/** The history as saved: empty replies and conversations dropped, newest 40 conversations kept. */
export function serializeChats(store: ChatStore): ChatStore {
  const conversations = store.conversations
    .map(c => ({ ...c, messages: c.messages.filter(m => m.content || m.error) }))
    .filter(c => c.messages.length)
    .sort((a, b) => b.updatedAt - a.updatedAt)
    .slice(0, MAX_CONVERSATIONS)
  return { ...store, activeId: conversations.some(c => c.id === store.activeId) ? store.activeId : null, conversations }
}

/** Chats that older versions kept in browser storage, if any. */
export function legacyChats(environmentId: string): ChatStore | null {
  try {
    const raw = localStorage.getItem(legacyChatKey(environmentId))
    return raw === null ? null : parseChats(JSON.parse(raw))
  } catch { return null }
}

export const titleFor = (text: string) => { const line = text.trim().replace(/\s+/g, " "); return line.length > 48 ? line.slice(0, 47) + "…" : line || "New chat" }

// The model server accepts at most 128 messages, 32,768 characters and a 64 KiB body.
const MAX_CHARS = 30000, MAX_BYTES = 56000, MAX_MESSAGES = 128
const bytes = (message: ChatMessage) => new TextEncoder().encode(JSON.stringify(message)).length + 1

/** Keeps the system prompt and the newest turns that fit the request limits; older turns are dropped. */
export function fitConversation(messages: ChatMessage[]): { messages: ChatMessage[]; dropped: number } {
  const system = messages.filter(m => m.role === "system")
  // A failed reply can leave two user turns in a row; strict chat templates require alternating roles.
  const rest = messages.filter(m => m.role !== "system").reduce<ChatMessage[]>((turns, m) => {
    const previous = turns[turns.length - 1]
    if (previous?.role === m.role) turns[turns.length - 1] = { role: m.role, content: `${previous.content}

${m.content}` }
    else turns.push(m)
    return turns
  }, [])
  let chars = system.reduce((sum, m) => sum + m.content.length, 0)
  let size = system.reduce((sum, m) => sum + bytes(m), 0)
  let start = rest.length
  while (start > 0) {
    const message = rest[start - 1]!
    if (chars + message.content.length > MAX_CHARS || size + bytes(message) > MAX_BYTES || system.length + rest.length - start + 1 > MAX_MESSAGES) break
    chars += message.content.length; size += bytes(message); start--
  }
  // Chat templates expect the first turn after the system prompt to come from the user.
  while (start < rest.length && rest[start]!.role !== "user") start++
  if (start >= rest.length) throw new Error("This message is too long. Shorten it or the system prompt.")
  return { messages: [...system, ...rest.slice(start)], dropped: start }
}
