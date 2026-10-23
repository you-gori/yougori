import type { ReactNode } from "react"
import { workspaceApi } from "@/api/workspace-api"

// READMEs on the Hub are written by anyone: rendered as text with basic Markdown only. Never
// HTML, never images (a picture could imitate the Verified badge), and links only to http(s)
// addresses, opened in the browser. Every pattern is bounded, so no line can stall the page.

const INLINE = /(`[^`\n]{1,500}`)|(\*\*[^*\n]{1,500}\*\*)|(!?\[[^\]\n]{0,300}\]\([^)\s]{1,2000}\))|(https?:\/\/[^\s<>()]{0,2000}[^\s<>().,;:!?'"])/g
const LONGEST_FORMATTED = 20_000

function link(href: string, label: string, key: string): ReactNode {
  if (!/^https?:\/\//i.test(href)) return <span key={key}>{label}</span>
  return <button key={key} type="button" className="hub-readme-link" title={href} onClick={() => { void workspaceApi.openUrl(href).catch(() => undefined) }}>{label}</button>
}

function inline(text: string, key: string): ReactNode[] {
  if (text.length > LONGEST_FORMATTED) return [text]
  const parts: ReactNode[] = []
  let last = 0, index = 0
  for (const match of text.matchAll(INLINE)) {
    const at = match.index ?? 0
    if (at > last) parts.push(text.slice(last, at))
    const token = match[0], id = `${key}-${index++}`
    if (match[1]) parts.push(<code key={id}>{token.slice(1, -1)}</code>)
    else if (match[2]) parts.push(<strong key={id}>{token.slice(2, -2)}</strong>)
    else if (match[3]) {
      const close = token.indexOf("](")
      const label = token.slice(token.startsWith("!") ? 2 : 1, close), href = token.slice(close + 2, -1)
      parts.push(token.startsWith("!") ? <span key={id} className="hub-readme-image">[image{label ? `: ${label}` : ""}]</span> : link(href, label || href, id))
    } else parts.push(link(token, token, id))
    last = at + token.length
  }
  if (last < text.length) parts.push(text.slice(last))
  return parts
}

/** `# Title ##` as its level and text, or nothing. Plain string work, not a backtracking pattern. */
function headingOf(line: string): { level: number; text: string } | null {
  const match = /^(#{1,6})[ \t]+([\s\S]*)$/.exec(line)
  if (!match) return null
  let text = (match[2] ?? "").trimEnd()
  let end = text.length
  while (end > 0 && text[end - 1] === "#") end--
  if (end < text.length && (end === 0 || text[end - 1] === " " || text[end - 1] === "\t")) text = text.slice(0, end).trimEnd()
  return text ? { level: (match[1] ?? "#").length, text } : null
}

export function HubReadme({ text }: { text: string }) {
  const lines = text.replace(/^---\r?\n[\s\S]*?\r?\n---(?:\r?\n|$)/, "").split(/\r?\n/)
  const line = (index: number) => lines[index] ?? ""
  const blocks: ReactNode[] = []
  const list = /^\s*(?:[-*+]|\d+[.)])\s+/
  for (let at = 0; at < lines.length;) {
    const current = line(at)
    if (!current.trim()) { at++; continue }
    if (/^\s*```/.test(current)) {
      const start = at++, code: string[] = []
      while (at < lines.length && !/^\s*```/.test(line(at))) code.push(line(at++))
      at++
      blocks.push(<pre key={start}><code>{code.join("\n")}</code></pre>)
      continue
    }
    const heading = headingOf(current)
    if (heading) {
      const content = inline(heading.text, `h${at}`)
      blocks.push(heading.level === 1 ? <h2 key={at}>{content}</h2> : heading.level === 2 ? <h3 key={at}>{content}</h3> : <h4 key={at}>{content}</h4>)
      at++
      continue
    }
    if (/^\s*>\s?/.test(current)) {
      const start = at, quote: string[] = []
      while (at < lines.length && /^\s*>\s?/.test(line(at))) quote.push(line(at++).replace(/^\s*>\s?/, ""))
      blocks.push(<blockquote key={start}>{inline(quote.join(" "), `q${start}`)}</blockquote>)
      continue
    }
    if (list.test(current)) {
      const start = at, ordered = /^\s*\d+[.)]\s+/.test(current), items: string[] = []
      while (at < lines.length && list.test(line(at))) items.push(line(at++).replace(list, ""))
      const content = items.map((item, index) => <li key={index}>{inline(item, `l${start}-${index}`)}</li>)
      blocks.push(ordered ? <ol key={start}>{content}</ol> : <ul key={start}>{content}</ul>)
      continue
    }
    if (/^\s*(?:-{3,}|\*{3,}|_{3,})\s*$/.test(current)) { blocks.push(<hr key={at} />); at++; continue }
    const start = at, paragraph: string[] = []
    while (at < lines.length && line(at).trim() && !/^\s*(?:```|#{1,6}\s|>|[-*+]\s|\d+[.)]\s)/.test(line(at))) paragraph.push(line(at++).trim())
    if (!paragraph.length) paragraph.push(line(at++).trim())
    blocks.push(<p key={start}>{inline(paragraph.join(" "), `p${start}`)}</p>)
  }
  return <article className="hub-readme" aria-label="README">{blocks}</article>
}
