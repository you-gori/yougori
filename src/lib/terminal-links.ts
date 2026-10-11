export const MAX_TERMINAL_LINKS = 8
const MAX_URL_LENGTH = 2048

export function normalizeTerminalLink(value: string): string | null {
  if (value.length > MAX_URL_LENGTH) return null
  try {
    const url = new URL(/^www\./i.test(value) ? `https://${value}` : value)
    if (!["http:", "https:"].includes(url.protocol) || !url.hostname || url.username || url.password) return null
    return url.href.length <= MAX_URL_LENGTH ? url.href : null
  } catch { return null }
}

// Remove surrounding prose punctuation without damaging balanced URL paths.
function trimLinkCandidate(value: string) {
  let candidate = value, previous
  do {
    previous = candidate
    candidate = candidate.replace(/[.,;!]+$/, "")
    for (const [open, close] of [["(", ")"], ["[", "]"], ["{", "}"]] as const) {
      while (candidate.endsWith(close) && candidate.split(close).length > candidate.split(open).length) candidate = candidate.slice(0, -1)
    }
  } while (candidate !== previous)
  return candidate
}

/** Links in plain terminal text, with the source position and length each one occupies. */
export function terminalLinkRanges(text: string): { url: string; start: number; length: number }[] {
  // eslint-disable-next-line no-control-regex -- never include terminal control bytes in a URL
  return [...text.matchAll(/(?:https?:\/\/|www\.)[^\s<>"'`\x00-\x1f]+/gi)].flatMap(match => {
    const candidate = trimLinkCandidate(match[0])
    const url = normalizeTerminalLink(candidate)
    return url ? [{ url, start: match.index, length: candidate.length }] : []
  })
}

export function extractTerminalLinks(text: string): string[] {
  const links: string[] = []
  // Input from xterm is already ANSI-decoded. Bound other console callers too.
  // Serial consoles may still contain ANSI styling (xterm callers do not).
  // eslint-disable-next-line no-control-regex -- strip terminal CSI control sequences
  const plain = text.slice(-65536).replace(/\x1b\[[0-?]*[ -/]*[@-~]/g, "")
  for (const { url } of terminalLinkRanges(plain)) if (!links.includes(url)) links.push(url)
  return links.slice(-MAX_TERMINAL_LINKS)
}

export function mergeTerminalLinks(previous: string[], incoming: string[]): string[] {
  const next = [...previous]
  for (const url of incoming) if (!next.includes(url)) next.push(url)
  const bounded = next.slice(-MAX_TERMINAL_LINKS)
  return previous.length === bounded.length && previous.every((url, index) => url === bounded[index]) ? previous : bounded
}

export function isLocalTerminalLink(value: string): boolean {
  const host = new URL(value).hostname.toLowerCase()
  return host === "localhost" || host.endsWith(".localhost") || host === "0.0.0.0" || host.startsWith("127.") || host === "[::1]" || host === "[::]"
}
