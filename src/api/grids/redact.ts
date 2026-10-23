/** A second line of defence, and nothing more.
 *
 *  What actually keeps secrets out of a screen is the engine and the hubs: a credential value
 *  never leaves the vault, the broker puts it on the request itself, and the Rust refuses to
 *  store or log one. This file is the belt to that pair of braces. If a backend ever answers
 *  with a field called `password`, a page should show "[redacted]" rather than the value, and
 *  somebody should hear about it.
 *
 *  What it cannot do, plainly:
 *  - It cannot help a page that calls `invoke` itself. It only covers answers that come through
 *    `@/api/grids/wire`, plus the Access Grid answers the credentials profile passes to it.
 *  - It cannot recognise a secret that reads like ordinary prose.
 *  - It never touches the contents of a string. Collapsing or truncating text would destroy a
 *    model's own answer, a bounty's authorization sentence or a report somebody has to read, so
 *    text rules are opt-in per field and are used only where the field really is an address.
 */

/** A field whose name says the value is the secret itself. Deliberately short: a long list that
 *  included `authorization`, `value` or `key` would blank a bounty's consent text and a research
 *  report, which is worse than the leak it guards against. */
const SECRET_NAME = /^(secret|password|passphrase|token|tokenhash|apikey|api_key|privatekey|private_key|clientsecret|client_secret|cookie|accesstoken|refreshtoken|sessiontoken|bearertoken)$/i
const SECRET_SUFFIX = /(password|passphrase|secret|privatekey|apikey|accesstoken|refreshtoken)$/i

export const REDACTED = "[redacted]"

/** Where a value that looked like a secret was found. */
export interface Leak {
  command: string
  /** The path to the field inside the answer, such as `hub.members[0].password`. */
  path: string
}

const heard = new Set<(leak: Leak) => void>()

/** Tells a test, or a developer build, that a backend sent a value where a reference belongs.
 *  It is never a thrown error: a person in front of a screen should see the rest of the page. */
export function onLeak(listener: (leak: Leak) => void): () => void {
  heard.add(listener)
  return () => { heard.delete(listener) }
}

function report(leak: Leak) {
  for (const listener of heard) listener(leak)
  if (!import.meta.env.PROD) console.warn(`The engine sent a value where a reference belongs: ${leak.command} ${leak.path}`)
}

/** `scheme://user:pass@host/path?query#fragment` keeps only `scheme://host/path`. The same rule
 *  the engine uses on its own diagnostics. */
export function safeUrl(text: string): string {
  try {
    const url = new URL(text)
    return `${url.protocol}//${url.host}${url.pathname}`.replace(/\/$/, "")
  } catch {
    return text
  }
}

/** A home folder prefix folded away, so no absolute path on somebody's computer is rendered:
 *  `C:\Users\dana\Work\site` becomes `...\Work\site`. */
export function safePath(text: string): string {
  return text
    .replace(/[A-Za-z]:[\\/]Users[\\/][^\\/]+/g, "...")
    .replace(/\/(?:home|Users)\/[^/]+/g, "...")
}

/** What one kind of answer allows through, beyond the default of leaving every string alone. */
export interface FieldPolicy {
  /** Whole subtrees that belong to somebody else: a research report's document, a bounty's
   *  terms, a swarm trace. They are not walked at all, so nothing inside one is ever changed. */
  opaque?: readonly string[]
  /** Fields a person has to be able to read in full, whatever they are called. */
  keep?: readonly string[]
  /** Fields that are addresses: anything before the host and after the path is dropped. */
  urls?: readonly string[]
  /** Fields that are diagnostics and may carry a path on somebody's computer. */
  paths?: readonly string[]
}

function secret(name: string, policy?: FieldPolicy): boolean {
  if (policy?.keep?.includes(name) || policy?.opaque?.includes(name)) return false
  return SECRET_NAME.test(name) || SECRET_SUFFIX.test(name)
}

/** Walks an answer and replaces only the fields whose names say they are secret values. Every
 *  other string is returned exactly as it arrived. */
export function scrub<T>(value: T, policy: FieldPolicy | undefined, command: string, path = ""): T {
  if (Array.isArray(value)) {
    return value.map((item, index) => scrub(item, policy, command, `${path}[${index}]`)) as T
  }
  if (!value || typeof value !== "object") return value
  const out: Record<string, unknown> = {}
  for (const [name, item] of Object.entries(value as Record<string, unknown>)) {
    const here = path ? `${path}.${name}` : name
    if (policy?.opaque?.includes(name) || policy?.keep?.includes(name)) { out[name] = item; continue }
    if (secret(name, policy)) {
      if (item !== null && item !== undefined && item !== "") report({ command, path: here })
      out[name] = REDACTED
      continue
    }
    if (typeof item === "string") {
      out[name] = policy?.urls?.includes(name) ? safeUrl(item) : policy?.paths?.includes(name) ? safePath(item) : item
      continue
    }
    out[name] = scrub(item, policy, command, here)
  }
  return out as T
}
