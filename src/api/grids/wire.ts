/** The one call path.
 *
 *  Everything the client sends goes through `call()`, which, in order: gives the call a
 *  memorable name so several calls in one action can be read together, adds `ifVersion` when
 *  the caller said what it believed it was changing, hands the command to the transport,
 *  turns a refusal into a typed error carrying that name, and runs the answer past the
 *  redaction pass before a page sees it.
 *
 *  `setTransport` replaces the whole path in one line. That is what a test or a browser fixture
 *  should use, instead of replacing method after method.
 */
import { run } from "@/api/platform-api"
import { classify, CliOnlyError, ConflictError, DesktopOnlyError, GridError } from "@/api/grids/errors"
import { scrub, type FieldPolicy } from "@/api/grids/redact"
import type { CallOptions } from "@/api/grids/types"

export type Transport =
  <T>(command: string, args: Record<string, unknown>, browser: () => T | Promise<T>) => Promise<T>

const native: Transport = (command, args, browser) => run(command, args, browser)

let transport: Transport = native

/** Replaces the one call path, for a test or a browser fixture. Returns the previous one. */
export function setTransport(next: Transport): Transport {
  const was = transport
  transport = next
  return was
}

/** Puts the real path back. */
export function resetTransport(): void {
  transport = native
}

const FIRST = ["keen", "calm", "bright", "quiet", "swift", "steady", "warm", "clear", "bold", "gentle", "patient", "brisk"]
const SECOND = ["heron", "otter", "falcon", "beacon", "harbour", "lantern", "meadow", "compass", "willow", "ember", "quarry", "anchor"]

function pick<T>(items: readonly T[], at: number): T {
  return items[at % items.length] as T
}

/** A name for one call, memorable enough to say out loud when two people are reading the same
 *  log. Not a secret and not an identifier anybody has to type. */
export function requestId(): string {
  const bytes = new Uint8Array(3)
  if (typeof globalThis.crypto?.getRandomValues === "function") globalThis.crypto.getRandomValues(bytes)
  else for (let at = 0; at < bytes.length; at += 1) bytes[at] = Math.floor(Math.random() * 256)
  const tail = Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("")
  return `${pick(FIRST, bytes[0] ?? 0)}-${pick(SECOND, bytes[1] ?? 0)}-${tail}`
}

/** Commands the engine reads a request name from. Empty today, because no engine command reads
 *  one: both dispatchers look up the keys they want, so sending an extra key would be ignored
 *  rather than carried, and an argument nobody reads is an argument nobody can trust. Add one
 *  command at a time here as the engine learns to write it into the audit reason. */
export const CARRIES_REQUEST_ID: ReadonlySet<string> = new Set<string>()

export interface Call<T> extends CallOptions {
  /** What to answer when there is no desktop app. Without one the call is desktop-only. */
  browser?: () => T | Promise<T>
  /** What to tell the person when there is no desktop app and no browser answer. One sentence
   *  per product, naming what they were doing, because one sentence for all four says nothing. */
  desktop?: string
  policy?: FieldPolicy
}

/** The answer a command gives back when it carries a version of what it changed. No command
 *  sends one today; the field is read so that the day one does, a stale page is told. */
interface Versioned { version?: unknown }

export async function call<T>(
  command: string,
  args: Record<string, unknown> = {},
  options: Call<T> = {},
): Promise<T> {
  const id = options.requestId ?? requestId()
  const payload: Record<string, unknown> = { ...args }
  if (options.expect) payload.ifVersion = options.expect.version
  if (CARRIES_REQUEST_ID.has(command)) payload.requestId = id
  const sentence = options.desktop ?? "Open Yougori Desktop to use the grids on this computer"
  const fallback = options.browser ?? ((): T => { throw new DesktopOnlyError(sentence, command, id) })
  let answer: T
  try {
    answer = await transport<T>(command, payload, fallback)
  } catch (reason) {
    if (reason instanceof GridError) throw reason
    throw classify(reason instanceof Error ? reason.message : String(reason), command, id)
  }
  const expected = options.expect?.version
  const actual = (answer as Versioned | null)?.version
  if (expected !== undefined && typeof actual === "number" && actual !== expected) {
    throw new ConflictError("Somebody changed this while this page was looking at an older copy. Read it again and try once more.", expected, actual, command, id)
  }
  return scrub(answer, options.policy, command)
}

/** For something the command line can do and the desktop cannot. The sentence names the line,
 *  with the confirmation the route asks for, so it can be pasted as it is. */
export function cliOnly(command: string, line: string): never {
  throw new CliOnlyError(line, command, requestId())
}
