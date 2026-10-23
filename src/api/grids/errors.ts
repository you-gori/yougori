/** What a refusal was, in a form a page can branch on, with the words the engine used kept
 *  exactly as they were. The client never rewrites an engine sentence: it classifies it. */
import { ACTION_NAMES } from "@/api/grids/permits.generated"
import type { Action, Capability, Role } from "@/api/grids/types"

export type Failure =
  | "notAllowed" | "needsApproval" | "conflict" | "notFound" | "notReady"
  | "capabilityOff" | "desktopOnly" | "cliOnly" | "offline" | "abandoned" | "unknown"

export class GridError extends Error {
  readonly failure: Failure
  /** The engine command, or the product action, the call was making. */
  readonly command: string
  readonly requestId: string
  constructor(failure: Failure, message: string, command: string, requestId: string) {
    super(message)
    this.name = "GridError"
    this.failure = failure
    this.command = command
    this.requestId = requestId
  }
}

/** The client's own table said no, so the engine was never asked. The engine decides what
 *  actually happens; this only saves a round trip and gives a sentence sooner. */
export class NotAllowedError extends GridError {
  readonly action: Action
  readonly held: readonly Role[]
  constructor(action: Action, held: readonly Role[], command: string, requestId: string) {
    super("notAllowed", `This account may not ${ACTION_NAMES[action]} in this grid`, command, requestId)
    this.name = "NotAllowedError"
    this.action = action
    this.held = held
  }
}

/** This grid does not do that at all, whoever is asking. */
export class CapabilityOffError extends GridError {
  readonly capability: Capability
  constructor(capability: Capability, doing: string, command: string, requestId: string) {
    super("capabilityOff", `This grid does not ${doing}, so there is nothing to change here`, command, requestId)
    this.name = "CapabilityOffError"
    this.capability = capability
  }
}

/** Somebody else has to agree before this can happen. */
export class NeedsApprovalError extends GridError {
  readonly resourceId: string
  readonly approvalId: string | null
  constructor(message: string, resourceId: string, approvalId: string | null, command: string, requestId: string) {
    super("needsApproval", message, command, requestId)
    this.name = "NeedsApprovalError"
    this.resourceId = resourceId
    this.approvalId = approvalId
  }
}

/** Somebody changed it while this page was looking at an older copy. */
export class ConflictError extends GridError {
  readonly expected: number
  readonly actual: number | null
  constructor(message: string, expected: number, actual: number | null, command: string, requestId: string) {
    super("conflict", message, command, requestId)
    this.name = "ConflictError"
    this.expected = expected
    this.actual = actual
  }
}

/** Only the desktop app can do this; a browser fixture cannot. The sentence says what the
 *  person was doing, because one sentence for all four grids tells them nothing. */
export class DesktopOnlyError extends GridError {
  constructor(message: string, command: string, requestId: string) {
    super("desktopOnly", message, command, requestId)
    this.name = "DesktopOnlyError"
  }
}

/** Only the command line can do this today. The sentence names the line to run. */
export class CliOnlyError extends GridError {
  readonly line: string
  constructor(line: string, command: string, requestId: string) {
    super("cliOnly", `The desktop does not offer this yet. Run \`${line}\` instead.`, command, requestId)
    this.name = "CliOnlyError"
    this.line = line
  }
}

/** The engine answers with a sentence, not a code, so these are the sentences the Rust produces
 *  today. Anything else stays `unknown` and the engine's own words are shown unchanged. When the
 *  engine starts sending a code, this table is the only thing that goes. */
const SENTENCES: ReadonlyArray<readonly [RegExp, Failure]> = [
  [/^Open Yougori Desktop|must run inside its native desktop application|from the main Yougori window/i, "desktopOnly"],
  [/needs an approver|waiting for approval|someone else must agree/i, "needsApproval"],
  [/already decided|already used|changed since you|out of date/i, "conflict"],
  [/does not serve models|does not host workspaces|does not broker credentials|does not run authorised research/i, "capabilityOff"],
  [/may not |are not allowed to |is not allowed to |refused/i, "notAllowed"],
  [/no computer with the ID|could not be found|was not found|not found/i, "notFound"],
  [/cannot be reached|stopped answering|is not connected|offline/i, "offline"],
  [/is not ready|not ready yet/i, "notReady"],
]

export function classify(message: string, command: string, requestId: string): GridError {
  for (const [pattern, failure] of SENTENCES) {
    if (pattern.test(message)) return new GridError(failure, message, command, requestId)
  }
  return new GridError("unknown", message, command, requestId)
}

/** The sentence inside any thrown thing, for a page that only wants to show it. */
export function say(reason: unknown): string {
  return reason instanceof Error ? reason.message : String(reason)
}
