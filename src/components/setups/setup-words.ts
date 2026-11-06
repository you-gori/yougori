import type { ShownAvailability } from "@/api/setups/catalogue"
import type { CapabilityHealth, CapabilityStatus, Diagnostic, InstanceState, NextAction, OperationState } from "@/api/setups/types"
import type { StateTone } from "./setup-marks"

/** The words for every state the engine reports, and the tone of the mark beside them. */

export const LIFECYCLE: Record<InstanceState, { text: string; tone: StateTone }> = {
  draft: { text: "Draft", tone: "unknown" },
  creating: { text: "Being set up", tone: "busy" },
  running: { text: "Running", tone: "ok" },
  stopped: { text: "Stopped", tone: "off" },
  updating: { text: "Updating", tone: "busy" },
  removing: { text: "Being removed", tone: "busy" },
  retained: { text: "Removed, data kept", tone: "off" },
  removed: { text: "Removed", tone: "off" },
}

export const HEALTH: Record<CapabilityHealth, { text: string; tone: StateTone }> = {
  ready: { text: "Ready", tone: "ok" },
  starting: { text: "Starting", tone: "busy" },
  needs_sign_in: { text: "Needs sign-in", tone: "attention" },
  waiting_for_computer: { text: "Waiting for a computer", tone: "busy" },
  degraded: { text: "Partly working", tone: "attention" },
  failed: { text: "Failed", tone: "attention" },
  unsupported: { text: "Unsupported here", tone: "blocked" },
}

export const OPERATION: Record<OperationState, { text: string; tone: StateTone }> = {
  planned: { text: "Planned", tone: "busy" },
  awaiting_input: { text: "Waiting for you", tone: "attention" },
  applying: { text: "Working", tone: "busy" },
  cancelling: { text: "Cancelling", tone: "busy" },
  completed: { text: "Finished", tone: "ok" },
  failed: { text: "Did not finish", tone: "attention" },
  // A timeout is not a failure: the engine checks what actually happened before saying more.
  unknown: { text: "Checking what happened", tone: "busy" },
}

export const AVAILABILITY_TONE: Record<ShownAvailability, StateTone> = {
  available: "ok",
  needs_configuration: "attention",
  unsupported: "blocked",
  planned: "planned",
  unknown: "unknown",
  other_grid: "attention",
}

export const RESOURCE_ACTION: Record<string, string> = {
  create: "Create",
  reuse: "Reuse",
  attach: "Attach",
  update: "Change",
  stop: "Stop",
  detach: "Detach",
  retain: "Keep",
  remove: "Remove",
}

const lookup = <K extends string, V>(table: Record<K, V>, key: string, fallback: V): V => (key in table ? table[key as K] : fallback)
export const lifecycleOf = (value: string) => lookup(LIFECYCLE, value, { text: value, tone: "unknown" as StateTone })
export const healthOf = (value: string) => lookup(HEALTH, value, { text: value, tone: "unknown" as StateTone })
export const operationOf = (value: string) => lookup(OPERATION, value, { text: value, tone: "unknown" as StateTone })
export const resourceActionOf = (value: string | null | undefined) => value ? lookup(RESOURCE_ACTION, value, value.replace(/_/g, " ")) : "Use"

/** The capabilities that want a person: sign-ins, failures and partial ones. */
export const needsAttention = (capabilities: Pick<CapabilityStatus, "health">[]) =>
  capabilities.filter(capability => healthOf(capability.health).tone === "attention")

/** A typed next action in words. Each one is a button or a sentence; none is a command to run. */
export function nextActionText(action: NextAction | { kind: string; [key: string]: unknown }): string {
  const detail = action as Record<string, unknown>
  switch (action.kind) {
    case "sign_in": return `Sign in to ${String(detail.provider ?? "the provider")}`
    case "provide_input": return "Answer a question"
    case "choose_supported_option": return "Choose an option this computer supports"
    case "retry": return "Try again"
    case "continue": return "Continue"
    case "reconcile": return "Check what happened"
    case "cancel": return "Cancel"
    case "review": return "Review again"
    case "add_computer": return "Add a computer"
    case "view_logs": return "Open its logs"
    case "open_docs": return "Read how this works"
    default: return action.kind.replace(/_/g, " ")
  }
}

export const plural = (count: number, one: string, many = `${one}s`) => `${count.toLocaleString("en-US")} ${count === 1 ? one : many}`

/** The start of the terms' digest a change waiting for `terms_to_accept` asks the person to agree
 *  to, as the engine names it, or null. */
export function termsToAgree(error: Diagnostic | null | undefined): string | null {
  if (error?.code !== "terms_to_accept") return null
  return /accept_terms set to ([0-9a-f]{12,64})/.exec(error.message)?.[1] ?? null
}
