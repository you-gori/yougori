/** The engine's CORE-07 product document of a setup (`product` on `setup_get`), as the desktop
 *  reads it: the same document `yougori template status` shows, so the two resolve one state.
 *  `setup_plan` and `setup_permissions` carry one too: a plan's lists what its chosen capabilities
 *  ask for (each requested), and a setup's read-back permissions list what its capabilities request.
 *
 *  This mirrors the parts of `foundation::product::ProductView` a setup's document carries today:
 *  the permissions its capabilities ask for, the inventory of its move to VM sandboxes, and what
 *  needs the person. It decides nothing: the engine writes the document, and the words here only
 *  say what it holds. A document this desktop cannot read is said to be unreadable, never guessed
 *  at. `product.test.ts` reads every golden fixture the Rust contract pins, so a drift fails there.
 */

/** The contract version this desktop reads (`PRODUCT_CONTRACT_VERSION`). */
export const PRODUCT_CONTRACT_VERSION = 2

export type PermissionStatus =
  | { status: "requested" }
  | { status: "permitted_by_contract" }
  | { status: "awaiting_approval" }
  | { status: "approved" }
  | { status: "not_permitted"; refusal: Refusal }

export interface PermissionLine { kind: string; text: string; status: PermissionStatus }

/** A stable code in its domain, a plain reason and a remedy with its words. */
export interface Refusal {
  code: { domain: string; code: string }
  reason: string
  remedy: { remedy: string } & Record<string, unknown>
  remedy_text: string
}

/** An execution category with its own recorded label; `sandbox` is true only for a VM. */
export interface CategoryShown { category: string; label: string; decision: string; sandbox: boolean }

export type LegacyChoice =
  | { recorded: "sandbox_type"; kind: string; gpu: boolean }
  | { recorded: "isolation_tier"; tier: string }
  | { recorded: "category"; category: string }

export type MigrationOption = { option: "vm_sandbox" } | { option: "labelled"; category: CategoryShown }

export type MigrationOutcome =
  | { outcome: "unchanged"; requirement: unknown }
  | { outcome: "strengthened"; requirement: unknown; reason: string }
  | { outcome: "preserved"; category: CategoryShown }
  | { outcome: "needs_decision"; options: MigrationOption[]; refusal: Refusal }
  | { outcome: "decided"; choice: MigrationOption }
  | { outcome: "refused"; refusal: Refusal }
  | { outcome: "follows_owner" }

export interface MigrationItem { subject: string; recorded: LegacyChoice; outcome: MigrationOutcome }

export type MigrationStatus =
  | { status: "not_needed" }
  | { status: "pending" }
  | { status: "in_progress"; completed: number; total: number }
  | { status: "interrupted"; completed: number; total: number }
  | { status: "completed" }

export interface MigrationShown { status: MigrationStatus; items: MigrationItem[]; backup?: unknown }

/** The document. Parts a setup's document does not carry yet (execution, capabilities, sandbox,
 *  model, endpoint, grants, progress) are kept as the engine sent them and not interpreted here. */
export interface ProductView {
  contract_version: number
  subject: { kind: "setup" | "sandbox" | "model" | "operation"; id: string }
  shown_at: { clock: string; at: number; configuration: string }
  permissions?: PermissionLine[]
  refusals?: Refusal[]
  migration?: MigrationShown
  [part: string]: unknown
}

/** A reply that carries a document (`setup_get`, `setup_plan`, `setup_permissions`): `product`,
 *  or `productUnavailable` with why the engine sent none. */
export interface ProductReply {
  product?: unknown
  setupId?: string
  summary?: { setupId?: string }
  productUnavailable?: string | null
}

export type ProductRead =
  | { readable: true; view: ProductView }
  | { readable: false; reason: string }

const isObject = (value: unknown): value is Record<string, unknown> => typeof value === "object" && value !== null && !Array.isArray(value)
const text = (value: unknown): value is string => typeof value === "string" && value.length > 0 && [...value].length <= 2_000
const tag = (value: unknown, key: string, choices: string[]) => isObject(value) && choices.includes(String(value[key]))
const list = (value: unknown, check: (item: unknown) => boolean) => Array.isArray(value) && value.length <= 512 && value.every(check)
const optionalList = (value: unknown, check: (item: unknown) => boolean) => value === undefined || list(value, check)
const category = (value: unknown) => isObject(value) && text(value.category) && text(value.label) && text(value.decision) && typeof value.sandbox === "boolean"
const refusal = (value: unknown): boolean => isObject(value) && isObject(value.code) && text(value.code.domain) && text(value.code.code) && text(value.reason) && isObject(value.remedy) && text(value.remedy.remedy) && text(value.remedy_text)
const option = (value: unknown): boolean => isObject(value) && (value.option === "vm_sandbox" || value.option === "labelled" && category(value.category))
const recorded = (value: unknown): boolean => isObject(value) && (value.recorded === "sandbox_type" && text(value.kind) && typeof value.gpu === "boolean" || value.recorded === "isolation_tier" && text(value.tier) || value.recorded === "category" && text(value.category))
const outcome = (value: unknown): boolean => {
  if (!isObject(value)) return false
  switch (value.outcome) {
    case "unchanged": case "follows_owner": return true
    case "strengthened": return text(value.reason)
    case "preserved": return category(value.category)
    case "needs_decision": return list(value.options, option) && refusal(value.refusal)
    case "decided": return option(value.choice)
    case "refused": return refusal(value.refusal)
    default: return false
  }
}
const permission = (value: unknown): boolean => isObject(value) && text(value.kind) && text(value.text) && isObject(value.status) && tag(value.status, "status", ["requested", "permitted_by_contract", "awaiting_approval", "approved", "not_permitted"]) && (value.status.status !== "not_permitted" || refusal(value.status.refusal))
const migration = (value: unknown): boolean => {
  if (value === undefined) return true
  if (!isObject(value) || !isObject(value.status) || !list(value.items, item => isObject(item) && text(item.subject) && recorded(item.recorded) && outcome(item.outcome))) return false
  const status = value.status
  if (["not_needed", "pending", "completed"].includes(String(status.status))) return true
  return ["in_progress", "interrupted"].includes(String(status.status)) && Number.isSafeInteger(status.completed) && Number.isSafeInteger(status.total) && Number(status.completed) >= 0 && Number(status.completed) <= Number(status.total)
}

/** Escape controls even when an older or malformed producer bypassed ShownText. React renders
 *  the result as text; no HTML or terminal sequence is interpreted. */
export function productText(value: string): string {
  // eslint-disable-next-line no-misleading-character-class -- escape each invisible scalar, including combining characters
  return value.replace(/[\p{Cc}\p{Cf}\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2028\u2029\u2800\u3164\ufe00-\ufe0f\uffa0]/gu, character => `\\u{${character.codePointAt(0)!.toString(16)}}`)
}

/** Validate every part this renderer dereferences. Unreadable or wrong-subject documents never
 *  supply permission/migration labels; parts this renderer does not display stay uninterpreted. */
export function readProduct(value: unknown, setupId?: string): ProductRead | null {
  if (value === undefined || value === null) return null
  const malformed: ProductRead = { readable: false, reason: "The setup's product document is not in a shape this Yougori reads." }
  if (!isObject(value) || typeof value.contract_version !== "number") return malformed
  if (value.contract_version > PRODUCT_CONTRACT_VERSION) return { readable: false, reason: "The setup's product document was written by a newer Yougori. Update Yougori to read it." }
  if (value.contract_version !== PRODUCT_CONTRACT_VERSION) return { readable: false, reason: `The setup's product document is version ${value.contract_version}, which this Yougori shows only through the engine.` }
  const subject = value.subject, shown = value.shown_at
  if (!isObject(subject) || !text(subject.id) || !["setup", "sandbox", "model", "operation"].includes(String(subject.kind)) || !isObject(shown) || !text(shown.clock) || !text(shown.configuration) || typeof shown.at !== "number" || !Number.isFinite(shown.at) || shown.at < 0 || !optionalList(value.permissions, permission) || !optionalList(value.refusals, refusal) || !migration(value.migration)) return malformed
  if (setupId !== undefined && (subject.kind !== "setup" || subject.id !== setupId)) return { readable: false, reason: "The product document belongs to another setup. Refresh this setup before using its information." }
  return { readable: true, view: value as ProductView }
}

/** A permission's standing in words. Asking grants nothing. */
export function permissionWords(status: PermissionStatus): string {
  switch (status.status) {
    case "requested": return "requested; asking grants nothing"
    case "permitted_by_contract": return "permitted by the contract"
    case "awaiting_approval": return "needs your approval"
    case "approved": return "approved"
    case "not_permitted": return `not permitted: ${status.refusal.reason}`
    default: return "status unknown to this Yougori"
  }
}

/** What an old setup recorded for one sandbox, in words. */
export function recordedWords(recorded: LegacyChoice): string {
  switch (recorded.recorded) {
    case "sandbox_type": return recorded.gpu && recorded.kind !== "gpu" ? `${recorded.kind} with a GPU` : recorded.kind
    case "isolation_tier": return `tier ${recorded.tier}`
    case "category": return recorded.category.replaceAll("_", " ")
    default: return "recorded choice unknown to this Yougori"
  }
}

export function optionWords(option: MigrationOption): string {
  return option.option === "vm_sandbox" ? "a VM sandbox" : option.option === "labelled" ? option.category.label : "an option unknown to this Yougori"
}

/** What the move to VM sandboxes does with one recorded choice, in words. */
export function outcomeWords(outcome: MigrationOutcome): string {
  switch (outcome.outcome) {
    case "unchanged": return "stays a VM sandbox"
    case "strengthened": return `becomes a VM sandbox: ${outcome.reason}`
    case "preserved": return `keeps its label: ${outcome.category.label}`
    case "needs_decision": return `a decision is needed before it moves: ${outcome.options.map(optionWords).join(" or ")}`
    case "decided": return `decided: ${optionWords(outcome.choice)}`
    case "refused": return `refused: ${outcome.refusal.reason}`
    case "follows_owner": return "follows the setup that owns it"
    default: return "an outcome unknown to this Yougori"
  }
}

/** Where the move to VM sandboxes stands, in words. */
export function migrationHeading(status: MigrationStatus): string {
  switch (status.status) {
    case "pending": return "Move to VM sandboxes (an inventory; nothing has changed)"
    case "in_progress": return "Move to VM sandboxes (in progress)"
    case "interrupted": return "Move to VM sandboxes (stopped part way; it resumes after the completed steps)"
    case "completed": return "Move to VM sandboxes (done)"
    default: return "Move to VM sandboxes"
  }
}
