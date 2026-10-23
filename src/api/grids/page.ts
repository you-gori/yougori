/** Pages and filters.
 *
 *  Every status command in the four products answers with whole lists today, so this runs on
 *  this computer. That is a shape a page can be written against, not a saving: a hub with a
 *  very long history still sends all of it on the read that asks for it. Only an engine command
 *  with a cursor of its own fixes that, and when one arrives only the profile adapter changes.
 *
 *  Asking for no page asks for everything. That is deliberate: a method that used to return
 *  every worker must keep returning every worker, rather than quietly stopping at fifty.
 */
import type {
  ApprovalState, AuditDecision, Stage, WorkspaceState,
} from "@/api/grids/types"

export interface PageRequest {
  /** The cursor the last page ended at. */
  after?: string | null
  /** Left out, the whole list comes back. */
  limit?: number
}

export interface Page<T> {
  items: T[]
  /** The cursor to ask for the next page with, or null at the end. */
  next: string | null
  /** How many there are in all, known because the whole list was read. */
  total: number
}

export interface HostFilter { online?: boolean; excluded?: boolean; draining?: boolean; planId?: string | null; search?: string }
export interface WorkspaceFilter { state?: readonly WorkspaceState[]; ownerId?: string | null; hostId?: string | null; search?: string }
export interface PersonFilter { role?: string; search?: string }
export interface CredentialFilter { ownerId?: string; search?: string }
export interface GrantFilter { credentialId?: string; who?: string }
export interface ApprovalFilter { state?: readonly ApprovalState[]; requestedBy?: string; credentialId?: string }
export interface AuditFilter { action?: string; principal?: string; decision?: AuditDecision; since?: number; until?: number }
export interface ResearchFilter { stage?: readonly Stage[]; state?: readonly string[]; search?: string }

/** The largest page a caller may ask for at once, so one mistyped number cannot ask a hub for
 *  everything it has in the name of paging. */
export const MOST = 500

export function paginate<T>(items: readonly T[], request: PageRequest = {}, key: (item: T) => string): Page<T> {
  const limit = request.limit === undefined ? items.length : Math.max(1, Math.min(request.limit, MOST))
  const found = request.after ? items.findIndex(item => key(item) === request.after) : -1
  const start = request.after ? (found < 0 ? items.length : found + 1) : 0
  const slice = items.slice(start, start + limit)
  const last = slice[slice.length - 1]
  return { items: slice, next: last && start + limit < items.length ? key(last) : null, total: items.length }
}

/** Keeps the items every test agrees with. A filter left out never narrows anything. */
export function where<T>(items: readonly T[], tests: ReadonlyArray<(item: T) => boolean>): T[] {
  return items.filter(item => tests.every(test => test(item)))
}

/** Case-insensitive "does any of this mention that". */
export function mentions(search: string | undefined, ...fields: Array<string | null | undefined>): boolean {
  if (!search) return true
  const wanted = search.trim().toLowerCase()
  return !wanted || fields.some(field => (field ?? "").toLowerCase().includes(wanted))
}
