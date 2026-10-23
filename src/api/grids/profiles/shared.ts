/** The parts every grid has in common: reading an invite, saying where a hub may be reached,
 *  and the one sentence each product shows when there is no desktop app to ask. */
import type { Reach } from "@/api/grids/types"

export type InviteKind = "models" | "workspaces" | "credentials" | "research"

const PREFIX: Record<InviteKind, string> = {
  models: "grid-invite:",
  workspaces: "desk-invite:",
  credentials: "access-invite:",
  research: "bounty-invite:",
}

export interface Invite { company: string; address: string; fingerprint: string }

/** `atob` gives one character per byte; an invite's JSON is UTF-8, so a company name with
 *  letters outside ASCII must be decoded as bytes, not read as Latin-1. */
export function decodeUtf8(bytes: string): string {
  return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(bytes, character => character.charCodeAt(0)))
}

/** The company an invite names, read on this computer so a mistyped code is caught before
 *  anybody tries to join. One function for all four; they differed only in the prefix. */
export function readInvite(kind: InviteKind, code: string): Invite | null {
  const compact = code.replace(/\s+/g, "")
  const prefix = PREFIX[kind]
  if (!compact.startsWith(prefix)) return null
  try {
    const body = compact.slice(prefix.length).replace(/-/g, "+").replace(/_/g, "/")
    const wire = JSON.parse(decodeUtf8(atob(body + "=".repeat((4 - body.length % 4) % 4)))) as { c?: unknown; a?: unknown; f?: unknown }
    return typeof wire.c === "string" && wire.c.trim() && typeof wire.a === "string" && typeof wire.f === "string"
      ? { company: wire.c, address: wire.a, fingerprint: wire.f.replace(/:/g, "").toUpperCase() }
      : null
  } catch {
    return null
  }
}

/** What the engine's `tunnel` argument wants: nothing for the company network, "quick" for a
 *  quick link, or the saved domain. */
export function tunnelOf(reach: Reach): string | null {
  if (reach === "quick") return "quick"
  return typeof reach === "object" ? reach.domain : null
}

/** One sentence per product, naming what the person was trying to do. One sentence for all
 *  four would tell them nothing, so each profile keeps its own. */
export const DESKTOP_ONLY = {
  models: "Open Yougori Desktop to host or join a Closed Neo Grid",
  workspaces: "Open Yougori Desktop to host or join a sandbox grid",
  credentials: "Open Yougori Desktop to host or sign in to an Access Grid",
  research: "Open Yougori Desktop to use Swarm Mining",
  closed: "Open Yougori Desktop to host a private bounty",
} as const

/** What a change reports; a page reads the status again afterwards. */
export interface Done { message?: string; warning?: string | null }
