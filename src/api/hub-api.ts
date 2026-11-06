import { run } from "@/api/platform-api"
import { registryApi } from "@/api/model-registry-api"

// The Hub on yougori.com (docs/hub.md). Reads go through the engine's website proxy, which also
// signs starring in with the account; running and publishing open a console with the CLI.
export type HubKind = "template" | "tool"
export interface HubCounts { clones: number; clonesWeek: number; stars: number; forks: number; versions: number }
/** The words a format 2 template is filed under. */
export type HubTag = "grids" | "models" | "tools" | "workspaces" | "credentials" | "research" | "website-api" | "data" | "automation"
/** What a template needs before it runs here. */
export interface HubRequires { yougori?: string; gpu?: string; platforms?: string[] }
export interface HubSummary {
  ref: string; publisher: string; name: string; kind: HubKind; title: string; summary: string; topics: string[]; license: string
  /** Uploaded by the Yougori owner account: the only uploads Yougori checks. */
  verified: boolean
  /** The publisher holds Hub collateral, so the item is Verified too, but Yougori has not checked
   *  its files. Older websites leave it out. */
  collateral?: boolean
  latestVersion: string | null; createdAt: number; updatedAt: number; counts: HubCounts
  forkedFrom: { ref: string; available: boolean } | null
  /** Format 2 items only, and every one optional: older items have none of these. */
  subtitle?: string | null; format?: number | null; tags?: HubTag[] | null; requires?: HubRequires | null
}
export interface HubFile { path: string; bytes: number; sha256: string; text: boolean }
export interface HubReview {
  environments?: { name: string; type?: string; image?: string; cpu?: number; memoryGb?: number; storageGb?: number; gpu?: boolean | string; internet?: boolean; ports?: number[]; tools?: string[]; pcAccess?: unknown[]; writablePcFolders?: boolean }[]
  totals?: { environments?: number; cpu?: number; memoryGb?: number; storageGb?: number; gpu?: string }
  public?: { environment: string; port: number; access: string }[]
  connections?: { from: string; to: string }[]
  tools?: { name: string; source: string; environment?: string; downloads?: string[]; commands?: string[] }[]
  inputs?: { id: string; question: string; type: string; secret?: boolean }[]
  steps?: string[]
  warnings?: string[]
  requires?: HubRequires
  /** Format 2 reviews keep every key above and add these. Aliases are search words, never shown. */
  format?: number
  resources?: { id: string; kind: string; dependsOn?: string[]; when?: unknown; summary?: string }[]
  capabilities?: { id: string; selection: "required" | "optional" | "default"; locked?: boolean }[]
  subtitle?: string
  aliases?: string[]
}
export interface HubVersion { version: string; createdAt: number; digest: string; verified: boolean; fileCount: number; bytes: number; clones: number; changelog: string | null }
export interface HubDetail extends HubSummary {
  state: "active" | "removed" | "deleted"
  removed: { reason: string; message: string; at: number } | null
  starred: boolean; mine: boolean
  versions: HubVersion[]
  version: {
    version: string; createdAt: number; digest: string; verified: boolean; fileCount: number; bytes: number
    readme: string | null; readmeTruncated?: boolean; changelog: string | null; files: HubFile[]
    review: HubReview; notices: string[]
  } | null
}
export interface HubList { items: HubSummary[]; total: number; page: number; pageSize: number }
export interface HubFileView { path: string; bytes: number; sha256: string; text: boolean; tooLarge?: boolean; content?: string }
export interface HubInstance {
  schema: 1; name: string; ref: string | null; source: "hub" | "local"; folder?: string | null; kind?: HubKind; title?: string
  version?: string; digest?: string; verified?: boolean; state: "creating" | "ready" | "incomplete" | "stopped"
  failed?: { part: string; message: string; next?: string } | null
  /** The command that continues or finishes the instance, written even while it is being created. */
  next?: string | null
  createdAt?: number; updatedAt?: number
  environments?: Record<string, string>; public?: Record<string, string>
  steps?: { title: string; detail?: string; command?: string }[]
  outputs?: { label: string; value: string }[]
}
export type HubConsoleAction = "run" | "addTool" | "publishTemplate" | "publishTool" | "status" | "continue" | "update" | "remove"
/** What saving a template the builder made wrote. A README somebody already edited is kept. */
export interface SavedTemplate { folder: string; name: string; written: string[]; keptReadme: boolean }
/** A run refreshes its instance's `updatedAt` about every 30 seconds; a record still "creating"
 *  after this long belongs to a run that stopped (its window was closed). */
export const HUB_STALE_SECONDS = 120
export const instanceState = (instance: Pick<HubInstance, "state" | "updatedAt">, now = Date.now() / 1000): HubInstance["state"] =>
  instance.state === "creating" && instance.updatedAt != null && now - instance.updatedAt > HUB_STALE_SECONDS ? "incomplete" : instance.state
export type HubSort = "popular" | "trending" | "stars" | "new" | "updated"

/** The template formats this app sets up itself, through the engine: review, apply and progress
 *  here, with no console window. Every other format still opens a console with the CLI. */
export const NATIVE_RUN_FORMATS: ReadonlySet<number> = new Set([1, 2])

/** Whether a template version is set up here or through the CLI. The version's own review says
 *  which format it is; the item's format is used when the review does not.
 *
 *  The engine plans format 1 templates, but can't yet hand this app their questions, so a format
 *  1 template that asks anything (or whose summary is missing) keeps the console, where the CLI
 *  asks them. One with nothing to ask runs here. */
export function runsNatively(item: Pick<HubSummary, "kind" | "format">, review?: Pick<HubReview, "format" | "inputs" | "environments"> | null, formats: ReadonlySet<number> = NATIVE_RUN_FORMATS) {
  if (item.kind !== "template") return false
  const format = typeof review?.format === "number" ? review.format : typeof item.format === "number" ? item.format : 1
  if (!formats.has(format)) return false
  if (format !== 1) return true
  const asks = Array.isArray(review?.inputs) ? review!.inputs.length : 0
  return Boolean(review && Array.isArray(review.environments) && review.environments.length) && asks === 0
}

/** What a publisher holds to be Verified; matches COLLATERAL_MICROS in the website's server/hub/collateral.mjs. */
export const HUB_COLLATERAL = "$100"
/** Shown on everything Yougori did not upload, collateral or not. */
export const HUB_WARNING = (kind: HubKind, collateral = false) => `Not checked by Yougori. Community ${kind === "tool" ? "tools" : "templates"} can contain harmful code, including viruses. Read the files first and run only what you trust.${collateral ? ` Its publisher holds ${HUB_COLLATERAL} collateral, which they lose if Yougori removes their work for harmful code.` : ""}`
/** Verified: uploaded by the Yougori owner account, or by a publisher who holds collateral. */
export const isVerified = (item: Pick<HubSummary, "verified" | "collateral">) => item.verified || Boolean(item.collateral)
export const hubCommand = (item: Pick<HubSummary, "publisher" | "name" | "kind">, version?: string | null) =>
  `${item.kind === "tool" ? "yougori tool add" : "yougori run"} hub/${item.publisher}/${item.name}${version ? `@${version}` : ""}`

/** The engine refuses percent-encoded addresses, so search text keeps to plain words: letters,
 *  digits, dots and dashes, joined with `+` (a space to the website). */
export function searchWords(value: string) {
  return value.toLowerCase().replace(/[^a-z0-9 _.-]+/g, " ").replace(/\.{2,}/g, ".").trim().split(/\s+/).filter(Boolean).slice(0, 6).join("+").slice(0, 120)
}
/** File paths that can travel through the proxy unchanged; others open on yougori.com. */
export const plainFilePath = (path: string) => /^[A-Za-z0-9._/-]+$/.test(path) && !path.includes("..") && !path.includes("//")
const SLUG = /^[a-z0-9][a-z0-9_-]{0,63}$/
const item = (publisher: string, name: string) => {
  if (!SLUG.test(publisher) || !SLUG.test(name)) throw new Error("This is not a Hub address")
  return `/hub/items/${publisher}/${name}`
}
const unavailable = () => { throw new Error("Open Yougori Desktop to use the Hub") }

export const hubApi = {
  list(query: { q?: string; sort?: HubSort; kind?: HubKind | ""; verified?: boolean; page?: number }) {
    const parts: string[] = []
    const words = query.q ? searchWords(query.q) : ""
    if (words) parts.push(`q=${words}`)
    if (query.sort && query.sort !== "popular") parts.push(`sort=${query.sort}`)
    if (query.kind) parts.push(`kind=${query.kind}`)
    if (query.verified) parts.push("verified=1")
    if (query.page && query.page > 1) parts.push(`page=${Math.floor(query.page)}`)
    return registryApi.request<HubList>(`/hub/items${parts.length ? `?${parts.join("&")}` : ""}`)
  },
  async detail(publisher: string, name: string, version?: string | null) {
    if (version && !/^[0-9][0-9A-Za-z.-]{0,63}$/.test(version)) throw new Error("This is not a version of this item")
    return (await registryApi.request<{ item: HubDetail }>(`${item(publisher, name)}${version ? `?version=${version}` : ""}`)).item
  },
  file(publisher: string, name: string, version: string, path: string) {
    if (!plainFilePath(path)) return Promise.reject(new Error("Open this file on yougori.com to read it."))
    return registryApi.request<HubFileView>(`${item(publisher, name)}/files?version=${version}&path=${path}`)
  },
  star: (publisher: string, name: string, starred: boolean) => registryApi.request<{ starred: boolean; stars: number }>(`${item(publisher, name)}/star`, { starred }),
  async instances() { return (await run<{ instances: HubInstance[] }>("hub_instances", {}, () => ({ instances: [] }))).instances },
  async builtins() { return (await run<{ templates: { id: string; title: string; folder: string }[] }>("hub_builtin_templates", {}, () => ({ templates: [] }))).templates },
  openConsole: (action: HubConsoleAction, target: string) => run<{ opened: boolean; command: string }>("open_hub_console", { request: { action, target } }, unavailable),
  /** Writes a template the builder made into a folder: empty, or holding this same template. */
  saveTemplateDraft: (request: { folder: string; template: string; project?: string | null; summary?: string | null; files?: Record<string, string> }) =>
    run<SavedTemplate>("hub_save_template_draft", { request: { folder: request.folder, template: request.template, ...(request.project ? { project: request.project } : {}), ...(request.summary ? { summary: request.summary } : {}), ...(request.files && Object.keys(request.files).length ? { files: request.files } : {}) } }, unavailable),
  async folder(title: string) {
    const { open } = await import("@tauri-apps/plugin-dialog")
    const path = await open({ directory: true, multiple: false, title })
    return typeof path === "string" ? path : null
  },
  pageUrl: (item: Pick<HubSummary, "publisher" | "name">) => `https://yougori.com/hub/${item.publisher}/${item.name}`,
}
