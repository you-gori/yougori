import { useEffect, useState } from "react"
import { ArrowLeftIcon, ExternalLinkIcon, StarIcon, TriangleAlertIcon } from "lucide-react"
import {
  HUB_COLLATERAL, HUB_WARNING, hubApi, hubCommand, instanceState, isVerified, plainFilePath, runsNatively,
  type HubConsoleAction, type HubDetail, type HubFileView, type HubInstance, type HubKind, type HubList, type HubReview, type HubSort, type HubSummary,
} from "@/api/hub-api"
import { workspaceApi } from "@/api/workspace-api"
import { HubReadme } from "@/components/hub-readme"
import { PageHeader, PillButton } from "@/components/prompx"
import { Button } from "@/components/ui/button"
import { toastManager } from "@/components/ui/toast"
import { SetupBuilderScope } from "@/components/setups/setup-builder-provider"
import { useSetupBuilder } from "@/components/setups/builder-context"
import { TemplateCodeGuide } from "@/components/setups/template-code-guide"
import { CATALOGUE, GROUP_NAME, GROUPS } from "@/api/setups/catalogue"
import type { CapabilityGroup } from "@/api/setups/types"
import "@/components/hub-page.css"
import "@/components/setups/setups.css"

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)
const count = (value: number, one: string, many = `${one}s`) => `${value.toLocaleString("en-US")} ${value === 1 ? one : many}`
const day = (seconds: number) => new Date(seconds * 1000).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" })
const SORTS: [HubSort, string][] = [["popular", "Most cloned"], ["trending", "Trending this week"], ["stars", "Most stars"], ["new", "Newest"], ["updated", "Recently updated"]]
type View = "explore" | "computer" | "publish"
type Opened = { publisher: string; name: string }

function size(bytes: number) {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(bytes < 10 * 1024 ? 1 : 0)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function copy(text: string) {
  void navigator.clipboard?.writeText(text).then(() => toastManager.add({ title: "Copied", description: text, type: "success" }))
    .catch(() => toastManager.add({ title: "Could not copy", description: "Select the text and copy it instead.", type: "error" }))
}

/** Hands the action to the CLI in a console window, where the person reviews and confirms. */
async function openConsole(action: HubConsoleAction, target: string, title: string) {
  try {
    const result = await hubApi.openConsole(action, target)
    toastManager.add({ title, description: `A console window opened with: ${result.command}. Review what it does there before you confirm.`, type: "success" })
    return true
  } catch (reason) {
    toastManager.add({ title: "The console did not open", description: message(reason), type: "error" })
    return false
  }
}

async function publishFolder(kind: HubKind) {
  const folder = await hubApi.folder(kind === "tool" ? "Choose the tool's folder" : "Choose the template's folder").catch(() => null)
  if (folder) await openConsole(kind === "tool" ? "publishTool" : "publishTemplate", folder, kind === "tool" ? "Publishing the tool" : "Publishing the template")
}

/** The Verified badge: uploaded by Yougori, or by a publisher who holds collateral. */
function Verified({ collateral = false, large = false }: { collateral?: boolean; large?: boolean }) {
  return <span className={large ? "hub-verified hub-verified-large" : "hub-verified"} title={collateral ? `The publisher holds ${HUB_COLLATERAL} collateral, lost if they publish harmful code` : "Uploaded by Yougori"}>
    <svg viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1.2 9.8 2.5l2.2-.1.7 2.1 1.8 1.3-.7 2.1.7 2.1-1.8 1.3-.7 2.1-2.2-.1L8 14.8l-1.8-1.3-2.2.1-.7-2.1-1.8-1.3.7-2.1-.7-2.1 1.8-1.3.7-2.1 2.2.1Z" /><path d="m5.4 8.1 1.8 1.8 3.5-3.6" fill="none" /></svg>
    Verified
  </span>
}

// A format 2 item's subtitle, tags and requirements. Older items have none of them, and a part
// that is not the expected type is left out rather than trusted.
type HubExtras = Pick<HubSummary, "subtitle" | "tags" | "requires">

const TAG_NAME: Record<string, string> = {
  grids: "Grids", models: "Models", tools: "Tools", workspaces: "Workspaces", credentials: "Credentials",
  research: "Research", "website-api": "Website & API", data: "Data", automation: "Automation",
}
const tagsOf = (item: HubExtras): string[] => (Array.isArray(item.tags) ? item.tags as unknown[] : []).filter((tag): tag is string => typeof tag === "string" && tag in TAG_NAME)
const subtitleOf = (item: HubExtras) => typeof item.subtitle === "string" ? item.subtitle.trim() : ""

const SYSTEM: Record<string, string> = { windows: "Windows", win: "Windows", linux: "Linux", macos: "macOS", mac: "macOS", darwin: "macOS", osx: "macOS" }
const ARCH: Record<string, string> = { x86_64: "x86-64", amd64: "x86-64", x64: "x86-64", aarch64: "Arm", arm64: "Arm" }
const GPU: Record<string, string> = { nvidia: "an NVIDIA GPU", cuda: "an NVIDIA GPU", amd: "an AMD GPU", rocm: "an AMD GPU", apple: "an Apple GPU", metal: "an Apple GPU", intel: "an Intel GPU" }

/** A platform id such as `linux-x86_64` as people say it: "Linux (x86-64)". Unknown ids are left
 *  out rather than shown raw. */
function platformName(id: string) {
  const [system, ...rest] = id.toLowerCase().split(/[-_/ ](?=[a-z])/)
  const name = SYSTEM[system ?? ""]
  if (!name) return ""
  const arch = rest.length ? ARCH[rest.join("_")] ?? ARCH[rest.join("")] : ""
  return arch ? `${name} (${arch})` : name
}

/** What a template needs before it can run here, from the item and its review, in words. */
function requirementsOf(...sources: unknown[]) {
  const said: string[] = []
  for (const source of sources) {
    if (!source || typeof source !== "object" || Array.isArray(source)) continue
    const requires = source as Record<string, unknown>
    const yougori = typeof requires.yougori === "string" ? requires.yougori.trim().replace(/^[>=^~\s]+/, "") : ""
    if (/^[0-9][0-9A-Za-z.+-]{0,40}$/.test(yougori)) said.push(`Yougori ${yougori} or newer`)
    const platforms = (Array.isArray(requires.platforms) ? requires.platforms : []).filter((one): one is string => typeof one === "string").map(platformName).filter(Boolean)
    const unique = platforms.filter((one, index) => platforms.indexOf(one) === index)
    if (unique.length) said.push(`runs on ${unique.join(", ")}`)
    const gpu = typeof requires.gpu === "string" ? requires.gpu.trim().toLowerCase() : ""
    if (gpu === "optional" || gpu === "preferred") said.push("a GPU if you have one")
    else if (gpu === "any" || gpu === "required" || gpu === "yes" || gpu === "true") said.push("a GPU")
    else if (GPU[gpu]) said.push(GPU[gpu]!)
  }
  return said.filter((line, index) => said.indexOf(line) === index)
}

function Row({ item, onOpen }: { item: HubSummary; onOpen(item: Opened): void }) {
  const tags = tagsOf(item)
  const subtitle = subtitleOf(item)
  // The platforms it runs on and the minimum Yougori version, in plain words, from the item's own
  // metadata. Older items without `requires` show nothing here rather than a guess.
  const needs = requirementsOf(item.requires)
  return <button type="button" className="hub-row" onClick={() => onOpen(item)}>
    <span className="hub-row-head">
      <span className="hub-row-title">{item.title}</span>
      {isVerified(item) ? <Verified collateral={!item.verified} /> : null}
      <span className="hub-tag">{item.kind === "tool" ? "Tool" : "Template"}</span>
      {tags.map(tag => <span key={tag} className="hub-tag hub-tag-quiet">{TAG_NAME[tag]}</span>)}
    </span>
    {subtitle ? <span className="hub-row-subtitle">{subtitle}</span> : null}
    <span className="hub-row-ref">{item.ref}</span>
    <span className="hub-row-summary">{item.summary}</span>
    {needs.length ? <span className="hub-row-requires">Needs {needs.join(" · ")}</span> : null}
    <span className="hub-row-meta">
      <span>{count(item.counts.clones, "clone")}</span><span>{count(item.counts.stars, "star")}</span><span>{count(item.counts.forks, "fork")}</span>
      <span>{item.license}</span><span>Updated {day(item.updatedAt)}</span>
    </span>
  </button>
}

function Explore({ onOpen }: { onOpen(item: Opened): void }) {
  const [query, setQuery] = useState("")
  const [sort, setSort] = useState<HubSort>("popular")
  const [kind, setKind] = useState<HubKind | "">("")
  const [verified, setVerified] = useState(false)
  const [page, setPage] = useState(1)
  const [result, setResult] = useState<HubList | null>(null)
  const [error, setError] = useState("")
  useEffect(() => {
    let live = true
    const timer = setTimeout(() => {
      hubApi.list({ q: query, sort, kind, verified, page })
        .then(value => { if (live) { setResult(value); setError("") } })
        .catch(reason => { if (live) setError(message(reason)) })
    }, query ? 250 : 0)
    return () => { live = false; clearTimeout(timer) }
  }, [query, sort, kind, verified, page])
  const pages = result ? Math.max(1, Math.ceil(result.total / result.pageSize)) : 1
  return <div className="grid-board">
    <div className="hub-toolbar">
      <input className="hub-search" type="search" aria-label="Search the Hub" placeholder="Search templates, tools and publishers" value={query} onChange={event => { setQuery(event.target.value); setPage(1) }} />
      <span className="grid-seg" role="group" aria-label="Kind">
        {([["", "All"], ["template", "Templates"], ["tool", "Tools"]] as [HubKind | "", string][]).map(([value, label]) =>
          <button key={value} type="button" aria-pressed={kind === value} onClick={() => { setKind(value); setPage(1) }}>{label}</button>)}
      </span>
      <label className="hub-check"><input type="checkbox" checked={verified} onChange={event => { setVerified(event.target.checked); setPage(1) }} />Verified only</label>
      <label className="hub-sort">Sort<select value={sort} onChange={event => { setSort(event.target.value as HubSort); setPage(1) }}>{SORTS.map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label>
    </div>
    <p className="hub-note">Yougori checks only its own uploads. <strong>Verified</strong> means uploaded by Yougori, or by a publisher who holds {HUB_COLLATERAL} collateral and loses it if they publish harmful code.</p>
    {error ? <p role="alert" className="grid-error">{error}</p> : null}
    {result ? <>
      <p role="status" className="hub-count">{count(result.total, "result")}</p>
      {result.items.length ? <div className="hub-list">{result.items.map(item => <Row key={item.ref} item={item} onOpen={onOpen} />)}</div> : <div className="grid-empty">
        <p className="grid-empty-title">{query || kind || verified ? "Nothing matches yet" : "The Hub is empty"}</p>
        <p className="grid-empty-hint">{query || kind || verified ? "Try other words, or clear the filters." : "Build an application in your VMs, then use Create template to share it."}</p>
      </div>}
      {pages > 1 ? <nav className="hub-pages" aria-label="Pages">
        <Button size="xs" variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button>
        <span>{page} / {pages}</span>
        <Button size="xs" variant="outline" disabled={page >= pages} onClick={() => setPage(page + 1)}>Next</Button>
      </nav> : null}
    </> : error ? null : <p role="status" className="hub-count">Loading the Hub…</p>}
  </div>
}

// The review comes from the publisher's CLI. The website checks its shape, and this page still shows
// only values of the type each place expects, so nothing in it can break the page.
type Entry = Record<string, unknown>
const isEntry = (value: unknown): value is Entry => value !== null && typeof value === "object" && !Array.isArray(value)
const entries = (value: unknown): Entry[] => (Array.isArray(value) ? value.filter(isEntry) : [])
const texts = (value: unknown): string[] => (Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string") : [])
const textOf = (value: unknown): string => (typeof value === "string" ? value : typeof value === "number" && Number.isFinite(value) ? String(value) : "")
const amount = (value: unknown, unit = "") => textOf(value) ? `${textOf(value)}${unit}` : "—"
const access = (value: unknown) => value === "quick" ? "a quick public link" : value === "domain" ? "your own domain" : value === "none" ? "not public" : "you choose when it runs"
/** The review formats this app reads in full. */
const KNOWN_FORMATS = new Set([1, 2])
const SELECTION: Record<string, string> = { required: "Required", optional: "Optional", default: "On by default" }
const NAME_OF = new Map(CATALOGUE.map(capability => [capability.id, capability]))
/** A condition in words where it is simple, otherwise its own short text. */
function conditionText(value: unknown) {
  if (typeof value === "string") return value
  try { const text = JSON.stringify(value); return text.length > 120 ? `${text.slice(0, 117)}…` : text } catch { return "a condition" }
}

/** A format 2 review's capabilities, in the builder's six groups, and its resources. */
function ReviewGraph({ review }: { review: Entry }) {
  const capabilities = entries(review.capabilities).filter(entry => textOf(entry.id))
  const resources = entries(review.resources).filter(entry => textOf(entry.id))
  if (!capabilities.length && !resources.length) return null
  const grouped = new Map<CapabilityGroup | "", Entry[]>()
  for (const capability of capabilities) {
    const group = NAME_OF.get(textOf(capability.id))?.group ?? ""
    grouped.set(group, [...(grouped.get(group) ?? []), capability])
  }
  const order: (CapabilityGroup | "")[] = [...GROUPS.map(group => group.id), ""]
  return <>
    {capabilities.length ? <>
      <h3>What it can do</h3>
      {order.filter(group => grouped.has(group)).map(group => <div key={group || "other"} className="hub-capability-group">
        <h4>{group ? GROUP_NAME[group] : "Not known to this version of Yougori"}</h4>
        <ul>{grouped.get(group)!.map((capability, index) => {
          const id = textOf(capability.id)
          const selection = SELECTION[textOf(capability.selection)] ?? "Included"
          return <li key={index}>
            <strong>{NAME_OF.get(id)?.name ?? id}</strong> · {selection}{capability.locked === true ? " · settings fixed by the author" : ""}
          </li>
        })}</ul>
      </div>)}
    </> : null}
    {resources.length ? <>
      <h3>Parts it sets up</h3>
      <table className="hub-table">
        <thead><tr><th scope="col">Part</th><th scope="col">Kind</th><th scope="col">Needs</th><th scope="col">When</th><th scope="col">What it is</th></tr></thead>
        <tbody>{resources.map((resource, index) => <tr key={index}>
          <th scope="row"><code>{textOf(resource.id)}</code></th>
          <td>{textOf(resource.kind).replace(/_/g, " ") || "—"}</td>
          <td>{texts(resource.dependsOn).join(", ") || "—"}</td>
          <td>{resource.when === undefined || resource.when === null ? "Always" : <code>{conditionText(resource.when)}</code>}</td>
          <td>{textOf(resource.summary) || "—"}</td>
        </tr>)}</tbody>
      </table>
    </> : null}
  </>
}

function Review({ review: given, notices }: { review: HubReview; notices: string[] }) {
  const review: Entry = isEntry(given) ? given as Entry : {}
  const environments = entries(review.environments), publicEntries = entries(review.public), tools = entries(review.tools), inputs = entries(review.inputs)
  const totals = isEntry(review.totals) ? review.totals : null, warnings = texts(review.warnings), steps = texts(review.steps)
  // No format means format 1; anything that isn't a format this app reads, a number or not, is
  // newer than it understands.
  const format: unknown = review.format === undefined || review.format === null ? 1 : review.format
  const graph = entries(review.capabilities).length + entries(review.resources).length
  return <div className="hub-review">
    <p className="hub-note">Sent by the publisher's Yougori CLI when this version was published. When you run it, Yougori checks the files again on this computer and shows you what it will create before anything happens.</p>
    {typeof format !== "number" || !KNOWN_FORMATS.has(format) ? <p className="hub-callout">This review format is newer than this app understands. Everything it can read is listed below; update Yougori to see the rest before you run it.</p> : null}
    {texts(notices).map((text, index) => <p key={index} className="hub-callout">{text}</p>)}
    {warnings.length ? <ul className="hub-callout">{warnings.map((text, index) => <li key={index}>{text}</li>)}</ul> : null}
    {totals ? <dl className="hub-counters">
      <div><dt>Sandboxes</dt><dd>{textOf(totals.environments) || environments.length}</dd></div>
      <div><dt>CPU</dt><dd>{amount(totals.cpu)}</dd></div>
      <div><dt>Memory</dt><dd>{amount(totals.memoryGb, " GB")}</dd></div>
      <div><dt>Disk</dt><dd>{amount(totals.storageGb, " GB")}</dd></div>
      <div><dt>GPU</dt><dd>{textOf(totals.gpu) && totals.gpu !== "none" ? textOf(totals.gpu) : "No"}</dd></div>
    </dl> : null}
    {environments.length ? <table className="hub-table">
      <thead><tr><th scope="col">Sandbox</th><th scope="col">Type</th><th scope="col">Image</th><th scope="col">CPU</th><th scope="col">Memory</th><th scope="col">Internet</th><th scope="col">Ports</th><th scope="col">Tools</th><th scope="col">PC folders</th></tr></thead>
      <tbody>{environments.map((environment, index) => {
        const folders = Array.isArray(environment.pcAccess) ? environment.pcAccess.length : 0
        const ports = Array.isArray(environment.ports) ? environment.ports.filter(port => typeof port === "number" || typeof port === "string").join(", ") : ""
        return <tr key={index}>
          <th scope="row">{textOf(environment.name)}</th><td>{textOf(environment.type) || "container"}</td><td><code>{textOf(environment.image) || "—"}</code></td><td>{amount(environment.cpu)}</td>
          <td>{amount(environment.memoryGb, " GB")}</td><td>{environment.internet === false ? "Off" : "On"}</td>
          <td>{ports || "—"}</td><td>{texts(environment.tools).join(", ") || "—"}</td>
          <td>{folders ? <strong className="hub-flag">{folders}{environment.writablePcFolders === true ? ", writable" : ""}</strong> : "None"}</td>
        </tr>
      })}</tbody>
    </table> : null}
    {publicEntries.length ? <><h3>Internet access</h3><ul>{publicEntries.map((entry, index) => <li key={index}>{textOf(entry.environment)}, port {textOf(entry.port)}: {access(entry.access)}</li>)}</ul></> : null}
    {tools.length ? <><h3>Tools</h3><ul>{tools.map((tool, index) => {
      const source = textOf(tool.source), downloads = texts(tool.downloads)
      return <li key={index}>
        <strong>{textOf(tool.name)}</strong> · {source === "built-in" ? "built into Yougori" : source === "bundled" ? "included in this template" : source === "hub" ? "a Hub tool" : source}{textOf(tool.environment) ? ` · in ${textOf(tool.environment)}` : ""}
        {downloads.length ? <> · downloads from {downloads.map((address, at) => <code key={at}>{address} </code>)}</> : null}
      </li>
    })}</ul></> : null}
    {inputs.length ? <><h3>Questions it asks</h3><ul>{inputs.map((input, index) => <li key={index}>{textOf(input.question) || textOf(input.id)}{input.secret === true || input.type === "secret" ? " · kept secret, never uploaded" : ""}</li>)}</ul></> : null}
    <ReviewGraph review={review} />
    {steps.length ? <><h3>Steps for you afterwards</h3><ol>{steps.map((step, index) => <li key={index}>{step}</li>)}</ol></> : null}
    {!environments.length && !tools.length && !inputs.length && !graph ? <p className="hub-note">This version did not include a summary. Read its files to see what it does.</p> : null}
  </div>
}

const LINES_SHOWN = 5000

/** A text file with line numbers; very long files show their beginning. */
function CodeLines({ path, content }: { path: string; content: string }) {
  const lines = content.replace(/\n$/, "").split("\n")
  return <>
    <ol className="hub-code" aria-label={`Contents of ${path}`}>{lines.slice(0, LINES_SHOWN).map((line, index) => <li key={index}><code>{line || " "}</code></li>)}</ol>
    {lines.length > LINES_SHOWN ? <p className="hub-note">Showing the first {LINES_SHOWN.toLocaleString("en-US")} of {lines.length.toLocaleString("en-US")} lines. Open it on yougori.com to download the whole file.</p> : null}
  </>
}

function Files({ item }: { item: HubDetail }) {
  const version = item.version!
  const [path, setPath] = useState<string | null>(null)
  const [file, setFile] = useState<HubFileView | null>(null)
  const [error, setError] = useState("")
  useEffect(() => {
    if (!path) return
    let live = true
    setFile(null); setError("")
    hubApi.file(item.publisher, item.name, version.version, path).then(value => { if (live) setFile(value) }).catch(reason => { if (live) setError(message(reason)) })
    return () => { live = false }
  }, [path, item.publisher, item.name, version.version])
  if (path) return <div className="hub-file">
    <div className="hub-file-head">
      <Button size="xs" variant="ghost" onClick={() => setPath(null)}>All files</Button>
      <code>{path}</code>
    </div>
    {error ? <p role="alert" className="grid-error">{error}</p> : !file ? <p role="status" className="hub-note">Loading…</p>
      : file.text && file.content != null ? <CodeLines path={path} content={file.content} />
      : <p className="hub-note">{file.tooLarge ? `This file is ${size(file.bytes)}, too large to show here.` : `Binary file, ${size(file.bytes)}.`} <Button size="xs" variant="link" onClick={() => { void workspaceApi.openUrl(hubApi.pageUrl(item)).catch(() => undefined) }}>Open on yougori.com</Button></p>}
  </div>
  return <ul className="hub-files" aria-label="Files">
    {version.files.map(entry => <li key={entry.path}>
      {plainFilePath(entry.path)
        ? <button type="button" onClick={() => setPath(entry.path)}>{entry.path}</button>
        : <span title="Open this file on yougori.com">{entry.path}</span>}
      <span>{entry.text ? "" : "binary · "}{size(entry.bytes)}</span>
    </li>)}
  </ul>
}

function Detail({ opened, onBack }: { opened: Opened; onBack(): void }) {
  const builder = useSetupBuilder()
  const [item, setItem] = useState<HubDetail | null>(null)
  const [version, setVersion] = useState<string | null>(null)
  const [tab, setTab] = useState<"readme" | "files" | "creates" | "versions">("readme")
  const [error, setError] = useState("")
  const [starring, setStarring] = useState(false)
  useEffect(() => {
    let live = true
    setError("")
    hubApi.detail(opened.publisher, opened.name, version).then(value => { if (live) setItem(value) }).catch(reason => { if (live) setError(message(reason)) })
    return () => { live = false }
  }, [opened.publisher, opened.name, version])
  async function star() {
    if (!item || starring) return
    setStarring(true)
    try {
      const result = await hubApi.star(item.publisher, item.name, !item.starred)
      setItem({ ...item, starred: result.starred, counts: { ...item.counts, stars: result.stars } })
    } catch (reason) {
      const text = message(reason)
      toastManager.add({ title: "Could not star", description: /sign in/i.test(text) ? "Sign in to the Yougori Network first: run yougori login, then try again." : text, type: "error" })
    } finally { setStarring(false) }
  }
  const back = <Button size="xs" variant="ghost" className="hub-back" onClick={onBack}><ArrowLeftIcon aria-hidden="true" />Back</Button>
  if (error) return <div className="hub-item">{back}<p role="alert" className="grid-error">{error}</p></div>
  if (!item) return <div className="hub-item">{back}<p role="status" className="hub-note">Loading…</p></div>
  const current = item.version
  const command = current ? hubCommand(item, version) : ""
  const extras: HubExtras = item
  const tags = tagsOf(extras)
  const needs = requirementsOf(extras.requires, isEntry(current?.review) ? current?.review.requires : null)
  // A format 2 template is set up here, with its review and progress; older ones in a console.
  const native = current ? runsNatively(item, isEntry(current.review) ? current.review : null) : false
  const pinned = current ? `hub/${item.publisher}/${item.name}@${current.version}` : ""
  // One page: the heading, the warning, then what it is on the left and how to run it on the right.
  return <article className="hub-item" aria-label={item.title}>
    {back}
    <header className="hub-item-head">
      <div className="hub-item-heading">
        <div className="hub-detail-title">
          <h2>{item.title}</h2>
          {isVerified(item) ? <Verified collateral={!item.verified} large /> : null}
        </div>
        {subtitleOf(extras) ? <p className="hub-detail-subtitle">{subtitleOf(extras)}</p> : null}
        <p className="hub-item-meta">
          <span>{item.kind === "tool" ? "Tool" : "Template"} by <strong>{item.publisher}</strong></span>
          {current ? <span>Version {current.version}</span> : null}
          <span>{item.license}</span>
          <span>Updated {day(item.updatedAt)}</span>
          {item.forkedFrom ? <span>Forked from {item.forkedFrom.ref}{item.forkedFrom.available ? "" : " (no longer on the Hub)"}</span> : null}
        </p>
        {isVerified(item) ? <p className="hub-verified-line">{item.verified ? "Verified: uploaded by Yougori." : `Verified: ${item.publisher} holds ${HUB_COLLATERAL} collateral.`}</p> : null}
        {tags.length ? <p className="hub-item-tags">{tags.map(tag => <span key={tag} className="hub-tag hub-tag-quiet">{TAG_NAME[tag]}</span>)}</p> : null}
      </div>
      {current ? <div className="hub-item-actions">
        <Button size="sm" variant="outline" aria-pressed={item.starred} disabled={starring} onClick={() => void star()}><StarIcon aria-hidden="true" />{item.starred ? "Starred" : "Star"} · {item.counts.stars.toLocaleString("en-US")}</Button>
        <Button size="sm" variant="outline" onClick={() => { void workspaceApi.openUrl(hubApi.pageUrl(item)).catch(() => undefined) }}><ExternalLinkIcon aria-hidden="true" />Open on yougori.com</Button>
      </div> : null}
    </header>
    {item.removed ? <p role="alert" className="grid-error hub-removed">{item.removed.message} It can no longer be downloaded or run.</p> : null}
    {current && !item.verified ? <p className="hub-warning" role="note"><TriangleAlertIcon aria-hidden="true" /><span>{HUB_WARNING(item.kind, item.collateral)}</span></p> : null}
    <div className="hub-item-layout">
      {current ? <aside className="hub-item-aside" aria-label="Run it">
        <section className="hub-run-card">
          <h3>{item.kind === "tool" ? "Add it" : "Run it"}</h3>
          {needs.length ? <p className="hub-requires"><strong>Needs</strong> {needs.join(" · ")}</p> : null}
          <PillButton tone="dark" onClick={() => native
            ? builder.open({ mode: "run", hubRef: pinned })
            : void openConsole(item.kind === "tool" ? "addTool" : "run", pinned, item.kind === "tool" ? `Adding ${item.title}` : `Running ${item.title}`)}>{item.kind === "tool" ? "Add this tool" : "Run on this computer"}</PillButton>
          <div className="hub-command-row">
            <code className="hub-command">{command}</code>
            <Button size="xs" variant="ghost" onClick={() => copy(command)}>Copy</Button>
          </div>
          {native ? <>
            <p className="hub-note">Run opens the builder here: you choose what it includes and read a review before anything is set up, then follow its progress. No console window.</p>
          </> : item.kind === "template" ? <p className="hub-note">This template is in an older format, so Run opens a console window where the CLI reviews it with you.</p> : null}
        </section>
        <dl className="hub-facts">
          <div><dt>Clones</dt><dd>{item.counts.clones.toLocaleString("en-US")}</dd></div>
          <div><dt>Stars</dt><dd>{item.counts.stars.toLocaleString("en-US")}</dd></div>
          <div><dt>Forks</dt><dd>{item.counts.forks.toLocaleString("en-US")}</dd></div>
          <div><dt>Versions</dt><dd>{item.counts.versions.toLocaleString("en-US")}</dd></div>
          <div><dt>Size</dt><dd>{count(current.fileCount, "file")} · {size(current.bytes)}</dd></div>
          <div><dt>Address</dt><dd><code>{item.ref}</code></dd></div>
        </dl>
      </aside> : null}
      <div className="hub-item-main">
        <p className="hub-summary">{item.summary}</p>
        {current ? <>
          <div className="hub-tabs" role="group" aria-label="Item information">
            {([["readme", "README"], ["files", `Files ${current.fileCount}`], ["creates", item.kind === "tool" ? "What it installs" : "What it creates"], ["versions", `Versions ${item.versions.length}`]] as const).map(([value, label]) =>
              <button key={value} type="button" aria-pressed={tab === value} onClick={() => setTab(value)}>{label}</button>)}
          </div>
          {tab === "readme" ? current.readme ? <HubReadme text={current.readme} /> : <p className="hub-note">No README yet.</p> : null}
          {tab === "files" ? <Files key={current.version} item={item} /> : null}
          {tab === "creates" ? <Review review={current.review ?? {}} notices={current.notices ?? []} /> : null}
          {tab === "versions" ? <ol className="hub-versions">{item.versions.map(entry => <li key={entry.version}>
            <span className="hub-version-head">
              <Button size="xs" variant={entry.version === current.version ? "outline" : "ghost"} onClick={() => setVersion(entry.version === item.versions[0]?.version ? null : entry.version)}>{entry.version}</Button>
              {entry.verified ? <Verified /> : null}
              <span className="hub-note">{day(entry.createdAt)} · {count(entry.fileCount, "file")} · {size(entry.bytes)} · {count(entry.clones, "clone")}</span>
            </span>
            {entry.changelog ? <p>{entry.changelog}</p> : null}
          </li>)}</ol> : null}
        </> : null}
      </div>
    </div>
  </article>
}

const STATE: Record<HubInstance["state"], string> = { creating: "Being created", ready: "Ready", incomplete: "Not finished", stopped: "Stopped" }

function Instance({ instance, onOpenItem, onChanged }: { instance: HubInstance; onOpenItem(item: Opened): void; onChanged(): void }) {
  const [removing, setRemoving] = useState(false)
  const [publisher, name] = instance.ref?.split("/") ?? []
  const state = instanceState(instance)
  const next = instance.failed?.next ?? instance.next ?? null
  const nextLine = next ? <> Next: <code>{next}</code></> : null
  return <div className="grid-sheet hub-instance">
    <div className="hub-instance-head">
      <strong>{instance.name}</strong>
      <span className="hub-tag" data-state={state}>{STATE[state] ?? state}</span>
      {instance.verified ? <Verified /> : null}
      <span className="hub-note">
        {instance.ref && publisher && name ? <button type="button" className="hub-link" onClick={() => onOpenItem({ publisher, name })}>{instance.ref}</button> : instance.folder ? `From ${instance.folder}` : "From a folder"}
        {instance.version ? ` · ${instance.version}` : ""}{instance.updatedAt ? ` · updated ${day(instance.updatedAt)}` : ""}
      </span>
    </div>
    {instance.failed ? <p role="alert" className="grid-error">{instance.failed.message}{nextLine}</p>
      : state !== instance.state ? <p role="alert" className="grid-error">This run stopped before it finished, for example because its window was closed. Continue it to finish the remaining parts.{nextLine}</p> : null}
    {Object.keys(instance.public ?? {}).length ? <ul className="hub-links">{Object.entries(instance.public ?? {}).map(([environment, url]) =>
      <li key={environment}><span>{environment}</span>{/^https?:\/\//.test(url) ? <button type="button" className="hub-link" onClick={() => { void workspaceApi.openUrl(url).catch(() => undefined) }}>{url}</button> : <code>{url}</code>}</li>)}</ul> : null}
    {instance.outputs?.length ? <dl className="hub-outputs">{instance.outputs.map(output => <div key={output.label}><dt>{output.label}</dt><dd>{output.value}</dd></div>)}</dl> : null}
    {instance.steps?.length ? <ol className="hub-steps">{instance.steps.map((step, index) => <li key={index}><strong>{step.title}</strong>{step.detail ? ` ${step.detail}` : ""}{step.command ? <> <code>{step.command}</code> <Button size="xs" variant="ghost" onClick={() => copy(step.command!)}>Copy</Button></> : null}</li>)}</ol> : null}
    <div className="hub-instance-actions">
      {state === "incomplete" ? <Button size="xs" variant="outline" onClick={() => void openConsole("continue", instance.name, `Continuing ${instance.name}`)}>Continue</Button> : null}
      <Button size="xs" variant="outline" onClick={() => void openConsole("status", instance.name, `Status of ${instance.name}`)}>Status</Button>
      {instance.source === "hub" ? <Button size="xs" variant="outline" onClick={() => void openConsole("update", instance.name, `Updating ${instance.name}`)}>Update</Button> : null}
      {removing ? <span className="hub-confirm" role="group" aria-label={`Remove ${instance.name}`}>
        <span className="hub-note">Removes its sandboxes and links; named volumes keep their data.</span>
        <Button size="xs" variant="destructive" onClick={() => { setRemoving(false); void openConsole("remove", instance.name, `Removing ${instance.name}`).then(opened => { if (opened) setTimeout(onChanged, 4000) }) }}>Remove</Button>
        <Button size="xs" variant="ghost" onClick={() => setRemoving(false)}>Cancel</Button>
      </span> : <Button size="xs" variant="ghost" onClick={() => setRemoving(true)}>Remove…</Button>}
    </div>
  </div>
}

function Computer({ onOpenItem }: { onOpenItem(item: Opened): void }) {
  const [instances, setInstances] = useState<HubInstance[] | null>(null)
  const [error, setError] = useState("")
  const load = () => hubApi.instances().then(value => { setInstances(value); setError("") }).catch(reason => setError(message(reason)))
  useEffect(() => { void load(); const timer = setInterval(() => void load(), 10_000); return () => clearInterval(timer) }, [])
  return <div className="grid-board">
    {error ? <p role="alert" className="grid-error">{error}</p> : null}
    {!instances ? <p role="status" className="hub-note">Loading…</p> : instances.length ? instances.map(instance => <Instance key={instance.name} instance={instance} onOpenItem={onOpenItem} onChanged={() => void load()} />) : <div className="grid-empty">
      <p className="grid-empty-title">No templates on this computer yet</p>
      <p className="grid-empty-hint">Run one from Explore, or from a terminal with yougori run hub/PUBLISHER/NAME. Its sandboxes also appear under My computer.</p>
    </div>}
  </div>
}

function Publish() {
  return <div className="grid-board hub-publish">
    <div className="grid-sheet hub-publish-sheet">
      <h2>Share a template or a tool</h2>
      <p>Choose its folder. A console window opens with yougori template publish (or yougori tool publish): it checks the folder, shows what will be uploaded, and asks before anything is published. Sign in first with yougori login.</p>
      <div className="hub-run">
        <PillButton tone="dark" onClick={() => void publishFolder("template")}>Publish a template folder</PillButton>
        <PillButton tone="light" onClick={() => void publishFolder("tool")}>Publish a tool folder</PillButton>
      </div>
      <p className="hub-note">Build inside Sandbox VMs using the included Yougori setup package and skill, then select those VMs in Create template.</p>
    </div>
    <ul className="grid-sheet hub-rules">
      <li><strong>Open source and free.</strong> Every upload needs an open-source licence such as MIT or Apache-2.0. Nothing on the Hub can be sold.</li>
      <li><strong>No secrets.</strong> Keys and passwords become questions asked when someone runs it. Uploads with keys, tokens or .env values are refused.</li>
      <li><strong>Versions never change.</strong> To fix something, publish a higher version.</li>
      <li><strong>Verified</strong> means uploaded by Yougori, or by a publisher who holds {HUB_COLLATERAL} collateral from their balance on yougori.com/account. It can be released 30 days after their last upload and is lost if Yougori removes their work for harmful code. Everything not uploaded by Yougori still shows: "{HUB_WARNING("template")}"</li>
    </ul>
  </div>
}

function HubBody() {
  const builder = useSetupBuilder()
  const [builtins, setBuiltins] = useState<{ id: string; title: string; folder: string }[]>([])
  useEffect(() => { let live = true; void hubApi.builtins().then(items => { if (live) setBuiltins(items) }).catch(() => undefined); return () => { live = false } }, [])
  const [view, setView] = useState<View>("explore")
  const [opened, setOpened] = useState<Opened | null>(null)
  const go = (next: View) => { setOpened(null); setView(next) }
  return <section className="app-page" aria-label="Hub">
    <PageHeader
      title="Hub."
      lead="Templates and tools shared by the community. Read every file, then run a whole setup with one command, or make your own."
      actions={<>
        {builtins.find(item => item.id === "inference-solver") ? <PillButton tone="dark" onClick={() => builder.open({ mode: "run", folder: builtins.find(item => item.id === "inference-solver")!.folder })}>Create my inference</PillButton> : null}
        <PillButton tone="dark" onClick={() => builder.open({ mode: "create" })}>Create template</PillButton>
        <PillButton tone="light" onClick={() => { void workspaceApi.openUrl("https://yougori.com/hub").catch(() => undefined) }}>Open yougori.com/hub</PillButton>
      </>}
    />
    <div className="app-page-body">
      <TemplateCodeGuide />
      <span className="grid-seg hub-views" role="group" aria-label="Hub sections">
        {([["explore", "Explore"], ["computer", "On this computer"], ["publish", "Publish"]] as [View, string][]).map(([value, label]) =>
          <button key={value} type="button" aria-pressed={!opened && view === value} onClick={() => go(value)}>{label}</button>)}
      </span>
      {opened ? <Detail key={`${opened.publisher}/${opened.name}`} opened={opened} onBack={() => setOpened(null)} />
        : view === "explore" ? <Explore onOpen={setOpened} />
        : view === "computer" ? <Computer onOpenItem={setOpened} />
        : <Publish />}
    </div>
  </section>
}

export function HubPage() {
  return <SetupBuilderScope><HubBody /></SetupBuilderScope>
}
