import { useCallback, useEffect, useRef, useState } from "react"
import { ChevronUpIcon, DownloadIcon, FilePlusIcon, FolderIcon, FolderPlusIcon, RefreshCwIcon, SaveIcon, TrashIcon, UploadIcon } from "lucide-react"
import { guestFilesApi, joinPath, type GuestEntry } from "@/api/guest-files-api"
import { fileImportApi } from "@/api/file-import-api"
import { fileExportApi } from "@/api/file-export-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

// Code and text editor for files inside the selected environment. Reads and
// writes go through the environment's own shell, never through the PC.
export function GuestFiles({ environmentId, active }: { environmentId: string; active: boolean }) {
  const { state } = usePlatform()
  // `directory` is the folder whose files are listed and acted on; `draft` is what is typed in
  // the folder box, which only becomes the folder once it has been opened.
  const [directory, setDirectory] = useState(".")
  const [draft, setDraft] = useState(".")
  const [entries, setEntries] = useState<GuestEntry[]>([])
  const [openFile, setOpenFile] = useState("")
  const [contents, setContents] = useState("")
  const [saved, setSaved] = useState("")
  const [status, setStatus] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const [showSource, setShowSource] = useState(false)
  const [sourceId, setSourceId] = useState("")
  const [sourceDirectory, setSourceDirectory] = useState(".")
  const [sourceEntries, setSourceEntries] = useState<GuestEntry[]>([])
  const [sourcePath, setSourcePath] = useState("")
  const lock = useRef(false)
  const perform = useCallback(async (action: () => Promise<void>) => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError("")
    try { await action() } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) } finally { lock.current = false; setBusy(false) }
  }, [])
  const browse = useCallback((path: string) => perform(async () => {
    const listing = await guestFilesApi.list(environmentId, path)
    setDirectory(listing.path); setDraft(listing.path); setEntries(listing.entries)
  }), [environmentId, perform])
  useEffect(() => { if (active && !entries.length && !error) void browse(directory) }, [active]) // eslint-disable-line react-hooks/exhaustive-deps

  const open = (name: string) => void perform(async () => {
    const path = joinPath(directory, name)
    const text = await guestFilesApi.read(environmentId, path)
    setOpenFile(path); setContents(text); setSaved(text); setStatus("")
  })
  const create = (folder: boolean) => void perform(async () => {
    const name = window.prompt(folder ? "New folder name" : "New file name")?.trim()
    if (!name) return
    if (name.includes("/")) throw new Error("Enter a name, not a path.")
    await guestFilesApi.create(environmentId, joinPath(directory, name), folder)
    const listing = await guestFilesApi.list(environmentId, directory)
    setEntries(listing.entries); setStatus(`Created ${name}.`)
  })
  const remove = (entry: GuestEntry) => void perform(async () => {
    await guestFilesApi.remove(environmentId, joinPath(directory, entry.name), entry.directory)
    const listing = await guestFilesApi.list(environmentId, directory)
    setEntries(listing.entries)
    if (openFile === joinPath(directory, entry.name)) { setOpenFile(""); setContents(""); setSaved("") }
    setStatus(`Deleted ${entry.name}.`)
  })
  const save = () => void perform(async () => {
    // The text as it was read goes along, so a file changed by an agent, a terminal or another
    // window since then is not overwritten unseen.
    await guestFilesApi.write(environmentId, openFile, contents, saved)
    setSaved(contents); setStatus(`Saved ${openFile}.`)
  })
  const copyToPc = (entry: GuestEntry) => void perform(async () => {
    const destination = await fileExportApi.chooseDestination()
    if (!destination) return
    const result = await fileExportApi.copy(environmentId, joinPath(directory, entry.name), destination)
    setStatus(`Copied ${entry.name} to ${result.file ?? result.folder ?? destination}.`)
  })
  const importFromPc = (directoryPicker: boolean) => void perform(async () => {
    const { open } = await import("@tauri-apps/plugin-dialog")
    const selected = await open({ directory: directoryPicker, multiple: !directoryPicker, title: directoryPicker ? "Choose a folder to import" : "Choose files to import" })
    const paths = typeof selected === "string" ? [selected] : Array.isArray(selected) ? selected : []
    if (!paths.length) return
    const result = await fileImportApi.copy(environmentId, paths, () => undefined)
    setStatus(`Imported ${result.files} files. Open ${result.destination} in this environment.`)
    const listing = await guestFilesApi.list(environmentId, directory)
    setDirectory(listing.path); setDraft(listing.path); setEntries(listing.entries)
  })
  const browseSource = (id: string, path: string) => void perform(async () => {
    const listing = await guestFilesApi.list(id, path)
    setSourceDirectory(listing.path); setSourceEntries(listing.entries); setSourcePath("")
  })
  const importFromEnvironment = () => void perform(async () => {
    const result = await fileExportApi.between(sourceId, environmentId, sourcePath.trim())
    setStatus(`Copied ${result.files} files from ${result.sourceEnvironment}. Open ${result.destination} in this environment.`)
    setShowSource(false)
    const listing = await guestFilesApi.list(environmentId, directory)
    setDirectory(listing.path); setDraft(listing.path); setEntries(listing.entries)
  })
  const sources = state?.environments.filter(item => item.id !== environmentId && item.status === "running" && item.kind !== "fullVm" && item.kind !== "computerBranch") ?? []

  return <div data-guest-files className="flex h-full min-h-0 flex-col gap-2 p-2 text-sm">
    <div className="flex flex-wrap items-center gap-2">
      <Button size="xs" variant="ghost" aria-label="Parent folder" disabled={busy} onClick={() => void browse(joinPath(directory, ".."))}><ChevronUpIcon aria-hidden="true" /></Button>
      <Input aria-label="Folder path" className="h-7 min-w-0 flex-1" value={draft} disabled={busy} onChange={event => setDraft(event.target.value)} onKeyDown={event => { if (event.key === "Enter") void browse(draft) }} />
      <Button size="xs" variant="ghost" aria-label="Refresh files" disabled={busy} onClick={() => void browse(draft)}><RefreshCwIcon aria-hidden="true" /></Button>
      <Button size="xs" variant="outline" disabled={busy} onClick={() => importFromPc(false)}><UploadIcon aria-hidden="true" />Import files</Button>
      <Button size="xs" variant="outline" disabled={busy} onClick={() => importFromPc(true)}><UploadIcon aria-hidden="true" />Import folder</Button>
      <Button size="xs" variant="outline" disabled={busy || !sources.length} onClick={() => setShowSource(value => !value)}><UploadIcon aria-hidden="true" />Import from environment</Button>
      <Button size="xs" variant="outline" disabled={busy} onClick={() => create(false)}><FilePlusIcon aria-hidden="true" />New file</Button>
      <Button size="xs" variant="outline" disabled={busy} onClick={() => create(true)}><FolderPlusIcon aria-hidden="true" />New folder</Button>
    </div>
    {error ? <p role="alert" className="break-words text-xs text-destructive-foreground">{error}</p> : null}
    {status ? <p role="status" className="truncate text-xs text-muted-foreground">{status}</p> : null}
    {showSource ? <section aria-label="Import from another environment" className="space-y-2 rounded border bg-card p-2 text-xs">
      <div className="flex flex-wrap items-center gap-2"><label htmlFor="transfer-source">Source</label><select id="transfer-source" className="h-8 rounded border bg-background px-2" value={sourceId} disabled={busy} onChange={event => { const id = event.target.value; setSourceId(id); setSourceDirectory("."); setSourceEntries([]); setSourcePath(""); if (id) browseSource(id, ".") }}><option value="">Choose an environment</option>{sources.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}</select>{sourceId ? <Button size="xs" variant="ghost" disabled={busy} onClick={() => browseSource(sourceId, joinPath(sourceDirectory, ".."))}>Up</Button> : null}<span className="min-w-0 truncate font-mono text-muted-foreground">{sourceDirectory}</span></div>
      {sourceId ? <div className="grid max-h-24 grid-cols-2 gap-1 overflow-y-auto sm:grid-cols-3">{sourceEntries.map(entry => <div key={entry.name} className="flex min-w-0 items-center gap-1 rounded border p-1"><button type="button" className="min-w-0 flex-1 truncate text-left" title={entry.name} disabled={busy} onClick={() => entry.directory ? browseSource(sourceId, joinPath(sourceDirectory, entry.name)) : setSourcePath(joinPath(sourceDirectory, entry.name))}>{entry.directory ? <FolderIcon aria-hidden="true" className="mr-1 inline size-3" /> : null}{entry.name}</button><Button size="xs" variant="ghost" disabled={busy} onClick={() => setSourcePath(joinPath(sourceDirectory, entry.name))}>Select</Button></div>)}</div> : null}
      {sourceId ? <div className="flex flex-wrap items-center gap-2"><Button size="xs" variant="ghost" disabled={busy || !sourceDirectory.startsWith("/")} onClick={() => setSourcePath(sourceDirectory)}>Select this folder</Button><Input aria-label="Source file or folder path" className="h-8 min-w-44 flex-1" value={sourcePath} disabled={busy} onChange={event => setSourcePath(event.target.value)} placeholder="/home/user/project" /><Button size="xs" disabled={busy || !sourcePath.trim().startsWith("/")} onClick={importFromEnvironment}>Import selected</Button></div> : null}
    </section> : null}
    <div className="flex min-h-0 flex-1 gap-2">
      <ul aria-label="Environment files" className="w-56 shrink-0 overflow-auto rounded border p-1 text-xs">
        {entries.map(entry => <li key={entry.name} className="flex items-center gap-1">
          <button className="min-w-0 flex-1 truncate p-1 text-left" title={entry.name} disabled={busy} onClick={() => entry.directory ? void browse(joinPath(directory, entry.name)) : open(entry.name)}>
            {entry.directory ? <FolderIcon aria-hidden="true" className="mr-1 inline size-3" /> : null}{entry.name}
          </button>
          <Button size="icon-xs" variant="ghost" aria-label={`Delete ${entry.name}`} disabled={busy} onClick={() => remove(entry)}><TrashIcon aria-hidden="true" /></Button>
          <Button size="icon-xs" variant="ghost" aria-label={`Copy ${entry.name} to PC`} disabled={busy} onClick={() => copyToPc(entry)}><DownloadIcon aria-hidden="true" /></Button>
        </li>)}
        {!entries.length ? <li className="p-2 text-muted-foreground">This folder is empty.</li> : null}
      </ul>
      <div className="flex min-w-0 flex-1 flex-col gap-2">
        <div className="flex items-center gap-2 text-xs"><span className="min-w-0 flex-1 truncate" title={openFile}>{openFile || "Select a file to edit"}</span>
          <Button size="xs" disabled={busy || !openFile || contents === saved} onClick={save}><SaveIcon aria-hidden="true" />Save</Button></div>
        <textarea aria-label="File contents" spellCheck={false} className="min-h-0 flex-1 resize-none rounded border bg-background p-2 font-mono text-xs" value={contents} disabled={busy || !openFile} onChange={event => setContents(event.target.value)} />
      </div>
    </div>
  </div>
}
