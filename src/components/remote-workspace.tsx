import { RemoteWorkspaceToolbar } from "@/components/remote-workspace-toolbar"
import { terminalInstallers, type TerminalInstallerId } from "@/lib/terminal-installers"
import { RemoteDisplay } from "@/components/remote-display"
import { useCallback, useEffect, useRef, useState } from "react"
import { DownloadIcon, FolderIcon, RefreshCwIcon, UploadIcon, XIcon } from "lucide-react"
import { remoteAccessApi, type RemoteCapabilities, type RemoteFile } from "@/api/remote-access-api"
import { usePlatform } from "@/context/platform-context"
import type { Environment } from "@/types/platform"
import { GuestTerminal } from "@/components/guest-terminal"
import { GuestLogs } from "@/components/guest-logs"
import { SharingPanel } from "@/components/sharing-panel"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export function RemoteWorkspace({ environment, initialAppSessionId, onClose }: { environment: Environment; initialAppSessionId?: string; onClose(): void }) {
  const { setEnvironmentStatus, environmentActions, refreshPlatform } = usePlatform()
  const [capabilities, setCapabilities] = useState<RemoteCapabilities | null>(null), [error, setError] = useState("")
  const [reconnecting, setReconnecting] = useState(false)
  const [connectionVersion, setConnectionVersion] = useState(0)
  const [view, setView] = useState(initialAppSessionId ? "app" : "files")
  const [installTabs, setInstallTabs] = useState<{ id: string; tool: TerminalInstallerId }[]>([])
  const activeInstaller = useRef<string | null>(null)
  const onTerminalReady = useCallback((id: string, _ready: boolean, ended?: boolean) => { if (ended && activeInstaller.current === id) activeInstaller.current = null }, [])
  const onConnected = () => { setCapabilities(null); setError(""); setInstallTabs([]); activeInstaller.current = null; setView("files"); setConnectionVersion(value => value + 1) }
  const reconnect = async () => {
    if (reconnecting) return
    setReconnecting(true); setError("")
    try { await remoteAccessApi.reconnect(environment.id); await refreshPlatform(); onConnected() }
    catch (e) { setError(String(e)) }
    finally { setReconnecting(false) }
  }
  const startInstall = (tool: TerminalInstallerId) => {
    if (!capabilities?.installers || !capabilities.internet || environment.status !== "running") return
    if (activeInstaller.current) { setView(activeInstaller.current); return }
    const id = `install-${crypto.randomUUID()}`; activeInstaller.current = id
    setInstallTabs(tabs => [...tabs, { id, tool }]); setView(id)
  }
  useEffect(() => { let alive = true; let timer: ReturnType<typeof setTimeout>; const poll = async () => {
    try { const result = await remoteAccessApi.inspect(environment.id); if (alive) { setCapabilities(result); setError("") } }
    catch (e) { if (alive) { setError(String(e)); setCapabilities(null); setInstallTabs([]); activeInstaller.current = null } }
    finally { if (alive) timer = setTimeout(() => void poll(), 5000) }
  }; void poll(); return () => { alive = false; clearTimeout(timer) } }, [environment.id, environment.runtime, connectionVersion])
  useEffect(() => { if (environment.status !== "running" || !capabilities?.installers) { setInstallTabs([]); activeInstaller.current = null } }, [environment.status, capabilities?.installers])
  const selected = view === "files" && !capabilities?.files ? (capabilities?.desktop ? "desktop" : capabilities?.commands ? "terminal" : "logs") : view
  return <section aria-label={`${environment.name} remote workspace`} className="flex h-full min-h-0 flex-col overflow-auto bg-background text-foreground">
    <header className="flex flex-wrap items-center gap-2 border-b p-3"><div className="min-w-0 flex-1"><h1 className="truncate text-sm font-medium">{environment.name}</h1><p className="text-xs text-muted-foreground">Remote · {environment.status} · {capabilities?.permission ?? "Connecting"}</p></div>
      {capabilities?.power ? <><Button size="xs" variant="outline" disabled={Boolean(environmentActions[environment.id])} onClick={() => void setEnvironmentStatus(environment.id, environment.status === "running" ? "stopped" : "running").catch(e => setError(String(e)))}>{environment.status === "running" ? "Stop" : "Start"}</Button><Button size="xs" variant="outline" disabled={Boolean(environmentActions[environment.id])} onClick={() => void (async () => { try { await setEnvironmentStatus(environment.id, "stopped"); await setEnvironmentStatus(environment.id, "running") } catch (e) { setError(String(e)) } })()}>Restart</Button></> : null}
      <Button size="xs" variant="outline" loading={reconnecting} disabled={reconnecting} onClick={() => void reconnect()}>Reconnect</Button><SharingPanel compact reconnectEnvironmentId={environment.id} onConnected={onConnected} /><Button aria-label="Close remote workspace" size="icon-xs" variant="ghost" onClick={onClose}><XIcon /></Button>
    </header>
    <div className="border-b px-3 py-1"><RemoteWorkspaceToolbar environment={environment} capabilities={capabilities} onInstall={startInstall} onView={setView} onClose={onClose} onError={setError} /></div>
    <div className="flex flex-wrap gap-1 border-b p-2" role="tablist" aria-label="Remote workspace views">{[["desktop", "Desktop", capabilities?.desktop], ["files", "Files", capabilities?.files], ["terminal", "Terminal", capabilities?.commands], ["logs", "Logs", !capabilities?.name]].filter(([, , enabled]) => enabled).map(([id, label]) => <Button key={String(id)} role="tab" aria-selected={selected === id} size="sm" variant={selected === id ? "secondary" : "ghost"} onClick={() => setView(String(id))}>{label}</Button>)}{initialAppSessionId && capabilities?.apps ? <Button role="tab" aria-selected={selected === "app"} size="sm" variant={selected === "app" ? "secondary" : "ghost"} onClick={() => setView("app")}>App</Button> : null}{installTabs.map(tab => <div className="flex items-center" key={tab.id}><Button role="tab" aria-selected={selected === tab.id} size="sm" variant={selected === tab.id ? "secondary" : "ghost"} onClick={() => setView(tab.id)}>Install {terminalInstallers.find(tool => tool.id === tab.tool)?.name}</Button><Button aria-label={`Close ${tab.tool} installer`} size="icon-xs" variant="ghost" onClick={() => { setInstallTabs(tabs => tabs.filter(item => item.id !== tab.id)); if (activeInstaller.current === tab.id) activeInstaller.current = null; if (view === tab.id) setView("terminal") }}><XIcon /></Button></div>)}</div>
    {error ? <p role="alert" className="m-3 rounded border p-3 text-sm">{error} If the link or credentials changed, use Connect to update them.</p> : null}
    {capabilities ? <div className={selected.startsWith("install-") ? "hidden" : "min-h-0 flex-1 p-3"}>{selected === "app" && capabilities.apps && initialAppSessionId ? <RemoteDisplay environmentId={environment.id} appSessionId={initialAppSessionId} /> : selected.startsWith("install-") ? null : selected === "desktop" && capabilities.desktop ? <RemoteDisplay environmentId={environment.id} /> : selected === "files" && capabilities.files ? <RemoteFiles environmentId={environment.id} writable={capabilities.permission !== "view"} /> : selected === "terminal" && capabilities.commands && environment.status === "running" ? <GuestTerminal environmentId={environment.id} sessionId={`remote-${environment.id}`} active /> : selected === "logs" && !capabilities.name ? <GuestLogs environmentId={environment.id} active /> : <p className="text-sm text-muted-foreground">{environment.status !== "running" ? "The target is stopped. Its owner or a recipient with lifecycle permission can start it." : "The owner has not granted this capability."}</p>}</div> : null}
    {capabilities?.installers && environment.status === "running" ? installTabs.map(tab => <div key={tab.id} className={selected === tab.id ? "min-h-0 flex-1 p-3" : "hidden"}><GuestTerminal environmentId={environment.id} sessionId={tab.id} installer={tab.tool} active={selected === tab.id} onReady={onTerminalReady} /></div>) : null}
  </section>
}

const pathIn = (folder: string, name: string) => [folder, name].filter(Boolean).join("/")
const encode = (bytes: Uint8Array) => btoa(Array.from(bytes, b => String.fromCharCode(b)).join(""))
const decode = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0))
export function RemoteFiles({ environmentId, writable }: { environmentId: string; writable: boolean }) {
  const [folder, setFolder] = useState(""), [entries, setEntries] = useState<RemoteFile[]>([]), [file, setFile] = useState("")
  const [text, setText] = useState(""), [original, setOriginal] = useState(""), [error, setError] = useState(""), [busy, setBusy] = useState(false), [progress, setProgress] = useState("")
  const [newName, setNewName] = useState("")
  const lock = useRef(false), mounted = useRef(true)
  useEffect(() => { mounted.current = true; return () => { mounted.current = false } }, [])
  const perform = useCallback(async (action: () => Promise<void>) => { if (lock.current) return; lock.current = true; setBusy(true); setError(""); try { await action() } catch (e) { if (mounted.current) setError(String(e)) } finally { lock.current = false; if (mounted.current) setBusy(false) } }, [])
  const list = useCallback(async (path: string) => { const value = await remoteAccessApi.files<{ entries: RemoteFile[] }>(environmentId, { operation: "list", path }); if (mounted.current) { setFolder(path); setEntries(value.entries.sort((a, b) => Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name))) } }, [environmentId])
  useEffect(() => { void perform(() => list("")) }, [perform, list])
  const read = async (path: string, size: number) => {
    if (size > 100 * 1024 * 1024) throw new Error("Desktop download is limited to 100 MB per file. Use the CLI file API for larger files.")
    const chunks: Uint8Array[] = []
    for (let offset = 0; offset < size; offset += 65536) {
      if (!mounted.current) throw new Error("Transfer cancelled")
      const result = await remoteAccessApi.files<{ data: string }>(environmentId, { operation: "read", path, offset, length: Math.min(65536, size - offset) })
      const chunk = decode(result.data); if (chunk.length !== Math.min(65536, size - offset)) throw new Error("File changed during transfer. Refresh and retry.")
      chunks.push(chunk); setProgress(`Downloading ${Math.min(offset + chunk.length, size).toLocaleString()} / ${size.toLocaleString()} bytes`)
    }
    const bytes = new Uint8Array(size); let offset = 0; for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.length } return bytes
  }
  const write = async (path: string, bytes: Uint8Array) => { for (let offset = 0; offset < bytes.length; offset += 65536) { if (!mounted.current) throw new Error("Transfer cancelled; uploaded chunks were kept")
    const chunk = bytes.subarray(offset, offset + 65536); await remoteAccessApi.files(environmentId, { operation: "write", path, offset, data: encode(chunk) }); setProgress(`Uploading ${Math.min(offset + chunk.length, bytes.length).toLocaleString()} / ${bytes.length.toLocaleString()} bytes`)
  } await remoteAccessApi.files(environmentId, { operation: "truncate", path, length: bytes.length }) }
  const upload = (files: FileList | null) => { if (!files) return; void perform(async () => { for (const file of Array.from(files)) {
    if (file.size > 100 * 1024 * 1024) throw new Error("Desktop upload is limited to 100 MB per file")
    const name = file.webkitRelativePath || file.name; const parts = name.split("/")
    for (let i = 1; i < parts.length; i++) { const path = pathIn(folder, parts.slice(0, i).join("/")); try { await remoteAccessApi.files(environmentId, { operation: "stat", path }) } catch { await remoteAccessApi.files(environmentId, { operation: "mkdir", path }) } }
    const path = pathIn(folder, name); await remoteAccessApi.files(environmentId, { operation: "create", path }); await write(path, new Uint8Array(await file.arrayBuffer()))
  } setProgress("Upload complete"); await list(folder) }) }
  return <section className="flex h-full min-h-96 flex-col gap-3" aria-label="Shared folder">
    <div className="flex flex-wrap items-center gap-2"><Button variant="outline" size="xs" disabled={busy || !folder} onClick={() => void perform(() => list(folder.split("/").slice(0, -1).join("/")))}>Up</Button><span className="flex-1 truncate font-mono text-xs">/{folder}</span><Button aria-label="Refresh files" size="icon-xs" variant="ghost" disabled={busy} onClick={() => void perform(() => list(folder))}><RefreshCwIcon /></Button>
      <Button size="xs" variant="outline" disabled={busy} onClick={() => void perform(async () => { const { open } = await import("@tauri-apps/plugin-dialog"); const destination = await open({ directory: true, multiple: false, title: "Save this shared folder in…" }); if (typeof destination !== "string") return; setProgress("Downloading this folder. You can leave the window open while it copies."); const result = await remoteAccessApi.download(environmentId, folder, destination); setProgress(`Downloaded ${result.entries} entries to ${result.folder}`) })}>Download folder</Button>
      {writable ? <><label className="cursor-pointer rounded border px-2 py-1 text-xs"><UploadIcon className="mr-1 inline size-3" />Upload files<input aria-label="Upload files" type="file" multiple className="sr-only" disabled={busy} onChange={e => { upload(e.target.files); e.target.value = "" }} /></label><label className="cursor-pointer rounded border px-2 py-1 text-xs">Upload folder<input aria-label="Upload folder" type="file" multiple {...{ webkitdirectory: "" }} className="sr-only" disabled={busy} onChange={e => { upload(e.target.files); e.target.value = "" }} /></label></> : <span className="text-xs text-muted-foreground">Read only</span>}
    </div>
    {writable ? <div className="flex gap-2"><Input className="max-w-64" aria-label="New file or folder name" placeholder="New file or folder name" value={newName} onChange={e => setNewName(e.target.value)} /><Button size="xs" disabled={busy || !newName || /[/\\]/.test(newName)} onClick={() => void perform(async () => { await remoteAccessApi.files(environmentId, { operation: "create", path: pathIn(folder, newName) }); setNewName(""); await list(folder) })}>New file</Button><Button size="xs" variant="outline" disabled={busy || !newName || /[/\\]/.test(newName)} onClick={() => void perform(async () => { await remoteAccessApi.files(environmentId, { operation: "mkdir", path: pathIn(folder, newName) }); setNewName(""); await list(folder) })}>New folder</Button></div> : null}
    {error ? <p role="alert" className="text-xs text-destructive-foreground">{error}</p> : null}{progress ? <p role="status" className="text-xs text-muted-foreground">{progress}</p> : null}
    <div className="grid min-h-0 flex-1 grid-cols-[minmax(160px,30%)_1fr] gap-3"><ul className="max-h-[60vh] overflow-auto rounded border p-1">{entries.map(entry => <li key={entry.name} className="flex items-center gap-1 text-xs"><button className="min-w-0 flex-1 truncate p-2 text-left hover:bg-muted" disabled={busy} onClick={() => void perform(async () => { const path = pathIn(folder, entry.name); if (entry.directory) return list(path); if (entry.size > 65536) throw new Error("Use Download for files larger than 64 KiB"); const bytes = await read(path, entry.size); if (bytes.includes(0)) throw new Error("Binary file; use Download"); const value = new TextDecoder("utf-8", { fatal: true }).decode(bytes); setFile(path); setText(value); setOriginal(value); setProgress("") })}>{entry.directory ? <FolderIcon className="mr-1 inline size-3" /> : null}{entry.name}</button>{!entry.directory ? <Button aria-label={`Download ${entry.name}`} size="icon-xs" variant="ghost" disabled={busy} onClick={() => void perform(async () => { const bytes = await read(pathIn(folder, entry.name), entry.size); const url = URL.createObjectURL(new Blob([bytes])); const anchor = document.createElement("a"); anchor.href = url; anchor.download = entry.name; anchor.click(); setTimeout(() => URL.revokeObjectURL(url), 1000); setProgress("Download complete") })}><DownloadIcon /></Button> : null}</li>)}</ul>
      <div className="flex min-w-0 flex-col gap-2"><div className="flex items-center gap-2"><span className="flex-1 truncate text-xs">{file || "Select a text file"}</span><Button size="xs" disabled={!writable || busy || !file || text === original} onClick={() => void perform(async () => { const bytes = new TextEncoder().encode(text); if (bytes.length > 65536) throw new Error("Text editing is limited to 64 KiB"); await remoteAccessApi.files(environmentId, { operation: "replace", path: file, expectedData: encode(new TextEncoder().encode(original)), data: encode(bytes) }); setOriginal(text); setProgress("Saved"); await list(folder) })}>Save</Button></div><textarea aria-label="Shared file contents" className="min-h-72 flex-1 resize-none rounded border bg-background p-3 font-mono text-xs" readOnly={!writable} disabled={!file || busy} value={text} onChange={e => setText(e.target.value)} /></div>
    </div>
  </section>
}
