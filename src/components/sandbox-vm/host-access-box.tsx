import { useEffect, useId, useRef, useState } from "react"
import { sandboxVmApi, visibleText, type HostAccessMode, type HostAccessView } from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"

export function HostAccessBox({ sandbox }: { sandbox: string }) {
  const [view, setView] = useState<HostAccessView | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [modes, setModes] = useState<Record<string, HostAccessMode>>({})
  const sequence = useRef(0)
  const id = useId()
  useEffect(() => {
    if (busy) return
    let active = true
    async function refresh() {
      const ticket = ++sequence.current
      try {
        const value = await sandboxVmApi.hostAccess(sandbox)
        if (active && ticket === sequence.current) { setView(value); setError("") }
      } catch (reason) {
        if (active && ticket === sequence.current) setError(String(reason))
      }
    }
    void refresh()
    const timer = setInterval(() => void refresh(), 3000)
    return () => { active = false; clearInterval(timer) }
  }, [sandbox, busy])
  async function act(operation: string, fields: Record<string, unknown>) {
    sequence.current++
    setBusy(true); setError("")
    try { setView(await sandboxVmApi.hostAccess(sandbox, operation, fields)) }
    catch (reason) { setError(String(reason)) }
    finally { setBusy(false) }
  }
  const pending = view?.requests.filter(request => request.state === "pending") ?? []
  return <fieldset className="space-y-2 rounded border p-2" disabled={busy} aria-label="Computer file access">
    <legend className="px-1 font-medium">Computer file access</legend>
    {error ? <p role="alert" className="text-destructive">{visibleText(error)}</p> : null}
    {view ? <>
      <label htmlFor={`${id}-tree`} className="flex items-center gap-2">
        <input id={`${id}-tree`} type="checkbox" role="switch" checked={view.policy.treeVisible}
          onChange={event => void act("policy", { policy: { ...view.policy, treeVisible: event.target.checked } })} />
        See computer file tree
      </label>
      <p className="text-muted-foreground">Shows local drive, folder and file names only. File contents remain private until you grant access.</p>
      <label htmlFor={`${id}-ask`} className="flex items-center gap-2">
        <input id={`${id}-ask`} type="checkbox" role="switch" checked={view.policy.askForAccess}
          onChange={event => void act("policy", { policy: { ...view.policy, askForAccess: event.target.checked } })} />
        Ask for file access
      </label>
      <p className="text-muted-foreground">The AI can ask about a path you give it without seeing your whole tree. Turning off requests cancels pending requests; existing grants can be revoked below.</p>
      {pending.map(request => <div key={request.id} className="space-y-2 rounded border p-2">
        <p>Access requested by this VM:</p>
        <pre className="whitespace-pre-wrap break-all">{visibleText(request.path)}</pre>
        <label className="flex items-center gap-2">Permission
          <select aria-label={`Permission for ${request.path}`} value={modes[request.id] ?? request.mode}
            onChange={event => setModes(previous => ({ ...previous, [request.id]: event.target.value as HostAccessMode }))}>
            <option value="read">Read</option>
            {request.mode === "read_write" ? <option value="read_write">Read &amp; write</option> : null}
          </select>
        </label>
        <p className="text-muted-foreground">A folder grant includes its descendants. Read &amp; write can change your actual host files. Once covers one file operation; Always lasts until revoked for this VM.</p>
        <div className="flex flex-wrap gap-2">
          <Button size="xs" onClick={() => void act("approve", { request: request.id, mode: modes[request.id] ?? request.mode, duration: "once" })}>Allow once</Button>
          <Button size="xs" variant="outline" onClick={() => void act("approve", { request: request.id, mode: modes[request.id] ?? request.mode, duration: "always" })}>Always allow</Button>
          <Button size="xs" variant="ghost" onClick={() => void act("deny", { request: request.id })}>Deny</Button>
        </div>
      </div>)}
      {view.grants.length ? <ul aria-label="Active host-file permissions" className="space-y-1">
        {view.grants.map(grant => <li key={grant.id} className="flex flex-wrap items-center justify-between gap-2">
          <span className="break-all">{visibleText(grant.path)} · {grant.mode === "read" ? "Read" : "Read & write"} · {grant.duration === "once" ? "Once" : "Until revoked"}{grant.folder ? " · Including descendants" : ""}</span>
          <Button size="xs" variant="outline" onClick={() => void act("revoke", { grant: grant.id })}>Revoke</Button>
        </li>)}
      </ul> : <p className="text-muted-foreground">No host-file access granted.</p>}
      {view.requests.some(request => request.state !== "pending") ? <Button size="xs" variant="ghost" onClick={() => void act("dismiss", {})}>Dismiss completed requests</Button> : null}
    </> : <p>Reading file-access settings…</p>}
  </fieldset>
}
