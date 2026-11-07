import { useEffect, useMemo, useState } from "react"
import { sandboxVmApi, visibleText, type CombineDecisions, type CombineOperation, type CombinePreview } from "@/api/sandbox-vm-api"
import { Button } from "@/components/ui/button"
import { Dialog, DialogDescription, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"

const gib = (bytes: number) => `${(bytes / 2 ** 30).toFixed(2)} GiB`

/** One real VM holding both selected sandboxes (CLI: `yougori sandbox combine A --with B`).
 * Nothing changes until the owner presses Combine on the exact preview shown; every conflict
 * needs a choice, lasting file permissions carry over only when ticked, and the originals'
 * workspaces are removed only on an explicit choice afterwards. */
export function CombineSandboxesDialog({ first, second, open, onOpenChange }: {
  first: string; second: string; open: boolean; onOpenChange(open: boolean): void
}) {
  const [layout, setLayout] = useState<"separate" | "merged">("separate")
  const [keep, setKeep] = useState<Record<string, "first" | "second">>({})
  const [files, setFiles] = useState<Record<string, "first" | "second">>({})
  const [adopt, setAdopt] = useState<string[]>([])
  const [preview, setPreview] = useState<CombinePreview | null>(null)
  const [result, setResult] = useState<CombineOperation | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  // Whether an image conflict is decided comes from the sources, as a boolean: the preview object
  // itself must not be a dependency, or every answer would change the decisions and ask again.
  const imageProcess = Boolean(preview?.sources.some(source => source.image))
  const decisions = useMemo<CombineDecisions>(() => ({
    layout, keep, files, adopt, ...(imageProcess ? { imageProcess: "once" as const } : {}),
  }), [layout, keep, files, adopt, imageProcess])

  useEffect(() => {
    if (!open || result) return
    let active = true
    setError("")
    sandboxVmApi.combinePreview(first, second, decisions)
      .then(value => { if (active) setPreview(value) })
      .catch(reason => { if (active) setError(reason instanceof Error ? reason.message : String(reason)) })
    return () => { active = false }
  }, [open, first, second, decisions, result])

  async function start() {
    if (!preview) return
    setBusy(true)
    setError("")
    try {
      setResult(await sandboxVmApi.combineStart(first, second, preview.digest, decisions))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally { setBusy(false) }
  }

  async function finish(originals: "keep" | "remove") {
    if (!result) return
    setBusy(true)
    try {
      setResult(await sandboxVmApi.combineFinish(result.operation, originals))
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally { setBusy(false) }
  }

  const chosen = (conflict: CombinePreview["conflicts"][number]) => conflict.kind === "file" ? files[conflict.key.slice(5)] : keep[conflict.key]
  const choose = (conflict: CombinePreview["conflicts"][number], side: "first" | "second") => conflict.kind === "file"
    ? setFiles(current => ({ ...current, [conflict.key.slice(5)]: side }))
    : setKeep(current => ({ ...current, [conflict.key]: side }))
  const blocked = !preview || !preview.compatible || preview.undecidedConflicts > 0 || preview.capacity.fits === false
  return <Dialog open={open} onOpenChange={onOpenChange}>
    <DialogPopup>
      <DialogHeader>
        <DialogTitle>Combine sandboxes</DialogTitle>
        <DialogDescription>{visibleText(first)} and {visibleText(second)} become one virtual machine with both workspaces and their combined CPU and memory.</DialogDescription>
      </DialogHeader>
      <DialogPanel>
        {error ? <p role="alert" className="text-sm text-destructive">{error}</p> : null}
        {result ? <div className="space-y-2 text-sm">
          <p>{result.state === "healthy" ? `Combined into ${visibleText(result.combined ?? "")}; its files were checked inside it.` : `This combine is ${result.state}.`}</p>
          {result.state === "healthy" ? <div className="flex gap-2">
            <Button size="sm" variant="outline" disabled={busy} onClick={() => void finish("keep")}>Keep the originals' workspaces</Button>
            <Button size="sm" variant="destructive-outline" disabled={busy} onClick={() => void finish("remove")}>Remove the originals' workspaces</Button>
          </div> : null}
        </div> : preview ? <div className="space-y-3 text-sm">
          {!preview.compatible ? <p role="alert">These cannot be combined: {preview.reasons.join("; ")}</p> : null}
          <table className="w-full text-left">
            <thead><tr><th>Sandbox</th><th>OS</th><th>CPU</th><th>Memory</th><th>Workspace files</th></tr></thead>
            <tbody>{preview.sources.map(source => <tr key={source.sandbox}>
              <td>{visibleText(source.sandbox)}</td><td>{visibleText(source.os.PRETTY_NAME ?? source.os.ID ?? "")} {source.os.machine}</td>
              <td>{source.cpu}</td><td>{gib(source.memoryBytes)}</td><td>{source.workspace?.files ?? 0}</td>
            </tr>)}</tbody>
          </table>
          <p>Combined VM: {preview.combined.params.cpu} vCPU, {gib(preview.combined.params.memoryGb * 2 ** 30)}; {preview.capacity.fits === false ? "the host cannot admit it" : "both originals release theirs first, so nothing is reserved twice"}.</p>
          <fieldset className="space-y-1">
            <legend>Workspaces</legend>
            <label className="mr-3"><input type="radio" name="layout" checked={layout === "separate"} onChange={() => setLayout("separate")} /> Each in its own folder</label>
            <label><input type="radio" name="layout" checked={layout === "merged"} onChange={() => setLayout("merged")} /> Merged in one folder</label>
          </fieldset>
          {preview.conflicts.length ? <fieldset className="space-y-1">
            <legend>Conflicts to decide</legend>
            {preview.conflicts.map(conflict => <div key={conflict.key}>
              <span>{visibleText(conflict.key)}: </span>
              {conflict.kind === "image-process" ? <span>runs once in the combined VM</span> : (["first", "second"] as const).map(side =>
                <label key={side} className="mr-2"><input type="radio" name={conflict.key} checked={chosen(conflict) === side}
                  onChange={() => choose(conflict, side)} /> Keep {side === "first" ? visibleText(first) : visibleText(second)}'s</label>)}
            </div>)}
          </fieldset> : null}
          {preview.permissions.lastingGrants.length ? <fieldset className="space-y-1">
            <legend>Lasting file permissions (carried only when ticked)</legend>
            {preview.permissions.lastingGrants.map(grant => <label key={grant.grant} className="block">
              <input type="checkbox" checked={adopt.includes(grant.grant)} onChange={event => setAdopt(current => event.target.checked ? [...current, grant.grant] : current.filter(id => id !== grant.grant))} /> {visibleText(grant.path)} ({grant.mode === "read" ? "read" : "read & write"})
            </label>)}
          </fieldset> : null}
          <p>Not carried: {preview.notCarried.join("; ")}.</p>
          <p>{preview.trust}</p>
          <p className="text-muted-foreground">{preview.transition}</p>
          <Button disabled={busy || blocked} onClick={() => void start()}>{busy ? "Combining…" : "Combine"}</Button>
        </div> : <p className="text-sm">Reading both sandboxes…</p>}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
