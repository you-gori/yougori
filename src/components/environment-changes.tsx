import { useRef, useState } from "react"
import { FileDiffIcon, RefreshCwIcon } from "lucide-react"
import { changesApi, type ChangeReport, type FieldChange } from "@/api/projects-api"
import { Button } from "@/components/ui/button"
import { Dialog, DialogTrigger, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter } from "@/components/ui/dialog"

function Fields({ title, rows }: { title: string; rows?: FieldChange[] }) {
  if (!rows?.length) return null
  return <section className="space-y-2"><h3 className="text-sm font-semibold">{title}</h3><div className="divide-y rounded-lg border">{rows.map(row => <div className="grid gap-2 px-3 py-2 text-xs sm:grid-cols-3" key={row.name}><strong className="break-all">{row.name}</strong><span className="break-all text-muted-foreground">{typeof row.before === "string" ? row.before : JSON.stringify(row.before)}</span><span className="break-all">{typeof row.after === "string" ? row.after : JSON.stringify(row.after)}</span></div>)}</div></section>
}
export function EnvironmentChanges({ environmentId }: { environmentId: string }) {
  const [open, setOpen] = useState(false)
  const [report, setReport] = useState<ChangeReport | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [reset, setReset] = useState(false)
  const lock = useRef(false)
  const refresh = async (baseline = false, offset = 0) => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError("")
    try { setReport(await changesApi.inspect(environmentId, baseline, offset)); setReset(false) }
    catch (e) { setError(String(e)) }
    finally { lock.current = false; setBusy(false) }
  }
  const s = report?.summary
  return <Dialog open={open} onOpenChange={value => { setOpen(value); if (value) void refresh() }}>
    <DialogTrigger render={<Button variant="outline" size="sm" />}><FileDiffIcon aria-hidden="true" />Changes</DialogTrigger>
    <DialogPopup className="max-w-6xl">
      <DialogHeader><DialogTitle>Changes</DialogTitle><DialogDescription>{report?.baselineAt ? `Since ${new Date(report.baselineAt).toLocaleString()}` : "Files and configuration changed since your shared-folder baseline."}</DialogDescription></DialogHeader>
      <DialogPanel className="space-y-4">
        {s ? <div className="flex flex-wrap gap-x-5 gap-y-2 rounded-lg bg-muted/50 px-4 py-3 text-sm" aria-label="Change counts">{[[s.modified, "files modified"], [s.created, "files created"], [s.deleted, "files deleted"], [s.renamed, "files renamed"], [s.variables, "environment variables changed"], [s.packagesInstalled, "packages installed"]].map(([value, label]) => <span key={label}><strong className="tabular-nums">{value}</strong> {label}</span>)}</div> : null}
        {report?.baselineCreated ? <p className="text-sm">Baseline saved. Future changes will appear here.</p> : null}
        {report?.notice ? <p className="text-xs text-muted-foreground">{report.notice}</p> : null}
        {report?.warnings?.map(w => <p className="text-xs text-amber-700 dark:text-amber-300" key={w}>{w}</p>)}
        {report?.files?.length ? <div className="divide-y rounded-lg border">{report.files.map(file => <details key={`${file.folder}/${file.path}`}><summary className="flex cursor-pointer items-center justify-between gap-3 px-3 py-2 text-sm"><span className="min-w-0 break-all" title={file.folder}>{file.from ? `${file.from} → ` : ""}{file.path}</span><span className="shrink-0 text-xs capitalize text-muted-foreground">{file.kind}</span></summary><div className="border-t bg-muted/30 p-3"><p className="mb-2 break-all text-xs text-muted-foreground">{file.folder} · {file.beforeBytes ?? "—"} → {file.afterBytes ?? "—"} bytes</p><p className="mb-2 break-all font-mono text-[10px] text-muted-foreground">SHA-256: {file.beforeHash ?? "—"} → {file.afterHash ?? "—"}</p>{file.diff ? <pre className="max-h-80 overflow-auto whitespace-pre font-mono text-xs leading-5">{file.diff.split("\n").map((line, index) => <span className={`block ${line.startsWith("+") ? "text-green-700 dark:text-green-300" : line.startsWith("-") ? "text-red-700 dark:text-red-300" : "text-muted-foreground"}`} key={index}>{line || " "}</span>)}</pre> : <p className="text-xs text-muted-foreground">{file.kind === "renamed" ? "Contents unchanged." : "A text diff is unavailable for binary, large files, or this page's display limit."}</p>}</div></details>)}</div> : null}
        {report?.totalFiles ? <div className="flex items-center justify-between text-xs text-muted-foreground"><span>{(report.offset ?? 0) + 1}–{(report.offset ?? 0) + (report.files?.length ?? 0)} of {report.totalFiles} changed files</span><div className="flex gap-2"><Button size="sm" variant="outline" disabled={busy || !report.offset} onClick={() => void refresh(false, Math.max(0, (report.offset ?? 0) - 200))}>Previous</Button><Button size="sm" variant="outline" disabled={busy || report.nextOffset == null} onClick={() => void refresh(false, report.nextOffset ?? 0)}>Next</Button></div></div> : null}
        <Fields title="Environment variables · values hidden" rows={report?.variables} /><Fields title="Packages" rows={report?.packages} /><Fields title="Configuration" rows={report?.configuration} />
        {error ? <p role="alert" className="text-sm text-destructive-foreground">{error}</p> : null}
        {busy ? <p role="status" className="text-sm text-muted-foreground">Comparing shared folders…</p> : null}
        {reset ? <div className="flex flex-wrap items-center gap-3 rounded-lg border p-3 text-sm"><p className="flex-1">Use the current files as the new baseline? This clears the comparison without changing your files.</p><Button size="sm" variant="ghost" onClick={() => setReset(false)}>Cancel</Button><Button size="sm" disabled={busy} onClick={() => void refresh(true)}>Save new baseline</Button></div> : null}
      </DialogPanel>
      <DialogFooter><Button variant="ghost" onClick={() => setOpen(false)}>Close</Button>{report?.available ? <Button variant="outline" disabled={busy} onClick={() => setReset(true)}>New baseline</Button> : null}<Button disabled={busy} onClick={() => void refresh()}><RefreshCwIcon aria-hidden="true" />Refresh</Button></DialogFooter>
    </DialogPopup>
  </Dialog>
}
