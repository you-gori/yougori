import { useCallback, useEffect, useState } from "react"
import { FolderOpenIcon, ImportIcon } from "lucide-react"
import { projectsApi, type ProjectPreview, type DeploymentReadiness } from "@/api/projects-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Dialog, DialogTrigger, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter } from "@/components/ui/dialog"

export function ProjectManager() {
  const { refreshPlatform } = usePlatform()
  const [open, setOpen] = useState(false)
  const [projects, setProjects] = useState<ProjectPreview[]>([])
  const [selected, setSelected] = useState<ProjectPreview | null>(null)
  const [composePath, setComposePath] = useState<string | null>(null)
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const [notice, setNotice] = useState("")
  const [readiness,setReadiness]=useState<DeploymentReadiness|null>(null)
  const discover = useCallback(() => projectsApi.discover().then(setProjects), [])
  useEffect(() => {
    let alive = true
    const refresh = () => void projectsApi.discover().then(p => { if (alive) setProjects(p) }).catch(() => undefined)
    refresh()
    const timer = window.setInterval(refresh, 15000)
    return () => { alive = false; window.clearInterval(timer) }
  }, [])
  const perform = async (label: string, action: () => Promise<void>) => {
    if (busy) return
    setBusy(label); setError(""); setNotice("")
    try { await action() } catch (e) { setError(String(e)) }
    finally { setBusy(""); await refreshPlatform().catch(() => undefined) }
  }
  const choose = (compose: boolean) => perform("Reading project…", async () => {
    const path = await projectsApi.choose()
    if (!path) return
    const preview = compose ? await projectsApi.importCompose(path, false) : await projectsApi.inspect(path)
    setComposePath(compose ? path : null); setSelected(preview)
    setReadiness(null)
  })
  return <Dialog open={open} onOpenChange={value => { if (!busy) setOpen(value) }}>
    <DialogTrigger render={<Button size="xs" variant="ghost" className="workspace-footer-reclaim" />}>Projects{projects.length ? <span className="text-muted-foreground">{projects.length}</span> : null}</DialogTrigger>
    <DialogPopup className="max-w-5xl">
      <DialogHeader><DialogTitle>Projects</DialogTitle><DialogDescription>Open yougori.yaml or import an existing Docker Compose project.</DialogDescription></DialogHeader>
      <DialogPanel className="space-y-4">
        <div className="flex flex-wrap gap-2">
          <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => void choose(false)}><FolderOpenIcon />Open yougori.yaml</Button>
          <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => void choose(true)}><ImportIcon />Import Docker Project</Button>
        </div>
        {projects.length ? <div aria-label="Detected projects" className="divide-y rounded-lg border">{projects.map(project => <button type="button" className="flex w-full items-center justify-between gap-4 px-3 py-2 text-left text-sm hover:bg-muted" key={project.path} disabled={Boolean(busy)} onClick={() => void perform("Reading project…", async () => { setSelected(await projectsApi.inspect(project.path)); setComposePath(null); setReadiness(null) })}><span className="font-medium">{project.project ?? "Invalid project"}</span><span className="truncate text-xs text-muted-foreground">{project.path}</span></button>)}</div> : !selected ? <p className="py-3 text-sm text-muted-foreground">Project files in your CLI workspace and previously opened folders appear here automatically.</p> : null}
        {selected ? <section className="space-y-3" aria-label="Project plan">
          <div><h3 className="font-semibold">{selected.project}</h3><p className="break-all text-xs text-muted-foreground">{selected.path}</p></div>
          <div className="overflow-x-auto rounded-lg border"><table className="w-full text-left text-sm"><thead className="bg-muted/50 text-xs text-muted-foreground"><tr>{["Environment", "Image / type", "CPU", "RAM", "My PC", "Change"].map(s => <th className="px-3 py-2 font-medium" key={s}>{s}</th>)}</tr></thead><tbody className="divide-y">{selected.environments?.map(e => <tr key={e.name}><td className="px-3 py-2 font-medium">{e.name}</td><td className="max-w-60 truncate px-3 py-2" title={e.image}>{e.image || e.type}{e.gpu ? " · GPU" : ""}</td><td className="px-3 py-2">{e.cpu}</td><td className="whitespace-nowrap px-3 py-2">{e.memoryGb} GB</td><td className="px-3 py-2">{e.pcAccess ? e.editPc ? "View & Edit" : "View only" : "Off"}</td><td className="px-3 py-2 capitalize">{e.action}</td></tr>)}</tbody></table></div>
          <p className="text-xs text-muted-foreground">{selected.connections} connections · {selected.publications} public routes. {selected.notice}</p>
          {selected.environments?.some(e => e.editPc) ? <p className="text-xs text-amber-700 dark:text-amber-300">This project grants View & Edit access to selected PC folders. Review their changes from the environment’s Changes view.</p> : null}
        </section> : null}
        {error ? <p role="alert" className="whitespace-pre-wrap text-sm text-destructive-foreground">{error}</p> : null}
        {readiness ? <section aria-label="Deployment readiness" className="space-y-2 rounded-lg border p-3 text-sm"><p className="font-medium">{readiness.ready ? Object.values(readiness.environments).every(report => report.applicationVerified) ? "Application verified" : "Runtime ready; application verification not configured" : "Deployment needs attention"}</p>{Object.entries(readiness.environments).map(([name,report])=><div key={name} className="space-y-1"><p className="font-medium">{name}</p><div className="flex flex-wrap gap-x-4 gap-y-1 text-xs">{Object.entries(report.stages??{}).map(([stage,value])=><span key={stage}>{({saved:"Saved",running:"Runtime",process:"Application",localHttp:"Local HTTP",tunnel:"Tunnel",publicHttps:"Public HTTPS",authenticated:"Authenticated request"} as Record<string,string>)[stage]??stage}: <strong>{value.status}</strong>{value.httpStatus ? ` (HTTP ${value.httpStatus})` : ""}</span>)}</div>{report.recoveryAction ? <p className="text-xs text-muted-foreground">{report.recoveryAction}</p> : null}</div>)}<p className="text-xs text-muted-foreground">Public addresses are verified only when the configured HTTPS health request succeeds.</p></section> : null}
        {busy || notice ? <p role="status" className="text-sm text-muted-foreground">{busy || notice}</p> : null}
      </DialogPanel>
      <DialogFooter>
        <Button variant="ghost" disabled={Boolean(busy)} onClick={() => setOpen(false)}>Close</Button>
        {selected && !composePath ? <Button variant="outline" disabled={Boolean(busy)} onClick={() => void perform("Stopping project…", async () => { await projectsApi.action(selected.path, "down"); setNotice("Project stopped. Files and volumes are kept.") })}>Stop project</Button> : null}
        {selected && !composePath ? <Button variant="outline" disabled={Boolean(busy)} onClick={() => void perform("Checking deployment…",async()=>{setReadiness(await projectsApi.status(selected.path))})}>Check readiness</Button> : null}
        {selected ? <Button disabled={Boolean(busy)} loading={Boolean(busy)} onClick={() => void perform(composePath ? "Importing Compose…" : "Applying project…", async () => {
          if (composePath) { const preview = await projectsApi.importCompose(composePath, true); setSelected(preview); setComposePath(null); await discover(); setNotice("yougori.yaml created. Review the plan, then start the project.") }
          else { const result=await projectsApi.action(selected.path, "up"); setReadiness(result.readiness??null); setSelected(await projectsApi.inspect(selected.path)); await discover(); setNotice(result.ready===false ? "Project applied. Check the failed readiness stages below." : result.readiness ? "Project applied. Readiness results are shown below." : "Project applied and started.") }
        })}>{composePath ? "Create yougori.yaml" : "Apply & start"}</Button> : null}
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
