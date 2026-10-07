import { useEffect, useRef, useState } from "react"
import { platformApi } from "@/api/platform-api"
import { usePlatform } from "@/context/platform-context"
import { GuestWorkspace } from "@/components/guest-workspace"
import { Switch } from "@/components/ui/switch"
import { Button } from "@/components/ui/button"
import { sharingApi } from "@/api/sharing-api"
import { workspaceApi, type HostShare } from "@/api/workspace-api"
import { ShieldCheckIcon, XIcon } from "lucide-react"
import { Dialog, DialogPopup, DialogTitle, DialogDescription, DialogHeader } from "@/components/ui/dialog"
import { ConfigurationHelp } from "@/components/configuration-help"
import { pcAccessLevel } from "@/lib/pc-access"

export default function IsolatedCliView({onHide}:{onHide():void}){
 const {state,refreshPlatform,updateContainerNetwork}=usePlatform()
 const [id,setId]=useState(""),[error,setError]=useState(""),[busy,setBusy]=useState(false),[target,setTarget]=useState(""),[permission,setPermission]=useState("view"),[notice,setNotice]=useState(""),[grants,setGrants]=useState<string[]>([])
 const [shares,setShares]=useState<HostShare[]>([]),[pcMode,setPcMode]=useState("view")
 const [accessOpen, setAccessOpen] = useState(false)
 const opening=useRef(false)
 const open=async()=>{if(opening.current)return;opening.current=true;setBusy(true);setError("");try{const value=await platformApi.openIsolatedCli();await refreshPlatform();setId(value)}catch(reason){setError(String(reason))}finally{setBusy(false);opening.current=false}}
 useEffect(()=>{if(!id)void open()},[id]) // eslint-disable-line react-hooks/exhaustive-deps
 const loadShares=async(environmentId:string)=>{setShares((await workspaceApi.services(environmentId)).shares)}
 useEffect(()=>{if(!id)return;let active=true;void workspaceApi.services(id).then(services=>{if(active)setShares(services.shares)}).catch(()=>{/* The folder list reloads with the next permission change. */});return()=>{active=false}},[id])
 const perform=async(action:()=>Promise<void>)=>{if(busy)return;setBusy(true);setError("");try{await action()}catch(reason){setError(String(reason))}finally{setBusy(false)}}
 const field="h-8 min-w-0 rounded-md border border-input bg-background px-2 text-xs focus-visible:outline-2 focus-visible:outline-ring"
 const grantable=state?.environments.filter(e=>e.id!==id&&e.kind!=="computerBranch"&&!e.runtime.startsWith("shared://"))??[]
 const feedback = <>
  {error ? <div role="alert" className="flex shrink-0 items-start gap-2 border-b px-4 py-2 text-xs text-destructive-foreground"><p className="min-w-0 flex-1 break-words">{error}</p><Button size="icon-xs" variant="ghost" aria-label="Dismiss CLI error" onClick={() => setError("")}><XIcon aria-hidden="true" /></Button></div> : null}
  {notice ? <div role="status" className="flex shrink-0 items-start gap-2 border-b px-4 py-2 text-xs text-muted-foreground"><p className="min-w-0 flex-1 whitespace-pre-wrap break-words">{notice}</p><Button size="icon-xs" variant="ghost" aria-label="Dismiss CLI notice" onClick={() => setNotice("")}><XIcon aria-hidden="true" /></Button></div> : null}
 </>
 return <section id="host-terminal-panel" aria-label="Isolated Yougori CLI" className="isolated-cli flex h-full min-h-0 flex-1 flex-col overflow-hidden bg-background">
  {!accessOpen ? feedback : null}
  {id ? <div className="min-h-0 flex-1"><GuestWorkspace embedded compact initialEnvironmentId={id} onClose={onHide} toolbarActions={
    <Button size="xs" variant="ghost" className="gap-1.5 text-xs text-muted-foreground" onClick={() => setAccessOpen(true)} aria-label="CLI access" title="Manage environment and PC folder access"><ShieldCheckIcon aria-hidden="true" />Access</Button>
  } /></div> : <div className="grid flex-1 place-items-center p-6 text-sm text-muted-foreground">{busy ? <span role="status">Starting CLI…</span> : <Button size="sm" onClick={() => void open()}>Start CLI</Button>}</div>}
  <Dialog open={accessOpen} onOpenChange={setAccessOpen}>
    <DialogPopup className="max-w-2xl" bottomStickOnMobile={false}>
      <DialogHeader><DialogTitle>CLI access</DialogTitle><DialogDescription>Choose what this isolated terminal can access.</DialogDescription></DialogHeader>
      <div className="min-h-0 overflow-y-auto px-6 pb-6">
        <div className="mb-5 flex items-center justify-between gap-3 border-b pb-5">
          <label htmlFor="cli-internet" className="text-sm font-medium">Internet access</label>
          <div className="flex items-center gap-2"><ConfigurationHelp label="CLI Internet access details">Required to download tools and connect to online providers. PC folder and environment permissions are managed separately.</ConfigurationHelp><Switch id="cli-internet" checked={state?.environments.find(environment => environment.id === id)?.networkAccess ?? false} disabled={busy || !id} onCheckedChange={enabled => void perform(() => updateContainerNetwork(id, enabled))} /></div>
        </div>
        <section aria-label="Environment access" className="border-b pb-5">
          <div className="mb-3 flex items-center gap-2 text-sm font-medium">Environments<ConfigurationHelp label="Environment grant details">All environments includes the environments available now. Grants expire after 24 hours or when the engine exits. View Only reads environment information; Full control allows changes. Manage other grants in the environment's Sharing controls.</ConfigurationHelp></div>
          <div className="flex flex-wrap items-center gap-2">
    <select aria-label="Environment for isolated CLI" className={`${field} flex-1`} value={target} disabled={busy} onChange={e=>setTarget(e.target.value)} title="Give the CLI access to one environment"><option value="">Grant environment…</option><option value="all">All environments</option>{grantable.map(e=><option key={e.id} value={e.id}>{e.name}</option>)}</select>
    <select aria-label="Isolated CLI permission" className={`${field} shrink-0`} value={permission} disabled={busy} onChange={e=>setPermission(e.target.value)}><option value="view">View Only</option><option value="control">Full control</option></select>
    <Button size="xs" variant="outline" className="h-8! shrink-0 px-3!" disabled={busy||!target||!grantable.length} title="The grant expires after 24 hours, or when the engine exits" onClick={()=>void perform(async()=>{const selected=target==="all"?grantable:grantable.filter(environment=>environment.id===target);const commands:string[]=[];
      for(const environment of selected){try{const result=await platformApi.grantIsolatedCliEnvironment(environment.id,permission);setGrants(current=>[...current,result.grant.id]);commands.push(result.command)}catch(reason){setNotice(`${commands.length} of ${selected.length} grants created. Use Revoke to remove grants created in this session.`);throw reason}}
      setNotice(commands.join("\n"))})}>Grant 24h</Button>
    {grants.length?<Button size="xs" variant="ghost" className="h-8! shrink-0 px-3!" disabled={busy} onClick={()=>void perform(async()=>{for(const grant of grants){await sharingApi.revoke(grant);setGrants(current=>current.filter(id=>id!==grant))}setNotice("Grant revoked. Manage other grants in the environment's Sharing controls.")})}>Revoke</Button>:null}
          </div>
        </section>
        <section aria-label="My PC access" className="pt-5">
          <div className="mb-3 flex items-center gap-2"><span className="text-sm font-medium">PC folders</span><span className="ml-auto text-xs text-muted-foreground">{pcAccessLevel(shares)}</span><ConfigurationHelp label="PC folder permission details">Only selected folders are shared. View Only can read files. View &amp; Edit can read, create, change and delete them.</ConfigurationHelp></div>
          {shares.length ? <ul className="mb-3 space-y-2">{shares.map(share => <li key={share.id} className="flex min-w-0 items-center gap-3 text-xs"><span className="min-w-0 flex-1 truncate" title={share.path}>{share.path}</span><span className="shrink-0 text-muted-foreground">{share.readOnly ? "View Only" : "View & Edit"}</span></li>)}</ul> : null}
          <div className="flex flex-wrap items-center gap-2">
     <select aria-label="My PC permission for the isolated CLI" className={`${field} shrink-0`} value={pcMode} disabled={busy} onChange={e=>setPcMode(e.target.value)}><option value="view">View Only</option><option value="edit">View &amp; Edit</option></select>
     <Button size="xs" variant="outline" className="h-8! shrink-0 px-3!" disabled={busy} onClick={()=>void perform(async()=>{const folders=await workspaceApi.chooseFolders();for(const folder of folders)await workspaceApi.share(id,folder,pcMode==="view");if(folders.length){await loadShares(id);setNotice(`My PC access: ${pcMode==="view"?"View Only — the CLI can read":"View & Edit — the CLI can read, change, create, and delete"} files in ${folders.length===1?"the selected folder":`${folders.length} selected folders`}.`)}})}>Choose PC folders</Button>
     {shares.length?<Button size="xs" variant="ghost" className="h-8! shrink-0 px-3!" disabled={busy} onClick={()=>void perform(async()=>{for(const share of shares)await workspaceApi.unshare(share.id);await loadShares(id);setNotice("My PC access: No Access. The CLI keeps only its own files inside the microVM.")})}>Set No Access</Button>:null}
          </div>
        </section>
      </div>
      {accessOpen ? feedback : null}
    </DialogPopup>
  </Dialog>
 </section>
}
