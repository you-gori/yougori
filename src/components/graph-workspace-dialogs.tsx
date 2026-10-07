import { lazy, Suspense, useEffect, useMemo, useRef, useState } from "react"
import { CopyIcon, FolderPlusIcon, XIcon } from "lucide-react"
import { workspaceApi } from "@/api/workspace-api"
import { publicationDefinitions, publicationDestination, publicationDestinations } from "@/components/graph-capabilities"
import type { useWorkspaceFeatures, WorkspaceDialog } from "@/components/use-workspace-features"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { Field, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Radio, RadioGroup } from "@/components/ui/radio-group"
import { CloudflareAccountFields } from "@/components/cloudflare-account-fields"
import { accountRequest, emptyCloudflareDraft } from "@/lib/cloudflare-account"
import { readPublicAccessPresets } from "@/lib/public-access-presets"
import { rememberPublicAccessPreset } from "@/lib/public-access-preset-actions"
import { changeTour, getTour, isWebsiteTour, ownsTour, tourWebsiteOpened, tourWebsitePublished, useInstructionsTour } from "@/lib/instructions-tour"
import { platformApi } from "@/api/platform-api"

const AddServicePortDialog = lazy(async () => ({ default: (await import("@/components/dialogs/add-service-port-dialog")).AddServicePortDialog }))

type Model = ReturnType<typeof useWorkspaceFeatures>
export function GraphWorkspaceDialogs({ model }: { model: Model }) {
  const [busy, setBusy] = useState(false)
  const tour = useInstructionsTour()
  const guided = Boolean(ownsTour(tour) && tour?.environmentId === model.dialog?.environmentId && (tour?.step.startsWith("demo-") || tour?.step === "done"))
  return <Dialog modal={!guided} disablePointerDismissal={guided} open={Boolean(model.dialog)} onOpenChange={(open, details) => {
    // A publication or writable share must not finish invisibly after dismissal.
    if (!open && busy) { details.cancel(); return }
    const guideEvent = details.event.target instanceof Element && details.event.target.closest('[data-tour-ui]')
    if (!open && (guideEvent || (guided && details.reason === "focus-out"))) { details.cancel(); return }
    if (!open) {
      model.setDialog(null)
      if (guided && model.dialog && isWebsiteTour(model.dialog.environmentId, "demo-port-add", "demo-publish", "demo-link")) changeTour({ step: "demo-port-open" })
    }
  }}>
    {model.dialog?.type === "service" && !model.dialog.port
      ? <Suspense fallback={null}><AddServicePortDialog key={model.dialog.environmentId} environment={model.decorated.find(item => item.id === model.dialog?.environmentId)} onBusyChange={setBusy} onAddPort={port => { if (model.dialog) return model.addPort(model.dialog.environmentId, port) }} /></Suspense>
      : model.dialog ? <WorkspaceDialogContent dialog={model.dialog} key={`${model.dialog.environmentId}:${model.dialog.type}:${model.dialog.type === "service" ? model.dialog.port : ""}`} model={model} onBusyChange={setBusy} /> : null}
  </Dialog>
}

function WorkspaceDialogContent({ dialog, model, onBusyChange }: { dialog: WorkspaceDialog; model: Model; onBusyChange(busy: boolean): void }) {
  const env = model.decorated.find(item => item.id === dialog.environmentId)
  const [busy, setBusy] = useState(false)
  const operationLock = useRef(false)
  const [error, setError] = useState(dialog.type === "service" ? dialog.error ?? "" : "")
  const [notice, setNotice] = useState("")
  const [writeAccess, setWriteAccess] = useState(false)
  const [folders, setFolders] = useState<string[]>([])
  const [hostPort, setHostPort] = useState("")
  const [cloudflare, setCloudflare] = useState(() => ({ ...emptyCloudflareDraft(), ...(dialog.type === "service" && dialog.account ? { mode: "account" as const } : {}) }))
  const [cloudflareLoading, setCloudflareLoading] = useState(true)
  const [presets, setPresets] = useState(readPublicAccessPresets)
  const [selectedPresetId, setSelectedPresetId] = useState<string | null>(null)
  const [kind, setKind] = useState<"local" | "cloudflare">(dialog.type === "service" && dialog.kind && dialog.kind !== "local" ? "cloudflare" : "local")
  const perform = async (action: () => Promise<unknown>) => {
    if (operationLock.current) return
    operationLock.current = true
    setError(""); setNotice(""); setBusy(true); onBusyChange(true)
    try { await action() }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally {
      // Reconcile even a partially completed multi-folder operation. A failed
      // refresh must not leave the dialog permanently busy or hide the first error.
      try { await model.refresh(dialog.environmentId) }
      catch (reason) { setError(current => current || (reason instanceof Error ? reason.message : String(reason))) }
      finally { operationLock.current = false; setBusy(false); onBusyChange(false) }
    }
  }
  const running = env?.status === "running"
  const port = dialog.type === "service" ? dialog.port : 0
  const publications = useMemo(() => env?.workspace?.publications.filter(p => p.port === port) ?? [], [env?.workspace?.publications, port])
  useEffect(() => {
    const refreshPresets = () => setPresets(readPublicAccessPresets())
    window.addEventListener("yougori-public-presets-changed", refreshPresets)
    return () => window.removeEventListener("yougori-public-presets-changed", refreshPresets)
  }, [])
  const tour = useInstructionsTour()
  useEffect(() => {
    for (const publication of publications) tourWebsitePublished(dialog.environmentId, publication)
  }, [dialog.environmentId, publications, tour?.step])
  const validPort = (value: string) => /^\d+$/.test(value) && Number(value) > 0 && Number(value) < 65536 && Number(value) !== 7443
  const copy = (value: string) => void perform(() => navigator.clipboard.writeText(value))
  const publishService = () => void perform(async () => {
    const current = getTour()
    if (isWebsiteTour(dialog.environmentId, "demo-publish")) {
      if (port !== 3000 || kind !== "cloudflare" || cloudflare.mode !== "quick" || selectedPresetId) throw new Error("For this tutorial, choose Public access / Cloudflare Tunnel and Quick link — no account. Nothing was published.")
      const { verifyHelloWebsite } = await import("@/lib/tour-website")
      await verifyHelloWebsite(platformApi.executeEnvironmentCommand, dialog.environmentId, current!.run)
      // Skip or closing the dialog during this read-only check cancels the
      // subsequent publication; it must not start invisibly afterwards.
      if (!isWebsiteTour(dialog.environmentId, "demo-publish") || getTour()?.run !== current?.run) return
    }
    if (hostPort && kind !== "cloudflare" && !validPort(hostPort)) throw new Error("Enter a valid host port or leave it empty.")
    const preset = kind === "cloudflare" && selectedPresetId ? presets.find(item => item.id === selectedPresetId && item.port === port) : undefined
    if (kind === "cloudflare" && selectedPresetId && !preset) throw new Error("This saved setup is no longer available for this app port")
    if (preset) {
      const inUse = model.decorated.find(item => item.id !== dialog.environmentId && item.workspace?.publications.some(publication => publication.kind === "cloudflare" && publication.hostPort === preset.hostPort && publication.urls.includes(`https://${preset.hostname}`)))
      if (inUse) throw new Error(`${preset.hostname} is already connected to ${inUse.name}. Disconnect it there first.`)
    }
    const account = kind === "cloudflare" ? preset
      ? { hostPort: preset.hostPort, options: { hostname: preset.hostname, presetId: preset.id, presetSourceEnvironmentId: preset.credentialEnvironmentId, remember: false, routesReviewed: true } }
      : cloudflare.mode === "account" ? accountRequest(cloudflare) : undefined : undefined
    const publication = await workspaceApi.publish(dialog.environmentId, port, kind, account?.hostPort ?? (kind === "cloudflare" || !hostPort ? undefined : Number(hostPort)), account?.options)
    tourWebsitePublished(dialog.environmentId, publication)
    if (account && !preset && cloudflare.mode === "account" && cloudflare.remember) {
      try {
        await rememberPublicAccessPreset(dialog.environmentId, port, account.options.hostname, account.hostPort)
        setPresets(readPublicAccessPresets())
      } catch (reason) {
        setNotice(`Connected, but could not add this domain to Saved setups: ${reason instanceof Error ? reason.message : String(reason)}`)
      }
    }
    setCloudflare(current => ({ ...current, token: "" }))
  })

  return <DialogPopup className={dialog.type === "service" ? "w-[min(68rem,calc(100vw-2rem))] max-w-none" : undefined} closeProps={{ disabled: busy }} data-service-options={dialog.type === "service" ? dialog.environmentId : undefined} data-service-port={port}>
    {dialog.type === "service" ? <DialogHeader className="flex-row items-center gap-4 border-b px-6 pb-5! pt-6 pe-14">
      <span aria-hidden="true" className="flex size-14 shrink-0 flex-col items-center justify-center rounded-xl border border-primary/30 bg-primary/10 font-mono text-primary"><span className="text-[10px] font-medium uppercase leading-none tracking-wider opacity-70">Port</span><span className="mt-1 text-base font-semibold leading-none">{port}</span></span>
      <div className="flex min-w-0 flex-1 flex-col gap-1.5">
        <div className="flex flex-wrap items-center gap-2"><DialogTitle className="min-w-0 truncate">{`Port ${port}`} · <span className="font-normal text-muted-foreground">{env?.name ?? "Environment"}</span></DialogTitle><span className={`inline-flex h-5 items-center gap-1.5 rounded-full border px-2 text-[11px] font-medium ${running ? "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400" : "bg-muted text-muted-foreground"}`}><span className={`size-1.5 rounded-full ${running ? "bg-emerald-500" : "bg-muted-foreground/60"}`} />{running ? "Running" : "Stopped"}</span></div>
        <DialogDescription>Choose who can open this app: devices on your network, or anyone with a public link.</DialogDescription>
      </div>
    </DialogHeader> : <DialogHeader>
      <DialogTitle>My PC · {env?.name ?? "Environment"}</DialogTitle>
      <DialogDescription>Only the folders you choose are shared. Disconnecting revokes access; stopping the environment removes its shares.</DialogDescription>
    </DialogHeader>}
    <DialogPanel className={dialog.type === "service" ? "flex flex-col gap-4 px-6 pb-6 pt-5!" : "flex flex-col gap-4"}>
      {!running ? <p className="rounded-xl border border-amber-500/30 bg-amber-500/10 px-3.5 py-2.5 text-sm">Start this environment to share files or publish services.</p> : null}
      {error ? <p className="rounded-xl border border-destructive/30 bg-destructive/10 px-3.5 py-2.5 text-sm text-destructive-foreground" role="alert">{error}</p> : null}
      {notice ? <p className="rounded-xl border bg-muted/60 px-3.5 py-2.5 text-sm text-muted-foreground" role="status">{notice}</p> : null}
      {dialog.type === "shares" ? <>
        <div className="flex items-center justify-between gap-2 rounded-lg border p-3 text-sm"><span>{env?.workspace?.shares.length ? "PC access: selected folders only" : "No Access — this environment cannot access your PC files"}</span>{env?.workspace?.shares.length ? <Button disabled={busy} variant="outline" onClick={() => void perform(async () => { for (const share of env.workspace?.shares ?? []) await workspaceApi.unshare(share.id) })}>Set No Access</Button> : null}</div>
        {env?.kind === "fullVm" ? <p className="text-xs text-muted-foreground">Open the private folder URL in the VM browser to view files and edit them when permitted. Read-only WebDAV is also available. Containers and managed microVMs mount folders automatically.</p> : null}
        {env?.workspace?.shares.map(share => <div className="space-y-1 rounded-lg border p-3 text-xs" key={share.id}>
          <div className="flex items-center gap-2"><span className="min-w-0 flex-1 break-all font-medium">{share.path}</span><span className="shrink-0 text-muted-foreground">{share.readOnly ? "View Only" : "View & Edit"}</span><Button aria-label={`Disconnect ${share.path}`} disabled={busy} onClick={() => void perform(() => workspaceApi.unshare(share.id))} size="icon-xs" variant="ghost"><XIcon aria-hidden="true" /></Button></div>
          <div className="flex items-center gap-2"><code className="min-w-0 flex-1 break-all text-muted-foreground">{share.mountPath ?? "Private folder link"}</code><Button aria-label="Copy guest folder location" disabled={busy} onClick={() => void perform(async () => { const location = share.mountPath ?? (await workspaceApi.shareCredentials(share.id)).guestUrl; copy(location) })} size="icon-xs" variant="ghost"><CopyIcon aria-hidden="true" /></Button></div>
          {!share.mountPath ? <p className="text-muted-foreground">Keep this URL private. It grants access to the selected folder while connected.</p> : null}
        </div>)}
        {folders.length ? <div className="space-y-2 rounded-lg border p-3">{folders.map(folder => <div className="flex items-center gap-2 text-xs" key={folder}><span className="min-w-0 flex-1 break-all">{folder}</span><Button aria-label={`Remove selected ${folder}`} disabled={busy} onClick={() => setFolders(current => current.filter(p => p !== folder))} size="icon-xs" variant="ghost"><XIcon aria-hidden="true" /></Button></div>)}</div> : null}
        <Button disabled={!running || busy} onClick={() => void perform(async () => { const selected = await workspaceApi.chooseFolders(); setFolders(current => [...new Set([...current, ...selected])]) })} variant="outline"><FolderPlusIcon aria-hidden="true" />Choose folders</Button>
        <RadioGroup aria-label="Selected folder permission" disabled={busy} value={writeAccess ? "edit" : "view"} onValueChange={value => setWriteAccess(value === "edit")}><label className="flex items-center gap-2 text-sm"><Radio value="view" />View Only — read files</label><label className="flex items-center gap-2 text-sm"><Radio value="edit" />View &amp; Edit — read, change, create, and delete files</label></RadioGroup>
        {writeAccess ? <p className="text-xs text-muted-foreground">Programs inside this environment can change or delete files in the selected folders.</p> : null}
        <Button disabled={!running || !folders.length} loading={busy} onClick={() => void perform(async () => {
          for (const folder of folders) { await workspaceApi.share(dialog.environmentId, folder, !writeAccess); setFolders(current => current.filter(p => p !== folder)) }
        })}>Connect selected folders</Button>
      </> : <>
        {env?.workspace?.notice ? <p className="text-xs text-muted-foreground">{env.workspace.notice}</p> : null}
        <div className="grid gap-5 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
        <div className="space-y-4">
        {publications.length ? <section aria-label="Active connections" className="space-y-2">
          <h3 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Connected</h3>
          {publications.map(publication => <div className="rounded-xl border bg-card p-3" key={publication.id}>
            <div className="flex items-center gap-2"><span className="min-w-0 flex-1 text-sm font-medium">{publicationDefinitions.find(item => item.kind === publication.kind)?.title}{publication.cloudflareAccount ? " · Your account" : ""}</span><span className="text-xs text-muted-foreground">{publication.status}</span><Button aria-label={`Disconnect ${publication.kind} from port ${port}`} disabled={busy} onClick={() => void perform(async () => { await workspaceApi.unpublish(publication.id); if (isWebsiteTour(dialog.environmentId, "demo-link")) { model.setDialog(null); changeTour({ step: "demo-port-open" }) } })} size="xs" variant="ghost">Disconnect</Button></div>
            {publication.urls.map(url => <div className="mt-1 flex items-center gap-1" key={url}><button disabled={busy} className="min-w-0 flex-1 truncate text-left text-xs text-primary underline" onClick={() => void perform(async () => { await workspaceApi.openUrl(url); tourWebsiteOpened(dialog.environmentId, port, publication.kind === "cloudflare" && !publication.cloudflareAccount) })} title={url} type="button">{url}</button><Button aria-label={`Copy ${url}`} disabled={busy} onClick={() => copy(url)} size="icon-xs" variant="ghost"><CopyIcon aria-hidden="true" /></Button></div>)}
            {publication.message ? <p className="mt-1 text-xs text-muted-foreground">{publication.message}</p> : null}
          </div>)}
        </section> : null}
        <fieldset className="space-y-2"><legend className="mb-2 text-sm font-medium">Where should this port be available?</legend><RadioGroup aria-label="Publish to" className="grid gap-2" disabled={busy} onValueChange={value => setKind(value === "local" ? "local" : "cloudflare")} value={publicationDestination(kind)}>{publicationDestinations.map(item => <label className={`flex min-h-20 cursor-pointer items-start gap-3 rounded-xl border p-3 transition-colors ${publicationDestination(kind) === item.kind ? "border-primary bg-primary/5" : "bg-card hover:border-primary/40"}`} key={item.kind}><Radio aria-label={item.title} aria-description={item.kind === "local" ? "This PC and devices on your local network" : "A public link that anyone can open"} value={item.kind} /><span aria-hidden="true" className="min-w-0"><span className="block text-sm font-medium">{item.title}</span><span className="mt-1 block text-xs leading-4 text-muted-foreground">{item.kind === "local" ? "This PC and devices on your local network" : "A public link that anyone can open"}</span></span></label>)}</RadioGroup></fieldset>
        </div>
        <div className="min-w-0">
        {kind === "cloudflare" ? <section aria-label="Cloudflare configuration and status" className="space-y-3"><div><h3 className="text-sm font-medium">Choose your public link</h3><p className="mt-1 text-xs text-muted-foreground">Add visitor restrictions in Cloudflare if this app should be private.</p></div><CloudflareAccountFields environmentId={dialog.environmentId} port={port} value={cloudflare} onChange={setCloudflare} onLoadingChange={setCloudflareLoading} busy={busy || cloudflareLoading} perform={perform} refreshKey={publications.filter(p => p.kind === "cloudflare").map(p => p.id).join(",")} compact presets={presets} selectedPresetId={selectedPresetId} onSelectPreset={setSelectedPresetId} /></section> : <Field className="rounded-xl border bg-card p-3"><FieldLabel>Port on this PC <span className="text-xs font-normal text-muted-foreground">Optional</span></FieldLabel><Input disabled={busy} inputMode="numeric" onChange={event => setHostPort(event.target.value)} placeholder="Automatic" type="text" value={hostPort} /><p className="text-xs text-muted-foreground">Leave blank to choose an available port automatically.</p></Field>}
        </div>
        </div>
        {busy ? <p className="text-xs text-muted-foreground" role="status">Connecting… The first Cloudflare download can take a few minutes.</p> : null}
      </>}
    </DialogPanel>
    {dialog.type === "service" ? <DialogFooter variant="bare" className="flex-row flex-wrap items-center justify-between gap-3 border-t bg-muted/40 px-6 py-4">
      {model.manual[dialog.environmentId]?.includes(port) && !publications.length ? <Button disabled={busy} onClick={() => void perform(() => model.removePort(dialog.environmentId, port))} size="sm" variant="destructive">Remove manual port</Button> : <p className="max-w-80 text-xs leading-4 text-muted-foreground">Saved connections reconnect when this node starts. Links work while the node and Yougori are running.</p>}
      <div className="ml-auto flex items-center gap-2"><DialogClose render={<Button disabled={busy} type="button" variant="ghost" />}>Done</DialogClose><Button disabled={!running || (kind === "cloudflare" && cloudflareLoading) || publications.some(p => p.kind === kind)} loading={busy} onClick={publishService}>{kind === "local" ? "Connect local network" : "Publish service"}</Button></div>
    </DialogFooter> : <DialogFooter><DialogClose render={<Button disabled={busy} type="button" variant="ghost" />}>Done</DialogClose></DialogFooter>}
  </DialogPopup>
}
