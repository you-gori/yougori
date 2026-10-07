import { CloudDeploymentWarning, cloudRiskAcknowledgement } from "@/components/cloud-deployment-warning"
import { useEffect, useRef, useState } from "react"
import { cloudApi, type CloudDeployRequest } from "@/api/cloud-api"
import { duplicationApi, type CloudCopyLocation, type DuplicationRequest } from "@/api/duplication-api"
import { usePlatform } from "@/context/platform-context"
import type { Environment } from "@/types/platform"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Checkbox } from "@/components/ui/checkbox"
import { ConfigurationHelp } from "@/components/configuration-help"
import { Dialog, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter, DialogPopup } from "@/components/ui/dialog"
import { driveLabel, storageDrives } from "@/lib/storage-drives"

const providers = [["aws", "AWS"], ["azure", "Azure"], ["google", "Google Cloud"]] as const
const accountLabel = (provider: string) => provider === "aws" ? "AWS CLI profile" : provider === "azure" ? "Subscription ID" : "Project ID"
const emptyTarget: CloudDeployRequest = { provider:"aws", account:"", region:"", name:"", image:"", machineType:"", subnet:"", resourceGroup:"", securityGroup:"", keyPair:"", sshPublicKey:"", imageProject:"", containerImage:"", username:"ubuntu" }

function ProviderChoice({ value, onChange, label }: { value: CloudCopyLocation["provider"]; onChange(value: CloudCopyLocation["provider"]): void; label: string }) {
  return <div className="flex gap-1" role="group" aria-label={label}>{providers.map(([provider, name]) => <Button key={provider} type="button" size="xs" variant={provider === value ? "secondary" : "ghost"} aria-pressed={provider === value} onClick={() => onChange(provider)}>{name}</Button>)}</div>
}
function Field({ label, value, onChange, placeholder }: { label: string; value: string; onChange(value: string): void; placeholder?: string }) {
  return <label className="min-w-0 space-y-1 text-xs"><span>{label}</span><Input value={value} onChange={event => onChange(event.target.value)} placeholder={placeholder} autoComplete="off" spellCheck={false} /></label>
}

export function CloudDuplicateDialog({ environment, destination, onClose }: { environment: Environment; destination: "local" | "cloud"; onClose(): void }) {
  const { state, duplicateEnvironment, refreshPlatform } = usePlatform()
  const deployment = state?.cloudDeployments?.[environment.id]
  const [saved] = useState(() => Object.values(state?.duplicationJobs ?? {}).find(job => job.request.environmentId === environment.id && job.request.destination === destination && job.status !== "complete"))
  const [operationId] = useState(() => saved?.request.operationId ?? crypto.randomUUID())
  const [name, setName] = useState(saved?.request.name ?? `${environment.name.slice(0, 65)} copy`)
  const [source, setSource] = useState<CloudCopyLocation>(saved?.request.source ?? state?.cloudCopySources?.[environment.id]?.location ?? { provider: deployment?.provider as CloudCopyLocation["provider"] ?? "aws", account:deployment?.account ?? "", region:deployment?.region ?? "", resourceGroup:deployment?.resourceGroup ?? "", instance:deployment ? deployment.provider === "aws" ? deployment.resourceId : deployment.name : "", bucket:"" })
  const [target, setTarget] = useState<CloudDeployRequest>(saved?.request.target ?? { ...emptyTarget, provider:source.provider, account:source.account, region:source.region, resourceGroup:source.resourceGroup })
  const [targetBucket, setTargetBucket] = useState(saved?.request.targetBucket ?? "")
  const [drive, setDrive] = useState(saved?.request.storageDrive ?? environment.storageDrive ?? "")
  const [reviewed, setReviewed] = useState(saved?.request.reviewed ?? false)
  const [inspected, setInspected] = useState(Boolean(saved))
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const guard = useRef(false)
  const alive = useRef(true)
  useEffect(() => { alive.current = true; return () => { alive.current = false } }, [])
  const job = state?.duplicationJobs?.[operationId]
  const frozen = Boolean(job || saved)
  const cloudSource = environment.kind === "cloud"
  const direct = cloudSource && destination === "cloud" && source.provider === target.provider && source.account === target.account && source.region === target.region && source.resourceGroup === target.resourceGroup
  const supported = cloudSource || environment.kind === "fullVm" && environment.provider === "qemu"
  const sourceReady = !cloudSource || inspected
  const editSource = (key: keyof CloudCopyLocation, value: string) => { setSource(current => ({ ...current, [key]:value })); setInspected(false); setReviewed(false) }
  const editTarget = (key: keyof CloudDeployRequest, value: string) => { setTarget(current => ({ ...current, [key]:value })); setReviewed(false) }
  const perform = async (action: () => Promise<unknown>) => {
    if (guard.current) return
    guard.current = true; setBusy(true); setError("")
    try { await action() } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { guard.current = false; setBusy(false) }
  }
  useEffect(() => {
    if (!busy) return
    const timer = window.setInterval(() => void refreshPlatform().catch(() => undefined), 2000)
    return () => window.clearInterval(timer)
  }, [busy, refreshPlatform])
  const submit = () => perform(async () => {
    const request: DuplicationRequest = saved?.request ?? job?.request ?? { operationId, environmentId:environment.id, name, destination, source:cloudSource ? source : null, target:destination === "cloud" ? target : null, targetBucket, storageDrive:drive || null, reviewed }
    await duplicateEnvironment(request)
    if (alive.current) onClose()
  })
  const targetFields: [keyof CloudDeployRequest, string, string?][] = [["account", accountLabel(target.provider)], ["region", target.provider === "google" ? "Zone" : "Region"], ["machineType", "Machine size"], ["subnet", "Existing subnet"], ["username", "SSH username", "User already installed in the copied OS"]]
  if (target.provider === "azure") targetFields.push(["resourceGroup", "Resource group"], ["securityGroup", "Network security group"])
  if (target.provider === "aws") targetFields.push(["securityGroup", "Security group ID"], ["keyPair", "SSH key pair name"])
  return <Dialog open onOpenChange={open => { if (!open) onClose() }}>
    <DialogPopup className="w-[min(72rem,calc(100vw-2rem))] max-w-none">
      <DialogHeader><DialogTitle>Duplicate environment</DialogTitle><DialogDescription>{environment.name} → {destination === "cloud" ? "New cloud VM" : "Local VM"}</DialogDescription></DialogHeader>
      <form className="contents" onSubmit={event => { event.preventDefault(); void submit() }}>
        <DialogPanel className="space-y-4">
          <fieldset disabled={busy || frozen} className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2"><Field label="Name" value={name} onChange={setName} />
              {state ? <label className="space-y-1 text-xs">{destination === "local" ? "Storage drive" : "Transfer drive"}<select aria-label={destination === "local" ? "Storage drive" : "Transfer drive"} className="block h-9 w-full rounded-md border bg-background px-2" value={drive} onChange={event => setDrive(event.target.value)}><option value="">Default drive</option>{storageDrives(state.host).filter(item => item.path).map(item => <option key={item.path} value={item.path} disabled={item.readOnly}>{driveLabel(item.path)} · {item.freeGb.toFixed(1)} GB free</option>)}</select></label> : null}
            </div>
            <div className={`grid gap-5 ${cloudSource && destination === "cloud" ? "md:grid-cols-2" : ""}`}>
              {cloudSource ? <section aria-label="Source cloud VM" className="space-y-3 rounded-lg border p-4">
                <div className="flex items-center justify-between gap-2"><h3 className="text-sm font-medium">Source VM</h3><ConfigurationHelp label="Source VM help">Check the source before stopping it to record its provider identity. Then stop the VM at the provider and check again. Disconnecting SSH does not stop it.</ConfigurationHelp></div>
                <ProviderChoice label="Source provider" value={source.provider} onChange={value => editSource("provider", value)} />
                <div className="grid gap-3 sm:grid-cols-2">
                  <Field label={`Source ${accountLabel(source.provider)}`} value={source.account} onChange={value => editSource("account", value)} />
                  <Field label={source.provider === "google" ? "Source zone" : "Source region"} value={source.region} onChange={value => editSource("region", value)} />
                  <Field label={source.provider === "aws" ? "Instance ID" : "VM name"} value={source.instance} onChange={value => editSource("instance", value)} />
                  {source.provider === "azure" ? <Field label="Source resource group" value={source.resourceGroup} onChange={value => editSource("resourceGroup", value)} /> : null}
                  {!direct && source.provider !== "azure" ? <Field label="Source transfer bucket" value={source.bucket} onChange={value => editSource("bucket", value)} placeholder="Existing private bucket" /> : null}
                </div>
                <div className="flex flex-wrap gap-2"><Button type="button" size="sm" variant="ghost" disabled={!source.account} onClick={() => void perform(() => cloudApi.authenticate(source.provider, source.account))}>Sign in</Button><Button type="button" size="sm" variant="outline" onClick={() => void perform(async () => { try { const result = await duplicationApi.inspectSource(environment.id, source); if (destination === "local" && result.bootMode !== "uefi") throw new Error("Prepare a UEFI-bootable source image before copying this BIOS-only VM locally."); setInspected(true) } finally { await refreshPlatform().catch(() => undefined) } })}>{inspected ? "Source verified" : "Check source"}</Button></div>
              </section> : null}
              {destination === "cloud" ? <section aria-label="Destination cloud VM" className="space-y-3 rounded-lg border p-4">
                <div className="flex items-center justify-between gap-2"><h3 className="text-sm font-medium">Destination VM</h3><ConfigurationHelp label="Destination VM help">The copied disk supplies the OS and installed software. Existing network rules are preserved. Azure uses a private IP. The cloud provider may adapt boot drivers during image import.</ConfigurationHelp></div>
                <ProviderChoice label="Destination provider" value={target.provider} onChange={value => editTarget("provider", value)} />
                <div className="grid gap-3 sm:grid-cols-2">{targetFields.map(([key, label, placeholder]) => <Field key={key} label={label} value={target[key]} onChange={value => editTarget(key, value)} placeholder={placeholder} />)}
                  {!direct && target.provider !== "azure" ? <Field label="Destination transfer bucket" value={targetBucket} onChange={value => { setTargetBucket(value); setReviewed(false) }} placeholder="Existing private bucket" /> : null}
                </div>
                {target.provider === "google" ? <label className="block space-y-1 text-xs">SSH public key<textarea className="h-16 w-full resize-y rounded-md border bg-background p-2 font-mono text-xs" value={target.sshPublicKey} onChange={event => editTarget("sshPublicKey", event.target.value)} /></label> : null}
                <Button type="button" size="sm" variant="ghost" disabled={!target.account} onClick={() => void perform(() => cloudApi.authenticate(target.provider, target.account))}>Sign in to destination</Button>
              </section> : null}
            </div>
            <CloudDeploymentWarning /><label className="flex items-start gap-2 text-xs"><Checkbox checked={reviewed} onCheckedChange={value => setReviewed(value === true)} /><span>{cloudRiskAcknowledgement}</span></label>
          </fieldset>
          {!supported ? <p role="status" className="text-sm text-muted-foreground">This is a {environment.kind === "microVm" ? "microVM" : "container"}, not a bootable cloud VM disk. It can be duplicated locally. Cloud conversion would need a separate runtime migration to preserve its behavior.</p> : !cloudSource && environment.status !== "stopped" ? <p role="status" className="text-sm text-muted-foreground">Stop the source environment before duplicating its disk.</p> : null}
          <p className="text-xs text-muted-foreground">Copies the complete boot disk, including installed apps and files. External services, shared folders and attached data disks are not silently substituted. Cloud copies require Linux and a compatible CPU architecture.</p>
          {job ? <div className="space-y-2 text-xs"><p role="status">{job.phase}{busy ? "…" : ""}</p>{job.resources.length ? <details><summary>Copy resources</summary><p className="mt-2 text-muted-foreground">These resources belong to this copy. Images and transfer files can incur charges until removed.</p><ul className="mt-2 space-y-1">{job.resources.map(resource => <li className="break-all" key={resource}>{resource}</li>)}</ul></details> : null}</div> : null}
          {error || job?.error ? <p role="alert" className="whitespace-pre-wrap text-sm text-destructive-foreground">{error || job?.error}</p> : null}
        </DialogPanel>
        <DialogFooter><Button type="button" variant="ghost" onClick={onClose}>{busy ? "Run in background" : "Cancel"}</Button><Button type="submit" loading={busy} disabled={busy || !supported || !sourceReady || !reviewed || !name.trim() || !cloudSource && environment.status !== "stopped"}>{frozen ? "Resume copy" : "Duplicate"}</Button></DialogFooter>
      </form>
    </DialogPopup>
  </Dialog>
}
