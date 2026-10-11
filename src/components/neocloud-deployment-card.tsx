import { useState } from "react"
import providers from "@/lib/neocloud-providers.json"
import { neocloudApi } from "@/api/neocloud-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { CloudEnvironmentDialog } from "@/components/dialogs/cloud-environment-dialog"
import { ExternalLink } from "@/components/shared/external-link"

function sshDefaults(hint: string, address: string) {
  const userHost = hint.match(/([a-zA-Z0-9_-]+)@([a-zA-Z0-9.-]+)/)
  const port = hint.match(/(?:^|\s)-p\s+(\d+)/) ?? hint.match(/@[^\s:]+:(\d+)/)
  const identity = hint.match(/(?:^|\s)-i\s+(?:"([^"]+)"|'([^']+)'|([^\s]+))/)
  return { host: userHost?.[2] || address, username: userHost?.[1] || "root", port: port ? Number(port[1]) : 22, identityFile: identity?.[1] || identity?.[2] || identity?.[3] || "" }
}

export function NeocloudDeploymentCard({ environmentId }: { environmentId: string }) {
  const { state, refreshPlatform } = usePlatform()
  const deployment = state?.neocloudDeployments?.[environmentId]
  const environment = state?.environments.find(item => item.id === environmentId)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const [confirmation, setConfirmation] = useState("")
  const [recoveryId, setRecoveryId] = useState("")
  const [configure, setConfigure] = useState(false)
  if (!deployment || !environment) return null
  const perform = async (action: "inspect" | "start" | "stop" | "delete") => {
    if (busy) return
    setBusy(true); setError("")
    try { await neocloudApi.action(environmentId, action, action === "delete" ? confirmation : undefined); await refreshPlatform() }
    catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)); await refreshPlatform().catch(() => undefined) }
    finally { setBusy(false) }
  }
  const provider = providers.find(p => p.id === deployment.provider)
  const canStop = provider?.canStop !== false
  const active = deployment.state !== "Deleted"
  const serverless = deployment.product === "serverless"
  const pending = /requested|pending|creating/i.test(deployment.state)
  const stopped = /^(stopped|exited|paused|shutoff)$/i.test(deployment.state)
  const running = /^(running|active)$/i.test(deployment.state)
  return <section aria-label="Neocloud compute" className="rounded-lg border bg-card p-4 text-sm space-y-3">
    <div className="flex flex-wrap items-center justify-between gap-2"><div><h3 className="font-semibold">{provider?.name || deployment.provider} · {deployment.product.toUpperCase()}</h3><p className="text-xs text-muted-foreground">{deployment.state}</p></div><span className="font-mono text-xs text-muted-foreground">{deployment.resourceId || "ID pending"}</span></div>
    <p className="break-all text-xs text-muted-foreground">{deployment.image}{deployment.offer ? ` · ${deployment.offer}` : ""}{deployment.location ? ` · ${deployment.location}` : ""}</p>
    {deployment.sshHint ? <p className="break-all font-mono text-xs text-muted-foreground">{deployment.sshHint}</p> : null}
    {serverless && deployment.address ? <ExternalLink className="break-all text-xs underline" href={deployment.address} onError={setError}>Model API · {deployment.address}</ExternalLink> : null}
    {!deployment.resourceId ? <div className="space-y-2 rounded-md border p-2"><p className="text-xs text-muted-foreground">If the provider created a resource but its ID did not reach Yougori, find the ID in your provider account and attach it here. Yougori verifies it before enabling controls.</p><div className="flex gap-2"><Input aria-label="Existing provider resource ID" value={recoveryId} onChange={event => setRecoveryId(event.target.value)} /><Button size="xs" variant="outline" disabled={busy || !recoveryId.trim()} onClick={() => { setBusy(true); setError(""); void neocloudApi.recoverId(environmentId, recoveryId.trim()).then(() => refreshPlatform()).catch(reason => setError(String(reason))).finally(() => setBusy(false)) }}>Verify ID</Button></div></div> : null}
    <div className="flex flex-wrap gap-2"><Button size="xs" variant="outline" disabled={busy || !active || !deployment.resourceId} onClick={() => void perform("inspect")}>Refresh state</Button>{canStop && <><Button size="xs" variant="outline" disabled={busy || !active || pending || running || (serverless ? !stopped || Boolean(deployment.resourceId) : !deployment.resourceId)} onClick={() => void perform("start")}>{serverless ? "Create endpoint" : "Start compute"}</Button><Button size="xs" variant="outline" disabled={busy || !active || pending || !deployment.resourceId || stopped} onClick={() => void perform("stop")}>{serverless ? "Stop & remove endpoint" : deployment.provider === "civo" ? "Power off (still billed)" : "Stop compute"}</Button></>}{!serverless ? <Button size="xs" variant="outline" disabled={busy || !active} onClick={() => setConfigure(true)}>Configure SSH & files</Button> : null}</div>
    <p className="text-xs text-muted-foreground">{serverless ? `Stopping deletes this endpoint at ${deployment.provider === "runpod" ? "RunPod" : "JarvisLabs"}; Start creates a new one and its URL may change. It has no SSH terminal or guest files. Check provider billing for storage and request charges.` : <>{canStop ? "Start and Stop call the provider CLI." : "This provider supports deletion, not reversible stop/start."} SSH Connect only opens your session. {deployment.provider === "civo" ? "Civo continues billing stopped instances; delete the resource to end instance charges." : "Stopping compute may leave disk and other charges active."} Yougori does not delete the provider resource when the app closes.</>}</p>
    {active ? <details className="text-xs"><summary className="cursor-pointer">Delete provider resource</summary><p className="my-2 text-muted-foreground">{serverless && stopped ? "This removes the saved Yougori endpoint configuration." : "This permanently deletes the remote compute resource and its provider-managed data. Yougori keeps this node until the provider confirms deletion."} Type {deployment.name} to confirm.</p><div className="flex gap-2"><Input aria-label="Resource name to delete" value={confirmation} onChange={event => setConfirmation(event.target.value)} /><Button size="xs" variant="destructive" disabled={busy || pending || confirmation !== deployment.name || (!deployment.resourceId && !(serverless && stopped))} onClick={() => void perform("delete")}>Delete</Button></div></details> : <p className="text-xs">Provider resource deleted. You can remove this node.</p>}
    {error || deployment.lastError ? <p role="alert" className="max-h-28 overflow-y-auto break-words whitespace-pre-wrap text-xs text-destructive">{error || deployment.lastError}</p> : null}
    {configure ? <CloudEnvironmentDialog key={environmentId} open={configure} onOpenChange={value => { setConfigure(value); if (!value) void refreshPlatform() }} environmentId={environmentId} initialProfile={{ name: environment.name, vendor: "other", ...sshDefaults(deployment.sshHint, deployment.address) }} /> : null}
  </section>
}
