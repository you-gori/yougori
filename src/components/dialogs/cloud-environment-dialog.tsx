import { useRef, useState } from "react"
import { cloudApi, type CloudProfile } from "@/api/cloud-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Dialog, DialogPopup, DialogHeader, DialogTitle, DialogDescription, DialogPanel, DialogFooter } from "@/components/ui/dialog"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { useCloudProfileDraft } from "@/lib/cloud-profile-draft"
import { parseSshCommand } from "@/lib/ssh-command"

type Vendor = CloudProfile["vendor"]
const defaultUser: Record<Vendor, string> = { aws: "ec2-user", google: "", azure: "azureuser", other: "" }
// The default SSH user of common EC2 images (AWS "Connect to your Linux instance").
const ec2Users = [["Amazon Linux", "ec2-user"], ["Ubuntu", "ubuntu"], ["Debian", "admin"], ["RHEL / SUSE", "ec2-user"], ["CentOS", "centos"], ["Fedora", "fedora"]] as const

export function CloudEnvironmentDialog({ open, onOpenChange, environmentId, initialProfile, embedded = false, onBusyChange }: { embedded?: boolean; onBusyChange?(busy: boolean): void; open: boolean; onOpenChange(open: boolean): void; environmentId?:string; initialProfile?:Partial<CloudProfile> }) {
  const { addCloudEnvironment,configureCloudEnvironment } = usePlatform()
  const { profile, setProfile, reset } = useCloudProfileDraft(environmentId, initialProfile)
  const [verified, setVerified] = useState("")
  const [busy, setBusy] = useState<"connect" | "save" | "browse" | null>(null)
  const [error, setError] = useState("")
  const [command, setCommand] = useState("")
  const [keyHint, setKeyHint] = useState("")
  const guard = useRef(false)
  const aws = profile.vendor === "aws"
  const signature = JSON.stringify(profile)
  const connected = verified === signature
  const edit = (change: Partial<CloudProfile>) => {
    const next = { ...profile, ...change }
    if (next.host !== profile.host || next.port !== profile.port) next.hostKey = ""
    // Swap an untouched default user when the provider changes.
    if (change.vendor && change.vendor !== profile.vendor && profile.username === defaultUser[profile.vendor]) next.username = defaultUser[change.vendor]
    setProfile(next)
    setError("")
  }
  const perform = async (action: NonNullable<typeof busy>, operation: () => Promise<void>) => {
    if (guard.current) return
    guard.current = true; onBusyChange?.(true); setBusy(action); setError("")
    try { await operation() }
    catch (e) { setError(String(e instanceof Error ? e.message : e)) }
    finally { guard.current = false; setBusy(null); onBusyChange?.(false) }
  }
  const connect = () => {
    void perform("connect", async () => {
      setVerified("")
      const checked = await cloudApi.testConnection(profile, environmentId)
      setProfile({ ...profile, hostKey: checked.hostKey })
      setVerified(JSON.stringify(checked))
    })
  }
  const save = () => {
    if (!connected) return
    void perform("save", async () => {
      if (environmentId) await configureCloudEnvironment(environmentId, profile)
      else await addCloudEnvironment(profile)
      setVerified("")
      reset()
      onOpenChange(false)
    })
  }
  const pasteCommand = (text: string) => {
    setCommand(text)
    const parsed = parseSshCommand(text)
    if (!parsed) return
    const absoluteKey = parsed.key && /^([a-z]:[\\/]|\/|~)/i.test(parsed.key) ? parsed.key : ""
    edit({ host: parsed.host, ...(parsed.username ? { username: parsed.username } : {}), ...(parsed.port ? { port: parsed.port } : {}), ...(absoluteKey ? { identityFile: absoluteKey } : {}) })
    setKeyHint(parsed.key && !absoluteKey ? `Now choose ${parsed.key.split(/[\\/]/).pop()} with Browse.` : "")
  }
  const content = <>
      {embedded ? <p className="px-6 pt-4 text-sm text-muted-foreground">Connect an existing Linux server over SSH. Its power stays under your control.</p> : <DialogHeader><DialogTitle className="text-base">Cloud environment</DialogTitle><DialogDescription>Connect an existing Linux server over SSH. Its power stays under your control.</DialogDescription></DialogHeader>}
      <form className="contents" onSubmit={e => { e.preventDefault(); connect() }}>
        <DialogPanel className="space-y-5">
          <fieldset disabled={Boolean(busy)} className="space-y-5">
            <div className="flex flex-wrap gap-1.5" role="group" aria-label="Cloud provider">{([['aws', 'AWS EC2'], ['google', 'Google Compute Engine'], ['azure', 'Azure VM'], ['other', 'Other server']] as const).map(([value, label]) => <Button key={value} type="button" size="sm" variant={profile.vendor === value ? "default" : "outline"} aria-pressed={profile.vendor === value} onClick={() => edit({ vendor: value })}>{label}</Button>)}</div>
            {aws ? <div className="space-y-3 rounded-xl border bg-muted/40 p-4">
              <div>
                <p className="text-sm font-medium">Connect to your EC2 instance</p>
                <p className="mt-1 text-xs leading-relaxed text-muted-foreground">In the EC2 console open <strong className="font-medium text-foreground">Instances → your instance → Connect → SSH client</strong>. Paste its example command here, or fill the fields below.</p>
              </div>
              <Label className="grid gap-2">SSH command from AWS (optional)<Input value={command} onChange={e => pasteCommand(e.target.value)} placeholder={'ssh -i "my-key.pem" ec2-user@ec2-203-0-113-25.compute-1.amazonaws.com'} spellCheck={false} autoComplete="off" className="font-mono" /></Label>
              {command && !parseSshCommand(command) ? <p className="text-xs text-muted-foreground">Paste the whole command, starting with ssh.</p> : null}
            </div> : null}
            <div className="grid gap-4 sm:grid-cols-2">
              <Label className="grid gap-2">Node name<Input autoFocus required value={profile.name} onChange={e => edit({ name: e.target.value })} placeholder={aws ? "My EC2 server" : "Production database"} /></Label>
              <Label className="grid gap-2">Server address<Input required value={profile.host} onChange={e => edit({ host: e.target.value })} placeholder={aws ? "Public IPv4 address or public DNS" : "IP address or hostname"} spellCheck={false} /></Label>
              <div className="grid content-start gap-2">
                <Label className="grid gap-2">SSH username<Input required value={profile.username} onChange={e => edit({ username: e.target.value })} autoComplete="off" spellCheck={false} /></Label>
                {aws ? <div className="flex flex-wrap gap-1" role="group" aria-label="Username for your instance image">{ec2Users.map(([image, user]) => <Button key={image} type="button" size="xs" variant={profile.username === user ? "secondary" : "ghost"} onClick={() => edit({ username: user })}>{image} · {user}</Button>)}</div> : null}
              </div>
              <Label className="grid content-start gap-2">SSH port<Input required type="number" min={1} max={65535} value={profile.port || ""} onChange={e => edit({ port: Number(e.target.value) })} /></Label>
            </div>
            <div className="space-y-2">
              <Label htmlFor="cloud-identity">{aws ? "SSH identity file (.pem key pair)" : "SSH identity file or public key"}</Label>
              <div className="flex gap-2"><Input id="cloud-identity" required value={profile.identityFile} onChange={e => { edit({ identityFile: e.target.value }); setKeyHint("") }} placeholder={aws ? "The .pem file you downloaded when you created the key pair" : "Choose a key file or paste an SSH public key"} spellCheck={false} /><Button type="button" variant="outline" onClick={() => void perform("browse", async () => { const path = await cloudApi.selectKey(aws); if (path) { edit({ identityFile: path }); setKeyHint("") } })}>Browse</Button></div>
              {keyHint ? <p role="status" className="text-xs font-medium text-foreground">{keyHint}</p> : null}
              <p className="text-xs text-muted-foreground">{aws ? "The instance's security group must allow inbound SSH (TCP 22) from your IP. Amazon Linux and Ubuntu include the OpenSSH server and Python 3 that Yougori needs." : "Pasted public keys use the matching private key in this PC’s SSH agent. Otherwise, browse for your private key file. Requires OpenSSH and Python 3 on the server."}</p>
            </div>
          </fieldset>
          <p className="text-xs leading-relaxed text-muted-foreground">Private connections to your local nodes and selected shared data only. Local network and Public access are unavailable for cloud nodes. Nothing is installed as a background service.</p>
          {connected ? <p role="status" className="text-sm text-emerald-600 dark:text-emerald-400">Connection successful</p> : null}
          {error ? <p role="alert" className="text-sm text-destructive whitespace-pre-wrap">{error}</p> : null}
        </DialogPanel>
        <DialogFooter>
          <Button disabled={Boolean(busy)} type="button" variant="outline" onClick={() => onOpenChange(false)}>Cancel</Button>
          <Button type="submit" variant={connected ? "outline" : "default"} disabled={Boolean(busy)} loading={busy === "connect"}>Connect</Button>
          <Button type="button" disabled={Boolean(busy) || !connected} loading={busy === "save"} onClick={save}>{environmentId ? "Save SSH access" : "Add cloud node"}</Button>
        </DialogFooter>
      </form>
    </>
  return embedded ? content : <Dialog open={open} onOpenChange={value => { if (!busy) onOpenChange(value) }}>
    <DialogPopup className="w-[min(880px,calc(100vw-2rem))] max-w-none" closeProps={{ disabled: Boolean(busy) }}>{content}</DialogPopup>
  </Dialog>
}
