import { useEffect, useRef, useState } from "react"
import { SharedEnvironmentForm } from "@/components/shared-environment-form"
import { LinkIcon, Share2Icon } from "lucide-react"
import { remoteAccessApi, type RemoteGrant, type RemotePermission, type RemoteShares } from "@/api/remote-access-api"
import { workspaceApi } from "@/api/workspace-api"
import { usePlatform } from "@/context/platform-context"
import { CloudflareAccountFields } from "@/components/cloudflare-account-fields"
import { accountRequest, emptyCloudflareDraft } from "@/lib/cloudflare-account"
import { readPublicAccessPresets } from "@/lib/public-access-presets"
import { rememberPublicAccessPreset } from "@/lib/public-access-preset-actions"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogDescription, DialogHeader, DialogPanel, DialogPopup, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { useTopicWalkthroughModal } from "@/lib/topic-walkthrough"
import "@/components/sharing-panel.css"

// The protected remote gateway always serves this port; saved domains from other ports reuse their own credentials.
const GATEWAY_ID = "remote-access", GATEWAY_PORT = 7445
const labels: Record<RemotePermission, string> = { view: "View Only", edit: "View & Edit Files", control: "Full Control of Shared Target" }
const permissionHelp: Record<RemotePermission, string> = { view: "Read the chosen folder, logs and status.", edit: "Read and change the chosen folder. No commands.", control: "Terminals, commands, installs and start/stop." }
const shortPermission: Record<RemotePermission, string> = { view: "View only", edit: "Edit files", control: "Full control" }
const EXPIRY: [string, string][] = [["1", "1 hour"], ["24", "24 hours"], ["168", "7 days"], ["never", "Never"]]
const statusLabel: Record<RemoteGrant["status"], string> = { online: "Active", offline: "Waiting for link", expired: "Expired", revoked: "Revoked" }

export function SharingPanel({ environmentId, reconnectEnvironmentId, onConnected, compact = false }: { environmentId?: string; reconnectEnvironmentId?: string; onConnected?(): void; compact?: boolean }) {
  const { state } = usePlatform()
  const [open, setOpen] = useState(false), [busy, setBusy] = useState(false), [error, setError] = useState(""), [notice, setNotice] = useState("")
  const topic = useTopicWalkthroughModal(open)
  const lock = useRef(false)
  const [shares, setShares] = useState<RemoteShares | null>(null)
  const [adding, setAdding] = useState(false)
  const [username, setUsername] = useState(""), [password, setPassword] = useState("")
  const [permission, setPermission] = useState<RemotePermission>("view"), [folder, setFolder] = useState(""), [expiry, setExpiry] = useState("24")
  const [pcConfirmed, setPcConfirmed] = useState(false), [accessConfirmed, setAccessConfirmed] = useState(false)
  const [cloudflare, setCloudflare] = useState(emptyCloudflareDraft), [accountLoading, setAccountLoading] = useState(false)
  const [presets, setPresets] = useState(readPublicAccessPresets), [presetId, setPresetId] = useState<string | null>(null)
  const [resetId, setResetId] = useState(""), [resetPassword, setResetPassword] = useState("")
  const pc = environmentId === "my-pc"
  const environment = state?.environments.find(e => e.id === environmentId)
  const targetName = pc ? "My PC" : environment?.name ?? "environment"
  useEffect(() => {
    if (!open || !environmentId) return
    let alive = true; let timer: ReturnType<typeof setTimeout>
    const poll = async () => { try { const result = await remoteAccessApi.list(); if (alive) setShares(result) } catch (e) { if (alive) setError(String(e)) } finally { if (alive) timer = setTimeout(() => void poll(), 4000) } }
    void poll(); return () => { alive = false; clearTimeout(timer) }
  }, [open, environmentId])
  useEffect(() => {
    const refresh = () => setPresets(readPublicAccessPresets())
    window.addEventListener("yougori-public-presets-changed", refresh)
    return () => window.removeEventListener("yougori-public-presets-changed", refresh)
  }, [])
  const perform = async (action: () => Promise<unknown>) => {
    if (lock.current) return
    lock.current = true; setBusy(true); setError(""); setNotice("")
    try { await action(); if (environmentId) setShares(await remoteAccessApi.list()) } catch (e) { setError(e instanceof Error ? e.message : String(e)) } finally { lock.current = false; setBusy(false) }
  }
  const copy = (text: string, message: string) => void perform(async () => { await terminalClipboard.writeText(text); setNotice(message) })
  const resetForm = () => { setUsername(""); setPassword(""); setFolder(""); setPermission("view"); setExpiry("24"); setPcConfirmed(false); setAccessConfirmed(false) }
  const addRecipient = () => void perform(async () => {
    await remoteAccessApi.create({ targetId: environmentId!, username, password, permission, folder: folder.trim() || null, expiresAt: expiry === "never" ? null : Math.floor(Date.now() / 1000) + Number(expiry) * 3600, confirmPcFiles: pcConfirmed, acknowledgeExistingAccess: accessConfirmed })
    resetForm(); setAdding(false)
    setNotice(shares?.url ? "Person added. Copy their invite below." : "Person added. Turn on the link to get their invite.")
  })
  const start = async () => {
    const preset = presetId ? presets.find(item => item.id === presetId) : undefined
    if (presetId && !preset) throw new Error("This saved domain is no longer available")
    const account = preset
      ? { hostPort: preset.hostPort, options: { hostname: preset.hostname, presetId: preset.id, presetSourceEnvironmentId: preset.credentialEnvironmentId, presetPort: preset.port, remember: false, routesReviewed: true } }
      : cloudflare.mode === "account" ? accountRequest(cloudflare) : null
    await remoteAccessApi.start(account?.options, account?.hostPort)
    if (account && !preset && cloudflare.remember) {
      try { await rememberPublicAccessPreset(GATEWAY_ID, GATEWAY_PORT, account.options.hostname, account.hostPort) }
      catch (reason) { setNotice(`Link is on, but the domain could not be added to Saved domains: ${reason instanceof Error ? reason.message : String(reason)}`) }
    }
    setCloudflare(current => ({ ...current, token: "" }))
  }
  const recipients = shares?.grants.filter(g => g.targetId === environmentId) ?? []
  const active = recipients.filter(g => g.status !== "revoked" && g.status !== "expired")
  const ended = recipients.filter(g => g.status === "revoked" || g.status === "expired")
  const online = Boolean(shares?.url)
  const quick = shares?.url?.includes(".trycloudflare.com") ?? false
  const canAdd = Boolean(username.trim()) && password.length >= 8 && !(pc && (!folder || !pcConfirmed)) && !(permission === "edit" && !folder.trim())
  const permissions = (Object.keys(labels) as RemotePermission[]).filter(key => !pc || key !== "control")

  return <Dialog modal={!topic} open={open} onOpenChange={(value, details) => { if (busy || (!value && topic && details.reason === "focus-out") || (details.event.target instanceof Element && details.event.target.closest('[data-topic-ui]'))) return; setOpen(value); if (!value) { setPassword(""); setResetPassword(""); setCloudflare(v => ({ ...v, token: "" })) } }}>
    <DialogTrigger render={<Button className="nodrag" size={compact ? "icon-xs" : "sm"} variant={compact ? "ghost" : "outline"} aria-label={environmentId ? `Share ${targetName} via Tunnel` : "Connect to Shared Environment"} title={environmentId ? "Share via Tunnel" : "Connect to Shared Environment"} />}>
      {environmentId ? <Share2Icon aria-hidden="true" /> : <LinkIcon aria-hidden="true" />}{compact ? null : environmentId ? "Share via Tunnel" : "Connect to Shared Environment"}
    </DialogTrigger>
    <DialogPopup data-instruction="sharing-dialog" className={environmentId ? "share-popup" : "sm:max-w-xl"}>
      <DialogHeader><DialogTitle>{environmentId ? `Share ${targetName}` : reconnectEnvironmentId ? "Reconnect shared environment" : "Connect to a shared environment"}</DialogTitle><DialogDescription>{environmentId ? "Invite people to work here. Files, workloads and compute stay on this machine." : "Use the link and recipient credentials supplied by the owner."}</DialogDescription></DialogHeader>
      <DialogPanel className={environmentId ? "share-panel" : "space-y-5"}>
        {!environmentId ? <SharedEnvironmentForm environmentId={reconnectEnvironmentId} onConnected={onConnected} onBusyChange={setBusy} onClose={() => setOpen(false)} /> : <>
          <div className="share-status" data-online={online || undefined} role="status">
            <span className="share-dot" aria-hidden="true" />
            <div className="share-status-text"><strong>{busy ? "Working…" : online ? "Link is on" : "Link is off"}</strong><span>{online ? `${active.length} ${active.length === 1 ? "person" : "people"} can connect · ${quick ? "Quick link" : "Your domain"}` : "People can't connect until the link is on."}</span></div>
            {online ? <><Button size="xs" variant="outline" disabled={busy} onClick={() => void perform(() => remoteAccessApi.stop())}>Disconnect Remote Users</Button></> : null}
          </div>
          {error ? <p role="alert" className="share-error">{error}</p> : null}
          {notice ? <p role="status" className="share-notice">{notice}</p> : null}

          <div className="share-columns">
          <section className="share-card" aria-label="People">
            <div className="share-card-head">
              <div><h3>People</h3><p>Each person gets their own link and password, which you can revoke at any time.</p></div>
              <div className="share-card-actions">
                {ended.length > 1 ? <Button size="sm" variant="ghost" disabled={busy} onClick={() => void perform(async () => { for (const grant of ended) await remoteAccessApi.remove(grant.id); setNotice(`Removed ${ended.length} people whose access ended.`) })}>Clear ended</Button> : null}
                {adding ? null : <Button size="sm" onClick={() => { setAdding(true); setNotice("") }}>Add person</Button>}
              </div>
            </div>

            {adding ? <form className="share-form" onSubmit={e => { e.preventDefault(); if (canAdd) addRecipient() }}>
              <div className="share-form-row">
                <label>Username<Input required value={username} maxLength={64} autoComplete="off" placeholder="teammate" onChange={e => setUsername(e.target.value)} /></label>
                <label>Share password<Input required type="password" minLength={8} maxLength={256} value={password} autoComplete="new-password" placeholder="8+ characters" onChange={e => setPassword(e.target.value)} /></label>
                <div className="share-expiry"><span>Access ends after</span>
                  <div className="share-segments" role="radiogroup" aria-label="Expires">{EXPIRY.map(([value, label]) => <button key={value} type="button" role="radio" aria-checked={expiry === value} onClick={() => setExpiry(value)}>{label}</button>)}</div>
                </div>
              </div>
              <p className="share-hint">Send the password privately. Yougori only stores a verifier.</p>

              <div className="share-choice" role="radiogroup" aria-label="Permission">
                {permissions.map(key => <button key={key} type="button" role="radio" aria-checked={permission === key} onClick={() => setPermission(key)}><strong>{labels[key]}</strong><span>{permissionHelp[key]}</span></button>)}
              </div>

              <label className="share-folder">{pc ? "PC folder" : "Optional folder to share"}
                <span className="share-folder-input"><Input disabled={environment?.kind === "fullVm"} value={folder} placeholder={pc ? "Choose a project folder" : "/workspace"} onChange={e => { setFolder(e.target.value); setPcConfirmed(false) }} />{pc ? <Button type="button" variant="outline" size="sm" onClick={() => void perform(async () => { const selected = await workspaceApi.chooseFolders(); if (selected[0]) { setFolder(selected[0]); setPcConfirmed(false) } })}>Browse</Button> : null}</span>
              </label>
              {environment?.kind === "fullVm" ? <p className="share-hint">Full Control includes the VM desktop and start/stop. This VM has no file or terminal agent.</p> : environment?.kind === "cloud" ? <p className="share-hint">Files and commands use your SSH connection. Cloud start and stop are unavailable.</p> : null}
              {permission === "edit" && !folder.trim() ? <p className="share-hint">Choose a folder to allow editing.</p> : null}
              {pc ? <>
                <label className="share-check"><input type="checkbox" checked={pcConfirmed} onChange={e => setPcConfirmed(e.target.checked)} />I allow this recipient to access this PC folder.</label>
                <p className="share-hint">The PC desktop, keyboard, mouse and commands are never shared. Protected app and vault storage can't be shared.</p>
              </> : permission === "control" ? <label className="share-check"><input type="checkbox" checked={accessConfirmed} onChange={e => setAccessConfirmed(e.target.checked)} />Allow use of PC folders and node connections already granted to this environment.</label> : null}

              <div className="share-actions"><Button type="button" variant="ghost" size="sm" disabled={busy} onClick={() => { setAdding(false); resetForm() }}>Cancel</Button><Button type="submit" size="sm" loading={busy} disabled={busy || !canAdd}>Add recipient</Button></div>
            </form> : null}

            {recipients.length ? <ul className="share-people">{recipients.map(grant => {
              const isEnded = grant.status === "revoked" || grant.status === "expired"
              return <li key={grant.id} data-ended={isEnded || undefined}>
                <div className="share-person">
                  <div className="share-person-name"><strong>{grant.username}</strong><span className="share-pill" data-status={grant.status}>{statusLabel[grant.status]}</span></div>
                  <p>{shortPermission[grant.permission]}{grant.folder ? ` · ${grant.folder}` : ""}{grant.connectedUsers ? ` · ${grant.connectedUsers} connected` : ""}{grant.expiresAt ? ` · until ${new Date(grant.expiresAt * 1000).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" })}` : " · no expiry"}</p>
                </div>
                {isEnded ? <div className="share-person-actions"><Button size="xs" variant="ghost" className="share-revoke" disabled={busy} onClick={() => void perform(async () => { await remoteAccessApi.remove(grant.id); setNotice(`${grant.username} removed.`) })}>Remove</Button></div> : <div className="share-person-actions">
                  <select aria-label={`Permission for ${grant.username}`} disabled={busy} value={grant.permission} onChange={e => void perform(() => remoteAccessApi.update(grant.id, { permission: e.target.value as RemotePermission }))}>{permissions.map(key => <option key={key} value={key}>{shortPermission[key]}</option>)}</select>
                  <Button size="xs" variant="outline" disabled={!grant.link || grant.status !== "online"} title={grant.link ? undefined : "Turn on the link first"} onClick={() => copy(`Link: ${grant.link}\nUsername: ${grant.username}`, "Invite copied. Send the password separately.")}>Copy invite</Button>
                  <Button size="xs" variant="ghost" disabled={busy} onClick={() => { setResetId(resetId === grant.id ? "" : grant.id); setResetPassword("") }}>Reset password</Button>
                  <Button size="xs" variant="ghost" disabled={busy} onClick={() => void perform(() => remoteAccessApi.update(grant.id))}>Disconnect</Button>
                  <Button size="xs" variant="ghost" className="share-revoke" disabled={busy} onClick={() => void perform(() => remoteAccessApi.update(grant.id, { revoke: true }))}>Revoke</Button>
                </div>}
                {resetId === grant.id ? <form className="share-reset" onSubmit={e => { e.preventDefault(); void perform(async () => { await remoteAccessApi.update(resetId, { password: resetPassword }); setResetId(""); setResetPassword(""); setNotice(`New password saved for ${grant.username}.`) }) }}>
                  <Input aria-label="New recipient password" type="password" required minLength={8} maxLength={256} placeholder="New password, 8+ characters" value={resetPassword} onChange={e => setResetPassword(e.target.value)} />
                  <Button type="submit" size="sm" disabled={busy || resetPassword.length < 8}>Save password</Button><Button type="button" variant="ghost" size="sm" onClick={() => { setResetId(""); setResetPassword("") }}>Cancel</Button>
                </form> : null}
              </li>
            })}</ul> : adding ? null : <p className="share-empty">No one has access yet. Add a person to create their private invite.</p>}
          </section>

          <section className="share-card" aria-label="Link">
            <div className="share-card-head"><div><h3>Link</h3><p>One protected link serves everyone you invite. Keep Yougori open while people are connected.</p></div></div>
            {online ? <div className="share-link-on">
              <span className="model-label">Invite links</span>
              {active.some(grant => grant.link) ? active.filter(grant => grant.link).map(grant => <div key={grant.id} className="share-url">
                <div><strong>{grant.username}</strong><code>{grant.link}</code></div>
                <Button size="xs" variant="ghost" aria-label={`Copy link for ${grant.username}`} onClick={() => copy(grant.link!, `Link for ${grant.username} copied. Send the password separately.`)}>Copy</Button>
              </div>) : <p className="share-hint">Add a person to get their invite link.</p>}
              <p className="share-hint">{quick ? "Quick link. It changes when the link restarts, so re-send invites after turning it back on." : "Your Cloudflare domain. Invites keep working across restarts."}</p>
            </div> : <>
              <CloudflareAccountFields environmentId={GATEWAY_ID} port={GATEWAY_PORT} value={cloudflare} onChange={setCloudflare} onLoadingChange={setAccountLoading} busy={busy} perform={perform} refreshKey={String(open)} compact presets={presets} selectedPresetId={presetId} onSelectPreset={setPresetId} anyPresetPort />
              <div className="share-actions">
                {!active.length ? <span className="share-hint">Add a person first.</span> : null}
                <Button size="sm" disabled={busy || accountLoading || !active.length} loading={busy} onClick={() => void perform(start)}>Enable tunnel</Button>
              </div>
            </>}
            <p className="share-hint">People connect from Yougori with their invite link, username and password. Vault requests still need your separate approval.</p>
          </section>
          </div>

          {shares?.audit.length ? <details className="share-activity"><summary>Recent sharing activity</summary><ul>{shares.audit.filter(a => !a.shareId || recipients.some(g => g.id === a.shareId)).slice(-30).reverse().map((a, i) => <li key={i}><time>{new Date(a.at * 1000).toLocaleTimeString()}</time>{a.event}{a.success ? "" : " · refused"}</li>)}</ul></details> : null}
        </>}
        {!environmentId && notice ? <p role="status" className="text-xs text-muted-foreground">{notice}</p> : null}{!environmentId && error ? <p role="alert" className="text-sm text-destructive-foreground">{error}</p> : null}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
