import { useEffect, useRef, useState, type Dispatch, type ReactNode, type SetStateAction } from "react"
import { workspaceApi, type SavedCloudflareAccount } from "@/api/workspace-api"
import { savedCloudflareDraft, type CloudflareDraft } from "@/lib/cloudflare-account"
import { cloudflareTokenInput } from "@/lib/cloudflare-token"
import type { PublicAccessPreset } from "@/lib/public-access-presets"
import { Address, Slot } from "@/components/popup-kit"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Radio, RadioGroup } from "@/components/ui/radio-group"

/** The address a quick link gets: Cloudflare picks the words when the link turns on. */
export function QuickLinkAddress() {
  return <Address>https://<Slot>random-words</Slot>.trycloudflare.com</Address>
}

const card = (picked: boolean, disabled = false) =>
  `flex min-w-0 cursor-pointer items-start gap-3 rounded-xl border p-3 text-sm ${picked ? "border-primary bg-primary/5" : "bg-card hover:border-primary/40"}${disabled ? " cursor-not-allowed opacity-50" : ""}`

function Step({ number, title, children }: { number: number; title: string; children: ReactNode }) {
  return <li className="grid grid-cols-[1.5rem_minmax(0,1fr)] gap-x-2 gap-y-2">
    <span aria-hidden="true" className="mt-px flex size-5 items-center justify-center rounded-full border text-[11px] font-medium text-muted-foreground">{number}</span>
    <div className="min-w-0 space-y-2"><p className="text-sm font-medium">{title}</p>{children}</div>
  </li>
}

/** How a public link is made: Cloudflare's free quick tunnel, the person's own Cloudflare tunnel
 *  and domain, or a domain already saved under Public access setups. Each choice says it is
 *  Cloudflare and shows the address people will open before anything is turned on. */
export function CloudflareAccountFields({ environmentId, port, value, onChange, onLoadingChange, busy, perform, refreshKey, compact = false, presets = [], selectedPresetId = null, onSelectPreset, anyPresetPort = false }: {
  environmentId: string; port: number; value: CloudflareDraft; onChange: Dispatch<SetStateAction<CloudflareDraft>>; onLoadingChange(loading: boolean): void; busy: boolean; perform(action: () => Promise<unknown>): Promise<void>; refreshKey: string; compact?: boolean; presets?: PublicAccessPreset[]; selectedPresetId?: string | null; onSelectPreset?(id: string | null): void
  /** Saved domains made for another app port can be chosen; the caller passes presetPort when connecting. */
  anyPresetPort?: boolean
}) {
  const [saved, setSaved] = useState<SavedCloudflareAccount | null>(null)
  const [loadError, setLoadError] = useState("")
  const [revision, setRevision] = useState(0)
  const restored = useRef(false)
  useEffect(() => {
    let disposed = false
    onLoadingChange(true)
    void workspaceApi.savedCloudflare(environmentId, port).then(result => {
      if (disposed) return
      const draft = savedCloudflareDraft(result)
      setSaved(result); setLoadError("")
      if (!restored.current) {
        restored.current = true
        if (draft) onChange(current => current.hostname || current.localPort || current.token ? current : draft)
      }
    }).catch(() => { if (!disposed) setLoadError("Could not read saved credentials. You can paste a token for this session or retry.") })
      .finally(() => { if (!disposed) onLoadingChange(false) })
    return () => { disposed = true }
  }, [environmentId, port, revision, onChange, onLoadingChange, refreshKey])
  const origin = /^\d+$/.test(value.localPort) && Number(value.localPort) > 0 && Number(value.localPort) <= 65535 ? `http://127.0.0.1:${Number(value.localPort)}` : "http://127.0.0.1:<local tunnel port>"
  const hostname = value.hostname.trim()
  const preset = selectedPresetId ? presets.find(item => item.id === selectedPresetId) : undefined
  const quick = !selectedPresetId && value.mode === "quick"
  const account = !selectedPresetId && value.mode === "account"
  return <section aria-label="Cloudflare account options" className={compact ? "space-y-3" : "flex flex-col gap-3 rounded-lg border p-3"}>
    <RadioGroup aria-label="Cloudflare account mode" className="grid grid-cols-1 gap-2 sm:grid-cols-2" disabled={busy} value={selectedPresetId ? `preset:${selectedPresetId}` : value.mode} onValueChange={mode => {
      if (mode.startsWith("preset:")) { onSelectPreset?.(mode.slice(7)); return }
      onSelectPreset?.(null)
      onChange(current => ({ ...current, mode: mode === "account" ? "account" : "quick", token: "", routesReviewed: false }))
    }}>
      <Label className={card(quick)}>
        <Radio aria-label="Quick link — no account" aria-description="Cloudflare's free quick tunnel. People open a temporary https://….trycloudflare.com address, new each time the link turns on." value="quick" />
        <span aria-hidden="true" className="min-w-0 space-y-1.5">
          <span className="block font-medium">Quick link — no account</span>
          <span className="block text-xs leading-relaxed text-muted-foreground">Cloudflare's free quick tunnel, ready in one step. The address is new each time the link turns on.</span>
          <span className="block"><QuickLinkAddress /></span>
        </span>
      </Label>
      <Label className={card(account)}>
        <Radio aria-label="Use my Cloudflare account (optional)" aria-description="Your own domain, through a dedicated tunnel on your Cloudflare account. The address stays the same." value="account" />
        <span aria-hidden="true" className="min-w-0 space-y-1.5">
          <span className="block font-medium">Use my Cloudflare account (optional)</span>
          <span className="block text-xs leading-relaxed text-muted-foreground">Your own domain, through a dedicated tunnel on your Cloudflare account. The address stays the same.</span>
          <span className="block">{hostname ? <Address>https://{hostname}</Address> : <span className="popup-quiet">https:// and the hostname you enter</span>}</span>
        </span>
      </Label>
      {presets.length ? <div className="col-span-full space-y-2 pt-1">
        <p className="text-xs font-medium text-muted-foreground">{anyPresetPort ? "Saved domains" : `Saved domains · choose one for app port :${port}`}</p>
        <div className="grid max-h-44 gap-2 overflow-y-auto pr-1 sm:grid-cols-2">{presets.map(item => {
          const otherPort = !anyPresetPort && item.port !== port
          return <Label key={item.id} className={card(selectedPresetId === item.id, otherPort)}>
            <Radio aria-label={anyPresetPort ? `Use ${item.hostname}` : `Use ${item.hostname} for app port ${item.port}`} disabled={otherPort} value={`preset:${item.id}`} />
            <span aria-hidden="true" className="min-w-0 space-y-1 text-xs">
              <Address>https://{item.hostname}</Address>
              <span className="block text-muted-foreground">{anyPresetPort ? `Saved tunnel · local port :${item.hostPort}` : `App port :${item.port} · local port :${item.hostPort}`}{otherPort ? " · made for a different app port" : ""}</span>
            </span>
          </Label>
        })}</div>
      </div> : null}
    </RadioGroup>

    {preset ? <p className="text-xs leading-relaxed text-muted-foreground">People open <Address>https://{preset.hostname}</Address>. It uses the tunnel token saved for this domain, and a saved domain serves one environment at a time.</p>
      : account ? <div className="space-y-3 rounded-xl border p-3">
        <ol className="space-y-4">
          <Step number={1} title="Create a dedicated tunnel in Cloudflare">
            <p className="text-xs leading-relaxed text-muted-foreground">Free and paid Cloudflare accounts both work. Use a tunnel that serves only this app; Yougori never asks for your Cloudflare password.</p>
            <div className="flex flex-wrap gap-2">
              <Button type="button" size="sm" variant="outline" disabled={busy} onClick={() => void perform(() => workspaceApi.openUrl("https://dash.cloudflare.com/"))}>Open Cloudflare dashboard</Button>
              <Button type="button" size="sm" variant="link" disabled={busy} onClick={() => void perform(() => workspaceApi.openUrl("https://developers.cloudflare.com/tunnel/advanced/tunnel-tokens/"))}>Where to get the token</Button>
            </div>
          </Step>
          <Step number={2} title="Choose the address and point the tunnel here">
            <div className="grid gap-3 sm:grid-cols-2">
              <Field><FieldLabel>Public hostname</FieldLabel><Input type="text" placeholder="app.example.com" autoComplete="off" spellCheck={false} maxLength={253} disabled={busy} value={value.hostname} onChange={event => onChange(current => ({ ...current, hostname: event.target.value, routesReviewed: false }))} /><FieldDescription>A domain you manage in Cloudflare.</FieldDescription></Field>
              <Field><FieldLabel>Local tunnel port</FieldLabel><Input type="text" inputMode="numeric" placeholder="45000" maxLength={5} disabled={busy} value={value.localPort} onChange={event => onChange(current => ({ ...current, localPort: event.target.value, routesReviewed: false }))} /><FieldDescription>Any unused port on this PC.</FieldDescription></Field>
            </div>
            <div className="rounded-lg bg-muted/50 p-3 text-xs text-muted-foreground">
              <p>In Cloudflare, open Networking → Tunnels, and set this tunnel's route to the HTTP service URL:</p>
              <code className="mt-1 block break-all font-medium text-foreground" aria-label="Cloudflare service URL">{origin}</code>
            </div>
          </Step>
          <Step number={3} title="Paste the tunnel token">
            <Field><FieldLabel>Tunnel token</FieldLabel><Input type="password" autoComplete="new-password" spellCheck={false} maxLength={4096} placeholder={saved?.saved ? "Saved securely — leave empty to reuse" : "Paste token or Cloudflare command"} disabled={busy} value={value.token} onChange={event => onChange(current => ({ ...current, token: cloudflareTokenInput(event.target.value), routesReviewed: false }))} /><FieldDescription>{saved?.saved ? "A saved token is available for this environment and port. It is never sent back to this form." : "The token or the whole install command; Yougori runs the connector for you."}</FieldDescription></Field>
            <Label className="flex items-center gap-2 text-xs"><Checkbox disabled={busy} checked={value.remember} onCheckedChange={checked => onChange(current => ({ ...current, remember: checked === true }))} />Remember for this node and port</Label>
            <p className="text-xs leading-relaxed text-muted-foreground">Keeps the hostname, local tunnel port and token in this PC's credential vault after connecting, so this port reconnects without setup next time.</p>
            {saved?.saved ? <div className="space-y-1"><Button type="button" size="sm" variant="ghost" className="self-start" disabled={busy} onClick={() => void perform(async () => { await workspaceApi.forgetCloudflare(environmentId, port); setSaved({ saved: false, hostname: "", hostPort: null }); onChange(current => ({ ...current, token: "", remember: false, routesReviewed: false })) })}>{compact ? "Forget token for this node" : "Forget saved token"}</Button>{compact && presets.some(item => item.port === port && item.hostname === value.hostname) ? <p className="text-xs text-muted-foreground">The reusable saved setup has its own copy. Remove it from Saved setups to forget that copy too.</p> : null}</div> : null}
            {loadError ? <div className="flex flex-col gap-1"><p role="alert" className="text-xs text-destructive-foreground">{loadError}</p><Button type="button" size="xs" variant="ghost" disabled={busy} onClick={() => setRevision(current => current + 1)}>Retry credential lookup</Button></div> : null}
          </Step>
          <Step number={4} title="Confirm the tunnel serves only this app">
            <p className="text-xs leading-relaxed text-muted-foreground">Other routes on the same tunnel could expose other services on this PC, and Yougori does not check or change them. Do not run copies of this tunnel pointing at different services.</p>
            <Label className="flex items-start gap-2 text-xs"><Checkbox disabled={busy} checked={value.routesReviewed} onCheckedChange={checked => onChange(current => ({ ...current, routesReviewed: checked === true }))} />I reviewed this dedicated tunnel’s routes</Label>
          </Step>
        </ol>
        <p className="border-t pt-3 text-xs leading-relaxed text-muted-foreground">Account authentication does not make visitors log in; set up Cloudflare Access in your dashboard if they should. Disconnecting stops this connector, and forgetting a saved token does not stop an active connector or revoke the token in Cloudflare.</p>
      </div>
      : <p className="text-xs leading-relaxed text-muted-foreground">No account or setup needed. Cloudflare hands out the exact address when the link turns on, and it changes each time the tunnel restarts.</p>}
  </section>
}
