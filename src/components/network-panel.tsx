import { marketApi, type NetworkShare } from "@/api/market-api"
import { workspaceApi } from "@/api/workspace-api"
import { useNetwork } from "@/components/use-network"
import { useState } from "react"
import { ConfidentialNetworkChat } from "@/components/confidential-network-chat"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogDescription, DialogFooter, DialogHeader, DialogPanel, DialogPopup, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import "@/components/network-panel.css"

type Network = ReturnType<typeof useNetwork>
const privacyNotice = "Neo Grid prompts and replies are visible to the provider and Yougori gateway during inference. They are not saved in gateway transcripts. Recording is off by default. Free providers can enable --listen to save prompts and replies; current GPUs do not enforce host privacy."
const money = (value: number) => `$${(value / 1e6).toFixed(2)}`
const uptime = (seconds: number) => `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`

export function NetworkAccount({ network }: { network: Network }) {
  const { status, busy, perform } = network
  const website = status?.website ?? "https://yougori.com"
  return <section className="network-card" aria-label="Neo Grid account">
    {status?.signedIn && status.account ? <>
      <div className="network-card-head">
        <div className="network-identity"><strong>{status.account.email}</strong><span>{status.account.wallet ?? "No wallet connected"}</span></div>
        <div className="network-actions"><Button size="sm" variant="outline" disabled={busy} onClick={() => void perform(() => workspaceApi.openUrl(`${website}/account`))}>Manage account</Button><Button size="sm" variant="ghost" disabled={busy} onClick={() => void perform(marketApi.signOut)}>Sign out</Button></div>
      </div>
      <dl className="network-balances">
        <div><dt>Credit</dt><dd>{money(status.account.creditMicros)}</dd></div>
        <div><dt>Earnings</dt><dd>{money(status.account.earningsMicros)}</dd></div>
        <div><dt>Available</dt><dd>{money(status.account.availableMicros)}</dd></div>
      </dl>
    </> : <>
      <div className="network-card-head">
        <div className="network-identity"><strong>Not signed in</strong><span>Sign in or create a free account with your wallet. One approval signs in both the app and CLI. No transaction is sent.</span></div>
        <Button size="sm" disabled={busy || Boolean(status?.login && !status.login.error && status.login.expiresIn > 0)} onClick={() => void perform(marketApi.signIn)}>Sign in</Button>
      </div>
      {status?.login ? <div className="network-login" role="status">
        <div className="network-login-code"><span>Approve code</span><strong>{status.login.userCode}</strong></div>
        <div className="network-identity"><span>{status.login.verificationUrl}</span><span>{status.login.error ?? (status.login.expiresIn > 0 ? "Waiting for browser approval…" : "Code expired. Sign in again.")}</span></div>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void perform(() => workspaceApi.openUrl(status.login!.verificationUrlComplete || status.login!.verificationUrl))}>Open browser</Button>
      </div> : null}
    </>}
  </section>
}

function PrivacyNotice({ network }: { network: Network }) {
  return <div className="network-notice">
    <p>{privacyNotice}</p>
    <Button size="sm" variant="ghost" onClick={() => void network.perform(() => workspaceApi.openUrl(`${network.status?.website ?? "https://yougori.com"}/privacy`))}>Security and privacy</Button>
  </div>
}

export function NetworkShareDetails({ share, network }: { share: NetworkShare; network: Network }) {
  const node = share.node
  return <article className="network-card" aria-label={`Sharing ${share.model}`}>
    <div className="network-card-head">
      <div className="network-identity"><strong>{share.model}</strong>
        <span className="network-chips"><span className="network-chip" data-live={share.live || undefined}>{share.live ? "Live" : share.status}</span><span className="network-chip">{share.mode === "free" ? "Free for everyone" : "Paid"}</span></span>
      </div>
      <div className="network-actions">
        {share.listing ? <Button size="sm" variant="outline" onClick={() => void network.perform(() => workspaceApi.openUrl(share.listing!))}>View provider</Button> : null}
        <Button size="sm" variant="outline" disabled={network.busy} onClick={() => void network.perform(() => marketApi.unshare(share.environmentId))}>Stop sharing</Button>
      </div>
    </div>
    {share.message ? <p className="network-message" role="status">{share.message}</p> : null}
    {share.warnings.map(warning => <p className="network-warning" key={warning}>{warning}</p>)}
    {node ? <dl className="network-stats">
      <div><dt>GPU</dt><dd>{node.gpu ?? "Waiting for GPU details"}</dd></div>
      <div><dt>Price / 1M tokens</dt><dd>{node.price ? `$${node.price.input} input / $${node.price.output} output` : "Free"}</dd></div>
      <div><dt>Speed</dt><dd>{node.tps == null ? "Connection test pending" : `${node.tps.toFixed(1)} ${node.speedMetric === "input_tokens" ? "input " : ""}tokens/s · ${node.tpsSource === "window" ? "last 15 min" : node.tpsSource === "benchmark" ? "connection benchmark" : "all-time average"}`}</dd></div>
      {node.quant ? <div><dt>Precision</dt><dd>{node.quant} · separate Neo Grid model</dd></div> : null}
      <div><dt>Uptime today / week</dt><dd>{uptime(node.uptimeTodaySeconds)} / {uptime(node.uptimeWeekSeconds)}</dd></div>
      <div><dt>Availability (7 days)</dt><dd>{node.availability == null ? "Waiting for checks" : `${node.availability}%`}</dd></div>
      <div><dt>Tokens input / output</dt><dd>{node.tokensIn.toLocaleString()} / {node.tokensOut.toLocaleString()}</dd></div>
      <div><dt>Earned</dt><dd>{money(node.earnedMicros)}</dd></div>
    </dl> : null}
  </article>
}

export function ModelNetworkPanel({ environmentId }: { environmentId: string }) {
  const network = useNetwork()
  const share = network.status?.shares.find(item => item.environmentId === environmentId)
  return <section className="network-panel" aria-label="Model Neo Grid sharing">
    {network.error ? <p className="network-error" role="alert">{network.error}</p> : null}
    <NetworkAccount network={network} />
    {share ? <NetworkShareDetails share={share} network={network} /> : null}
    <section className="network-card" aria-label="Sharing mode">
      <div className="network-card-head">
        <div className="network-identity"><strong>{share ? "Sharing mode" : "This model is not shared."}</strong><span>Paid sharing uses the Neo Grid price for its ten priced models; other models are shared free. Free models can be used without an account or wallet.</span></div>
        <div className="network-actions">
          <Button size="sm" disabled={!network.status?.signedIn || network.busy} onClick={() => void network.perform(() => marketApi.share(environmentId, "paid"))}>Share paid</Button>
          <Button size="sm" variant="outline" disabled={!network.status?.signedIn || network.busy} onClick={() => void network.perform(() => marketApi.share(environmentId, "free"))}>Share free</Button>
        </div>
      </div>
    </section>
    <PrivacyNotice network={network} />
  </section>
}

export function NetworkPanel() {
  const [open, setOpen] = useState(false)
  const network = useNetwork(open)
  const shares = network.status?.shares ?? []
  return <Dialog open={open} onOpenChange={setOpen}>
    <DialogTrigger render={<Button size="sm" variant="outline" className="dashboard-action" />}>Neo Grid</DialogTrigger>
    <DialogPopup className="network-popup">
      <DialogHeader className="network-header">
        <DialogTitle>Neo Grid</DialogTitle>
        <DialogDescription>Share models through the Yougori endpoint and manage your account.</DialogDescription>
      </DialogHeader>
      <DialogPanel className="network-panel">
        {network.error ? <p className="network-error" role="alert">{network.error}</p> : null}
        <NetworkAccount network={network} />
        <section className="network-section" aria-label="Shared models">
          <h3>Shared models{shares.length ? <span>{shares.length}</span> : null}</h3>
          {shares.length ? shares.map(share => <NetworkShareDetails key={share.environmentId} share={share} network={network} />) : <p className="network-empty">No shared models yet. Choose Paid or Free when running a Hugging Face model.</p>}
        </section>
        <ConfidentialNetworkChat />
        <PrivacyNotice network={network} />
      </DialogPanel>
      <DialogFooter className="network-footer sm:justify-between">
        <Button variant="outline" onClick={() => void network.perform(() => workspaceApi.openUrl(`${network.status?.website ?? "https://yougori.com"}/network`))}>Browse models and create API</Button>
        <DialogClose render={<Button variant="ghost" />}>Close</DialogClose>
      </DialogFooter>
    </DialogPopup>
  </Dialog>
}
