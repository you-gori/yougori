import { marketApi, type NetworkShare } from "@/api/market-api"
import { workspaceApi } from "@/api/workspace-api"
import { useNetwork } from "@/components/use-network"
import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogTrigger, DialogPopup, DialogTitle, DialogDescription, DialogPanel } from "@/components/ui/dialog"
import "@/components/network-panel.css"

type Network = ReturnType<typeof useNetwork>
const money = (value: number) => `$${(value / 1e6).toFixed(2)}`
const uptime = (seconds: number) => `${Math.floor(seconds / 3600)}h ${Math.floor(seconds % 3600 / 60)}m`

export function NetworkAccount({ network }: { network: Network }) {
  const { status, busy, perform } = network
  const website = status?.website ?? "https://yougori.com"
  return <div className="network-account">
    {status?.signedIn && status.account ? <>
      <p>{status.account.email}</p>
      <p>Wallet: {status.account.wallet ?? "Connect a wallet on your account page"}</p>
      <p>Credit {money(status.account.creditMicros)} · Earnings {money(status.account.earningsMicros)} · Available {money(status.account.availableMicros)}</p>
      <div className="network-actions"><Button size="sm" variant="outline" disabled={busy} onClick={() => void perform(() => workspaceApi.openUrl(`${website}/account`))}>Manage account and wallet</Button><Button size="sm" variant="ghost" disabled={busy} onClick={() => void perform(marketApi.signOut)}>Sign out</Button></div>
    </> : <>
      <p>Sign in once for the app and CLI. Create a free account in your browser. A wallet is needed to deposit or withdraw.</p>
      {status?.login ? <div role="status">
        <p>Approve code <strong>{status.login.userCode}</strong></p>
        <p>{status.login.verificationUrl}</p>
        <p>{status.login.error ?? (status.login.expiresIn > 0 ? "Waiting for browser approval…" : "Code expired. Sign in again.")}</p>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void perform(() => workspaceApi.openUrl(status.login!.verificationUrlComplete || status.login!.verificationUrl))}>Open browser</Button>
      </div> : null}
      <Button size="sm" disabled={busy || Boolean(status?.login && !status.login.error && status.login.expiresIn > 0)} onClick={() => void perform(marketApi.signIn)}>Sign in</Button>
    </>}
  </div>
}

export function NetworkShareDetails({ share, network }: { share: NetworkShare; network: Network }) {
  const node = share.node
  return <article className="network-share" aria-label={`Sharing ${share.model}`}>
    <strong>{share.model}</strong>
    <p>{share.live ? "Live" : share.status} · {share.mode === "free" ? "Free for everyone" : "Paid"}</p>
    {share.message ? <p role="status">{share.message}</p> : null}
    {share.warnings.map(warning => <p key={warning}>{warning}</p>)}
    {node ? <dl className="network-stats">
      <div><dt>GPU</dt><dd>{node.gpu ?? "Waiting for GPU details"}</dd></div>
      <div><dt>Price / 1M tokens</dt><dd>{node.price ? `$${node.price.input} input / $${node.price.output} output` : "Free"}</dd></div>
      <div><dt>Speed</dt><dd>{node.tps == null ? "Waiting for traffic" : `${node.tps.toFixed(1)} tokens/s · ${node.tpsSource === "window" ? "last 15 min" : "all-time average"}`}</dd></div>
      <div><dt>Uptime today / week</dt><dd>{uptime(node.uptimeTodaySeconds)} / {uptime(node.uptimeWeekSeconds)}</dd></div>
      <div><dt>Availability (7 days)</dt><dd>{node.availability == null ? "Waiting for checks" : `${node.availability}%`}</dd></div>
      <div><dt>Tokens input / output</dt><dd>{node.tokensIn.toLocaleString()} / {node.tokensOut.toLocaleString()}</dd></div>
      <div><dt>Earned</dt><dd>{money(node.earnedMicros)}</dd></div>
    </dl> : null}
    <div className="network-actions">
      {share.listing ? <Button size="sm" variant="outline" onClick={() => void network.perform(() => workspaceApi.openUrl(share.listing!))}>View provider</Button> : null}
      <Button size="sm" variant="outline" disabled={network.busy} onClick={() => void network.perform(() => marketApi.unshare(share.environmentId))}>Stop sharing</Button>
    </div>
  </article>
}

export function ModelNetworkPanel({ environmentId }: { environmentId: string }) {
  const network = useNetwork()
  const share = network.status?.shares.find(item => item.environmentId === environmentId)
  return <section className="network-panel" aria-label="Model Network sharing">
    <NetworkAccount network={network} />
    <p>Paid sharing uses the Network price for its ten priced models; other models are shared free. Free models can be used without an account or wallet.</p>
    {share ? <NetworkShareDetails share={share} network={network} /> : <p>This model is not shared.</p>}
    <div className="network-actions">
      <Button size="sm" disabled={!network.status?.signedIn || network.busy} onClick={() => void network.perform(() => marketApi.share(environmentId, "paid"))}>Share paid</Button>
      <Button size="sm" variant="outline" disabled={!network.status?.signedIn || network.busy} onClick={() => void network.perform(() => marketApi.share(environmentId, "free"))}>Share free</Button>
    </div>
    {network.error ? <p role="alert">{network.error}</p> : null}
  </section>
}

export function NetworkPanel() {
  const [open, setOpen] = useState(false)
  const network = useNetwork(open)
  return <Dialog open={open} onOpenChange={setOpen}>
    <DialogTrigger render={<Button size="sm" variant="outline" className="dashboard-action" />}>Network</DialogTrigger>
    <DialogPopup className="network-popup" showCloseButton={false}>
      <div className="network-heading"><DialogTitle>Yougori Network</DialogTitle><DialogClose render={<Button size="sm" variant="outline" />}>Close</DialogClose></div>
      <DialogDescription>Share models through the Yougori endpoint and manage your account.</DialogDescription>
      <DialogPanel className="network-panel">
        <NetworkAccount network={network} />
        <Button size="sm" variant="outline" onClick={() => void network.perform(() => workspaceApi.openUrl(`${network.status?.website ?? "https://yougori.com"}/network`))}>Browse models and create API</Button>
        {network.status?.shares.length ? network.status.shares.map(share => <NetworkShareDetails key={share.environmentId} share={share} network={network} />) : <p>No shared models. Choose Paid or Free when running a Hugging Face model.</p>}
        {network.error ? <p role="alert">{network.error}</p> : null}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
