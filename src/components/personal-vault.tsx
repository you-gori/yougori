import { useCallback, useEffect, useRef, useState } from "react"
import { listen } from "@tauri-apps/api/event"
import { vaultApi, type VaultStatus, type VaultConnectionMode } from "@/api/vault-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Dialog, DialogClose, DialogPopup, DialogTitle, DialogDescription } from "@/components/ui/dialog"
import { cloudflareTokenInput } from "@/lib/cloudflare-token"
import { VaultItemEditor } from "@/components/vault-item-editor"
import { useTopicWalkthroughModal } from "@/lib/topic-walkthrough"
import "@/components/personal-vault.css"

const empty: VaultStatus = { running: false, locked: true, items: [], clients: [], pending: [], activity: [] }
const name = (path: string) => path.split(/[\\/]/).pop() || path
const localUrl = "http://127.0.0.1:49732/mcp"
const stdioConfig = JSON.stringify({ mcpServers: { yougori: { command: "yougori", args: ["vault", "mcp"] } } }, null, 2)

/** Set when the toolbar's create action hands a new vault over to its row; the row's copy opens
 *  its dialog when it mounts or hears of it, whichever comes first. */
let carryOnPending = false
const CARRY_ON = "yougori-vault-carry-on"

export function PersonalVault({ startupError, asRowName = false, asCreate = false }: { startupError?: string | null; asRowName?: boolean; asCreate?: boolean } = {}) {
  const [open, setOpen] = useState(false)
  // Whether this is the create action's copy of a vault that now exists (see `handedOver`).
  const handedOverRef = useRef(false)
  const topic = useTopicWalkthroughModal(open)
  const [status, setStatus] = useState<VaultStatus>(empty)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState("")
  const [error, setError] = useState("")
  const [copied, setCopied] = useState("")
  const [mode, setMode] = useState<VaultConnectionMode>("quick")
  const operationPending = useRef(false)
  const formInitialized = useRef(false)
  const [hostname, setHostname] = useState("")
  const [tunnelToken, setTunnelToken] = useState("")
  const [routesReviewed, setRoutesReviewed] = useState(false)
  const [key, setKey] = useState("")
  const [guide, setGuide] = useState<"chatgpt" | "claude">("chatgpt")
  const [replaceLink, setReplaceLink] = useState(false)
  const [editingItems, setEditingItems] = useState(false)
  const [removingItem, setRemovingItem] = useState<string | null>(null)
  const [pluginPath, setPluginPath] = useState("")
  // Status reads can resolve out of order. Only the newest-started read, or a later
  // local change, may replace what is shown, so an approved request cannot reappear.
  const statusOrder = useRef({ started: 0, applied: 0 })
  const applyStatus = useCallback((sequence: number, value: VaultStatus | ((previous: VaultStatus) => VaultStatus)) => {
    if (sequence <= statusOrder.current.applied) return false
    statusOrder.current.applied = sequence
    setStatus(value); setLoaded(true)
    return true
  }, [])
  const refresh = useCallback(async () => {
    const sequence = ++statusOrder.current.started
    const value = await vaultApi.status()
    applyStatus(sequence, value)
    return value
  }, [applyStatus])
  const updateSetup = (setup: VaultStatus["setup"]) => applyStatus(++statusOrder.current.started, previous => ({ ...previous, setup }))
  useEffect(() => {
    let disposed = false, reading = false
    const update = () => {
      if (reading) return
      reading = true
      const sequence = ++statusOrder.current.started
      void vaultApi.status().then(value => {
        if (disposed || !applyStatus(sequence, value)) return
        if (open && !formInitialized.current) {
          setMode(value.setup?.mode === "domain" || (value.setup?.mode === "local" && value.setup.hostname) ? "domain" : "quick")
          setHostname(value.setup?.hostname ?? "")
          formInitialized.current = true
        }
      }).catch(reason => { if (!disposed) { setError(String(reason)); setLoaded(true) } }).finally(() => { reading = false })
    }
    update()
    const timer = window.setInterval(update, open ? 2000 : 10000)
    return () => { disposed = true; window.clearInterval(timer) }
  }, [applyStatus, open])
  useEffect(() => {
    // `yougori vault open|approve|add` brings the dashboard forward here; the person decides in this window.
    let disposed = false
    let unlisten: (() => void) | undefined
    void listen<string>("yougori-open-vault", event => {
      // Once the vault exists, its row's copy answers; the create action's copy stays shut.
      if (handedOverRef.current) return
      setOpen(true)
      if (event.payload === "add") setEditingItems(true)
      void refresh().catch(() => undefined)
    }).then(stop => { if (disposed) stop(); else unlisten = stop }).catch(() => undefined)
    return () => { disposed = true; unlisten?.() }
  }, [refresh])
  useEffect(() => {
    let disposed = false
    let unlisten: (() => void) | undefined
    void listen<number>("vault-approval-needed", () => {
      if (handedOverRef.current) return
      void refresh().catch(() => undefined)
      if (!document.hasFocus()) setOpen(true)
    }).then(stop => { if (disposed) stop(); else unlisten = stop }).catch(() => undefined)
    return () => { disposed = true; unlisten?.() }
  }, [refresh])
  useEffect(() => {
    if (!key) return
    const timer = window.setTimeout(() => setKey(""), 60000)
    return () => window.clearTimeout(timer)
  }, [key])
  const perform = async (label: string, operation: () => Promise<unknown>) => {
    if (operationPending.current) return
    operationPending.current = true
    setBusy(label); setError("")
    try { await operation(); await refresh() }
    catch (reason) { setError(String(reason)); await refresh().catch(() => undefined) }
    finally { operationPending.current = false; setBusy("") }
  }
  const control = (action: Parameters<typeof vaultApi.control>[0], id?: string) => perform("Reviewing vault request...", () => vaultApi.control(action, id))
  const copy = async (value: string) => {
    try { await navigator.clipboard.writeText(value); setCopied(value); window.setTimeout(() => setCopied(""), 2000) }
    catch { setError("Clipboard access is unavailable. Select and copy the text.") }
  }
  const code = (value: string, label: string) => <div className="vault-code"><code data-multiline={value.includes("\n") || undefined}>{value}</code><button type="button" aria-label={`Copy ${label}`} onClick={() => void copy(value)}>{copied === value ? "Copied" : "Copy"}</button></div>
  const created = Boolean(status.setup?.created)
  // The create action only lives until the vault exists. Its dialog then closes and hands over
  // to the row's copy, so nothing stays open unseen and polling, and nothing pops up again after
  // a later delete.
  const handedOver = asCreate && created
  useEffect(() => {
    handedOverRef.current = handedOver
    if (!handedOver || !open) return
    setOpen(false)
    carryOnPending = true
    window.dispatchEvent(new CustomEvent(CARRY_ON))
  }, [handedOver, open])
  useEffect(() => {
    if (!asRowName) return
    const carryOn = () => { if (carryOnPending) { carryOnPending = false; setOpen(true) } }
    carryOn()
    window.addEventListener(CARRY_ON, carryOn)
    return () => window.removeEventListener(CARRY_ON, carryOn)
  }, [asRowName])
  const ready = status.running && status.gateway?.running
  const publicUrl = status.setup?.publicUrl
  const activeMode = publicUrl ? status.setup?.mode : mode
  const chooseMode = (value: VaultConnectionMode) => { setMode(value); setRoutesReviewed(false) }
  const changeOpen = (value: boolean) => {
    setOpen(value)
    if (!value) setEditingItems(false)
    if (!value) setRemovingItem(null)
    setKey(""); setTunnelToken(""); setReplaceLink(false)
    formInitialized.current = false
    if (value) { setMode(status.setup?.mode === "domain" || (status.setup?.mode === "local" && status.setup.hostname) ? "domain" : "quick"); setHostname(status.setup?.hostname ?? ""); setRoutesReviewed(false) }
  }
  const connect = (replace = false) => perform(replace ? "Creating a new quick link..." : "Connecting your tunnel...", async () => {
    const setup = await vaultApi.connection(replace ? "quick" : mode, hostname, cloudflareTokenInput(tunnelToken), routesReviewed, replace)
    updateSetup(setup)
    setTunnelToken(""); setReplaceLink(false)
  })
  const bootstrapVault = (updating: boolean) => perform(updating ? "Updating vault and restoring public access..." : "Starting vault and restoring public access...", async () => {
    const result = await vaultApi.bootstrap(true)
    if (result.tunnelError) throw new Error(`Vault ${updating ? "updated" : "started"}, but the public link could not be restored: ${result.tunnelError}`)
  })
  const downloadPlugin = async () => {
    try {
      const { open } = await import("@tauri-apps/plugin-dialog")
      const directory = await open({ directory: true, multiple: false, title: "Save Yougori Personal Vault plugin in..." })
      if (typeof directory !== "string") return
      await perform("Saving plugin package...", async () => { setPluginPath(await vaultApi.exportPlugin(directory)) })
    } catch (reason) { setError(String(reason)) }
  }
  const connectionKeyButton = <Button size="sm" variant="outline" className="vault-key-button" disabled={Boolean(busy) || !ready || Boolean(status.updateRequired)} onClick={() => void perform("Showing connection key...", async () => { const result = await vaultApi.control("credentials"); if (result.token) setKey(result.token) })}>Show connection key</Button>
  const statusLabel = !loaded ? "Loading" : !created ? "Not set up" : status.updateRequired ? "Update needed" : ready ? "Running" : "Offline"
  const statusTone = !loaded || !created ? "idle" : status.updateRequired ? "warning" : ready ? "ok" : "error"
  // As the create action the vault only offers itself until it exists. Once it is set up the
  // sandbox row takes over, so nothing is mounted here at all; and nothing is offered before
  // the first status arrives, so an existing vault never flashes a "create" button.
  if (asCreate && (!loaded || created)) return null
  return <>
    {asRowName ? (
      // In the sandbox list the vault's name behaves like any row name: a plain button.
      <button type="button" data-list-focus data-instruction="vault-trigger" aria-label="Personal Vault MCP" title="Personal Vault MCP" onClick={() => changeOpen(true)}>
        Personal Vault MCP
        {status.pending.length > 0 && <span className="environment-list-tag">{status.pending.length}</span>}
      </button>
    ) : asCreate ? (
      <Button variant="outline" size="sm" className="dashboard-action" data-instruction="vault-trigger" aria-label="Create my personal vault MCP" title="Create my personal vault MCP" onClick={() => changeOpen(true)}>Create my personal vault MCP</Button>
    ) : (
      <Button variant="outline" size="sm" className="dashboard-action relative" data-instruction="vault-trigger" aria-label="Personal Vault MCP" title="Personal Vault MCP" onClick={() => changeOpen(true)}>
        Personal Vault MCP
        {status.pending.length > 0 && <span className="absolute -right-1 -top-1 min-w-4 rounded-full bg-primary px-1 text-[10px] text-primary-foreground">{status.pending.length}</span>}
        {startupError && !ready && <span className="absolute -right-1 -top-1 size-2 rounded-full bg-destructive" aria-label="Personal Vault needs attention" />}
      </Button>
    )}
    <Dialog modal={!topic} open={open} onOpenChange={(value, details) => { if (!(!value && topic && details.reason === "focus-out") && !(details.event.target instanceof Element && details.event.target.closest('[data-topic-ui]'))) changeOpen(value) }}>
      <DialogPopup data-instruction="vault-dialog" bottomStickOnMobile={false} showCloseButton={false} className="vault-popup max-w-none">
        <header className="vault-header">
          <div>
            <DialogTitle>Personal Vault</DialogTitle>
            <DialogDescription className="vault-status" data-tone={statusTone}>{statusLabel}</DialogDescription>
          </div>
          <DialogClose render={<Button variant="outline" size="sm" />}>Close</DialogClose>
        </header>
        <div className="vault-body">
          {error && <div role="alert" className="vault-banner" data-tone="error"><span>{error}</span><button type="button" aria-label="Dismiss vault error" onClick={() => setError("")}>Dismiss</button></div>}
          {startupError && !ready && <section aria-label="Vault recovery" className="vault-banner" data-tone="error"><div><strong>Vault unavailable</strong><p>The container didn’t start. Your data is untouched.</p><details className="vault-disclosure"><summary>Details</summary><pre>{startupError}</pre></details></div></section>}
          {busy && <p role="status" className="vault-busy">{busy}</p>}
          {status.pending.some(p => p.ready && p.client) && <section aria-label="Pending vault requests" className="vault-requests">
            <h2>Requests waiting for you</h2>
            {status.pending.filter(p => p.ready && p.client).map(p => <div key={p.id} className="vault-request">
              <p className="vault-request-title">{p.title ?? p.operation.replaceAll("_", " ")}</p>
              <p className="vault-muted">Requested by {name(p.client.executable)}</p>
              {p.description && <p className="vault-request-description">{p.description}</p>}
              <div className="vault-actions"><Button size="sm" variant="outline" onClick={() => void control("deny", p.id)}>Deny</Button><Button size="sm" onClick={() => void control("approve", p.id)}>{p.allowLabel ?? "Approve once"}</Button></div>
            </div>)}
          </section>}

          {!loaded ? <p role="status" className="vault-loading">Loading…</p> : editingItems ? <div className="vault-editor"><VaultItemEditor onCancel={() => setEditingItems(false)} onSave={async items => { await vaultApi.addItems(items); await refresh(); setEditingItems(false) }} /></div> : !created ? <section className="vault-onboarding">
            <h2>One home for your private information</h2>
            <p>Passwords, API keys, and personal details. Agents only get what you approve.</p>
            <Button disabled={Boolean(busy) || status.supported === false} onClick={() => void perform("Creating your vault…", () => vaultApi.create())}>Create your personal vault</Button>
            {status.supported === false && <p className="vault-muted">{status.notice}</p>}
          </section> : <>
            <div className="vault-grid">
              <section className="vault-column" aria-labelledby="vault-items-title">
                <div className="vault-column-head">
                  <h2 id="vault-items-title">Items{!status.locked && <span>{status.items.length}</span>}</h2>
                  <div className="vault-actions">
                    {status.locked && ready && !status.updateRequired && <Button size="sm" variant="outline" disabled={Boolean(busy)} onClick={() => void control("browse")}>View items</Button>}
                    {status.updateRequired ? <Button size="sm" disabled={Boolean(busy)} onClick={() => void bootstrapVault(true)}>Update vault</Button> : !ready ? <Button size="sm" disabled={Boolean(busy)} onClick={() => void bootstrapVault(false)}>{startupError?.includes("Protected vault startup task failed") ? "Repair startup" : "Start vault"}</Button> : <Button size="sm" disabled={Boolean(busy)} onClick={() => setEditingItems(true)}>Add items</Button>}
                  </div>
                </div>
                <section aria-label="Vault items" className="vault-items">
                  {!status.items.length ? <p className="vault-empty">{status.locked ? "Choose View items to open the vault." : "No items yet."}</p> : status.items.map(item => <div key={item.id} className="vault-item">
                    <div className="vault-item-text"><p>{item.label}</p><span>{item.kind.replaceAll("_", " ")}{item.fields.length ? ` · ${item.fields.join(", ")}` : ""}</span></div>
                    {removingItem === item.id ? <div className="vault-actions"><span className="vault-muted">Remove permanently?</span><Button size="xs" variant="ghost" onClick={() => setRemovingItem(null)}>Cancel</Button><Button size="xs" variant="destructive" disabled={Boolean(busy)} onClick={() => { setRemovingItem(null); void control("remove", item.id) }}>Remove item</Button></div> : <div className="vault-item-actions">
                      <span aria-label="Value hidden" className="vault-mask">••••••</span>
                      <Button size="xs" variant="ghost" onClick={() => void copy(item.id)}>{copied === item.id ? "Copied" : "Copy ID"}</Button>
                      <Button size="xs" variant="ghost" disabled={Boolean(busy)} aria-label={`Remove ${item.label}`} onClick={() => setRemovingItem(item.id)}>Remove</Button>
                    </div>}
                  </div>)}
                </section>
                <p className="vault-footnote">Nothing is shared until you approve it.</p>
              </section>

              <section className="vault-column vault-connections" aria-labelledby="vault-connections-title">
                <div className="vault-column-head"><h2 id="vault-connections-title">Connections</h2></div>

                <section aria-label="Public host instructions" className="vault-block">
                  <div className="vault-block-head"><div><h3>ChatGPT, Claude & online agents</h3><p>Through Cloudflare Tunnel</p></div>{publicUrl && <span className="vault-status" data-tone="ok">Connected</span>}</div>
                  {status.updateRequired && !publicUrl && <p role="status" className="vault-note">{status.setup?.mode === "quick" ? "Your previous quick link ended when Yougori restarted. Update the vault to start a new one." : status.setup?.mode === "domain" ? "Update the vault to reconnect your domain." : "Update the vault before connecting a tunnel."}</p>}
                  {publicUrl ? <>
                    <span className="vault-eyebrow">{activeMode === "domain" ? "Your domain" : "Quick link · temporary"}</span>
                    {code(publicUrl, "ChatGPT or Claude server URL")}
                    <div className="vault-actions vault-actions-start">
                      {activeMode === "quick" && <Button size="xs" variant="outline" disabled={Boolean(busy)} onClick={() => setReplaceLink(true)}>Change tunnel domain</Button>}
                      <Button size="xs" variant="ghost" disabled={Boolean(busy)} onClick={() => void perform("Disconnecting your tunnel...", async () => { const setup = await vaultApi.connection("local"); updateSetup(setup); setReplaceLink(false) })}>Disconnect tunnel</Button>
                    </div>
                    {replaceLink && <div className="vault-confirm"><p>The current address will stop working.</p><div className="vault-actions"><Button size="xs" variant="ghost" disabled={Boolean(busy)} onClick={() => setReplaceLink(false)}>Cancel</Button><Button size="xs" disabled={Boolean(busy)} onClick={() => void connect(true)}>Create new quick link</Button></div></div>}
                  </> : <>
                    <div className="vault-segmented" role="group" aria-label="Tunnel type">{(["quick", "domain"] as const).map(option => <button key={option} type="button" aria-pressed={mode === option} disabled={Boolean(busy)} onClick={() => chooseMode(option)}>{option === "quick" ? "Quick link" : "My domain"}</button>)}</div>
                    {mode === "quick" ? <p className="vault-muted vault-spaced">No Cloudflare account needed. The address changes on restart.</p> : <div className="vault-form">
                      <label><span>Domain</span><Input aria-label="Vault hostname" placeholder="vault.example.com" value={hostname} disabled={Boolean(busy)} onChange={e => { setHostname(e.target.value); setRoutesReviewed(false) }} /></label>
                      <label><span>Tunnel token</span><Input aria-label="Cloudflare tunnel token" type="password" autoComplete="off" maxLength={4096} disabled={Boolean(busy)} placeholder={status.setup?.hostname && status.setup.hostname === hostname ? "Saved token · leave blank to reuse" : "Paste token or Cloudflare command"} value={tunnelToken} onChange={e => { setTunnelToken(cloudflareTokenInput(e.target.value)); setRoutesReviewed(false) }} /></label>
                      <details className="vault-disclosure"><summary>Where do I get a token?</summary><p>In Cloudflare, create a dedicated Tunnel. Add this domain as a public hostname with service <code>http://127.0.0.1:49732</code>. Paste its token or install command here. Don’t run the command.</p></details>
                      <label className="vault-check"><input type="checkbox" checked={routesReviewed} disabled={Boolean(busy)} onChange={e => setRoutesReviewed(e.target.checked)} />This tunnel routes only this domain to port 49732.</label>
                    </div>}
                    <Button size="sm" disabled={Boolean(busy) || !ready || Boolean(status.updateRequired) || (mode === "domain" && (!hostname.trim() || !routesReviewed))} onClick={() => void connect()}>Connect tunnel</Button>
                  </>}

                  <details className="vault-disclosure">
                    <summary>How to connect ChatGPT or Claude</summary>
                    <section aria-label="ChatGPT and Claude setup" className="vault-guide">
                      <div className="vault-segmented vault-segmented-small" role="group" aria-label="Connection guide"><button type="button" aria-pressed={guide === "chatgpt"} onClick={() => setGuide("chatgpt")}>ChatGPT</button><button type="button" aria-pressed={guide === "claude"} onClick={() => setGuide("claude")}>Claude</button></div>
                      {status.updateRequired ? <p className="vault-muted">Click Update vault above to activate the new MCP tools and restore public access.</p> : !publicUrl ? <p className="vault-muted">Connect a tunnel above to get your server address.</p> : !status.oauthReady ? <p className="vault-muted">{status.oauthUnavailable ? `Vault sign-in is off: ${status.oauthUnavailable}` : "Vault sign-in isn’t ready yet. Start or update the vault first."}</p> : <>
                        {guide === "chatgpt" ? <ol className="vault-steps"><li>In ChatGPT, enable Developer mode in Settings → Security and login, then open Apps / Plugins and create a custom connection.</li><li>Name it <strong>Yougori Personal Vault</strong> and paste the full server URL above, including <code>/mcp</code>.</li><li>Set Authentication to <strong>OAuth</strong>. Leave Client ID and Client Secret blank for automatic registration.</li><li>Follow the Yougori sign-in page, click Continue on my PC, and allow the matching request here.</li><li>Enable Yougori from the tools menu in a new chat.</li></ol> : <ol className="vault-steps"><li>In Claude, open Settings → Connectors → Add custom connector.</li><li>Name it <strong>Yougori Personal Vault</strong> and paste the full server URL above.</li><li>Leave the OAuth Client ID and Client Secret in Advanced settings blank.</li><li>Click Connect, then Continue on my PC, and allow the matching request here.</li><li>Enable the connector in your chat.</li></ol>}
                        <p className="vault-muted">Keep Yougori open and this PC awake.</p>
                      </>}
                      <details className="vault-disclosure"><summary>Getting a registration error?</summary><p>Update the vault, then create a fresh connector with the current URL and empty Client ID and Secret. Some workspaces restrict custom connectors.</p></details>
                    </section>
                  </details>
                  {publicUrl && <details className="vault-disclosure"><summary>Other apps (Bearer token)</summary><ol className="vault-steps"><li>Add an MCP server named <strong>Yougori Personal Vault</strong>, choose Streamable HTTP, and paste the server URL above.</li><li>Choose Bearer token authentication and paste the connection key. If headers are required, use <code>Authorization: Bearer YOUR_KEY</code>.</li><li>Approve the connection here.</li></ol>{connectionKeyButton}</details>}
                </section>

                <section aria-label="Localhost instructions" className="vault-block">
                  <div className="vault-block-head"><div><h3>On this computer</h3><p>Local agents and developer tools</p></div></div>
                  {code(status.setup?.localUrl ?? localUrl, "localhost address")}
                  <details className="vault-disclosure">
                    <summary>How to connect locally</summary>
                    <ol className="vault-steps"><li>Add an MCP server named <strong>Yougori Personal Vault</strong>, choose Streamable HTTP, and paste the URL above.</li><li>Choose Bearer token authentication and paste the connection key.</li><li>Approve the connection here.</li></ol>
                    <details className="vault-disclosure"><summary>Using a command or JSON config?</summary><p>Use command <code>yougori</code> with arguments <code>vault mcp</code>. No key needed.</p>{code(stdioConfig, "local MCP configuration")}</details>
                    {connectionKeyButton}
                  </details>
                </section>

                <div className="vault-block vault-plugin">
                  <Button size="sm" variant="outline" disabled={Boolean(busy) || !ready || !publicUrl || !status.oauthReady || Boolean(status.updateRequired)} onClick={() => void downloadPlugin()}>Download plugin ZIP</Button>
                  <p className="vault-muted">{status.updateRequired ? "Update the vault first." : publicUrl ? activeMode === "quick" ? "Uses your current quick link." : "Uses your vault domain." : "Connect a tunnel first."}</p>
                  {pluginPath && <p role="status" className="vault-muted vault-path">Saved to {pluginPath}</p>}
                </div>
              </section>
            </div>

            <div className="vault-footer">
              {key && <div className="vault-key"><div className="vault-key-head"><span className="vault-eyebrow">Connection key</span><Button size="xs" variant="ghost" onClick={() => setKey("")}>Hide key</Button></div>{code(key, "connection key")}<p className="vault-muted">Hidden after 60 seconds. Never paste it into a chat.</p></div>}
              <div className="vault-footer-grid">
                <details className="vault-disclosure"><summary>Connected agents · {status.clients.length}</summary><section aria-label="Connected vault clients" className="vault-list">{!status.clients.length ? <p className="vault-muted">None yet.</p> : status.clients.map(client => <div key={client.id} className="vault-list-row"><span>{name(client.executable)}</span><Button size="xs" variant="ghost" disabled={Boolean(busy)} aria-label={`Disconnect and revoke ${name(client.executable)}`} onClick={() => void control("revoke", client.id)}>Disconnect</Button></div>)}</section></details>
                <details className="vault-disclosure"><summary>Recent activity</summary><section aria-label="Vault activity" className="vault-list">{!status.activity.length ? <p className="vault-muted">Nothing yet. Secret values are never logged.</p> : status.activity.slice(-20).reverse().map((entry, i) => <div key={`${entry.request}-${i}`} className="vault-list-row vault-muted"><span>{new Date(entry.time).toLocaleTimeString()} · {entry.operation.replaceAll("_", " ")}</span><span>{entry.outcome.replaceAll("_", " ")}</span></div>)}</section></details>
              </div>
            </div>
          </>}
        </div>
      </DialogPopup>
    </Dialog>
  </>
}
