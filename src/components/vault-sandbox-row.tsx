import { useCallback, useEffect, useRef, useState } from "react"
import { vaultApi, type VaultStatus } from "@/api/vault-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { toastManager } from "@/components/ui/toast"
import { PersonalVault } from "@/components/personal-vault"
import { VaultRowMenu } from "@/components/vault-row-menu"

const empty: VaultStatus = { running: false, locked: true, items: [], clients: [], pending: [], activity: [] }

/** The Personal Vault MCP pinned under the sandboxes, wearing the same row chrome: name,
 *  status and actions, with its secrets, requests and the add form in the expanded detail. */
export function VaultSandboxRow({ startupError }: { startupError?: string | null }) {
  const [status, setStatus] = useState<VaultStatus>(empty)
  const [loaded, setLoaded] = useState(false)
  const [busy, setBusy] = useState("")
  const [expanded, setExpanded] = useState(false)
  const [label, setLabel] = useState("")
  const [resource, setResource] = useState("")
  const [value, setValue] = useState("")
  const order = useRef(0)

  const refresh = useCallback(async () => {
    const sequence = ++order.current
    const next = await vaultApi.status()
    if (sequence === order.current) { setStatus(next); setLoaded(true) }
  }, [])

  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 4000)
    return () => window.clearInterval(timer)
  }, [refresh])

  const perform = async (job: string, operation: () => Promise<unknown>) => {
    if (busy) return
    setBusy(job)
    try { await operation(); await refresh() }
    catch (error) { toastManager.add({ title: "Personal Vault", description: error instanceof Error ? error.message : String(error), type: "error" }) }
    finally { setBusy("") }
  }

  const addSecret = () => perform("Adding", async () => {
    if (!label.trim() || !value) throw new Error("A name and a secret value are required.")
    await vaultApi.addItems([{ label: label.trim(), kind: "password", resource: resource.trim(), value }])
    setLabel(""); setResource(""); setValue("")
  })

  // The same path as the vault dialog's "Start vault": setup lock, protected broker, gateway and public link.
  const activate = () => perform("Activating", async () => {
    const result = await vaultApi.bootstrap(true)
    if (!result.created) throw new Error("Create your personal vault first: open Personal Vault MCP.")
    if (result.tunnelError) throw new Error(`Vault started, but the public link could not be restored: ${result.tunnelError}`)
  })

  const running = status.running
  // Only requests the broker has made reviewable carry an id and client to approve.
  const requests = status.pending.filter(request => request.ready && request.client)
  const dash = <span className="text-muted-foreground">—</span>
  // Until the vault is set up there is nothing to put in these columns, so the workspace offers
  // the create action above the list instead of a row of em-dashes. A created-but-stopped vault
  // keeps its row, so Activate stays reachable.
  //
  // The menu stays mounted even then. A finished delete forgets the setup, so the next poll drops
  // this row — and the dialog naming what the delete could not clean up afterwards lives inside
  // it. Unmounting here would take that list off the screen seconds after it appeared, and it is
  // the only place the leftover Credential Manager entry is ever named. Rendering it alone costs
  // nothing: the dialog is in a portal, so a closed one puts no markup in the table.
  if (!loaded || !status.setup?.created) return <VaultRowMenu />
  return <>
    <VaultRowMenu />
    {/* Marks this row for the native menu, which appends only "Delete my vault" and clears the flag. */}
    <tr className="workspace-list-row" data-expanded={expanded || undefined} data-running={running || undefined} aria-busy={Boolean(busy)} onContextMenu={() => { document.documentElement.dataset.yougoriVaultContext = "1" }}>
      <td className="environment-list-select-cell" />
      <th scope="row" className="environment-list-name">
        <div className="environment-list-name-line">
          <button type="button" className="environment-list-disclosure" aria-expanded={expanded} aria-label={`${expanded ? "Hide" : "Show"} Personal Vault MCP details`} onClick={() => setExpanded(open => !open)} />
          <PersonalVault startupError={startupError} asRowName />
        </div>
        <span className="environment-list-type">Vault</span>
        <span className="sr-only">{running ? "Running" : "Not active"}</span>
        {startupError && !running ? <span className="environment-list-subtitle" title={startupError}>{startupError}</span> : null}
        {/* A delete that stopped partway leaves the vault in place; running it again is safe. */}
        {status.destroyIncomplete ? <span className="environment-list-subtitle">Deleting didn’t finish, and the vault stays closed. Right-click this row and run Delete my vault again; if it stops again, it names each file left and how to remove it yourself.</span> : null}
      </th>
      <td className="environment-list-number">{dash}</td>
      <td className="environment-list-number">{dash}</td>
      <td className="environment-list-number">{dash}</td>
      <td className="environment-list-number">{dash}</td>
      <td className="environment-list-links">{dash}</td>
      <td className="environment-list-access">{running ? `${status.clients.length} connected` : dash}</td>
      <td className="environment-list-services">{running ? `${status.items.length} secret${status.items.length === 1 ? "" : "s"}` : dash}</td>
      <td className="environment-list-actions">
        {running ? <>
          <Button size="xs" variant="ghost" disabled={Boolean(busy)} onClick={() => setExpanded(true)}>Add</Button>
          <Button size="xs" variant="ghost" disabled={Boolean(busy)} onClick={() => void perform("Locking", () => vaultApi.control("lock"))}>Lock</Button>
        </> : <Button size="xs" disabled={Boolean(busy)} aria-busy={Boolean(busy)} onClick={() => void activate()}>{busy === "Activating" ? "Activating…" : "Activate"}</Button>}
      </td>
    </tr>
    {expanded ? (
      <tr className="environment-list-detail">
        <td colSpan={99}>
          <div className="environment-list-details vault-detail">
            <section aria-label="Add a secret">
              <h4>Add a secret</h4>
              <form className="vault-detail-add" onSubmit={event => { event.preventDefault(); void addSecret() }}>
                <Input aria-label="Name" placeholder="Name (e.g. OpenAI key)" value={label} disabled={Boolean(busy)} onChange={event => setLabel(event.target.value)} />
                <Input aria-label="Where it is used" placeholder="Where it is used (optional)" value={resource} disabled={Boolean(busy)} onChange={event => setResource(event.target.value)} />
                <Input aria-label="Secret value" type="password" placeholder="Secret value" value={value} disabled={Boolean(busy)} onChange={event => setValue(event.target.value)} />
                <Button size="sm" type="submit" disabled={Boolean(busy) || !running}>{busy === "Adding" ? "Adding…" : "Save"}</Button>
              </form>
              {!running ? <p className="vault-detail-note">Activate the vault to store secrets.</p> : null}
            </section>

            {requests.length ? (
              <section aria-label="Requests to approve">
                <h4>Requests</h4>
                <ul className="vault-detail-pending">
                  {requests.map(request => (
                    <li key={request.id}>
                      <span><strong>{request.title ?? request.operation}</strong>{request.description ? <span className="vault-detail-note"> {request.description}</span> : null}</span>
                      <span className="vault-detail-row-actions">
                        <Button size="xs" disabled={Boolean(busy)} onClick={() => void perform("Approving", () => vaultApi.control("approve", request.id))}>{request.allowLabel ?? "Approve"}</Button>
                        <Button size="xs" variant="ghost" disabled={Boolean(busy)} onClick={() => void perform("Denying", () => vaultApi.control("deny", request.id))}>Deny</Button>
                      </span>
                    </li>
                  ))}
                </ul>
              </section>
            ) : null}

            <section aria-label="Secrets">
              <h4>Secrets</h4>
              {status.items.length ? (
                <ul className="vault-detail-list">
                  {status.items.map(item => (
                    <li key={item.id}><span className="truncate"><strong>{item.label}</strong>{item.resource ? <span className="vault-detail-note"> · {item.resource}</span> : null}</span><span className="vault-detail-note">{item.kind}</span></li>
                  ))}
                </ul>
              ) : <p className="vault-detail-note">No secrets yet.</p>}
            </section>
          </div>
        </td>
      </tr>
    ) : null}
  </>
}
