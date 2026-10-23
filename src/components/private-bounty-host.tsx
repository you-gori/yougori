import { useEffect, useState } from "react"
import { bountyApi, type PrivateHost, type PrivatePreview } from "@/api/bounty-api"
import { say } from "@/api/grids/errors"
import { Terms } from "./swarm-terms"
import { Button } from "./ui/button"
import { useArmed } from "./use-armed"
export function PrivateBountyHost({ refreshKey, onConnect }: { refreshKey: number; onConnect(preview: PrivatePreview): void }) {
  const [host, setHost] = useState<PrivateHost | null>(null)
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  const { armed, arm, disarm } = useArmed()
  useEffect(() => {
    let alive = true
    let timer: number
    // A read that works again clears the last failure, so the page does not keep saying the
    // host is unreachable after it has come back.
    const poll = async () => { try { const result = await bountyApi.status(); if (alive) { setHost(result.host); setError("") } } catch (reason) { if (alive) setError(say(reason)) } finally { if (alive) timer = window.setTimeout(() => void poll(), 4000) } }
    void poll(); return () => { alive = false; window.clearTimeout(timer) }
  }, [refreshKey])
  const run = async (work: () => Promise<unknown>) => { setBusy(true); setError(""); try { await work(); setHost((await bountyApi.status()).host) } catch (reason) { setError(say(reason)) } finally { setBusy(false) } }
  if (!host) return error ? <p className="grid-error">{error}</p> : null
  return <section className="grid-board swarm-host" aria-label="Private bounty host">
    <h2>{host.bounty.title}</h2><p className="grid-hint">Hosted on {host.address} · {host.members.length} joined workers · Keep this computer running</p>
    <div className="swarm-project-actions"><Button disabled={busy} onClick={() => void run(async () => onConnect(await bountyApi.localConnect()))}>Add local worker</Button>{host.address !== "127.0.0.1" ? <Button variant="outline" onClick={() => void run(() => navigator.clipboard.writeText(host.invite))}>Copy invitation</Button> : null}<Button disabled={busy} variant={armed === "host" ? "destructive" : "ghost"} onClick={() => armed === "host" ? (disarm(), void run(() => bountyApi.remove())) : arm("host")}>{armed === "host" ? "Confirm stop and remove host" : "Remove host"}</Button></div>
    {host.members.length ? <details><summary>Joined workers</summary>{host.members.map(member => <p key={member.id}>{member.name} · {member.state ?? "offline"} <Button variant="ghost" size="xs" disabled={busy} onClick={() => void run(() => bountyApi.removeMember(member.id))}>Revoke access</Button></p>)}</details> : null}
    <details><summary>Shared agent activity</summary><div className="swarm-chat-log">{host.coordination?.events.map(event => <p key={event.sequence}><strong>{event.type.replaceAll("_", " ")}</strong><span>{event.body.content ?? event.body.observations ?? event.body.summary ?? "Task updated"}</span></p>)}</div></details>
    <details><summary>Submitted findings ({host.coordination?.reports.length ?? 0})</summary>{host.coordination?.reports.map(report => <details className="swarm-report" key={report.id}><summary>{report.title} · {report.state}</summary>{report.document ? <Terms value={report.document} /> : <p className="grid-hint">This report has no detail yet.</p>}</details>)}</details>
    {error ? <p role="alert" className="grid-error">{error}</p> : null}
  </section>
}
