import { useState } from "react"
import { desksApi, type Desk, type DeskPerson, type DesksHub } from "@/api/desks-api"
import type { GridRun } from "@/components/grid-swarm"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { useArmed } from "@/components/use-armed"
import "@/components/neo-grid.css"

const gb = (bytes: number) => bytes >= 1073741824 ? `${(bytes / 1073741824).toFixed(1)} GB` : `${Math.max(1, Math.round(bytes / 1048576))} MB`

function stateText(desk: Desk) {
  if (desk.state === "ready") return desk.hostOnline ? (desk.reachable ? "Ready" : "Ready · waiting for its share") : "Ready · its computer is offline"
  if (desk.state === "building") return desk.hostOnline ? "Building" : "Building · its computer is offline"
  if (desk.state === "failed") return "Failed"
  if (desk.state === "moving") return desk.parcelBytes ? `Moving · ${gb(desk.parcelBytes)} of data packed` : "Moving with its data"
  return "Waiting for a computer with room"
}

/** A number with its unit sitting in the same box. */
export function UnitField({ id, label, unit, value, min, max, step, disabled, onChange }: { id: string; label: string; unit: string; value: string; min: number; max: number; step: number; disabled?: boolean; onChange(value: string): void }) {
  return <div className="grid-field">
    <label htmlFor={id}>{label}</label>
    <div className="grid-unit">
      <Input id={id} type="number" inputMode="decimal" min={min} max={max} step={step} value={value} disabled={disabled} onChange={event => onChange(event.target.value)} />
      <span className="grid-unit-suffix" aria-hidden="true">{unit}</span>
    </div>
  </div>
}

/** The admin's people and desks: who may sign in, and the sandbox each one gets. */
export function GridPeopleAndDesks({ hub, run }: { hub: DesksHub; run: GridRun }) {
  const { armed, arm, disarm } = useArmed()
  const [username, setUsername] = useState("")
  const [personName, setPersonName] = useState("")
  const [password, setPassword] = useState("")
  const [personCpu, setPersonCpu] = useState("2")
  const [personMemory, setPersonMemory] = useState("4")
  const [personDisk, setPersonDisk] = useState("20")
  const [personGpu, setPersonGpu] = useState(false)
  const people: DeskPerson[] = hub.people ?? []
  const desks: Desk[] = hub.desks ?? []
  const sized = (cpu: string, memory: string, disk: string) => Number(cpu) > 0 && Number(memory) > 0 && Number(disk) > 0
  const personProblem = !username.trim() ? "Give a username." : password.length < 10 ? "A password has at least 10 characters." : !sized(personCpu, personMemory, personDisk) ? "Give their desk's CPU, memory and disk as numbers." : ""

  const addPerson = () => {
    if (personProblem) return
    const made = { username: username.trim(), name: personName.trim() || username.trim(), password }
    const desk = { cpu: Number(personCpu), memoryGb: Number(personMemory), diskGb: Number(personDisk), gpu: personGpu }
    void run(`Adding ${made.username}`, () => desksApi.addPerson(made.username, made.name, made.password, desk), `${made.name} can sign in; their desk is ordered`).then(ok => { if (ok) { setUsername(""); setPersonName(""); setPassword("") } })
  }
  /** A person's desks in one line: each with its size and where it stands. */
  const deskLine = (person: DeskPerson) => {
    const mine = desks.filter(desk => desk.personId === person.id)
    if (!mine.length) return " · no desk yet"
    return mine.map(desk => ` · ${desk.name}: ${desk.summary} · ${stateText(desk)}${desk.host ? ` on ${desk.host}` : ""}`).join("")
  }

  return <>
    <section aria-label="People" className="grid-part">
      <p className="grid-part-title">People <span>each with their own desk</span></p>
      {people.map(person => {
        const removing = armed === `person-${person.id}`
        return <div key={person.id} className="grid-line">
          <strong>{person.name}</strong>
          <span className="grid-muted">{person.username}{person.adminRole && person.adminRole !== "user" ? ` · ${person.adminRole}` : ""}{deskLine(person)}{person.lastLoginAt ? "" : " · never signed in"}</span>
          <span className="grid-line-actions">
            <Button size="xs" variant={removing ? "destructive" : "ghost"} aria-label={`Remove ${person.name}`} title="They can no longer sign in; their desks stay" onClick={() => removing ? (disarm(), void run(`Removing ${person.name}`, () => desksApi.removePerson(person.id), `${person.name} removed`)) : arm(`person-${person.id}`)}>{removing ? "Confirm" : "Remove"}</Button>
          </span>
        </div>
      })}
      <form className="grid-form-block" aria-label="New person" onSubmit={event => { event.preventDefault(); addPerson() }}>
        <div className="grid-fields">
          <div className="grid-field">
            <label htmlFor="desk-person-username">Username</label>
            <Input id="desk-person-username" placeholder="ada.lovelace" value={username} spellCheck={false} autoComplete="off" onChange={event => setUsername(event.target.value)} />
          </div>
          <div className="grid-field">
            <label htmlFor="desk-person-name">Name</label>
            <Input id="desk-person-name" placeholder="Optional" value={personName} onChange={event => setPersonName(event.target.value)} />
          </div>
          <div className="grid-field">
            <label htmlFor="desk-person-password">Password</label>
            <Input id="desk-person-password" type="password" placeholder="10 characters or more" value={password} autoComplete="new-password" onChange={event => setPassword(event.target.value)} />
          </div>
          <UnitField id="desk-person-cpu" label="CPU cores" unit="cores" value={personCpu} min={0.5} max={64} step={0.5} onChange={setPersonCpu} />
          <UnitField id="desk-person-memory" label="Memory (GB)" unit="GB" value={personMemory} min={0.5} max={512} step={0.5} onChange={setPersonMemory} />
          <UnitField id="desk-person-disk" label="Disk (GB)" unit="GB" value={personDisk} min={1} max={2048} step={1} onChange={setPersonDisk} />
          <div className="grid-field">
            <span className="grid-field-label">GPU</span>
            <label className="grid-check-field"><input type="checkbox" aria-label="GPU" checked={personGpu} onChange={event => setPersonGpu(event.target.checked)} />Their desk gets a GPU</label>
          </div>
        </div>
        <div className="grid-form-actions">
          <Button size="sm" type="submit" disabled={Boolean(personProblem)} title={personProblem || undefined}>Add person and their desk</Button>
          <p className="grid-hint">{personProblem || "They sign in with these from any computer; the password is kept only as a hash. Their desk, a container of this size, is ordered at once and named after them."}</p>
        </div>
      </form>
    </section>

    <section aria-label="Desks" className="grid-part">
      <p className="grid-part-title">Desks <span>every sandbox the grid hosts: whose it is and where it runs</span></p>
      {desks.length ? null : <p className="grid-line grid-muted">No desks yet. Add a person above and their desk is ordered with them.</p>}
      {desks.map(desk => {
        const removing = armed === `desk-${desk.id}`
        return <div key={desk.id} className="grid-line grid-computer">
          <i aria-hidden="true" className="grid-dot" data-online={desk.reachable || undefined} />
          <span className="grid-computer-main">
            <strong>{desk.name}</strong>
            <span className="grid-status" data-tone={desk.state === "failed" ? "error" : desk.reachable ? "ok" : "wait"}>{stateText(desk)}{desk.state === "failed" || !desk.reachable ? ` · ${desk.note}` : ""}</span>
          </span>
          {desk.access === "restricted" ? <span className="grid-tag" title="A full VM without network: desktop and inbound uploads only">Restricted</span> : null}
          <span className="grid-meta" title={desk.summary}>{desk.person ?? "nobody"}{desk.host ? ` · on ${desk.host}` : ""}</span>
          <span className="grid-line-actions">
            {desk.state === "failed" ? <Button size="xs" variant="outline" aria-label={`Retry ${desk.name}`} onClick={() => void run(`Retrying ${desk.name}`, () => desksApi.retryDesk(desk.id))}>Retry</Button> : null}
            <Button size="xs" variant={removing ? "destructive" : "ghost"} aria-label={`Remove ${desk.name}`} title="Deletes the desk's sandbox and its data" onClick={() => removing ? (disarm(), void run(`Removing ${desk.name}`, () => desksApi.removeDesk(desk.id), `${desk.name} removed`)) : arm(`desk-${desk.id}`)}>{removing ? "Confirm" : "Remove"}</Button>
          </span>
        </div>
      })}
    </section>
  </>
}
