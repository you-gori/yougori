import { useState, type FormEvent, type ReactNode } from "react"
import { accessApi, type AccessCredential, type AccessDecision, type AccessKind, type AccessMe, type AccessOverview, type AccessPermission, type AccessPerson, type AccessRule } from "@/api/access-api"
import { useArmed } from "@/components/use-armed"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import "@/components/neo-grid.css"
import "@/components/access-grid.css"

/** Runs one change with a busy line and a toast; resolves whether it worked. */
export type AccessRun = (job: string, work: () => Promise<unknown>, done?: string) => Promise<boolean>

const tabs = ["People", "Credentials", "Rules", "Settings", "Activity"] as const
type Tab = typeof tabs[number]
const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] as const
const MIN_PASSWORD = 10

const permissions: Record<AccessPermission, string> = {
  member: "Member · uses what rules allow",
  approver: "Approver · also decides requests",
  auditor: "Auditor · reads everything",
  admin: "Administrator · manages the grid",
}
const kinds: Record<AccessKind, string> = { bearer: "Bearer token", header: "Header", basic: "Basic sign-in", query: "Query parameter", oauth: "OAuth client credentials", "github-app": "GitHub App", aws: "AWS key" }
const fieldLabels: Partial<Record<AccessKind, [string, string]>> = {
  header: ["Header name", "X-Api-Key"],
  basic: ["Username", "service-account"],
  query: ["Parameter name", "api_key"],
}
/** What the value is, for each kind. */
const valueLabels: Record<AccessKind, [string, string]> = {
  bearer: ["Token", "Never shown again"],
  header: ["Value", "Never shown again"],
  basic: ["Password", "Never shown again"],
  query: ["Value", "Never shown again"],
  oauth: ["Client secret", "Never shown again"],
  "github-app": ["Private key (.pem)", "-----BEGIN RSA PRIVATE KEY-----"],
  aws: ["Access key", "ACCESS_KEY_ID:SECRET_ACCESS_KEY"],
}
/** Each minting kind's settings: key, label, placeholder, required. */
const settingsOf: Partial<Record<AccessKind, [string, string, string, boolean][]>> = {
  oauth: [["tokenUrl", "Token URL", "https://login.example.com/oauth2/token", true], ["clientId", "Client ID", "app id", true], ["scope", "Scope", "Optional", false], ["audience", "Audience", "Optional", false], ["auth", "Secret sent in", "basic (header) or body", false]],
  "github-app": [["appId", "Client ID or App ID", "Iv23li…", true], ["installationId", "Installation ID", "7654321", true], ["apiUrl", "API URL", "https://api.github.com", false]],
  aws: [["region", "Region", "us-east-1", true], ["service", "Service", "From the host, or s3, execute-api…", false], ["roleArn", "Role ARN", "Optional: temporary keys from this role", false], ["externalId", "External ID", "Optional", false]],
}
const decisions: Record<AccessDecision, string> = { allow: "At once", ask: "An approver decides", never: "Never" }

/** Common services, to start a credential from. */
const presets: { name: string; kind: AccessKind; field?: string; destination: string; config?: Record<string, string>; note: string }[] = [
  { name: "GitHub", kind: "bearer", destination: "https://api.github.com", note: "A fine-grained personal access token" },
  { name: "GitHub App", kind: "github-app", destination: "https://api.github.com", config: { apiUrl: "https://api.github.com" }, note: "One-hour installation tokens, made on the hub" },
  { name: "OpenAI", kind: "bearer", destination: "https://api.openai.com", note: "An API key" },
  { name: "Anthropic", kind: "header", field: "x-api-key", destination: "https://api.anthropic.com", note: "An API key; agents add the anthropic-version header" },
  { name: "Stripe", kind: "bearer", destination: "https://api.stripe.com", note: "A restricted key" },
  { name: "Slack", kind: "bearer", destination: "https://slack.com/api", note: "A bot token" },
  { name: "Cloudflare", kind: "bearer", destination: "https://api.cloudflare.com/client/v4", note: "An API token" },
  { name: "Hugging Face", kind: "bearer", destination: "https://huggingface.co", note: "An access token" },
  { name: "Notion", kind: "bearer", destination: "https://api.notion.com", note: "An integration secret; agents add the Notion-Version header" },
  { name: "Microsoft Graph", kind: "oauth", destination: "https://graph.microsoft.com", config: { tokenUrl: "https://login.microsoftonline.com/TENANT/oauth2/v2.0/token", scope: "https://graph.microsoft.com/.default", auth: "body" }, note: "An app registration's client secret; short-lived tokens" },
  { name: "AWS S3", kind: "aws", destination: "https://s3.us-east-1.amazonaws.com", config: { region: "us-east-1", service: "s3" }, note: "An IAM key, best with a role for temporary keys" },
]

function ago(at: number) {
  const seconds = Math.max(0, Math.floor(Date.now() / 1000) - at)
  if (seconds < 60) return "just now"
  if (seconds < 3600) return `${Math.floor(seconds / 60)} min ago`
  if (seconds < 86_400) return `${Math.floor(seconds / 3600)} h ago`
  return new Date(at * 1000).toLocaleDateString()
}

function Field({ id, label, children, wide }: { id: string; label: string; children: ReactNode; wide?: boolean }) {
  return <div className={wide ? "grid-field grid-field-wide" : "grid-field"}><label htmlFor={id}>{label}</label>{children}</div>
}

function Armed({ label, armedLabel, onConfirm, destructive = true }: { label: string; armedLabel?: string; onConfirm(): void; destructive?: boolean }) {
  const { armed, arm, disarm } = useArmed()
  return <Button size="xs" variant={armed ? (destructive ? "destructive" : "default") : "ghost"} onClick={() => { if (armed) { disarm(); onConfirm() } else arm("go") }}>{armed ? (armedLabel ?? "Confirm") : label}</Button>
}

function Remove({ label, onConfirm }: { label: string; onConfirm(): void }) {
  const { armed, arm, disarm } = useArmed()
  return <Button size="xs" variant={armed ? "destructive" : "ghost"} aria-label={`Remove ${label}`} onClick={() => { if (armed) { disarm(); onConfirm() } else arm("remove") }}>{armed ? "Confirm" : "Remove"}</Button>
}

const teamsOf = (text: string) => text.split(",").map(team => team.trim()).filter(Boolean)

function PersonForm({ person, run, onDone, sso }: { person?: AccessPerson; run: AccessRun; onDone(): void; sso: boolean }) {
  const editing = Boolean(person)
  const [username, setUsername] = useState(person?.username ?? "")
  const [name, setName] = useState(person?.name ?? "")
  const [email, setEmail] = useState(person?.email ?? "")
  const [permission, setPermission] = useState<AccessPermission>(person?.permission ?? "member")
  const [teams, setTeams] = useState(person?.teams.join(", ") ?? "")
  const [password, setPassword] = useState("")
  const [again, setAgain] = useState("")
  const prefix = person ? `access-person-${person.id}` : "access-person-new"
  const problem = !editing && !/^[a-z0-9][a-z0-9._-]{2,31}$/i.test(username.trim()) ? "A username is 3–32 letters, digits, dots, dashes or underscores."
    : email.trim() && !/^[^@\s]+@[^@\s]+$/.test(email.trim()) ? "That email does not look right."
    : (!editing || password) && password.length < MIN_PASSWORD ? `A password has at least ${MIN_PASSWORD} characters.`
    : password !== again ? "The passwords do not match."
    : ""
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (problem) return
    const ok = person
      ? await run(`Saving ${person.username}`, async () => {
        const result = await accessApi.manage({ action: "personUpdate", person: person.id, name: name.trim() || person.username, email: email.trim(), permission, teams: teamsOf(teams) })
        if (password) await accessApi.manage({ action: "personPassword", person: person.id, password })
        return result
      }, `${person.username} saved`)
      : await run(`Adding ${username.trim()}`, () => accessApi.manage({ action: "personAdd", username: username.trim(), name: name.trim(), email: email.trim(), permission, teams: teamsOf(teams), password }), `${username.trim()} added`)
    if (ok) {
      setPassword(""); setAgain("")
      if (!person) { setUsername(""); setName(""); setEmail(""); setTeams(""); setPermission("member") }
      onDone()
    }
  }
  return <form className="grid-inline-form access-form" aria-label={person ? `Edit ${person.username}` : "Add a person"} onSubmit={event => void save(event)}>
    <div className="grid-fields">
      {editing ? null : <Field id={`${prefix}-username`} label="Username"><Input id={`${prefix}-username`} value={username} autoComplete="off" placeholder="grace" onChange={event => setUsername(event.target.value)} /></Field>}
      <Field id={`${prefix}-name`} label="Name"><Input id={`${prefix}-name`} value={name} autoComplete="off" placeholder="Grace Hopper" onChange={event => setName(event.target.value)} /></Field>
      <Field id={`${prefix}-email`} label="Email"><Input id={`${prefix}-email`} value={email} autoComplete="off" placeholder={sso ? "As your identity provider knows them" : "For single sign-on, optional"} onChange={event => setEmail(event.target.value)} /></Field>
      <Field id={`${prefix}-permission`} label="Permission">
        <select id={`${prefix}-permission`} className="grid-select-field" value={permission} onChange={event => setPermission(event.target.value as AccessPermission)}>
          {Object.entries(permissions).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
        </select>
      </Field>
      <Field id={`${prefix}-teams`} label="Teams"><Input id={`${prefix}-teams`} value={teams} autoComplete="off" placeholder="Research, Ops" onChange={event => setTeams(event.target.value)} /></Field>
      <Field id={`${prefix}-password`} label={editing ? "New password" : "Password"}><Input id={`${prefix}-password`} type="password" value={password} autoComplete="new-password" placeholder={editing ? "Leave empty to keep it" : undefined} onChange={event => setPassword(event.target.value)} /></Field>
      <Field id={`${prefix}-again`} label="Type it again"><Input id={`${prefix}-again`} type="password" value={again} autoComplete="new-password" onChange={event => setAgain(event.target.value)} /></Field>
    </div>
    <div className="grid-form-actions">
      <Button type="submit" size="sm" disabled={Boolean(problem)} title={problem || undefined}>{editing ? "Save" : "Add person"}</Button>
      {editing ? <Button type="button" size="sm" variant="ghost" onClick={onDone}>Cancel</Button> : null}
      <p className="grid-hint">{problem || (editing ? "A new password ends their sign-ins on every computer." : "Give them the password privately, with the invite.")}</p>
    </div>
  </form>
}

function People({ overview, admin, run }: { overview: AccessOverview; admin: boolean; run: AccessRun }) {
  const [editing, setEditing] = useState<string | null>(null)
  const sso = Boolean(overview.sso)
  return <>
    <p className="access-intro">Each person signs in on their own computer with their own username and password{sso ? " or through your identity provider" : ""}. Their permission says what they may do besides using what the rules allow them.</p>
    {overview.people.map(person => <div key={person.id} className="access-row">
      <div className="grid-line">
        <strong>{person.name}</strong>
        <span className="grid-muted">{person.username}{person.email ? ` · ${person.email}` : ""} · {permissions[person.permission].split(" · ")[0]}{person.teams.length ? ` · ${person.teams.join(", ")}` : ""} · {person.twoStep ? "two-step on" : "two-step off"} · {person.devices.length} {person.devices.length === 1 ? "computer" : "computers"} · {person.lastSeenAt ? `signed in ${ago(person.lastSeenAt)}` : "not signed in yet"}{person.id === overview.owner ? " · runs the grid" : ""}</span>
        {admin ? <span className="grid-line-actions">
          <Button size="xs" variant="outline" aria-expanded={editing === person.id} onClick={() => setEditing(current => current === person.id ? null : person.id)}>Edit</Button>
          {person.id === overview.owner ? null : <Remove label={person.username} onConfirm={() => void run(`Removing ${person.username}`, () => accessApi.manage({ action: "personRemove", person: person.id }), `${person.username} removed`)} />}
        </span> : null}
      </div>
      {editing === person.id ? <div className="access-row-form">
        <PersonForm person={person} run={run} sso={sso} onDone={() => setEditing(null)} />
        <div className="grid-line access-inline" role="group" aria-label={`Sign-ins of ${person.username}`}>
          <span className="grid-muted">Sign-ins</span>
          <Armed label="Sign out everywhere" onConfirm={() => void run(`Signing ${person.username} out`, () => accessApi.manage({ action: "personSignOut", person: person.id }), `${person.username} is signed out everywhere`)} />
          {person.twoStep ? <Armed label="Reset two-step" onConfirm={() => void run(`Resetting ${person.username}'s two-step sign-in`, () => accessApi.manage({ action: "personTwoStepReset", person: person.id }), "Two-step reset; they sign in again and can turn it on anew")} /> : null}
        </div>
        {person.devices.length ? <ul className="grid-part" aria-label={`Computers of ${person.username}`}>
          {person.devices.map(device => <li key={device.id} className="grid-line">
            <span className="grid-muted">{device.computer || "A computer"} · last used {ago(device.lastUsedAt)}{device.strong ? " · with a second factor" : ""}</span>
            <span className="grid-line-actions"><Armed label="Sign out" onConfirm={() => void run("Signing that computer out", () => accessApi.manage({ action: "deviceRevoke", person: person.id, device: device.id }), "Signed out")} /></span>
          </li>)}
        </ul> : null}
      </div> : null}
    </div>)}
    {admin ? <div className="access-add"><p className="grid-part-title">Add a person</p><PersonForm run={run} sso={sso} onDone={() => undefined} /></div> : null}
  </>
}

function CredentialForm({ run }: { run: AccessRun }) {
  const [preset, setPreset] = useState("")
  const [name, setName] = useState("")
  const [kind, setKind] = useState<AccessKind>("bearer")
  const [field, setField] = useState("")
  const [destinations, setDestinations] = useState("")
  const [value, setValue] = useState("")
  const [note, setNote] = useState("")
  const [config, setConfig] = useState<Record<string, string>>({})
  const places = destinations.split(/[\n,]/).map(place => place.trim()).filter(Boolean)
  const settings = settingsOf[kind] ?? []
  const needsField = Boolean(fieldLabels[kind])
  const missing = settings.find(([key, , , required]) => required && !config[key]?.trim())
  const problem = !name.trim() ? "Name the credential, such as GitHub."
    : needsField && !field.trim() ? `Give the ${(fieldLabels[kind]?.[0] ?? "field").toLowerCase()}.`
    : missing ? `Give the ${missing[1].toLowerCase()}.`
    : !places.length ? "Give at least one destination, such as https://api.github.com."
    : places.some(place => !/^https?:\/\//i.test(place)) ? "Destinations start with https:// (http:// only for private addresses)."
    : !value ? `Enter the ${valueLabels[kind][0].toLowerCase()}.`
    : ""
  const choose = (chosen: string) => {
    setPreset(chosen)
    const found = presets.find(item => item.name === chosen)
    if (!found) return
    setName(found.name); setKind(found.kind); setField(found.field ?? ""); setDestinations(found.destination); setConfig(found.config ?? {}); setNote(found.note)
  }
  const readFile = async (file: File | undefined) => {
    if (file) setValue(await file.text())
  }
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (problem) return
    const settingsGiven = Object.fromEntries(Object.entries(config).map(([key, text]) => [key, text.trim()]).filter(([key, text]) => text && settings.some(([own]) => own === key)))
    const ok = await run(`Adding ${name.trim()}`, () => accessApi.manage({ action: "credentialAdd", name: name.trim(), kind, field: field.trim(), destinations: places, value, note: note.trim(), config: settingsGiven }), `${name.trim()} added`)
    if (ok) { setPreset(""); setName(""); setField(""); setDestinations(""); setValue(""); setNote(""); setConfig({}) }
  }
  return <form className="grid-inline-form access-form" aria-label="Add a credential" onSubmit={event => void save(event)}>
    <div className="grid-fields">
      <Field id="access-credential-preset" label="Start from">
        <select id="access-credential-preset" className="grid-select-field" value={preset} onChange={event => choose(event.target.value)}>
          <option value="">Any service</option>
          {presets.map(item => <option key={item.name} value={item.name}>{item.name}</option>)}
        </select>
      </Field>
      <Field id="access-credential-name" label="Name"><Input id="access-credential-name" value={name} autoComplete="off" placeholder="GitHub" onChange={event => setName(event.target.value)} /></Field>
      <Field id="access-credential-kind" label="Sent as">
        <select id="access-credential-kind" className="grid-select-field" value={kind} onChange={event => { setKind(event.target.value as AccessKind); setValue("") }}>
          {Object.entries(kinds).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select>
      </Field>
      {needsField ? <Field id="access-credential-field" label={fieldLabels[kind]?.[0] ?? "Field"}><Input id="access-credential-field" value={field} autoComplete="off" placeholder={fieldLabels[kind]?.[1]} onChange={event => setField(event.target.value)} /></Field> : null}
      {settings.map(([key, label, placeholder]) => <Field key={key} id={`access-credential-${key}`} label={label}>
        <Input id={`access-credential-${key}`} value={config[key] ?? ""} autoComplete="off" spellCheck={false} placeholder={placeholder} onChange={event => setConfig(current => ({ ...current, [key]: event.target.value }))} />
      </Field>)}
      {kind === "github-app" ? <Field id="access-credential-value" label={valueLabels[kind][0]} wide>
        <textarea id="access-credential-value" className="grid-textarea" value={value} spellCheck={false} placeholder={valueLabels[kind][1]} onChange={event => setValue(event.target.value)} />
        <input type="file" accept=".pem" aria-label="Read the private key from a file" onChange={event => void readFile(event.target.files?.[0])} />
      </Field> : <Field id="access-credential-value" label={valueLabels[kind][0]}><Input id="access-credential-value" type="password" value={value} autoComplete="off" placeholder={valueLabels[kind][1]} onChange={event => setValue(event.target.value)} /></Field>}
      <Field id="access-credential-destinations" label="Destinations, one per line" wide>
        <textarea id="access-credential-destinations" className="grid-textarea" value={destinations} spellCheck={false} placeholder="https://api.github.com" onChange={event => setDestinations(event.target.value)} />
      </Field>
      <Field id="access-credential-note" label="Note" wide><Input id="access-credential-note" value={note} autoComplete="off" placeholder="What it is for" onChange={event => setNote(event.target.value)} /></Field>
    </div>
    <div className="grid-form-actions">
      <Button type="submit" size="sm" disabled={Boolean(problem)} title={problem || undefined}>Add credential</Button>
      <p className="grid-hint">{problem || (kind === "oauth" || kind === "github-app" || kind === "aws" ? "The hub makes short-lived tokens from it; agents, and even approved reveals, only ever get those." : "The value is sealed on the computer that runs the grid. Agents use it only through rules, and only at these destinations.")}</p>
    </div>
  </form>
}

function ReplaceValue({ credential, run, onDone }: { credential: AccessCredential; run: AccessRun; onDone(): void }) {
  const [value, setValue] = useState("")
  const pem = credential.kind === "github-app"
  const submit = (event: FormEvent) => {
    event.preventDefault()
    if (value) void run(`Replacing ${credential.name}'s value`, () => accessApi.manage({ action: "credentialUpdate", credential: credential.id, value }), `${credential.name}'s value replaced`).then(ok => { if (ok) { setValue(""); onDone() } })
  }
  return <form className="grid-line access-inline" aria-label={`Replace the value of ${credential.name}`} onSubmit={submit}>
    {pem ? <textarea className="grid-textarea" aria-label={`New private key of ${credential.name}`} value={value} spellCheck={false} placeholder={valueLabels[credential.kind][1]} onChange={event => setValue(event.target.value)} />
      : <Input type="password" aria-label={`New value of ${credential.name}`} value={value} autoComplete="off" placeholder="New value" onChange={event => setValue(event.target.value)} />}
    <Button type="submit" size="xs" disabled={!value}>Replace</Button>
    <Button type="button" size="xs" variant="ghost" onClick={onDone}>Cancel</Button>
  </form>
}

function configText(credential: AccessCredential) {
  const config = credential.config ?? {}
  const parts = (settingsOf[credential.kind] ?? []).filter(([key]) => config[key] !== undefined && config[key] !== "").map(([key, label]) => `${label.toLowerCase()} ${config[key]}`)
  return parts.length ? ` · ${parts.join(", ")}` : ""
}

function Credentials({ overview, admin, run }: { overview: AccessOverview; admin: boolean; run: AccessRun }) {
  const [replacing, setReplacing] = useState<string | null>(null)
  return <>
    <p className="access-intro">A credential is sent only to its destinations, and only on requests a rule allows. Its value is sealed on the computer that runs the grid and is never shown again. OAuth, GitHub App and AWS credentials go out as short-lived tokens or signatures only.</p>
    {overview.credentials.length ? overview.credentials.map(credential => <div key={credential.id} className="access-row">
      <div className="grid-line">
        <strong>{credential.name}</strong>
        <span className="grid-muted" title={credential.destinations.join(", ")}>{kinds[credential.kind]}{credential.field ? ` ${credential.field}` : ""}{configText(credential)} · {credential.destinations.join(", ")}{credential.hint ? ` · ends in ${credential.hint}` : ""} · {credential.rules} {credential.rules === 1 ? "rule" : "rules"}{credential.note ? ` · ${credential.note}` : ""}</span>
        {admin ? <span className="grid-line-actions">
          <Button size="xs" variant="outline" aria-expanded={replacing === credential.id} onClick={() => setReplacing(current => current === credential.id ? null : credential.id)}>Replace value</Button>
          <Remove label={credential.name} onConfirm={() => void run(`Removing ${credential.name}`, () => accessApi.manage({ action: "credentialRemove", credential: credential.id }), `${credential.name} and its rules removed`)} />
        </span> : null}
      </div>
      {replacing === credential.id ? <ReplaceValue credential={credential} run={run} onDone={() => setReplacing(null)} /> : null}
    </div>) : <p className="grid-line grid-muted">No credentials yet.</p>}
    {admin ? <div className="access-add"><p className="grid-part-title">Add a credential</p><CredentialForm run={run} /></div> : null}
  </>
}

function RuleForm({ overview, run }: { overview: AccessOverview; run: AccessRun }) {
  const teams = [...new Set(overview.people.flatMap(person => person.teams))].sort((a, b) => a.localeCompare(b))
  const [credential, setCredential] = useState(overview.credentials[0]?.id ?? "")
  const [who, setWho] = useState("everyone")
  const [team, setTeam] = useState("")
  const [methods, setMethods] = useState<string[]>([])
  const [path, setPath] = useState("")
  const [decision, setDecision] = useState<AccessDecision>("allow")
  const [reveal, setReveal] = useState(false)
  const [hours, setHours] = useState("")
  const [limit, setLimit] = useState("")
  const target = who === "team:" ? `team:${team.trim()}` : who
  const problem = !credential ? "Add a credential first."
    : who === "team:" && !team.trim() ? "Name the team."
    : path.trim() && !path.trim().startsWith("/") ? "A path starts with /, such as /repos/acme."
    : hours.trim() && !(Number(hours) > 0) ? "Hours is a positive number."
    : limit.trim() && !(Number.isInteger(Number(limit)) && Number(limit) > 0) ? "The hourly limit is a whole number of uses."
    : limit.trim() && decision !== "allow" ? "An hourly limit belongs to an At once rule."
    : ""
  const save = async (event: FormEvent) => {
    event.preventDefault()
    if (problem) return
    const ok = await run("Adding the rule", () => accessApi.manage({ action: "ruleAdd", credential, who: target, methods, path: path.trim(), decision, reveal, ...(hours.trim() ? { hours: Number(hours) } : {}), ...(limit.trim() ? { limit: Number(limit) } : {}) }), "Rule added")
    if (ok) { setPath(""); setHours(""); setLimit(""); setMethods([]); setReveal(false) }
  }
  const toggle = (method: string) => setMethods(current => current.includes(method) ? current.filter(own => own !== method) : [...current, method])
  return <form className="grid-inline-form access-form" aria-label="Add a rule" onSubmit={event => void save(event)}>
    <div className="grid-fields">
      <Field id="access-rule-credential" label="Credential">
        <select id="access-rule-credential" className="grid-select-field" value={credential} onChange={event => setCredential(event.target.value)}>
          {overview.credentials.map(item => <option key={item.id} value={item.id}>{item.name}</option>)}
        </select>
      </Field>
      <Field id="access-rule-who" label="Who">
        <select id="access-rule-who" className="grid-select-field" value={who} onChange={event => setWho(event.target.value)}>
          <option value="everyone">Everyone</option>
          {teams.map(name => <option key={name} value={`team:${name}`}>Team {name}</option>)}
          <option value="team:">Another team…</option>
          {overview.people.map(person => <option key={person.id} value={`person:${person.username}`}>{person.name} ({person.username})</option>)}
        </select>
      </Field>
      {who === "team:" ? <Field id="access-rule-team" label="Team"><Input id="access-rule-team" value={team} autoComplete="off" placeholder="Research" onChange={event => setTeam(event.target.value)} /></Field> : null}
      <Field id="access-rule-decision" label="Decision">
        <select id="access-rule-decision" className="grid-select-field" value={decision} onChange={event => setDecision(event.target.value as AccessDecision)}>
          {Object.entries(decisions).map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select>
      </Field>
      <Field id="access-rule-path" label="Path prefix"><Input id="access-rule-path" value={path} autoComplete="off" spellCheck={false} placeholder="Any path, or /repos/acme" onChange={event => setPath(event.target.value)} /></Field>
      <Field id="access-rule-limit" label="Uses an hour at once"><Input id="access-rule-limit" value={limit} inputMode="numeric" autoComplete="off" placeholder="No limit" onChange={event => setLimit(event.target.value)} /></Field>
      <Field id="access-rule-hours" label="Lapses after (hours)"><Input id="access-rule-hours" value={hours} inputMode="decimal" autoComplete="off" placeholder="Never" onChange={event => setHours(event.target.value)} /></Field>
      <div className="grid-field grid-field-wide">
        <span className="grid-field-label">Methods</span>
        <div className="access-methods" role="group" aria-label="Methods">
          {METHODS.map(method => <label key={method} className="grid-check-field"><input type="checkbox" checked={methods.includes(method)} onChange={() => toggle(method)} />{method}</label>)}
        </div>
      </div>
      <div className="grid-field grid-field-wide">
        <span className="grid-field-label">The value itself</span>
        <label className="grid-check-field"><input type="checkbox" checked={reveal} onChange={event => setReveal(event.target.checked)} />They may also ask to have it (a short-lived token for OAuth, GitHub App and AWS); an approver decides each time</label>
      </div>
    </div>
    <div className="grid-form-actions">
      <Button type="submit" size="sm" disabled={Boolean(problem)} title={problem || undefined}>Add rule</Button>
      <p className="grid-hint">{problem || (methods.length ? `Only ${methods.join(", ")}.` : "No method ticked means any method.")} A matching Never wins; otherwise At once wins over An approver decides. Past an hourly limit, an approver decides.</p>
    </div>
  </form>
}

function ruleLine(rule: AccessRule) {
  const methods = rule.methods.length ? rule.methods.join(", ") : "any method"
  const lapses = rule.expiresAt ? ` · until ${new Date(rule.expiresAt * 1000).toLocaleString()}` : ""
  const limit = rule.limit ? ` · ${rule.limit} an hour, then an approver decides` : ""
  return `${methods} ${rule.path || "any path"} · ${decisions[rule.decision].toLowerCase()}${limit}${rule.reveal ? " · may ask to have the value" : ""}${lapses}${rule.note ? ` · ${rule.note}` : ""}`
}

function Rules({ overview, admin, run }: { overview: AccessOverview; admin: boolean; run: AccessRun }) {
  return <>
    <p className="access-intro">A rule says who may use a credential, for which methods and path, and whether an approver decides first. With no matching rule, a request is refused.</p>
    {overview.rules.length ? overview.rules.map(rule => <div key={rule.id} className="grid-line">
      <strong>{rule.whoLabel} · {rule.credentialName ?? "removed credential"}</strong>
      <span className="grid-muted" title={`${ruleLine(rule)} · added by ${rule.createdBy}`}>{ruleLine(rule)}</span>
      {admin ? <span className="grid-line-actions"><Remove label={`rule for ${rule.whoLabel}`} onConfirm={() => void run("Removing the rule", () => accessApi.manage({ action: "ruleRemove", rule: rule.id }), "Rule removed")} /></span> : null}
    </div>) : <p className="grid-line grid-muted">No rules yet, so nobody can use any credential.</p>}
    {admin && overview.credentials.length ? <div className="access-add"><p className="grid-part-title">Add a rule</p><RuleForm overview={overview} run={run} /></div> : null}
  </>
}

function SsoForm({ overview, run }: { overview: AccessOverview; run: AccessRun }) {
  const [issuer, setIssuer] = useState(overview.sso?.issuer ?? "")
  const [clientId, setClientId] = useState(overview.sso?.clientId ?? "")
  const [claim, setClaim] = useState(overview.sso?.claim ?? "email")
  const [passwordless, setPasswordless] = useState(overview.sso?.passwordless ?? false)
  const [port, setPort] = useState(overview.sso?.redirectPort ? String(overview.sso.redirectPort) : "")
  const portNumber = Number(port.trim())
  const problem = !/^https?:\/\//.test(issuer.trim()) ? "Give the issuer, your identity provider's https:// address." : !clientId.trim() ? "Give the client ID of the app you registered there." : port.trim() && !(Number.isInteger(portNumber) && portNumber >= 1024 && portNumber <= 65535) ? "The sign-in port is a number from 1024 to 65535, or empty." : ""
  const save = (event: FormEvent) => {
    event.preventDefault()
    if (problem) return
    void run("Setting up single sign-on", () => accessApi.manage({ action: "ssoSet", issuer: issuer.trim(), clientId: clientId.trim(), claim: claim.trim() || "email", passwordless, redirectPort: port.trim() ? portNumber : null }), "Single sign-on is set")
  }
  return <form className="grid-inline-form access-form" aria-label="Single sign-on" onSubmit={save}>
    <div className="grid-fields">
      <Field id="access-sso-issuer" label="Issuer"><Input id="access-sso-issuer" value={issuer} spellCheck={false} autoComplete="off" placeholder="https://login.microsoftonline.com/TENANT/v2.0" onChange={event => setIssuer(event.target.value)} /></Field>
      <Field id="access-sso-client" label="Client ID"><Input id="access-sso-client" value={clientId} spellCheck={false} autoComplete="off" placeholder="The app registered for Yougori" onChange={event => setClientId(event.target.value)} /></Field>
      <Field id="access-sso-claim" label="Matched claim"><Input id="access-sso-claim" value={claim} spellCheck={false} autoComplete="off" placeholder="email" onChange={event => setClaim(event.target.value)} /></Field>
      <Field id="access-sso-port" label="Sign-in port"><Input id="access-sso-port" value={port} inputMode="numeric" spellCheck={false} autoComplete="off" placeholder="Any (Entra); fixed for Okta" onChange={event => setPort(event.target.value)} /></Field>
      <div className="grid-field grid-field-wide">
        <span className="grid-field-label">Passwords</span>
        <label className="grid-check-field"><input type="checkbox" checked={passwordless} onChange={event => setPasswordless(event.target.checked)} />Only the identity provider signs people in (the person who runs the grid keeps their password)</label>
      </div>
    </div>
    <div className="grid-form-actions">
      <Button type="submit" size="sm" disabled={Boolean(problem)} title={problem || undefined}>{overview.sso ? "Save" : "Turn on single sign-on"}</Button>
      {overview.sso ? <Armed label="Turn off" onConfirm={() => void run("Turning off single sign-on", () => accessApi.manage({ action: "ssoClear" }), "Single sign-on is off")} /> : null}
      <p className="grid-hint">{problem || `Register a public (native) app with PKCE at your provider, redirect address ${port.trim() ? `http://127.0.0.1:${port.trim()}/callback` : "http://127.0.0.1/callback (Entra: Mobile and desktop, added in the app manifest)"}. Okta matches the port: set one here and register it. People are matched by the claim against their email here. The provider's own second factor counts as two-step.`}</p>
    </div>
  </form>
}

function Settings({ overview, admin, run }: { overview: AccessOverview; admin: boolean; run: AccessRun }) {
  const required = overview.settings.requireTwoStep
  return <>
    <p className="access-intro">Sign-in rules for everyone in the grid.</p>
    <div className="grid-line">
      <span className="grid-key">Two-step</span>
      <span className="grid-muted">{required ? "Required: without two-step codes or single sign-on, people and their agents can use, see and manage nothing" : "Optional: each person chooses"}</span>
      {admin ? <span className="grid-line-actions"><Button size="xs" variant="outline" onClick={() => void run(required ? "Making two-step optional" : "Requiring two-step sign-in", () => accessApi.manage({ action: "settingsSet", requireTwoStep: !required }), required ? "Two-step is optional" : "Two-step is required")}>{required ? "Make optional" : "Require"}</Button></span> : null}
    </div>
    <div className="grid-line">
      <span className="grid-key">Single sign-on</span>
      <span className="grid-muted">{overview.sso ? `Through ${overview.sso.issuer}, matching ${overview.sso.claim}${overview.sso.passwordless ? "; passwords no longer sign people in" : ""}` : "Off: people sign in with their passwords"}</span>
    </div>
    {admin ? <div className="access-add"><SsoForm key={overview.sso?.issuer ?? "none"} overview={overview} run={run} /></div> : null}
  </>
}

function Activity({ overview, run }: { overview: AccessOverview; run: AccessRun }) {
  const [verified, setVerified] = useState<{ ok: boolean; entries: number; brokenAt?: number; reason?: string } | null>(null)
  const verify = () => void run("Checking the activity log", async () => {
    const result = await accessApi.manage({ action: "activityVerify" }) as unknown as { ok: boolean; entries: number; brokenAt?: number; reason?: string }
    setVerified(result)
    return result
  })
  return <>
    <p className="access-intro">Every use, refusal, decision, sign-in and change, newest first. URLs are kept without their query; values never appear. Each entry is chained to the one before, so a changed or removed entry shows. Export it with yougori access log --export FILE.</p>
    <div className="grid-line">
      <Button size="xs" variant="outline" onClick={verify}>Check the chain</Button>
      {verified ? <span className="grid-muted" role="status">{verified.ok ? `The chain checks out: ${verified.entries} entries.` : `The chain breaks at entry ${verified.brokenAt} of ${verified.entries}: ${verified.reason}.`}</span> : null}
    </div>
    {overview.activity.length ? overview.activity.map((entry, index) => <div key={`${entry.at}-${index}`} className="grid-line">
      <span className="grid-key">{ago(entry.at)}</span>
      <strong>{entry.person || "unknown"}</strong>
      <span className="grid-muted" title={[entry.action, entry.credential, entry.target, entry.outcome, entry.agent, entry.computer].filter(Boolean).join(" · ")}>
        {entry.action}{entry.credential ? ` ${entry.credential}` : ""}{entry.target ? ` · ${entry.target}` : ""} · {entry.outcome}{entry.agent ? ` · ${entry.agent}` : ""}
      </span>
    </div>) : <p className="grid-line grid-muted">Nothing yet.</p>}
  </>
}

/** The whole grid for approvers, auditors and admins; only admins change it. */
export function AccessAdmin({ me, overview, run }: { me: AccessMe; overview: AccessOverview; run: AccessRun }) {
  const [tab, setTab] = useState<Tab>("People")
  const admin = me.person.permission === "admin"
  return <div className="grid-sheet">
    <details className="grid-part access-fold" open>
      <summary className="grid-part-title">{admin ? "Manage" : "The grid"} <span>{admin ? "people, credentials, rules, sign-in and activity" : `read only, as ${me.person.permission}`}</span></summary>
      <div className="access-tabs" role="tablist" aria-label="Access Grid sections">
        {tabs.map((name, index) => <button key={name} type="button" role="tab" id={`access-tab-${index}`} aria-controls="access-panel" aria-selected={tab === name} onClick={() => setTab(name)}>
          {name}{name === "People" ? ` ${overview.people.length}` : name === "Credentials" ? ` ${overview.credentials.length}` : name === "Rules" ? ` ${overview.rules.length}` : ""}
        </button>)}
      </div>
      <div id="access-panel" role="tabpanel" aria-labelledby={`access-tab-${tabs.indexOf(tab)}`} className="access-panel">
        {tab === "People" ? <People overview={overview} admin={admin} run={run} />
          : tab === "Credentials" ? <Credentials overview={overview} admin={admin} run={run} />
          : tab === "Rules" ? <Rules overview={overview} admin={admin} run={run} />
          : tab === "Settings" ? <Settings overview={overview} admin={admin} run={run} />
          : <Activity overview={overview} run={run} />}
      </div>
    </details>
  </div>
}
