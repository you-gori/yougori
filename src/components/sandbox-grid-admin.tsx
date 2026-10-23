import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react"
import { desksApi, type DeskAccess, type DeskKind, type EnterpriseConnection, type EnterpriseProvider, type EnterpriseStatus } from "@/api/desks-api"
import { say } from "@/api/grids/errors"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { open } from "@tauri-apps/plugin-dialog"
import { workspaceApi } from "@/api/workspace-api"
import "./sandbox-grid-admin.css"

type Change = (request: Record<string, unknown>) => Promise<boolean>
const providers: Record<EnterpriseProvider, string> = { citrix: "Citrix", azureVirtualDesktop: "Azure Virtual Desktop", windows365: "Windows 365", horizon: "Omnissa Horizon" }
const providerGuides: Record<EnterpriseProvider, string> = {
  citrix: "https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/policies/reference/ica-policy-settings/clipboard-redirection/overview.html",
  azureVirtualDesktop: "https://learn.microsoft.com/en-us/azure/virtual-desktop/redirection-configure-clipboard",
  windows365: "https://learn.microsoft.com/en-us/windows-365/enterprise/manage-rdp-device-redirections",
  horizon: "https://docs.omnissa.com/HorizonClientLinuxGuide-Vmulti/CopyingandPastingText",
}
const tabs = ["Permissions", "Images", "Workspace roles", "Company workspaces", "Settings", "Activity"] as const
/** Each provider's credential: the identifiers the admin sees again, and the one secret that goes to the hub computer's vault. */
const credentialFields: Record<EnterpriseProvider, { key: string; label: string; secret?: boolean; hint?: string }[]> = {
  azureVirtualDesktop: [
    { key: "tenantId", label: "Entra tenant ID" }, { key: "clientId", label: "App registration client ID" }, { key: "clientSecret", label: "Client secret", secret: true },
    { key: "subscriptionId", label: "Subscription ID" }, { key: "resourceGroup", label: "Resource group" }, { key: "applicationGroup", label: "Application group", hint: "People get the Desktop Virtualization User role on it. The app needs User Access Administrator on the group and User.Read.All in Graph." },
  ],
  windows365: [
    { key: "tenantId", label: "Entra tenant ID" }, { key: "clientId", label: "App registration client ID" }, { key: "clientSecret", label: "Client secret", secret: true },
    { key: "groupId", label: "Group object ID", hint: "The group the provisioning policy is assigned to; people are added to it. The app needs GroupMember.ReadWrite.All and User.Read.All." },
  ],
  citrix: [
    { key: "customerId", label: "Citrix Cloud customer ID" }, { key: "clientId", label: "API client ID" }, { key: "clientSecret", label: "API client secret", secret: true },
    { key: "deliveryGroup", label: "Delivery group", hint: "People are added to its users." },
  ],
  horizon: [
    { key: "username", label: "Administrator username" }, { key: "domain", label: "Domain" }, { key: "password", label: "Password", secret: true },
    { key: "pool", label: "Desktop pool ID", hint: "People are entitled to it. The REST API is on the workspace URL above." },
  ],
}
type Tab = typeof tabs[number]

function Field({ label, children, hint }: { label: string; children: ReactNode; hint?: string }) {
  return <label className="desk-admin-field"><span>{label}</span>{children}{hint ? <small>{hint}</small> : null}</label>
}

function Remove({ label, request, change, disabled }: { label: string; request: Record<string, unknown>; change: Change; disabled?: boolean }) {
  const [armed, setArmed] = useState(false)
  return <span className="desk-admin-inline"><Button type="button" size="xs" variant={armed ? "destructive" : "ghost"} disabled={disabled} aria-label={`Remove ${label}`} onClick={() => { if (!armed) setArmed(true); else void change(request).then(ok => { if (ok) setArmed(false) }) }}>{armed ? "Confirm" : "Remove"}</Button>{armed ? <Button size="xs" variant="ghost" onClick={() => setArmed(false)}>Cancel</Button> : null}</span>
}

/** Who may manage the grid, and which workspace role each person's future desks take. People
 *  themselves are added on the page above, with their desk. */
function Permissions({ data, change, disabled }: { data: EnterpriseStatus; change: Change; disabled: boolean }) {
  const admin = data.adminRole === "administrator"
  return <>
    <p className="desk-admin-intro">Administrative permission says who may manage this grid. A workspace role, when the catalog has one, chooses the image and access policy of a person's future desks; desks already built keep theirs.</p>
    {data.people.length ? data.people.map(person => <div className="grid-line desk-admin-row" key={person.id}>
      <strong>{person.name}</strong>
      <span className="grid-muted">{person.username}{person.mfa ? " · two-step on" : ""}</span>
      <span className="grid-line-actions">
        <select className="grid-select-field" aria-label={`Administrative permission for ${person.name}`} value={person.adminRole ?? "user"} disabled={disabled || !admin} onChange={event => void change({ action: "personUpdate", id: person.id, adminRole: event.target.value })}>
          <option value="user">Workspace user</option><option value="auditor">Auditor · read only</option><option value="operator">Operator · desks and computers</option><option value="administrator">Administrator</option>
        </select>
        {data.enterprise.roles.length ? <select className="grid-select-field" aria-label={`Workspace role for ${person.name}`} value={person.roleId ?? ""} disabled={disabled || !admin} onChange={event => void change({ action: "personUpdate", id: person.id, roleId: event.target.value || null })}><option value="">No workspace role</option>{data.enterprise.roles.map(role => <option key={role.id} value={role.id}>{role.name}</option>)}</select> : null}
        {admin ? <EmailField person={person} change={change} disabled={disabled} /> : null}
        {admin ? <ResetPassword person={person} change={change} disabled={disabled} /> : null}
        {admin && person.mfa ? <Button size="xs" variant="ghost" title="Clears their authenticator; they set it up again" onClick={() => void change({ action: "mfaReset", id: person.id })}>Reset two-step</Button> : null}
      </span>
    </div>) : <p className="grid-line grid-muted">No people yet. Add them on the page above, each with their desk.</p>}
  </>
}

/** The email the identity provider and the connectors know a person by. */
function EmailField({ person, change, disabled }: { person: EnterpriseStatus["people"][number]; change: Change; disabled: boolean }) {
  const [email, setEmail] = useState(person.email ?? "")
  const [open, setOpen] = useState(false)
  if (!open) return <Button size="xs" variant="ghost" onClick={() => { setEmail(person.email ?? ""); setOpen(true) }}>{person.email ? person.email : "Add email"}</Button>
  return <form className="desk-admin-inline" aria-label={`Email for ${person.name}`} onSubmit={event => { event.preventDefault(); void change({ action: "personUpdate", id: person.id, email: email.trim() }).then(ok => { if (ok) setOpen(false) }) }}>
    <Input size="sm" type="email" aria-label={`Email for ${person.name}`} placeholder="ada@company.example" maxLength={254} value={email} onChange={event => setEmail(event.target.value)} />
    <Button type="submit" size="xs" disabled={disabled} title="Company sign-in and connectors match people by this email">Save</Button>
    <Button type="button" size="xs" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
  </form>
}

function ResetPassword({ person, change, disabled }: { person: EnterpriseStatus["people"][number]; change: Change; disabled: boolean }) {
  const [password, setPassword] = useState("")
  const [open, setOpen] = useState(false)
  if (!open) return <Button size="xs" variant="ghost" onClick={() => setOpen(true)}>Reset password</Button>
  return <form className="desk-admin-inline" aria-label={`New password for ${person.name}`} onSubmit={event => { event.preventDefault(); void change({ action: "personPassword", id: person.id, password }).then(ok => { if (ok) { setPassword(""); setOpen(false) } }) }}>
    <Input size="sm" type="password" aria-label={`New password for ${person.name}`} placeholder="New password, 10+ characters" minLength={10} maxLength={256} autoComplete="new-password" value={password} onChange={event => setPassword(event.target.value)} />
    <Button type="submit" size="xs" disabled={disabled || password.length < 10} title="Ends their current sign-ins and desk invitations">Save</Button>
    <Button type="button" size="xs" variant="ghost" onClick={() => setOpen(false)}>Cancel</Button>
  </form>
}

function Roles({ data, change, disabled }: { data: EnterpriseStatus; change: Change; disabled: boolean }) {
  const [name, setName] = useState(""), [description, setDescription] = useState(""), [imageId, setImage] = useState(""), [access, setAccess] = useState<DeskAccess>("restricted")
  const admin = data.adminRole === "administrator"
  return <>
    <p className="desk-admin-intro">A workspace role pairs a prepared image with an access policy, for teams such as “Research” or “IT operations”. Give a person the role under Permissions; their next desk is built from it.</p>
    {data.enterprise.roles.map(role => {
      const image = data.enterprise.images.find(entry => entry.id === role.imageId)
      return <div className="grid-line desk-admin-row" key={role.id}>
        <strong>{role.name}</strong>
        <span className="grid-muted">{image ? `${image.name} ${image.version}` : "image missing"} · {role.access === "restricted" ? "restricted" : "standard access"}{role.description ? ` · ${role.description}` : ""}{image?.applications.length ? ` · ${image.applications.join(", ")}` : ""}</span>
        {admin ? <span className="grid-line-actions"><Remove label={role.name} request={{ action: "roleRemove", id: role.id }} change={change} disabled={disabled} /></span> : null}
      </div>
    })}
    {admin ? <form className="grid-form-block" aria-label="New workspace role" onSubmit={event => { event.preventDefault(); void change({ action: "roleAdd", name, description, imageId, access }).then(ok => { if (ok) { setName(""); setDescription("") } }) }}>
      <div className="grid-fields">
        <Field label="Role name"><Input required value={name} maxLength={64} onChange={event => setName(event.target.value)} placeholder="Research" /></Field>
        <Field label="Prepared image"><select className="grid-select-field" required value={imageId} onChange={event => setImage(event.target.value)}><option value="">Choose an image</option>{data.enterprise.images.map(image => <option key={image.id} value={image.id}>{image.name} · {image.version}</option>)}</select></Field>
        <Field label="Data access"><select className="grid-select-field" value={access} onChange={event => setAccess(event.target.value as DeskAccess)}><option value="restricted">Restricted · desktop and uploads only</option><option value="standard">Standard · guest command access</option></select></Field>
        <Field label="Purpose"><Input value={description} maxLength={2000} onChange={event => setDescription(event.target.value)} placeholder="Optional" /></Field>
      </div>
      <div className="grid-form-actions">
        <Button size="sm" type="submit" disabled={disabled || !data.enterprise.images.length}>Create role</Button>
        <p className="grid-hint">{!data.enterprise.images.length ? "Publish an image first." : access === "restricted" ? "Restricted needs a prepared full VM: no guest network, no downloads, no command output, no outbound clipboard. What is on screen can still be photographed." : "Standard keeps guest commands and networking; use it where data may leave."}</p>
      </div>
    </form> : null}
  </>
}

function Images({ data, change, disabled }: { data: EnterpriseStatus; change: Change; disabled: boolean }) {
  const [name, setName] = useState(""), [version, setVersion] = useState("1"), [kind, setKind] = useState<DeskKind>("vm"), [image, setImage] = useState(""), [sha256, setSha] = useState(""), [applications, setApps] = useState(""), [description, setDescription] = useState("")
  const [cpu, setCpu] = useState("2"), [memory, setMemory] = useState("4"), [disk, setDisk] = useState("40")
  const [source, setSource] = useState("url"), [path, setPath] = useState(""), [fileError, setFileError] = useState("")
  const admin = data.adminRole === "administrator"
  const local = kind === "vm" && source === "file" && data.actor === "owner"
  const choose = async () => {
    try { setFileError(""); const selected = await open({ multiple: false, directory: false, filters: [{ name: "Prepared VM disks", extensions: ["qcow2", "raw", "img", "vhd", "vhdx", "vmdk"] }] }); if (typeof selected === "string") setPath(selected) }
    catch (reason) { setFileError(String(reason)) }
  }
  return <>
    <p className="desk-admin-intro">A prepared disk with its applications installed, or a container image pinned to its digest. Every computer checks the bytes against the checksum before a desk starts from them.</p>
    {data.enterprise.images.map(entry => <div className="grid-line desk-admin-row" key={entry.id}>
      <strong>{entry.name} {entry.version}</strong>
      <span className="grid-muted">{entry.spec.kind === "vm" ? "VM disk" : "container"} · {entry.spec.cpu} CPU · {entry.spec.memoryGb} GB memory · {entry.spec.diskGb} GB disk{entry.applications.length ? ` · ${entry.applications.join(", ")}` : ""}<code className="desk-admin-code">{entry.sha256 ? `sha256 ${entry.sha256.slice(0, 12)}…` : entry.spec.image}</code></span>
      {admin ? <span className="grid-line-actions"><Remove label={`${entry.name} ${entry.version}`} request={{ action: "imageRemove", id: entry.id }} change={change} disabled={disabled} /></span> : null}
    </div>)}
    {admin ? <form className="grid-form-block" aria-label="New image" onSubmit={event => { event.preventDefault(); void change({ action: local ? "imageImport" : "imageAdd", ...(local ? { path } : {}), name, version, description, applications: applications.split(",").map(entry => entry.trim()).filter(Boolean), spec: { kind, image, cpu: Number(cpu), memoryGb: Number(memory), diskGb: Number(disk), gpu: false }, sha256: kind === "vm" ? sha256.trim() : null }).then(ok => { if (ok) { setName(""); setImage(""); setSha(""); setPath("") } }) }}>
      <div className="grid-fields">
        <Field label="Image name"><Input required value={name} maxLength={64} onChange={event => setName(event.target.value)} placeholder="Research workstation" /></Field>
        <Field label="Version"><Input required value={version} maxLength={64} onChange={event => setVersion(event.target.value)} placeholder="2026.10" /></Field>
        <Field label="Image type"><select className="grid-select-field" value={kind} onChange={event => setKind(event.target.value as DeskKind)}><option value="vm">Prepared virtual machine disk</option><option value="container">Container image</option></select></Field>
        {kind === "vm" && data.actor === "owner" ? <Field label="Source"><select className="grid-select-field" value={source} onChange={event => setSource(event.target.value)}><option value="url">HTTPS download</option><option value="file">File on this computer</option></select></Field> : null}
        {local ? <div className="desk-admin-field"><span>Prepared disk file</span><Button type="button" size="sm" variant="outline" disabled={disabled} onClick={() => void choose()}>Choose disk image</Button><small>{path || "The grid keeps a private copy and hands it to the computers that need it."}</small>{fileError ? <p role="alert">{fileError}</p> : null}</div>
          : <Field label={kind === "vm" ? "Download URL" : "Image reference"} hint={kind === "vm" ? "HTTPS, reachable by every computer; a prepared QCOW2, RAW, VHD or VMDK disk." : "With @sha256: and the 64-character digest."}><Input required value={image} maxLength={4096} onChange={event => setImage(event.target.value)} placeholder={kind === "vm" ? "https://images.company.example/research.qcow2" : "registry.company.example/it@sha256:…"} /></Field>}
        {kind === "vm" && !local ? <Field label="SHA-256 checksum"><Input required pattern="[a-fA-F0-9]{64}" value={sha256} onChange={event => setSha(event.target.value)} /></Field> : null}
        <Field label="Installed applications" hint="Names separated by commas, already in the image."><Input value={applications} onChange={event => setApps(event.target.value)} placeholder="Python, RStudio" /></Field>
        <Field label="CPU cores"><Input type="number" required min={0.5} max={64} step={0.5} value={cpu} onChange={event => setCpu(event.target.value)} /></Field>
        <Field label="Memory (GB)"><Input type="number" required min={0.5} max={512} step={0.5} value={memory} onChange={event => setMemory(event.target.value)} /></Field>
        <Field label="Disk (GB)"><Input type="number" required min={1} max={2048} step={1} value={disk} onChange={event => setDisk(event.target.value)} /></Field>
        <Field label="Description"><Input value={description} maxLength={2000} onChange={event => setDescription(event.target.value)} placeholder="Optional" /></Field>
      </div>
      <div className="grid-form-actions"><Button size="sm" disabled={disabled || (local && !path)} type="submit">{disabled ? "Publishing…" : "Publish image"}</Button></div>
    </form> : null}
  </>
}

/** The credential fields of one provider, as a form fragment. Secret fields are password inputs. */
function CredentialFields({ provider, values, onChange }: { provider: EnterpriseProvider; values: Record<string, string>; onChange(values: Record<string, string>): void }) {
  return <>{credentialFields[provider].map(field => <Field key={field.key} label={field.label} hint={field.hint}><Input type={field.secret ? "password" : "text"} autoComplete={field.secret ? "new-password" : "off"} spellCheck={false} maxLength={512} value={values[field.key] ?? ""} onChange={event => onChange({ ...values, [field.key]: event.target.value })} /></Field>)}</>
}

function credentialComplete(provider: EnterpriseProvider, values: Record<string, string>) {
  return credentialFields[provider].every(field => (values[field.key] ?? "").trim())
}

/** One connection: open it, keep its credential, test it, assign people, read what happened. */
function ConnectionRow({ connection, data, change, disabled, onLaunchError }: { connection: EnterpriseConnection; data: EnterpriseStatus; change: Change; disabled: boolean; onLaunchError(text: string): void }) {
  const [editing, setEditing] = useState(false), [values, setValues] = useState<Record<string, string>>({}), [personId, setPerson] = useState("")
  const admin = data.adminRole === "administrator", operator = admin || data.adminRole === "operator", owner = data.actor === "owner"
  const tasks = (data.enterprise.provisioning ?? []).filter(task => task.connectionId === connection.id)
  const latest = tasks[tasks.length - 1]
  const candidates = data.people.filter(person => person.email)
  const outcome = (task: NonNullable<typeof latest>) => task.state === "pending" ? "waiting" : task.state === "running" ? "running" : task.note || task.state
  return <div className="grid-line desk-admin-row">
    <strong>{connection.name}</strong>
    <span className="grid-muted">
      {providers[connection.provider]} · {connection.roleIds.length ? connection.roleIds.map(id => data.enterprise.roles.find(role => role.id === id)?.name).join(", ") : "everyone signed in"}
      {connection.credentialSet ? ` · credential set${connection.credentialAt ? ` ${new Date(connection.credentialAt * 1000).toLocaleDateString()}` : ""}` : " · no credential: opens the portal only"}
      {latest ? <><br />{latest.want === "test" ? "Test" : `${latest.want === "assign" ? "Assign" : "Take back"} ${latest.personName || latest.email || ""}`}: {outcome(latest)}</> : null}
    </span>
    <span className="grid-line-actions">
      <Button type="button" variant="outline" size="xs" onClick={() => { onLaunchError(""); void workspaceApi.openUrl(connection.url).catch(reason => onLaunchError(String(reason))) }}>Open</Button>
      {operator && connection.credentialSet ? <Button type="button" size="xs" variant="ghost" disabled={disabled} onClick={() => void change({ action: "connectionTest", id: connection.id })}>Test</Button> : null}
      {operator && connection.credentialSet && candidates.length ? <span className="desk-admin-inline">
        <select className="grid-select-field" aria-label={`Person to assign at ${connection.name}`} value={personId} onChange={event => setPerson(event.target.value)}><option value="">Choose a person</option>{candidates.map(person => <option key={person.id} value={person.id}>{person.name}</option>)}</select>
        <Button type="button" size="xs" disabled={disabled || !personId} onClick={() => void change({ action: "connectionProvision", id: connection.id, personId })}>Assign</Button>
        <Button type="button" size="xs" variant="ghost" disabled={disabled || !personId} onClick={() => void change({ action: "connectionRevoke", id: connection.id, personId })}>Take back</Button>
      </span> : null}
      {admin && owner ? (editing
        ? <form className="desk-admin-inline" aria-label={`Credential for ${connection.name}`} onSubmit={event => { event.preventDefault(); void change({ action: "connectionCredential", id: connection.id, credential: values }).then(ok => { if (ok) { setEditing(false); setValues({}) } }) }}>
          <CredentialFields provider={connection.provider} values={values} onChange={setValues} />
          <Button type="submit" size="xs" disabled={disabled || !credentialComplete(connection.provider, values)}>Save credential</Button>
          <Button type="button" size="xs" variant="ghost" onClick={() => { setEditing(false); setValues({}) }}>Cancel</Button>
        </form>
        : <Button type="button" size="xs" variant="ghost" onClick={() => setEditing(true)}>{connection.credentialSet ? "Replace credential" : "Add credential"}</Button>) : null}
      {admin && owner && connection.credentialSet ? <Button type="button" size="xs" variant="ghost" disabled={disabled} title="Deletes the secret from this computer's vault" onClick={() => void change({ action: "connectionCredential", id: connection.id, set: false })}>Forget credential</Button> : null}
      {admin ? <Remove label={connection.name} request={{ action: "connectionRemove", id: connection.id }} change={change} disabled={disabled} /> : null}
    </span>
  </div>
}

function Connections({ data, change, disabled }: { data: EnterpriseStatus; change: Change; disabled: boolean }) {
  const [launchError, setLaunchError] = useState("")
  const [name, setName] = useState(""), [provider, setProvider] = useState<EnterpriseProvider>("citrix"), [url, setUrl] = useState(""), [roleIds, setRoles] = useState<string[]>([])
  const [withCredential, setWithCredential] = useState(false), [credential, setCredential] = useState<Record<string, string>>({})
  const admin = data.adminRole === "administrator", owner = data.actor === "owner"
  const tasks = [...(data.enterprise.provisioning ?? [])].reverse().slice(0, 20)
  return <>
    <p className="desk-admin-intro">Workspaces your company already runs on Citrix, Azure Virtual Desktop, Windows 365 or Omnissa Horizon, shown to people beside their desks. Without a credential they open the provider's own portal. With one, entered here on the computer that hosts the grid, Yougori also assigns people at the provider when you ask and takes it back when they are removed; the provider's own policies still apply.</p>
    {launchError ? <p role="alert" className="grid-line grid-error">{launchError}</p> : null}
    {data.enterprise.connections.map(connection => <ConnectionRow key={connection.id} connection={connection} data={data} change={change} disabled={disabled} onLaunchError={setLaunchError} />)}
    {admin ? <form className="grid-form-block" aria-label="New company workspace" onSubmit={event => { event.preventDefault(); void change({ action: "connectionAdd", name, provider, url, roleIds, ...(withCredential ? { credential } : {}) }).then(ok => { if (ok) { setName(""); setUrl(""); setRoles([]); setCredential({}); setWithCredential(false) } }) }}>
      <div className="grid-fields">
        <Field label="Name"><Input required maxLength={64} value={name} onChange={event => setName(event.target.value)} placeholder="Company research desktops" /></Field>
        <Field label="Provider"><select className="grid-select-field" value={provider} onChange={event => { setProvider(event.target.value as EnterpriseProvider); setCredential({}) }}>{Object.entries(providers).map(([key, label]) => <option key={key} value={key}>{label}</option>)}</select></Field>
        <Field label="HTTPS workspace URL"><Input required type="url" pattern="https://.*" value={url} onChange={event => setUrl(event.target.value)} placeholder={provider === "citrix" ? "https://company.cloud.com" : provider === "horizon" ? "https://horizon.company.example" : "https://windows.cloud.microsoft"} /></Field>
        {data.enterprise.roles.length ? <div className="desk-admin-field"><span>Shown to</span>{data.enterprise.roles.map(role => <label key={role.id} className="grid-check-field"><input type="checkbox" checked={roleIds.includes(role.id)} onChange={event => setRoles(ids => event.target.checked ? [...ids, role.id] : ids.filter(id => id !== role.id))} />{role.name}</label>)}<small>Nobody ticked means everyone signed in.</small></div> : null}
        {owner ? <div className="desk-admin-field"><span>Credential</span><label className="grid-check-field"><input type="checkbox" checked={withCredential} onChange={event => setWithCredential(event.target.checked)} />Let Yougori assign people at {providers[provider]}</label><small>The secret is kept in this computer's vault and never leaves it; the rest is shown again here.</small></div> : null}
        {owner && withCredential ? <CredentialFields provider={provider} values={credential} onChange={setCredential} /> : null}
      </div>
      <div className="grid-form-actions">
        <Button size="sm" type="submit" disabled={disabled || (withCredential && !credentialComplete(provider, credential))}>Add workspace</Button>
        <Button type="button" variant="ghost" size="sm" onClick={() => { setLaunchError(""); void workspaceApi.openUrl(providerGuides[provider]).catch(reason => setLaunchError(String(reason))) }}>{providers[provider]} policy guide</Button>
        <p className="grid-hint">{withCredential ? "Assign people from the row above once it is added; Test checks the credential without changing anything." : "Without a credential nothing is provisioned at the provider; clipboard, drive and network rules are set there."}</p>
      </div>
    </form> : null}
    {tasks.length ? <>
      <p className="desk-admin-intro">What the connectors were asked to do, latest first.</p>
      {tasks.map(task => <div className="grid-line desk-admin-row" key={task.id}><span className="grid-key">{new Date(task.at * 1000).toLocaleString()}</span><span className="grid-muted">{data.enterprise.connections.find(connection => connection.id === task.connectionId)?.name ?? task.connectionId} · {task.want}{task.personName ? ` ${task.personName}` : ""} · {task.state}{task.note ? ` · ${task.note}` : ""}</span></div>)}
    </> : null}
  </>
}

/** Where desks park while they move, the cloud computer that steps in, and the company's sign-in. */
function Settings({ data, change, disabled }: { data: EnterpriseStatus; change: Change; disabled: boolean }) {
  const admin = data.adminRole === "administrator", owner = data.actor === "owner"
  const { sso, parking, cloudFallback } = data.enterprise
  const [issuer, setIssuer] = useState(sso?.issuer ?? ""), [clientId, setClientId] = useState(sso?.clientId ?? ""), [claim, setClaim] = useState(sso?.usernameClaim ?? "email"), [passwordless, setPasswordless] = useState(Boolean(sso?.passwordless))
  const [parkProvider, setParkProvider] = useState<"awsS3" | "s3Compatible">(parking?.provider ?? "awsS3"), [location, setLocation] = useState(parking?.location ?? ""), [accessKey, setAccessKey] = useState(""), [secretKey, setSecretKey] = useState("")
  const [cloud, setCloud] = useState<Record<string, string>>({ provider: cloudFallback?.provider ?? "aws", account: cloudFallback?.account ?? "", region: cloudFallback?.region ?? "", image: cloudFallback?.image ?? "", imageProject: cloudFallback?.imageProject ?? "", machineType: cloudFallback?.machineType ?? "", subnet: cloudFallback?.subnet ?? "", securityGroup: cloudFallback?.securityGroup ?? "", keyPair: cloudFallback?.keyPair ?? "", resourceGroup: cloudFallback?.resourceGroup ?? "", sshPublicKey: cloudFallback?.sshPublicKey ?? "", username: cloudFallback?.username ?? "", identityFile: cloudFallback?.identityFile ?? "", maxComputers: String(cloudFallback?.maxComputers ?? 1) })
  const set = (key: string) => (event: { target: { value: string } }) => setCloud(values => ({ ...values, [key]: event.target.value }))
  const cloudFields: { key: string; label: string; show?: string[]; hint?: string }[] = [
    { key: "account", label: "Account or profile", hint: "The signed-in CLI profile (aws), project (gcloud) or subscription (az) on this computer." }, { key: "region", label: "Region or zone" }, { key: "image", label: "Linux image" },
    { key: "imageProject", label: "Image project", show: ["google"] }, { key: "machineType", label: "Machine type" }, { key: "subnet", label: "Subnet" },
    { key: "securityGroup", label: "Security group", show: ["aws", "azure"] }, { key: "keyPair", label: "EC2 key pair", show: ["aws"] }, { key: "resourceGroup", label: "Resource group", show: ["azure"] },
    { key: "sshPublicKey", label: "SSH public key file", show: ["azure", "google"] }, { key: "username", label: "SSH username" }, { key: "identityFile", label: "SSH private key file", hint: "On this computer; it installs Yougori on the new machine." }, { key: "maxComputers", label: "At most" },
  ]
  return <>
    <p className="desk-admin-intro">Every credential here is the company's own, typed once by its administrator. Nothing is provisioned or billed without one.</p>
    <form className="grid-form-block" aria-label="Company sign-in" onSubmit={event => { event.preventDefault(); void change({ action: "ssoSet", issuer: issuer.trim(), clientId: clientId.trim(), usernameClaim: claim.trim() || "email", passwordless }) }}>
      <div className="grid-fields">
        <Field label="Identity provider issuer" hint="Entra ID: https://login.microsoftonline.com/TENANT/v2.0 · Okta: https://company.okta.com · Google: https://accounts.google.com"><Input type="url" required value={issuer} maxLength={512} disabled={!admin} onChange={event => setIssuer(event.target.value)} /></Field>
        <Field label="Client ID" hint="A public native app (PKCE, no secret) whose redirect is http://127.0.0.1/callback on any port."><Input required value={clientId} maxLength={256} disabled={!admin} onChange={event => setClientId(event.target.value)} /></Field>
        <Field label="Email claim" hint="The token claim that carries the person's email; matched to the emails under Permissions."><Input value={claim} maxLength={64} disabled={!admin} onChange={event => setClaim(event.target.value)} /></Field>
        <div className="desk-admin-field"><span>Passwords</span><label className="grid-check-field"><input type="checkbox" checked={passwordless} disabled={!admin} onChange={event => setPasswordless(event.target.checked)} />Only the identity provider signs people in</label></div>
      </div>
      <div className="grid-form-actions">
        <Button size="sm" type="submit" disabled={disabled || !admin}>{sso ? "Save sign-in" : "Turn on company sign-in"}</Button>
        {sso && admin ? <Button size="sm" type="button" variant="ghost" disabled={disabled} onClick={() => void change({ action: "ssoClear" })}>Turn off</Button> : null}
        <p className="grid-hint">{sso ? `On since ${new Date((sso.setAt ?? 0) * 1000).toLocaleDateString()}; people use "Sign in with my company account".` : "Off; people sign in with their username and password."}</p>
      </div>
    </form>
    <form className="grid-form-block" aria-label="Desk parking" onSubmit={event => { event.preventDefault(); void change({ action: "parkingSet", provider: parkProvider, location: location.trim(), accessKey: accessKey.trim(), secretKey }).then(ok => { if (ok) { setAccessKey(""); setSecretKey("") } }) }}>
      <div className="grid-fields">
        <Field label="Parking bucket"><select className="grid-select-field" value={parkProvider} disabled={!owner} onChange={event => setParkProvider(event.target.value as "awsS3" | "s3Compatible")}><option value="awsS3">Amazon S3</option><option value="s3Compatible">S3-compatible (R2, MinIO, Backblaze, Wasabi…)</option></select></Field>
        <Field label={parkProvider === "awsS3" ? "Bucket" : "Endpoint and bucket"} hint={parkProvider === "awsS3" ? "s3://bucket/prefix?region=eu-west-1" : "https://endpoint/bucket/prefix"}><Input required value={location} maxLength={2048} disabled={!owner} onChange={event => setLocation(event.target.value)} /></Field>
        <Field label="Access key"><Input required={!parking} autoComplete="off" spellCheck={false} value={accessKey} disabled={!owner} onChange={event => setAccessKey(event.target.value)} /></Field>
        <Field label="Secret key"><Input required={!parking} type="password" autoComplete="new-password" value={secretKey} disabled={!owner} onChange={event => setSecretKey(event.target.value)} /></Field>
      </div>
      <div className="grid-form-actions">
        <Button size="sm" type="submit" disabled={disabled || !owner || !accessKey.trim() || !secretKey}>{parking ? "Replace parking" : "Set parking"}</Button>
        {parking && owner ? <Button size="sm" type="button" variant="ghost" disabled={disabled} onClick={() => void change({ action: "parkingClear" })}>Stop parking</Button> : null}
        <p className="grid-hint">{parking ? `Desks move through ${parking.location}; the keys stay in this computer's vault and go only to the two computers moving a desk.` : "Without a bucket, desks move through the grid's hub, up to 64 GB each. Set on the computer that hosts the grid."}</p>
      </div>
    </form>
    <form className="grid-form-block" aria-label="Cloud computer" onSubmit={event => { event.preventDefault(); void change({ action: "cloudFallbackSet", ...cloud, maxComputers: Number(cloud.maxComputers) || 1 }) }}>
      <div className="grid-fields">
        <Field label="Cloud computer when nothing has room" hint="Created with your own aws, gcloud or az command line, signed in on this computer; deleted again after an hour of hosting nothing."><select className="grid-select-field" value={cloud.provider ?? "aws"} disabled={!admin} onChange={set("provider")}><option value="aws">Amazon Web Services</option><option value="google">Google Cloud</option><option value="azure">Microsoft Azure</option></select></Field>
        {cloudFields.filter(field => !field.show || field.show.includes(cloud.provider ?? "aws")).map(field => <Field key={field.key} label={field.label} hint={field.hint}><Input value={cloud[field.key] ?? ""} maxLength={512} disabled={!admin} type={field.key === "maxComputers" ? "number" : "text"} min={field.key === "maxComputers" ? 1 : undefined} max={field.key === "maxComputers" ? 64 : undefined} spellCheck={false} onChange={set(field.key)} /></Field>)}
      </div>
      <div className="grid-form-actions">
        <Button size="sm" type="submit" disabled={disabled || !admin}>{cloudFallback ? "Save cloud computer" : "Turn on cloud computer"}</Button>
        {cloudFallback && admin ? <Button size="sm" type="button" variant="ghost" disabled={disabled} onClick={() => void change({ action: "cloudFallbackClear" })}>Turn off</Button> : null}
        <p className="grid-hint">{cloudFallback ? `On: up to ${cloudFallback.maxComputers} ${cloudFallback.provider} machine${cloudFallback.maxComputers === 1 ? "" : "s"} of type ${cloudFallback.machineType} in ${cloudFallback.region}.` : "Off; a desk with nowhere to go waits for a computer."}</p>
      </div>
    </form>
  </>
}

/** The enterprise side of a sandbox grid: permissions, the image catalog, workspace roles, company
 *  workspaces and the activity log, for the grid's owner or a signed-in administrator. */
export function SandboxGridAdmin({ onChanged }: { onChanged(): Promise<unknown> }) {
  const [data, setData] = useState<EnterpriseStatus | null>(null), [tab, setTab] = useState<Tab>("Permissions"), [error, setError] = useState(""), [busy, setBusy] = useState(false)
  const sequence = useRef(0), lock = useRef(false)
  const invalidate = useCallback(() => { sequence.current++ }, [])
  const refresh = useCallback(async () => { const id = ++sequence.current; try { const next = await desksApi.manage({ action: "status" }); if (sequence.current === id) setData(next) } catch (reason) { if (sequence.current === id) { setData(null); setError(say(reason)) } } }, [])
  useEffect(() => { void refresh(); const timer = setInterval(() => { if (!lock.current) void refresh() }, 10000); return () => { invalidate(); clearInterval(timer) } }, [refresh, invalidate])
  const change: Change = async request => {
    if (lock.current) return false
    lock.current = true; setBusy(true); setError(""); sequence.current++
    try { await desksApi.manage(request); await refresh(); await onChanged(); return true }
    catch (reason) { setError(say(reason)); return false }
    finally { lock.current = false; setBusy(false) }
  }
  const submitting = (event: FormEvent) => { event.preventDefault() }
  return <section className="desk-admin" aria-label="Sandbox Grid administration" aria-busy={busy} onSubmitCapture={busy ? submitting : undefined}>
    <div className="desk-admin-tabs" role="tablist" aria-label="Enterprise sections">
      {tabs.map(name => <button key={name} type="button" role="tab" id={`desk-admin-tab-${tabs.indexOf(name)}`} aria-controls="desk-admin-panel" aria-selected={tab === name} onClick={() => setTab(name)}>{name}</button>)}
      <span className="grid-muted desk-admin-actor">{data ? (data.actor === "owner" ? "grid owner" : data.adminRole) : "loading…"}</span>
    </div>
    {error ? <p role="alert" className="grid-line grid-error">{error}</p> : null}
    {data ? <div id="desk-admin-panel" role="tabpanel" aria-labelledby={`desk-admin-tab-${tabs.indexOf(tab)}`} className="desk-admin-panel">
      {tab === "Permissions" ? <Permissions data={data} change={change} disabled={busy} />
        : tab === "Images" ? <Images data={data} change={change} disabled={busy} />
        : tab === "Workspace roles" ? <Roles data={data} change={change} disabled={busy} />
        : tab === "Company workspaces" ? <Connections data={data} change={change} disabled={busy} />
        : tab === "Settings" ? <Settings key={`${data.enterprise.sso?.setAt ?? 0}-${data.enterprise.parking?.setAt ?? 0}-${data.enterprise.cloudFallback?.setAt ?? 0}`} data={data} change={change} disabled={busy} />
        : <>
          <p className="desk-admin-intro">The latest 2,000 management changes. Credentials and file contents are never included.</p>
          {[...data.enterprise.audit].reverse().map((event, index) => <div className="grid-line desk-admin-row" key={`${event.at}-${index}`}><span className="grid-key">{new Date(event.at * 1000).toLocaleString()}</span><span className="grid-muted">{data.people.find(person => person.id === event.actor)?.name ?? event.actor} · {event.action} · {event.subject}</span></div>)}
          {!data.enterprise.audit.length ? <p className="grid-line grid-muted">Nothing yet.</p> : null}
        </>}
    </div> : null}
  </section>
}
