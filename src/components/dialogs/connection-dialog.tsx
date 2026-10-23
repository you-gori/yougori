import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react"
import { Button } from "@/components/ui/button"
import { Checkbox } from "@/components/ui/checkbox"
import {
  Dialog,
  DialogClose,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogPanel,
  DialogPopup,
  DialogTitle,
} from "@/components/ui/dialog"
import { Field, FieldDescription, FieldLabel } from "@/components/ui/field"
import { Form } from "@/components/ui/form"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Radio, RadioGroup } from "@/components/ui/radio-group"
import { Select, SelectItem, SelectPopup, SelectTrigger, SelectValue } from "@/components/ui/select"
import { usePlatform } from "@/context/platform-context"
import { platformApi } from "@/api/platform-api"
import { permissionLabel } from "@/lib/domain"
import { cn } from "@/lib/utils"
import type { CommandResult, ConnectionDirection, Environment, PermissionKind } from "@/types/platform"
import "./connection-dialog.css"
import { supportsConnections, supportsSharedConnection, connectionPermissions, isTunnelShared } from "@/lib/environment-connections"

const permissionDetails = {
  network: { description: "Allow all network traffic between these environments." },
  ports: { description: "Allow only the TCP ports you specify." },
  files: { description: "Exchange files through a shared directory." },
  volumes: { description: "Attach a shared directory for this connection." },
  data: { description: "Exchange data through the shared directory." },
  secrets: { description: "Attach a separate directory for shared secrets." },
} satisfies Record<PermissionKind, { description: string }>

type SelectedFolder = { environmentId: string; path: string }

export function FolderBrowser({ environment, selected, onSelect, disabled }: {
  environment: Environment
  selected: SelectedFolder[]
  onSelect(path: string): void
  disabled: boolean
}) {
  const [path, setPath] = useState("")
  const [basePath, setBasePath] = useState("")
  const [entries, setEntries] = useState<{ name: string; directory: boolean }[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState("")
  useEffect(() => {
    if (environment.status !== "running" || environment.kind === "fullVm") return
    let cancelled = false
    setLoading(true)
    setError("")
    platformApi.listEnvironmentFolders(environment.id, path).then(result => {
      if (!cancelled) { setEntries(result.entries); if (!path) { setBasePath(result.path); setPath(result.path) } }
    }).catch(reason => { if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason)) })
      .finally(() => { if (!cancelled) setLoading(false) })
    return () => { cancelled = true }
  }, [environment.id, environment.kind, environment.status, path])
  const canBrowse = environment.status === "running" && environment.kind !== "fullVm"
  const chosen = selected.some(folder => folder.environmentId === environment.id && folder.path === path)
  return <div className="connection-folder-browser">
    <div className="connection-folder-heading"><strong>{environment.name}</strong><span>{environment.kind === "cloud" ? "Cloud" : environment.kind === "fullVm" ? "VM" : environment.kind === "microVm" ? "MicroVM" : "Container"}</span></div>
    {canBrowse ? <>
      <div className="connection-folder-path"><Button type="button" size="xs" variant="ghost" disabled={disabled || !path || path === basePath} onClick={() => setPath(path.split("/").slice(0, -1).join("/") || basePath)}>Up</Button><code title={path}>{path || "Opening workspace…"}</code><Button type="button" size="xs" variant="outline" disabled={disabled || loading || !path || path === "/" || chosen || selected.length >= 8} onClick={() => onSelect(path)}>{chosen ? "Selected" : "Share folder"}</Button></div>
      {path === "/" ? <p className="connection-help">Open a project or data folder to share it. The entire filesystem cannot be shared.</p> : null}
      <div className="connection-folder-list" aria-label={`${environment.name} files and folders`}>
        {loading ? <p>Loading files and folders…</p> : error ? <p role="alert">{error}</p> : entries.length ? [...entries].sort((a, b) => Number(b.directory) - Number(a.directory) || a.name.localeCompare(b.name)).map(entry => entry.directory
          ? <button type="button" key={entry.name} disabled={disabled} onClick={() => setPath(`${path === "/" ? "" : path}/${entry.name}`)}><span className="truncate font-medium">{entry.name}</span></button>
          : <div className="connection-folder-file" key={entry.name} title="Included when you share this folder"><span className="truncate text-muted-foreground">{entry.name}</span></div>) : <p>This folder is empty.</p>}
      </div>
    </> : <p className="connection-help">{environment.status !== "running" ? "Start or connect this environment to browse folders." : "This VM has no Yougori guest file agent. It can access folders selected from the other environment through the private file browser."}</p>}
  </div>
}

export function ConnectionDialog({ open, onOpenChange, initialSourceId, initialTargetId }: {
  open: boolean
  onOpenChange(open: boolean): void
  initialSourceId?: string
  initialTargetId?: string
}) {
  const { state, createConnection, deleteConnection } = usePlatform()
  const options = useMemo(() => state?.environments.filter(supportsConnections).map((environment) => ({ label: environment.name, value: environment.id })) ?? [], [state?.environments])
  const [sourceId, setSourceId] = useState("")
  const [targetId, setTargetId] = useState("")
  const [direction, setDirection] = useState<ConnectionDirection>("bidirectional")
  const [selectedPermissions, setSelectedPermissions] = useState<PermissionKind[]>(["data"])
  const [ports, setPorts] = useState("")
  const [ssh, setSsh] = useState(false)
  const [commands, setCommands] = useState(false)
  const [sshPort, setSshPort] = useState("22")
  const [volume, setVolume] = useState("")
  const [selectedFolders, setSelectedFolders] = useState<SelectedFolder[]>([])
  const [saving, setSaving] = useState(false)
  const [formError, setFormError] = useState("")
  const [peerCommand, setPeerCommand] = useState("")
  const [peerResult, setPeerResult] = useState<CommandResult | null>(null)
  const [peerCommandError, setPeerCommandError] = useState("")
  const [runningCommand, setRunningCommand] = useState(false)
  const initialized = useRef<string | null>(null)
  const descriptionId = useId()
  const source = state?.environments.find(e => e.id === sourceId)
  const target = state?.environments.find(e => e.id === targetId)
  const remote = isTunnelShared(source) || isTunnelShared(target)
  const shared = supportsSharedConnection(source, target)
  const permissions = connectionPermissions(shared, remote).filter(permission => ["network", "ports", "secrets"].includes(permission))
  const existingConnection = state?.connections.find(connection =>
    (connection.sourceId === sourceId && connection.targetId === targetId)
      || (connection.sourceId === targetId && connection.targetId === sourceId))
  const cloud = !remote && state?.environments.some(e => (e.id === sourceId || e.id === targetId) && e.kind === "cloud")
  useEffect(() => {
    if (!shared || remote) setSelectedPermissions(current => {
      const allowed: PermissionKind[] = connectionPermissions(shared, remote).filter(permission => permission !== "files" && permission !== "volumes")
      const filtered = current.filter(p => allowed.includes(p))
      return filtered.length === current.length ? current : filtered.length ? filtered : remote ? [] : ["data"]
    })
  }, [shared, remote])

  useEffect(() => {
    if (!open) { initialized.current = null; return }
    // Host telemetry and other windows may refresh the environment list while
    // this form is open. Initialize once per opening, never erase an active draft.
    const key = JSON.stringify([initialSourceId, initialTargetId])
    if (initialized.current === key) return
    initialized.current = key
    const proposedSource = options.find(item => item.value === initialSourceId)?.value ?? options[0]?.value ?? ""
    const proposedTarget = options.find(item => item.value === initialTargetId && item.value !== proposedSource)?.value ?? options.find(item => item.value !== proposedSource)?.value ?? ""
    const existing = state?.connections.find(connection =>
      (connection.sourceId === proposedSource && connection.targetId === proposedTarget)
        || (connection.sourceId === proposedTarget && connection.targetId === proposedSource))
    setSourceId(existing?.sourceId ?? proposedSource)
    setTargetId(existing?.targetId ?? proposedTarget)
    setSelectedPermissions(existing ? [...new Set(existing.permissions.map(permission => ["files", "volumes"].includes(permission) ? "data" : permission))] : state?.environments.some(environment => [proposedSource, proposedTarget].includes(environment.id) && isTunnelShared(environment)) ? [] : ["data"])
    setDirection(existing?.direction ?? "bidirectional")
    setPorts(existing?.ports.join(", ") ?? "")
    setSsh(existing?.sshPort !== undefined)
    setCommands(Boolean(existing?.commands) || Boolean(!existing && state?.environments.some(environment => [proposedSource, proposedTarget].includes(environment.id) && isTunnelShared(environment))))
    setSshPort(String(existing?.sshPort ?? 22))
    setVolume(existing?.volume ?? "")
    setSelectedFolders(existing?.selectedFolders ?? [])
    setFormError("")
    setPeerResult(null)
    setPeerCommandError("")
  }, [initialSourceId, initialTargetId, open, options, state?.connections, state?.environments])

  const choosePair = (nextSource: string, nextTarget: string) => {
    const existing = state?.connections.find(connection =>
      (connection.sourceId === nextSource && connection.targetId === nextTarget)
        || (connection.sourceId === nextTarget && connection.targetId === nextSource))
    const nextRemote = state?.environments.some(environment =>
      (environment.id === nextSource || environment.id === nextTarget) && isTunnelShared(environment))
    setSourceId(existing?.sourceId ?? nextSource)
    setTargetId(existing?.targetId ?? nextTarget)
    setSelectedPermissions(existing ? [...new Set(existing.permissions.map(permission => ["files", "volumes"].includes(permission) ? "data" : permission))] : nextRemote ? [] : ["data"])
    setDirection(existing?.direction ?? "bidirectional")
    setPorts(existing?.ports.join(", ") ?? "")
    setSsh(existing?.sshPort !== undefined)
    setCommands(Boolean(existing?.commands) || Boolean(!existing && nextRemote))
    setSshPort(String(existing?.sshPort ?? 22))
    setVolume(existing?.volume ?? "")
    setSelectedFolders(existing?.selectedFolders ?? [])
    setFormError("")
    setPeerResult(null)
    setPeerCommandError("")
  }

  const togglePermission = (permission: PermissionKind, checked: boolean) => {
    setSelectedPermissions((current) => checked ? [...new Set([...current, permission])] : current.filter((item) => item !== permission))
    setFormError("")
  }

  const runPeerCommand = async () => {
    if (!existingConnection || runningCommand || !peerCommand.trim()) return
    setRunningCommand(true)
    setPeerResult(null)
    setPeerCommandError("")
    try { setPeerResult(await platformApi.executeConnectedCommand(existingConnection.id, sourceId, peerCommand)) }
    catch (reason) { setPeerCommandError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setRunningCommand(false) }
  }

  const removeExistingConnection = async () => {
    if (!existingConnection || saving) return
    setSaving(true)
    setFormError("")
    try {
      await deleteConnection(existingConnection.id)
      onOpenChange(false)
    } catch (reason) {
      setFormError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setSaving(false)
    }
  }

  const submit = async (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault()
    if (saving) return
    if (!sourceId || !targetId || sourceId === targetId) {
      setFormError("Choose two different environments.")
      return
    }
    if (!options.some(item => item.value === sourceId) || !options.some(item => item.value === targetId)) {
      setFormError("A selected environment is no longer available. Choose another environment.")
      return
    }
    if (isTunnelShared(source) && isTunnelShared(target)) {
      setFormError("Connect one shared environment to one environment on this computer.")
      return
    }
    if (!selectedPermissions.length && !ssh && !commands) {
      if (existingConnection) {
        await removeExistingConnection()
        return
      }
      setFormError("Choose at least one capability to create a connection.")
      return
    }
    if (selectedFolders.length && !selectedPermissions.includes("data")) { setFormError("Turn on Data to share selected folders."); return }
    if (selectedFolders.some(folder => /^\/+$/u.test(folder.path))) { setFormError("Remove the / selection and choose a specific project or data folder."); return }
    if (selectedPermissions.includes("data") && !selectedFolders.length && !existingConnection) { setFormError("Choose at least one folder to share, or turn off Share data."); return }
    if (ssh && (!/^\d+$/.test(sshPort) || Number(sshPort) < 1 || Number(sshPort) > 65535)) { setFormError("SSH port must be between 1 and 65535."); return }
    const allowedPorts = selectedPermissions.includes("ports") || ssh ? ports.split(",").map(port => port.trim()).filter(Boolean) : []
    if (ssh && !allowedPorts.some(port => Number(port) === Number(sshPort))) allowedPorts.push(String(Number(sshPort)))
    if (selectedPermissions.includes("ports") && !selectedPermissions.includes("network") && !allowedPorts.length) {
      setFormError("Enter at least one TCP port, or grant full network access instead.")
      return
    }
    if (allowedPorts.some(port => !/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65_535)) {
      setFormError("TCP ports must be whole numbers between 1 and 65535, separated by commas.")
      return
    }
    const normalizedPorts = allowedPorts.map(port => String(Number(port)))
    if (new Set(normalizedPorts).size !== normalizedPorts.length) {
      setFormError("Each TCP port should only be listed once.")
      return
    }
    const sharedVolume = selectedPermissions.includes("volumes") ? volume.trim() : ""
    if (sharedVolume && !/^[a-zA-Z0-9_.-]{1,80}$/.test(sharedVolume)) {
      setFormError("Shared volume names may use up to 80 letters, numbers, dots, dashes, or underscores.")
      return
    }
    setSaving(true)
    setFormError("")
    try {
      await createConnection({
        sourceId,
        targetId,
        direction,
        permissions: ssh ? [...new Set<PermissionKind>([...selectedPermissions, "ports"])] : selectedPermissions,
        ports: normalizedPorts,
        sshPort: ssh ? Number(sshPort) : undefined,
        commands,
        selectedFolders,
        volume: sharedVolume || undefined,
      })
      onOpenChange(false)
    } catch (reason) {
      setFormError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setSaving(false)
    }
  }

  if (!state) return null
  const sourceOption = options.find((item) => item.value === sourceId)
  const targetOption = options.find((item) => item.value === targetId)
  const hasNetwork = selectedPermissions.includes("network")
  const hasPorts = selectedPermissions.includes("ports") || ssh
  const hasStorage = selectedPermissions.some(permission => ["files", "volumes", "data"].includes(permission))
  const removingOnSave = Boolean(existingConnection && !selectedPermissions.length && !ssh && !commands)
  const arrow = direction === "oneWay" ? "→" : "↔"

  return (
    <Dialog onOpenChange={value => { if (!saving) onOpenChange(value) }} open={open}>
      <DialogPopup bottomStickOnMobile={false} closeProps={{ disabled: saving }} className="connection-workbench max-h-[calc(100dvh-2rem)] max-w-[1040px] overflow-hidden sm:max-w-[1040px]">
        <DialogHeader className="connection-header">
          <DialogTitle className="text-base leading-5">{existingConnection ? "Edit connection" : "New connection"}</DialogTitle>
          <DialogDescription className="connection-subtitle">Private connections between environments, including a shared environment you control.</DialogDescription>
        </DialogHeader>
        <Form className="contents" onSubmit={submit}>
          <DialogPanel scrollFade={false} className="p-0!">
            <section aria-label="Connection endpoints" className="connection-route">
              <div className="connection-endpoints">
                <Field className="min-w-0">
                  <FieldLabel>From</FieldLabel>
                  <Select disabled={saving || !options.length} items={options} onValueChange={value => choosePair(value ?? "", targetId)} value={sourceId}>
                    <SelectTrigger className="connection-endpoint"><SelectValue placeholder="Choose source" /></SelectTrigger>
                    <SelectPopup alignItemWithTrigger={false} className="max-w-[calc(100vw-3rem)]">{options.map(item => <SelectItem disabled={item.value === targetId} key={item.value} value={item.value}><span className="truncate">{item.label}</span></SelectItem>)}</SelectPopup>
                  </Select>
                </Field>
                <Button aria-label="Swap source and destination" title="Swap source and destination" className="connection-swap" disabled={saving || !sourceId || !targetId} onClick={() => { setSourceId(targetId); setTargetId(sourceId); setFormError("") }} size="sm" type="button" variant="ghost">Swap</Button>
                <Field className="min-w-0">
                  <FieldLabel>To</FieldLabel>
                  <Select disabled={saving || options.length < 2} items={options} onValueChange={value => choosePair(sourceId, value ?? "")} value={targetId}>
                    <SelectTrigger className="connection-endpoint"><SelectValue placeholder="Choose destination" /></SelectTrigger>
                    <SelectPopup alignItemWithTrigger={false} className="max-w-[calc(100vw-3rem)]">{options.map(item => <SelectItem disabled={item.value === sourceId} key={item.value} value={item.value}><span className="truncate">{item.label}</span></SelectItem>)}</SelectPopup>
                  </Select>
                </Field>
              </div>
              <div className="connection-direction-row">
                <RadioGroup aria-label="Connection direction" className="connection-directions" disabled={saving} onValueChange={value => { setDirection(value as ConnectionDirection); setFormError("") }} value={direction}>
                  <Label className={cn("connection-direction", direction === "oneWay" && "is-selected")}><Radio className="sr-only" value="oneWay" />One-way</Label>
                  <Label className={cn("connection-direction", direction === "bidirectional" && "is-selected")}><Radio className="sr-only" value="bidirectional" />Bidirectional</Label>
                </RadioGroup>
                <p className="connection-direction-help">{direction === "oneWay" ? "Network access goes from source to destination." : "Network access works in both directions."}</p>
              </div>
              {options.length < 2 ? <p role="status" className="connection-empty">Create at least two environments to connect them.</p> : null}
            </section>

            <div className="connection-columns">
              <section aria-label="Permissions" className="connection-permissions">
                <div className="connection-section-heading"><h2>What can these environments do?</h2><span>{selectedPermissions.length + Number(commands)} selected</span></div>
                <div className="connection-permission-list">
                  {!remote ? <Label className={cn("connection-permission", selectedPermissions.includes("data") && "is-selected")}>
                    <span className="connection-permission-copy"><span id={`${descriptionId}-data-label`}>Share data</span><span>Choose specific folders below. Both sides can browse those folders through the private connection.</span></span>
                    <Checkbox aria-labelledby={`${descriptionId}-data-label`} checked={selectedPermissions.includes("data")} disabled={saving} onCheckedChange={value => togglePermission("data", Boolean(value))} />
                  </Label> : null}
                  <Label className={cn("connection-permission", commands && "is-selected")}>
                    <span className="connection-permission-copy"><span id={`${descriptionId}-commands-label`}>Run commands</span><span>Run shell commands in the other environment from Yougori or its CLI. Full VMs need verified guest SSH.</span></span>
                    <Checkbox aria-labelledby={`${descriptionId}-commands-label`} checked={commands} disabled={saving} onCheckedChange={value => { setCommands(Boolean(value)); setFormError("") }} />
                  </Label>
                  <details className="connection-advanced"><summary>Network and legacy access</summary>
                  <Label className={cn("connection-permission", ssh && "is-selected")}>
                    <span className="connection-permission-copy"><span id={`${descriptionId}-ssh-label`}>SSH / SFTP port</span><span>Open a TCP port for a guest SSH server. You manage its login and host key.</span></span>
                    <Checkbox aria-labelledby={`${descriptionId}-ssh-label`} checked={ssh} disabled={saving} onCheckedChange={value => setSsh(Boolean(value))} />
                  </Label>
                  {permissions.map(permission => {
                    const description = cloud && permission === "network" ? "Allow TCP between these nodes over SSH. Cloud terminals use a private SOCKS proxy; no UDP or LAN routing." : cloud && ["files", "volumes", "data"].includes(permission) ? "Connection-owned shared folder. Cloud servers use its browser/API, not a mounted drive." : permissionDetails[permission].description
                    const checked = selectedPermissions.includes(permission)
                    return <Label className={cn("connection-permission", checked && "is-selected")} key={permission}>
                      <span className="connection-permission-copy"><span id={`${descriptionId}-${permission}-label`}>{permissionLabel[permission]}</span><span id={`${descriptionId}-${permission}`}>{permission === "network" && !shared && !cloud ? "Private IPv4: TCP, UDP and ping between these two environments." : permission === "ports" && hasNetwork ? "Network access already includes every TCP port." : description}</span></span>
                      <Checkbox aria-labelledby={`${descriptionId}-${permission}-label`} aria-describedby={`${descriptionId}-${permission}`} checked={checked} disabled={saving} onCheckedChange={value => togglePermission(permission, value)} />
                    </Label>
                  })}
                  </details>
                </div>
              </section>

              <section aria-label="Connection details" className="connection-details">
                <div className="connection-section-heading"><h2>Connection details</h2></div>
                <div aria-label="Access summary" role="group" className="connection-summary">
                  <p className="connection-summary-route"><span title={sourceOption?.label}>{sourceOption?.label ?? "Source"}</span><span role="img" aria-label={direction === "oneWay" ? "to" : "both ways"}>{arrow}</span><span title={targetOption?.label}>{targetOption?.label ?? "Destination"}</span></p>
                  <p>{hasNetwork ? cloud ? "All TCP ports are allowed over SSH. UDP, ping and LAN routing are unavailable." : shared ? "All network traffic is allowed. The TCP port list does not restrict this connection." : "IPv4 TCP, UDP and ping are allowed. No IPv6, multicast or fragmented IP traffic." : hasPorts ? "Network access is restricted to your allowed TCP ports." : "No network traffic is granted by this connection."}</p>
                </div>
                {hasPorts ? <Field name="ports">
                  <FieldLabel>Allowed TCP ports <span className="connection-optional">{hasNetwork ? "Optional" : "Required"}</span></FieldLabel>
                  <Input className="connection-input" disabled={saving} onChange={event => { setPorts(event.target.value); setFormError("") }} placeholder="443, 5432, 6379" type="text" value={ports} />
                  <FieldDescription className="connection-help">{hasNetwork ? "Saved as a reference only; all ports are already allowed." : "Separate ports with commas. Valid range: 1–65535."}</FieldDescription>
                </Field> : null}
                {ssh ? <Field name="sshPort"><FieldLabel>SSH TCP port</FieldLabel><Input aria-label="SSH TCP port" value={sshPort} disabled={saving} inputMode="numeric" onChange={event => setSshPort(event.target.value)} /><FieldDescription>Only this additional TCP port is opened. Verify the guest's host key and authenticate from the source environment. Account permissions govern commands and files; passwords and private keys stay with your SSH client.</FieldDescription></Field> : null}
                {selectedPermissions.includes("volumes") ? <Field name="volume">
                  <FieldLabel>Shared volume <span className="connection-optional">Optional</span></FieldLabel>
                  <Input className="connection-input" disabled={saving} maxLength={80} onChange={event => { setVolume(event.target.value); setFormError("") }} placeholder="workspace-data" type="text" value={volume} />
                  <FieldDescription className="connection-help">A label for this connection’s shared directory.</FieldDescription>
                </Field> : null}
                {hasStorage || selectedPermissions.includes("secrets") ? <p className="connection-help">{selectedFolders.length ? `${selectedFolders.length} selected guest folder${selectedFolders.length === 1 ? "" : "s"} will be available through the private file browser. ` : hasStorage ? "Data also keeps a separate connection-owned folder. " : ""}{selectedPermissions.includes("secrets") ? "Secrets use a separate directory. " : ""}{direction === "oneWay" ? "The source can write; the destination can only read." : "Both environments can read and write."}</p> : null}
                {remote ? <p className="connection-help">Shared environment commands need the owner’s Full Control grant and a live tunnel. Selected guest folders cannot cross this tunnel yet; use the shared node’s Files view.</p> : null}
                {hasStorage ? <p className="connection-help">Selected folders expose their original files immediately. The separate connection folder stays available for older workflows. Do not share live database files.</p> : null}
                {existingConnection?.commands && existingConnection.active && existingConnection.enforcementStatus === "enforced" && (existingConnection.direction === "bidirectional" || existingConnection.sourceId === sourceId) ? <div className="connection-command-box">
                  <label htmlFor="connection-peer-command">Run in {targetOption?.label ?? "peer"}</label>
                  <div><Input id="connection-peer-command" aria-label="Peer command" className="connection-input" value={peerCommand} onChange={event => setPeerCommand(event.target.value)} placeholder="ls -la" spellCheck={false} /><Button type="button" size="sm" disabled={saving || runningCommand || !peerCommand.trim()} onClick={() => void runPeerCommand()}>{runningCommand ? "Running…" : "Run"}</Button></div>
                  {peerCommandError ? <p role="alert" className="connection-error">{peerCommandError}</p> : null}
                  {peerResult ? <pre aria-label="Peer command result">{`Exit ${peerResult.exitCode}\n${peerResult.stdout}${peerResult.stderr}`}</pre> : null}
                </div> : null}
                <p className="connection-scope"><span>{remote ? "Connects only these two nodes through the owner’s existing share. It does not make either guest publicly reachable." : cloud ? "Connects only these two nodes over SSH; your PC must be able to reach the cloud server. No Local network or Public access publishing." : "This connects these two environments only. It works independently of Internet access and does not publish anything."}</span></p>
              </section>
            </div>
            {selectedPermissions.includes("data") && !remote ? <section aria-label="Choose folders to share" className="connection-folders">
              <div className="connection-section-heading"><h2>Folders to share</h2><span>{selectedFolders.length} of 8 chosen</span></div>
              <p className="connection-help">Each side opens at its working or project folder. Choose only the folders to share; connected containers and managed MicroVMs see peer folders immediately under /yougori/shared. Changes stay live.</p>
              <div className="connection-folder-columns">
                {source ? <FolderBrowser key={source.id} environment={source} selected={selectedFolders} disabled={saving} onSelect={path => setSelectedFolders(folders => [...folders, { environmentId: source.id, path }])} /> : null}
                {target ? <FolderBrowser key={target.id} environment={target} selected={selectedFolders} disabled={saving} onSelect={path => setSelectedFolders(folders => [...folders, { environmentId: target.id, path }])} /> : null}
              </div>
              {selectedFolders.length ? <div className="connection-chosen-folders">{selectedFolders.map(folder => <div key={`${folder.environmentId}:${folder.path}`}><span>{state.environments.find(env => env.id === folder.environmentId)?.name}: <code>{folder.path}</code></span><Button type="button" size="xs" variant="ghost" disabled={saving} onClick={() => setSelectedFolders(items => items.filter(item => item !== folder))}>Remove</Button></div>)}</div> : null}
              {selectedFolders.some(folder => /^\/+$/u.test(folder.path)) ? <p className="connection-help" role="alert">This connection shares the entire filesystem. Remove the / selection and choose a specific project or data folder before saving.</p> : null}
            </section> : null}
          </DialogPanel>
          <DialogFooter className="connection-footer">
            {formError ? <p className="connection-error" role="alert">{formError}</p> : null}
            <div className="connection-footer-row">
              <span className="connection-footer-note">Rules apply when both environments are running.</span>
              <div className="connection-actions">
                {existingConnection && !removingOnSave ? <Button disabled={saving} onClick={() => void removeExistingConnection()} type="button" variant="ghost" className="text-destructive-foreground">Remove connection</Button> : null}
                <DialogClose render={<Button className="rounded-full" disabled={saving} type="button" variant="ghost" />}>Cancel</DialogClose>
                <Button aria-label={removingOnSave ? "Remove connection" : existingConnection ? "Save connection" : "Create connection"} aria-busy={saving} className="connection-submit" disabled={options.length < 2} loading={saving} type="submit" variant={removingOnSave ? "destructive" : "default"}>{removingOnSave ? "Remove connection" : existingConnection ? "Save changes" : "Create connection"}</Button>
              </div>
            </div>
          </DialogFooter>
        </Form>
      </DialogPopup>
    </Dialog>
  )
}
