import { useEffect, useState } from "react"
import { platformApi } from "@/api/platform-api"
import { workspaceApi } from "@/api/workspace-api"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Dialog, DialogClose, DialogDescription, DialogPanel, DialogPopup, DialogTitle, DialogTrigger } from "@/components/ui/dialog"
import { Switch } from "@/components/ui/switch"
import { formatBytesFromGb } from "@/lib/domain"
import { useTopicWalkthroughModal } from "@/lib/topic-walkthrough"
import { PreferencesVolumes } from "@/components/dialogs/preferences-volumes"
import { ReleaseUpdateSettings } from "@/components/release-update"
import { PreferencesStartupHealth } from "@/components/dialogs/preferences-startup-health"
import { SandboxDoctor } from "@/components/security/doctor"
import { HostEvidence } from "@/components/security/host-evidence"
import "@/components/dialogs/preferences-dialog.css"

export function PreferencesDialog() {
  const { state, updateSettings } = usePlatform()
  const [open, setOpen] = useState(false)
  const [location, setLocation] = useState("")
  const [selected, setSelected] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const topic = useTopicWalkthroughModal(open)

  useEffect(() => {
    if (!open) return
    let cancelled = false
    void platformApi.getStorageLocation()
      .then(value => { if (!cancelled) setLocation(value) })
      .catch(reason => { if (!cancelled) setError(String(reason)) })
    return () => { cancelled = true }
  }, [open])

  const perform = async (action: () => Promise<unknown>) => {
    if (busy) return
    setBusy(true)
    setError("")
    try { await action() } catch (reason) { setError(String(reason)) } finally { setBusy(false) }
  }

  if (!state) return null
  const { host } = state
  const free = Math.max(0, host.totalStorageGb - host.usedStorageGb)
  const usedPercent = host.totalStorageGb > 0 ? Math.min(100, Math.max(0, host.usedStorageGb / host.totalStorageGb * 100)) : 0
  const nearFull = host.totalStorageGb > 0 && (free / host.totalStorageGb < .1 || free < 5)
  const autoStartIds = state.settings.autoStartEnvironmentIds ?? []
  const autoStartCount = state.environments.filter(env => autoStartIds.includes(env.id)).length
  const canMoveStorage = state.environments.length === 0

  return <Dialog modal={!topic} open={open} onOpenChange={(value, details) => {
    if (!busy && !(!value && topic && details.reason === "focus-out") && !(details.event.target instanceof Element && details.event.target.closest("[data-topic-ui]"))) setOpen(value)
  }}>
    <DialogTrigger render={<Button data-tour="settings" variant="outline" size="sm" className="dashboard-action" />}>Settings</DialogTrigger>
    <DialogPopup data-instruction="settings-dialog" className="preferences-workbench max-w-none" bottomStickOnMobile={false} showCloseButton={false}>
      <header className="preferences-header">
        <div>
          <DialogTitle>Settings</DialogTitle>
          <DialogDescription>Changes save as you make them.</DialogDescription>
        </div>
        <DialogClose render={<Button disabled={busy} variant="outline" size="sm" />}>Close</DialogClose>
      </header>
      <DialogPanel className="preferences-panel" scrollFade={false}>
        <section className="preferences-section" aria-labelledby="preferences-storage-title">
          <div className="preferences-section-label">
            <h3 id="preferences-storage-title">Storage</h3>
            <p>Where Yougori keeps its data</p>
          </div>
          <div className="preferences-section-body">
            <div className="preferences-capacity">
              <strong>{formatBytesFromGb(free)}</strong>
              <span>available</span>
              <span className="preferences-capacity-total">{formatBytesFromGb(host.usedStorageGb)} of {formatBytesFromGb(host.totalStorageGb)} used</span>
            </div>
            <div className="preferences-meter" data-near-full={nearFull || undefined} role="meter" aria-label="Default drive storage used" aria-valuemin={0} aria-valuemax={100} aria-valuenow={Math.round(usedPercent)}><span style={{ width: `${usedPercent}%` }} /></div>
            {nearFull && <p role="alert" className="preferences-storage-warning">Running low on space. Free some up before importing more workloads.</p>}

            <div className="preferences-folder">
              <div>
                <span className="preferences-eyebrow">Folder</span>
                <p title={location || undefined}>{location || "Loading…"}</p>
              </div>
              <Button disabled={busy || !canMoveStorage} variant="outline" size="sm" onClick={() => void perform(async () => {
                const folders = await workspaceApi.chooseFolders()
                if (folders[0]) setSelected(folders[0])
              })}>Change</Button>
            </div>
            <p className="preferences-hint">{canMoveStorage ? "Holds the runtime and shared app data. New environments can still pick another drive." : "To move this folder, export and remove your existing environments first. New environments can still pick another drive."}</p>

            {selected && canMoveStorage && <div className="preferences-pending">
              <span className="preferences-eyebrow">Move to</span>
              <p title={selected}>{selected}</p>
              <div className="preferences-pending-actions">
                <Button disabled={busy} variant="ghost" size="sm" onClick={() => setSelected("")}>Cancel</Button>
                <Button disabled={busy} loading={busy} size="sm" onClick={() => void perform(() => platformApi.setStorageLocation(selected))}>Move and restart</Button>
              </div>
            </div>}
          </div>
        </section>

        <section className="preferences-section" aria-labelledby="preferences-startup-title">
          <div className="preferences-section-label">
            <h3 id="preferences-startup-title">Startup</h3>
            <p>How Yougori runs on this computer</p>
          </div>
          <div className="preferences-section-body">
            <div className="preferences-row">
              <div><label htmlFor="preferences-launch">Launch at sign-in</label><p>Open Yougori after you sign in. This does not start the API before sign-in.</p></div>
              <Switch id="preferences-launch" disabled={busy} checked={state.settings.launchAtStartup} onCheckedChange={checked => void perform(() => updateSettings({ ...state.settings, launchAtStartup: checked }))} />
            </div>
            {state.settings.launchAtStartup && <div className="preferences-row">
              <div><label htmlFor="preferences-background">Start in the background</label><p>Run only the engine at sign-in, for the yougori command line. Linux requires a systemd user session. Open the dashboard any time.</p></div>
              <Switch id="preferences-background" disabled={busy} checked={state.settings.startupHeadless ?? false} onCheckedChange={checked => void perform(() => updateSettings({ ...state.settings, startupHeadless: checked }))} />
            </div>}
            <div className="preferences-row">
              <div><label htmlFor="preferences-awake">Keep computer awake</label><p>While environments are running.</p></div>
              <Switch id="preferences-awake" disabled={busy} checked={state.settings.keepAwake ?? false} onCheckedChange={checked => void perform(() => updateSettings({ ...state.settings, keepAwake: checked }))} />
            </div>
            <details className="preferences-note">
              <summary>What about closing the lid?</summary>
              <p>Your operating system still decides what happens when the lid closes or the computer is forced to sleep. To keep running with the lid closed, change its lid action. Linux requires systemd-inhibit; macOS may need external power and a display.</p>
            </details>
            {state.startupReport && <div className="preferences-note" role="status" aria-label="Automatic startup result">
              <p>Last automatic startup: {state.startupReport.status === "startedUnverified" ? "started; application health unverified" : state.startupReport.status}.</p>
              {state.startupReport.serviceRegistration && <p>Sign-in startup: {state.startupReport.serviceRegistration.status}. {state.startupReport.serviceRegistration.recoveryAction}</p>}
              {state.startupReport.environments.map(result => <div key={result.environmentId}>
                <p>{state.environments.find(environment => environment.id === result.environmentId)?.name ?? result.environmentId}: {result.status === "runningUnverified" ? "running; application health unverified" : result.status} · {result.stage}{result.readiness?.verifiedPublicly ? " · Public URL verified" : ""}</p>
                {result.error && <p>{result.error}</p>}
                {result.recoveryAction && <p>{result.recoveryAction}</p>}
              </div>)}
            </div>}
          </div>
        </section>

        <section className="preferences-section" aria-labelledby="preferences-autostart-title">
          <div className="preferences-section-label">
            <h3 id="preferences-autostart-title">Environments</h3>
            <p>Started automatically when Yougori opens</p>
          </div>
          <div className="preferences-section-body">
            {state.environments.length ? <>
              <p className="preferences-count">{autoStartCount} of {state.environments.length} start automatically</p>
              <div className="preferences-environment-list">
                {state.environments.map(env => {
                  const id = `preferences-autostart-${env.id}`
                  return <div key={env.id}>
                    <div className="preferences-row preferences-environment-row">
                      <label htmlFor={id} title={env.name}>{env.name}</label>
                      <Switch id={id} disabled={busy} checked={autoStartIds.includes(env.id)} onCheckedChange={checked => void perform(() => updateSettings({ ...state.settings, autoStartEnvironmentIds: checked ? [...new Set([...autoStartIds, env.id])] : autoStartIds.filter(item => item !== env.id) }))} />
                    </div>
                    {autoStartIds.includes(env.id) && <PreferencesStartupHealth environmentId={env.id} />}
                  </div>
                })}
              </div>
            </> : <p className="preferences-empty">Environments you create will show up here.</p>}
          </div>
        </section>

        <PreferencesVolumes open={open} />

        <ReleaseUpdateSettings />

        <section className="preferences-section col-span-full" aria-labelledby="preferences-evidence-title">
          <div className="preferences-section-label">
            <h3 id="preferences-evidence-title">VM sandbox and host evidence</h3>
            <p>What Yougori has observed about this computer. Looking changes nothing.</p>
          </div>
          <div className="preferences-section-body space-y-3">
            <SandboxDoctor />
            <HostEvidence />
          </div>
        </section>

        {error && <p role="alert" className="preferences-error">{error}</p>}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
