import { duplicationApi, type DuplicationRequest } from "@/api/duplication-api"
import { tourEnvironmentCreated, tourEnvironmentCreationFailed } from "@/lib/instructions-tour"
import { storageCleanupDescription } from "@/lib/storage-cleanup"
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import type { EnvironmentAction } from "@/lib/environment-actions"
import { toastManager } from "@/components/ui/toast"
import { platformApi } from "@/api/platform-api"
import { cloudApi, type CloudProfile } from "@/api/cloud-api"
import { Button } from "@/components/ui/button"
import { AlertDialog, AlertDialogPopup, AlertDialogHeader, AlertDialogTitle, AlertDialogDescription, AlertDialogFooter } from "@/components/ui/alert-dialog"
import { localBackupApi } from "@/api/local-backup-api"
import { applySavedDomains, migrateSavedDomains } from "@/lib/public-access-presets"
import type {
  AddDestinationRequest,
  AppSettings,
  CreateConnectionRequest,
  CreateEnvironmentRequest,
  EnvironmentStatus,
  PlatformState,
  ResourcePolicy,
} from "@/types/platform"

interface PlatformContextValue {
  state: PlatformState | null
  refreshPlatform():Promise<void>
  configureCloudEnvironment(id:string,profile:CloudProfile):Promise<void>
  loading: boolean
  error: string | null
  environmentActions: Record<string, EnvironmentAction | undefined>
  openEnvironmentWindow(environmentId: string): Promise<boolean>
  createEnvironment(request: CreateEnvironmentRequest): Promise<void>
  addCloudEnvironment(request: CloudProfile): Promise<void>
  setEnvironmentStatus(environmentId: string, status: EnvironmentStatus): Promise<void>
  deleteEnvironment(environmentId: string, recoverRuntime?: boolean): Promise<void>
  reclaimStorage(): Promise<void>
  recoverContainerRuntime(environmentId: string): Promise<void>
  factoryResetEnvironment(environmentId: string, confirmation: string): Promise<void>
  renameEnvironment(environmentId: string, name: string): Promise<void>
  updateContainerStartupCommand(environmentId: string, command: string): Promise<void>
  updateResourcePolicy(environmentId: string, resourcePolicy: ResourcePolicy): Promise<void>
  updateContainerNetwork(environmentId: string, enabled: boolean): Promise<void>
  updateEnvironmentGpu(environmentId: string, enabled: boolean): Promise<void>
  createConnection(request: CreateConnectionRequest): Promise<void>
  setConnectionActive(connectionId: string, active: boolean): Promise<void>
  deleteConnection(connectionId: string): Promise<void>
  createSnapshot(environmentId: string, name: string): Promise<void>
  deleteSnapshot(snapshotId: string): Promise<void>
  restoreSnapshot(snapshotId: string): Promise<void>
  addDestination(request: AddDestinationRequest): Promise<void>
  deleteDestination(destinationId: string): Promise<void>
  runBackup(environmentId: string, destinationId: string): Promise<void>
  restoreBackup(backupId: string): Promise<void>
  duplicateEnvironment(request: DuplicationRequest): Promise<void>
  duplicateLocalEnvironment(environmentId: string, name: string, storageDrive?: string): Promise<void>
  importLocalBackup(path: string, targetProvider?: "yougoriOci" | "yougoriCuda"): Promise<void>
  updateSettings(settings: AppSettings): Promise<void>
  resetPlatform(): Promise<void>
}

const PlatformContext = createContext<PlatformContextValue | null>(null)
const PLATFORM_STATE_EVENT = "yougori-platform-state"

function isTauri() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
}

async function publishPlatformState(state: PlatformState) {
  if (!isTauri()) return
  const { emit } = await import("@tauri-apps/api/event")
  await emit(PLATFORM_STATE_EVENT, state)
}

export function PlatformProvider({ children, pollHostMetrics = true }: { children: ReactNode; pollHostMetrics?: boolean }) {
  const [state, commitState] = useState<PlatformState | null>(null)
  // Counts applied updates so an in-flight background read cannot replace a newer one.
  const stateRevision = useRef(0)
  // Highest engine revision applied. Replies, polls and other windows' events can arrive
  // out of order; an older engine state must never roll back a newer one.
  const engineRevision = useRef(-1)
  const setState = useCallback((next: PlatformState) => {
    if (typeof next.stateRevision === "number") {
      if (next.stateRevision < engineRevision.current) return false
      engineRevision.current = next.stateRevision
    }
    stateRevision.current += 1
    commitState(next)
    // Saved domains are engine state shared with the CLI.
    if (next.savedDomains) applySavedDomains(next.savedDomains)
    return true
  }, [])
  useEffect(() => { migrateSavedDomains().catch(() => undefined) }, [])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [creatingEnvironments, setCreatingEnvironments] = useState(0)
  const [environmentActions, setEnvironmentActions] = useState<Record<string, EnvironmentAction | undefined>>({})
  const actionLocks = useRef(new Set<string>())
  const [recoveryConfirmation, setRecoveryConfirmation] = useState<((confirmed: boolean) => void) | null>(null)
  const [recoveringVm, setRecoveringVm] = useState(false)
  const recoveryResolver = useRef<((confirmed: boolean) => void) | null>(null)
  const confirmRecovery = useCallback((vm = false) => new Promise<boolean>(resolve => {
    if (recoveryResolver.current) { resolve(false); return }
    recoveryResolver.current = resolve
    setRecoveringVm(vm)
    setRecoveryConfirmation(() => resolve)
  }), [])
  useEffect(() => () => { recoveryResolver.current?.(false); recoveryResolver.current = null }, [])
  const runEnvironmentAction = useCallback(async <T,>(id: string, action: EnvironmentAction, operation: (phase: (action: EnvironmentAction) => void) => Promise<T>): Promise<T> => {
    // Synchronous guard also catches two clicks before React paints the spinner.
    if (actionLocks.current.has(id)) throw new Error("An action is already in progress for this environment. Please wait.")
    actionLocks.current.add(id)
    const phase = (next: EnvironmentAction) => setEnvironmentActions(current => ({ ...current, [id]: next }))
    phase(action)
    try { return await operation(phase) }
    finally {
      actionLocks.current.delete(id)
      setEnvironmentActions(current => { const next = { ...current }; delete next[id]; return next })
    }
  }, [])
  const refreshPlatform = useCallback(async () => {
    const revision = stateRevision.current
    const next = await platformApi.getState()
    // A background read must not undo a completed command or a newer event.
    if (revision === stateRevision.current) setState(next)
  }, [setState])
  const duplicating = Object.values(environmentActions).includes("duplicating")
  useEffect(() => {
    if (!duplicating) return
    const timer = window.setInterval(() => void refreshPlatform().catch(() => undefined), 2000)
    return () => window.clearInterval(timer)
  }, [duplicating, refreshPlatform])
  const stateLoaded = state !== null
  const runningEnvironmentCount = state?.environments.filter((environment) => environment.status === "running").length ?? 0
  const provisioning = Boolean(creatingEnvironments || state?.environments.some(environment => environment.status === "provisioning"))

  useEffect(() => {
    if (!provisioning) return
    let disposed = false, timer = 0
    const refresh = async () => {
      const revision = stateRevision.current
      try {
        // Read persisted progress only; do not collect host metrics or boot runtimes.
        const next = await platformApi.getState()
        if (!disposed && revision === stateRevision.current) setState(next)
      } catch { /* Completion/errors also arrive through the command and events. */ }
      finally { if (!disposed) timer = window.setTimeout(refresh, 1000) }
    }
    void refresh()
    return () => { disposed = true; window.clearTimeout(timer) }
  }, [provisioning, setState])

  useEffect(() => {
    let active = true
    const revision = stateRevision.current
    platformApi.getState()
      .then((nextState) => {
        if (active && revision === stateRevision.current) setState(nextState)
      })
      .catch((reason: unknown) => {
        if (active) setError(reason instanceof Error ? reason.message : String(reason))
      })
      .finally(() => {
        if (active) setLoading(false)
      })
    return () => { active = false }
  }, [setState])

  useEffect(() => {
    if (!isTauri()) return
    let disposed = false
    let unlisten: (() => void) | undefined
    void import("@tauri-apps/api/event")
      .then(({ listen }) => listen<PlatformState>(PLATFORM_STATE_EVENT, ({ payload }) => {
        if (!disposed && payload && Array.isArray(payload.environments)) {
          setState(payload)
          setError(null)
          setLoading(false)
        }
      }))
      .then((stopListening) => {
        if (disposed) stopListening()
        else unlisten = stopListening
      })
      .catch(() => undefined)
    return () => {
      disposed = true
      unlisten?.()
    }
  }, [setState])

  useEffect(() => {
    if (!stateLoaded || !pollHostMetrics) return
    let disposed = false
    let timer = 0

    const schedule = () => {
      if (disposed) return
      // Runtime telemetry is useful while a workload is active, but polling a
      // completely idle or backgrounded desktop only burns CPU and wakes disks.
      const delay = document.visibilityState === "hidden"
        ? 120_000
        : runningEnvironmentCount > 0
          ? 12_000
          : 60_000
      timer = window.setTimeout(refresh, delay)
    }
    const refresh = () => {
      const revision = stateRevision.current
      platformApi.refreshHostMetrics()
        .then((nextState) => {
          if (!disposed && revision === stateRevision.current && setState(nextState)) {
            void publishPlatformState(nextState).catch(() => undefined)
          }
        })
        .catch(() => undefined)
        .finally(schedule)
    }
    const visibilityChanged = () => {
      window.clearTimeout(timer)
      schedule()
    }

    document.addEventListener("visibilitychange", visibilityChanged)
    schedule()
    return () => {
      disposed = true
      window.clearTimeout(timer)
      document.removeEventListener("visibilitychange", visibilityChanged)
    }
  }, [pollHostMetrics, runningEnvironmentCount, setState, stateLoaded])

  const perform = useCallback(async (
    action: () => Promise<PlatformState>,
    successTitle?: string,
    successDescription?: string,
  ) => {
    try {
      const nextState = await action()
      setError(null)
      // The event carries this state's engine revision, so other windows can order it too.
      if (setState(nextState)) void publishPlatformState(nextState).catch(() => undefined)
      if (successTitle) toastManager.add({ title: successTitle, description: successDescription })
    } catch (reason) {
      const message = reason instanceof Error ? reason.message : String(reason)
      setError(message)
      toastManager.add({ title: "Something went wrong", description: message, type: "error" })
      throw reason
    }
  }, [setState])

  const value = useMemo<PlatformContextValue>(() => ({
    state,
    loading,
    error,
    environmentActions,
    addCloudEnvironment: request => perform(() => platformApi.addCloudEnvironment(request), "Cloud node added", "Choose Connect to access the existing server."),
    openEnvironmentWindow: (environmentId) => {
      const environment = state?.environments.find(item => item.id === environmentId)
      return runEnvironmentAction(environmentId, environment?.status === "running" ? "opening" : environment?.kind === "cloud" ? "connecting" : "starting", async phase => {
        if (!environment) throw new Error("Environment not found")
        if (environment.status !== "running" && !environment.runtime?.startsWith("shared://tunnel/")) {
          try { await perform(() => platformApi.setEnvironmentStatus(environmentId, "running"), environment.kind === "cloud" ? "Cloud server connected" : "Environment started") }
          catch (error) { if (environment.kind === "cloud") { try { setState(await platformApi.getState()) } catch { /* Preserve the connection error. */ } } throw error }
        }
        phase("opening")
        return platformApi.openEnvironmentWindow(environmentId)
      })
    },
    createEnvironment: async (request) => {
      setCreatingEnvironments(count => count + 1)
      try {
        await perform(async () => {
          const next = await platformApi.createEnvironment(request)
          if (request.kind === "container") {
            const created = next.environments.find(e => e.name === request.name && e.kind === "container")
            if (created) tourEnvironmentCreated(created.id, created.name)
          }
          return next
        }, "Environment created", `${request.name} is ready to start.`)
      } catch (reason) {
        tourEnvironmentCreationFailed(request.name)
        try { setState(await platformApi.getState()) } catch { /* Keep the existing error. */ }
        throw reason
      } finally { setCreatingEnvironments(count => count - 1) }
    },
    setEnvironmentStatus: (environmentId, status) => runEnvironmentAction(environmentId, state?.environments.find(e => e.id === environmentId)?.kind === "cloud" ? status === "running" ? "connecting" : "disconnecting" : status === "running" ? "starting" : status === "paused" ? "pausing" : "stopping", () => perform(
      async () => {
        try { return await platformApi.setEnvironmentStatus(environmentId, status) }
        catch (reason) {
          const vm = String(reason).includes("YOUGORI_VM_RUNTIME_BUSY")
          if (status !== "stopped" || (!vm && !String(reason).includes("YOUGORI_RUNTIME_BUSY"))) throw reason
          if (!await confirmRecovery(vm)) throw new Error("Stop cancelled. The abandoned runtime was not changed.")
          if (vm) await platformApi.recoverVmRuntime(environmentId)
          else await platformApi.recoverContainerRuntime(environmentId)
          return platformApi.setEnvironmentStatus(environmentId, "stopped")
        }
      },
      state?.environments.find(e => e.id === environmentId)?.kind === "cloud" ? status === "running" ? "Cloud server connected" : "Disconnected — cloud server left running" : status === "running" ? "Environment started" : status === "paused" ? "Environment paused" : "Environment stopped",
    )),
    deleteEnvironment: (environmentId, recoverRuntime) => runEnvironmentAction(environmentId, "deleting", async () => {
      let cleanup: Awaited<ReturnType<typeof platformApi.deleteEnvironment>>["storageCleanup"]
      await perform(async () => {
        const result = await platformApi.deleteEnvironment(environmentId, recoverRuntime)
        cleanup = result.storageCleanup
        return result
      })
      const warnings = cleanup?.warnings ?? []
      toastManager.add({
        title: warnings.length ? "Environment removed — cleanup incomplete" : "Environment removed",
        description: storageCleanupDescription(cleanup),
        type: warnings.length ? "warning" : "success",
        ...(warnings.length ? { timeout: 0 } : {}),
      })
    }),
    reclaimStorage: async () => {
      const result = await platformApi.reclaimStorage()
      setState(result)
      const warnings = result.storageCleanup?.warnings ?? []
      toastManager.add({ title: warnings.length ? "Storage cleanup needs attention" : "Storage cleanup complete", description: storageCleanupDescription(result.storageCleanup), type: warnings.length ? "warning" : "success", timeout: 0 })
    },
    recoverContainerRuntime: (environmentId) => runEnvironmentAction(environmentId, "stopping", () => perform(
      () => platformApi.recoverContainerRuntime(environmentId),
      "Runtime recovery finished",
      "Your saved containers and images were kept. Retry Start to open the environment.",
    )),
    factoryResetEnvironment: (environmentId, confirmation) => runEnvironmentAction(environmentId, "resetting", async () => {
      try { await perform(() => platformApi.factoryResetEnvironment(environmentId, confirmation), "Factory reset complete", "The original image is ready. Press Start to begin again.") }
      catch (reason) { try { setState(await platformApi.getState()) } catch { /* Preserve reset error. */ } throw reason }
    }),
    renameEnvironment: (environmentId, name) => perform(
      () => platformApi.renameEnvironment(environmentId, name),
      "Name saved",
    ),
    updateContainerStartupCommand: (environmentId, command) => perform(
      () => platformApi.updateContainerStartupCommand(environmentId, command),
      "Startup command saved",
      "It will run the next time you start this container.",
    ),
    updateResourcePolicy: (environmentId, resourcePolicy) => perform(
      () => platformApi.updateResourcePolicy(environmentId, resourcePolicy),
      "Resource policy saved",
      "The scheduler is using the new limits.",
    ),
    updateContainerNetwork: (environmentId, enabled) => perform(
      () => platformApi.updateContainerNetwork(environmentId, enabled),
      enabled ? "Internet access enabled" : "Internet access blocked",
      "Applied immediately to running environments and saved for the next start.",
    ),
    updateEnvironmentGpu: (environmentId, enabled) => perform(
      () => platformApi.updateEnvironmentGpu(environmentId, enabled),
      enabled ? "GPU access enabled" : "GPU access disabled",
      enabled ? "Yougori will expose accelerated graphics when the environment starts." : "The environment will use software rendering.",
    ),
    createConnection: (request) => perform(
      () => platformApi.createConnection(request),
      "Connection saved",
      "Access rules apply when the connection is enabled and both nodes are running.",
    ),
    setConnectionActive: (connectionId, active) => perform(
      () => platformApi.setConnectionActive(connectionId, active),
      active ? "Connection enabled" : "Connection paused",
    ),
    deleteConnection: (connectionId) => perform(() => platformApi.deleteConnection(connectionId), "Connection removed"),
    createSnapshot: (environmentId, name) => perform(
      () => platformApi.createSnapshot(environmentId, name),
      "Snapshot created",
      "Only changed blocks used additional storage.",
    ),
    deleteSnapshot: (snapshotId) => perform(() => platformApi.deleteSnapshot(snapshotId), "Snapshot deleted"),
    restoreSnapshot: (snapshotId) => perform(
      () => platformApi.restoreSnapshot(snapshotId),
      "Snapshot restored",
      "The environment, connections, and policies are ready at this restore point.",
    ),
    addDestination: (request) => perform(
      () => platformApi.addDestination(request),
      "Destination connected",
      "The destination is ready for encrypted backups.",
    ),
    deleteDestination: (destinationId) => perform(() => platformApi.deleteDestination(destinationId), "Destination removed"),
    runBackup: (environmentId, destinationId) => perform(
      () => platformApi.runBackup(environmentId, destinationId),
      "Backup complete",
      "The incremental snapshot is safely stored.",
    ),
    restoreBackup: (backupId) => perform(
      () => platformApi.restoreBackup(backupId),
      "Backup restored",
      "The environment, disk, connections, and resource policy were recovered.",
    ),
    duplicateEnvironment: async request => {
      await runEnvironmentAction(request.environmentId, "duplicating", async () => {
        try { await perform(() => duplicationApi.duplicate(request), "Environment duplicated", "The independent copy is ready to configure.") }
        finally { await refreshPlatform().catch(() => undefined) }
      })
    },
    duplicateLocalEnvironment: async (environmentId, name, storageDrive) => {
      await runEnvironmentAction(environmentId, "duplicating", async () => {
        await perform(() => localBackupApi.duplicate(environmentId, name, storageDrive), "Environment duplicated", "The independent copy is stopped and ready to configure.")
      })
    },
    importLocalBackup: (path, targetProvider) => perform(() => localBackupApi.import(path, targetProvider), "Local backup restored", "A new stopped environment has been added. Your existing environments are unchanged."),
    updateSettings: (settings) => {
      const patch = Object.fromEntries(Object.entries(settings).filter(([key, value]) => JSON.stringify(state?.settings[key as keyof AppSettings]) !== JSON.stringify(value))) as Partial<AppSettings>
      return perform(() => platformApi.patchSettings(patch, state?.settingsRevision ?? 0), "Settings saved")
    },
    refreshPlatform,
    configureCloudEnvironment:(id,profile)=>perform(()=>cloudApi.configure(id,profile),"Cloud SSH configured"),
    resetPlatform: () => perform(() => platformApi.resetPlatform(), "Local data reset"),
  }), [refreshPlatform, confirmRecovery, environmentActions, error, loading, perform, runEnvironmentAction, setState, state])

  const finishRecoveryConfirmation = (confirmed: boolean) => {
    recoveryResolver.current?.(confirmed)
    recoveryResolver.current = null
    setRecoveryConfirmation(null)
  }
  return <PlatformContext.Provider value={value}>{children}
    <AlertDialog open={Boolean(recoveryConfirmation)} onOpenChange={open => { if (!open) finishRecoveryConfirmation(false) }}>
      <AlertDialogPopup>
        <AlertDialogHeader>
          <AlertDialogTitle>Stop the abandoned runtime?</AlertDialogTitle>
          <AlertDialogDescription>{recoveringVm
            ? "This VM is still running outside the current Yougori instance. Recovery tries a normal shutdown, then forces it to stop if it does not respond. Unsaved guest work may be lost; the VM disk and snapshots are kept. Other VMs and runtimes owned by a live app will not be stopped. This can take about 40 seconds."
            : "The old Yougori app has closed, but its container runtime is still running. Stopping it will stop every container inside that abandoned runtime. Unsaved work may be lost; saved disks, images and snapshots are kept. Unrelated VMs and runtimes owned by a live app will not be stopped."}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <Button variant="ghost" onClick={() => finishRecoveryConfirmation(false)}>Cancel</Button>
          <Button variant="destructive" onClick={() => finishRecoveryConfirmation(true)}>Stop</Button>
        </AlertDialogFooter>
      </AlertDialogPopup>
    </AlertDialog>
  </PlatformContext.Provider>
}

export function usePlatform() {
  const context = useContext(PlatformContext)
  if (!context) throw new Error("usePlatform must be used within PlatformProvider")
  return context
}
