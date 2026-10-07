import seedState from "@/data/seed.json"
import { availableStorage } from "@/lib/storage-drives"
import type { CloudProfile } from "./cloud-api"
import { supportsConnections, supportsSharedConnection, connectionPermissions, isTunnelShared } from "@/lib/environment-connections"
import type {
  AddDestinationRequest,
  AppSettings,
  CreateConnectionRequest,
  CreateEnvironmentRequest,
  CommandResult,
  EnvironmentStatus,
  EnvironmentDeletionResult,
  GuestSession,
  PlatformState,
  ResourcePolicy,
  StorageAllocation,
} from "@/types/platform"
import {
  containerRuntimeCapacity,
  scheduleResources,
  validateContainerResourcePolicy,
} from "@/lib/domain"
import { guestFileFixture } from "@/lib/guest-file-fixture"

const STORAGE_KEY = "yougori.platform.v1"
const BUILTIN_MICRO_VM_SOURCE = "builtin:alpine"
const CLI_ENVIRONMENT_NAME = "Yougori CLI"

export interface InstalledSkills {
  environmentId: string
  skillPath: string
  referencePath: string
  delivery: "directory" | "drive"
  message: string
}

function isTauri() {
  return typeof window !== "undefined" && "__TAURI_INTERNALS__" in window
}

const browserAdapterEnabled =
  !import.meta.env.PROD && (import.meta.env.MODE === "test" || import.meta.env.VITE_YOUGORI_TEST_ADAPTER === "1")

async function nativeInvoke<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  const { invoke } = await import("@tauri-apps/api/core")
  return invoke<T>(command, args)
}

function cloneSeed(): PlatformState {
  return enableAutomaticAllocation(structuredClone(seedState) as PlatformState)
}

function enableAutomaticAllocation(state: PlatformState) {
  for (const environment of state.environments) environment.resourcePolicy.dynamic = true
  for (const snapshot of state.snapshots) {
    if (snapshot.environmentState) snapshot.environmentState.resourcePolicy.dynamic = true
  }
  return state
}

function readBrowserState(): PlatformState {
  try {
    const value = localStorage.getItem(STORAGE_KEY)
    if (value) return enableAutomaticAllocation(JSON.parse(value) as PlatformState)
  } catch {
    // A restricted browser context can reject localStorage. The in-memory seed is safe.
  }
  return cloneSeed()
}

function writeBrowserState(state: PlatformState) {
  enableAutomaticAllocation(state)
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(state))
  } catch {
    // The app remains usable for this session when persistence is unavailable.
  }
  return structuredClone(state)
}

function now() {
  return new Date().toISOString()
}

function id(prefix: string) {
  return `${prefix}-${crypto.randomUUID()}`
}

function hasCommandTerminal(environment: PlatformState["environments"][number]) {
  return environment.kind === "container"
    || environment.kind === "cloud"
    || (environment.kind === "microVm" && environment.runtime === BUILTIN_MICRO_VM_SOURCE)
}

function enforceLocalRetention(state: PlatformState) {
  state.snapshots = state.snapshots.slice(0, state.settings.snapshotRetention)
  state.backupRuns = state.backupRuns.slice(0, 500)
}

function captureSnapshot(state: PlatformState, environment: PlatformState["environments"][number], name: string, deltaGb: number, createdAt?: string) {
  state.snapshots.unshift({
    id: id("snap"),
    environmentId: environment.id,
    name,
    createdAt: createdAt ?? now(),
    sizeGb: Math.max(0.2, environment.storageDeltaGb + 7.4),
    deltaGb,
    encrypted: true,
    status: "ready",
    environmentState: {
      runtime: environment.runtime,
      provider: environment.provider,
      runtimePath: environment.runtimePath,
      containerCommand: environment.containerCommand,
      networkAccess: environment.networkAccess,
      gpuAccess: environment.gpuAccess,
      sandboxPolicy: environment.sandboxPolicy,
      description: environment.description,
      branchType: environment.branchType,
      resourcePolicy: structuredClone(environment.resourcePolicy),
    },
    connections: structuredClone(state.connections.filter((item) => item.sourceId === environment.id || item.targetId === environment.id)),
  })
}

function validateResourcePolicy(policy: ResourcePolicy | CreateEnvironmentRequest["resourcePolicy"]) {
  for (const [label, range] of [["CPU", policy.cpu], ["Memory", policy.memoryGb]] as const) {
    if (!Number.isFinite(range.min) || !Number.isFinite(range.preferred) || !Number.isFinite(range.max) || range.min <= 0) {
      throw new Error(`${label} values must be positive numbers`)
    }
    if (range.preferred < range.min || range.max < range.preferred) {
      throw new Error(`${label} values must satisfy minimum ≤ preferred ≤ maximum`)
    }
  }
}

export async function run<T>(command: string, args: Record<string, unknown> | undefined, browser: () => T | Promise<T>) {
  if (isTauri()) return nativeInvoke<T>(command, args)
  if (browserAdapterEnabled) return browser()
  throw new Error("Yougori must run inside its native desktop application. Start it with `npm run tauri dev`.")
}

export const platformApi = {
  installEnvironmentSkills(environmentId: string) {
    return run<InstalledSkills>("install_environment_skills", { environmentId }, () => {
      const environment = readBrowserState().environments.find(e => e.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      if (environment.status !== "running") throw new Error("Start this environment before installing Skills.")
      if (environment.kind === "cloud" || environment.kind === "computerBranch") throw new Error("Skill installation supports local containers, microVMs and VMs.")
      const drive = environment.kind === "fullVm"
      const base = `${drive ? "YOUGORI · preview" : "/yougori-import-preview"}/yougori-environment`
      return { environmentId, skillPath: `${base}/SKILL.md`, referencePath: `${base}/references/connections.md`, delivery: drive ? "drive" : "directory", message: "Browser preview only. No files were installed; use Yougori Desktop to install Skills inside this environment." }
    })
  },
  addCloudEnvironment(request: CloudProfile) {
    return run<PlatformState>("add_cloud_environment", { request }, () => {
      const state = readBrowserState()
      if (state.environments.some(e => e.name.toLowerCase() === request.name.trim().toLowerCase())) throw new Error("An environment with this name already exists")
      if (!request.host || !request.username || !request.identityFile || !request.hostKey) throw new Error("Complete the SSH connection and verify the server identity")
      const environmentId = id("env"), range = { min: 0, preferred: 0, max: 0, current: 0 }
      state.environments.push({ id: environmentId, name: request.name.trim(), kind: "cloud", provider: "cloudSsh", runtime: `${request.vendor} · ${request.username}@${request.host}:${request.port}`, status: "stopped", description: "Existing cloud server · private SSH connection", createdAt: now(), cpuUsage: 0, memoryUsageGb: 0, storageDeltaGb: 0, networkRxMbps: 0, networkAccess: false, resourcePolicy: { cpu: { ...range }, memoryGb: { ...range }, priority: "normal", dynamic: true } })
      localStorage.setItem(`yougori.cloud.${environmentId}`, JSON.stringify(request))
      return writeBrowserState(state)
    })
  },
  connectionSkills(environmentId: string) {
    return run<string>("get_connection_skills", { environmentId }, async () => {
      const { workspaceApi } = await import("@/api/workspace-api")
      const { previewConnectionSkill } = await import("@/lib/connection-skills")
      const { shares } = await workspaceApi.services(environmentId)
      return previewConnectionSkill(readBrowserState(), environmentId, shares)
    })
  },
  getStorageAllocation(environmentId?: string, newVm = false, storageDrive?: string) {
    return run<StorageAllocation>("get_storage_allocation", { environmentId: environmentId ?? null, newVm, storageDrive: storageDrive || null }, () => {
      const state = readBrowserState()
      if (!environmentId) return { capacityGb: 0, physicalGb: 0, maximumGb: Math.max(0, Math.min(newVm ? 16384 : 16380, Math.floor(availableStorage(state.host, storageDrive) - 2))), shared: false }
      const environment = environmentId ? state.environments.find(e => e.id === environmentId) : undefined
      if (environmentId && !environment) throw new Error("Environment not found")
      const container = environment?.kind === "container"
      const saved = Number(localStorage.getItem(`${STORAGE_KEY}.disk.${environmentId}`)) || environment?.storageLimitGb
      const capacityGb = saved || (container ? 20 : environment?.kind === "microVm" ? 6 : 64)
      return { capacityGb, physicalGb: 0.1, maximumGb: Math.max(capacityGb, Math.floor(availableStorage(state.host, environment?.storageDrive) - 2)), shared: false, limitEnforced: container ? Boolean(saved) : undefined }
    })
  },

  expandEnvironmentStorage(environmentId: string, capacityGb: number) {
    return run<StorageAllocation>("expand_environment_storage", { environmentId, capacityGb }, async () => {
      const state = readBrowserState()
      const environment = state.environments.find(e => e.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      const before = await platformApi.getStorageAllocation(environmentId)
      const container = environment.kind === "container"
      if (environment.status !== "stopped" && (!container || !before.limitEnforced)) throw new Error(container ? "Stop this container once to enable its storage limit." : "Stop the environment before expanding storage.")
      const minimum = container ? Math.max(1, Math.floor(before.physicalGb) + 1) : Math.ceil(before.capacityGb)
      if (!Number.isInteger(capacityGb) || capacityGb < minimum || capacityGb > Math.min(container ? 16380 : 16384, before.maximumGb)) throw new Error(container ? "Choose a storage limit from 1 GB to the available maximum, above this container's current usage." : "Storage can only be expanded within the available capacity.")
      localStorage.setItem(`${STORAGE_KEY}.disk.${environmentId}`, String(capacityGb))
      if (container) { environment.storageLimitGb = capacityGb; writeBrowserState(state) }
      return { ...before, capacityGb, limitEnforced: container ? true : undefined }
    })
  },
  async selectBootMedia() {
    if (!isTauri()) {
      if (browserAdapterEnabled) return null
      throw new Error("The native Yougori file picker is unavailable in a browser.")
    }
    const { open } = await import("@tauri-apps/plugin-dialog")
    const selected = await open({
      multiple: false,
      directory: false,
      filters: [
        { name: "Boot media, microVM manifests, and virtual disks", extensions: ["json", "iso", "qcow2", "qcow", "vhd", "vhdx", "vmdk", "img", "raw"] },
      ],
    })
    return typeof selected === "string" ? selected : null
  },

  getState() {
    return run<PlatformState>("get_platform_state", undefined, readBrowserState)
  },

  openEnvironmentWindow(environmentId: string) {
    return run<boolean>("open_environment_window", { environmentId }, () => false)
  },

  // The CLI itself runs inside a microVM. The browser preview models the same
  // environment so its permissions behave like every other guest; real grants
  // and guest commands still require the desktop runtime.
  openIsolatedCli() {
    return run<string>("open_isolated_cli", {}, async () => {
      const existing = readBrowserState().environments.find(environment => environment.name === CLI_ENVIRONMENT_NAME)
      const created = existing ?? (await platformApi.createEnvironment({
        name: CLI_ENVIRONMENT_NAME,
        kind: "microVm",
        provider: "qemu",
        runtime: BUILTIN_MICRO_VM_SOURCE,
        networkAccess: true,
        description: "Isolated Yougori CLI. No PC access by default. Grant selected PC folders and environment control explicitly.",
        resourcePolicy: { cpu: { min: 1, preferred: 1, max: 2 }, memoryGb: { min: 0.5, preferred: 0.5, max: 2 }, priority: "normal", dynamic: true },
      })).environments.find(environment => environment.name === CLI_ENVIRONMENT_NAME)
      if (!created) throw new Error("CLI environment was not created")
      const next = await platformApi.setEnvironmentStatus(created.id, "running")
      next.cliEnvironmentId = created.id
      writeBrowserState(next)
      return created.id
    })
  },

  grantIsolatedCliEnvironment(environmentId: string, permission: string) {
    return run<{ grant: { id: string }; command: string }>("grant_isolated_cli_environment", { environmentId, permission }, () => {
      throw new Error("Granting an environment to the isolated CLI requires Yougori Desktop")
    })
  },

  closeEnvironmentWindow() {
    return run<void>("close_environment_window", undefined, () => { window.close() })
  },

  resetPlatform() {
    return run<PlatformState>("reset_platform_state", undefined, () => {
      Object.keys(localStorage).filter(key => key.startsWith(`${STORAGE_KEY}.disk.`)).forEach(key => localStorage.removeItem(key))
      return writeBrowserState(cloneSeed())
    })
  },

  createEnvironment(request: CreateEnvironmentRequest) {
    return run<PlatformState>("create_environment", { request }, () => {
      const state = readBrowserState()
      const name = request.name.trim()
      if (name.length < 2 || name.length > 80) throw new Error("Environment name must be between 2 and 80 characters")
      if (!request.runtime.trim()) throw new Error("Runtime is required")
      if (request.kind === "container" && !["yougoriOci", "yougoriCuda"].includes(request.provider)) {
        throw new Error("Choose the Yougori OCI or NVIDIA CUDA container runtime")
      }
      if (request.kind === "computerBranch") {
        throw new Error("Computer Branch is temporarily unavailable")
      } else if (request.sandboxPolicy) {
        throw new Error("File access policy is only valid for Computer Branches")
      }
      if (state.environments.some((environment) => environment.name.toLocaleLowerCase() === name.toLocaleLowerCase())) {
        throw new Error("An environment with this name already exists")
      }
      validateResourcePolicy(request.resourcePolicy)
      const policyErrors = request.kind === "container"
        ? validateContainerResourcePolicy(request.resourcePolicy, state.host)
        : []
      if (policyErrors.length > 0) throw new Error(policyErrors.join(" "))
      if (request.storageGb !== undefined && (!Number.isInteger(request.storageGb) || request.storageGb < (request.kind === "microVm" ? 6 : 1) || request.storageGb > Math.min(request.kind === "container" ? 16380 : 16384, Math.floor(availableStorage(state.host, request.storageDrive) - 2)))) throw new Error("Storage exceeds available capacity or is below the minimum.")
      const environmentId = id("env")
      if (request.storageGb !== undefined) {
        localStorage.setItem(`${STORAGE_KEY}.disk.${environmentId}`, String(request.storageGb))
      }
      state.environments.unshift({
        id: environmentId,
        ...request,
        name,
        networkAccess: ["container", "microVm", "fullVm"].includes(request.kind) && (request.networkAccess ?? true),
        gpuAccess: (request.kind === "container" || request.kind === "fullVm") && (request.provider === "yougoriCuda" || Boolean(request.gpuAccess)),
        runtime: request.runtime.trim(),
        description: request.description.trim(),
        status: "stopped",
        createdAt: now(),
        cpuUsage: 0,
        memoryUsageGb: 0,
        storageDeltaGb: 0.1,
        storageLimitGb: request.kind === "container" ? request.storageGb ?? 20 : undefined,
        networkRxMbps: 0,
        resourcePolicy: {
          ...request.resourcePolicy,
          dynamic: true,
          cpu: { ...request.resourcePolicy.cpu, current: 0 },
          memoryGb: { ...request.resourcePolicy.memoryGb, current: 0 },
        },
      })
      return writeBrowserState(state)
    })
  },

  setEnvironmentStatus(environmentId: string, status: EnvironmentStatus) {
    return run<PlatformState>("set_environment_status", { environmentId, status }, () => {
      const state = readBrowserState()
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      if (environment.kind === "cloud") {
        if (!["running", "stopped"].includes(status)) throw new Error("Cloud nodes support Connect and Disconnect only")
        environment.status = status
        environment.lastError = undefined
        environment.controlEndpoint = status === "running" ? "socks5h://127.0.0.1:1080" : undefined
        environment.consoleEndpoint = status === "running" ? "http://127.0.0.1:8080" : undefined
        for (const link of state.connections.filter(c => c.sourceId === environmentId || c.targetId === environmentId)) link.enforcementStatus = status === "running" && state.environments.find(e => e.id === (link.sourceId === environmentId ? link.targetId : link.sourceId))?.status === "running" ? "enforced" : "pending"
        return writeBrowserState(state)
      }
      if (status === "running" && environment.kind === "container") {
        const candidates = state.environments.filter((item) =>
          item.kind === "container" && (item.status === "running" || item.id === environmentId))
        const cpuFloor = candidates.reduce((sum, item) => sum + (item.resourcePolicy.dynamic ? item.resourcePolicy.cpu.min : item.resourcePolicy.cpu.preferred), 0)
        const memoryFloor = candidates.reduce((sum, item) => sum + (item.resourcePolicy.dynamic ? item.resourcePolicy.memoryGb.min : item.resourcePolicy.memoryGb.preferred), 0)
        const capacity = containerRuntimeCapacity(state.host)
        const reservedMemory = state.environments.reduce((sum, item) => {
          if (item.id === environmentId) return sum
          const reservesMemory = item.kind === "container"
            ? item.status === "paused"
            : item.status === "running" || item.status === "paused"
          return sum + (reservesMemory ? Math.max(item.resourcePolicy.memoryGb.current, item.resourcePolicy.memoryGb.preferred) : 0)
        }, 0)
        if (cpuFloor > capacity.cpu || memoryFloor + reservedMemory > capacity.memoryGb) {
          throw new Error("Not enough shared container capacity after reserving RAM for the host; stop a container or lower its allocation.")
        }
      }
      environment.status = status
      if (status === "running") {
        environment.lastOpenedAt = now()
        environment.resourcePolicy.cpu.current = environment.resourcePolicy.cpu.preferred
        environment.resourcePolicy.memoryGb.current = environment.resourcePolicy.memoryGb.preferred
        environment.cpuUsage = Math.max(environment.cpuUsage, 4)
        environment.memoryUsageGb = Math.max(environment.memoryUsageGb, environment.resourcePolicy.memoryGb.min * 0.65)
      } else {
        environment.cpuUsage = 0
        environment.memoryUsageGb = 0
        environment.networkRxMbps = 0
        environment.resourcePolicy.cpu.current = 0
        if (status !== "paused") environment.resourcePolicy.memoryGb.current = 0
      }
      return writeBrowserState(scheduleResources(state))
    })
  },

  factoryResetEnvironment(environmentId: string, confirmation: string) {
    return run<PlatformState>("factory_reset_environment", { environmentId, confirmation }, () => {
      const state = readBrowserState()
      const environment = state.environments.find(item => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      if (confirmation !== environment.name) throw new Error("Type the environment name exactly to confirm factory reset")
      if (environment.kind === "cloud" || environment.kind === "computerBranch" || environment.provider === "nativeSandbox") throw new Error("Factory reset is only supported for containers, MicroVMs and VMs")
      if (environment.status !== "stopped" && environment.status !== "error") throw new Error("Shut down this environment before factory reset")
      environment.status = "stopped"
      environment.lastError = undefined
      environment.consoleEndpoint = undefined
      environment.controlEndpoint = undefined
      environment.lastOpenedAt = undefined
      environment.cpuUsage = environment.memoryUsageGb = environment.storageDeltaGb = environment.networkRxMbps = 0
      environment.resourcePolicy.cpu.current = environment.resourcePolicy.memoryGb.current = 0
      state.snapshots = state.snapshots.filter(item => item.environmentId !== environmentId)
      for (const connection of state.connections) {
        if (connection.sourceId === environmentId || connection.targetId === environmentId) {
          connection.enforcementStatus = "pending"
          connection.providerRuleIds = []
          connection.lastError = undefined
        }
      }
      return writeBrowserState(state)
    })
  },

  deleteEnvironment(environmentId: string, recoverRuntime = false) {
    return run<EnvironmentDeletionResult>("delete_environment", { environmentId, recoverRuntime }, () => {
      const state = readBrowserState()
      state.environments = state.environments.filter((item) => item.id !== environmentId)
      state.connections = state.connections.filter((item) => item.sourceId !== environmentId && item.targetId !== environmentId)
      state.snapshots = state.snapshots.filter((item) => item.environmentId !== environmentId)
      localStorage.removeItem(`yougori.cloud.${environmentId}`)
      return { ...writeBrowserState(state), storageCleanup: { reclaimedCacheBytes: 0, warnings: [] } }
    })
  },

  reclaimStorage() {
    return run<EnvironmentDeletionResult>("reclaim_storage", {}, () => ({ ...readBrowserState(), storageCleanup: { reclaimedCacheBytes: 0, reclaimedDiskBytes: 0, notes: ["Storage reclamation requires the desktop runtime."], warnings: [] } }))
  },

  recoverContainerRuntime(environmentId: string) {
    return run<PlatformState>("recover_container_runtime", { environmentId, confirmed: true }, () => readBrowserState())
  },

  recoverVmRuntime(environmentId: string) {
    return run<PlatformState>("recover_vm_runtime", { environmentId, confirmed: true }, () => readBrowserState())
  },

  renameEnvironment(environmentId: string, name: string) {
    name = name.trim()
    if ([...name].length < 2 || [...name].length > 80 || /\p{Cc}/u.test(name)) return Promise.reject(new Error("Name must contain 2–80 characters and no control characters"))
    return run<PlatformState>("rename_environment", { environmentId, name }, () => {
      const state = readBrowserState()
      const environment = state.environments.find(item => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      environment.name = name
      return writeBrowserState(state)
    })
  },

  updateContainerStartupCommand(environmentId: string, command: string) {
    command = command.trim()
    if (new TextEncoder().encode(command).length > 32768 || command.includes("\0")) return Promise.reject(new Error("Startup command must be at most 32 KB and cannot contain null characters"))
    return run<PlatformState>("update_container_startup_command", { environmentId, command }, () => {
      const state = readBrowserState()
      const environment = state.environments.find(item => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      if (environment.kind !== "container") throw new Error("Startup commands are available for local containers only")
      if (environment.status !== "stopped") throw new Error("Stop the container before changing its startup command")
      environment.containerCommand = command || undefined
      return writeBrowserState(state)
    })
  },

  updateResourcePolicy(environmentId: string, resourcePolicy: ResourcePolicy) {
    resourcePolicy = { ...resourcePolicy, dynamic: true }
    return run<PlatformState>("update_resource_policy", { environmentId, resourcePolicy }, () => {
      const state = readBrowserState()
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      if (environment.kind === "cloud") throw new Error("Cloud resources are managed outside Yougori")
      validateResourcePolicy(resourcePolicy)
      const policyErrors = environment.kind === "container"
        ? validateContainerResourcePolicy(resourcePolicy, state.host)
        : []
      if (policyErrors.length > 0) throw new Error(policyErrors.join(" "))
      if (resourcePolicy.cpu.max > state.host.totalCpu || resourcePolicy.memoryGb.max > state.host.totalMemoryGb) throw new Error("Resource maximum cannot exceed the host capacity")
      if (environment.status === "running" && (environment.kind === "microVm" || environment.kind === "fullVm") && (resourcePolicy.cpu.max > environment.resourcePolicy.cpu.max || resourcePolicy.memoryGb.max > environment.resourcePolicy.memoryGb.max)) throw new Error("Stop the virtual machine before expanding its CPU or memory maximum")
      environment.resourcePolicy = {
        ...resourcePolicy,
        cpu: { ...resourcePolicy.cpu, current: environment.status === "running" ? resourcePolicy.cpu.preferred : 0 },
        memoryGb: { ...resourcePolicy.memoryGb, current: environment.status !== "running" ? 0 : environment.kind === "microVm" ? environment.resourcePolicy.memoryGb.current : resourcePolicy.memoryGb.preferred },
      }
      return writeBrowserState(scheduleResources(state))
    })
  },

  updateContainerNetwork(environmentId: string, enabled: boolean) {
    return run<PlatformState>("update_container_network", { environmentId, enabled }, () => {
      const state = readBrowserState()
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      if (!(["yougoriOci", "yougoriCuda"].includes(environment.provider ?? "") && environment.kind === "container") && !(environment.provider === "qemu" && ["fullVm", "microVm"].includes(environment.kind))) {
        throw new Error("Internet access is available for containers, MicroVMs and VMs")
      }
      if (!["stopped", "running", "paused"].includes(environment.status)) {
        throw new Error("Wait until the environment is ready before changing internet access")
      }
      environment.networkAccess = enabled
      return writeBrowserState(state)
    })
  },

  updateEnvironmentGpu(environmentId: string, enabled: boolean) {
    return run<PlatformState>("update_environment_gpu", { environmentId, enabled }, () => {
      const state = readBrowserState()
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      const supportsGpu = ["yougoriOci", "yougoriCuda"].includes(environment.provider ?? "")
        ? environment.kind === "container"
        : environment.provider === "qemu" && environment.kind === "fullVm"
      if (!supportsGpu) {
        throw new Error("GPU access is unavailable for this environment")
      }
      if (environment.status !== "stopped") {
        throw new Error("Stop the environment before changing GPU access")
      }
      environment.gpuAccess = enabled
      return writeBrowserState(state)
    })
  },

  createConnection(request: CreateConnectionRequest) {
    return run<PlatformState>("create_connection", { request }, () => {
      const state = readBrowserState()
      if (request.sourceId === request.targetId) throw new Error("An environment cannot connect to itself")
      if (!request.permissions.length && !request.commands) throw new Error("Select at least one capability")
      if (request.sshPort !== undefined && (!Number.isInteger(request.sshPort) || request.sshPort < 1 || request.sshPort > 65535 || (!request.permissions.includes("network") && !(request.permissions.includes("ports") && request.ports.includes(String(request.sshPort)))))) throw new Error("SSH requires its TCP port to be explicitly allowed on this connection")
      if (request.ports.some((port) => !/^\d+$/.test(port) || Number(port) < 1 || Number(port) > 65_535)) {
        throw new Error("Ports must be valid values between 1 and 65535")
  }
      const environmentIds = new Set(state.environments.map((environment) => environment.id))
      if (!environmentIds.has(request.sourceId) || !environmentIds.has(request.targetId)) {
        throw new Error("A selected environment no longer exists")
      }
      const source = state.environments.find(e => e.id === request.sourceId)!
      const target = state.environments.find(e => e.id === request.targetId)!
      if (!supportsConnections(source) || !supportsConnections(target)) throw new Error("Connections require containers, MicroVMs or VMs")
      if ((request.selectedFolders?.length ?? 0) > 8 || request.selectedFolders?.some(folder =>
        ![source.id, target.id].includes(folder.environmentId) || !folder.path.startsWith("/") || folder.path === "/" || folder.path.split("/").includes(".."))) throw new Error("Choose up to eight specific folders from these two environments")
      const existing = state.connections.find(connection =>
        (connection.sourceId === request.sourceId && connection.targetId === request.targetId)
          || (connection.sourceId === request.targetId && connection.targetId === request.sourceId))
      const remote = isTunnelShared(source) || isTunnelShared(target)
      if (remote && (isTunnelShared(source) && isTunnelShared(target))) throw new Error("Connect one shared environment to one environment on this computer")
      if (remote) {
        const sharedId = isTunnelShared(source) ? source.id : target.id
        if (state.connections.some(connection => (connection.sourceId === sharedId || connection.targetId === sharedId) && connection.id !== existing?.id)) throw new Error("This shared environment already has a private connection")
      }
      const allowed = connectionPermissions(supportsSharedConnection(source, target), remote)
      if (request.permissions.some(p => !allowed.includes(p))) throw new Error("Secrets sharing is available between containers only. Use Data for a VM connection folder.")
      if (existing) {
        Object.assign(existing, request, { volume: request.volume?.trim() || undefined, enforcementStatus: existing.active ? "enforced" : "pending", lastError: undefined })
        return writeBrowserState(state)
      }
      state.connections.push({
        id: id("conn"),
        ...request,
        volume: request.volume?.trim() || undefined,
        active: true,
        createdAt: now(),
      })
      return writeBrowserState(state)
    })
  },

  listEnvironmentFolders(environmentId: string, path: string) {
    return run<{ path: string; entries: { name: string; directory: boolean }[] }>("list_environment_folders", { environmentId, path }, () => ({ path: path || "/workspace", entries: [] }))
  },
  requestConnectedFiles(environmentId: string, request: { connectionId: string; operation: string; path: string; [key: string]: unknown }) {
    return run<{ entries?: { name: string; directory: boolean; size: number }[]; data?: string; ok?: boolean }>("request_connected_files", { environmentId, request }, () => {
      if (request.operation === "list") return { entries: [] }
      throw new Error("Shared files require Yougori Desktop")
    })
  },

  executeConnectedCommand(connectionId: string, sourceId: string, command: string) {
    return run<CommandResult>("execute_connected_command", { request: { connectionId, sourceId, command } }, () => {
      const state = readBrowserState()
      const connection = state.connections.find(item => item.id === connectionId)
      if (!connection?.commands || !connection.active || connection.enforcementStatus === "error") throw new Error("This connection does not allow commands")
      const targetId = connection.sourceId === sourceId ? connection.targetId : connection.targetId === sourceId && connection.direction === "bidirectional" ? connection.sourceId : ""
      if (!targetId) throw new Error("Commands are not allowed in this direction")
      return { stdout: `[test adapter] ${command}\n`, stderr: "", exitCode: 0 }
    })
  },

  setConnectionActive(connectionId: string, active: boolean) {
    return run<PlatformState>("set_connection_active", { connectionId, active }, () => {
      const state = readBrowserState()
      const connection = state.connections.find((item) => item.id === connectionId)
      if (!connection) throw new Error("Connection not found")
      connection.active = active
      return writeBrowserState(state)
    })
  },

  deleteConnection(connectionId: string) {
    return run<PlatformState>("delete_connection", { connectionId }, () => {
      const state = readBrowserState()
      state.connections = state.connections.filter((item) => item.id !== connectionId)
      return writeBrowserState(state)
    })
  },

  createSnapshot(environmentId: string, name: string) {
    return run<PlatformState>("create_snapshot", { environmentId, name }, () => {
      const state = readBrowserState()
      const snapshotName = name.trim()
      if (!snapshotName || snapshotName.length > 100) {
        throw new Error("Snapshot name must be between 1 and 100 characters")
      }
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      captureSnapshot(state, environment, snapshotName, Math.max(0.1, environment.storageDeltaGb * 0.18))
      enforceLocalRetention(state)
      return writeBrowserState(state)
    })
  },

  deleteSnapshot(snapshotId: string) {
    return run<PlatformState>("delete_snapshot", { snapshotId }, () => {
      const state = readBrowserState()
      state.snapshots = state.snapshots.filter((item) => item.id !== snapshotId)
      return writeBrowserState(state)
    })
  },

  restoreSnapshot(snapshotId: string) {
    return run<PlatformState>("restore_snapshot", { snapshotId }, () => {
      const state = readBrowserState()
      const snapshot = state.snapshots.find((item) => item.id === snapshotId)
      if (!snapshot) throw new Error("Snapshot not found")
      const environment = state.environments.find((item) => item.id === snapshot.environmentId)
      if (!environment) throw new Error("Environment not found")
      environment.status = "stopped"
      environment.storageDeltaGb = snapshot.deltaGb
      if (snapshot.environmentState) {
        if (environment.kind === "container") {
          const errors = validateContainerResourcePolicy(snapshot.environmentState.resourcePolicy, state.host)
          if (errors.length > 0) throw new Error(errors.join(" "))
        }
        environment.runtime = snapshot.environmentState.runtime
        environment.provider = snapshot.environmentState.provider
        environment.runtimePath = snapshot.environmentState.runtimePath
        environment.containerCommand = snapshot.environmentState.containerCommand
        environment.networkAccess = snapshot.environmentState.networkAccess
        environment.gpuAccess = snapshot.environmentState.gpuAccess
        environment.sandboxPolicy = snapshot.environmentState.sandboxPolicy
        environment.description = snapshot.environmentState.description
        environment.branchType = snapshot.environmentState.branchType
        environment.resourcePolicy = structuredClone(snapshot.environmentState.resourcePolicy)
      }
      if (snapshot.connections) {
        state.connections = state.connections.filter((item) => item.sourceId !== environment.id && item.targetId !== environment.id)
        const environmentIds = new Set(state.environments.map((item) => item.id))
        state.connections.push(...structuredClone(snapshot.connections.filter((item) => environmentIds.has(item.sourceId) && environmentIds.has(item.targetId))))
      }
      environment.cpuUsage = 0
      environment.memoryUsageGb = 0
      environment.resourcePolicy.cpu.current = 0
      environment.resourcePolicy.memoryGb.current = 0
      return writeBrowserState(scheduleResources(state))
    })
  },

  addDestination(request: AddDestinationRequest) {
    return run<PlatformState>("add_backup_destination", { request }, () => {
      const state = readBrowserState()
      if (!request.name.trim() || !request.location.trim() || !request.accessKey.trim() || !request.secretKey.trim()) {
        throw new Error("Destination, location, and credentials are required")
      }
      const { accessKey, secretKey, ...destination } = request
      void accessKey
      void secretKey
      state.destinations.push({
        id: id("dest"),
        ...destination,
        name: destination.name.trim(),
        location: destination.location.trim(),
        encrypted: true,
        connected: true,
        lastVerifiedAt: now(),
      })
      return writeBrowserState(state)
    })
  },

  deleteDestination(destinationId: string) {
    return run<PlatformState>("delete_backup_destination", { destinationId }, () => {
      const state = readBrowserState()
      state.destinations = state.destinations.filter((item) => item.id !== destinationId)
      state.backupRuns = state.backupRuns.filter((item) => item.destinationId !== destinationId)
      return writeBrowserState(state)
    })
  },

  runBackup(environmentId: string, destinationId: string) {
    return run<PlatformState>("run_backup", { environmentId, destinationId }, () => {
      const state = readBrowserState()
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      const destination = state.destinations.find((item) => item.id === destinationId)
      if (!destination) throw new Error("Backup destination not found")
      if (!destination.connected) throw new Error("Backup destination is offline")
      const transfer = Math.max(0.1, environment.storageDeltaGb * 0.12)
      const createdAt = now()
      captureSnapshot(state, environment, `Backup · ${new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date())}`, transfer, createdAt)
      state.backupRuns.unshift({
        id: id("backup"),
        environmentId,
        destinationId,
        createdAt,
        completedAt: now(),
        transferredGb: transfer,
        deduplicatedGb: Math.max(0, environment.storageDeltaGb - transfer),
        status: "complete",
      })
      enforceLocalRetention(state)
      return writeBrowserState(state)
    })
  },

  restoreBackup(backupId: string) {
    return run<PlatformState>("restore_backup", { backupId }, () => {
      const state = readBrowserState()
      const backupRun = state.backupRuns.find((item) => item.id === backupId)
      if (!backupRun || backupRun.status !== "complete") throw new Error("Completed backup not found")
      return writeBrowserState(state)
    })
  },

  getGuestSession(environmentId: string) {
    return run<GuestSession>("get_guest_session", { environmentId }, () => {
      const state = readBrowserState()
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment || environment.status !== "running") throw new Error("Start the environment before opening it")
      return {
        kind: environment.kind === "cloud" ? "headlessTerminal" : environment.kind === "container"
          ? "containerTerminal"
          : environment.kind === "microVm"
            ? environment.runtime === BUILTIN_MICRO_VM_SOURCE
              ? "headlessTerminal"
              : "headlessSerial"
            : "embeddedVnc",
        message: "Browser test adapter session",
      }
    })
  },

  readEnvironmentConsole(environmentId: string) {
    return run<string>("read_environment_console", { environmentId }, () => "[browser adapter] microVM serial output\n")
  },

  executeEnvironmentCommand(environmentId: string, command: string) {
    return run<CommandResult>("execute_environment_command", { request: { environmentId, command } }, () => {
      const state = readBrowserState()
      const environment = state.environments.find((item) => item.id === environmentId)
      if (!environment) throw new Error("Environment not found")
      if (environment.status !== "running") throw new Error("The environment is not running")
      const value = command.trim()
      if (!value || value.length > 32_768) throw new Error("Command must be between 1 and 32768 characters")
      if (!hasCommandTerminal(environment)) {
        if (environment.kind === "microVm") {
          throw new Error("Command execution is unavailable for custom microVMs; use the read-only serial console")
        }
        throw new Error("Use the graphical console to interact with this environment")
      }
      return guestFileFixture(environmentId, value) ?? {
        stdout: `[test adapter] ${value}\n`,
        stderr: "",
        exitCode: 0,
      }
    })
  },

  updateSettings(settings: AppSettings) {
    return run<PlatformState>("update_settings", { settings }, () => {
      const state = readBrowserState()
      if (!Number.isInteger(settings.snapshotRetention)
        || settings.snapshotRetention < 1
        || settings.snapshotRetention > 365) {
        throw new Error("Snapshot retention must be between 1 and 365")
      }
      if (!Number.isInteger(settings.bandwidthLimitMbps)
        || settings.bandwidthLimitMbps < 0
        || settings.bandwidthLimitMbps > 100_000) {
        throw new Error("Backup bandwidth must be 0 (unlimited) or at most 100,000 Mbps")
      }
      state.settings = settings
      state.settingsRevision = (state.settingsRevision ?? 0) + 1
      enforceLocalRetention(state)
      return writeBrowserState(scheduleResources(state))
    })
  },

  async patchSettings(patch: Partial<AppSettings>, expectedRevision: number) {
    await run<{ revision: number; changed: Partial<AppSettings>; applied: boolean }>("patch_settings", { patch, expectedRevision }, () => {
      const state = readBrowserState()
      if ((state.settingsRevision ?? 0) !== expectedRevision) throw new Error("Settings changed. Read the current settings and retry.")
      const unknown = Object.keys(patch).filter(key => !(key in state.settings))
        .filter(key => !["autoStartEnvironmentIds", "keepAwake", "customThemeColors", "startupHeadless"].includes(key))
      if (unknown.length) throw new Error(`Unknown settings field: ${unknown[0]}`)
      const next = { ...state.settings, ...patch }
      if (!Number.isInteger(next.snapshotRetention) || next.snapshotRetention < 1 || next.snapshotRetention > 365) throw new Error("Snapshot retention must be between 1 and 365")
      if (!Number.isInteger(next.bandwidthLimitMbps) || next.bandwidthLimitMbps < 0 || next.bandwidthLimitMbps > 100_000) throw new Error("Backup bandwidth must be 0 (unlimited) or at most 100,000 Mbps")
      if (next.dataDirectory !== state.settings.dataDirectory) throw new Error("Use Storage settings to choose a location and restart the engine")
      if (next.autoStartEnvironmentIds?.some(id => !state.environments.some(environment => environment.id === id))) throw new Error("Automatic startup must reference existing environments")
      const changed = Object.fromEntries(Object.entries(patch).filter(([key, value]) => JSON.stringify(state.settings[key as keyof AppSettings]) !== JSON.stringify(value))) as Partial<AppSettings>
      state.settings = next
      if (Object.keys(changed).length) state.settingsRevision = (state.settingsRevision ?? 0) + 1
      enforceLocalRetention(state)
      writeBrowserState(scheduleResources(state))
      return { revision: state.settingsRevision ?? 0, changed, applied: true }
    })
    return platformApi.getState()
  },

  getStorageLocation() { return run<string>("get_storage_location", {}, () => "Browser preview — no local environment storage") },
  setStorageLocation(path: string) { return run<void>("set_storage_location", { path }, () => { throw new Error("Choose storage in the Yougori desktop app") }) },

  refreshHostMetrics() {
    return run<PlatformState>("refresh_host_metrics", undefined, () => {
      const state = readBrowserState()
      const previousCpu = state.host.usedCpuPercent
      const cpu = Math.max(8, Math.min(92, previousCpu + (Math.random() - 0.5) * 12))
      const previousGpu = state.host.gpuUsagePercent ?? 12
      const gpu = Math.max(0, Math.min(100, previousGpu + (Math.random() - 0.5) * 16))
      const memoryPercent = (state.host.usedMemoryGb / state.host.totalMemoryGb) * 100
      state.host.usedCpuPercent = Math.round(cpu)
      state.host.gpuUsagePercent = Math.round(gpu)
      state.host.usedMemoryGb = Math.max(3, Math.min(state.host.totalMemoryGb - 1, state.host.usedMemoryGb + (Math.random() - 0.5) * 0.7))
      state.host.cpuHistory = [...state.host.cpuHistory.slice(-11), Math.round(cpu)]
      state.host.gpuHistory = [...state.host.gpuHistory.slice(-11), Math.round(gpu)]
      state.host.memoryHistory = [...state.host.memoryHistory.slice(-11), Math.round(memoryPercent)]
      state.host.pressure = cpu > 82 || memoryPercent > 88 ? "high" : cpu > 68 || memoryPercent > 76 ? "moderate" : "low"
      state.host.updatedAt = now()
      return writeBrowserState(scheduleResources(state))
    })
  },
}
