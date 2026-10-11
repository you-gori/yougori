import type { CloudCopyLocation, DuplicationJob } from "@/api/duplication-api"
export type EnvironmentKind = "container" | "microVm" | "fullVm" | "computerBranch" | "cloud"
export type EnvironmentStatus = "running" | "stopped" | "paused" | "provisioning" | "error"
export type RuntimeProviderKind = "yougoriOci" | "yougoriCuda" | "qemu" | "nativeSandbox" | "cloudSsh"
export type BranchType = "exactCopy" | "appsSettings" | "appsOnly" | "cleanOs"
export type SandboxFileAccess = "readOnly" | "readWrite"
export type Priority = "low" | "normal" | "high" | "critical"
export type PermissionKind = "network" | "ports" | "files" | "volumes" | "data" | "secrets"
export type ConnectionDirection = "oneWay" | "bidirectional"
export type ThemePreference = "light" | "dark" | "system" | "theme1" | "theme2" | "theme3" | "theme4" | "theme5" | "custom"

export interface CustomThemeColors {
  background: string
  surface: string
  accent: string
  detail: string
}

export interface ResourceRange {
  min: number
  preferred: number
  max: number
  current: number
}

export interface ResourcePolicy {
  cpu: ResourceRange
  memoryGb: ResourceRange
  priority: Priority
  dynamic: boolean
}

export interface SandboxShare {
  path: string
  access: SandboxFileAccess
}

export interface SandboxPolicy {
  executable: string
  arguments: string
  shares: SandboxShare[]
  networkAccess: boolean
}

export interface Environment {
  storageDrive?: string | null
  id: string
  name: string
  kind: EnvironmentKind
  status: EnvironmentStatus
  runtime: string
  provider?: RuntimeProviderKind
  runtimeId?: string
  runtimePath?: string
  controlEndpoint?: string
  consoleEndpoint?: string
  containerCommand?: string
  networkAccess?: boolean
  gpuAccess?: boolean
  sandboxPolicy?: SandboxPolicy
  lastError?: string
  description: string
  branchType?: BranchType
  createdAt: string
  lastOpenedAt?: string
  cpuUsage: number
  memoryUsageGb: number
  storageDeltaGb: number
  storageLimitGb?: number
  networkRxMbps: number
  resourcePolicy: ResourcePolicy
}

export interface Connection {
  id: string
  sourceId: string
  targetId: string
  direction: ConnectionDirection
  permissions: PermissionKind[]
  ports: string[]
  commands?: boolean
  selectedFolders?: { environmentId: string; path: string }[]
  sshPort?: number
  volume?: string
  active: boolean
  createdAt: string
  enforcementStatus?: "enforced" | "pending" | "error"
  providerRuleIds?: string[]
  lastError?: string
}

export type SnapshotStatus = "ready" | "creating" | "failed"

export interface Snapshot {
  id: string
  environmentId: string
  name: string
  createdAt: string
  sizeGb: number
  deltaGb: number
  encrypted: boolean
  status: SnapshotStatus
  providerSnapshotId?: string
  artifactPath?: string
  artifactSizeBytes?: number
  checksumSha256?: string
  environmentState?: {
    runtime: string
    provider?: RuntimeProviderKind
    runtimePath?: string
    containerCommand?: string
    networkAccess?: boolean
    gpuAccess?: boolean
    sandboxPolicy?: SandboxPolicy
    description: string
    branchType?: BranchType
    resourcePolicy: ResourcePolicy
  }
  connections?: Connection[]
}

export type BackupProvider = "awsS3" | "azureBlob" | "googleCloud" | "s3Compatible"

export interface BackupDestination {
  id: string
  name: string
  provider: BackupProvider
  location: string
  encrypted: boolean
  connected: boolean
  lastVerifiedAt: string
}

export type BackupRunStatus = "complete" | "running" | "failed"

export interface BackupRun {
  id: string
  environmentId: string
  destinationId: string
  createdAt: string
  completedAt?: string
  transferredGb: number
  deduplicatedGb: number
  status: BackupRunStatus
  remoteObject?: string
  checksumSha256?: string
  lastError?: string
}

export interface HostMetrics {
  storageDrives?: HostStorageDrive[]
  hostname: string
  os: string
  cpuModel: string
  totalCpu: number
  usedCpuPercent: number
  gpuUsagePercent: number | null
  totalMemoryGb: number
  usedMemoryGb: number
  totalStorageGb: number
  usedStorageGb: number
  storageDrive?: string | null
  storageSavedGb: number
  pressure: "low" | "moderate" | "high"
  cpuHistory: number[]
  gpuHistory: number[]
  memoryHistory: number[]
  updatedAt: string
}

export interface HostStorageDrive {
  path: string
  name: string
  fileSystem: string
  totalGb: number
  freeGb: number
  readOnly: boolean
  removable: boolean
}

export interface ProviderStatus {
  id: string
  name: string
  kind: "container" | "virtualization" | "storage" | "backup"
  status: "ready" | "unavailable" | "needsSetup"
  detail: string
}

export interface AppSettings {
  autoStartEnvironmentIds?: string[]
  keepAwake?: boolean
  theme: ThemePreference
  customThemeColors?: CustomThemeColors | null
  launchAtStartup: boolean
  /** Start at login as a background engine without the dashboard. */
  startupHeadless?: boolean
  minimizeToTray: boolean
  pauseOnBattery: boolean
  telemetryEnabled: boolean
  dataDirectory: string
  snapshotRetention: number
  bandwidthLimitMbps: number
}

export interface PlatformState {
  settingsRevision?: number
  /** Increases with every committed engine change; older replies and events are stale. */
  stateRevision?: number
  startupReport?: {
    startedAt: string
    completedAt: string | null
    status: "running" | "succeeded" | "startedUnverified" | "failed" | "interrupted"
    trigger: string
    startsBeforeSignIn: boolean
    serviceRegistration?: { status: string; mechanism: string; recoveryAction?: string; startsBeforeSignIn: boolean } | null
    environments: {
      environmentId: string
      provider: RuntimeProviderKind
      storageRoot: string | null
      stage: string
      status: string
      error: string | null
      recoveryAction: string | null
      readiness: { ready?: boolean; verifiedPublicly?: boolean; [key: string]: unknown } | null
    }[]
  } | null
  neocloudDeployments?: Record<string, { provider: string; product: string; name: string; resourceId: string; state: string; image: string; offer: string; diskGb?: number; location: string; address: string; sshHint: string; requestId: string; lastError: string | null; extra?: Record<string, unknown> }>
  /** Reusable Cloudflare account tunnels shared by the app and the CLI; tokens stay in the OS vault. */
  savedDomains?: { id: string; credentialEnvironmentId: string; port: number; hostname: string; hostPort: number }[]
  cloudCopySources?: Record<string, { location: CloudCopyLocation; host: string }>
  duplicationJobs?: Record<string, DuplicationJob>
  cliEnvironmentId?: string | null
  cloudDeployments?: Record<string,{provider:string;account:string;region:string;resourceGroup:string;name:string;resourceId:string;state:string;address:string;username:string;requestId:string;lastError:string|null}>
  manualServicePorts?: Record<string, number[]>
  schemaVersion?: number
  environments: Environment[]
  connections: Connection[]
  snapshots: Snapshot[]
  destinations: BackupDestination[]
  backupRuns: BackupRun[]
  pendingVmRestores?: string[]
  host: HostMetrics
  providers: ProviderStatus[]
  settings: AppSettings
}

export interface StorageCleanupResult {
  reclaimedCacheBytes: number
  reclaimedDiskBytes?: number
  notes?: string[]
  warnings: string[]
}

export interface EnvironmentDeletionResult extends PlatformState {
  storageCleanup?: StorageCleanupResult
}

export interface CreateEnvironmentRequest {
  storageDrive?: string
  storageGb?: number
  name: string
  kind: EnvironmentKind
  runtime: string
  provider: RuntimeProviderKind
  containerCommand?: string
  networkAccess?: boolean
  gpuAccess?: boolean
  sandboxPolicy?: SandboxPolicy
  description: string
  branchType?: BranchType
  resourcePolicy: Omit<ResourcePolicy, "cpu" | "memoryGb"> & {
    cpu: Omit<ResourceRange, "current">
    memoryGb: Omit<ResourceRange, "current">
  }
}

export interface StorageAllocation {
  limitEnforced?: boolean
  capacityGb: number
  physicalGb: number
  maximumGb: number
  shared: boolean
}

export interface CreateConnectionRequest {
  sourceId: string
  targetId: string
  sshPort?: number
  direction: ConnectionDirection
  permissions: PermissionKind[]
  ports: string[]
  commands?: boolean
  selectedFolders?: { environmentId: string; path: string }[]
  volume?: string
}

export interface AddDestinationRequest {
  name: string
  provider: BackupProvider
  location: string
  accessKey: string
  secretKey: string
}

export interface GuestSession {
  kind: "containerTerminal" | "headlessTerminal" | "embeddedVnc" | "headlessSerial" | "nativeApplication"
  websocketUrl?: string
  password?: string
  message: string
}

export interface CommandResult {
  stdout: string
  stderr: string
  exitCode: number
}
