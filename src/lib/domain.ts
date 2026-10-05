import type {
  EnvironmentKind,
  EnvironmentStatus,
  PermissionKind,
  PlatformState,
  Priority,
  ResourcePolicy,
} from "@/types/platform"

export function containerRuntimeCapacity(host: Pick<PlatformState["host"], "totalCpu" | "totalMemoryGb">) {
  const hostReserve = Math.max(1, host.totalMemoryGb * 0.1)
  return { cpu: Math.min(host.totalCpu, 255), memoryGb: Math.floor(Math.max(0, host.totalMemoryGb - hostReserve - 0.375) * 8) / 8 }
}

export const environmentKindLabel: Record<EnvironmentKind, string> = {
  cloud: "Cloud environment",
  container: "Container",
  microVm: "MicroVM",
  fullVm: "VM",
  computerBranch: "Computer branch",
}

export const environmentKindDescription: Record<EnvironmentKind, string> = {
  cloud: "An existing remote server connected privately over SSH.",
  container: "A lightweight service using the local container runtime.",
  microVm: "A headless, direct-kernel workload with minimal emulated hardware.",
  fullVm: "A complete operating system with a real desktop.",
  computerBranch: "Run one Windows application with only the files and network access you allow.",
}

export const statusLabel: Record<EnvironmentStatus, string> = {
  running: "Running",
  stopped: "Stopped",
  paused: "Paused",
  provisioning: "Creating",
  error: "Needs attention",
}

export const permissionLabel: Record<PermissionKind, string> = {
  network: "Network access",
  ports: "Ports",
  files: "Files",
  volumes: "Shared volumes",
  data: "Data",
  secrets: "Secrets",
}

export function formatBytesFromGb(value: number) {
  if (value < 1) return `${Math.round(value * 1024)} MB`
  return `${value.toFixed(value >= 10 ? 1 : 2)} GB`
}

export function formatRelativeTime(date: string) {
  const elapsed = Date.now() - new Date(date).getTime()
  const minutes = Math.max(0, Math.floor(elapsed / 60_000))
  if (minutes < 1) return "just now"
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  if (days < 7) return `${days}d ago`
  return new Intl.DateTimeFormat(undefined, { month: "short", day: "numeric" }).format(new Date(date))
}

export function formatDateTime(date: string) {
  return new Intl.DateTimeFormat(undefined, {
    month: "short",
    day: "numeric",
    hour: "numeric",
    minute: "2-digit",
  }).format(new Date(date))
}

export function validateResourcePolicy(policy: ResourcePolicy): string[] {
  const errors: string[] = []
  for (const [label, range] of [
    ["CPU", policy.cpu],
    ["Memory", policy.memoryGb],
  ] as const) {
    if (![range.min, range.preferred, range.max].every(Number.isFinite)) {
      errors.push(`${label} values must be finite numbers.`)
      continue
    }
    if (range.min <= 0) errors.push(`${label} minimum must be greater than zero.`)
    if (range.preferred < range.min) errors.push(`${label} preferred must be at least the minimum.`)
    if (range.max < range.preferred) errors.push(`${label} maximum must be at least the preferred value.`)
  }
  return errors
}

export function validateContainerResourcePolicy(policy: { cpu: { max: number }; memoryGb: { max: number } }, host: Pick<PlatformState["host"], "totalCpu" | "totalMemoryGb">): string[] {
  const errors: string[] = []
  if (policy.cpu.max > Math.min(host.totalCpu, 255)) {
    errors.push(`Container CPU maximum cannot exceed this computer's supported CPU count.`)
  }
  if (policy.memoryGb.max > Math.min(host.totalMemoryGb, 1024)) {
    errors.push(`Container memory maximum cannot exceed this computer's RAM.`)
  }
  return errors
}

export function storageSummary(state: PlatformState) {
  const physical = state.snapshots.reduce((sum, snapshot) => sum + (snapshot.artifactSizeBytes !== undefined ? snapshot.artifactSizeBytes / 1_073_741_824 : snapshot.deltaGb), 0)
    + state.environments.reduce((sum, environment) => sum + environment.storageDeltaGb, 0)
  const logical = physical + state.host.storageSavedGb
  const ratio = physical === 0 ? 1 : logical / physical
  return { logical, physical, ratio }
}

function priorityWeight(priority: Priority) {
  return { low: 0.7, normal: 1, high: 1.35, critical: 1.8 }[priority]
}

function targetFor(range: ResourcePolicy["cpu"], priority: Priority, pressure: PlatformState["host"]["pressure"]) {
  const weight = priorityWeight(priority)
  const target = pressure === "low"
    ? range.preferred * Math.min(weight, 1.25)
    : pressure === "moderate"
      ? range.preferred * Math.min(1.1, Math.max(0.8, 0.85 * weight))
      : range.min + (range.preferred - range.min) * 0.25 * Math.min(weight, 1)
  return Math.min(range.max, Math.max(range.min, target))
}

export function scheduleResources(state: PlatformState) {
  for (const environment of state.environments) environment.resourcePolicy.dynamic = true
  const running = state.environments.filter((environment) => environment.status === "running" && environment.kind !== "cloud")
  const priorityOrder: Record<Priority, number> = { low: 0, normal: 1, high: 2, critical: 3 }
  running.sort((a, b) => priorityOrder[b.resourcePolicy.priority] - priorityOrder[a.resourcePolicy.priority])

  for (const environment of state.environments.filter((item) => item.status !== "running")) {
    environment.resourcePolicy.cpu.current = 0
    environment.resourcePolicy.memoryGb.current = environment.status === "paused"
      ? environment.resourcePolicy.memoryGb.current || environment.resourcePolicy.memoryGb.preferred : 0
  }
  for (const environment of running) {
    environment.resourcePolicy.cpu.current = environment.resourcePolicy.cpu.min
    if (environment.kind !== "microVm") environment.resourcePolicy.memoryGb.current = environment.resourcePolicy.memoryGb.min
    else if (environment.resourcePolicy.memoryGb.current <= 0) environment.resourcePolicy.memoryGb.current = environment.resourcePolicy.memoryGb.preferred
  }

  const cpuFloor = running.reduce((sum, item) => sum + item.resourcePolicy.cpu.current, 0)
  const memoryFloor = state.environments.filter(item => item.status === "running" || item.status === "paused").reduce((sum, item) => sum + item.resourcePolicy.memoryGb.current, 0)
  const factor = state.host.pressure === "low" ? 0.9 : state.host.pressure === "moderate" ? 0.78 : 0.62
  let cpuRemaining = Math.max(cpuFloor, state.host.totalCpu * factor) - cpuFloor
  let memoryRemaining = Math.max(memoryFloor, state.host.totalMemoryGb * factor) - memoryFloor
  const containers = running.filter((environment) => environment.kind === "container")
  const containerCpuFloor = containers.reduce((sum, item) => sum + item.resourcePolicy.cpu.current, 0)
  const containerMemoryFloor = state.environments.filter(item => item.kind === "container" && (item.status === "running" || item.status === "paused")).reduce((sum, item) => sum + item.resourcePolicy.memoryGb.current, 0)
  const capacity = containerRuntimeCapacity(state.host)
  const otherMemoryFloor = state.environments.filter(item => item.kind !== "container" && (item.status === "running" || item.status === "paused"))
    .reduce((sum, item) => sum + Math.max(item.resourcePolicy.memoryGb.current, item.resourcePolicy.memoryGb.preferred), 0)
  let containerCpuRemaining = Math.max(0, capacity.cpu - containerCpuFloor)
  let containerMemoryRemaining = Math.max(0, capacity.memoryGb - otherMemoryFloor - containerMemoryFloor)

  for (const environment of running) {
    const cpuTarget = targetFor(environment.resourcePolicy.cpu, environment.resourcePolicy.priority, state.host.pressure)
    const memoryTarget = targetFor(environment.resourcePolicy.memoryGb, environment.resourcePolicy.priority, state.host.pressure)
    let cpuExtra = Math.min(cpuRemaining, Math.max(0, cpuTarget - environment.resourcePolicy.cpu.current))
    let memoryExtra = environment.kind === "microVm" ? 0 : Math.min(memoryRemaining, Math.max(0, memoryTarget - environment.resourcePolicy.memoryGb.current))
    if (environment.kind === "container") {
      cpuExtra = Math.min(cpuExtra, containerCpuRemaining)
      memoryExtra = Math.min(memoryExtra, containerMemoryRemaining)
    }
    const previousCpu = environment.resourcePolicy.cpu.current
    const previousMemory = environment.resourcePolicy.memoryGb.current
    environment.resourcePolicy.cpu.current = Math.min(
      environment.resourcePolicy.cpu.max,
      Math.max(environment.resourcePolicy.cpu.min, Math.round(Math.floor((previousCpu + cpuExtra) / 0.05 + 1e-9) * 0.05 * 1e9) / 1e9),
    )
    if (environment.kind !== "microVm") environment.resourcePolicy.memoryGb.current = Math.min(
      environment.resourcePolicy.memoryGb.max,
      Math.max(environment.resourcePolicy.memoryGb.min, Math.floor((previousMemory + memoryExtra) / 0.125) * 0.125),
    )
    const assignedCpu = Math.max(0, environment.resourcePolicy.cpu.current - previousCpu)
    const assignedMemory = Math.max(0, environment.resourcePolicy.memoryGb.current - previousMemory)
    cpuRemaining = Math.max(0, cpuRemaining - assignedCpu)
    memoryRemaining = Math.max(0, memoryRemaining - assignedMemory)
    if (environment.kind === "container") {
      containerCpuRemaining = Math.max(0, containerCpuRemaining - assignedCpu)
      containerMemoryRemaining = Math.max(0, containerMemoryRemaining - assignedMemory)
    }
  }
  return state
}
