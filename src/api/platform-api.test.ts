// @vitest-environment jsdom
import { beforeEach, describe, expect, it } from "vitest"
import { platformApi } from "@/api/platform-api"
import { workspaceApi } from "@/api/workspace-api"
import type { CreateEnvironmentRequest } from "@/types/platform"

async function createTestEnvironment(name: string, overrides: Partial<CreateEnvironmentRequest> = {}) {
  const request: CreateEnvironmentRequest = {
    name,
    kind: "container",
    runtime: "quay.io/libpod/alpine:latest",
    provider: "yougoriOci",
    description: "Test-only browser adapter fixture",
    resourcePolicy: {
      cpu: { min: 0.1, preferred: 0.25, max: 1 },
      memoryGb: { min: 0.125, preferred: 0.25, max: 0.5 },
      priority: "normal",
      dynamic: true,
    },
    ...overrides,
  }
  const state = await platformApi.createEnvironment(request)
  return state.environments[0]!
}

describe("browser platform adapter", () => {
  it("patches only intended settings and rejects a stale writer without overwriting the first change", async () => {
    const initial = await platformApi.getState()
    const first = await platformApi.patchSettings({ keepAwake: true }, initial.settingsRevision ?? 0)
    expect(first.settings.keepAwake).toBe(true)
    expect(first.settings.theme).toBe(initial.settings.theme)
    await expect(platformApi.patchSettings({ snapshotRetention: 42 }, initial.settingsRevision ?? 0)).rejects.toThrow("Settings changed")
    const after = await platformApi.getState()
    expect(after.settings.keepAwake).toBe(true)
    expect(after.settings.snapshotRetention).toBe(initial.settings.snapshotRetention)
    await expect(platformApi.patchSettings({ dataDirectory: "/other" }, after.settingsRevision ?? 0)).rejects.toThrow("Storage settings")
  })
  it("edits an existing connection without creating another or changing its ID", async () => {
    const source = await createTestEnvironment("Edit source")
    const target = await createTestEnvironment("Edit target")
    const created = await platformApi.createConnection({ sourceId: source.id, targetId: target.id, direction: "bidirectional", permissions: ["files"], ports: [] })
    const original = created.connections.find(connection => connection.sourceId === source.id && connection.targetId === target.id)!
    const edited = await platformApi.createConnection({ sourceId: target.id, targetId: source.id, direction: "oneWay", permissions: ["data", "volumes"], ports: [], volume: "workspace-data" })
    expect(edited.connections.filter(connection => connection.id === original.id)).toHaveLength(1)
    expect(edited.connections.find(connection => connection.id === original.id)).toMatchObject({
      sourceId: target.id, targetId: source.id, direction: "oneWay", permissions: ["data", "volumes"], volume: "workspace-data", createdAt: original.createdAt,
    })
    await platformApi.setConnectionActive(original.id, false)
    const inactive = await platformApi.createConnection({ sourceId: target.id, targetId: source.id, direction: "oneWay", permissions: ["data"], ports: [] })
    expect(inactive.connections.find(connection => connection.id === original.id)?.active).toBe(false)
  })
  it("requires explicit SSH port permission and preserves the method across disconnect/reconnect", async () => {
    const a = await createTestEnvironment("SSH source"), b = await createTestEnvironment("SSH target")
    const request = { sourceId: a.id, targetId: b.id, permissions: ["ports"] as const, ports: ["2222"], sshPort: 2222, direction: "oneWay" as const }
    await expect(platformApi.createConnection({ ...request, permissions: ["files"] })).rejects.toThrow("explicitly allowed")
    await expect(platformApi.createConnection({ ...request, permissions: ["ports"], ports: ["80"] })).rejects.toThrow("explicitly allowed")
    const state = await platformApi.createConnection({ ...request, permissions: ["ports"] })
    const link = state.connections.find(c => c.sourceId === a.id)!
    expect(link.sshPort).toBe(2222)
    await platformApi.setConnectionActive(link.id, false)
    expect((await platformApi.getState()).connections.find(c => c.id === link.id)).toMatchObject({ active: false, sshPort: 2222 })
    await platformApi.deleteConnection(link.id)
    expect((await platformApi.getState()).connections.some(c => c.id === link.id)).toBe(false)
  })
  it("persists independent standard and GPU limits and increases one without stopping either node", async () => {
    const initial = await platformApi.getState()
    initial.host.totalStorageGb = 512
    initial.host.usedStorageGb = 100
    localStorage.setItem("yougori.platform.v1", JSON.stringify(initial))
    const cpu = await createTestEnvironment("Storage CPU", { storageGb: 20 })
    const gpu = await createTestEnvironment("Storage GPU", { provider: "yougoriCuda", runtime: "docker.io/library/ubuntu:24.04", storageGb: 100, gpuAccess: true })
    await platformApi.setEnvironmentStatus(cpu.id, "running")
    await platformApi.setEnvironmentStatus(gpu.id, "running")
    expect(await platformApi.getStorageAllocation(cpu.id)).toMatchObject({ capacityGb: 20, shared: false, limitEnforced: true })
    expect(await platformApi.getStorageAllocation(gpu.id)).toMatchObject({ capacityGb: 100, shared: false, limitEnforced: true })
    await platformApi.expandEnvironmentStorage(cpu.id, 40)
    const restored = await platformApi.getState()
    expect(restored.environments.find(e => e.id === cpu.id)).toMatchObject({ status: "running", storageLimitGb: 40 })
    expect(restored.environments.find(e => e.id === gpu.id)).toMatchObject({ status: "running", storageLimitGb: 100 })
    expect((await platformApi.getStorageAllocation(cpu.id)).capacityGb).toBe(40)
    expect((await platformApi.getStorageAllocation(gpu.id)).capacityGb).toBe(100)
    await platformApi.expandEnvironmentStorage(cpu.id, 1)
    expect((await platformApi.getStorageAllocation(cpu.id)).capacityGb).toBe(1)
    expect((await platformApi.getStorageAllocation(gpu.id)).capacityGb).toBe(100)
    await expect(platformApi.expandEnvironmentStorage(cpu.id, 0)).rejects.toThrow("1 GB")
    await expect(createTestEnvironment("Too small", { storageGb: 0 })).rejects.toThrow("minimum")
  })

  it("persists a trimmed display name without changing runtime or resource metadata", async () => {
    const environment = await createTestEnvironment("Original name")
    const state = await platformApi.renameEnvironment(environment.id, "  Renamed VM  ")
    expect(state.environments.find(item => item.id === environment.id)).toEqual({ ...environment, name: "Renamed VM" })
    expect((await platformApi.getState()).environments.find(item => item.id === environment.id)?.name).toBe("Renamed VM")
    for (const name of [" ", "a", "x".repeat(81), "Bad\nName"]) {
      await expect(platformApi.renameEnvironment(environment.id, name)).rejects.toThrow("2–80")
    }
    await expect(platformApi.renameEnvironment("missing", "Valid name")).rejects.toThrow("not found")
  })
  it("cloud lifecycle never grants local power, resource, host folder or publishing controls", async () => {
    const state = await platformApi.addCloudEnvironment({ name: "Cloud fixture", vendor: "aws", host: "cloud.example.test", port: 22, username: "ubuntu", identityFile: "C:\\test-only.pem", hostKey: "test-only" })
    const cloud = state.environments.find(e => e.kind === "cloud")!
    expect(cloud).toMatchObject({ status: "stopped", networkAccess: false, resourcePolicy: { cpu: { current: 0 }, memoryGb: { current: 0 } } })
    await expect(platformApi.setEnvironmentStatus(cloud.id, "paused")).rejects.toThrow("Connect and Disconnect")
    await expect(platformApi.updateResourcePolicy(cloud.id, cloud.resourcePolicy)).rejects.toThrow("managed outside")
    await expect(platformApi.factoryResetEnvironment(cloud.id, cloud.name)).rejects.toThrow("only supported")
    await platformApi.setEnvironmentStatus(cloud.id, "running")
    for (const kind of ["local", "cloudflare"] as const) await expect(workspaceApi.publish(cloud.id, 3000, kind)).rejects.toThrow("Cloud nodes")
    await expect(workspaceApi.share(cloud.id, "C:\\User data", false)).rejects.toThrow("not direct My PC")
    await platformApi.setEnvironmentStatus(cloud.id, "stopped")
    const disconnected = (await platformApi.getState()).environments.find(e => e.id === cloud.id)!
    expect(disconnected.controlEndpoint).toBeUndefined()
    await platformApi.deleteEnvironment(cloud.id)
    expect(localStorage.getItem(`yougori.cloud.${cloud.id}`)).toBeNull()
  })
  it.each(["\n", "\r\n"])("Skills includes current My PC mounts and permissions, without private links or other environments' folders (%j line endings)", async newline => {
    const target = await createTestEnvironment("PC Skills")
    const other = await createTestEnvironment("Private folders")
    await platformApi.setEnvironmentStatus(target.id, "running")
    await platformApi.createConnection({ sourceId: target.id, targetId: other.id, direction: "bidirectional", permissions: ["files"], ports: [] })
    const read = await workspaceApi.share(target.id, "C:\\Shared input", true)
    const write = await workspaceApi.share(target.id, "C:\\Shared project", false)
    await workspaceApi.share(other.id, "C:\\Not for this environment", false)
    const text = (await platformApi.connectionSkills(target.id)).replace(/\r?\n/g, newline)
    const data = JSON.parse(text.replaceAll("\r\n", "\n").split("```json\n")[1]!.split("\n```")[0]!)
    expect(data.myPc.connected).toBe(true)
    expect(data.myPc.folders).toEqual(expect.arrayContaining([
      expect.objectContaining({ shareId: read.id, hostPath: read.path, mountPath: read.mountPath, readOnly: true, writable: false, usableNow: true }),
      expect.objectContaining({ shareId: write.id, hostPath: write.path, mountPath: write.mountPath, readOnly: false, writable: true, usableNow: true }),
    ]))
    expect(text).not.toContain("Not for this environment")
    expect(text).not.toContain(read.guestUrl)
    expect(text).not.toContain(`test-${read.id}`)
    await workspaceApi.unshare(read.id)
    expect(await platformApi.connectionSkills(target.id)).not.toContain(read.mountPath!)
    await workspaceApi.unshare(write.id)
    expect(await platformApi.connectionSkills(target.id)).toContain('"connected": false')
  })
  it("runtime recovery preserves environments and snapshots", async () => {
    const target = await createTestEnvironment("Recover target")
    await createTestEnvironment("Keep other")
    await platformApi.createSnapshot(target.id, "Keep snapshot")
    const before = await platformApi.getState()
    const after = await platformApi.recoverContainerRuntime(target.id)
    expect(after.environments).toEqual(before.environments)
    expect(after.snapshots).toEqual(before.snapshots)
    expect(after.connections).toEqual(before.connections)
  })
  it("does not offer the shared container disk's occupied capacity to a new VM", async () => {
    const state = await platformApi.getState()
    state.host.totalStorageGb = 100
    state.host.usedStorageGb = 99
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
    expect((await platformApi.getStorageAllocation()).maximumGb).toBe(0)
    expect(await platformApi.getStorageAllocation(undefined, true)).toEqual({ capacityGb: 0, physicalGb: 0, maximumGb: 0, shared: false })
    state.host.usedStorageGb = 80
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
    expect((await platformApi.getStorageAllocation(undefined, true)).maximumGb).toBe(18)
  })

  beforeEach(async () => {
    localStorage.clear()
    await platformApi.resetPlatform()
    const state = await platformApi.getState()
    state.host.totalCpu = 8
    state.host.totalMemoryGb = 16
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
  })

  it("factory reset erases only the target snapshots and retains its image and settings", async () => {
    const target = await createTestEnvironment("Reset target")
    const other = await createTestEnvironment("Keep me")
    await platformApi.createSnapshot(target.id, "Target snapshot")
    await platformApi.createSnapshot(other.id, "Keep snapshot")
    await expect(platformApi.factoryResetEnvironment(target.id, "wrong")).rejects.toThrow(/name exactly/)
    await platformApi.setEnvironmentStatus(target.id, "running")
    await expect(platformApi.factoryResetEnvironment(target.id, target.name)).rejects.toThrow(/Shut down/)
    await platformApi.setEnvironmentStatus(target.id, "stopped")
    const before = await platformApi.getState()
    const after = await platformApi.factoryResetEnvironment(target.id, target.name)
    const fresh = after.environments.find(e => e.id === target.id)!
    expect(fresh.runtime).toBe(target.runtime)
    expect(fresh.name).toBe(target.name)
    expect(fresh.resourcePolicy.memoryGb.max).toBe(target.resourcePolicy.memoryGb.max)
    expect(fresh.status).toBe("stopped")
    expect(after.snapshots).toHaveLength(1)
    expect(after.snapshots[0]!.environmentId).toBe(other.id)
    expect(after.environments.find(e => e.id === other.id)).toEqual(before.environments.find(e => e.id === other.id))
  })

  it("persists a new environment", async () => {
    const before = await platformApi.getState()
    const after = await platformApi.createEnvironment({
      name: "Isolated Test",
      kind: "microVm",
      runtime: "Fedora CoreOS",
      provider: "qemu",
      description: "Automated test environment",
      resourcePolicy: {
        cpu: { min: 1, preferred: 2, max: 4 },
        memoryGb: { min: 1, preferred: 2, max: 4 },
        priority: "normal",
        dynamic: false,
      },
    })
    expect(after.environments).toHaveLength(before.environments.length + 1)
    expect(after.environments[0]!.resourcePolicy.dynamic).toBe(true)
    expect((await platformApi.getState()).environments[0]?.name).toBe("Isolated Test")
    await expect(platformApi.openEnvironmentWindow(after.environments[0]!.id)).resolves.toBe(false)
  })

  it("creates, starts, updates and restores containers above the old fixed runtime limits", async () => {
    const environment = await createTestEnvironment("Large container")
    await platformApi.updateResourcePolicy(environment.id, {
      cpu: { min: 0.5, preferred: 4, max: 8, current: 0 },
      memoryGb: { min: 0.5, preferred: 2, max: 4, current: 0 },
      priority: "normal", dynamic: false,
    })
    const started = await platformApi.setEnvironmentStatus(environment.id, "running")
    expect(started.environments[0]!.resourcePolicy.memoryGb.current).toBe(2)
    expect(started.environments[0]!.resourcePolicy.cpu.current).toBe(4)
    const saved = await platformApi.createSnapshot(environment.id, "Large limits")
    await platformApi.setEnvironmentStatus(environment.id, "stopped")
    const restored = await platformApi.restoreSnapshot(saved.snapshots[0]!.id)
    expect(restored.environments[0]!.resourcePolicy.memoryGb.max).toBe(4)
    expect(restored.environments[0]!.resourcePolicy.cpu.max).toBe(8)
  })

  it("ignores attempts to disable automatic allocation", async () => {
    const environment = await createTestEnvironment("Fixed resources")
    await platformApi.setEnvironmentStatus(environment.id, "running")
    const next = await platformApi.updateResourcePolicy(environment.id, {
      ...environment.resourcePolicy, dynamic: false,
      cpu: { ...environment.resourcePolicy.cpu, preferred: 0.5 },
      memoryGb: { ...environment.resourcePolicy.memoryGb, preferred: 0.375 },
    })
    const policy = next.environments[0]!.resourcePolicy
    expect(policy.dynamic).toBe(true)
    expect(policy.cpu.current).toBe(0.5)
    expect(policy.memoryGb.current).toBe(0.375)
    const refreshed = await platformApi.refreshHostMetrics()
    expect(refreshed.environments[0]!.resourcePolicy).toEqual(policy)
  })

  it("enables allocation in saved environments and restored legacy snapshots", async () => {
    const environment = await createTestEnvironment("Legacy allocation")
    const state = await platformApi.createSnapshot(environment.id, "Before upgrade")
    state.environments[0]!.resourcePolicy.dynamic = false
    state.snapshots[0]!.environmentState!.resourcePolicy.dynamic = false
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
    const loaded = await platformApi.getState()
    expect(loaded.environments[0]!.resourcePolicy.dynamic).toBe(true)
    expect(loaded.snapshots[0]!.environmentState!.resourcePolicy.dynamic).toBe(true)
    const restored = await platformApi.restoreSnapshot(state.snapshots[0]!.id)
    expect(restored.environments[0]!.resourcePolicy.dynamic).toBe(true)
    expect(restored.environments[0]!.resourcePolicy.cpu.max).toBe(environment.resourcePolicy.cpu.max)
  })

  it("keeps paused container RAM reserved when admitting another container", async () => {
    const first = await createTestEnvironment("Paused reservation")
    await platformApi.updateResourcePolicy(first.id, {
      ...first.resourcePolicy, dynamic: false,
      memoryGb: { min: 0.5, preferred: 8, max: 8, current: 0 },
    })
    await platformApi.setEnvironmentStatus(first.id, "running")
    const paused = await platformApi.setEnvironmentStatus(first.id, "paused")
    expect(paused.environments[0]!.resourcePolicy.memoryGb.current).toBe(8)
    const second = await createTestEnvironment("Needs more RAM")
    await platformApi.updateResourcePolicy(second.id, {
      ...second.resourcePolicy, dynamic: false,
      memoryGb: { min: 8, preferred: 8, max: 8, current: 0 },
    })
    await expect(platformApi.setEnvironmentStatus(second.id, "running")).rejects.toThrow("Not enough shared container capacity")
    await platformApi.setEnvironmentStatus(first.id, "stopped")
    await expect(platformApi.setEnvironmentStatus(second.id, "running")).resolves.toBeDefined()
  })

  it("records bounded GPU history with host telemetry", async () => {
    const refreshed = await platformApi.refreshHostMetrics()
    expect(refreshed.host.gpuUsagePercent).toBeTypeOf("number")
    expect(refreshed.host.gpuUsagePercent).toBeGreaterThanOrEqual(0)
    expect(refreshed.host.gpuUsagePercent).toBeLessThanOrEqual(100)
    expect(refreshed.host.gpuHistory).toHaveLength(1)
  })

  it("uses the guest command terminal for the built-in microVM and rejects GPU emulation", async () => {
    const created = await platformApi.createEnvironment({
      name: "Lean microVM",
      kind: "microVm",
      runtime: "builtin:alpine",
      provider: "qemu",
      gpuAccess: true,
      description: "Direct-kernel test environment",
      resourcePolicy: {
        cpu: { min: 1, preferred: 1, max: 2 },
        memoryGb: { min: 0.25, preferred: 0.5, max: 1 },
        priority: "normal",
        dynamic: true,
      },
    })
    const environment = created.environments[0]!
    expect(environment.gpuAccess).toBe(false)
    await platformApi.setEnvironmentStatus(environment.id, "running")
    await expect(platformApi.getGuestSession(environment.id)).resolves.toMatchObject({ kind: "headlessTerminal" })
    await expect(platformApi.executeEnvironmentCommand(environment.id, "  uname -a  ")).resolves.toEqual({
      stdout: "[test adapter] uname -a\n",
      stderr: "",
      exitCode: 0,
    })
    await platformApi.setEnvironmentStatus(environment.id, "stopped")
    await expect(platformApi.executeEnvironmentCommand(environment.id, "uname -a")).rejects.toThrow("not running")
    await expect(platformApi.updateEnvironmentGpu(environment.id, true)).rejects.toThrow("unavailable")
  })

  it("keeps custom microVMs on the read-only serial console", async () => {
    const created = await platformApi.createEnvironment({
      name: "Custom microVM",
      kind: "microVm",
      runtime: "C:\\VMs\\custom-microvm.json",
      provider: "qemu",
      description: "Custom direct-kernel test environment",
      resourcePolicy: {
        cpu: { min: 1, preferred: 1, max: 2 },
        memoryGb: { min: 0.25, preferred: 0.5, max: 1 },
        priority: "normal",
        dynamic: true,
      },
    })
    const environment = created.environments[0]!
    await platformApi.setEnvironmentStatus(environment.id, "running")

    await expect(platformApi.getGuestSession(environment.id)).resolves.toMatchObject({ kind: "headlessSerial" })
    await expect(platformApi.executeEnvironmentCommand(environment.id, "uname -a")).rejects.toThrow("read-only serial console")
  })

  it("defaults new environments to Internet on and preserves explicit offline creation", async () => {
    expect((await createTestEnvironment("Online default")).networkAccess).toBe(true)
    expect((await createTestEnvironment("Offline explicit", { networkAccess: false })).networkAccess).toBe(false)
  })

  it("persists and guards container internet access", async () => {
    const environment = await createTestEnvironment("Network policy", { networkAccess: false })
    expect(environment.networkAccess).toBe(false)
    const enabled = await platformApi.updateContainerNetwork(environment.id, true)
    expect(enabled.environments.find((item) => item.id === environment.id)?.networkAccess).toBe(true)
    const gpuEnabled = await platformApi.updateEnvironmentGpu(environment.id, true)
    expect(gpuEnabled.environments.find((item) => item.id === environment.id)?.gpuAccess).toBe(true)
    await platformApi.setEnvironmentStatus(environment.id, "running")
    const disconnected = await platformApi.updateContainerNetwork(environment.id, false)
    expect(disconnected.environments.find(item => item.id === environment.id)).toMatchObject({ status: "running", networkAccess: false })
    const reconnected = await platformApi.updateContainerNetwork(environment.id, true)
    expect(reconnected.environments.find(item => item.id === environment.id)).toMatchObject({ status: "running", networkAccess: true })
    await expect(platformApi.updateEnvironmentGpu(environment.id, false)).rejects.toThrow("Stop the environment")
  })

  it("rejects computer branches while the feature is unavailable", async () => {
    const executable = "C:\\Tools\\Example\\example.exe"
    await expect(platformApi.createEnvironment({
      name: "Native branch",
      kind: "computerBranch",
      runtime: executable,
      provider: "nativeSandbox",
      sandboxPolicy: {
        executable,
        arguments: "--safe-mode",
        shares: [{ path: "C:\\Work\\Input", access: "readOnly" }],
        networkAccess: false,
      },
      description: "Restricted native application",
      resourcePolicy: {
        cpu: { min: 1, preferred: 2, max: 4 },
        memoryGb: { min: 1, preferred: 2, max: 4 },
        priority: "normal",
        dynamic: true,
      },
    })).rejects.toThrow("temporarily unavailable")
  })

  it("rejects VM-backed computer branches", async () => {
    await expect(platformApi.createEnvironment({
      name: "Old branch",
      kind: "computerBranch",
      runtime: "current-computer",
      provider: "qemu",
      description: "Retired VM branch",
      resourcePolicy: {
        cpu: { min: 1, preferred: 2, max: 4 },
        memoryGb: { min: 1, preferred: 2, max: 4 },
        priority: "normal",
        dynamic: true,
      },
    })).rejects.toThrow("temporarily unavailable")
  })

  it("cascades connection and snapshot removal with an environment", async () => {
    const source = await createTestEnvironment("Cascade source")
    const target = await createTestEnvironment("Cascade target")
    await platformApi.createConnection({ sourceId: source.id, targetId: target.id, direction: "oneWay", permissions: ["ports"], ports: ["8080"] })
    const environmentId = source.id
    const withSnapshot = await platformApi.createSnapshot(environmentId, "Disposable")
    expect(withSnapshot.snapshots.some((item) => item.environmentId === environmentId)).toBe(true)
    const removed = await platformApi.deleteEnvironment(environmentId)
    expect(removed.snapshots.some((item) => item.environmentId === environmentId)).toBe(false)
    expect(removed.connections.some((item) => item.sourceId === environmentId || item.targetId === environmentId)).toBe(false)
  })

  it("restores environment configuration and connection rules from a snapshot", async () => {
    const environment = await createTestEnvironment("Restore source")
    const target = await createTestEnvironment("Restore target")
    await platformApi.createConnection({ sourceId: environment.id, targetId: target.id, direction: "oneWay", permissions: ["network"], ports: [] })
    const before = await platformApi.getState()
    const originalConnections = before.connections.filter((connection) => connection.sourceId === environment.id || connection.targetId === environment.id)
    const snapshotted = await platformApi.createSnapshot(environment.id, "Restore contract")
    const snapshotId = snapshotted.snapshots[0]!.id

    await platformApi.updateResourcePolicy(environment.id, {
      cpu: { min: 0.1, preferred: 0.15, max: 0.2, current: 0 },
      memoryGb: { min: 0.125, preferred: 0.125, max: 0.125, current: 0 },
      priority: "low",
      dynamic: false,
    })
    for (const connection of originalConnections) await platformApi.deleteConnection(connection.id)

    const restored = await platformApi.restoreSnapshot(snapshotId)
    const restoredEnvironment = restored.environments.find((item) => item.id === environment.id)!
    expect(restoredEnvironment.resourcePolicy.priority).toBe(environment.resourcePolicy.priority)
    expect(restoredEnvironment.resourcePolicy.cpu.preferred).toBe(environment.resourcePolicy.cpu.preferred)
    expect(restoredEnvironment.status).toBe("stopped")
    expect(restored.connections.filter((connection) => connection.sourceId === environment.id || connection.targetId === environment.id)).toHaveLength(originalConnections.length)
  })

  it("never persists backup credentials", async () => {
    await platformApi.addDestination({
      name: "Secure archive",
      provider: "s3Compatible",
      location: "https://storage.example.test/opendock",
      accessKey: "TEST_ACCESS_KEY",
      secretKey: "TEST_SECRET_KEY",
    })
    const persisted = localStorage.getItem("yougori.platform.v1") ?? ""
    expect(persisted).not.toContain("TEST_ACCESS_KEY")
    expect(persisted).not.toContain("TEST_SECRET_KEY")
  })

  it("rejects invalid connections and backup destinations", async () => {
    const source = await createTestEnvironment("Validation source")
    const target = await createTestEnvironment("Validation target")
    await expect(platformApi.createConnection({
      sourceId: source.id,
      targetId: target.id,
      direction: "oneWay",
      permissions: ["ports"],
      ports: ["70000"],
    })).rejects.toThrow("Ports must be valid")
    await expect(platformApi.runBackup(source.id, "missing-destination")).rejects.toThrow("Backup destination not found")
  })
})
