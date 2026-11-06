import type { Environment } from "@/types/platform"
import type { SandboxVmStatus } from "@/api/sandbox-vm-api"

/** A view of the VM inventory, never a second persisted environment or an OCI runtime. */
export function sandboxVmEnvironments(status: SandboxVmStatus | null): Environment[] {
  return (status?.sandboxes ?? []).flatMap<Environment>(vm => {
    const workspace = status?.workspaces.find(item => item.sandbox === vm.sandbox)
    const phase = vm.phase === "ready" ? "running" : vm.phase === "starting" ? "provisioning" : "stopped"
    // Importer VMs and discarded test workspaces remain in the engine's audit
    // history. They are not saved environments a person can reopen.
    if (phase === "stopped" && vm.phase !== "stopping" && !workspace) return []
    const range = { min: 0, max: 0, preferred: 0, current: 0 }
    return [{
      id: vm.sandbox, name: workspace?.folder.split(/[\\/]/).filter(Boolean).pop() || vm.sandbox,
      kind: "fullVm", status: phase, runtime: `sandbox-vm://${vm.sandbox}`,
      description: workspace?.folder ?? "Private virtual machine", createdAt: workspace?.imported_at ?? "",
      cpuUsage: 0, memoryUsageGb: 0, storageDeltaGb: 0, networkRxMbps: 0,
      resourcePolicy: { cpu: range, memoryGb: range, priority: "normal", dynamic: false },
    }]
  })
}
