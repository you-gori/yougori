import { expect, it } from "vitest"
import { sandboxVmEnvironments } from "./sandbox-vm-environments"

it("keeps live and saved VMs while omitting ended importer/discarded history", () => {
  const environments = sandboxVmEnvironments({
    sandboxes: [
      { sandbox: "live", phase: "ready", state: "running", boot: 1, revocation: null },
      { sandbox: "saved", phase: "ended", state: "stopped", boot: 1, revocation: null },
      { sandbox: "discarded", phase: "ended", state: "stopped", boot: 1, revocation: null },
    ],
    workspaces: [{ sandbox: "saved", sandbox_running: false, folder: "C:/projects/website", imported_at: "today", files: 1, excluded: 0, skipped: 0, state: { state: "imported" } }],
  })
  expect(environments.map(vm => vm.id)).toEqual(["live", "saved"])
  expect(environments[1]?.name).toBe("website")
})
