import { useMemo, useState, type ReactNode } from "react"
import { ModelWorkspace } from "@/components/model-workspace"
import { NetworkPanel } from "@/components/network-panel"
import { useNetwork } from "@/components/use-network"
import { WorkspaceActionsContext, type WorkspaceActions } from "@/components/use-workspace-actions"

/** The sidebar and the pages' actions for My computer share one network read, the account sign-in
 *  and the Run-a-local-model popup, so an action shows up wherever its result belongs. */
export function WorkspaceActionsProvider({ onCreate, children }: { onCreate(): void; children: ReactNode }) {
  const network = useNetwork(true)
  const [networkOpen, setNetworkOpen] = useState(false)
  const [modelOpen, setModelOpen] = useState(false)
  const website = network.status?.website ?? "https://yougori.com"
  const value = useMemo<WorkspaceActions>(() => ({
    network, website, create: onCreate,
    openNetwork: () => setNetworkOpen(true),
    openModel: () => setModelOpen(true),
  }), [network, website, onCreate])
  return <WorkspaceActionsContext.Provider value={value}>
    {children}
    <NetworkPanel open={networkOpen} onOpenChange={setNetworkOpen} hideTrigger />
    <ModelWorkspace open={modelOpen} onOpenChange={setModelOpen} hideTrigger />
  </WorkspaceActionsContext.Provider>
}
