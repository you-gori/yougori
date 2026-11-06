import { createContext, useContext } from "react"
import type { useNetwork } from "@/components/use-network"

/** What the sidebar and the pages' actions share for My computer and the account sign-in. */
export interface WorkspaceActions {
  network: ReturnType<typeof useNetwork>
  website: string
  create(): void
  openNetwork(): void
  /** Opens the Run-a-local-model popup from My computer. */
  openModel(): void
}

export const WorkspaceActionsContext = createContext<WorkspaceActions | null>(null)

export function useWorkspaceActions() {
  const value = useContext(WorkspaceActionsContext)
  if (!value) throw new Error("useWorkspaceActions is used outside WorkspaceActionsProvider")
  return value
}
