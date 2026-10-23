import { createContext, useContext } from "react"
import type { GridStatus } from "@/api/grid-api"
import type { SwarmWorker } from "@/api/swarm-api"
import type { DesksStatus } from "@/api/desks-api"
import type { useNetwork } from "@/components/use-network"

/** What the sidebar, the pages' actions and the Neo Grid and Swarm Mining pages share. */
export interface WorkspaceActions {
  grid: GridStatus | null
  gridError: string
  refreshGrid(): Promise<void>
  workers: SwarmWorker[]
  swarmError: string
  refreshSwarm(): Promise<void>
  network: ReturnType<typeof useNetwork>
  website: string
  create(): void
  openModel(): void
  openHost(): void
  openJoin(): void
  openNetwork(): void
  openSetup(mode: "join" | "closed"): void
  /** The Sandbox Grid: its own hub, membership and desk sign-in. */
  desks: DesksStatus | null
  desksError: string
  refreshDesks(): Promise<void>
  openDesksHost(): void
  openDesksJoin(): void
  /** A person signs in to open their desk from their company's sandbox grid. */
  openDeskLogin(): void
}

export const WorkspaceActionsContext = createContext<WorkspaceActions | null>(null)

export function useWorkspaceActions() {
  const value = useContext(WorkspaceActionsContext)
  if (!value) throw new Error("useWorkspaceActions is used outside WorkspaceActionsProvider")
  return value
}
