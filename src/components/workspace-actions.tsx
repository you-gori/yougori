import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react"
import { gridApi, type GridStatus } from "@/api/grid-api"
import { swarmApi, type SwarmWorker } from "@/api/swarm-api"
import { desksApi, type DesksStatus } from "@/api/desks-api"
import { GridHostDialog } from "@/components/grid-host-dialog"
import { GridJoinDialog } from "@/components/grid-join-dialog"
import { ModelWorkspace } from "@/components/model-workspace"
import { NetworkPanel } from "@/components/network-panel"
import { WorkerSetupDialog } from "@/components/swarm-dialogs"
import { DeskLoginDialog } from "@/components/desk-login-dialog"
import { toastManager } from "@/components/ui/toast"
import { useNetwork } from "@/components/use-network"
import { WorkspaceActionsContext, type WorkspaceActions } from "@/components/use-workspace-actions"

const message = (reason: unknown) => reason instanceof Error ? reason.message : String(reason)

// Read at call time, so a replaced API method is used on the next poll.
const readGrid = () => gridApi.status()
const readSwarm = () => swarmApi.workers()
const readDesks = () => desksApi.status()

/** One engine read, refreshed every 4 s; a failed read keeps the last value and gives the reason.
 *  Reads can overlap (a timer tick beside a manual refresh); only the newest one started may
 *  change what is shown, so a slow older answer never brings back state that is already gone. */
function usePolled<T>(read: () => Promise<T>, initial: T) {
  const [value, setValue] = useState<T>(initial)
  const [error, setError] = useState("")
  const newest = useRef(0)
  const refresh = useCallback(async () => {
    const id = ++newest.current
    try {
      const next = await read()
      if (newest.current === id) { setValue(next); setError("") }
    } catch (reason) {
      if (newest.current === id) setError(message(reason))
    }
  }, [read])
  useEffect(() => {
    void refresh()
    const timer = window.setInterval(() => void refresh(), 4000)
    // Reads still in flight are abandoned: the counter moves on, so none of them applies.
    const generation = newest
    return () => { window.clearInterval(timer); generation.current++ }
  }, [refresh])
  return { value, error, refresh }
}

/** The sidebar, the pages' actions and the Neo Grid and Swarm Mining pages share one status and one
 *  set of dialogs, so an action shows up wherever its result belongs. */
export function WorkspaceActionsProvider({ onCreate, children }: { onCreate(): void; children: ReactNode }) {
  const network = useNetwork(true)
  const grid = usePolled<GridStatus | null>(readGrid, null)
  const swarm = usePolled<SwarmWorker[]>(readSwarm, [])
  const desks = usePolled<DesksStatus | null>(readDesks, null)
  const [hosting, setHosting] = useState(false)
  const [joining, setJoining] = useState(false)
  const [networkOpen, setNetworkOpen] = useState(false)
  const [setup, setSetup] = useState<"join" | "closed" | null>(null)
  const [modelOpen, setModelOpen] = useState(false)
  const [deskOpen, setDeskOpen] = useState(false)
  const [desksHost, setDesksHost] = useState(false)
  const [desksJoin, setDesksJoin] = useState(false)
  const website = network.status?.website ?? "https://yougori.com"
  const done = (title: string, refresh: () => Promise<void>) => (text?: string) => {
    toastManager.add({ title, description: text, type: "success" })
    void refresh()
  }
  const value = useMemo<WorkspaceActions>(() => ({
    grid: grid.value, gridError: grid.error, refreshGrid: grid.refresh,
    workers: swarm.value, swarmError: swarm.error, refreshSwarm: swarm.refresh,
    network, website, create: onCreate,
    openModel: () => setModelOpen(true),
    openHost: () => setHosting(true),
    openJoin: () => setJoining(true),
    openNetwork: () => setNetworkOpen(true),
    openSetup: mode => setSetup(mode),
    desks: desks.value, desksError: desks.error, refreshDesks: desks.refresh,
    openDesksHost: () => setDesksHost(true),
    openDesksJoin: () => setDesksJoin(true),
    openDeskLogin: () => setDeskOpen(true),
  }), [grid.value, grid.error, grid.refresh, swarm.value, swarm.error, swarm.refresh, desks.value, desks.error, desks.refresh, network, website, onCreate])
  return <WorkspaceActionsContext.Provider value={value}>
    {children}
    <GridHostDialog open={hosting} onOpenChange={setHosting} onHosted={done("Grid is running", grid.refresh)} />
    <GridJoinDialog open={joining} onOpenChange={setJoining} membership={grid.value?.member ?? null} onJoined={done("Joined the grid", grid.refresh)} />
    <NetworkPanel open={networkOpen} onOpenChange={setNetworkOpen} hideTrigger />
    <WorkerSetupDialog open={setup !== null} mode={setup ?? "join"} onOpenChange={open => { if (!open) setSetup(null) }} onReady={text => { toastManager.add({ title: text, type: "success" }); void swarm.refresh() }} />
    <ModelWorkspace open={modelOpen} onOpenChange={setModelOpen} hideTrigger />
    <GridHostDialog variant="desks" open={desksHost} onOpenChange={setDesksHost} onHosted={done("Sandbox grid is running", desks.refresh)} />
    <GridJoinDialog variant="desks" open={desksJoin} onOpenChange={setDesksJoin} membership={null} onJoined={done("Joined the sandbox grid", desks.refresh)} />
    <DeskLoginDialog open={deskOpen} onOpenChange={setDeskOpen} onSignedIn={text => { toastManager.add({ title: text, type: "success" }); void desks.refresh() }} />
  </WorkspaceActionsContext.Provider>
}
