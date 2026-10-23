import { useState } from "react"
import { SwarmWorkerDetail } from "./swarm-worker-detail"
import { WorkerActivity } from "./swarm-activity"
import { Tabs, TabsList, TabsTab, TabsPanel } from "./ui/tabs"

export function SwarmWorkerWorkspace({ workerId, hasBounty, onChanged }: {
  workerId: string; hasBounty: boolean; onChanged(): void
}) {
  const [tab, setTab] = useState<string | number>("activity")
  return <Tabs value={tab} onValueChange={setTab} className="swarm-workspace">
    <TabsList aria-label="Worker workspace">
      <TabsTab value="conversation">Conversation</TabsTab>
      <TabsTab value="activity">Activity</TabsTab>
    </TabsList>
    <TabsPanel value="conversation" keepMounted>
      {hasBounty
        ? <SwarmWorkerDetail workerId={workerId} onChanged={onChanged} active={tab === "conversation"} />
        : <p className="grid-note">A private conversation opens once this worker accepts a bounty.</p>}
    </TabsPanel>
    <TabsPanel value="activity" keepMounted>
      <WorkerActivity workerId={workerId} active={tab === "activity"} />
    </TabsPanel>
  </Tabs>
}
