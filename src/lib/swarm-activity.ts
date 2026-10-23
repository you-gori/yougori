import type { SwarmActivity } from "@/api/swarm-api"

/** Updates replace the same row; full snapshots also work after reconnecting. */
export function mergeActivity(current: SwarmActivity[], incoming: SwarmActivity[]) {
  const rows = [...current]
  for (const event of incoming) {
    const index = rows.findIndex(row => event.streamId ? row.streamId === event.streamId : row.seq === event.seq)
    if (index < 0) rows.push(event)
    else if (rows[index]!.seq <= event.seq) rows[index] = event
  }
  return rows.slice(-200)
}
