import type { ResourceView } from "@/api/setups/types"

/** Where everything in a setup's diagram goes. Pure and deterministic: the same resources, in any
 *  order, always give the same picture.
 *
 *  Parts are laid out left to right by what they need: a part with nothing to wait for is on the
 *  left, and each part sits one column right of the furthest part it needs. Each computer (or
 *  place) a part runs on gets its own lane. Needing a part and being connected to it are different
 *  things (a dependency is not network access), so they are different kinds of edge; a connection
 *  has a direction and ports, and its own handle in the middle so it can be chosen like a part.
 */

export const NODE_WIDTH = 176
export const NODE_HEIGHT = 56
export const COLUMN = 236
export const ROW = 76
export const LANE_GAP = 26
export const LANE_LABEL = 26
export const PAD = 16

/** The order kinds are stacked in within a column, so the same kinds always line up. */
const KIND_ORDER = [
  "grid", "compute_pool", "worker_group", "environment", "vm_sandbox", "model_service", "workspace_pool", "service_publication",
  "access_binding", "credential_broker", "volume", "artifact_store", "job", "connection",
]
const kindRank = (kind: string) => { const at = KIND_ORDER.indexOf(kind); return at === -1 ? KIND_ORDER.length : at }

export const UNKNOWN_PLACE = "Where it runs isn't known yet"

export interface DiagramNode {
  id: string
  resource: ResourceView
  lane: number
  level: number
  x: number
  y: number
}

export interface DiagramEdge {
  id: string
  /** "needs": `from` waits for `to`. "connects": `from` may reach `to` on its ports. */
  type: "needs" | "connects"
  from: string
  to: string
  ports: number[]
  direction: "one_way" | "both"
  /** The connection resource it stands for, for a connection. */
  resource: ResourceView | null
  /** Its handle, where a connection can be chosen. */
  x: number
  y: number
}

export interface DiagramLane { name: string; y: number; height: number }

export interface DiagramLayout {
  nodes: DiagramNode[]
  edges: DiagramEdge[]
  lanes: DiagramLane[]
  width: number
  height: number
}

/** Something in the diagram that can be chosen: a part, or a connection's handle. */
export interface DiagramItem { id: string; x: number; y: number; kind: "node" | "connection" }

const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0)

export function layoutSetup(resources: ResourceView[]): DiagramLayout {
  const sorted = [...resources].sort((a, b) => byText(a.resourceId, b.resourceId))
  const ids = new Set(sorted.map(resource => resource.resourceId))
  // A connection between two parts that are both here is drawn as an edge between them.
  const isEdge = (resource: ResourceView) => Boolean(resource.kind === "connection" && resource.connection && ids.has(resource.connection.from) && ids.has(resource.connection.to))
  const parts = sorted.filter(resource => !isEdge(resource))
  const partIds = new Set(parts.map(part => part.resourceId))
  const needs = (resource: ResourceView) => [...new Set(resource.dependsOn ?? [])].filter(id => partIds.has(id) && id !== resource.resourceId).sort(byText)

  // Columns: one right of the furthest part it needs. A cycle (which the engine refuses) can't
  // loop here: a part being worked out counts as column 0.
  const level = new Map<string, number>()
  const working = new Set<string>()
  const byId = new Map(parts.map(part => [part.resourceId, part]))
  const columnOf = (id: string): number => {
    const known = level.get(id)
    if (known !== undefined) return known
    if (working.has(id)) return 0
    working.add(id)
    const deps = needs(byId.get(id)!)
    const column = deps.length ? Math.max(...deps.map(columnOf)) + 1 : 0
    working.delete(id)
    level.set(id, column)
    return column
  }
  for (const part of parts) columnOf(part.resourceId)

  // Lanes: this computer first, then other places by name, then the ones nobody said.
  const placeOf = (resource: ResourceView) => resource.placement?.trim() || UNKNOWN_PLACE
  const places = [...new Set(parts.map(placeOf))].sort((a, b) =>
    a === b ? 0 : a === "This computer" ? -1 : b === "This computer" ? 1 : a === UNKNOWN_PLACE ? 1 : b === UNKNOWN_PLACE ? -1 : byText(a, b))

  const nodes: DiagramNode[] = []
  const lanes: DiagramLane[] = []
  let top = PAD
  places.forEach((place, lane) => {
    const here = parts.filter(part => placeOf(part) === place)
    const columns = new Map<number, ResourceView[]>()
    for (const part of here) columns.set(level.get(part.resourceId)!, [...(columns.get(level.get(part.resourceId)!) ?? []), part])
    let tallest = 1
    for (const [column, stack] of [...columns.entries()].sort((a, b) => a[0] - b[0])) {
      stack.sort((a, b) => kindRank(a.kind) - kindRank(b.kind) || byText(a.label, b.label) || byText(a.resourceId, b.resourceId))
      tallest = Math.max(tallest, stack.length)
      stack.forEach((resource, row) => nodes.push({
        id: resource.resourceId, resource, lane, level: column,
        x: PAD + column * COLUMN,
        y: top + LANE_LABEL + row * ROW,
      }))
    }
    const height = LANE_LABEL + tallest * ROW - (ROW - NODE_HEIGHT)
    lanes.push({ name: place, y: top, height })
    top += height + LANE_GAP
  })

  const at = new Map(nodes.map(node => [node.id, node]))
  const middle = (a: DiagramNode, b: DiagramNode) => ({ x: (a.x + b.x) / 2 + NODE_WIDTH / 2, y: (a.y + b.y) / 2 + NODE_HEIGHT / 2 })
  const edges: DiagramEdge[] = []
  for (const part of parts) {
    for (const dependency of needs(part)) {
      const from = at.get(part.resourceId)!, to = at.get(dependency)!
      edges.push({ id: `needs:${part.resourceId}:${dependency}`, type: "needs", from: part.resourceId, to: dependency, ports: [], direction: "one_way", resource: null, ...middle(from, to) })
    }
  }
  for (const resource of sorted.filter(isEdge)) {
    const link = resource.connection!
    const from = at.get(link.from)!, to = at.get(link.to)!
    edges.push({
      id: `connects:${resource.resourceId}`, type: "connects", from: link.from, to: link.to,
      ports: [...new Set(link.ports ?? [])].filter(port => Number.isInteger(port)).sort((a, b) => a - b),
      direction: link.direction === "both" ? "both" : "one_way", resource,
      // A connection between parts in the same place and column would sit on a part; it is
      // nudged into the gap beside them instead.
      ...(from.x === to.x ? { x: from.x + NODE_WIDTH + (COLUMN - NODE_WIDTH) / 2, y: (from.y + to.y) / 2 + NODE_HEIGHT / 2 } : middle(from, to)),
    })
  }
  edges.sort((a, b) => byText(a.id, b.id))

  const columns = nodes.length ? Math.max(...nodes.map(node => node.level)) + 1 : 1
  const linked = edges.some(edge => edge.type === "connects" && at.get(edge.from)!.x === at.get(edge.to)!.x)
  return {
    nodes,
    edges,
    lanes,
    width: PAD * 2 + (columns - 1) * COLUMN + NODE_WIDTH + (linked ? COLUMN - NODE_WIDTH : 0),
    height: Math.max(top - LANE_GAP + PAD, PAD * 2 + NODE_HEIGHT),
  }
}

/** Everything that can be chosen, in reading order: by lane, then column, then down the column,
 *  with each connection's handle after the parts. */
export function diagramItems(layout: DiagramLayout): DiagramItem[] {
  return [
    ...layout.nodes.map(node => ({ id: node.id, x: node.x + NODE_WIDTH / 2, y: node.y + NODE_HEIGHT / 2, kind: "node" as const })),
    ...layout.edges.filter(edge => edge.type === "connects").map(edge => ({ id: edge.resource!.resourceId, x: edge.x, y: edge.y, kind: "connection" as const })),
  ]
}

/** Where an arrow key goes from one item: the nearest item that way. Left and right move between
 *  columns, up and down within one, and Home and End to the first and the last. */
export function neighbour(items: DiagramItem[], fromId: string, key: string): string | null {
  const from = items.find(item => item.id === fromId)
  if (!from) return items[0]?.id ?? null
  if (key === "Home") return items[0]?.id ?? null
  if (key === "End") return items[items.length - 1]?.id ?? null
  const ahead = (item: DiagramItem) =>
    key === "ArrowRight" ? item.x > from.x + 1 : key === "ArrowLeft" ? item.x < from.x - 1 : key === "ArrowDown" ? item.y > from.y + 1 : key === "ArrowUp" ? item.y < from.y - 1 : false
  const sideways = key === "ArrowRight" || key === "ArrowLeft"
  // Staying in the same row (or column) matters more than being near: across first, then along.
  const cost = (item: DiagramItem) => sideways
    ? Math.abs(item.x - from.x) + Math.abs(item.y - from.y) * 3
    : Math.abs(item.y - from.y) + Math.abs(item.x - from.x) * 3
  const best = items.filter(item => item.id !== from.id && ahead(item)).sort((a, b) => cost(a) - cost(b) || byText(a.id, b.id))[0]
  return best?.id ?? null
}
