import { expect, it } from "vitest"
import type { ResourceView } from "@/api/setups/types"
import { COLUMN, diagramItems, layoutSetup, neighbour, PAD, UNKNOWN_PLACE } from "./diagram-layout"

const part = (resourceId: string, over: Partial<ResourceView> = {}): ResourceView => ({ resourceId, kind: "environment", owned: true, label: resourceId, ...over })

const office: ResourceView[] = [
  part("web", { kind: "service_publication", dependsOn: ["app"], placement: "This computer" }),
  part("app", { dependsOn: ["db", "models"], placement: "This computer" }),
  part("db", { kind: "volume", placement: "This computer" }),
  part("models", { kind: "model_service", owned: false, borrowedFrom: "Neo Grid", placement: "Office PC 2" }),
  part("app-to-models", { kind: "connection", connection: { from: "app", to: "models", ports: [8080, 8080, 443], direction: "one_way" } }),
  part("loose", { kind: "job" }),
]

it("lays out the same picture for the same parts, whatever order they come in", () => {
  const first = layoutSetup(office)
  for (const order of [[...office].reverse(), [office[3]!, office[0]!, office[5]!, office[1]!, office[4]!, office[2]!]]) {
    expect(layoutSetup(order)).toEqual(first)
  }
})

it("puts each part one column right of the furthest part it needs, one lane per place", () => {
  const layout = layoutSetup(office)
  const at = Object.fromEntries(layout.nodes.map(node => [node.id, node]))
  expect(at.db!.level).toBe(0)
  expect(at.models!.level).toBe(0)
  expect(at.app!.level).toBe(1)
  expect(at.web!.level).toBe(2)
  expect(at.web!.x).toBe(PAD + 2 * COLUMN)
  // This computer first, other places by name, unknown places last.
  expect(layout.lanes.map(lane => lane.name)).toEqual(["This computer", "Office PC 2", UNKNOWN_PLACE])
  expect(at.models!.lane).toBe(1)
  expect(at.loose!.lane).toBe(2)
  // A connection between two parts here is an edge, not a part.
  expect(at["app-to-models"]).toBeUndefined()
})

it("keeps needing a part apart from being connected to it, with a connection's direction and ports", () => {
  const { edges } = layoutSetup(office)
  expect(edges.filter(edge => edge.type === "needs").map(edge => `${edge.from}>${edge.to}`)).toEqual(["app>db", "app>models", "web>app"])
  const link = edges.find(edge => edge.type === "connects")!
  expect(link).toMatchObject({ from: "app", to: "models", ports: [443, 8080], direction: "one_way" })
  expect(link.resource?.resourceId).toBe("app-to-models")
})

it("survives what the engine should never send: a cycle, a missing part, a connection to nowhere", () => {
  const layout = layoutSetup([
    part("a", { dependsOn: ["b", "ghost", "a"] }),
    part("b", { dependsOn: ["a"] }),
    part("lost", { kind: "connection", connection: { from: "a", to: "ghost" } }),
  ])
  expect(layout.nodes.map(node => node.id).sort()).toEqual(["a", "b", "lost"])
  expect(layout.edges.every(edge => edge.to !== "ghost")).toBe(true)
  expect(layout.width).toBeGreaterThan(0)
})

it("moves between parts with the arrow keys the way the picture reads", () => {
  const items = diagramItems(layoutSetup(office))
  expect(items[0]!.id).toBe("db")
  expect(neighbour(items, "db", "ArrowRight")).toBe("app")
  expect(neighbour(items, "app", "ArrowRight")).toBe("web")
  expect(neighbour(items, "web", "ArrowRight")).toBeNull()
  expect(neighbour(items, "app", "ArrowLeft")).toBe("db")
  expect(neighbour(items, "db", "ArrowDown")).toBe("models")
  expect(neighbour(items, "models", "ArrowDown")).toBe("loose")
  expect(neighbour(items, "models", "ArrowUp")).toBe("db")
  // The connection's handle sits between the parts it joins, and is reached like one.
  expect(neighbour(items, "models", "ArrowRight")).toBe("app-to-models")
  expect(neighbour(items, "db", "Home")).toBe("db")
  expect(neighbour(items, "db", "End")).toBe("app-to-models")
  expect(neighbour(items, "nothing", "ArrowRight")).toBe("db")
})
