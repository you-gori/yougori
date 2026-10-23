// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, waitFor } from "@testing-library/react"
import { afterEach, beforeEach, expect, it, vi } from "vitest"
import { GridsPage } from "./grids-page"
import { emptyBlueprint, type GridBlueprint } from "@/lib/grid-blueprint"
import { readResearch } from "@/lib/research-authorisation"
import { grids } from "@/api/grids"
import type { GridCreation } from "@/components/grid-create-wizard"

/** One button that hands the page a finished blueprint, so this is about what the page then does
 *  with it rather than about the wizard, which has its own test. */
let asked: ((creation: GridCreation) => Promise<void>) | null = null
vi.mock("@/components/grid-create-wizard", () => ({
  GridCreateWizard: ({ onCreate }: { onCreate(creation: GridCreation): Promise<void> }) => {
    asked = onCreate
    return null
  },
}))
vi.mock("@/components/grid-realm-view", () => ({ GridRealmView: () => null }))
vi.mock("@/components/grid-rollout", () => ({ GridRollout: () => null }))
vi.mock("@/context/platform-context", () => ({ usePlatform: () => ({ state: { host: { hostname: "Studio PC" } } }) }))
vi.mock("@/components/use-access-status", () => ({ useAccessStatus: () => ({ status: null, refresh: vi.fn() }), accessHint: () => "Not set up" }))
vi.mock("@/components/use-workspace-actions", () => ({
  useWorkspaceActions: () => ({
    grid: null, workers: [], desks: null,
    refreshGrid: vi.fn(), refreshDesks: vi.fn(), refreshSwarm: vi.fn(),
  }),
}))
vi.mock("@/api/grids", () => ({
  grids: {
    models: { suggestedAddress: vi.fn(), host: vi.fn(), addPlan: vi.fn() },
    workspaces: { host: vi.fn(), setOffer: vi.fn() },
    credentials: { host: vi.fn() },
  },
}))

const creation = (over: Partial<GridBlueprint>): GridCreation => ({
  blueprint: { ...emptyBlueprint("ada"), name: "Acme", address: "192.168.1.20", ...over },
  password: "correct horse battery",
  accepted: [],
})

beforeEach(() => { window.localStorage.clear(); asked = null })
afterEach(() => { cleanup(); vi.resetAllMocks() })

const page = () => {
  const onFocus = vi.fn()
  render(<GridsPage focus={null} onFocus={onFocus} />)
  return onFocus
}

it("orders the model the summary named, rather than only starting the hub", async () => {
  vi.mocked(grids.models.host).mockResolvedValue({} as never)
  page()
  await waitFor(() => expect(asked).not.toBeNull())
  await asked?.(creation({
    capabilities: ["models"],
    models: { ...emptyBlueprint("ada").models, model: "acme/assistant", scope: "remaining", percent: 60 },
  }))
  expect(grids.models.host).toHaveBeenCalledWith("Acme", "192.168.1.20", "correct horse battery", "network")
  expect(grids.models.addPlan).toHaveBeenCalledWith({ model: "acme/assistant", quant: null, target: { kind: "remaining", percent: 60 } })
})

it("gives this computer the share the summary named, once it has joined its own grid", async () => {
  vi.mocked(grids.workspaces.host).mockResolvedValue({ member: { deviceId: "m1" } } as never)
  page()
  await waitFor(() => expect(asked).not.toBeNull())
  const blueprint = emptyBlueprint("ada")
  await asked?.(creation({
    capabilities: ["workspaces"],
    workspaces: { ...blueprint.workspaces, commitment: "share", share: { cpu: 8, memoryGb: 32, diskGb: 200, gpu: true } },
  }))
  expect(grids.workspaces.setOffer).toHaveBeenCalledWith("m1", { cpu: 8, memoryGb: 32, diskGb: 200, gpu: true, idleOnly: false })
})

it("keeps what research was authorised instead of throwing the answers away", async () => {
  const onFocus = page()
  await waitFor(() => expect(asked).not.toBeNull())
  const blueprint = emptyBlueprint("ada")
  await asked?.(creation({
    capabilities: ["research"],
    research: {
      ...blueprint.research,
      scope: "Review the checkout service",
      sources: [{ kind: "folder", value: "C:/work/checkout" }],
      worker: { kind: "microVm", cpu: 6, memoryGb: 16, diskGb: 80, gpu: false },
    },
  }))
  // Nothing is started here, and nothing is lost either.
  expect(grids.models.host).not.toHaveBeenCalled()
  expect(grids.workspaces.host).not.toHaveBeenCalled()
  const kept = readResearch()
  expect(kept?.scope).toBe("Review the checkout service")
  expect(kept?.sources).toEqual([{ kind: "folder", value: "C:/work/checkout" }])
  expect(kept?.worker.diskGb).toBe(80)
  // And the page sends somebody to where a worker is made, with that in hand.
  expect(onFocus).toHaveBeenCalledWith({ kind: "page", grid: "research" })
})
