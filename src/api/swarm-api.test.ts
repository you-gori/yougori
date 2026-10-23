import { describe, expect, it, vi, beforeEach } from "vitest"
import { swarmApi, type SwarmOffer } from "@/api/swarm-api"

const invoke = vi.fn()
vi.mock("@/api/platform-api", () => ({ run: (command: string, args: unknown) => invoke(command, args) }))

beforeEach(() => { invoke.mockReset(); invoke.mockResolvedValue({ worker: {} }) })

const offer: SwarmOffer = {
  id: "offer-1", termsVersion: 3, termsDigest: "td", sourceRevision: "rev", authorizationDigest: "ad",
  bounty: { id: "bounty-7", title: "T", terms: { sourceDigest: "sd", serviceRules: { version: 5, digest: "rd" } } },
}

describe("swarmApi.accept", () => {
  it("sends the bounty's digests and records authorization and rules consent", async () => {
    await swarmApi.accept("worker-1", offer, 30)
    const [command, { request }] = invoke.mock.calls[0] as [string, { request: Record<string, unknown> }]
    expect(command).toBe("swarm_dispatch")
    expect(request).toMatchObject({
      action: "accept", workerId: "worker-1", bountyId: "bounty-7",
      termsVersion: 3, termsDigest: "td", sourceRevision: "rev", sourceDigest: "sd",
      authorizationAccepted: true, authorizationDigest: "ad",
      rulesAccepted: true, rulesVersion: 5, rulesDigest: "rd",
      directPaymentAccepted: true, budgetMinutes: 30, confirmed: true,
    })
  })

  it("wraps each action in a swarm_dispatch request", async () => {
    await swarmApi.prepare({ name: "W", model: "hf.co/a/b" })
    expect(invoke.mock.calls[0]![1]).toMatchObject({ request: { action: "prepare", name: "W", model: "hf.co/a/b" } })
    await swarmApi.practiceStart("worker-1", "source")
    expect(invoke.mock.calls[1]![1]).toEqual({ request: { action: "practiceStart", workerId: "worker-1", content: "source" } })
  })
})
