// @vitest-environment jsdom
import { beforeEach, expect, it } from "vitest"
import { emptyBlueprint } from "@/lib/grid-blueprint"
import { forgetResearch, readResearch, rememberResearch, researchSentence } from "@/lib/research-authorisation"

const authorised = () => ({
  ...emptyBlueprint("ada").research,
  scope: "Review the checkout service",
  sources: [{ kind: "folder" as const, value: "C:/work/checkout" }],
  network: "destinations" as const,
  destinations: ["https://staging.acme.test"],
  worker: { kind: "microVm" as const, cpu: 6, memoryGb: 16, diskGb: 80, gpu: false },
  approval: "beforeEachSource" as const,
})

beforeEach(() => { window.localStorage.clear() })

it("keeps what somebody authorised, so closing the wizard does not throw it away", () => {
  rememberResearch(authorised())
  const read = readResearch()
  expect(read?.scope).toBe("Review the checkout service")
  expect(read?.sources).toEqual([{ kind: "folder", value: "C:/work/checkout" }])
  expect(read?.destinations).toEqual(["https://staging.acme.test"])
  expect(read?.approval).toBe("beforeEachSource")
  // What a worker is given when one is made on the Swarm Mining page.
  expect(read?.worker).toEqual({ kind: "microVm", cpu: 6, memoryGb: 16, diskGb: 80, gpu: false })
})

it("holds no secret, and forgets when asked", () => {
  rememberResearch(authorised())
  expect(window.localStorage.getItem("yougori.research.authorised")).not.toMatch(/password|secret/i)
  forgetResearch()
  expect(readResearch()).toBeNull()
})

it("says what was authorised in one sentence, with the scope and where it may reach", () => {
  expect(researchSentence(authorised())).toBe(
    "You authorised Review the checkout service, on 1 source. It may reach https://staging.acme.test.",
  )
  const offline = { ...authorised(), network: "offline" as const, sources: [] }
  expect(researchSentence(offline)).toBe("You authorised Review the checkout service, on no source yet. It stays offline.")
})

it("reads nothing out of rubbish rather than throwing in the page that asks", () => {
  window.localStorage.setItem("yougori.research.authorised", "{not json")
  expect(readResearch()).toBeNull()
  window.localStorage.setItem("yougori.research.authorised", JSON.stringify({ scope: 7 }))
  expect(readResearch()).toBeNull()
})
