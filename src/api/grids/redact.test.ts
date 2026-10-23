// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest"
import { REDACTED, onLeak, safePath, safeUrl, scrub } from "@/api/grids/redact"

afterEach(() => { vi.restoreAllMocks() })

describe("the redaction pass", () => {
  it("replaces a field whose name says the value is the secret, and says where it was", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    const seen: string[] = []
    const stop = onLeak(leak => seen.push(`${leak.command} ${leak.path}`))
    const answer = scrub({ hub: { name: "Acme", password: "hunter2", people: [{ apiKey: "sk-live-1" }] } }, undefined, "grid_status")
    stop()
    expect(answer.hub.password).toBe(REDACTED)
    expect(answer.hub.people[0]!.apiKey).toBe(REDACTED)
    expect(answer.hub.name).toBe("Acme")
    expect(seen).toEqual(["grid_status hub.password", "grid_status hub.people[0].apiKey"])
  })

  it("never throws, because a person in front of a screen should still see the rest of the page", () => {
    vi.spyOn(console, "warn").mockImplementation(() => {})
    expect(() => scrub({ token: "abc" }, undefined, "anything")).not.toThrow()
  })

  it("leaves the words somebody consents to exactly as they arrived", () => {
    const offer = {
      bounty: {
        authorization: "Acme authorizes testing of checkout.acme.test.",
        scope: "checkout.acme.test only",
        terms: { objective: "Find logic flaws", serviceRules: { text: "Do not disrupt the service.\nStop if asked." } },
      },
    }
    const safe = scrub(offer, { opaque: ["terms", "bounty"], keep: ["authorization", "scope"] }, "swarm_dispatch")
    expect(safe).toEqual(offer)
  })

  it("does not walk into a document somebody else wrote", () => {
    const report = { id: "r1", document: { value: "kept", token: "kept too", lines: ["a\nb"] } }
    const safe = scrub(report, { opaque: ["document"] }, "swarm_dispatch")
    expect(safe.document).toEqual(report.document)
  })

  it("leaves every other string exactly as it is, however long or many lines it has", () => {
    const answer = "A long answer.\n\nWith blank lines and " + "x".repeat(900)
    expect(scrub({ answer }, undefined, "grid_swarm_run").answer).toBe(answer)
  })

  it("keeps a credential hint, a fingerprint and an invite code, because the pages render them", () => {
    const status = { hint: "9f2a", fingerprint: "AB:CD:EF", invite: "grid-invite:eyJ2IjoxfQ", keyFingerprint: "00:11" }
    expect(scrub(status, undefined, "access_status")).toEqual(status)
  })

  it("drops a sign-in and a query from an address, only where the policy names the field", () => {
    const row = { url: "https://dana:hunter2@hub.acme.test/v1/use?key=abc#here", note: "https://dana:hunter2@hub.acme.test/v1" }
    const safe = scrub(row, { urls: ["url"] }, "access_status")
    expect(safe.url).toBe("https://hub.acme.test/v1/use")
    expect(safe.note).toBe(row.note)
  })

  it("folds a home folder away, only where the policy names the field", () => {
    expect(safePath("C:\\Users\\dana\\Work\\site")).toBe("...\\Work\\site")
    expect(safePath("/home/dana/work/site")).toBe(".../work/site")
    expect(scrub({ where: "C:\\Users\\dana\\Work" }, { paths: ["where"] }, "x").where).toBe("...\\Work")
  })

  it("leaves something that is not an address alone", () => {
    expect(safeUrl("not an address")).toBe("not an address")
  })
})
