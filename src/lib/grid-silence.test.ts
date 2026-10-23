import { describe, expect, it } from "vitest"
import { ASK_TO_LEAVE_DAYS, daysSince, silenceNotice } from "./grid-silence"

const daysAgo = (days: number) => Math.floor(Date.now() / 1000) - days * 86400

describe("a hub that stopped answering", () => {
  it("says nothing while the silence is still ordinary", () => {
    expect(daysSince(null)).toBeNull()
    expect(silenceNotice(null, "Acme")).toBeNull()
    expect(silenceNotice(daysSince(daysAgo(2)), "Acme")).toBeNull()
    expect(silenceNotice(ASK_TO_LEAVE_DAYS - 1, "Acme")).toBeNull()
  })

  it("asks about leaving after a week, and promises nothing is removed", () => {
    expect(daysSince(daysAgo(9))).toBe(9)
    const notice = silenceNotice(daysSince(daysAgo(9)), "Acme")
    expect(notice).toContain("Acme's hub has not answered for 9 days")
    expect(notice).toContain("nothing here is removed by leaving")
  })
})
