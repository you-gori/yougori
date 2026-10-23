import { expect, it } from "vitest"
import profile from "../../distribution.txt?raw"
import { LIVE_TARGETS } from "./distribution"

it("uses the same explicit source edition as the native engine", () => {
  expect(["public", "private"]).toContain(profile.trim())
  expect(LIVE_TARGETS).toBe(profile.trim() === "private")
})
