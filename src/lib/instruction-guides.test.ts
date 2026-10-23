import { describe, expect, it } from "vitest"
import { instructionGuides } from "./instruction-guides"
import { instructionTargets } from "./topic-walkthrough"

describe("topic walkthrough catalog", () => {
  it("gives every required topic a target for each step and begins with Settings", () => {
    expect(instructionGuides).toHaveLength(17)
    expect(instructionGuides[0]?.id).toBe("settings")
    expect(new Set(instructionGuides.map(guide => guide.id)).size).toBe(instructionGuides.length)
    expect(Object.keys(instructionTargets).sort()).toEqual(instructionGuides.map(guide => guide.id).sort())
    for (const guide of instructionGuides) {
      expect(guide.steps.length).toBeGreaterThanOrEqual(3)
      expect(instructionTargets[guide.id]).toHaveLength(guide.steps.length)
    }
  })
})
