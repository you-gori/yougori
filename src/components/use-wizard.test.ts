import { expect, it } from "vitest"
import { stepAfter, stepsAsked, type AskedStep } from "@/components/use-wizard"
import { blueprintSteps, emptyBlueprint, type GridBlueprint } from "@/lib/grid-blueprint"

/** The walk a person makes: forward from the first question, answering as they go. */
function walk(steps: readonly AskedStep<GridBlueprint>[], answers: GridBlueprint): string[] {
  const trail = [steps[0]?.id ?? ""]
  for (;;) {
    const next = stepAfter(steps, answers, trail[trail.length - 1] as string)
    if (!next) return trail
    trail.push(next.id)
  }
}

const sandbox = (): GridBlueprint => ({ ...emptyBlueprint("ada"), capabilities: ["workspaces"], name: "Acme", address: "192.168.1.20" })
const models = (): GridBlueprint => ({ ...emptyBlueprint("ada"), capabilities: ["models"], name: "Acme", address: "192.168.1.20" })

it("walks only the questions this grid is asked, in order", () => {
  const steps = blueprintSteps()
  expect(walk(steps, sandbox())).toEqual(stepsAsked(steps, sandbox()).map(step => step.id))
  expect(walk(steps, models())).toEqual(stepsAsked(steps, models()).map(step => step.id))
})

it("goes back past a question that was never asked", () => {
  const steps = blueprintSteps()
  const answers = models()
  const trail = walk(steps, answers)
  const percent = trail.indexOf("models-percent")
  expect(percent).toBeGreaterThan(0)
  // Back from the percentage reaches the question about computers, never a sandbox question.
  expect(trail[percent - 1]).toBe("models-scope")
  expect(trail).not.toContain("desks-image")
})

it("skips the question a later answer settles", () => {
  const steps = blueprintSteps()
  const answers = sandbox()
  answers.workspaces = { ...answers.workspaces, image: { kind: "registry", reference: "docker.io/library/ubuntu:24.04" }, kind: "container" }
  const trail = walk(steps, answers)
  expect(trail).toContain("desks-image")
  expect(trail).not.toContain("desks-kind")
  // Going back from what a desk can reach lands on the image, not on the question it settled.
  const network = trail.indexOf("desks-network")
  expect(trail[network - 1]).toBe("desks-image")
})

it("will not move on from a question whose answer cannot be used", () => {
  const steps = blueprintSteps()
  const nothing = { ...emptyBlueprint("ada"), name: "" }
  expect(steps[0]?.problem(nothing)).toBe("Choose what this grid is for.")
  const named = steps.find(step => step.id === "name")
  expect(named?.problem(nothing)).toContain("Give the grid a name")
  expect(named?.problem({ ...nothing, name: "Acme" })).toBe("")
})

it("ends on the summary, whatever the grid is for", () => {
  const steps = blueprintSteps()
  for (const answers of [sandbox(), models(), { ...emptyBlueprint("ada"), capabilities: ["research" as const] }]) {
    expect(walk(steps, answers as GridBlueprint).at(-1)).toBe("summary")
  }
})
