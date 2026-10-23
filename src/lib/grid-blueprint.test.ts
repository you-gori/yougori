import { expect, it } from "vitest"
import {
  askedSteps, blueprintSteps, emptyBlueprint, rehearse, stepTitle,
  type GridBlueprint, type GridFacts,
} from "@/lib/grid-blueprint"

const facts: GridFacts = { computer: "Studio PC", computers: ["Design laptop"], alreadyHere: [] }

const ask = (part: Partial<GridBlueprint>): GridBlueprint => ({
  ...emptyBlueprint("ada"),
  name: "Acme",
  address: "192.168.1.20",
  ...part,
})

const ids = (answers: GridBlueprint) => askedSteps(answers).map(step => step.id)

it("asks what the grid is for before it asks anything else", () => {
  expect(blueprintSteps()[0]?.id).toBe("purpose")
  // With nothing chosen, only the questions every grid has are asked.
  expect(ids(ask({}))).toEqual(["purpose", "name", "reach", "password", "people", "summary"])
})

it("asks only the questions that belong to what the grid is for", () => {
  const sandbox = ids(ask({ capabilities: ["workspaces"] }))
  expect(sandbox).toContain("desks-sharing")
  expect(sandbox).toContain("desks-commitment")
  expect(sandbox).toContain("desks-disk")
  expect(sandbox).toContain("desks-image")
  expect(sandbox).toContain("desks-network")
  expect(sandbox.filter(id => id.startsWith("models-"))).toEqual([])
  expect(sandbox.filter(id => id.startsWith("credentials-"))).toEqual([])
  expect(sandbox.filter(id => id.startsWith("research-"))).toEqual([])

  const models = ids(ask({ capabilities: ["models"] }))
  expect(models).toEqual([
    "purpose", "name", "reach", "password",
    "models-model", "models-quant", "models-scope", "models-percent", "models-idle", "models-schedule",
    "people", "summary",
  ])

  const credentials = ids(ask({ capabilities: ["credentials"] }))
  expect(credentials).toContain("credentials-destination")
  expect(credentials).toContain("credentials-methods")
  expect(credentials).toContain("credentials-paths")
  expect(credentials).toContain("credentials-approval")
  expect(credentials).toContain("credentials-rotation")

  const research = ids(ask({ capabilities: ["research"] }))
  expect(research).toContain("research-scope")
  expect(research).toContain("research-sources")
  expect(research).toContain("research-network")
  expect(research).toContain("research-worker")
  expect(research).toContain("research-approval")
})

it("asks both sets once when a grid is for two things", () => {
  const both = ids(ask({ capabilities: ["models", "workspaces"] }))
  expect(both.filter(id => id === "name")).toHaveLength(1)
  expect(both.filter(id => id === "password")).toHaveLength(1)
  expect(both).toContain("models-model")
  expect(both).toContain("desks-image")
})

it("settles what a desk is: derived from a container image, asked outright otherwise", () => {
  const registry = ask({ capabilities: ["workspaces"] })
  registry.workspaces = { ...registry.workspaces, image: { kind: "registry", reference: "docker.io/library/ubuntu:24.04" }, kind: "container" }
  expect(ids(registry)).not.toContain("desks-kind")
  const prepared = ask({ capabilities: ["workspaces"] })
  prepared.workspaces = { ...prepared.workspaces, image: { kind: "prepared", name: "Research desktop" } }
  expect(ids(prepared)).toContain("desks-kind")
})

it("never asks how many computers when the admin picked them", () => {
  const picked = ask({ capabilities: ["models"] })
  picked.models = { ...picked.models, scope: "computers", computers: ["m1"] }
  expect(ids(picked)).not.toContain("models-percent")
})

it("puts cores and memory on the computer's offer and the disk on the desk", () => {
  const answers = ask({ capabilities: ["workspaces"] })
  answers.workspaces = { ...answers.workspaces, share: { cpu: 8, memoryGb: 32, diskGb: 200, gpu: true }, deskDiskGb: 60 }
  const summary = rehearse(answers, facts).wouldCreate.join(" ")
  expect(summary).toContain("with 60 GB of disk")
  // No desk is made by creating the grid, so the summary does not say one is.
  expect(summary).toContain("No desk is ordered now")
  expect(summary).toContain("Studio PC offering 8 cores, 32 GB of memory and 200 GB of disk")
})

it("says where everything would be in sentences, with no path, identifier or vault entry in any of them", () => {
  const answers = ask({ capabilities: ["models"], administrators: ["ada", "grace"], approvers: ["grace"] })
  answers.models = { ...answers.models, model: "acme/assistant" }
  const dry = rehearse(answers, facts)
  const labels = dry.lines.map(line => line.label)
  expect(labels).toEqual(["Records", "Key", "Stored for it", "Reach", "Administrators", "Approvers", "Computers"])
  const everything = `${dry.headline} ${dry.lines.map(line => line.value).join(" ")} ${dry.wouldCreate.join(" ")}`
  expect(everything).toContain("Studio PC")
  expect(everything).toContain("ada and grace")
  expect(everything).toContain("Design laptop")
  expect(everything).not.toMatch(/realm-[0-9a-f]/i)
  expect(everything).not.toMatch(/\.db\b/)
  expect(everything).not.toMatch(/yougori-core/)
  expect(everything).not.toMatch(/[A-Za-z]:\\/)
})

it("raises a sentence for each high-impact answer, with the scope in it", () => {
  const answers = ask({ capabilities: ["workspaces"], reach: { kind: "quick" }, approvers: [] })
  answers.workspaces = { ...answers.workspaces, commitment: "whole" }
  const dry = rehearse(answers, facts)
  // Committing a computer whole is not done here, so it is said rather than agreed to.
  expect(dry.warnings.map(warning => warning.id)).toEqual(["public-link"])
  expect(dry.warnings[0]?.sentence).toContain("Acme")
  expect(dry.wouldCreate.join(" ")).toContain("committed whole on the Sandbox Grid's own page")
})

it("warns about every computer losing its model, and about being the only approver", () => {
  const answers = ask({ capabilities: ["models", "credentials"], administrators: ["ada"], approvers: ["ada"] })
  answers.models = { ...answers.models, model: "acme/assistant", scope: "all", percent: 100 }
  answers.credentials = { ...answers.credentials, name: "Deploy key", destination: "https://api.github.com", approval: "allow" }
  const warnings = rehearse(answers, facts).warnings
  expect(warnings.map(warning => warning.id)).toEqual(["every-computer", "credential-at-once", "only-approver"])
  expect(warnings[0]?.sentence).toContain("removes the model it runs now")
  expect(warnings[1]?.sentence).toContain("Nobody ever sees its value")
})

it("names the question to go back to when an answer cannot be used", () => {
  const answers = ask({ capabilities: ["credentials"], name: "" })
  const dry = rehearse(answers, facts)
  expect(dry.problem?.step).toBe("name")
  expect(stepTitle("name")).toBe("What is it called?")
  const named = rehearse(ask({ capabilities: ["credentials"] }), facts)
  expect(named.problem?.step).toBe("credentials-name")
})

it("records a credential as a shape and never as a value", () => {
  const answers = ask({ capabilities: ["credentials"] })
  answers.credentials = { ...answers.credentials, name: "Deploy key", destination: "https://api.github.com" }
  expect(Object.keys(answers.credentials)).not.toContain("value")
  expect(JSON.stringify(answers)).not.toContain("password")
  const dry = rehearse(answers, facts)
  expect(dry.wouldCreate.join(" ")).toContain("is made after the grid exists, in the step that takes its value")
})

it("says what authorising research really does, which is hand the answers to Swarm Mining", () => {
  const answers = ask({ capabilities: ["research"] })
  answers.research = { ...answers.research, scope: "Review the checkout service", sources: [{ kind: "folder", value: "C:/work" }] }
  const dry = rehearse(answers, facts)
  // No grid with its own key and its own records is created here, so the rehearsal never says one is.
  expect(dry.headline).toContain("what you authorise here is what Swarm Mining's setup is given")
  expect(dry.headline).not.toContain("its own key")
  expect(dry.wouldCreate.join(" ")).toContain("kept for Swarm Mining's own setup")
  expect(dry.wouldCreate.join(" ")).toContain("The worker itself is made there")
})

it("says when this computer already runs a grid of the same kind", () => {
  const answers = ask({ capabilities: ["models"] })
  answers.models = { ...answers.models, model: "acme/assistant" }
  const dry = rehearse(answers, { ...facts, alreadyHere: ["models"] })
  expect(dry.lines[0]?.value).toContain("already runs a grid for serving models")
})
