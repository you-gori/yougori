// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"
import { GridCreateWizard } from "./grid-create-wizard"

afterEach(cleanup)

const facts = { computer: "Studio PC", computers: ["Design laptop"], alreadyHere: [] }

function open(onCreate = vi.fn().mockResolvedValue(undefined), onOpenChange = vi.fn()) {
  render(
    <GridCreateWizard
      open
      onOpenChange={onOpenChange}
      facts={facts}
      me="ada"
      onCreate={onCreate}
      suggestedAddress={() => Promise.resolve("192.168.1.20")}
    />,
  )
  return { onCreate, onOpenChange }
}

const next = () => fireEvent.click(screen.getByRole("button", { name: "Next" }))
const back = () => fireEvent.click(screen.getByRole("button", { name: "Back" }))
const asking = () => screen.getByRole("dialog").textContent ?? ""

/** Answers the questions every grid is asked, leaving the wizard on the first of its own. */
async function throughTheCommonQuestions() {
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Acme" } })
  next()
  await screen.findByLabelText("This computer's address on your network")
  await waitFor(() => expect((screen.getByLabelText("This computer's address on your network") as HTMLInputElement).value).toBe("192.168.1.20"))
  next()
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "a short sentence" } })
  fireEvent.change(screen.getByLabelText("Password again"), { target: { value: "a short sentence" } })
  next()
}

it("asks what the grid is for before it asks anything else", () => {
  open()
  expect(screen.getByRole("dialog")).toHaveTextContent("What is this grid for?")
  expect(screen.getByRole("checkbox", { name: /Sandbox workspaces/ })).toBeInTheDocument()
  expect(screen.queryByLabelText("Name")).not.toBeInTheDocument()
  // Nothing may be answered until the purpose is.
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  expect(asking()).toContain("Choose what this grid is for.")
})

it("asks only the chosen purpose's questions and never the others", async () => {
  open()
  fireEvent.click(screen.getByRole("checkbox", { name: /Sandbox workspaces/ }))
  next()
  await throughTheCommonQuestions()
  expect(asking()).toContain("Who uses a desk?")
  const asked: string[] = []
  for (let step = 0; step < 8; step += 1) {
    asked.push(screen.getByRole("dialog").textContent ?? "")
    if (screen.queryByRole("button", { name: /Create the grid|Open Swarm Mining/ })) break
    next()
  }
  const everything = asked.join(" ")
  expect(everything).toContain("How much of a computer may this grid use?")
  expect(everything).toContain("How much disk does one desk get?")
  expect(everything).toContain("What is a desk built from?")
  expect(everything).toContain("What can a desk reach?")
  expect(everything).not.toContain("Which model?")
  expect(everything).not.toContain("Where may it be sent?")
})

it("asks what a desk is when the answer does not already settle it", async () => {
  open()
  fireEvent.click(screen.getByRole("checkbox", { name: /Sandbox workspaces/ }))
  next()
  await throughTheCommonQuestions()
  next() // who uses a desk
  next() // how much of a computer
  next() // the share
  next() // one desk's disk
  expect(asking()).toContain("What is a desk built from?")
  fireEvent.click(screen.getByRole("radio", { name: /A container image/ }))
  fireEvent.change(screen.getByLabelText("Container image"), { target: { value: "docker.io/library/ubuntu:24.04" } })
  next()
  // A container image settles it, so the question is not asked at all.
  expect(asking()).toContain("What can a desk reach?")
  back()
  fireEvent.click(screen.getByRole("radio", { name: /A prepared workspace/ }))
  fireEvent.change(screen.getByLabelText("Prepared workspace"), { target: { value: "Research desktop" } })
  next()
  expect(asking()).toContain("Is a desk a container, a microVM or a VM?")
})

it("goes back past a question that was skipped, and back from the first one closes without creating anything", async () => {
  const { onCreate, onOpenChange } = open()
  fireEvent.click(screen.getByRole("checkbox", { name: /Serving models/ }))
  next()
  await throughTheCommonQuestions()
  expect(asking()).toContain("Which model?")
  fireEvent.change(screen.getByLabelText(/^Model/), { target: { value: "acme/assistant" } })
  next() // which size
  next() // which computers
  fireEvent.click(screen.getByRole("radio", { name: /Ones you pick/ }))
  expect(screen.getByRole("button", { name: "Next" })).toBeDisabled()
  fireEvent.click(screen.getByRole("radio", { name: /All of them/ }))
  next()
  expect(asking()).toContain("How many of them?")
  back()
  expect(asking()).toContain("Which computers run it?")
  back(); back(); back(); back(); back(); back()
  expect(asking()).toContain("What is this grid for?")
  back()
  expect(onOpenChange).toHaveBeenCalledWith(false)
  expect(onCreate).not.toHaveBeenCalled()
})

it("says what would happen in sentences, and creates nothing until the last word", async () => {
  const { onCreate } = open()
  fireEvent.click(screen.getByRole("checkbox", { name: /Serving models/ }))
  next()
  await throughTheCommonQuestions()
  fireEvent.change(screen.getByLabelText(/^Model/), { target: { value: "acme/assistant" } })
  next(); next(); next(); next(); next(); next()
  expect(asking()).toContain("Who administers it, and who approves?")
  next()
  const summary = screen.getByRole("region", { name: "What would happen" })
  expect(summary).toHaveTextContent("Records")
  expect(summary).toHaveTextContent("Key")
  expect(summary).toHaveTextContent("Stored for it")
  expect(summary).toHaveTextContent("Reach")
  expect(summary).toHaveTextContent("Administrators")
  expect(summary).toHaveTextContent("Approvers")
  expect(summary).toHaveTextContent("Computers")
  expect(summary).toHaveTextContent("Studio PC mints the key")
  expect(summary.textContent).not.toMatch(/\.db\b/)
  expect(summary.textContent).not.toMatch(/realm-[0-9a-f]/i)
  expect(onCreate).not.toHaveBeenCalled()
  fireEvent.click(screen.getByRole("button", { name: "Create the grid" }))
  await waitFor(() => expect(onCreate).toHaveBeenCalledTimes(1))
  const creation = onCreate.mock.calls[0]?.[0] as { blueprint: { name: string; capabilities: string[] }; password: string; accepted: string[] }
  expect(creation.blueprint.name).toBe("Acme")
  expect(creation.blueprint.capabilities).toEqual(["models"])
  expect(creation.password).toBe("a short sentence")
  expect(JSON.stringify(creation.blueprint)).not.toContain("a short sentence")
})

it("will not create a grid until each high-impact sentence is agreed to", async () => {
  const { onCreate } = open()
  fireEvent.click(screen.getByRole("checkbox", { name: /Sandbox workspaces/ }))
  next()
  fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Acme" } })
  next()
  await screen.findByLabelText("This computer's address on your network")
  fireEvent.click(screen.getByRole("radio", { name: /Anywhere, through Cloudflare/ }))
  next()
  fireEvent.change(screen.getByLabelText("Password"), { target: { value: "a short sentence" } })
  fireEvent.change(screen.getByLabelText("Password again"), { target: { value: "a short sentence" } })
  next()
  next() // who uses a desk
  fireEvent.click(screen.getByRole("radio", { name: /The whole computer/ }))
  next()
  next(); next(); next(); next() // desk disk, image, kind, network
  expect(asking()).toContain("Who administers it, and who approves?")
  next()
  const create = screen.getByRole("button", { name: "Create the grid" })
  expect(create).toBeDisabled()
  const sentences = screen.getAllByRole("alert").map(one => one.textContent ?? "")
  expect(sentences.some(one => one.includes("quick public link"))).toBe(true)
  // Nothing here commits the computer whole, so nothing here asks anybody to agree that it
  // does. The summary says where it happens instead.
  expect(sentences.some(one => one.includes("Committing Studio PC whole"))).toBe(false)
  expect(screen.getByRole("region", { name: "What would happen" })).toHaveTextContent("This screen does not do it.")
  const agreements = screen.getAllByRole("checkbox")
  fireEvent.click(agreements[agreements.length - 1] as HTMLElement)
  fireEvent.click(screen.getByRole("button", { name: "Create the grid" }))
  await waitFor(() => expect(onCreate).toHaveBeenCalledTimes(1))
  const creation = onCreate.mock.calls[0]?.[0] as { accepted: string[] }
  expect(creation.accepted).toEqual(["public-link"])
})

it("says a research grid is alone in its grid, and offers nothing a company grid has", () => {
  open()
  fireEvent.click(screen.getByRole("checkbox", { name: /Serving models/ }))
  fireEvent.click(screen.getByRole("checkbox", { name: /Authorised research/ }))
  expect(asking()).toContain("Research gets a grid of its own")
  expect(screen.getByRole("checkbox", { name: /Serving models/ })).not.toBeChecked()
  expect(screen.getByRole("checkbox", { name: /Authorised research/ })).toBeChecked()
})
