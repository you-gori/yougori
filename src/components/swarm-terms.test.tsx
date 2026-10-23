// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { readFileSync } from "node:fs"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it } from "vitest"
import { Terms } from "./swarm-terms"

afterEach(() => cleanup())

it("reads somebody else's terms as words rather than as the shape they arrived in", () => {
  render(<Terms value={{
    setupCommand: "npm ci",
    install_network: true,
    in_scope: ["https://acme.test", "https://api.acme.test"],
    serviceRules: { version: 3, text: "No denial of service." },
    note: "",
    owner: null,
  }} />)
  expect(screen.getByText("Setup command")).toBeInTheDocument()
  expect(screen.getByText("npm ci")).toBeInTheDocument()
  expect(screen.getByText("Install network")).toBeInTheDocument()
  expect(screen.getByText("yes")).toBeInTheDocument()
  expect(screen.getByText("https://acme.test, https://api.acme.test")).toBeInTheDocument()
  expect(screen.getByText("Service rules")).toBeInTheDocument()
  expect(screen.getByText("Version: 3; Text: No denial of service.")).toBeInTheDocument()
  // Nothing that was not written is shown, and no brace, bracket or quote mark is.
  expect(screen.queryByText("Note")).not.toBeInTheDocument()
  expect(screen.queryByText("Owner")).not.toBeInTheDocument()
  expect(document.body.textContent).not.toMatch(/[{}[\]"]/)
})

it("says so plainly when there is nothing to show", () => {
  render(<Terms value={{}} />)
  expect(screen.getByText("Nothing was given here.")).toBeInTheDocument()
  cleanup()
  // A number is said as the number, not dropped and not quoted.
  render(<Terms value={{ port: 3000 }} />)
  expect(screen.getByText("3000")).toBeInTheDocument()
})

it("never dumps the words somebody agrees to, or a worker's findings, as machine shape", () => {
  // The accept dialog, the private bounty preview, the worker's reports and the host's reports
  // are the four places where somebody else's words are read by a person.
  for (const file of ["swarm-dialogs.tsx", "closed-bounty-dialog.tsx", "swarm-worker-detail.tsx", "private-bounty-host.tsx"]) {
    const source = readFileSync(`src/components/${file}`, "utf8")
    expect(source, file).not.toContain("JSON.stringify")
    expect(source, file).toContain("<Terms value=")
  }
  // And the project file list beside them is plain scrollable text, not a terminal frame.
  const css = readFileSync("src/components/swarm.css", "utf8")
  const rule = css.split("\n").find(line => line.startsWith(".swarm-file-list")) ?? ""
  expect(rule).not.toMatch(/background|border-radius|padding/)
})

it("shows nothing rather than failing when a publisher wrote no terms at all", () => {
  // A preview whose policy carries no target, which a real board answer can leave out.
  render(<Terms value={undefined} />)
  expect(screen.getByText("Nothing was given here.")).toBeInTheDocument()
  cleanup()
  render(<Terms value={null} />)
  expect(screen.getByText("Nothing was given here.")).toBeInTheDocument()
})
