// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it, vi } from "vitest"

vi.mock("@/api/workspace-api", () => ({ workspaceApi: { openUrl: vi.fn(() => Promise.resolve()) } }))

import { HubReadme } from "./hub-readme"

afterEach(cleanup)

it("reads headings with closing hashes, keeps C# and leaves other lines as text", () => {
  render(<HubReadme text={"## Install ##\n\n# Learn C#\n\n###### deep\n\n#hashtag\n\n####### seven"} />)
  const readme = screen.getByRole("article", { name: "README" })
  expect([...readme.querySelectorAll("h2, h3, h4")].map(node => `${node.tagName}:${node.textContent}`)).toEqual(["H3:Install", "H2:Learn C#", "H4:deep"])
  expect([...readme.querySelectorAll("p")].map(node => node.textContent)).toEqual(["#hashtag", "####### seven"])
})

it("renders hostile lines from a published README without stalling", () => {
  const hostile = [
    `# a${" ".repeat(200_000)}b`,
    "[".repeat(200_000),
    "[a](".repeat(50_000),
    `https://${".".repeat(100_000)}`,
    `**${"a".repeat(100_000)}`,
    "`".repeat(100_000),
    // Under the length where formatting stops, so the bounded patterns themselves are timed.
    `# a${" ".repeat(19_000)}b`,
    "[".repeat(19_900),
    "[a](".repeat(4_900),
    `see https://${"a.".repeat(9_000)}`,
    "**a ".repeat(4_900),
  ].join("\n\n")
  const started = performance.now()
  render(<HubReadme text={hostile} />)
  expect(performance.now() - started).toBeLessThan(5_000)
  expect(screen.getByRole("article", { name: "README" })).toBeInTheDocument()
})

it("keeps links, code, bold and the image placeholder", () => {
  render(<HubReadme text={"Read [the guide](https://example.com/guide) and run `yougori run`, **carefully**. ![Verified](https://x.example/b.svg) [local](file:///etc/passwd)"} />)
  const readme = screen.getByRole("article", { name: "README" })
  expect(screen.getByRole("button", { name: "the guide" })).toHaveAttribute("title", "https://example.com/guide")
  expect(readme.querySelector("code")).toHaveTextContent("yougori run")
  expect(readme.querySelector("strong")).toHaveTextContent("carefully")
  expect(readme).toHaveTextContent("[image: Verified]")
  expect(readme.querySelector("img")).toBeNull()
  expect(screen.queryByRole("button", { name: "local" })).toBeNull()
})
