import { describe, expect, it } from "vitest"
import { extractTerminalLinks, isLocalTerminalLink, mergeTerminalLinks, normalizeTerminalLink, terminalLinkRanges } from "./terminal-links"

describe("terminal links", () => {
  it("finds URLs in colored output, strips prose punctuation and deduplicates", () => {
    expect(extractTerminalLinks("Local: \x1b[36mhttp://localhost:5173/\x1b[0m\nSee (https://example.com/path_(one)). https://example.com/path_(one) www.example.org")).toEqual([
      "http://localhost:5173/", "https://example.com/path_(one)", "https://www.example.org/",
    ])
  })
  it("reports on-screen ranges without trailing prose punctuation", () => {
    const line = "Open (https://x.com). or https://example.com/a.)"
    expect(terminalLinkRanges(line)).toEqual([
      { url: "https://x.com/", start: 6, length: "https://x.com".length },
      { url: "https://example.com/a", start: 25, length: "https://example.com/a".length },
    ])
  })
  it("preserves query strings, fragments and IPv6", () => {
    expect(extractTerminalLinks('https://example.com/login?code=a%2Fb&x=2#next http://[::1]:3000/')).toEqual([
      'https://example.com/login?code=a%2Fb&x=2#next', 'http://[::1]:3000/',
    ])
  })
  it("never produces executable, file, credential-bearing or oversized links", () => {
    for (const url of ["javascript:alert(1)", "file:///C:/private", "https://user:password@example.com/", `https://example.com/${"a".repeat(2048)}`, "not a URL"]) expect(normalizeTerminalLink(url)).toBeNull()
  })
  it("keeps bounded history and reuses unchanged arrays", () => {
    const previous = ["https://example.com/"]
    expect(mergeTerminalLinks(previous, previous)).toBe(previous)
    expect(mergeTerminalLinks(previous, Array.from({ length: 12 }, (_, i) => `https://example.com/${i}`))).toHaveLength(8)
  })
  it("identifies links that a phone cannot use as-is", () => {
    for (const url of ["http://localhost:3000", "http://127.0.0.2", "http://[::1]", "http://0.0.0.0", "http://app.localhost"]) expect(isLocalTerminalLink(url)).toBe(true)
    expect(isLocalTerminalLink("https://example.com")).toBe(false)
  })
})
