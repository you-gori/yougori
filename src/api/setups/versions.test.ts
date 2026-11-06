import { describe, expect, it } from "vitest"
import { isNewerVersion } from "./versions"

describe("isNewerVersion", () => {
  it("orders versions as semver does", () => {
    expect(isNewerVersion("1.0.1", "1.0.0")).toBe(true)
    expect(isNewerVersion("1.10.0", "1.9.9")).toBe(true)
    expect(isNewerVersion("2.0.0", "1.99.99")).toBe(true)
    expect(isNewerVersion("1.0.0", "1.0.0")).toBe(false)
    expect(isNewerVersion("1.0.0", "1.0.1")).toBe(false)
  })

  it("puts a release after its prereleases, and orders prereleases", () => {
    expect(isNewerVersion("1.0.0", "1.0.0-beta")).toBe(true)
    expect(isNewerVersion("1.0.0-beta", "1.0.0")).toBe(false)
    expect(isNewerVersion("1.0.0-beta.11", "1.0.0-beta.2")).toBe(true)
    expect(isNewerVersion("1.0.0-beta", "1.0.0-alpha")).toBe(true)
    expect(isNewerVersion("1.0.0-alpha.1", "1.0.0-alpha")).toBe(true)
    expect(isNewerVersion("1.0.0-alpha", "1.0.0-1")).toBe(true)
  })

  it("never calls something it can't read newer", () => {
    expect(isNewerVersion(null, "1.0.0")).toBe(false)
    expect(isNewerVersion("latest", "1.0.0")).toBe(false)
    expect(isNewerVersion("1.0", "0.9.0")).toBe(false)
    expect(isNewerVersion("2.0.0", undefined)).toBe(false)
  })
})
