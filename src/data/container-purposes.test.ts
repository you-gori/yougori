import { describe, expect, it } from "vitest"
import { containerPurposes, containerPurposeImage, matchesOciImage } from "@/data/container-purposes"
import { customOciImage, ociImages, ociStartupCommand } from "@/data/oci-images"

describe("container purposes", () => {
  it("maps every purpose to a real curated image with its existing startup behavior", () => {
    expect(new Set(containerPurposes.map(purpose => purpose.id)).size).toBe(containerPurposes.length)
    for (const purpose of containerPurposes) {
      const image = containerPurposeImage(purpose)
      expect(ociImages).toContain(image)
      expect(image).not.toBe(customOciImage)
      expect(matchesOciImage(image, purpose.label)).toBe(true)
      expect(ociStartupCommand(image)).toBe("sleep 2147483647")
    }
  })

  it("searches names, references, registries, categories, and purpose keywords", () => {
    const search = (query: string) => ociImages.filter(image => matchesOciImage(image, query)).map(image => image.value)
    expect(search("  PYthon  ")).toContain("docker.io/library/python:slim")
    expect(search("node  docker hub")).toEqual(["docker.io/library/node:lts-slim"])
    expect(search("next.js")).toContain("docker.io/library/node:lts-slim")
    expect(search("react website")).toContain("docker.io/library/node:lts-slim")
    expect(search("fastapi")).toContain("docker.io/library/python:slim")
    expect(search("automation")).toContain("docker.io/library/python:slim")
    expect(search("relational database")).toEqual([])
    expect(search("operating systems")).toHaveLength(3)
  })

  it("handles blank queries and no matches without losing the custom option", () => {
    expect(ociImages.filter(image => matchesOciImage(image, " \t "))).toEqual(ociImages)
    expect(ociImages.filter(image => matchesOciImage(image, "nonexistent-test-image-xyz"))).toEqual([])
    expect(matchesOciImage(customOciImage, "custom")).toBe(true)
  })
})
