import { describe, expect, it } from "vitest"
import { customOciImage, defaultOciImage, ociImageGroups, ociImages, ociRegistryLabel, ociStartupCommand } from "@/data/oci-images"

describe("OCI image catalog", () => {
  it("starts services with their image defaults instead of replacing them with sleep", () => {
    for (const image of ociImages) {
      expect(ociStartupCommand(image)).toBe(image.category === "Operating systems" || image.category === "Languages" ? "sleep 2147483647" : "")
    }
  })
  it("offers exactly five unique starter images without empty groups", () => {
    const references = ociImages.map((image) => image.value)
    expect(ociImages).toHaveLength(5)
    expect(ociImages.map(image => image.label)).toEqual(["Alpine 3.24 (Yougori default)", "Ubuntu", "Debian", "Node.js", "Python"])
    expect(new Set(references).size).toBe(references.length)
    expect(ociImageGroups.flatMap((group) => group.items)).toEqual(ociImages)
    expect(ociImageGroups.every(group => group.items.length > 0)).toBe(true)
  })

  it("keeps a runnable default and custom escape hatch", () => {
    expect(defaultOciImage.value).toBe("docker.io/library/alpine:3.24")
    expect(ociImages).not.toContain(customOciImage)
    expect(customOciImage.value).toBe("__custom__")
  })

  it("identifies registries for both presets and custom references", () => {
    expect(ociRegistryLabel(defaultOciImage.value)).toBe("Docker Hub")
    expect(ociRegistryLabel("ghcr.io/example/custom:latest")).toBe("GitHub")
    expect(ociRegistryLabel("images.example/app:latest")).toBe("images.example")
  })
})
