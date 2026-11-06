export interface OciImageOption {
  value: string
  label: string
  description: string
  builtin?: boolean
  badge?: string
  displayReference?: string
  disabled?: boolean
  category: "Operating systems" | "Languages" | "Web servers" | "Data services" | "Developer tools"
}

export interface OciImageGroup {
  value: OciImageOption["category"]
  items: OciImageOption[]
}

export const customOciImage: OciImageOption = {
  value: "__custom__",
  label: "Custom image",
  description: "Enter any OCI-compatible registry reference",
  category: "Developer tools",
}

// Keep the starter catalogue small; other images remain available through Custom image.
export const ociImages: OciImageOption[] = [
  { category: "Operating systems", label: "Alpine 3.24 (Yougori default)", value: "docker.io/library/alpine:3.24", description: "Lightweight Linux for small sandboxes" },
  { category: "Operating systems", label: "Ubuntu", value: "docker.io/library/ubuntu:latest", description: "General-purpose Linux with a familiar package ecosystem" },
  { category: "Operating systems", label: "Debian", value: "docker.io/library/debian:stable-slim", description: "Compact Debian base for services and development" },
  { category: "Languages", label: "Node.js", value: "docker.io/library/node:lts-slim", description: "Node.js LTS on Debian for JavaScript and TypeScript apps" },
  { category: "Languages", label: "Python", value: "docker.io/library/python:slim", description: "Python on Debian for APIs, automation, and scripts" },
]

const categoryOrder: OciImageOption["category"][] = ["Operating systems", "Languages"]

export const ociImageGroups: OciImageGroup[] = categoryOrder.map((value) => ({
  value,
  items: ociImages.filter((image) => image.category === value),
}))

export const defaultOciImage = ociImages[0]!

export function ociStartupCommand(image: OciImageOption): string {
  return image.category === "Operating systems" || image.category === "Languages"
    ? "sleep 2147483647"
    : ""
}

export function ociRegistryLabel(reference: string): string {
  const host = reference.split("/", 1)[0] ?? reference
  return ({
    "docker.io": "Docker Hub",
    "ghcr.io": "GitHub",
    "mcr.microsoft.com": "Microsoft",
    "public.ecr.aws": "Amazon ECR",
    "quay.io": "Quay",
    "registry.access.redhat.com": "Red Hat",
  } as Record<string, string>)[host] ?? host
}
