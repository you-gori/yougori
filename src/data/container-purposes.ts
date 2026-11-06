import { ociImages, ociRegistryLabel, type OciImageOption } from "@/data/oci-images"

// These are base-image shortcuts, not preinstalled projects or multi-service stacks.
export const containerPurposes = [
  {
    id: "website", label: "Website", image: "docker.io/library/node:lts-slim",
    description: "Node.js for building a frontend with tools such as React, Vue, or Vite.",
    keywords: "frontend javascript typescript react vue vite angular svelte",
  },
  {
    id: "saas", label: "SaaS", image: "docker.io/library/node:lts-slim",
    description: "Node.js on Debian for a full-stack app. Add your framework and connect a separate database as needed.",
    keywords: "fullstack full-stack next nextjs next.js nuxt subscription dashboard",
  },
  {
    id: "api", label: "API", image: "docker.io/library/python:slim",
    description: "Python on Debian for a backend. Add tools such as FastAPI, Flask, or Django.",
    keywords: "backend rest fastapi flask django server",
  },
  {
    id: "automation", label: "Automation", image: "docker.io/library/python:slim",
    description: "A compact Python workspace for scripts, bots, and background jobs.",
    keywords: "script scripting bot jobs task automation python",
  },
] as const

export type ContainerPurpose = typeof containerPurposes[number]

export function containerPurposeImage(purpose: ContainerPurpose): OciImageOption {
  const image = ociImages.find(image => image.value === purpose.image)
  if (!image) throw new Error(`Missing image for ${purpose.label}`)
  return image
}

// Precompute once; searching never contacts a registry or downloads an image.
const imageSearchText = new Map(ociImages.map(image => [image.value, [
  image.label, image.value, image.description, image.category, ociRegistryLabel(image.value),
  ...containerPurposes.filter(purpose => purpose.image === image.value)
    .map(purpose => `${purpose.label} ${purpose.keywords}`),
].join(" ").toLowerCase()]))

export function matchesOciImage(image: OciImageOption, query: string): boolean {
  const text = imageSearchText.get(image.value) ?? `${image.label} ${image.value}`.toLowerCase()
  return query.trim().toLowerCase().split(/\s+/).every(term => text.includes(term))
}
