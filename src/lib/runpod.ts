import type { RunpodGpu } from "@/api/runpod-api"

export const validName = (name: string) => /^[A-Za-z0-9_-]{2,40}$/.test(name)
/** A name RunPod and Yougori both accept, made from readable parts. */
export function suggestName(parts: string[], taken: string[]): string {
  const base = parts.join("-").toLowerCase().replace(/[^a-z0-9_-]+/g, "-").replace(/-+/g, "-").replace(/^-|-$/g, "").slice(0, 34) || "runpod"
  const used = new Set(taken.map(t => t.toLowerCase()))
  for (let n = 1; n < 100; n++) {
    const name = n === 1 ? base : `${base}-${n}`
    if (!used.has(name)) return name
  }
  return `${base}-${Date.now() % 10000}`
}

/** The price of `gpu` on the chosen cloud, per GPU per hour. */
export const gpuPrice = (gpu: RunpodGpu, cloud: "secure" | "community") => cloud === "secure" ? gpu.securePrice : gpu.communityPrice

/** RunPod's serverless GPU groups in plain words. */
export const gpuPools: Record<string, string> = {
  AMPERE_16: "16 GB (A4000, A4500, RTX 4000)",
  AMPERE_24: "24 GB (L4, A5000, RTX 3090)",
  ADA_24: "24 GB Pro (RTX 4090)",
  ADA_32_PRO: "32 GB (RTX 5090)",
  AMPERE_48: "48 GB (A6000, A40)",
  ADA_48_PRO: "48 GB Pro (L40, L40S, RTX 6000 Ada)",
  AMPERE_80: "80 GB (A100)",
  ADA_80_PRO: "80 GB Pro (H100)",
  HOPPER_141: "141 GB (H200)",
  BLACKWELL_96: "96 GB (RTX PRO 6000)",
  BLACKWELL_180: "180 GB (B200)",
}

/** Template names without the provider's prefix: "Runpod Pytorch 2.8.0" reads "PyTorch 2.8.0". */
export const templateName = (name: string) => name.replace(/^runpod\s+/i, "").replace(/^pytorch/i, "PyTorch")

/** Templates most people want first, then official, your own, and community ones. */
const preferred = ["runpod-torch-v280", "cw3nka7d08", "runpod-ubuntu-2404", "runpod-ubuntu-2204", "wgd3p4n4o6"]
export function templateRank(t: { id: string; official: boolean; own: boolean }): number {
  const at = preferred.indexOf(t.id)
  return at >= 0 ? at : t.own ? 20 : t.official ? 30 : 40
}

/** Stock as a 0–3 meter level. */
export const stockLevel = (stock: string, available = true): 0 | 1 | 2 | 3 => !available ? 0 : stock === "high" ? 3 : stock === "medium" ? 2 : 1

/** GPU memory tiers used to group the GPU list. */
export const vramTiers = [
  { min: 0, max: 17, title: "Entry · up to 16 GB" },
  { min: 17, max: 33, title: "Mainstream · 20–32 GB" },
  { min: 33, max: 64, title: "Professional · 40–48 GB" },
  { min: 64, max: Infinity, title: "Data centre · 80 GB and more" },
] as const
