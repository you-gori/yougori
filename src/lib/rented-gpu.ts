/** Rented NeoCloud GPUs as Swarm Mining shows them: prices, what each pod is doing, and where a
 *  worker's model runs. Plain helpers, shared by the Swarm page and the closed bounty dialog. */
import type { SwarmRentedWorker } from "@/api/swarm-api"

export const price = (usd: number | null | undefined) => usd ? `$${usd.toFixed(2)}/h` : "price unknown"
/** What running pods cost together. A pod with no recorded price makes the sum a floor, never a total. */
export const together = (usd: number, unpriced = 0) => !unpriced ? price(usd) : usd ? `at least ${price(usd)}` : "price unknown"
export const gpuText = (pod: { gpu: string | null; gpuCount: number | null; name?: string | null }) =>
  pod.gpu ? `${pod.gpuCount && pod.gpuCount > 1 ? `${pod.gpuCount} × ` : ""}${pod.gpu}` : pod.name ?? "GPU"
export const withoutPrefix = (value: string) => value.trimStart().replace(/^(https?:\/\/)?(www\.)?(hf\.co|huggingface\.co)\//i, "")

/** Safetensors models from the families that call tools on a rented GPU, uncensored so they do
 *  not refuse security work, with the GPU memory each needs. */
export const RENTED_MODELS = [
  { id: "mlabonne/Qwen3-8B-abliterated", label: "Qwen3 8B", note: "24 GB GPU" },
  { id: "mlabonne/Meta-Llama-3.1-8B-Instruct-abliterated", label: "Llama 3.1 8B", note: "24 GB GPU" },
  { id: "mlabonne/Qwen3-14B-abliterated", label: "Qwen3 14B", note: "48 GB GPU" },
  { id: "mlabonne/Qwen3-30B-A3B-abliterated", label: "Qwen3 30B", note: "80 GB GPU" },
]

/** Where a worker's model runs: this computer, or a NeoCloud pod the person already rented. */
export interface Placement { pod: string; model: string }

/** What still stops a worker on a rented GPU from being created, or nothing. */
export function placementProblem(value: Placement | null): string {
  if (!value) return ""
  if (!value.pod) return "Choose a running rented GPU, or run the model on this computer."
  if (!value.model.trim()) return "Choose the model it runs."
  return ""
}

/** The worker's model on a rented GPU, as the worker request carries it. */
export const placementSetup = (value: Placement) => ({ model: `hf.co/${withoutPrefix(value.model).trim()}`, rentedGpu: value.pod })

/** What a worker's rented GPU is doing, in a sentence: a stopped or failed pod never reads as
 *  working, and a paused worker's pod that still runs says it is still billed. */
export function rentedLine(worker: SwarmRentedWorker): string {
  if (worker.podState === "Deleted" || !worker.name) return "Its rented GPU no longer exists in NeoCloud. Remove this worker, or create one with another GPU."
  const gpu = `${worker.name} · ${gpuText(worker)}`
  if (worker.podState === "Stopping") return `${gpu} is stopping in NeoCloud.`
  if (!worker.billing) return `${gpu} is ${worker.podState} in NeoCloud and not billed. Start it there, then choose Resume. Yougori never rents or starts a GPU for you.`
  if (worker.workerState === "paused") return `${gpu} still runs while ${worker.workerName} is paused, and is billed at ${price(worker.hourlyUsd)}. Stop it if you are done for now.`
  if (worker.workerState === "stopped" || worker.workerState === "failed") return `${gpu} is being stopped, so it is no longer billed once NeoCloud confirms.`
  return `${gpu} · ${price(worker.hourlyUsd)} · ${worker.podState === "Running" ? "running" : "starting"}`
}

