import type { GridComputer, GridProgress } from "@/api/grid-api"

/** How a computer's state reads on the board: one plain sentence, a tone, and progress when it counts. */
export interface ComputerStatus {
  text: string
  tone: "ok" | "busy" | "wait" | "off" | "error"
  /** 0–1 while a phase counts bytes. */
  fraction?: number
}

const gb = (bytes: number) => (bytes / 1e9).toFixed(1)

/** A progress line such as "Downloading Qwen/Qwen3-8B · 3.2 of 16.0 GB · 45 MB/s". */
export function progressText(progress: GridProgress, model: string): string {
  const counted = progress.total > 0
  switch (progress.phase) {
    case "downloading":
      return counted
        ? `Downloading ${model} · ${gb(progress.done)} of ${gb(progress.total)} GB${progress.rate > 0 ? ` · ${Math.round(progress.rate / 1e6)} MB/s` : ""}`
        : `Downloading ${model}`
    case "verifying": return `Checking the downloaded files of ${model}`
    case "installing": return `Installing the runtime for ${model}`
    case "queued":
    case "freeing_memory": return `Waiting for GPU memory to load ${model}`
    case "preparing": return `Preparing ${model}`
    default: return `Loading ${model}`
  }
}

export function progressFraction(progress: GridProgress | null | undefined): number | undefined {
  if (!progress || progress.total <= 0 || !["downloading", "verifying"].includes(progress.phase)) return undefined
  return Math.min(1, Math.max(0, progress.done / progress.total))
}

/** What a computer is doing for the grid, in words a person understands without the docs. */
export function computerStatus(computer: GridComputer, planModel: string | undefined): ComputerStatus {
  if (computer.excluded) return { text: "Left out · gets no model and no work", tone: "off" }
  if (!computer.capable) return { text: "Can't run models (no supported GPU)", tone: "off" }
  if (!computer.online) return { text: planModel ? `Offline · will run ${planModel}` : "Offline", tone: "off" }
  const report = computer.models[0]
  if (!planModel) return { text: "Waiting for a model · assign one below", tone: "wait" }
  if (!report) return { text: `Starting ${planModel}`, tone: "wait" }
  const model = report.model || planModel
  if (report.progress) return { text: progressText(report.progress, model), tone: "wait", fraction: progressFraction(report.progress) }
  switch (report.state) {
    case "available": return { text: `Ready · serving ${model}`, tone: "ok" }
    case "busy": return { text: `Answering a request · ${model}`, tone: "busy" }
    case "person_active": return { text: `Paused while its person works · ${model}`, tone: "wait" }
    case "outside_schedule": return { text: `Outside its hours · ${model}`, tone: "wait" }
    case "activity_unknown": return { text: "Can't tell if someone is using it, so it doesn't serve", tone: "wait" }
    case "preparing": return { text: `Preparing ${model}`, tone: "wait" }
    case "loading": return { text: report.reason || `Loading ${model}`, tone: "wait" }
    case "stopped": return { text: report.reason || `${model} is stopped`, tone: "off" }
    case "locked": return { text: "Locked down on this computer", tone: "off" }
    case "error": return { text: report.reason || `Problem with ${model}`, tone: "error" }
    default: return { text: report.reason || model, tone: "wait" }
  }
}
