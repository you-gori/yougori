import type { ModelStatus } from "@/api/projects-api"

export function modelProgress(status: ModelStatus): string {
  if (status.status === "downloading" && status.download?.totalBytes) {
    const { receivedBytes, totalBytes, bytesPerSecond } = status.download
    return `Downloading model weights · ${Math.min(100, 100 * receivedBytes / totalBytes).toFixed(1)}% · ${(receivedBytes / 1e9).toFixed(2)}/${(totalBytes / 1e9).toFixed(2)} GB · ${(bytesPerSecond / 1e6).toFixed(1)} MB/s`
  }
  if (status.status === "verifying") {
    const progress = status.verification
    return `Verifying model weights${progress?.totalBytes ? ` · ${Math.min(100, 100 * progress.checkedBytes / progress.totalBytes).toFixed(1)}%` : ""}`
  }
  return { idle: "On demand · model files cached", queued: "Waiting for GPU", freeing_memory: "Preparing GPU memory", unloading: "Releasing GPU memory", installing: "Installing model dependencies", downloading: "Downloading model weights", loading: "Loading model into GPU memory", ready: "Model ready", error: status.error ?? "Model setup failed" }[status.status]
}
