import { run } from "@/api/platform-api"
export interface PublishedModel {
  id: string; ref: string; name: string; description: string; license: string; visibility: "public" | "private" | "api-only"; owned: boolean; canHost: boolean; canDownload: boolean
  price: { input: number; output: number } | null; royaltyPercent: number
  downloads?: number
  version: { id: string; label: string; source: string; delivery?: string; sourceOnly?: boolean; inferenceAvailable?: boolean; quant: string | null } | null
}
const desktop = () => { throw new Error("Open Yougori Desktop to publish models") }
export const registryApi = {
  request: <T,>(path: string, body?: unknown) => run<T>("model_registry_request", { path, body: body ?? null }, desktop),
  list: (mine = false) => registryApi.request<{ models: PublishedModel[]; storage: { configured: boolean } }>(`/models${mine ? "?mine=1" : ""}`),
  upload: (modelId: string, folder: string, label: string, quant?: string, resume?: string) => run("model_registry_upload", { modelId, folder, label, quant, resume }, desktop),
  connect: (model: string, endpoint: string, apiKey: string) => run("model_registry_connect", { model, endpoint, apiKey }, desktop),
  pause: () => run<void>("model_registry_pause", {}, desktop),
  download: (model: string, output: string) => run("model_registry_download", { model, output }, desktop),
  folder: async () => {
    const { open } = await import("@tauri-apps/plugin-dialog")
    const path = await open({ directory: true, multiple: false, title: "Choose model folder" })
    return typeof path === "string" ? path : null
  },
}
