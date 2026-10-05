import { run } from "@/api/platform-api"
const desktop = () => { throw new Error("Open Yougori Desktop to use project files and local workloads") }
export interface ProjectPreview {
  path: string
  project?: string
  error?: string
  environments?: { name: string; type: string; image: string; cpu: number; memoryGb: number; gpu: boolean; pcAccess: number; editPc: boolean; variables: string[]; action: string }[]
  connections?: number
  publications?: number
  notice?: string
  generated?: boolean
}
export interface ReadinessStage { status: string; detail?: string; httpStatus?: number; expectedStatus?: number; checks?: { publicationId: string; url: string; probe: ReadinessStage }[] }
export interface EnvironmentReadiness { environmentId: string; ready: boolean; level: string; applicationVerified?: boolean; verifiedPublicly?: boolean; stages?: Record<string, ReadinessStage>; error?: string; recoveryAction?: string | null }
export interface DeploymentReadiness { project: string; status: string; ready: boolean; saved: boolean; environments: Record<string, EnvironmentReadiness> }
export interface ProjectActionResult { project: string; status: string; ready?: boolean; readiness?: DeploymentReadiness }
export const projectsApi = {
  discover: () => run<ProjectPreview[]>("discover_projects", {}, () => []),
  inspect: (path: string) => run<ProjectPreview>("inspect_project", { path }, desktop),
  importCompose: (path: string, write: boolean) => run<ProjectPreview>("import_compose", { path, write }, desktop),
  action: (path: string, action: "up" | "apply" | "down") => run<ProjectActionResult>("project_action", { path, action }, desktop),
  status: (path: string) => run<DeploymentReadiness>("deployment_status", { path }, desktop),
  choose: async () => {
    const { open } = await import("@tauri-apps/plugin-dialog")
    const path = await open({ title: "Open Yougori or Docker Compose project", multiple: false, filters: [{ name: "Project YAML", extensions: ["yaml", "yml"] }] })
    return typeof path === "string" ? path : null
  },
}
export interface FileChange { folder: string; path: string; kind: "modified" | "created" | "deleted" | "renamed"; from?: string; beforeBytes: number | null; afterBytes: number | null; diff: string | null; beforeHash?: string; afterHash?: string }
export interface FieldChange { name: string; kind?: string; before: unknown; after: unknown }
export interface ChangeReport {
  available: boolean; totalFiles?: number; offset?: number; nextOffset?: number | null; baselineAt?: string; baselineCreated?: boolean; notice?: string; warnings?: string[]
  summary?: { modified: number; created: number; deleted: number; renamed: number; variables: number; packagesInstalled: number; packagesChanged: number; configuration: number }
  files?: FileChange[]; variables?: FieldChange[]; packages?: FieldChange[]; configuration?: FieldChange[]
}
export const changesApi = { inspect: (environmentId: string, baseline = false, offset = 0) => run<ChangeReport>("environment_changes", { environmentId, baseline, offset }, desktop) }
/** context and stream are reported by models started with streaming support. */
export interface ModelStatus { status: "installing" | "downloading" | "loading" | "ready" | "error"; model: string; error: string | null; gpu?: string; context?: number; stream?: boolean }
export interface ModelRun { id: string; model: string; apiUrl?: string; apiKey?: string }
export interface ModelPreflight { format?: string; quant?: string; files?: { rfilename: string; size: number; sha256?: string }[]; model: string; task: string; modelType: string; supported: boolean; reason: string; runner: string; revision: string; resources: { storageGbRecommended: number | null; gpuMemoryGbEstimated: number | null; estimateOnly: boolean }; downloads: { location: string; checksumVerification: string; hostWeightImportRequired: boolean } }
/** Key plus any localhost and public (Cloudflare) addresses currently serving the model API. */
export interface ModelApiAccess { id: string; model: string; apiKey: string; apiUrl: string | null; publicUrl: string | null; publicId: string | null; publicAccount: boolean }
export interface UsageCounters { requests: number; prompt_tokens: number; completion_tokens: number; errors: number; rejected: number; yougori?: number; api?: number }
export type UsageOutcome = "ok" | "cancelled" | "busy" | "invalid" | "error" | "rejected"
export interface UsageRequest { time: number; source: "yougori" | "api"; outcome: UsageOutcome; prompt_tokens: number; completion_tokens: number; seconds: number; stream: boolean }
/** Recorded by the model server; `hours` is keyed by Unix hour. Prompts are never stored. */
export interface ModelUsage { since: number; totals: UsageCounters; hours: Record<string, UsageCounters>; recent: UsageRequest[] }
export interface ChatMessage { role: "system" | "user" | "assistant"; content: string }
export interface ChatOptions { maxTokens: number; temperature: number }
export interface ChatUsage { prompt_tokens: number; completion_tokens: number; total_tokens: number; truncated_messages?: number; context_window?: number }
export interface ChatReply { finishReason: "stop" | "length" | "cancelled"; usage?: ChatUsage }
export const modelsApi = {
  preflight: (model: string, quant?: string) => run<ModelPreflight>("model_preflight", { model, quant }, desktop),
  api: (environmentId: string, port: number) => run<ModelRun>("model_api", { environmentId, port }, desktop),
  run: (model: string, port: number | null, quant?: string) => run<ModelRun>("run_model", { model, port, quant }, desktop),
  status: (environmentId: string) => run<ModelStatus>("model_status", { environmentId }, desktop),
  /** Conversations and chat settings shared with the CLI; null when none are saved. */
  history: (environmentId: string) => run<unknown>("model_chat_history", { environmentId }, () => JSON.parse(localStorage.getItem(`yougori.model-chat.v1:${environmentId}`) ?? "null")),
  saveHistory: (environmentId: string, history: unknown) => run<void>("save_model_chat_history", { environmentId, history }, () => { localStorage.setItem(`yougori.model-chat.v1:${environmentId}`, JSON.stringify(history)) }),
  access: (environmentId: string) => run<ModelApiAccess>("model_api_status", { environmentId }, desktop),
  usage: (environmentId: string, reset = false) => run<ModelUsage>("model_usage", { environmentId, reset }, desktop),
  chat: (environmentId: string, messages: ChatMessage[], options?: ChatOptions) => run<{ choices: { message: { content: string }; finish_reason?: string }[]; usage?: ChatUsage }>("model_chat", { environmentId, messages, ...options }, desktop),
  /** Streams reply text to onDelta; aborting the signal stops generation on the GPU. */
  stream: async (environmentId: string, messages: ChatMessage[], options: ChatOptions, onDelta: (text: string) => void, signal: AbortSignal) => {
    const { Channel, invoke, isTauri } = await import("@tauri-apps/api/core")
    if (!isTauri()) return desktop()
    const requestId = crypto.randomUUID()
    const onEvent = new Channel<{ delta: string }>()
    onEvent.onmessage = event => { if (!signal.aborted) onDelta(event.delta) }
    const cancel = () => void invoke("model_chat_cancel", { requestId }).catch(() => undefined)
    signal.addEventListener("abort", cancel, { once: true })
    try { return await invoke<ChatReply>("model_chat_stream", { environmentId, requestId, messages, ...options, onEvent }) }
    finally { signal.removeEventListener("abort", cancel) }
  },
}
