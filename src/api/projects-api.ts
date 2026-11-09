import { run } from "@/api/platform-api"
const desktop = () => { throw new Error("Open Yougori Desktop to use project files and local workloads") }
export interface FileChange { folder: string; path: string; kind: "modified" | "created" | "deleted" | "renamed"; from?: string; beforeBytes: number | null; afterBytes: number | null; diff: string | null; beforeHash?: string; afterHash?: string }
export interface FieldChange { name: string; kind?: string; before: unknown; after: unknown }
export interface ChangeReport {
  available: boolean; totalFiles?: number; offset?: number; nextOffset?: number | null; baselineAt?: string; baselineCreated?: boolean; notice?: string; warnings?: string[]
  summary?: { modified: number; created: number; deleted: number; renamed: number; variables: number; packagesInstalled: number; packagesChanged: number; configuration: number }
  files?: FileChange[]; variables?: FieldChange[]; packages?: FieldChange[]; configuration?: FieldChange[]
}
export const changesApi = { inspect: (environmentId: string, baseline = false, offset = 0) => run<ChangeReport>("environment_changes", { environmentId, baseline, offset }, desktop) }
/** context and stream are reported by models started with streaming support. */
export interface GpuOptimizer {
  releaseUncertain?: boolean
  supported: boolean; enabled: boolean; pinned: boolean; resident: boolean; loading: boolean; active: number; pending: number; idleTimeoutSeconds: number; allocatedBytes: number | null
  /** Observations from the runner (never admission decisions): segments its allocator still holds, and the most it held at once since its last unload. */
  reservedBytes?: number | null; peakAllocatedBytes?: number | null
  /** The shared GPU grant this model holds itself to under host-ledger admission: its bytes and the context it covers, in tokens. Absent on the one-resident scheduler. */
  capacityBytes?: number | null; capacityContext?: number | null
  /** While this model waits for the GPU (queued, or preparing GPU memory after a refused switch): which model holds it, and what to do about that. */
  waitingFor?: string
}
/** What the runner's launch does or does not support, as the runner reports it: the launch's own fact, not host evidence. */
export interface RunnerCapability { supported: boolean; detail: string }
/** How a model folder reached its workload: through the engine's catalog (published once, leased, served from a read-only view), or the folder itself. */
export interface ModelCatalogOutcome { state: "catalog" | "not_configured" | "source_only" | string; execution?: string; model?: string; view?: string; files?: number; bytes?: number; copied?: boolean; reused?: boolean; remedy?: string; detail?: string }
/** How the runner's helpers are served, as the helper rollout journal recorded the start (source injection in this build). */
export interface ModelHelpersOutcome { state: "recorded" | "unchanged" | "skipped" | "not_recorded" | string; loader?: string; helpers?: { helper: string; runner: string; serve: string | { bundle: string }; shadow: string | null }[]; detail?: string }
/** The profile and the bytes host admission reserves for a model (the engine's, read from its saved workload). */
export interface ModelAdmission { profile: string; bytes: number }
export interface ModelStatus { optimizer?: GpuOptimizer; admission?: ModelAdmission; capabilities?: Record<string, RunnerCapability>; sourceOnly?: boolean; inferenceAvailable?: boolean; status: "installing" | "downloading" | "verifying" | "loading" | "ready" | "idle" | "queued" | "unloading" | "freeing_memory" | "error"; model: string; error: string | null; gpu?: string; context?: number; stream?: boolean; task?: string; api?: string; precision?: string; chatTemplate?: boolean; chatWarning?: string; chatModelSuggestion?: string; download?: { receivedBytes: number; totalBytes: number; bytesPerSecond: number; transport: string }; verification?: { checkedBytes: number; totalBytes: number }
  /** A media model: its pipeline class, the jobs waiting and running, what it keeps and how fast its last jobs went. */
  pipeline?: string; offload?: boolean; queue?: { waiting: number; running: number; limit: number }; outputs?: { keptHours: number; capGb: number; bytes: number; jobs: number }; speed?: { lastJobSeconds?: number; secondsPerImage?: number; secondsPerOutputSecond?: number } }
export type { MediaTask } from "@/lib/media-tasks"
/** What a media job takes; the image is a data URL. */
export interface MediaInput { prompt?: string; text?: string; negative_prompt?: string; width?: number; height?: number; steps?: number; guidance?: number; seed?: number; count?: number; seconds?: number; fps?: number; voice?: string; image?: string; strength?: number; format?: string }
export interface MediaFile { name: string; file: string; url: string; content_type: string; bytes: number; width?: number; height?: number; seconds?: number; fps?: number; frames?: number; sample_rate?: number; audio?: boolean }
import type { MediaTask } from "@/lib/media-tasks"
export interface MediaJob { id: string; object: "job"; status: "queued" | "running" | "succeeded" | "failed" | "cancelled"; task: MediaTask; model: string; created: number; started: number | null; finished: number | null; progress: number; position?: number; input: Omit<MediaInput, "image"> & { image?: { bytes: number } }; error: string | null; output: { files?: MediaFile[]; seed?: number; images?: MediaFile[]; video?: MediaFile; audio?: MediaFile } | null; usage: { images?: number; output_seconds?: number; compute_seconds?: number } | null; expires: number | null; notes?: string[] }
export interface MediaSaved { jobId: string; folder: string; files: { path: string; name: string; bytes: number; contentType: string }[] }
export interface ModelRun { id: string; model: string; sourceOnly?: boolean; apiUrl?: string; apiKey?: string; catalog?: ModelCatalogOutcome; helpers?: ModelHelpersOutcome }
export type ArchitectureAgent = "claude" | "codex" | "kilo" | "opencode" | "gemini"
export interface ArchitectureTask { path: string; skillPath: string; promptPath: string; agent: ArchitectureAgent; launchCommand: string; resumeCommand: string; model: string; revision: string; agentStarted: false }
export interface ModelPreflight { sourceOnly?: boolean; localCode?: boolean; inferenceAvailable?: boolean; supportAvailable?: boolean; architectures?: string[]; format?: string; quant?: string; files?: { rfilename: string; size: number; sha256?: string }[]; model: string; task: string; modelType: string; supported: boolean; reason: string; runner: string; revision: string; resources: { workerMemoryGbRecommended?: number; storageGbRecommended: number | null; gpuMemoryGbEstimated: number | null; estimateOnly: boolean }; downloads: { location: string; checksumVerification: string; hostWeightImportRequired: boolean } }
/** Key plus any localhost and public (Cloudflare) addresses currently serving the model API. */
export interface ModelApiAccess { id: string; model: string; apiKey: string; apiUrl: string | null; publicUrl: string | null; publicId: string | null; publicAccount: boolean }
/** Tokens for chat models; images and milliseconds of output and GPU time for media models. */
export interface UsageCounters { requests: number; prompt_tokens: number; completion_tokens: number; errors: number; rejected: number; yougori?: number; api?: number; images?: number; output_ms?: number; compute_ms?: number }
export type UsageOutcome = "ok" | "cancelled" | "busy" | "invalid" | "error" | "rejected"
export interface UsageRequest { time: number; source: "yougori" | "api"; outcome: UsageOutcome; prompt_tokens: number; completion_tokens: number; seconds: number; stream: boolean; images?: number; output_ms?: number; compute_ms?: number }
/** Recorded by the model server; `hours` is keyed by Unix hour. Prompts are never stored. */
export interface ModelUsage { listen?: { enabled: boolean; path: string; error?: string | null }; since: number; totals: UsageCounters; hours: Record<string, UsageCounters>; recent: UsageRequest[]; speedMetric?: "input_tokens" | "output_tokens" }
export interface ChatMessage { role: "system" | "user" | "assistant"; content: string }
export interface ChatOptions { maxTokens: number; temperature: number }
export interface ChatUsage { prompt_tokens: number; completion_tokens: number; total_tokens: number; truncated_messages?: number; context_window?: number }
export interface ChatReply { finishReason: "stop" | "length" | "cancelled"; usage?: ChatUsage }
export const modelsApi = {
  optimizer: (environmentId: string, settings?: { enabled?: boolean; pinned?: boolean; idleTimeoutSeconds?: number }) => settings ? run<GpuOptimizer>("model_optimizer", { environmentId, ...settings }, desktop) : run<ModelStatus>("model_status", { environmentId }, desktop).then(status => status.optimizer ?? null),
  supportTask: (model: string, agent: ArchitectureAgent, quant?: string) => run<ArchitectureTask>("model_support_task", { model, agent, quant }, desktop),
  huggingface: () => run<{ configured: boolean; reference: string; tokensUrl: string }>("model_huggingface_status", {}, desktop),
  saveHuggingfaceToken: (value: string) => run("set_deployment_secret", { name: "huggingface-model-downloads", value }, desktop),
  forgetHuggingfaceToken: () => run("delete_deployment_secret", { name: "huggingface-model-downloads" }, desktop),
  preflight: (model: string, quant?: string, folder?: string) => run<ModelPreflight>("model_preflight", { model, quant, folder }, desktop),
  api: (environmentId: string, port: number) => run<ModelRun>("model_api", { environmentId, port }, desktop),
  compute: () => run<{ backend: string; os: string; architecture: string; available: boolean; detail?: string }>("model_compute_status", {}, desktop),
  /** `adapter` and `runner` (hf:OWNER/REPO@COMMIT) are a media model's LoRA adapter and pipeline runner. */
  run: (model: string, port: number | null, quant?: string, folder?: string, backend?: string, memoryGb?: number, adapter?: string, runner?: string) => run<ModelRun>("run_model", { model, port, quant, folder, backend, memoryGb, resources: adapter ? { adapter } : undefined, runner }, desktop),
  runNeocloud: (model: string, environmentId: string, port: number | null, adapter?: string, runner?: string) => run<ModelRun>("run_neocloud_model", { model, environmentId, port, adapter, runner }, desktop),
  status: (environmentId: string) => run<ModelStatus>("model_status", { environmentId }, desktop),
  /** Conversations and chat settings shared with the CLI; null when none are saved. */
  history: (environmentId: string) => run<unknown>("model_chat_history", { environmentId }, () => JSON.parse(localStorage.getItem(`yougori.model-chat.v1:${environmentId}`) ?? "null")),
  saveHistory: (environmentId: string, history: unknown) => run<void>("save_model_chat_history", { environmentId, history }, () => { localStorage.setItem(`yougori.model-chat.v1:${environmentId}`, JSON.stringify(history)) }),
  access: (environmentId: string) => run<ModelApiAccess>("model_api_status", { environmentId }, desktop),
  usage: (environmentId: string, reset = false) => run<ModelUsage>("model_usage", { environmentId, reset }, desktop),
  /** One job for a media model, answered at once; follow it with job(). */
  generate: (environmentId: string, input: MediaInput) => run<MediaJob>("model_generate", { environmentId, input }, desktop),
  job: (environmentId: string, jobId: string, action: "status" | "result" | "cancel" = "status", wait = 0) => run<MediaJob>("model_job", { environmentId, jobId, action, wait }, desktop),
  jobs: (environmentId: string) => run<{ data: MediaJob[] }>("model_job", { environmentId, action: "list" }, desktop),
  saveJob: (environmentId: string, jobId: string, folder: string) => run<MediaSaved>("model_job_save", { environmentId, jobId, folder }, desktop),
  file: (environmentId: string, fileId: string) => run<{ fileId: string; contentType: string; bytes: number; base64: string }>("model_file", { environmentId, fileId }, desktop),
  keepOutputs: (environmentId: string, hours: number) => run<{ keepOutputsHours: number; applied: boolean }>("model_optimizer", { environmentId, keepOutputsHours: hours }, desktop),
  chat: (environmentId: string, messages: ChatMessage[], options?: ChatOptions) => run<{ choices: { message: { content: string }; finish_reason?: string }[]; usage?: ChatUsage }>("model_chat", { environmentId, messages, ...options }, desktop),
  /** Streams reply text to onDelta; aborting the signal stops generation on the GPU. */
  stream: async (environmentId: string, messages: ChatMessage[], options: ChatOptions, onDelta: (text: string) => void, signal: AbortSignal) => {
    const { Channel, invoke, isTauri } = await import("@tauri-apps/api/core")
    if (!isTauri()) return desktop()
    // A stop pressed while the module loaded must not start generation on the GPU.
    if (signal.aborted) return { finishReason: "cancelled" } satisfies ChatReply
    const requestId = crypto.randomUUID()
    const onEvent = new Channel<{ delta: string }>()
    onEvent.onmessage = event => { if (!signal.aborted) onDelta(event.delta) }
    const cancel = () => void invoke("model_chat_cancel", { requestId }).catch(() => undefined)
    signal.addEventListener("abort", cancel, { once: true })
    try { return await invoke<ChatReply>("model_chat_stream", { environmentId, requestId, messages, ...options, onEvent }) }
    finally { signal.removeEventListener("abort", cancel) }
  },
}
