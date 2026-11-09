import { useCallback, useEffect, useRef, useState } from "react"
import { modelsApi, type MediaFile, type MediaInput, type MediaJob, type ModelStatus } from "@/api/projects-api"
import { registryApi } from "@/api/model-registry-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { modelProgress } from "@/lib/model-progress"
import "@/components/model-workspace.css"

const SIZES = ["512x512", "768x768", "1024x1024", "1024x576", "576x1024", "1280x720", "720x1280"]
const KINDS: Record<string, string> = { "text-to-image": "images", "image-to-image": "images from an image", "text-to-video": "video", "image-to-video": "video from an image", "text-to-audio": "sound", "text-to-speech": "speech" }
const STATUS: Record<MediaJob["status"], string> = { queued: "Waiting", running: "Generating", succeeded: "Done", failed: "Failed", cancelled: "Stopped" }
const PREVIEW_LIMIT = 64 * 1024 * 1024
const number = (value: string) => value.trim() === "" ? undefined : Number(value)
const readDataUrl = (file: File) => new Promise<string>((resolve, reject) => { const reader = new FileReader(); reader.onload = () => resolve(String(reader.result)); reader.onerror = () => reject(reader.error); reader.readAsDataURL(file) })

/** The form and job list of a media model: a prompt in, images, video or sound out, each job
 * followed until it ends, its files shown here and saved to a folder on request. */
export function ModelGenerate({ environmentId, status }: { environmentId: string; status: ModelStatus }) {
  const task = status.task ?? "text-to-image"
  const images = task.endsWith("to-image")
  const video = task.endsWith("to-video")
  const speech = task === "text-to-speech"
  const needsImage = task.startsWith("image-to")
  const [prompt, setPrompt] = useState("")
  const [negative, setNegative] = useState("")
  const [size, setSize] = useState("")
  const [count, setCount] = useState("1")
  const [steps, setSteps] = useState("")
  const [guidance, setGuidance] = useState("")
  const [seed, setSeed] = useState("")
  const [seconds, setSeconds] = useState(video ? "2" : "5")
  const [fps, setFps] = useState("")
  const [voice, setVoice] = useState("")
  const [image, setImage] = useState<{ name: string; data: string } | null>(null)
  const [jobs, setJobs] = useState<MediaJob[]>([])
  const [files, setFiles] = useState<Record<string, string>>({})
  const [saved, setSaved] = useState<Record<string, string>>({})
  const [saving, setSaving] = useState<string | null>(null)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const alive = useRef(true)
  const refresh = useCallback(async () => {
    try { const list = await modelsApi.jobs(environmentId); if (alive.current) { setJobs(list.data); setError("") } }
    catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : String(reason)) }
  }, [environmentId])
  useEffect(() => { alive.current = true; if (status.status === "ready") void refresh(); return () => { alive.current = false } }, [refresh, status.status])
  const active = jobs.some(job => job.status === "queued" || job.status === "running")
  useEffect(() => {
    if (!active) return
    const timer = window.setInterval(() => void refresh(), 2000)
    return () => window.clearInterval(timer)
  }, [active, refresh])
  // Previews load once per file; files too large for the gallery are saved instead.
  useEffect(() => {
    for (const job of jobs) for (const file of job.output?.files ?? []) {
      if (files[file.file] !== undefined) continue
      if (file.bytes > PREVIEW_LIMIT) { setFiles(f => ({ ...f, [file.file]: "large" })); continue }
      setFiles(f => ({ ...f, [file.file]: "" }))
      void modelsApi.file(environmentId, file.file)
        .then(value => { if (alive.current) setFiles(f => ({ ...f, [file.file]: `data:${value.contentType};base64,${value.base64}` })) })
        .catch(() => { if (alive.current) setFiles(f => ({ ...f, [file.file]: "unavailable" })) })
    }
  }, [jobs, files, environmentId])

  const generate = async () => {
    const input: MediaInput = {}
    if (speech) input.text = prompt.trim(); else if (prompt.trim()) input.prompt = prompt.trim()
    if (negative.trim()) input.negative_prompt = negative.trim()
    if (size) { const [w, h] = size.split("x").map(Number); input.width = w; input.height = h }
    if (images && number(count) !== undefined) input.count = number(count)
    if (number(steps) !== undefined) input.steps = number(steps)
    if (number(guidance) !== undefined) input.guidance = number(guidance)
    if (number(seed) !== undefined) input.seed = number(seed)
    if ((video || task === "text-to-audio") && number(seconds) !== undefined) input.seconds = number(seconds)
    if (video && number(fps) !== undefined) input.fps = number(fps)
    if (speech && voice.trim()) input.voice = voice.trim()
    if (needsImage) { if (!image) { setError("Choose the input image first."); return } input.image = image.data }
    setBusy(true); setError("")
    try { await modelsApi.generate(environmentId, input); await refresh() }
    catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { if (alive.current) setBusy(false) }
  }
  const cancel = async (id: string) => {
    try { await modelsApi.job(environmentId, id, "cancel"); await refresh() }
    catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : String(reason)) }
  }
  const save = async (id: string) => {
    try {
      const folder = await registryApi.folder()
      if (!folder) return
      setSaving(id)
      const result = await modelsApi.saveJob(environmentId, id, folder)
      if (alive.current) setSaved(s => ({ ...s, [id]: result.folder }))
    } catch (reason) { if (alive.current) setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { if (alive.current) setSaving(null) }
  }
  const choose = async (file: File | undefined) => {
    if (!file) return
    if (file.size > 20 * 1024 * 1024) { setError("The input image is larger than 20 MiB."); return }
    try { setImage({ name: file.name, data: await readDataUrl(file) }); setError("") } catch { setError("The image could not be read.") }
  }
  const ready = status.status === "ready"
  const phase = ready ? null : modelProgress(status)

  return <section className="model-generate" aria-label="Generate">
    <form className="model-generate-form" onSubmit={event => { event.preventDefault(); void generate() }}>
      <div className="model-chat-bar"><span role="status"><strong>{status.model}</strong> · {KINDS[task] ?? task}{status.pipeline ? ` · ${status.pipeline}` : ""}{status.gpu ? ` · ${status.gpu}` : ""}{phase ? ` · ${phase}` : ""}</span></div>
      <div className="model-field">
        <label className="model-label" htmlFor="generate-prompt">{speech ? "Text" : needsImage && video ? "Prompt (optional)" : "Prompt"}</label>
        <textarea id="generate-prompt" rows={3} value={prompt} disabled={busy} onChange={event => setPrompt(event.target.value)} placeholder={speech ? "What should be said" : images ? "A red bicycle leaning on a white wall, morning light" : video ? "Waves rolling onto a beach at sunset" : "Rain on a tin roof"} />
      </div>
      {needsImage ? <div className="model-field">
        <label className="model-label" htmlFor="generate-image">Input image</label>
        <div className="model-input-row">
          <input id="generate-image" type="file" accept="image/png,image/jpeg,image/webp" disabled={busy} onChange={event => void choose(event.target.files?.[0])} />
          <span className="model-hint">{image ? image.name : "PNG, JPEG or WebP, up to 20 MiB"}</span>
        </div>
      </div> : null}
      {speech ? <div className="model-fields">
        <div className="model-field"><label className="model-label" htmlFor="generate-voice">Voice (optional)</label><Input id="generate-voice" value={voice} disabled={busy} placeholder="Model default" onChange={event => setVoice(event.target.value)} /></div>
      </div> : <>
        <div className="model-field">
          <label className="model-label" htmlFor="generate-negative">Avoid (optional)</label>
          <Input id="generate-negative" value={negative} disabled={busy} placeholder="blurry, text, watermark" onChange={event => setNegative(event.target.value)} />
        </div>
        <div className="model-fields">
          {images || video ? <div className="model-field"><label className="model-label" htmlFor="generate-size">Size</label>
            <select id="generate-size" className="model-select" value={size} disabled={busy} onChange={event => setSize(event.target.value)}><option value="">Model default</option>{SIZES.map(s => <option key={s} value={s}>{s}</option>)}</select></div> : null}
          {images ? <div className="model-field"><label className="model-label" htmlFor="generate-count">Images</label><Input id="generate-count" type="number" min={1} max={8} value={count} disabled={busy} onChange={event => setCount(event.target.value)} /></div> : null}
          {video || task === "text-to-audio" ? <div className="model-field"><label className="model-label" htmlFor="generate-seconds">Seconds</label><Input id="generate-seconds" type="number" min={0.5} max={60} step={0.5} value={seconds} disabled={busy} onChange={event => setSeconds(event.target.value)} /></div> : null}
          {video ? <div className="model-field"><label className="model-label" htmlFor="generate-fps">Frames per second</label><Input id="generate-fps" type="number" min={1} max={60} value={fps} disabled={busy} placeholder="Model default" onChange={event => setFps(event.target.value)} /></div> : null}
          <div className="model-field"><label className="model-label" htmlFor="generate-steps">Steps</label><Input id="generate-steps" type="number" min={1} max={200} value={steps} disabled={busy} placeholder="Model default" onChange={event => setSteps(event.target.value)} /></div>
          <div className="model-field"><label className="model-label" htmlFor="generate-guidance">Guidance</label><Input id="generate-guidance" type="number" min={0} max={50} step={0.5} value={guidance} disabled={busy} placeholder="Model default" onChange={event => setGuidance(event.target.value)} /></div>
          <div className="model-field"><label className="model-label" htmlFor="generate-seed">Seed</label><Input id="generate-seed" type="number" min={0} value={seed} disabled={busy} placeholder="Random" onChange={event => setSeed(event.target.value)} /></div>
        </div>
      </>}
      <div className="model-form-actions">
        <span className="model-hint">{status.queue ? `${status.queue.waiting} waiting · ${status.queue.running} generating` : ""}{status.outputs ? ` · files kept ${status.outputs.keptHours} h` : ""}</span>
        <Button type="submit" disabled={!ready || busy || (!prompt.trim() && !(needsImage && video))} loading={busy}>Generate</Button>
      </div>
      {error ? <p role="alert" className="model-error">{error}</p> : null}
    </form>

    <div className="model-generate-jobs" aria-label="Jobs">
      {jobs.length === 0 ? <p className="model-hint">{ready ? "No jobs yet. Describe what to make and press Generate." : "Jobs appear here once the model is ready."}</p> : null}
      {jobs.map(job => <article key={job.id} className="model-generate-job" data-status={job.status}>
        <header>
          <strong>{STATUS[job.status]}{job.status === "running" ? ` ${Math.round(job.progress * 100)}%` : job.status === "queued" && job.position ? ` · position ${job.position}` : ""}</strong>
          <span className="model-hint">{job.input.prompt ?? job.input.text ?? ""}</span>
          <span className="model-generate-job-actions">
            {job.status === "queued" || job.status === "running" ? <Button size="xs" variant="ghost" onClick={() => void cancel(job.id)}>Stop</Button> : null}
            {job.status === "succeeded" ? <Button size="xs" variant="outline" disabled={saving === job.id} loading={saving === job.id} onClick={() => void save(job.id)}>Save to folder</Button> : null}
          </span>
        </header>
        {job.status === "running" ? <progress max={1} value={job.progress} aria-label="Progress" /> : null}
        {job.error ? <p className="model-error">{job.error}</p> : null}
        {saved[job.id] ? <p className="model-hint">Saved in {saved[job.id]}</p> : null}
        {job.output?.files?.length ? <div className="model-generate-preview">{job.output.files.map(file => <Preview key={file.file} file={file} source={files[file.file]} />)}</div> : null}
        {job.usage ? <p className="model-hint">{job.usage.images ? `${job.usage.images} image${job.usage.images === 1 ? "" : "s"}` : ""}{job.usage.output_seconds ? `${job.usage.images ? " · " : ""}${job.usage.output_seconds.toFixed(1)} s of output` : ""}{job.usage.compute_seconds ? ` · ${job.usage.compute_seconds.toFixed(1)} s on the GPU` : ""}{job.output?.seed !== undefined ? ` · seed ${job.output.seed}` : ""}</p> : null}
      </article>)}
    </div>
  </section>
}

function Preview({ file, source }: { file: MediaFile; source: string | undefined }) {
  const label = `${file.name}${file.width ? ` ${file.width}×${file.height}` : ""}${file.seconds ? ` ${file.seconds.toFixed(1)} s` : ""}`
  if (source === "large") return <p className="model-hint">{label}: too large to show here; save the files to play it.</p>
  if (source === "unavailable") return <p className="model-hint">{label}: the preview could not be loaded; save the files instead.</p>
  if (!source) return <p className="model-hint">{label}: loading preview…</p>
  if (file.content_type.startsWith("image/")) return <img src={source} alt={label} title={label} />
  if (file.content_type.startsWith("video/")) return <video controls src={source} title={label} />
  if (file.content_type.startsWith("audio/")) return <audio controls src={source} title={label} />
  return <p className="model-hint">{label}</p>
}
