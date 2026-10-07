import { ModelGpuOptimizer } from "@/components/model-gpu-optimizer"
import { useEffect, useRef, useState } from "react"
import { modelsApi, type ModelApiAccess } from "@/api/projects-api"
import { workspaceApi } from "@/api/workspace-api"
import { CloudflareAccountFields } from "@/components/cloudflare-account-fields"
import { accountRequest, emptyCloudflareDraft } from "@/lib/cloudflare-account"
import { readPublicAccessPresets } from "@/lib/public-access-presets"
import { rememberPublicAccessPreset } from "@/lib/public-access-preset-actions"
import { usePlatform } from "@/context/platform-context"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Switch } from "@/components/ui/switch"
import { modelApiSkill } from "@/lib/model-api-skill"
import { terminalClipboard } from "@/lib/terminal-clipboard"
import "@/components/model-workspace.css"

type Example = "curl" | "powershell" | "python" | "javascript" | "skill"
// The model server listens on this guest port.
const API_PORT = 8000
const EXAMPLES: [Example, string][] = [["python", "Python"], ["javascript", "JavaScript"], ["curl", "curl"], ["powershell", "PowerShell"], ["skill", "Agent skill"]]

/** With `key`, examples embed the real API key; otherwise they read it from YOUGORI_MODEL_API_KEY. */
function example(kind: Example, base: string, model: string, streaming: boolean, isPublic: boolean, key?: string) {
  const q = JSON.stringify
  switch (kind) {
    case "curl": return `curl ${base}/chat/completions \\
  -H "Authorization: Bearer ${key ?? "$YOUGORI_MODEL_API_KEY"}" \\
  -H "Content-Type: application/json" \\
  -d '{"model": ${JSON.stringify(model)}, "messages": [{"role": "user", "content": "Hello!"}], "max_tokens": 256}'`
    case "powershell": return `$body = @{
  model = "${model}"
  messages = @(@{ role = "user"; content = "Hello!" })
  max_tokens = 256
} | ConvertTo-Json -Depth 4
$reply = Invoke-RestMethod -Method Post -Uri "${base}/chat/completions" \`
  -Headers @{ Authorization = "Bearer ${key ?? "$env:YOUGORI_MODEL_API_KEY"}" } \`
  -ContentType "application/json" -Body $body
$reply.choices[0].message.content`
    case "python": return `# pip install openai
import os
from openai import OpenAI

client = OpenAI(base_url="${base}", api_key=${key ? q(key) : `os.environ["YOUGORI_MODEL_API_KEY"]`})

reply = client.chat.completions.create(
    model="${model}",
    messages=[{"role": "user", "content": "Hello!"}],
    max_tokens=256,
)
print(reply.choices[0].message.content)${streaming ? `

# Stream the reply as it is generated
stream = client.chat.completions.create(
    model="${model}",
    messages=[{"role": "user", "content": "Tell me a story."}],
    max_tokens=512,
    stream=True,
)
for chunk in stream:
    if chunk.choices:
        print(chunk.choices[0].delta.content or "", end="", flush=True)` : ""}`
    case "javascript": return `// npm install openai
import OpenAI from "openai"

const client = new OpenAI({ baseURL: "${base}", apiKey: ${key ? q(key) : "process.env.YOUGORI_MODEL_API_KEY"} })

const reply = await client.chat.completions.create({
  model: "${model}",
  messages: [{ role: "user", content: "Hello!" }],
  max_tokens: 256,
})
console.log(reply.choices[0].message.content)${streaming ? `

// Stream the reply as it is generated
const stream = await client.chat.completions.create({
  model: "${model}",
  messages: [{ role: "user", content: "Tell me a story." }],
  max_tokens: 512,
  stream: true,
})
for await (const chunk of stream) process.stdout.write(chunk.choices[0]?.delta?.content ?? "")` : ""}`
    case "skill": return modelApiSkill({ model, apiUrl: base }, { public: isPublic, streaming, apiKey: key })
  }
}

function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false)
  return <Button size="xs" variant="ghost" onClick={() => void terminalClipboard.writeText(text).then(() => { setCopied(true); window.setTimeout(() => setCopied(false), 1500) }).catch(() => undefined)}>{copied ? "Copied" : label}</Button>
}

function decisionExample(kind: Example, base: string, model: string, key?: string) {
  const request = { state: "Our checkout is returning errors.", questions: { route: { type: "choice", instructions: "Which team should handle this?", criteria: { technical: "Outage or bug", billing: "Payment issue" } } } }
  const body = { model, messages: [{ role: "user", content: JSON.stringify(request) }], max_tokens: 1 }
  if (kind === "python") return `import json, os\nfrom openai import OpenAI\nclient = OpenAI(base_url=${JSON.stringify(base)}, api_key=${key ? JSON.stringify(key) : 'os.environ["YOUGORI_MODEL_API_KEY"]'})\nrequest = json.loads(${JSON.stringify(JSON.stringify(request))})\nreply = client.chat.completions.create(model=${JSON.stringify(model)}, messages=[{"role": "user", "content": json.dumps(request)}], max_tokens=1)\nprint(json.loads(reply.choices[0].message.content)["answers"])`
  if (kind === "javascript") return `import OpenAI from "openai"\nconst client = new OpenAI({ baseURL: ${JSON.stringify(base)}, apiKey: ${key ? JSON.stringify(key) : "process.env.YOUGORI_MODEL_API_KEY"} })\nconst reply = await client.chat.completions.create(${JSON.stringify(body, null, 2)})\nconsole.log(JSON.parse(reply.choices[0].message.content).answers)`
  if (kind === "powershell") return `$body = '${JSON.stringify(body)}'\n$reply = Invoke-RestMethod -Method Post -Uri "${base}/chat/completions" -Headers @{ Authorization = "Bearer ${key ?? "$env:YOUGORI_MODEL_API_KEY"}" } -ContentType "application/json" -Body $body\n($reply.choices[0].message.content | ConvertFrom-Json).answers`
  if (kind === "skill") return `# Yougori decision model\nModel: ${model}\nBase URL: ${base}\nSend the following JSON to POST /chat/completions with Authorization: Bearer ${key ?? "<YOUGORI_MODEL_API_KEY>"}.\nThe message content is JSON containing state and typed questions. Parse the assistant's JSON content to read answers and probabilities.\n\n${JSON.stringify(body, null, 2)}`
  return `curl ${base}/chat/completions \\\n  -H "Authorization: Bearer ${key ?? "$YOUGORI_MODEL_API_KEY"}" \\\n  -H "Content-Type: application/json" \\\n  -d '${JSON.stringify(body)}'`
}

export function ModelApiPanel({ environmentId }: { environmentId: string }) {
  const { state } = usePlatform()
  const running = state?.environments.find(e => e.id === environmentId)?.status === "running"
  const [access, setAccess] = useState<ModelApiAccess | null>(null)
  const [streaming, setStreaming] = useState(false)
  const [sourceOnly, setSourceOnly] = useState(false)
  const [decision, setDecision] = useState(false)
  const [port, setPort] = useState("8000")
  const [busy, setBusy] = useState<"local" | "public" | null>(null)
  const [error, setError] = useState("")
  const [reveal, setReveal] = useState(false)
  const [kind, setKind] = useState<Example>("python")
  const [target, setTarget] = useState<"local" | "public">("public")
  const [setup, setSetup] = useState(false)
  const [cloudflare, setCloudflare] = useState(emptyCloudflareDraft)
  const [cloudflareLoading, setCloudflareLoading] = useState(false)
  const [presets, setPresets] = useState(readPublicAccessPresets)
  const [presetId, setPresetId] = useState<string | null>(null)
  const [notice, setNotice] = useState("")
  const [withKey, setWithKey] = useState(false)
  const alive = useRef(true)
  useEffect(() => {
    alive.current = true
    void modelsApi.access(environmentId).then(value => { if (alive.current) setAccess(value) }).catch(e => { if (alive.current) setError(String(e)) })
    void modelsApi.status(environmentId).then(value => { if (alive.current) { setStreaming(Boolean(value.stream)); setDecision(value.task === "structured-decision"); setSourceOnly(Boolean(value.sourceOnly)) } }).catch(() => undefined)
    return () => { alive.current = false }
  }, [environmentId])
  useEffect(() => {
    const refresh = () => setPresets(readPublicAccessPresets())
    window.addEventListener("yougori-public-presets-changed", refresh)
    return () => window.removeEventListener("yougori-public-presets-changed", refresh)
  }, [])
  const perform = async (which: "local" | "public", action: () => Promise<ModelApiAccess>) => {
    if (busy) return
    setBusy(which); setError("")
    try { const value = await action(); if (alive.current) setAccess(value) }
    catch (e) { if (alive.current) setError(String(e)) }
    finally { if (alive.current) setBusy(null) }
  }
  // Same publish flow as a node's Public access dialog: quick link, own Cloudflare account, or a saved domain.
  const connectPublic = () => perform("public", async () => {
    const preset = presetId ? presets.find(item => item.id === presetId) : undefined
    if (presetId && !preset) throw new Error("This saved domain is no longer available for the model API")
    const account = preset
      ? { hostPort: preset.hostPort, options: { hostname: preset.hostname, presetId: preset.id, presetSourceEnvironmentId: preset.credentialEnvironmentId, presetPort: preset.port, remember: false, routesReviewed: true } }
      : cloudflare.mode === "account" ? accountRequest(cloudflare) : undefined
    await workspaceApi.publish(environmentId, API_PORT, "cloudflare", account?.hostPort, account?.options)
    if (account && !preset && cloudflare.remember) {
      try { await rememberPublicAccessPreset(environmentId, API_PORT, account.options.hostname, account.hostPort) }
      catch (reason) { setNotice(`Connected, but could not add this domain to Saved setups: ${reason instanceof Error ? reason.message : String(reason)}`) }
    }
    setCloudflare(current => ({ ...current, token: "" })); setSetup(false); setTarget("public")
    return modelsApi.access(environmentId)
  })
  const disconnectPublic = () => perform("public", async () => { if (access?.publicId) await workspaceApi.unpublish(access.publicId); return modelsApi.access(environmentId) })
  const runAction = async (action: () => Promise<unknown>) => { setError(""); try { await action() } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) } }
  const enableLocal = () => perform("local", async () => { await modelsApi.api(environmentId, Number(port)); return modelsApi.access(environmentId) })
  const validPort = /^\d+$/.test(port) && Number(port) >= 1 && Number(port) <= 65535
  const model = access?.model ?? ""
  const base = target === "public" && access?.publicUrl ? access.publicUrl : access?.apiUrl ?? access?.publicUrl ?? null
  const isPublic = Boolean(access?.publicUrl && base === access.publicUrl)
  const snippet = base ? (decision ? decisionExample(kind, base, model, withKey ? access?.apiKey : undefined) : example(kind, base, model, streaming, isPublic, withKey ? access?.apiKey : undefined)) : ""

  if (sourceOnly) return <section className="model-card" aria-label="Source-only API"><h3>File downloads only</h3><p>No model weights were supplied. Chat and inference API are unavailable. Use Neo Grid to publish the source files.</p></section>
  return <section className="model-api" aria-label="Model API access">
    <ModelGpuOptimizer environmentId={environmentId} />
    <div className="model-api-cards">
      <div className="model-api-card">
        <div className="model-api-card-head"><h3>Local</h3><span data-on={Boolean(access?.apiUrl) || undefined}>{access?.apiUrl ? "On" : "Off"}</span></div>
        <p>Apps and agents on this PC.</p>
        {access?.apiUrl
          ? <div className="model-api-url"><code>{access.apiUrl}</code><CopyButton text={access.apiUrl} /></div>
          : <div className="model-api-enable">
            <Input className="w-24" aria-label="Local API port" type="number" min={1} max={65535} value={port} disabled={Boolean(busy)} onChange={e => setPort(e.target.value)} />
            <Button size="sm" variant="outline" disabled={!running || !validPort || Boolean(busy)} loading={busy === "local"} onClick={() => void enableLocal()}>Turn on</Button>
          </div>}
      </div>
      <div className="model-api-card">
        <div className="model-api-card-head"><h3>Public</h3><span data-on={Boolean(access?.publicUrl) || undefined}>{access?.publicUrl ? "On" : "Off"}</span></div>
        <p>An HTTPS address that works from anywhere, including online agents. Every request still needs your API key.</p>
        {access?.publicUrl
          ? <>
            <div className="model-api-url"><code>{access.publicUrl}</code><CopyButton text={access.publicUrl} /></div>
            <div className="model-api-enable"><small>{access.publicAccount ? "Your Cloudflare domain." : "Quick link. Lasts while Yougori runs; a new link is made each time."}</small><Button size="sm" variant="outline" disabled={Boolean(busy)} loading={busy === "public"} onClick={() => void disconnectPublic()}>Turn off</Button></div>
          </>
          : <div className="model-api-enable"><Button size="sm" variant={setup ? "secondary" : "outline"} disabled={!running || Boolean(busy)} aria-expanded={setup} onClick={() => setSetup(v => !v)}>Set up public access</Button></div>}
      </div>
    </div>
    {setup && !access?.publicUrl ? <div className="model-api-setup">
      <CloudflareAccountFields environmentId={environmentId} port={API_PORT} value={cloudflare} onChange={setCloudflare} onLoadingChange={setCloudflareLoading} busy={Boolean(busy) || cloudflareLoading} perform={runAction} refreshKey={access?.publicId ?? ""} compact presets={presets} selectedPresetId={presetId} onSelectPreset={setPresetId} anyPresetPort />
      <div className="model-api-enable">
        <Button size="sm" variant="ghost" disabled={Boolean(busy)} onClick={() => setSetup(false)}>Cancel</Button>
        <Button size="sm" disabled={!running || Boolean(busy) || cloudflareLoading} loading={busy === "public"} onClick={() => void connectPublic()}>Connect</Button>
      </div>
    </div> : null}
    {notice ? <p role="status" className="model-hint">{notice}</p> : null}
    {!running ? <p className="model-hint">Start the model to turn on API access.</p> : null}
    {error ? <p role="alert" className="model-error">{error}</p> : null}

    {access ? <div className="model-api-key">
      <span className="model-label">API key</span>
      <Input aria-label="Model API key" type={reveal ? "text" : "password"} readOnly value={access.apiKey} />
      <Button size="sm" variant="ghost" onClick={() => setReveal(v => !v)}>{reveal ? "Hide" : "Show"}</Button>
      <CopyButton text={access.apiKey} />
    </div> : null}

    <div className="model-api-docs">
      <h3>How to use</h3>
      {decision ? <p className="model-hint">This model returns typed decisions. Send JSON containing state and questions as the user message; parse the assistant’s JSON content for answers and probabilities. Direct model addresses also serve POST /v1/systemone.</p> : null}
      <ol className="model-api-steps">
        <li>Turn on Local or Public access above.</li>
        <li>{withKey ? "The API key is filled into the examples below, ready to run." : <>Put the API key in the <code>YOUGORI_MODEL_API_KEY</code> environment variable of the app that calls the model, or turn on Include API key below.</>}</li>
        <li>Use any OpenAI-compatible client with the base URL below and model <code>{model || "…"}</code>.</li>
      </ol>
      {base ? <>
        <div className="model-api-docs-bar">
          <div className="model-tabs" role="group" aria-label="Example">
            {EXAMPLES.map(([id, label]) => <button key={id} type="button" aria-pressed={kind === id} onClick={() => setKind(id)}>{label}</button>)}
          </div>
          <div className="model-api-include-key"><Switch id="model-api-include-key" checked={withKey} onCheckedChange={setWithKey} /><label htmlFor="model-api-include-key">Include API key</label></div>
          {access?.apiUrl && access.publicUrl ? <div className="model-tabs" role="group" aria-label="Address">
            <button type="button" aria-pressed={!isPublic} onClick={() => setTarget("local")}>Local</button>
            <button type="button" aria-pressed={isPublic} onClick={() => setTarget("public")}>Public</button>
          </div> : null}
        </div>
        <div className="md-code">
          <div className="md-code-bar"><span>{kind === "skill" ? "SKILL.md" : EXAMPLES.find(([id]) => id === kind)![1]}</span><CopyButton text={snippet} /></div>
          <pre><code>{snippet}</code></pre>
        </div>
        {kind === "skill" ? <p className="model-hint">Give this to a coding agent, or save it as yougori-model-api/SKILL.md.{withKey ? "" : " It contains no key."}</p> : null}
        {withKey ? <p className="model-api-key-warning">This example contains your API key. Don't commit it, paste it publicly or share it with anyone you don't trust with your GPU.</p> : null}
      </> : <p className="model-hint">Examples appear here once an address is on.</p>}
      <ul className="model-api-notes">
        <li>Endpoint: <code>POST /chat/completions</code>. Fields: <code>model</code>, <code>messages</code> (system, user and assistant text), <code>max_tokens</code> (up to {streaming ? "4096" : "2048"}), <code>temperature</code> (0–2){streaming ? <>, <code>stream</code></> : null}. Tools, images and other fields are rejected.</li>
        <li>The GPU answers one request at a time; a busy model replies 429, so wait and retry.</li>
        {streaming ? null : <li>This model was started by an older Yougori, so replies don't stream. Run it again from Hugging Face for streaming and longer replies.</li>}
        <li>Anyone with the public link and your key can use your GPU. Turn the public link off when you're done.</li>
      </ul>
    </div>
  </section>
}
