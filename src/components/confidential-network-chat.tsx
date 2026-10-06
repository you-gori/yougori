import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Textarea } from "@/components/ui/textarea"

export function ConfidentialNetworkChat() {
  const [open, setOpen] = useState(false)
  const [policy, setPolicy] = useState("")
  const [key, setKey] = useState("")
  const [node, setNode] = useState("")
  const [model, setModel] = useState("")
  const [prompt, setPrompt] = useState("")
  const [reply, setReply] = useState("")
  const [error, setError] = useState("")
  const [busy, setBusy] = useState(false)
  async function send() {
    if (busy) return
    setBusy(true); setError(""); setReply("")
    try {
      const { invoke, isTauri } = await import("@tauri-apps/api/core")
      if (!isTauri()) throw new Error("Confidential encryption requires the native App or CLI")
      const result = await invoke<{ choices?: { message: { content: string } }[]; error?: { message: string } }>("confidential_network_chat", { apiKey: key, nodeId: node, model: model.trim().replace(/^hf\.co\//, ""), prompt, policyPath: policy || null })
      if (result.error) throw new Error(result.error.message)
      setReply(result.choices?.[0]?.message.content ?? "No text response")
    } catch (reason) { setError(reason instanceof Error ? reason.message : String(reason)) }
    finally { setKey(""); setBusy(false) }
  }
  return <section aria-label="Confidential Network inference">
    <Button size="sm" variant="outline" aria-expanded={open} onClick={() => setOpen(!open)}>Confidential inference</Button>
    {open ? <div className="confidential-chat">
      <p>Experimental native client. No approved hardware policy ships yet, so requests are blocked by default. Compatible confidential CPU/GPU hardware and an independently verified image are required.</p>
      <p>Encryption stays in the native client. A website cannot supply its trust policy. Prompts and replies are not saved here, and failed verification never falls back to standard inference.</p>
      <label>Local attestation policy<Input value={policy} onChange={e => setPolicy(e.target.value)} placeholder="Path to independently verified policy.json" disabled={busy} /></label>
      <label>Provider ID<Input value={node} onChange={e => setNode(e.target.value)} placeholder="nd_…" disabled={busy} /></label>
      <label>Model repository<Input value={model} onChange={e => setModel(e.target.value)} placeholder="owner/model" disabled={busy} /></label>
      <label>Network API key<Input type="password" autoComplete="off" value={key} onChange={e => setKey(e.target.value)} disabled={busy} /></label>
      <label>Prompt<Textarea value={prompt} onChange={e => setPrompt(e.target.value)} maxLength={32768} disabled={busy} /></label>
      <Button size="sm" disabled={busy || !key || !node || !model || !prompt} onClick={() => void send()}>{busy ? "Verifying and sending…" : "Verify and send encrypted"}</Button>
      {error ? <p role="alert">{error}</p> : null}
      {reply ? <pre aria-label="Decrypted response">{reply}</pre> : null}
    </div> : null}
  </section>
}
