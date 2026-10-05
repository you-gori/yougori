import { useEffect, useState } from "react"
import { modelsApi } from "@/api/projects-api"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"

export function HuggingfaceAccess() {
  const [configured, setConfigured] = useState(false)
  const [token, setToken] = useState("")
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  useEffect(() => { let alive = true; void modelsApi.huggingface().then(value => { if (alive) setConfigured(value.configured) }).catch(() => undefined); return () => { alive = false } }, [])
  const change = async (forget: boolean) => {
    if (busy) return
    setBusy(true); setError("")
    try {
      if (forget) await modelsApi.forgetHuggingfaceToken()
      else await modelsApi.saveHuggingfaceToken(token.trim())
      setConfigured(!forget); setToken("")
    } catch (reason) { setError(String(reason)) }
    finally { setBusy(false) }
  }
  return <details className="model-hint">
    <summary>Hugging Face access · {configured ? "Read token saved" : "Public models"}</summary>
    <p>Private and gated models need a <a href="https://huggingface.co/settings/tokens" target="_blank" rel="noreferrer">Hugging Face read token</a> and approved access on their model page. The CLI and App share the token in your OS credential vault.</p>
    <label htmlFor="hf-read-token">Read token</label>
    <Input id="hf-read-token" type="password" autoComplete="off" value={token} disabled={busy} onChange={event => setToken(event.target.value)} placeholder="hf_…" />
    <div className="model-form-actions"><Button size="sm" disabled={busy || !/^hf_[A-Za-z0-9_]{9,1021}$/.test(token.trim())} loading={busy} onClick={() => void change(false)}>Save token</Button>{configured ? <Button size="sm" variant="outline" disabled={busy} onClick={() => void change(true)}>Forget token</Button> : null}</div>
    {error ? <p role="alert" className="model-error">{error}</p> : null}
  </details>
}
