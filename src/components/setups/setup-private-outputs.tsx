import { useEffect, useState } from "react"
import { Button } from "@/components/ui/button"
import { errorText, setupsApi, type PrivateOutput } from "@/api/setups/setups-api"

/** A setup's private outputs, such as a grid's invite.
 *
 *  Only their names are listed. A value is shown when the person asks, read from the product again
 *  each time, and let go when it is hidden or this view closes. Nothing here keeps, logs or copies a
 *  value unless the person asks to copy it. A build without private outputs shows nothing. */
export function PrivateOutputs({ setupId, revision }: { setupId: string; revision?: number }) {
  const [outputs, setOutputs] = useState<PrivateOutput[]>([])
  const [shown, setShown] = useState<Record<string, string>>({})
  const [busy, setBusy] = useState("")
  const [said, setSaid] = useState<Record<string, string>>({})

  useEffect(() => {
    let live = true
    // Whatever goes wrong reading the list, there is simply nothing to show.
    Promise.resolve().then(() => setupsApi.privateOutputs(setupId)).then(list => { if (live) setOutputs(list) }).catch(() => { if (live) setOutputs([]) })
    return () => { live = false }
  }, [setupId, revision])

  const tell = (key: string, text: string) => setSaid(current => ({ ...current, [key]: text }))
  const hide = (key: string) => {
    setShown(current => Object.fromEntries(Object.entries(current).filter(([one]) => one !== key)))
    tell(key, "")
  }

  async function show(key: string) {
    if (busy) return
    setBusy(key)
    tell(key, "")
    try {
      const value = await setupsApi.reveal(setupId, key)
      setShown(current => ({ ...current, [key]: value }))
    } catch (reason) {
      tell(key, errorText(reason))
    } finally {
      setBusy("")
    }
  }

  async function copy(key: string) {
    const value = shown[key]
    if (!value) return
    try {
      await navigator.clipboard.writeText(value)
      tell(key, "Copied.")
    } catch {
      tell(key, "Yougori couldn't copy it. Select it and copy it yourself.")
    }
  }

  if (!outputs.length) return null
  return <dl className="setup-outputs" aria-label="Private outputs">
    {outputs.map(output => <div key={output.key}>
      <dt>{output.label}</dt>
      <dd className="setup-private">
        {shown[output.key] !== undefined ? <>
          <code className="setup-private-value">{shown[output.key]}</code>
          <Button size="xs" variant="ghost" aria-label={`Copy ${output.label}`} onClick={() => void copy(output.key)}>Copy</Button>
          <Button size="xs" variant="ghost" aria-label={`Hide ${output.label}`} onClick={() => hide(output.key)}>Hide</Button>
        </> : <Button size="xs" variant="outline" aria-label={`Show ${output.label}`} disabled={busy === output.key} onClick={() => void show(output.key)}>
          {busy === output.key ? "Reading…" : "Show"}
        </Button>}
        {said[output.key] ? <span role="status" className="setup-note">{said[output.key]}</span> : null}
      </dd>
    </div>)}
  </dl>
}
