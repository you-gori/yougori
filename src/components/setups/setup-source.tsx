import { useId, useState } from "react"
import type { Diagnostic } from "@/api/setups/types"
import { Button } from "@/components/ui/button"
import { DiagnosticList } from "./setup-views"

/** The template source the builder's choices make, as the engine writes it, and the problems the
 *  engine found, each linked to the field it is about. Edited source goes back to the engine, which
 *  reads it into the same choices, so the screen and the file never disagree. */
export function SetupSource({ manifest, diagnostics, names, unavailable, error, busy, onUseSource, onGoTo }: {
  manifest: string | null
  diagnostics: Diagnostic[]
  names: Record<string, string>
  unavailable: boolean
  error: string
  busy: boolean
  /** Resolves true when the engine read the edited source; edits are kept until it does. */
  onUseSource(text: string): Promise<boolean>
  onGoTo(field: string): void
}) {
  const id = useId()
  const [text, setText] = useState("")
  const [edited, setEdited] = useState(false)
  // Until somebody edits it, it shows what the engine wrote; after, their own words, until the
  // engine has read them back.
  const shown = edited ? text : manifest ?? ""
  if (unavailable) return <p className="setup-callout" role="note">The source appears here once this build of Yougori can check drafts. Your choices are kept.</p>
  return <div className="setup-source">
    {error ? <p role="alert" className="grid-error">{error}</p> : null}
    {manifest === null && !error ? <p role="status" className="setup-note">Writing the source…</p> : null}
    {manifest !== null ? <>
      <label htmlFor={id} className="setup-field-label">yougori-template.yaml</label>
      <textarea
        id={id}
        className="setup-code"
        spellCheck={false}
        rows={Math.min(24, Math.max(8, shown.split("\n").length + 1))}
        value={shown}
        aria-describedby={`${id}-hint`}
        onChange={event => { setText(event.target.value); setEdited(true) }}
      />
      <p id={`${id}-hint`} className="setup-note">Edit it here if you prefer. Secrets are never written into it; they are asked when it runs.</p>
      <div className="setup-actions">
        <Button size="xs" variant="outline" disabled={!edited || busy} loading={busy} onClick={() => { void onUseSource(text).then(read => { if (read) setEdited(false) }) }}>Use this source</Button>
        {edited ? <Button size="xs" variant="ghost" disabled={busy} onClick={() => setEdited(false)}>Undo my edits</Button> : null}
      </div>
    </> : null}
    <DiagnosticList diagnostics={diagnostics} names={names} onGoTo={onGoTo} />
  </div>
}
