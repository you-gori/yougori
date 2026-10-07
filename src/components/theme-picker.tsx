import { useEffect, useState } from "react"
import { Palette } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Dialog, DialogDescription, DialogHeader, DialogPanel, DialogPopup, DialogTitle } from "@/components/ui/dialog"
import { usePlatform } from "@/context/platform-context"
import { defaultCustomTheme, themePresets, validCustomTheme, validThemeColor } from "@/lib/appearance"
import type { CustomThemeColors, ThemePreference } from "@/types/platform"
import "./theme-picker.css"
import { useTopicWalkthroughModal } from "@/lib/topic-walkthrough"

const colorFields: { key: keyof CustomThemeColors; label: string }[] = [
  { key: "background", label: "Background" },
  { key: "surface", label: "Surface" },
  { key: "accent", label: "Accent" },
  { key: "detail", label: "Text / detail" },
]

function Swatches({ colors }: { colors: CustomThemeColors }) {
  return <span aria-hidden="true" className="theme-swatches">
    {colorFields.map(({ key }) => <i key={key} style={{ backgroundColor: validThemeColor(colors[key]) ? colors[key] : "transparent" }} />)}
  </span>
}

export function ThemePicker() {
  const { state, updateSettings } = usePlatform()
  const [open, setOpen] = useState(false)
  const topic = useTopicWalkthroughModal(open)
  const [draft, setDraft] = useState<CustomThemeColors>(defaultCustomTheme)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState("")
  const savedBackground = state?.settings.customThemeColors?.background
  const savedSurface = state?.settings.customThemeColors?.surface
  const savedAccent = state?.settings.customThemeColors?.accent
  const savedDetail = state?.settings.customThemeColors?.detail
  useEffect(() => {
    const saved = savedBackground && savedSurface && savedAccent && savedDetail
      ? { background: savedBackground, surface: savedSurface, accent: savedAccent, detail: savedDetail }
      : null
    if (open) setDraft(saved && validCustomTheme(saved) ? saved : defaultCustomTheme)
  }, [open, savedBackground, savedSurface, savedAccent, savedDetail])
  if (!state) return null

  const choose = async (theme: ThemePreference, colors?: CustomThemeColors) => {
    if (busy) return
    setBusy(true)
    setError("")
    try {
      await updateSettings({ ...state.settings, theme, ...(colors ? { customThemeColors: colors } : {}) })
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : String(reason))
    } finally {
      setBusy(false)
    }
  }
  const saveCustom = () => {
    if (!validCustomTheme(draft)) { setError("Enter four six-digit hex colors, such as #315B8C."); return }
    void choose("custom", {
      background: draft.background.toUpperCase(),
      surface: draft.surface.toUpperCase(),
      accent: draft.accent.toUpperCase(),
      detail: draft.detail.toUpperCase(),
    })
  }

  return <Dialog modal={!topic} open={open} onOpenChange={(value, details) => { if (!(!value && topic && details.reason === "focus-out") && !(details.event.target instanceof Element && details.event.target.closest('[data-topic-ui]'))) setOpen(value) }}>
    <Button className="dashboard-theme workspace-footer-reclaim" data-tour="theme" size="xs" type="button" variant="ghost" onClick={() => setOpen(true)}><Palette aria-hidden="true" className="size-3.5" /> Theme</Button>
    <DialogPopup data-instruction="theme-dialog" className="theme-dialog max-w-[600px]" closeProps={{ disabled: busy }}>
      <DialogHeader className="gap-1 pb-2"><DialogTitle>Appearance</DialogTitle><DialogDescription>Choose a palette for Yougori.</DialogDescription></DialogHeader>
      <DialogPanel className="theme-panel">
        <div className="theme-basics" aria-label="Standard themes">
          {([ ["system", "System"], ["light", "Light"], ["dark", "Dark"] ] as const).map(([id, label]) =>
            <button key={id} type="button" aria-pressed={state.settings.theme === id} disabled={busy} onClick={() => void choose(id)}>{label}</button>)}
        </div>
        <div className="theme-grid" aria-label="Color themes">
          {themePresets.map((preset, index) => <button key={preset.id} className="theme-choice" type="button" aria-pressed={state.settings.theme === preset.id} disabled={busy} onClick={() => void choose(preset.id)}>
            <Swatches colors={preset.colors} /><span>Theme {index + 1} <small>{preset.name}</small></span>
          </button>)}
        </div>
        <section className="theme-custom" aria-label="Custom theme" data-selected={state.settings.theme === "custom"}>
          <div className="theme-custom-heading"><span>Theme 6 <small>Custom</small></span><Swatches colors={draft} /></div>
          <div className="theme-fields">
            {colorFields.map(({ key, label }) => <label key={key}><span>{label}</span><input aria-invalid={draft[key].length > 0 && !validThemeColor(draft[key])} autoComplete="off" maxLength={7} spellCheck={false} value={draft[key]} onChange={event => setDraft(current => ({ ...current, [key]: event.target.value }))} /></label>)}
          </div>
          <div className="theme-custom-footer"><p>Use # plus six hex digits. Text adjusts when needed for contrast.</p><Button size="sm" disabled={busy || !validCustomTheme(draft)} onClick={saveCustom}>Apply custom</Button></div>
        </section>
        {error ? <p className="theme-error" role="alert">{error}</p> : null}
      </DialogPanel>
    </DialogPopup>
  </Dialog>
}
