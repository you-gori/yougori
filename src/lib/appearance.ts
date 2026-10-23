import type { CustomThemeColors, ThemePreference } from "@/types/platform"

/** Every colour a theme decides: by hand for a preset, derived for a custom theme. Each token the
 *  app reads under a theme is one of these. */
export interface ThemePalette {
  background: string
  foreground: string
  /** Panels, the sidebar and the cream blocks. */
  card: string
  /** Menus, dialogs and every other popup: a clean raised surface, never a strong colour. */
  popover: string
  muted: string
  mutedForeground: string
  /** The hover surface. */
  accent: string
  /** Secondary buttons, light pills and the current sidebar row. */
  secondary: string
  /** The hairline on every popup, card and panel: it shows on background, card and popover, and
   *  never glares. */
  border: string
  input: string
  ring: string
  primary: string
  primaryForeground: string
  primaryHover: string
  graphLine: string
  graphDot: string
  /** The quieter half of a two-tone headline. */
  inkMuted: string
  /** Online and ready. */
  leaf: string
  peach: string
}

export type PresetId = Exclude<ThemePreference, "light" | "dark" | "system" | "custom">

export interface ThemePreset {
  id: PresetId
  name: string
  dark: boolean
  palette: ThemePalette
}

/** Five well-known palettes, lights first, each set by hand onto every token so cards, popups and
 *  hairlines look intended rather than mixed. Every value is the palette's own colour except the
 *  few marked as made from two of them.
 *
 *  The ids are what the settings file stores (the Rust enum checks them), so an id keeps its slot
 *  when the palette behind it changes. */
export const themePresets: readonly ThemePreset[] = [
  // Rosé Pine Dawn. https://rosepinetheme.com, https://github.com/rose-pine/palette
  // MIT License, Copyright (c) mvllow.
  {
    id: "theme1", name: "Rosé Pine Dawn", dark: false,
    palette: {
      background: "#faf4ed", // base
      foreground: "#575279", // text
      card: "#fffaf3", // surface
      popover: "#fffdf9", // surface, lifted toward white
      muted: "#f2e9e1", // overlay
      mutedForeground: "#686486", // between text and subtle, so it reads on overlay
      accent: "#f2e9e1", // overlay
      secondary: "#dfdad9", // highlight med
      border: "#dfdad9", // highlight med
      input: "#cecacd", // highlight high
      ring: "#286983", // pine
      primary: "#286983", // pine
      primaryForeground: "#fffaf3", // surface
      primaryHover: "#235c73", // pine, deepened
      graphLine: "#9893a5", // muted
      graphDot: "#cecacd", // highlight high
      inkMuted: "#797593", // subtle
      leaf: "#286983", // pine
      peach: "#d7827e", // rose
    },
  },
  // Catppuccin Latte. https://catppuccin.com/palette, https://github.com/catppuccin/palette
  // MIT License, Copyright (c) 2021 Catppuccin.
  {
    id: "theme3", name: "Catppuccin Latte", dark: false,
    palette: {
      background: "#eff1f5", // base
      foreground: "#4c4f69", // text
      card: "#e6e9ef", // mantle
      popover: "#f9fafc", // base, lifted toward white
      muted: "#dce0e8", // crust
      mutedForeground: "#5c5f77", // subtext 1
      accent: "#dce0e8", // crust
      secondary: "#ccd0da", // surface 0
      border: "#ccd0da", // surface 0
      input: "#bcc0cc", // surface 1
      ring: "#1e66f5", // blue
      primary: "#1e66f5", // blue
      primaryForeground: "#ffffff",
      primaryHover: "#1b5cdd", // blue, deepened
      graphLine: "#9ca0b0", // overlay 0
      graphDot: "#bcc0cc", // surface 1
      inkMuted: "#7c7f93", // overlay 2
      leaf: "#307820", // green, deepened so it reads as text
      peach: "#dc8a78", // rosewater
    },
  },
  // Nord. https://www.nordtheme.com, https://github.com/nordtheme/nord
  // MIT License, Copyright (c) 2016-present Sven Greb.
  {
    id: "theme5", name: "Nord", dark: true,
    palette: {
      background: "#2e3440", // nord0
      foreground: "#d8dee9", // nord4
      card: "#343a48", // between nord0 and nord1
      popover: "#3b4252", // nord1
      muted: "#3b4252", // nord1
      mutedForeground: "#aeb4bf", // nord4 toward nord0, so it reads on nord1
      accent: "#434c5e", // nord2
      secondary: "#434c5e", // nord2
      border: "#485164", // between nord2 and nord3
      input: "#4c566a", // nord3
      ring: "#88c0d0", // nord8
      primary: "#88c0d0", // nord8
      primaryForeground: "#2e3440", // nord0
      primaryHover: "#97c7d5", // nord8 toward nord6
      graphLine: "#4c566a", // nord3
      graphDot: "#434c5e", // nord2
      inkMuted: "#7d8696", // nord3 toward nord4
      leaf: "#a3be8c", // nord14
      peach: "#d08770", // nord12
    },
  },
  // Catppuccin Mocha. https://catppuccin.com/palette, https://github.com/catppuccin/palette
  // MIT License, Copyright (c) 2021 Catppuccin.
  {
    id: "theme2", name: "Catppuccin Mocha", dark: true,
    palette: {
      background: "#1e1e2e", // base
      foreground: "#cdd6f4", // text
      card: "#232334", // base toward surface 0
      popover: "#28293a", // base toward surface 0, one step more
      muted: "#28293a",
      mutedForeground: "#a6adc8", // subtext 0
      accent: "#313244", // surface 0
      secondary: "#313244", // surface 0
      border: "#3b3c4f", // between surface 0 and surface 1
      input: "#45475a", // surface 1
      ring: "#b4befe", // lavender
      primary: "#cba6f7", // mauve
      primaryForeground: "#11111b", // crust
      primaryHover: "#d3b3f8", // mauve, lifted
      graphLine: "#6c7086", // overlay 0
      graphDot: "#45475a", // surface 1
      inkMuted: "#7f849c", // overlay 1
      leaf: "#a6e3a1", // green
      peach: "#fab387", // peach
    },
  },
  // Tokyo Night. https://github.com/enkia/tokyo-night-vscode-theme
  // MIT License, Copyright (c) 2018-present Enkia.
  {
    id: "theme4", name: "Tokyo Night", dark: true,
    palette: {
      background: "#1a1b26", // editor background (Night)
      foreground: "#c0caf5", // terminal white
      card: "#1f2231", // between the Night and Storm backgrounds
      popover: "#24283b", // editor background (Storm)
      muted: "#24283b",
      mutedForeground: "#9aa5ce", // markdown text
      accent: "#2b3046", // Storm background toward terminal black
      secondary: "#2b3046",
      border: "#30354d", // Storm background toward terminal black, one step more
      input: "#414868", // terminal black
      ring: "#7aa2f7", // blue
      primary: "#7aa2f7", // blue
      primaryForeground: "#1a1b26", // editor background (Night)
      primaryHover: "#87abf8", // blue, lifted
      graphLine: "#565f89", // comments
      graphDot: "#2b3046",
      inkMuted: "#787c99", // sidebar text
      leaf: "#9ece6a", // strings
      peach: "#ff9e64", // constants
    },
  },
]

/** The four colours a preset is shown by in the picker. */
export function presetSwatches(preset: ThemePreset): CustomThemeColors {
  const { background, secondary, primary, foreground } = preset.palette
  return { background, surface: secondary, accent: primary, detail: foreground }
}

export const defaultCustomTheme: CustomThemeColors = {
  background: "#F5EBDD", surface: "#D8C4AD", accent: "#315B8C", detail: "#413333",
}

export function validThemeColor(value: string): boolean {
  return /^#[\da-fA-F]{6}$/.test(value)
}

export function validCustomTheme(colors: CustomThemeColors | null | undefined): colors is CustomThemeColors {
  return Boolean(colors && validThemeColor(colors.background) && validThemeColor(colors.surface) && validThemeColor(colors.accent) && validThemeColor(colors.detail))
}

function rgb(hex: string): [number, number, number] {
  return [1, 3, 5].map(index => Number.parseInt(hex.slice(index, index + 2), 16)) as [number, number, number]
}

function mix(first: string, second: string, secondWeight: number): string {
  const a = rgb(first), b = rgb(second)
  return `#${a.map((value, index) => Math.round(value * (1 - secondWeight) + b[index]! * secondWeight).toString(16).padStart(2, "0")).join("")}`
}

export function contrastRatio(first: string, second: string): number {
  const luminance = (hex: string) => {
    const [r, g, b] = rgb(hex).map(value => {
      const channel = value / 255
      return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
    })
    return r! * 0.2126 + g! * 0.7152 + b! * 0.0722
  }
  const a = luminance(first), b = luminance(second)
  return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
}

/** The same colour at half its saturation, so a raised surface on a dark theme stays quiet. */
function quieter(hex: string): string {
  const [r, g, b] = rgb(hex)
  const grey = Math.round(r * 0.299 + g * 0.587 + b * 0.114).toString(16).padStart(2, "0")
  return mix(hex, `#${grey}${grey}${grey}`, 0.5)
}

/** `color`, moved toward `toward` in twentieths until it reads at `minimum` on every surface. */
function readableOn(color: string, surfaces: readonly string[], toward: string, minimum = 4.5): string {
  for (let step = 0; step <= 20; step++) {
    const candidate = mix(color, toward, step / 20)
    if (surfaces.every(surface => contrastRatio(candidate, surface) >= minimum)) return candidate
  }
  return toward
}

/** `background` moved toward `color` by `weight`, or by less when the full step would leave `text`
 *  hard to read on it or take the surface further than `furthest` from the page. A surface stays
 *  a quiet step from the page however loud the colour it is tinted with. */
function surfaceNear(background: string, color: string, weight: number, text: string, furthest: number): string {
  for (let step = Math.round(weight * 20); step > 0; step--) {
    const surface = mix(background, color, step / 20)
    if (contrastRatio(text, surface) >= 4.5 && contrastRatio(surface, background) <= furthest) return surface
  }
  return background
}

/** The label on a primary button: the page's own background when it reads, else white or black. */
function labelOn(primary: string, background: string): string {
  for (const candidate of [background, "#FFFFFF", "#161616", "#000000"]) {
    if (contrastRatio(primary, candidate) >= 4.5) return candidate
  }
  return contrastRatio(primary, "#FFFFFF") > contrastRatio(primary, "#000000") ? "#FFFFFF" : "#000000"
}

/** A whole palette from a custom theme's four colours. The background and accent are used as
 *  given; text moves only as far as it must to read; the user's surface tints cards and hover
 *  states, and popups are the background lifted, never the surface colour. */
export function deriveTheme(colors: CustomThemeColors): { dark: boolean; palette: ThemePalette } {
  const { background, surface, accent, detail } = colors
  // Whichever of white and black reads better on the page decides the side, so text can always
  // reach AA by moving toward it, even on a mid grey.
  const dark = contrastRatio(background, "#FFFFFF") > contrastRatio(background, "#000000")
  const away = dark ? "#FFFFFF" : "#000000"
  // Text aims a little above AA on the page so the surfaces near it can still differ from it.
  const foreground = readableOn(detail, [background], away, 6)
  const card = surfaceNear(background, surface, dark ? 0.4 : 0.3, foreground, 1.25)
  const muted = surfaceNear(background, surface, dark ? 0.3 : 0.22, foreground, 1.2)
  const hover = surfaceNear(background, surface, dark ? 0.55 : 0.45, foreground, 1.35)
  const secondary = surfaceNear(background, surface, dark ? 0.7 : 0.6, foreground, 1.45)
  const popover = dark
    ? surfaceNear(background, quieter(mix(background, "#FFFFFF", 0.14)), 0.5, foreground, 1.2)
    : surfaceNear(background, "#FFFFFF", 0.75, foreground, 1.2)
  const mutedForeground = readableOn(mix(foreground, background, 0.35), [background, card, popover, muted], foreground)
  // The faintest hairline that still shows on the page, a card and a popup.
  let border = mix(background, foreground, 0.4)
  for (let step = 6; step < 20; step++) {
    const candidate = mix(background, foreground, step / 50)
    if ([background, card, popover].every(behind => contrastRatio(candidate, behind) >= 1.15)) {
      border = candidate
      break
    }
  }
  const primaryForeground = labelOn(accent, background)
  return {
    dark,
    palette: {
      background, foreground, card, popover, muted, mutedForeground,
      accent: hover, secondary, border,
      input: mix(border, foreground, 0.1),
      ring: readableOn(accent, [background], away, 3),
      primary: accent,
      primaryForeground,
      // Hover moves the button away from its label, so the label only gains contrast.
      primaryHover: mix(accent, contrastRatio(primaryForeground, "#000000") > contrastRatio(primaryForeground, "#FFFFFF") ? "#000000" : "#FFFFFF", 0.1),
      graphLine: mix(background, foreground, 0.4),
      graphDot: mix(background, foreground, 0.18),
      inkMuted: readableOn(mix(foreground, background, 0.5), [background], foreground, 3),
      leaf: readableOn(dark ? "#9CBC6A" : "#5F7D36", [background], away),
      peach: "#FFB57F",
    },
  }
}

/** Every token a palette sets, including the PrompX names the app's own blocks, pills and labels
 *  read, so nothing keeps the base theme's colour under a palette. */
function tokensOf(palette: ThemePalette, surface: string): Record<string, string> {
  return {
    "--background": palette.background,
    "--foreground": palette.foreground,
    "--card": palette.card,
    "--card-foreground": palette.foreground,
    "--popover": palette.popover,
    "--popover-foreground": palette.foreground,
    "--primary": palette.primary,
    "--primary-foreground": palette.primaryForeground,
    "--ring": palette.ring,
    "--accent": palette.accent,
    "--accent-foreground": palette.foreground,
    "--secondary": palette.secondary,
    "--secondary-foreground": palette.foreground,
    "--muted": palette.muted,
    "--muted-foreground": palette.mutedForeground,
    "--border": palette.border,
    "--input": palette.input,
    "--graph-line": palette.graphLine,
    "--graph-dot": palette.graphDot,
    "--theme-surface": surface,
    "--theme-detail": palette.foreground,
    "--dashboard-primary": palette.primary,
    "--dashboard-primary-hover": palette.primaryHover,
    "--dashboard-primary-foreground": palette.primaryForeground,
    "--cream": palette.card,
    "--cream-deep": palette.muted,
    "--beige": palette.secondary,
    "--peach": palette.peach,
    "--leaf": palette.leaf,
    "--ink-soft": palette.mutedForeground,
    "--ink-muted": palette.inkMuted,
  }
}

export interface ResolvedAppearance {
  dark: boolean
  background: string
  tokens: Record<string, string>
}

export function resolveAppearance(theme: ThemePreference, custom: CustomThemeColors | null | undefined): ResolvedAppearance | null {
  if (theme === "custom") {
    if (!validCustomTheme(custom)) return null
    const { dark, palette } = deriveTheme(custom)
    return { dark, background: palette.background, tokens: tokensOf(palette, custom.surface) }
  }
  const preset = themePresets.find(candidate => candidate.id === theme)
  if (!preset) return null
  return { dark: preset.dark, background: preset.palette.background, tokens: tokensOf(preset.palette, preset.palette.card) }
}
