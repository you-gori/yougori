import { describe, expect, it } from "vitest"
import { contrastRatio, defaultCustomTheme, resolveAppearance, themePresets, validCustomTheme } from "./appearance"
import type { CustomThemeColors } from "@/types/platform"

/** How light a colour is, as its contrast with black, which rises with luminance. */
const lift = (hex: string) => contrastRatio(hex, "#000000")

/** What every theme must hold, preset or custom: text at WCAG AA on every surface it sits on, a
 *  primary button whose label reads, and hairlines that show on the page, a card and a popup
 *  without glaring. */
function expectReadable(tokens: Record<string, string>, name: string) {
  const token = (key: string) => {
    const value = tokens[key]
    expect(value, `${name} sets ${key}`).toMatch(/^#[\da-fA-F]{6}$/)
    return value!
  }
  const atLeast = (foreground: string, background: string, minimum: number) =>
    expect(contrastRatio(token(foreground), token(background)), `${name}: ${foreground} on ${background}`).toBeGreaterThanOrEqual(minimum)
  for (const surface of ["--background", "--card", "--popover", "--muted", "--accent", "--secondary"]) atLeast("--foreground", surface, 4.5)
  for (const surface of ["--background", "--card", "--popover", "--muted"]) atLeast("--muted-foreground", surface, 4.5)
  atLeast("--card-foreground", "--card", 4.5)
  atLeast("--popover-foreground", "--popover", 4.5)
  atLeast("--accent-foreground", "--accent", 4.5)
  atLeast("--secondary-foreground", "--secondary", 4.5)
  atLeast("--primary-foreground", "--primary", 4.5)
  atLeast("--dashboard-primary-foreground", "--dashboard-primary", 4.5)
  atLeast("--dashboard-primary-foreground", "--dashboard-primary-hover", 4.5)
  atLeast("--ink-soft", "--background", 4.5)
  atLeast("--leaf", "--background", 4.5)
  atLeast("--ink-muted", "--background", 3)
  atLeast("--ring", "--background", 3)
  for (const surface of ["--background", "--card", "--popover"]) {
    const edge = contrastRatio(token("--border"), token(surface))
    expect(edge, `${name}: the border shows on ${surface}`).toBeGreaterThanOrEqual(1.15)
    expect(edge, `${name}: the border does not glare on ${surface}`).toBeLessThanOrEqual(2)
  }
}

/** The five palettes this app shipped before, kept as custom inputs: loud surfaces, a near-black
 *  red and a navy, which the derivation has to turn into readable themes. */
const formerPresets: CustomThemeColors[] = [
  { background: "#F3E4C9", surface: "#BFA28C", accent: "#A98B76", detail: "#BABF94" },
  { background: "#2D0000", surface: "#6D0808", accent: "#757D6F", detail: "#EEEAD7" },
  { background: "#F5EBDD", surface: "#F2765E", accent: "#315B8C", detail: "#413333" },
  { background: "#010736", surface: "#0D1C42", accent: "#22396F", detail: "#FCF1D0" },
  { background: "#FFF5F5", surface: "#F7D6D0", accent: "#E2B4BD", detail: "#4A4A4A" },
]

describe("theme presets", () => {
  it("are the five stored ids, each with a real name", () => {
    expect(themePresets.map(preset => preset.id).sort()).toEqual(["theme1", "theme2", "theme3", "theme4", "theme5"])
    for (const preset of themePresets) expect(preset.name).not.toMatch(/^Theme \d/)
    expect(new Set(themePresets.map(preset => preset.name)).size).toBe(themePresets.length)
  })

  it("keep every text and border token readable on every surface", () => {
    for (const preset of themePresets) {
      const resolved = resolveAppearance(preset.id, null)!
      expect(resolved.dark).toBe(preset.dark)
      expect(resolved.background).toBe(preset.palette.background)
      expectReadable(resolved.tokens, preset.name)
    }
  })

  it("raise popups above the page: a step lighter on dark themes, white or lifted on light ones", () => {
    for (const preset of themePresets) {
      const { tokens } = resolveAppearance(preset.id, null)!
      if (preset.dark) expect(lift(tokens["--popover"]!), preset.name).toBeGreaterThan(lift(tokens["--background"]!))
      else expect(lift(tokens["--popover"]!), preset.name).toBeGreaterThanOrEqual(lift(tokens["--background"]!))
    }
  })

  it("set the PrompX blocks, pills and labels too, so none keeps the base theme's colour", () => {
    for (const preset of themePresets) {
      const { tokens } = resolveAppearance(preset.id, null)!
      expect(tokens["--cream"]).toBe(preset.palette.card)
      expect(tokens["--beige"]).toBe(preset.palette.secondary)
      expect(tokens["--ink-muted"]).toBe(preset.palette.inkMuted)
    }
  })
})

describe("custom themes", () => {
  it("rejects incomplete colors", () => {
    expect(validCustomTheme({ ...defaultCustomTheme, accent: "red" })).toBe(false)
    expect(resolveAppearance("custom", null)).toBeNull()
  })

  it("derive readable text, popups and hairlines from any four colours", () => {
    const inputs: CustomThemeColors[] = [
      defaultCustomTheme,
      ...formerPresets,
      { background: "#FFFFFF", surface: "#F4F4F4", accent: "#EEEEEE", detail: "#FAFAFA" },
      { background: "#000000", surface: "#000000", accent: "#111111", detail: "#050505" },
      { background: "#777777", surface: "#FF0000", accent: "#888888", detail: "#7A7A7A" },
    ]
    for (const colors of inputs) {
      const resolved = resolveAppearance("custom", colors)!
      expect(resolved.background).toBe(colors.background)
      expect(resolved.tokens["--primary"]).toBe(colors.accent)
      expectReadable(resolved.tokens, `custom ${colors.background}`)
    }
  })

  it("lift popups off the page rather than painting them the surface colour", () => {
    for (const colors of [defaultCustomTheme, ...formerPresets]) {
      const { dark, tokens } = resolveAppearance("custom", colors)!
      if (dark) expect(lift(tokens["--popover"]!), colors.background).toBeGreaterThan(lift(colors.background))
      else expect(lift(tokens["--popover"]!), colors.background).toBeGreaterThanOrEqual(lift(colors.background))
      expect(tokens["--popover"]).not.toBe(colors.surface)
    }
  })
})
