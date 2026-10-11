export const terminalClipboard = {
  async readText(): Promise<string> {
    if ("__TAURI_INTERNALS__" in window) {
      const { readText } = await import("@tauri-apps/plugin-clipboard-manager")
      return readText()
    }
    return navigator.clipboard.readText()
  },
  async writeText(text: string): Promise<void> {
    if ("__TAURI_INTERNALS__" in window) {
      const { writeText } = await import("@tauri-apps/plugin-clipboard-manager")
      return writeText(text)
    }
    return navigator.clipboard.writeText(text)
  },
}

const osc52Gesture = 2000, osc52Limit = 1024 * 1024

/**
 * Text a guest program asked to copy with OSC 52 (`Pc;base64`), or null. TUIs such
 * as Codex copy their own mouse selections this way. Only writes are considered, and
 * only right after the user clicked or typed in that focused terminal, so background
 * output cannot replace the clipboard. The terminal still asks the user before the
 * first copy reaches the clipboard. Clipboard reads (`?`) are never answered.
 */
export function osc52CopyText(data: string, sinceGestureMs: number, focused: boolean): string | null {
  if (!focused || sinceGestureMs < 0 || sinceGestureMs > osc52Gesture || data.length > osc52Limit) return null
  const separator = data.indexOf(";")
  if (separator < 0 || !/^[cpqs0-7]*$/.test(data.slice(0, separator))) return null
  const encoded = data.slice(separator + 1)
  if (!encoded || !/^[A-Za-z0-9+/]*={0,2}$/.test(encoded)) return null
  try { return new TextDecoder("utf-8", { fatal: true }).decode(Uint8Array.from(atob(encoded), c => c.charCodeAt(0))) }
  catch { return null }
}

// Called only by the focused terminal's keyboard handler, never by guest output.
export function terminalClipboardAction(event: Pick<KeyboardEvent, "key" | "ctrlKey" | "metaKey" | "shiftKey" | "altKey">, hasSelection: boolean): "copy" | "paste" | null {
  if (event.altKey) return null
  const key = event.key.toLowerCase()
  if (key === "insert" && event.shiftKey && !event.ctrlKey && !event.metaKey) return "paste"
  if (!event.ctrlKey && !event.metaKey) return null
  if (key === "v") return "paste"
  if (key === "c" && (hasSelection || event.shiftKey || event.metaKey)) return "copy"
  return null
}
