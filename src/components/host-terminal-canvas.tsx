import { useEffect, useRef, useState } from "react"
import { Terminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import { AlertCircleIcon, XIcon } from "lucide-react"
import { hostTerminalApi } from "@/api/host-terminal-api"
import { workspaceApi } from "@/api/workspace-api"
import { terminalClipboard, terminalClipboardAction } from "@/lib/terminal-clipboard"
import { terminalLinkRanges } from "@/lib/terminal-links"
import { terminalTheme } from "@/lib/terminal-theme"
import "@xterm/xterm/css/xterm.css"

export type HostShellState = "starting" | "ready" | "exited" | "error"
export interface HostCanvasControls { focus(): void; clear(): void }
export interface HostTab { id: string; name: string; cwd: string; reconnect?: boolean; command?: string; state: HostShellState }
export function HostTerminalCanvas({ tab, active, onState, onControls }: {
  tab: HostTab; active: boolean
  onState(id: string, state: HostShellState): void
  onControls(id: string, controls: HostCanvasControls | null): void
}) {
  const target = useRef<HTMLDivElement>(null)
  const activeRef = useRef(active)
  const fitRef = useRef<FitAddon | null>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const [error, setError] = useState("")
  const { id, cwd, reconnect, command } = tab
  useEffect(() => {
    activeRef.current = active
    if (active) {
      const frame = requestAnimationFrame(() => {
        if (target.current?.clientWidth) fitRef.current?.fit()
        if (!document.activeElement?.closest('[role="tablist"]')) terminalRef.current?.focus()
      })
      return () => cancelAnimationFrame(frame)
    }
  }, [active])

  useEffect(() => {
    let cancelled = false
    let disposeTerminal: (() => void) | undefined
    // xterm 5 schedules initial viewport work which outlives an immediate
    // dispose. Don't construct it in StrictMode's throwaway effect.
    void Promise.resolve().then(() => { if (!cancelled) disposeTerminal = mountTerminal() }).catch(reason => {
      if (!cancelled) { setError(reason instanceof Error ? reason.message : String(reason)); onState(id, "error") }
    })
    return () => { cancelled = true; disposeTerminal?.() }

    function mountTerminal() {
    if (!target.current) return
    let disposed = false, ready = false, created = false, offset = 0, timer = 0
    let readFailures = 0
    let inputQueue = Promise.resolve()
    const terminal = new Terminal({ fontSize: 13, fontFamily: '"Cascadia Code", "Cascadia Mono", Consolas, monospace', cursorBlink: true, cursorStyle: "bar", lineHeight: 1.2, scrollback: 2000, allowProposedApi: false, theme: terminalTheme })
    const fit = new FitAddon(); terminal.loadAddon(fit); terminal.open(target.current)
    if (target.current.clientWidth) fit.fit()
    terminalRef.current = terminal; fitRef.current = fit
    onControls(id, { focus: () => terminal.focus(), clear: () => { terminal.clear(); terminal.focus() } })
    const fail = (reason: unknown) => { if (!disposed) { ready = false; setError(reason instanceof Error ? reason.message : String(reason)); onState(id, "error") } }
    const report = (reason: unknown) => { if (!disposed) setError(reason instanceof Error ? reason.message : String(reason)) }
    const send = (text: string) => {
      const bytes = new TextEncoder().encode(text)
      inputQueue = inputQueue.then(async () => {
        for (let i = 0; i < bytes.length && ready && !disposed; i += 16 * 1024) {
          await hostTerminalApi.terminal({ sessionId: id, action: "write", data: btoa(String.fromCharCode(...bytes.slice(i, i + 16 * 1024))) })
        }
      }).catch(fail)
    }
    terminal.attachCustomKeyEventHandler(event => {
      // Let the dashboard handle this shortcut without sending it to the shell.
      if (event.ctrlKey && !event.altKey && !event.metaKey && event.code === "Backquote") return false
      const action = terminalClipboardAction(event, terminal.hasSelection())
      if (!action) return true // Ctrl+C without selection remains an interrupt.
      event.preventDefault(); event.stopPropagation()
      if (event.type !== "keydown" || event.repeat) return false
      if (action === "copy" && terminal.hasSelection()) void terminalClipboard.writeText(terminal.getSelection()).catch(report)
      if (action === "paste" && ready) void terminalClipboard.readText().then(text => { if (!disposed && ready && activeRef.current) terminal.paste(text) }).catch(report)
      return false
    })
    const links = terminal.registerLinkProvider({ provideLinks: (line, callback) => {
      const text = terminal.buffer.active.getLine(line - 1)?.translateToString(true) ?? ""
      // Highlight the characters on screen, not the normalized address that opens.
      callback(terminalLinkRanges(text).map(({ url, start, length }) => ({ text: url, range: { start: { x: start + 1, y: line }, end: { x: start + length, y: line } }, activate: () => { void workspaceApi.openUrl(url).catch(report) } })))
    } })
    const poll = async () => {
      if (disposed || !ready) return
      try {
        const output = await hostTerminalApi.terminal({ sessionId: id, action: "read", offset })
        if (disposed || !ready) return
        readFailures = 0
        offset = output.offset
        if (output.truncated) terminal.writeln("\r\n[Older output discarded; terminal history is limited to keep memory usage small.]")
        if (output.data) terminal.write(Uint8Array.from(atob(output.data), c => c.charCodeAt(0)))
        if (output.done) { ready = false; onState(id, "exited"); terminal.writeln(`\r\n[Shell exited${output.exitCode === null ? "" : ` · code ${output.exitCode}`} — open a new terminal to continue.]`); return }
      } catch (reason) {
        if (disposed || !ready) return
        // A read can safely resume at the same cursor. Never replay input or
        // create a replacement shell: the original command may still be running.
        if (/error sending request for url|failed to fetch|networkerror|timed out|timeout/i.test(String(reason)) && ++readFailures <= 3) {
          timer = window.setTimeout(() => void poll(), readFailures * 500)
          return
        }
        fail(reason); return
      }
      timer = window.setTimeout(() => void poll(), document.hidden ? 2500 : activeRef.current ? 120 : 1200)
    }
    void (async () => {
      // StrictMode's throwaway effect must not create/close the real session.
      await Promise.resolve()
      if (disposed) return
      if (!reconnect) await hostTerminalApi.terminal({ sessionId: id, action: "create", cwd, cols: Math.min(500, Math.max(2, terminal.cols)), rows: Math.min(250, Math.max(2, terminal.rows)) })
      created = true
      if (disposed) { await hostTerminalApi.terminal({ sessionId: id, action: "close" }); return }
      ready = true; onState(id, "ready"); if (activeRef.current) terminal.focus(); void poll()
      // Explicit launch buttons only send a fixed command into their fresh tab,
      // never into the user's existing shell, password prompt, or running agent.
      if (command && !reconnect) send(`${command}\r`)
    })().catch(fail)
    const input = terminal.onData(data => { if (ready && !disposed) send(data) })
    const resize = terminal.onResize(({ cols, rows }) => { if (ready) void hostTerminalApi.terminal({ sessionId: id, action: "resize", cols: Math.min(500, Math.max(2, cols)), rows: Math.min(250, Math.max(2, rows)) }).catch(fail) })
    const observer = new ResizeObserver(() => { if (!disposed && activeRef.current && target.current?.clientWidth) fit.fit() }); observer.observe(target.current)
    return () => {
      disposed = true; ready = false; window.clearTimeout(timer); observer.disconnect(); links.dispose(); input.dispose(); resize.dispose(); onControls(id, null)
      if (created) void hostTerminalApi.terminal({ sessionId: id, action: "close" }).catch(() => undefined)
      terminal.dispose(); terminalRef.current = null; fitRef.current = null
    }
    }
  }, [id, cwd, reconnect, command, onState, onControls])
  return <div className="host-terminal-canvas"><div ref={target} aria-label={`${tab.name} host command line`} className="host-terminal-xterm" />{error ? <div role="alert" className="host-terminal-shell-error"><AlertCircleIcon aria-hidden="true" /><span className="min-w-0 flex-1">{error}</span><button type="button" aria-label="Dismiss terminal error" onClick={() => setError("")}><XIcon className="size-4" /></button></div> : null}</div>
}
