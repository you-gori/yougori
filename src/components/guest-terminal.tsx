import { modelTerminalChatInput } from "@/lib/model-terminal-chat"
import { useEffect, useRef, useState } from "react"
import { RefreshCwIcon, XIcon } from "lucide-react"
import { Button } from "@/components/ui/button"
import { Terminal } from "@xterm/xterm"
import { FitAddon } from "@xterm/addon-fit"
import "@xterm/xterm/css/xterm.css"
import { workspaceApi } from "@/api/workspace-api"
import { TerminalLinkCards } from "@/components/terminal-link-cards"
import { osc52CopyText, terminalClipboard, terminalClipboardAction } from "@/lib/terminal-clipboard"
import { extractTerminalLinks, mergeTerminalLinks, normalizeTerminalLink } from "@/lib/terminal-links"
import { terminalInstallerInput, type TerminalReadyHandler, type TerminalInstallerId } from "@/lib/terminal-installers"
import { tourInstallerStarted } from "@/lib/instructions-tour"
import { terminalTheme } from "@/lib/terminal-theme"

export function GuestTerminal({ environmentId, sessionId, active, onReady, installer, modelChat }: { environmentId: string; sessionId: string; active: boolean; onReady?: TerminalReadyHandler; installer?: TerminalInstallerId; modelChat?: boolean }) {
  const targetRef = useRef<HTMLDivElement>(null)
  const terminalRef = useRef<Terminal | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const activeRef = useRef(active)
  const [error, setError] = useState("")
  const [disconnected, setDisconnected] = useState(false)
  const [attempt, setAttempt] = useState(0)
  const [links, setLinks] = useState<string[]>([])
  // A guest program may ask to copy (OSC 52). The user decides per terminal; until then each request waits here.
  const [pendingCopy, setPendingCopy] = useState<string | null>(null)
  const copyConsent = useRef<"ask" | "allow" | "deny">("ask")

  useEffect(() => {
    activeRef.current = active
    const frame = active ? requestAnimationFrame(() => { fitRef.current?.fit(); terminalRef.current?.focus() }) : 0
    return () => cancelAnimationFrame(frame)
  }, [active])

  useEffect(() => {
    // Wait until the mounted view has a frame. React's development lifecycle
    // can dispose an immediate xterm before its internal viewport timer fires.
    // Cancelling this frame also avoids creating a throwaway native PTY.
    const initialize = () => {
      const target = targetRef.current
      if (!target) return
      const nativeSessionId = `term-${crypto.randomUUID()}`
      let disposed = false, timer = 0, linkTimer = 0, offset = 0, ready = false, created = false
      let readFailures = 0
      let unfollow: (() => void) | undefined
      let inputQueue = Promise.resolve()
      let completedLinks: string[] = []
      const terminal = new Terminal({ fontSize: 13, fontFamily: '"Cascadia Code", "Cascadia Mono", Consolas, monospace', cursorBlink: true, scrollback: 3000, theme: terminalTheme })
      terminal.options.disableStdin = Boolean((installer || modelChat) && attempt === 0)
      const fit = new FitAddon(); terminal.loadAddon(fit); terminal.open(target); fit.fit()
      terminalRef.current = terminal; fitRef.current = fit
      const fail = (reason: unknown) => {
        if (disposed) return
        ready = false
        terminal.options.disableStdin = true
        window.clearTimeout(timer)
        unfollow?.(); unfollow = undefined
        if (created) {
          created = false
          void workspaceApi.terminal(environmentId, nativeSessionId, "close").catch(() => undefined)
        }
        const detail = reason instanceof Error ? reason.message : String(reason)
        setError(/error sending request for url|failed to fetch|networkerror/i.test(detail) ? "Lost connection to the environment. Reconnect to open a new terminal session." : detail)
        setDisconnected(true)
        onReady?.(sessionId, false, true)
      }
      terminal.attachCustomKeyEventHandler(event => {
        const action = terminalClipboardAction(event, terminal.hasSelection())
        if (!action) return true // Ctrl+C without a selection remains SIGINT.
        event.preventDefault()
        event.stopPropagation()
        if (event.type !== "keydown" || event.repeat) return false
        const selected = terminal.getSelection()
        if (action === "copy" && selected) {
          void terminalClipboard.writeText(selected).catch(() => { if (!disposed) setError("Couldn't copy to the clipboard. Please try again.") })
        } else if (action === "paste" && ready && !terminal.options.disableStdin) {
          void terminalClipboard.readText().then(text => {
            // Never deliver a delayed clipboard read into a closed or hidden tab.
            if (!disposed && ready && !terminal.options.disableStdin && activeRef.current) terminal.paste(text)
          }).catch(() => { if (!disposed) setError("Couldn't read the clipboard. Please try Ctrl+V again or use right-click Paste.") })
        }
        return false
      })
      const collectLinks = () => {
        if (disposed) return
        const buffer = terminal.buffer.active
        const cursorRow = buffer.baseY + buffer.cursorY
        let completedText = "", currentText = "", line = "", containsCursor = false
        for (let row = Math.max(0, buffer.length - 200); row < buffer.length; row++) {
          const wraps = buffer.getLine(row + 1)?.isWrapped
          containsCursor ||= row === cursorRow
          line += buffer.getLine(row)?.translateToString(!wraps) ?? ""
          if (!wraps) {
            if (containsCursor) currentText += line + "\n"
            else completedText += line + "\n"
            line = ""; containsCursor = false
          }
        }
        // The cursor's logical line can still change as output arrives or the
        // user types. Show its links, but replace them on the next scan instead
        // of saving partial URLs in history. Wrapped rows belong to one line.
        completedLinks = mergeTerminalLinks(completedLinks, extractTerminalLinks(completedText))
        setLinks(mergeTerminalLinks(completedLinks, extractTerminalLinks(currentText)))
      }
      // Guest OSC 52 copies are considered only right after a click or key press here,
      // and reach the clipboard only after the user allows copies from this terminal.
      let lastGesture = -Infinity
      const gesture = () => { lastGesture = performance.now() }
      target.addEventListener("pointerup", gesture, true)
      target.addEventListener("keydown", gesture, true)
      const guestCopy = terminal.parser.registerOscHandler(52, data => {
        const text = osc52CopyText(data, performance.now() - lastGesture, !disposed && activeRef.current && document.hasFocus() && target.contains(document.activeElement))
        if (text === null || disposed || copyConsent.current === "deny") return true
        if (copyConsent.current === "allow") void terminalClipboard.writeText(text).catch(() => { if (!disposed) setError("Couldn't copy to the clipboard. Please try again.") })
        else setPendingCopy(text)
        return true
      })
      // OSC 8 links can hide their URL behind a label. Observe them, but do not
      // consume the sequence.
      const hyperlink = terminal.parser.registerOscHandler(8, data => {
        const url = normalizeTerminalLink(data.slice(data.indexOf(";") + 1))
        if (url && !disposed) {
          completedLinks = mergeTerminalLinks(completedLinks, [url])
          setLinks(previous => mergeTerminalLinks(previous, [url]))
        }
        return false
      })
      const queueLinkScan = () => {
        if (disposed || linkTimer) return
        linkTimer = window.setTimeout(() => { linkTimer = 0; collectLinks() }, 250)
      }
      const ended = () => { terminal.writeln("\r\n[Session ended]"); ready = false; onReady?.(sessionId, false, true); setDisconnected(true) }
      const poll = async () => {
        if (disposed) return
        try {
          const output = await workspaceApi.terminal(environmentId, nativeSessionId, "read", { offset })
          if (disposed || !ready) return
          readFailures = 0
          offset = output.offset
          if (output.data) terminal.write(Uint8Array.from(atob(output.data), c => c.charCodeAt(0)), queueLinkScan)
          if (output.done) { ended(); return }
        } catch (reason) {
          if (disposed || !ready) return
          // Reads are safe to repeat at the same output offset. Never retry input writes.
          if (/error sending request for url|failed to fetch|networkerror|timed out|timeout/i.test(String(reason)) && ++readFailures <= 3) {
            timer = window.setTimeout(() => void poll(), readFailures * 500)
            return
          }
          fail(reason); return
        }
        timer = window.setTimeout(() => void poll(), document.visibilityState === "hidden" ? 2000 : activeRef.current ? 150 : 900)
      }
      // The engine pushes output as it appears; polling remains for engines without events.
      const follow = async () => {
        try {
          const stop = await workspaceApi.terminalFollow(environmentId, nativeSessionId, offset, frame => {
            if (disposed || !ready) return
            if (frame.error) { fail(new Error(frame.error)); return }
            if (frame.data && typeof frame.offset === "number") { offset = frame.offset; terminal.write(Uint8Array.from(atob(frame.data), c => c.charCodeAt(0)), queueLinkScan) }
            if (frame.done) { unfollow?.(); unfollow = undefined; ended() }
          })
          if (disposed || !ready) { stop(); return }
          unfollow = stop
        } catch {
          if (!disposed && ready) void poll()
        }
      }
      void workspaceApi.terminal(environmentId, nativeSessionId, "create", { cols: terminal.cols, rows: terminal.rows }).then(async () => {
        if (disposed) { void workspaceApi.terminal(environmentId, nativeSessionId, "close").catch(() => undefined); return }
        created = true; ready = true; if (activeRef.current) terminal.focus(); void follow()
        onReady?.(sessionId, true)
        if (modelChat && attempt === 0) {
          const command = modelTerminalChatInput()
          for (let start = 0; start < command.length && !disposed && ready; start += 2048) {
            await workspaceApi.terminal(environmentId, nativeSessionId, "write", { data: btoa(command.slice(start, start + 2048)) })
          }
          if (!disposed) terminal.options.disableStdin = false
        }
        if (installer && attempt === 0) {
          terminal.writeln(`\r\n[Preparing ${installer} installer in this environment...]`)
          const command = await workspaceApi.prepareInstaller(environmentId, nativeSessionId, installer)
          if (disposed || !ready) return
          // Fresh dedicated PTY only: never paste into an existing program or a
          // half-written shell command. Send one short command plus Enter directly.
          const data = btoa(terminalInstallerInput(command))
          await workspaceApi.terminal(environmentId, nativeSessionId, "write", { data })
          if (!disposed) tourInstallerStarted(environmentId, installer)
          if (!disposed) terminal.options.disableStdin = false
        }
      }).catch(fail)
      const input = terminal.onData(data => {
        if (!ready || disposed || terminal.options.disableStdin) return
        const bytes = new TextEncoder().encode(data)
        inputQueue = inputQueue.then(async () => {
          for (let start = 0; start < bytes.length && ready && !disposed; start += 16 * 1024) {
            const encoded = btoa(String.fromCharCode(...bytes.slice(start, start + 16 * 1024)))
            await workspaceApi.terminal(environmentId, nativeSessionId, "write", { data: encoded })
          }
        }).catch(reason => { if (!disposed) setError(String(reason)) })
      })
      const resize = terminal.onResize(({ cols, rows }) => { if (ready) void workspaceApi.terminal(environmentId, nativeSessionId, "resize", { cols, rows }).catch(() => undefined) })
      const observer = new ResizeObserver(() => { if (!disposed && activeRef.current && target.clientWidth) fit.fit() }); observer.observe(target)
      return () => { disposed = true; onReady?.(sessionId, false); unfollow?.(); if (created) void workspaceApi.terminal(environmentId, nativeSessionId, "close").catch(() => undefined); ready = false; window.clearTimeout(timer); window.clearTimeout(linkTimer); hyperlink.dispose(); guestCopy.dispose(); target.removeEventListener("pointerup", gesture, true); target.removeEventListener("keydown", gesture, true); observer.disconnect(); input.dispose(); resize.dispose(); terminal.dispose(); terminalRef.current = null; fitRef.current = null }
    }
    let release: (() => void) | undefined
    const frame = requestAnimationFrame(() => { release = initialize() })
    return () => { cancelAnimationFrame(frame); release?.() }
  }, [environmentId, sessionId, onReady, installer, modelChat, attempt])

  const reconnect = () => { setError(""); setDisconnected(false); setLinks([]); setPendingCopy(null); copyConsent.current = "ask"; setAttempt(value => value + 1) }
  const answerCopy = (choice: "once" | "always" | "block") => {
    const text = pendingCopy
    setPendingCopy(null)
    if (choice === "block") { copyConsent.current = "deny"; return }
    if (choice === "always") copyConsent.current = "allow"
    if (text !== null) void terminalClipboard.writeText(text).catch(() => setError("Couldn't copy to the clipboard. Please try again."))
  }
  return <div data-tour="guest-terminal" className="flex size-full min-h-0 min-w-0 flex-col bg-[#0c0c0c]">
    <div className="relative min-h-0 flex-1 p-3">
      <div aria-label="Terminal" className="size-full" ref={targetRef} />
      {error ? <div className="absolute inset-x-3 bottom-3 flex items-start gap-2 rounded border border-destructive/30 bg-background p-3 text-sm text-destructive-foreground" role="alert">
        <p className="min-w-0 flex-1 break-words">{error}</p>
        <Button size="icon-xs" variant="ghost" aria-label="Dismiss terminal error" onClick={() => setError("")}><XIcon aria-hidden="true" /></Button>
      </div> : null}
    </div>
    {pendingCopy !== null ? <div role="group" aria-label="Clipboard request" className="flex shrink-0 flex-wrap items-center gap-2 border-t border-white/10 px-4 py-2 text-xs text-white/70">
      <span className="min-w-0 flex-1">A program in this terminal wants to copy {pendingCopy.length.toLocaleString()} characters to your clipboard.</span>
      <Button size="xs" variant="outline" onClick={() => answerCopy("once")}>Copy</Button>
      <Button size="xs" variant="ghost" onClick={() => answerCopy("always")}>Always allow here</Button>
      <Button size="xs" variant="ghost" onClick={() => answerCopy("block")}>Block</Button>
    </div> : null}
    {disconnected ? <div className="flex shrink-0 items-center justify-between gap-3 border-t border-white/10 px-4 py-2 text-xs text-white/60">
      <span>Session disconnected</span><Button size="xs" variant="outline" onClick={reconnect} title="Opens a fresh shell. Previous commands and installers are not replayed."><RefreshCwIcon aria-hidden="true" />Reconnect</Button>
    </div> : null}
    <TerminalLinkCards links={links} />
  </div>
}
