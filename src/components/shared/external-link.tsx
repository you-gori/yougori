import type { ReactNode } from "react"
import { workspaceApi } from "@/api/workspace-api"

/** Returns a normalized http(s) address without embedded credentials, or null. */
function webUrl(value: string) {
  try {
    const url = new URL(value)
    return (url.protocol === "http:" || url.protocol === "https:") && !url.username && !url.password ? url.href : null
  } catch {
    return null
  }
}

// Provider-supplied addresses open in the system browser through the validated
// native command, never in a new webview window. Other schemes render as text.
export function ExternalLink({ href, className, children, onError }: { href: string; className?: string; children: ReactNode; onError?(message: string): void }) {
  const url = webUrl(href)
  if (!url) return <span className={className}>{children}</span>
  return <a className={className} href={url} rel="noreferrer" onClick={event => {
    event.preventDefault()
    void workspaceApi.openUrl(url).catch(reason => onError?.(reason instanceof Error ? reason.message : String(reason)))
  }}>{children}</a>
}
