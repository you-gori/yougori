import { useEffect, useState } from "react"

/** Errors that have had their full time on screen, by the view that showed them. Kept outside
 *  React so reopening the view, or a refresh repeating the same text, does not bring one back. */
const spent = new Map<string, Set<string>>()

/** An error for at most `ms` (20 seconds), then hidden. A different error gets its own time;
 *  once the view's source reports no error, anything it reports later is shown again. */
export function useFleeting(view: string, message: string | null | undefined, ms = 20_000): string | null {
  const [, expire] = useState(0)
  useEffect(() => {
    if (!message) { spent.delete(view); return }
    if (spent.get(view)?.has(message)) return
    const timer = window.setTimeout(() => {
      spent.set(view, (spent.get(view) ?? new Set<string>()).add(message))
      expire(count => count + 1)
    }, ms)
    return () => window.clearTimeout(timer)
  }, [view, message, ms])
  return message && !spent.get(view)?.has(message) ? message : null
}
