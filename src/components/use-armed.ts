import { useEffect, useRef, useState } from "react"

/** A destructive action asks once more on the same button before it runs; the ask expires after 4 s. */
export function useArmed() {
  const [armed, setArmed] = useState<string | null>(null)
  const timer = useRef(0)
  const arm = (key: string) => { window.clearTimeout(timer.current); setArmed(key); timer.current = window.setTimeout(() => setArmed(null), 4000) }
  useEffect(() => () => window.clearTimeout(timer.current), [])
  return { armed, arm, disarm: () => setArmed(null) }
}
