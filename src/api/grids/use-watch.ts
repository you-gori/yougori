/** The React binding for a shared read, the shape `use-access-status.ts` already has. */
import { useCallback, useEffect, useSyncExternalStore } from "react"
import { watch, type EventKind, type Watch } from "@/api/grids/events"

export interface Watching<T> extends Watch<T> {
  refresh(): Promise<void>
}

/** Watches one shared read. `every` is how often this part of the page wants news; the most
 *  eager watcher sets the pace for everybody, so the engine is still asked once. */
export function useWatch<T>(
  name: string,
  read: () => Promise<T>,
  options: { every: number; on?: readonly EventKind[] },
): Watching<T> {
  const store = watch(name, read, { on: options.on })
  const snapshot = useSyncExternalStore(
    useCallback((listener: () => void) => store.subscribe(listener), [store]),
    useCallback(() => store.snapshot(), [store]),
  )
  const every = options.every
  useEffect(() => store.hold(every), [store, every])
  const refresh = useCallback(() => store.refresh(), [store])
  return { ...snapshot, refresh }
}
