import { useEffect, useState } from "react"
import { hubApi } from "@/api/hub-api"
import type { SourceRef } from "./contract"

/** A version split as semver orders it: three numbers, then the prerelease parts. */
function parts(version: string): { numbers: number[]; prerelease: string[] } {
  const plain = version.trim().split("+")[0] ?? ""
  const dash = plain.indexOf("-")
  const core = dash < 0 ? plain : plain.slice(0, dash)
  const prerelease = dash < 0 ? "" : plain.slice(dash + 1)
  const numbers = core.split(".").map(part => (/^\d+$/.test(part) ? Number(part) : NaN))
  return { numbers, prerelease: prerelease ? prerelease.split(".") : [] }
}

/** Whether `candidate` comes after `current`, as semver orders versions. A version that isn't
 *  three plain numbers is never treated as newer. */
export function isNewerVersion(candidate: string | null | undefined, current: string | null | undefined): boolean {
  if (!candidate || !current) return false
  const a = parts(candidate)
  const b = parts(current)
  if (a.numbers.length !== 3 || b.numbers.length !== 3 || [...a.numbers, ...b.numbers].some(Number.isNaN)) return false
  for (let at = 0; at < 3; at++) {
    const [x, y] = [a.numbers[at] ?? 0, b.numbers[at] ?? 0]
    if (x !== y) return x > y
  }
  // The same numbers: a release comes after its prereleases.
  if (!a.prerelease.length || !b.prerelease.length) return !a.prerelease.length && b.prerelease.length > 0
  for (let at = 0; at < Math.max(a.prerelease.length, b.prerelease.length); at++) {
    const x = a.prerelease[at]
    const y = b.prerelease[at]
    if (x === undefined) return false
    if (y === undefined) return true
    if (x === y) continue
    const numeric = [/^\d+$/.test(x), /^\d+$/.test(y)]
    if (numeric[0] && numeric[1]) return Number(x) > Number(y)
    if (numeric[0] !== numeric[1]) return Boolean(numeric[1])
    return x > y
  }
  return false
}

/** The newest version of the Hub template a setup was made from, when it is newer than the one the
 *  setup runs; `null` otherwise, or when the Hub can't be reached. Nothing changes by asking. */
export function useNewerVersion(source: SourceRef | null | undefined): string | null {
  const hub = source?.kind === "hub" ? source : null
  const publisher = hub?.publisher
  const name = hub?.name
  const [latest, setLatest] = useState<{ item: string; version: string | null } | null>(null)
  useEffect(() => {
    if (!publisher || !name) return
    let live = true
    hubApi.detail(publisher, name)
      // A removed item offers no update, whatever its last version was.
      .then(item => { if (live) setLatest({ item: `${publisher}/${name}`, version: item.state === "active" ? item.latestVersion ?? item.version?.version ?? null : null }) })
      .catch(() => undefined)
    return () => { live = false }
  }, [publisher, name])
  const found = latest && latest.item === `${publisher}/${name}` ? latest.version : null
  return hub && isNewerVersion(found, hub.version) ? found : null
}
