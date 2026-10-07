import { useState, useSyncExternalStore } from "react"
import type { CloudProfile } from "@/api/cloud-api"

// Keep unfinished forms for this app session, including when their entry point
// unmounts. Only paths are held here; private key contents are never read.
const drafts = new Map<string, CloudProfile>()
const listeners = new Set<() => void>()
const subscribe = (listener: () => void) => {
  listeners.add(listener)
  return () => { listeners.delete(listener) }
}

export function useCloudProfileDraft(environmentId?: string, initialProfile?: Partial<CloudProfile>) {
  const [defaults] = useState<CloudProfile>(() => ({ name: "", vendor: "aws", host: "", port: 22, username: "ec2-user", identityFile: "", hostKey: "", ...initialProfile }))
  const key = environmentId ?? "new"
  const profile = useSyncExternalStore(subscribe, () => drafts.get(key) ?? defaults)
  const setProfile = (next: CloudProfile) => {
    drafts.set(key, next)
    listeners.forEach(listener => listener())
  }
  return { profile, setProfile, reset: () => setProfile(defaults) }
}
