import { useEffect, useState, useSyncExternalStore } from "react"

let active: string | null = null
const listeners = new Set<() => void>()

export function getTopicWalkthrough() { return active }
export function setTopicWalkthrough(id: string | null) {
  if (active === id) return
  active = id
  for (const notify of listeners) notify()
}
export function useTopicWalkthrough() {
  return useSyncExternalStore(notify => { listeners.add(notify); return () => { listeners.delete(notify) } }, getTopicWalkthrough, () => null)
}

// Keep a dialog nonmodal until it closes if a walkthrough opened it. Otherwise
// completing the tour would switch an already-open dialog back to modal and
// briefly put its backdrop above its own controls.
export function useTopicWalkthroughModal(open: boolean) {
  const topic = useTopicWalkthrough()
  const [openedDuringTour, setOpenedDuringTour] = useState(false)
  useEffect(() => {
    if (!open) setOpenedDuringTour(false)
    else if (topic) setOpenedDuringTour(true)
  }, [open, topic])
  return Boolean(topic || openedDuringTour)
}

export const instructionTargets: Record<string, readonly string[]> = {
  settings: ['[data-tour="settings"]', '[data-instruction="settings-dialog"]', '[data-instruction="settings-dialog"]'],
  container: ['[data-tour="new-environment"]', '[data-instruction-kind="container"]', '[data-tour="create-submit"]'],
  gpu: ['[data-tour="new-environment"]', '[data-instruction-kind="gpu"]', '[data-tour="create-submit"]'],
  microvm: ['[data-tour="new-environment"]', '[data-instruction-kind="microVm"]', '[data-tour="create-submit"]'],
  vm: ['[data-tour="new-environment"]', '[data-instruction-kind="fullVm"]', '[data-tour="create-submit"]'],
  cloud: ['[data-tour="new-environment"]', '[data-instruction-kind="cloud"]', '[data-create-environment]'],
  shared: ['[data-tour="new-environment"]', '[data-instruction-kind="shared"]', '[data-create-environment]'],
  runpod: ['[data-tour="new-environment"]', '[data-instruction-kind="neocloud"]', '[data-create-environment]'],
  public: ['[aria-label="Add or manage saved domain setups"]', '[data-instruction="public-presets-dialog"]', '[data-environment-id] [data-tour="node-port"]'],
  share: ['[data-environment-id] [aria-label^="Share "][aria-label$=" via Tunnel"]', '[data-instruction="sharing-dialog"]', '[data-instruction="sharing-dialog"]'],
  vault: ['[aria-label="Personal Vault MCP"]', '[data-instruction="vault-dialog"]', '[data-instruction="vault-dialog"]'],
  model: ['[data-instruction="model-trigger"]', '[data-instruction="model-dialog"]', '[data-instruction="model-dialog"]'],
  list: ['[data-environment-canvas]', '[aria-label="Environments"]', '[aria-label="Environments"]'],
  cli: ['[data-instruction-view="cli"]', '[aria-label="Yougori CLI"]', '[aria-label="Yougori CLI"]'],
  commands: ['[data-instruction-view="cli"]', '[aria-label="Yougori CLI"]', '[aria-label="Yougori CLI"]'],
  duplicate: ['[aria-label^="Duplicate "]', '[aria-label^="Duplicate "]', '[data-environment-id]'],
  delete: ['[data-environment-id]', '[data-environment-id]', '[data-environment-id]'],
  reclaim: ['[aria-label="Host resources and storage"]', '[data-instruction="reclaim"]', '[aria-label="Host resources and storage"]'],
  theme: ['[data-tour="theme"]', '[data-instruction="theme-dialog"]', '[data-instruction="theme-dialog"]'],
}
