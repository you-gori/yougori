import { useEffect, useState } from "react"
import { modelsApi } from "@/api/projects-api"
import { workspaceApi } from "@/api/workspace-api"
import type { Environment } from "@/types/platform"
import { modelProgress } from "@/lib/model-progress"

export function ModelNodeProgress({ environment }: { environment: Environment }) {
  const [output, setOutput] = useState("")
  const [phase, setPhase] = useState("Preparing CUDA runtime and container image")
  const [ready, setReady] = useState(false)
  const { id, status, lastError } = environment

  useEffect(() => {
    if (status !== "provisioning" && status !== "running") return
    let active = true
    let timer = 0
    const refresh = async () => {
      if (status === "running") {
        try {
          const health = await modelsApi.status(id)
          if (active) {
            setReady(health.status === "ready")
            setPhase(modelProgress(health))
          }
        } catch { if (active) setPhase("Starting model server") }
      } else if (active) {
        setReady(false)
        setPhase("Preparing CUDA runtime and container image")
      }
      try {
        const logs = await workspaceApi.logs(id)
        if (active) setOutput(logs)
      } catch { /* No container log exists until the image has been created. */ }
      if (active) timer = window.setTimeout(refresh, 3000)
    }
    void refresh()
    return () => { active = false; window.clearTimeout(timer) }
  }, [id, status])

  if (status !== "provisioning" && status !== "running" && status !== "error") return null
  if (ready && status === "running") return null
  const lines = output.trim().split("\n").slice(-6).join("\n").slice(-1800)
  return <div className="nodrag mt-3 min-w-0 border-t pt-2 text-[10px]" role="status" aria-label={`Model setup for ${environment.name}`}>
    <div className="font-medium text-muted-foreground">{status === "error" ? "Model setup needs attention" : phase}</div>
    {lastError ? <p className="mt-1 max-h-16 overflow-auto whitespace-pre-wrap break-words text-destructive">{lastError}</p> : null}
    <pre aria-label="Model setup logs" className="mt-1 max-h-24 overflow-auto whitespace-pre-wrap break-all rounded bg-[#0c0c0c] px-2 py-1.5 font-mono text-[10px] leading-4 text-[#cccccc]">{lines || (status === "provisioning" ? "Waiting for container logs…" : "Waiting for model output…")}</pre>
  </div>
}
