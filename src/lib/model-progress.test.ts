import { expect, it } from "vitest"
import type { GpuOptimizer, ModelStatus } from "@/api/projects-api"
import { modelProgress } from "./model-progress"

const optimizer: GpuOptimizer = { supported: true, enabled: true, pinned: false, resident: false, loading: false, active: 0, pending: 1, idleTimeoutSeconds: 0, allocatedBytes: null }
const queued = (waitingFor?: string): ModelStatus => ({ status: "queued", model: "acme/model", error: null, optimizer: waitingFor ? { ...optimizer, waitingFor } : optimizer })

it("says which model holds the GPU and what to do, while a model waits for it", () => {
  expect(modelProgress(queued("Model A still holds the GPU (paused or not answering). Resume or stop Model A to let this model load.")))
    .toBe("Waiting for GPU · Model A still holds the GPU (paused or not answering). Resume or stop Model A to let this model load.")
  expect(modelProgress(queued())).toBe("Waiting for GPU")
})
