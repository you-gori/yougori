import type { Environment, EnvironmentKind } from "@/types/platform"
import { environmentKindLabel } from "@/lib/domain"

// A presentation category, not a new disk format or isolation boundary.
// Existing CUDA containers keep their IDs, provider, snapshots and files.
export type EnvironmentCategory = EnvironmentKind | "gpu"
export function environmentCategory(environment: Pick<Environment, "kind" | "provider">): EnvironmentCategory {
  return environment.kind === "container" && environment.provider === "yougoriCuda" ? "gpu" : environment.kind
}
export function environmentLabel(environment: Pick<Environment, "kind" | "provider"> & Partial<Pick<Environment,"runtime">>) {
  if(environment.runtime?.startsWith("sandbox-vm://"))return "Sandbox VM"
  if(environment.runtime?.startsWith("shared://"))return "Shared environment"
  return environmentCategory(environment) === "gpu" ? "GPU · NVIDIA CUDA" : environmentKindLabel[environment.kind]
}
