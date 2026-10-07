import type { Environment } from "@/types/platform"

export function needsCudaUpdate(environment: Environment, error: string | null | undefined) {
  return environment.provider === "yougoriCuda" && Boolean(error && /\[YOUGORI_CUDA_UPDATE_REQUIRED\]|CUDA runtime update is (?:required|available)/i.test(error))
}

