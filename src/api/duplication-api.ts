import { run } from "@/api/platform-api"
import type { CloudDeployRequest } from "@/api/cloud-api"
import type { PlatformState } from "@/types/platform"

export interface CloudCopyLocation {
  provider: "aws" | "azure" | "google"
  account: string
  region: string
  instance: string
  resourceGroup: string
  bucket: string
}
export interface DuplicationRequest {
  operationId: string
  environmentId: string
  name: string
  destination: "local" | "cloud"
  source: CloudCopyLocation | null
  target: CloudDeployRequest | null
  targetBucket: string
  storageDrive: string | null
  reviewed: boolean
  localFiles?: { image: string; paths: string[]; storageGb: number } | null
}
export interface DuplicationJob {
  request: DuplicationRequest
  environmentId: string
  status: "running" | "failed" | "interrupted" | "complete"
  phase: string
  error: string | null
  resources: string[]
  completed?: Record<string, unknown>
  /** A step that was sent and whose result is not written down yet. */
  pending?: string | null
}
/** Whether a copy that stopped part way may be discarded here. The engine keeps a cloud copy's
 *  resources so it can be resumed, and refuses to remove them before it finishes; a copy that made
 *  none yet, or a copy of files, may go. */
export const discardable = (job: DuplicationJob) => job.status !== "complete" && job.status !== "running" && !job.pending && (!job.resources.length || Boolean(job.request.localFiles))
export const duplicationApi = {
  /** Removes a copy's temporary transfer resources at the provider. A copy that never finished is
   *  then forgotten (discarded); a finished one keeps its record, marked cleaned up. */
  cleanup: (operationId: string) => run<PlatformState>("cleanup_environment_duplication", { operationId }, () => { throw new Error("Cleaning up a copy needs Yougori Desktop") }),
  /** Gives up a copy that stopped part way: removes what it made at the provider and forgets it. The
   *  engine takes this only from Yougori's own window, and only where nothing the copy made would be
   *  left behind unknown. Call it only from the confirmation in `GiveUpCopy`. */
  abandon: (operationId: string) => run<PlatformState>("cleanup_environment_duplication", { operationId, abandon: true }, () => { throw new Error("Giving up a copy needs Yougori Desktop") }),
  inspectSource: (environmentId: string, source: CloudCopyLocation) => run<{ ready: boolean; disk: string; bootMode: "uefi" | "legacy-bios" }>("inspect_duplication_source", { environmentId, source }, () => { throw new Error("Source VM inspection requires Yougori Desktop and the provider CLI") }),
  duplicate: (request: DuplicationRequest) => run<PlatformState>("duplicate_environment", { request }, () => { throw new Error("Cloud duplication requires Yougori Desktop and the provider CLI") }),
}
