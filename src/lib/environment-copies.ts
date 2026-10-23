import type { DuplicationJob } from "@/api/duplication-api"
import type { Environment } from "@/types/platform"

/** The provider a copy's resources are at, as a person knows it. */
export const providerName = (job: DuplicationJob) => ({ aws: "AWS", azure: "Azure", google: "Google Cloud" } as Record<string, string>)[job.request.target?.provider ?? job.request.source?.provider ?? ""] ?? "your provider"

/** The copy, if any, a row speaks for: its own, once the copy's environment exists, otherwise the
 *  one its original is making. A copy is told about in one place only. */
export function copyFor(environment: Environment, jobs: Record<string, DuplicationJob>, environments: Environment[]): [string, DuplicationJob] | undefined {
  return Object.entries(jobs).find(([, job]) => job.environmentId === environment.id)
    ?? Object.entries(jobs).find(([, job]) => job.request.environmentId === environment.id && job.status !== "complete" && !environments.some(other => other.id === job.environmentId))
}
