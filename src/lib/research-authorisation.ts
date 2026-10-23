/** What a person authorised research to do, kept until Swarm Mining's own setup is given it.
 *
 *  Research is the one purpose the create wizard does not start: a worker is made on the Swarm
 *  Mining page, with its own model and its own setup. The wizard still asks what the research is
 *  for, which sources it may read, what it may reach and how big a worker is, so those answers
 *  are kept here and handed over rather than thrown away the moment the wizard closes.
 *
 *  This holds no secret and never did: a blueprint carries no password, and the password a grid
 *  is created with travels beside it, not in it. It stays on this computer and goes nowhere.
 */
import type { ResearchAnswers } from "@/lib/grid-blueprint"

const WHERE = "yougori.research.authorised"

/** Keeps what was authorised, so the Swarm Mining page can show it and seed a worker with it. */
export function rememberResearch(answers: ResearchAnswers): void {
  try {
    window.localStorage.setItem(WHERE, JSON.stringify(answers))
  } catch {
    // A computer that refuses to keep this still runs research; only the head start is lost.
  }
}

/** What was authorised, or nothing when the wizard was never used for research here. */
export function readResearch(): ResearchAnswers | null {
  try {
    const kept = window.localStorage.getItem(WHERE)
    if (!kept) return null
    const read = JSON.parse(kept) as Partial<ResearchAnswers>
    if (typeof read.scope !== "string" || !Array.isArray(read.sources)) return null
    return {
      scope: read.scope,
      sources: read.sources.filter(source => source && typeof source.value === "string"),
      network: read.network === "destinations" ? "destinations" : "offline",
      destinations: Array.isArray(read.destinations) ? read.destinations.filter(one => typeof one === "string") : [],
      worker: {
        kind: read.worker?.kind ?? "microVm",
        cpu: Number(read.worker?.cpu) || 4,
        memoryGb: Number(read.worker?.memoryGb) || 8,
        diskGb: Number(read.worker?.diskGb) || 40,
        gpu: Boolean(read.worker?.gpu),
      },
      approval: read.approval ?? "beforeStart",
    }
  } catch {
    return null
  }
}

/** Forgets it, for somebody who authorises research again or wants it gone. */
export function forgetResearch(): void {
  try {
    window.localStorage.removeItem(WHERE)
  } catch {
    // Nothing depends on this succeeding.
  }
}

/** What was authorised, in one sentence a person reads above their workers. */
export function researchSentence(answers: ResearchAnswers): string {
  const scope = answers.scope.trim() || "the scope you wrote"
  const sources = answers.sources.length
    ? `${answers.sources.length} ${answers.sources.length === 1 ? "source" : "sources"}`
    : "no source yet"
  const reach = answers.network === "destinations" && answers.destinations.length
    ? `It may reach ${answers.destinations.join(", ")}.`
    : "It stays offline."
  return `You authorised ${scope}, on ${sources}. ${reach}`
}
