import type { ReviewFlag, WorkspaceState } from "@/api/sandbox-vm-api"

/** What a review flag asks the person to look at (`files::ReviewFlag`). */
export const FLAG: Record<ReviewFlag, string> = {
  executable_bit: "becomes executable",
  executable_type: "a type Windows runs",
  git_hook: "a Git hook",
  git_configuration: "Git configuration",
  ci_workflow: "a CI workflow",
  shell_init: "shell start-up",
  build_script: "a build script",
  package_lifecycle: "package scripts",
  tool_configuration: "tool configuration that can start programs",
}

/** Where a staged workspace stands, in a sentence. */
export function stateText(state: WorkspaceState): string {
  switch (state.state) {
    case "imported": return "Imported, not reviewed"
    case "reviewed": return "Reviewed, not promoted"
    case "promoting": return "Promotion under way"
    case "promoted": return `Promoted ${state.applied.length} file${state.applied.length === 1 ? "" : "s"}`
    case "promotion_interrupted": return `A promotion was cut short: ${state.applied.length} written, ${state.not_applied.length} not written${state.changed.length ? `, ${state.changed.length} changed otherwise` : ""}. Review again to finish.`
    case "promotion_undone": {
      const files = (count: number) => `${count} file${count === 1 ? "" : "s"}`
      const undone = state.restored.length + state.removed.length
      const left = state.left.length === 1 ? "1 file had changed since and was left as it is" : `${state.left.length} files had changed since and were left as they are`
      return `A promotion was cut short when Yougori stopped, and undone at its next start: ${files(undone)} put back as before${state.left.length ? `; ${left}` : ""}. Review again to promote.`
    }
  }
}
