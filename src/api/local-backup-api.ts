import { run } from "@/api/platform-api"
import { BACKUP_EXTENSION } from "@/lib/legacy-names"
import type { PlatformState } from "@/types/platform"

export const localBackupApi = {
  duplicate(environmentId: string, name: string, storageDrive?: string) {
    return run<PlatformState>("duplicate_local_environment", { environmentId, name, storageDrive }, () => {
      throw new Error("Full environment duplication requires the desktop app")
    })
  },
  async choose(importing: boolean): Promise<string | null> {
    if (!("__TAURI_INTERNALS__" in window)) return run("choose_local_backup", {}, () => importing ? "C:\\Backups\\backup.yougori" : "C:\\Backups")
    const { open } = await import("@tauri-apps/plugin-dialog")
    const path = await open(importing
      ? { title: "Open a Yougori backup", filters: [{ name: "Yougori backup", extensions: ["yougori", BACKUP_EXTENSION] }], multiple: false }
      : { title: "Choose where to save the backup folder", directory: true, multiple: false })
    return typeof path === "string" ? path : null
  },
  export(environmentId: string, folder: string) {
    return run<string>("export_local_backup", { environmentId, folder }, () => { throw new Error("Full disk backups require the desktop app") })
  },
  import(path: string, targetProvider?: "yougoriOci" | "yougoriCuda") {
    return run<PlatformState>("import_local_backup", { path, targetProvider }, () => { throw new Error("Full disk restores require the desktop app") })
  },
}
