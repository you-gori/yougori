import { invoke, isTauri } from "@tauri-apps/api/core"

export interface ReleaseStatus {
  current: string
  latest: string
  channel: string
  platform: string
  updateAvailable: boolean
  downloadAvailable: boolean
  notes: string
  remindLater: boolean
}

/** Whether a release installs in place; if not, `reason` says why and where to get it. */
export interface UpdateReadiness {
  ready: boolean
  /** No publisher signature: the download is checked against its published SHA-256. */
  unsigned?: boolean
  reason?: string
}

export const releaseApi = {
  check(force = false): Promise<ReleaseStatus | null> {
    // Browser previews and guest windows do not check the host's release feed.
    return isTauri() ? invoke("check_release_update", { force }) : Promise.resolve(null)
  },
  remindLater(version: string): Promise<void> {
    return invoke("remind_release_update_later", { version })
  },
  openDownloads(): Promise<void> {
    return invoke("open_release_downloads")
  },
  prepare(version: string): Promise<UpdateReadiness> {
    return invoke("prepare_release_update", { version })
  },
  /** Downloads and checks the release; its installer runs once the app has quit. */
  install(version: string): Promise<{ installing: string }> {
    return invoke("install_release_update", { version })
  },
  /** Quits the way the app's Quit does: running environments stop first. */
  quit(): Promise<void> {
    return invoke("finish_app_close", { keepRunning: false })
  },
}
