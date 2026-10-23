import type { VaultStatus } from "@/api/vault-api"

/** Why the vault cannot be deleted right now, said with what to do first; `null` when it can.
 *  Checked when the delete dialog opens, so a delete that could not reach the vault is never
 *  offered, and nothing has to be guessed about afterwards. */
export function blockedBy(status: VaultStatus): string | null {
  if (status.supported === false) return status.notice ?? "Personal Vault is not available on this computer."
  if (!status.running) return "Personal Vault isn’t running, so it can’t be deleted now. Activate it from its row, then choose Delete my vault again."
  if (status.updateRequired) return `${status.notice ?? "Personal Vault needs an update first: choose Update vault on its row."} Then choose Delete my vault again.`
  return null
}
