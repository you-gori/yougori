import { useCallback, useContext, useState } from "react"
import type { NextAction } from "@/api/setups/types"
import { WorkspaceActionsContext } from "@/components/use-workspace-actions"

/** Providers whose sign-in is the Yougori account, which this app signs in to itself. */
const YOUGORI_ACCOUNT = new Set(["yougori", "yougori_network", "yougori-network", "network", "yougori_account", "yougori-account", "market"])

/** The next actions that are not about one operation, and what doing each of them means here.
 *
 *  A sign-in to the Yougori account opens the account sign-in this app already has. Any other
 *  provider signs in from the environment that uses it, in its own window, so this says where
 *  rather than asking for a password here. Logs open the setup's Activity.
 */
export function useNextActions({ onActivity, onConfigure }: {
  onActivity?(): void
  onConfigure?(): void
}) {
  const workspace = useContext(WorkspaceActionsContext)
  const [said, setSaid] = useState("")

  const act = useCallback((action: NextAction) => {
    setSaid("")
    switch (action.kind) {
      case "sign_in": {
        const provider = action.provider.trim()
        if (YOUGORI_ACCOUNT.has(provider.toLowerCase()) && workspace) { workspace.openNetwork(); return }
        setSaid(`Sign in to ${provider || "the provider"} from the environment that uses it: open it under My computer and use its sign-in. It opens in its own window, and this setup notices once you're signed in. Yougori never asks for that password here.`)
        return
      }
      case "add_computer":
        setSaid("Add a computer to the setup that uses it from its own configuration under My setups.")
        return
      case "view_logs":
        if (onActivity) { onActivity(); return }
        setSaid("Its activity is under My setups: open the setup and choose Activity.")
        return
      case "provide_input":
      case "choose_supported_option":
        if (onConfigure) { onConfigure(); return }
        setSaid("Change this from the setup's Configure.")
        return
      case "open_docs":
        setSaid(`The Yougori guide explains this under "${action.topic.replace(/[_-]+/g, " ")}".`)
        return
      default:
        setSaid("")
    }
  }, [workspace, onActivity, onConfigure])

  return { act, said, clear: () => setSaid("") }
}

/** The next-action kinds `useNextActions` carries out or explains. */
export const GENERAL_ACTIONS: ReadonlySet<string> = new Set(["sign_in", "add_computer", "view_logs", "provide_input", "choose_supported_option", "open_docs"])

/** The kinds about one operation, which the view showing that operation carries out itself. */
export const OPERATION_ACTIONS: ReadonlySet<string> = new Set(["retry", "continue", "reconcile", "cancel", "review"])

/** Everything a view that handles both kinds can offer as a button. */
export const ALL_ACTIONS: ReadonlySet<string> = new Set([...GENERAL_ACTIONS, ...OPERATION_ACTIONS])
