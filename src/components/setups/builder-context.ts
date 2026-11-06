import { createContext, useContext } from "react"
import type { BuilderIntent } from "./setup-intent"

/** Opens the template builder from anywhere in the app: the Hub, My setups, a search result. */
export interface SetupBuilderControls { open(intent: BuilderIntent): void }

export const SetupBuilderContext = createContext<SetupBuilderControls | null>(null)

export function useSetupBuilder(): SetupBuilderControls {
  const controls = useContext(SetupBuilderContext)
  if (!controls) throw new Error("useSetupBuilder must be used inside SetupBuilderScope")
  return controls
}
