import { createContext, useContext } from "react"
import type { SandboxVmStatus } from "@/api/sandbox-vm-api"

type Feed = { status: SandboxVmStatus | null; error: string; refresh(): Promise<void> }
export const SandboxVmContext = createContext<Feed>({ status: null, error: "", refresh: async () => {} })
export const useSandboxVms = () => useContext(SandboxVmContext)
