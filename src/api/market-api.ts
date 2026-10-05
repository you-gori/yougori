import { run } from "@/api/platform-api"

export type SharingMode = "paid" | "free"
export interface NetworkNode {
  id: string
  mode: SharingMode
  gpu: string | null
  tps: number | null
  tpsSource: "window" | "average" | null
  uptimeTodaySeconds: number
  uptimeWeekSeconds: number
  availability: number | null
  tokensIn: number
  tokensOut: number
  price: { input: number; output: number } | null
  earnedMicros: number
}
export interface NetworkShare {
  environmentId: string
  model: string
  mode: SharingMode
  nodeId: string | null
  status: string
  message: string
  live: boolean
  listing: string | null
  warnings: string[]
  node: NetworkNode | null
}
export interface NetworkStatus {
  website: string
  signedIn: boolean
  account: { email: string; wallet: string | null; creditMicros: number; earningsMicros: number; availableMicros: number } | null
  login: { userCode: string; verificationUrl: string; verificationUrlComplete: string; expiresIn: number; error: string | null } | null
  shares: NetworkShare[]
}
const desktop = () => { throw new Error("Open Yougori Desktop to use the Network") }
export const marketApi = {
  status: () => run<NetworkStatus>("market_status", {}, desktop),
  signIn: () => run<NetworkStatus>("market_sign_in", {}, desktop),
  signOut: () => run<NetworkStatus>("market_sign_out", {}, desktop),
  share: (environmentId: string, mode: SharingMode) => run<NetworkShare>("market_share_model", { environmentId, mode }, desktop),
  unshare: (environmentId: string) => run<{ environmentId: string; shared: false }>("market_unshare_model", { environmentId }, desktop),
  listen: async (callback: (status: NetworkStatus) => void): Promise<() => void> => {
    if (!("__TAURI_INTERNALS__" in window)) return () => {}
    const { listen } = await import("@tauri-apps/api/event")
    return listen<NetworkStatus>("yougori-market", event => callback(event.payload))
  },
}
