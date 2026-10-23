import { run } from "@/api/platform-api"

export interface VaultClient { id: string; executable: string; digest: string; device: string; user: string; process: number; environment: string }
export interface VaultItem { id: string; label: string; kind: string; resource: string; fields: string[] }
export interface VaultPending { id: string; client: VaultClient; operation: string; expiresAt: string; title?: string; description?: string; allowLabel?: string; ready?: boolean; destroy?: boolean }
export interface VaultItemInput { label: string; kind: string; resource: string; value: string }
export interface VaultActivity { time: string; client: string; request: string; operation: string; outcome: string }
export type VaultConnectionMode = "local" | "quick" | "domain"
export interface VaultSetup { created: boolean; mode: VaultConnectionMode; hostname: string; localUrl: string; publicUrl: string | null }
export interface VaultStatus { running: boolean; locked: boolean; oauthReady?: boolean; oauthUnavailable?: string | null; setup?: VaultSetup; updateRequired?: boolean; destroyIncomplete?: boolean; supported?: boolean; notice?: string; protection?: string; transport?: string; remote?: { fingerprint: string } | null; gateway?: { running: boolean; port: number }; items: VaultItem[]; clients: VaultClient[]; pending: VaultPending[]; activity: VaultActivity[] }
export const vaultApi = {
  status: () => run<VaultStatus>("vault_status", {}, () => ({ running: false, locked: true, supported: false, notice: "Open Yougori Desktop on Windows to use Personal Vault.", items: [], clients: [], pending: [], activity: [] })),
  control: (action: "start" | "browse" | "credentials" | "lock" | "revoke" | "remove" | "deny" | "approve" | "destroy", id?: string) => run<{ token?: string }>("vault_control", { action, id: id ?? null }, () => { throw new Error("Open Yougori Desktop to manage Personal Vault") }),
  addItems: (items: VaultItemInput[]) => run<{ added: string[] }>("vault_add_items", { items }, () => { throw new Error("Open Yougori Desktop to add Personal Vault items") }),
  exportPlugin: (directory: string) => run<string>("vault_export_plugin", { directory }, () => { throw new Error("Open Yougori Desktop to download the Personal Vault plugin") }),
  bootstrap: (interactive = false) => run<{ created: boolean; ready?: boolean; updateRequired?: boolean; tunnelError?: string }>("vault_bootstrap", { interactive }, () => ({ created: false })),
  create: () => run<VaultSetup>("vault_create", {}, () => { throw new Error("Open Yougori Desktop to create your Personal Vault") }),
  connection: (mode: VaultConnectionMode, hostname = "", token = "", routesReviewed = false, replaceQuickLink = false) => run<VaultSetup>("vault_connection", { mode, hostname, token: token || null, routesReviewed, replaceQuickLink }, () => { throw new Error("Open Yougori Desktop to configure vault access") }),
}
