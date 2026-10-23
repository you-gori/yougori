import { run } from "./platform-api"
import type { PlatformState } from "@/types/platform"
import type { CloudflareAccountOptions } from "./workspace-api"
export type RemotePermission = "view" | "edit" | "control"
export interface RemoteGrant { id: string; targetId: string; username: string; permission: RemotePermission; folder: string | null; expiresAt: number | null; status: "online" | "offline" | "expired" | "revoked"; link: string | null; connectedUsers: number }
export interface RemoteShares { grants: RemoteGrant[]; url: string | null; port: number | null; audit: { at: number; shareId: string; event: string; success: boolean }[] }
export interface RemoteCapabilities { restricted?: boolean; uploads?: boolean; apps?: boolean; appKind?: "container" | "microVm"; installers?: boolean; internet?: boolean; skills?: boolean; name?: string; permission: RemotePermission; files: boolean; commands: boolean; power: boolean; desktop: boolean }
export interface RemoteFile { name: string; directory: boolean; size: number }
const native = (): never => { throw new Error("Remote sharing requires Yougori Desktop") }
export const remoteAccessApi = {
  list: () => run<RemoteShares>("list_remote_shares", {}, () => ({ grants: [], url: null, port: null, audit: [] })),
  create: (request: { targetId: string; username: string; password: string; permission: RemotePermission; expiresAt: number | null; folder: string | null; confirmPcFiles: boolean; acknowledgeExistingAccess: boolean }) => run<{ id: string }>("create_remote_share", { request }, native),
  start: (cloudflare?: CloudflareAccountOptions, hostPort?: number) => run<{ url: string; port: number; warning?: string }>("start_remote_tunnel", { cloudflare, hostPort }, native),
  stop: () => run<void>("stop_remote_tunnel", {}, native),
  update: (shareId: string, changes: { permission?: RemotePermission; password?: string; revoke?: boolean } = {}) => run<void>("update_remote_share", { shareId, revoke: false, ...changes }, native),
  remove: (shareId: string) => run<void>("remove_remote_share", { shareId }, native),
  connect: (link: string, username: string, password: string, environmentId?: string) => run<PlatformState>("connect_remote_share", { link, username, password, environmentId }, native),
  reconnect: (environmentId: string) => run<PlatformState>("reconnect_remote_share", { environmentId }, native),
  inspect: (environmentId: string) => run<RemoteCapabilities>("remote_share_request", { environmentId, method: "inspect", params: {} }, native),
  download: (environmentId: string, path: string, destination: string) => run<{ folder: string; entries: number; bytes: number }>("download_remote_folder", { environmentId, path, destination }, native),
  desktop: <T = Record<string, unknown>>(environmentId: string, params: Record<string, unknown>) => run<T>("remote_share_request", { environmentId, method: "desktop", params }, native),
  upload: <T = Record<string, unknown>>(environmentId: string, params: Record<string, unknown>) => run<T>("remote_share_request", { environmentId, method: "upload", params }, native),
  files: <T = Record<string, unknown>>(environmentId: string, params: Record<string, unknown>) => run<T>("remote_share_request", { environmentId, method: "files", params }, native),
}
