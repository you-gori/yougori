import { run } from "./platform-api"
import type { PlatformState } from "@/types/platform"
export interface CloudDeployRequest {provider:"aws"|"azure"|"google";account:string;region:string;name:string;image:string;machineType:string;subnet:string;resourceGroup:string;securityGroup:string;keyPair:string;sshPublicKey:string;imageProject:string;containerImage:string;username:string}
export interface CloudProfile {
  name: string; vendor: "aws" | "google" | "azure" | "other"; host: string; port: number
  username: string; identityFile: string; hostKey: string
}
export interface CloudHostKey { key: string; fingerprint: string }
export type CloudOptionKind = "regions" | "images" | "machineTypes" | "subnets" | "securityGroups" | "keyPairs" | "resourceGroups" | "sshKeys"
export interface CloudOption { id: string; name: string; detail: string }
export interface CloudOptions { kind: CloudOptionKind; field: keyof CloudDeployRequest; items: CloudOption[]; imageProject?: string }
/** Which lookups apply to each provider (machine types, and Google subnets, need a region or zone). */
export function cloudOptionKinds(provider: CloudDeployRequest["provider"], region: string): CloudOptionKind[] {
  const kinds: CloudOptionKind[] = ["regions", "images"]
  if (provider === "aws") kinds.push("subnets", "securityGroups", "keyPairs")
  if (provider === "azure") kinds.push("subnets", "securityGroups", "resourceGroups", "sshKeys")
  if (provider === "google") { kinds.push("sshKeys"); if (region) kinds.push("subnets") }
  if (region) kinds.push("machineTypes")
  return kinds
}
export const cloudApi = {
  testConnection(request: CloudProfile, environmentId?: string) {
    return run<CloudProfile>("test_cloud_connection", { request, environmentId: environmentId ?? null }, () => ({ ...request, hostKey: request.hostKey || "ssh-ed25519 TEST-PREVIEW-ONLY" }))
  },
  deleteDeployment:(environmentId:string,confirmation:string)=>run<PlatformState>("delete_cloud_deployment",{environmentId,confirmation},()=>{throw new Error("Cloud deletion requires Yougori Desktop")}),
  authenticate:(provider:string,account:string,sso?:Record<string,string>)=>run<unknown>("cloud_authenticate",{provider,account,sso},()=>{throw new Error("Cloud authentication requires Yougori Desktop and the provider CLI")}),
  options:(provider:string,account:string,region:string,kind:CloudOptionKind)=>run<CloudOptions>("cloud_options",{provider,account,region:region||null,kind},()=>({kind,field:"region",items:[]})),
  deploy:(request:CloudDeployRequest,riskAcknowledged:boolean)=>run<PlatformState>("deploy_cloud_environment",{request,riskAcknowledged},()=>{throw new Error("Cloud deployment requires Yougori Desktop")}),
  action:(environmentId:string,action:"inspect"|"start"|"stop")=>run<{deployment:NonNullable<PlatformState["cloudDeployments"]>[string];providerResult:unknown}>("cloud_deployment_action",{environmentId,action},()=>{throw new Error("Cloud power operations require Yougori Desktop")}),
  configure:(environmentId:string,request:CloudProfile)=>run<PlatformState>("configure_cloud_environment",{environmentId,request},()=>{throw new Error("Cloud SSH configuration requires Yougori Desktop")}),
  scan(host: string, port: number) {
    return run<CloudHostKey[]>("scan_cloud_host", { host, port }, () => [{ key: "ssh-ed25519 TEST-PREVIEW-ONLY", fingerprint: "SHA256:preview-only-not-a-real-server" }])
  },
  details(environmentId: string) {
    return run<{ profile: CloudProfile; connection: { socksPort: number; filesPort: number } | null }>("get_cloud_connection", { environmentId }, () => ({ profile: JSON.parse(localStorage.getItem(`yougori.cloud.${environmentId}`) || "null") as CloudProfile, connection: { socksPort: 1080, filesPort: 8080 } }))
  },
  /** `pem` offers EC2 key pair files first. */
  async selectKey(pem = false) {
    if (!("__TAURI_INTERNALS__" in window)) return null
    const { open } = await import("@tauri-apps/plugin-dialog")
    const selected = await open({ multiple: false, directory: false, title: pem ? "Choose your EC2 key pair (.pem)" : "Choose SSH identity file", ...(pem ? { filters: [{ name: "EC2 key pair", extensions: ["pem"] }, { name: "All files", extensions: ["*"] }] } : {}) })
    return typeof selected === "string" ? selected : null
  },
}
