import { run } from "@/api/platform-api"

/** What a person may do in the Access Grid besides using what the rules allow them. */
export type AccessPermission = "member" | "approver" | "auditor" | "admin"
/** How the hub puts a credential on a request. The last three make short-lived credentials. */
export type AccessKind = "bearer" | "header" | "basic" | "query" | "oauth" | "github-app" | "aws"
export type AccessDecision = "allow" | "ask" | "never"

/** A computer that stays signed in for a person. */
export interface AccessDevice {
  id: string
  computer: string
  createdAt: number
  lastUsedAt: number
  /** Signed in with a second factor. */
  strong: boolean
}

export interface AccessPerson {
  id: string
  username: string
  name: string
  permission: AccessPermission
  teams: string[]
  createdAt: number
  lastSeenAt?: number | null
  email?: string | null
  twoStep: boolean
  devices: AccessDevice[]
}

export interface AccessCredential {
  id: string
  name: string
  kind: AccessKind
  /** The header name (header), query parameter (query) or username (basic). */
  field: string
  destinations: string[]
  note: string
  /** The value's last four characters, empty for short values. The value itself is never sent. */
  hint: string
  createdAt: number
  createdBy: string
  updatedAt: number
  rules: number
  /** Settings of the minting kinds: tokenUrl, clientId, appId, region, roleArn… Never secret. */
  config?: Record<string, string | number>
}

export interface AccessRule {
  id: string
  credential: string
  credentialName: string | null
  /** `everyone`, `team:NAME` or `person:ID`. */
  who: string
  whoLabel: string
  methods: string[]
  path: string
  decision: AccessDecision
  reveal: boolean
  expiresAt?: number | null
  /** Uses an hour at once per person; past it, an approver decides. */
  limit?: number | null
  note: string
  createdAt: number
  createdBy: string
}

/** A request an agent made, as its person or an approver sees it. */
export interface AccessRequest {
  id: string
  person: string
  agent: string
  computer: string
  credential: string
  credentialId: string
  kind: "use" | "reveal"
  method?: string
  url?: string
  hasQuery?: boolean
  bodyBytes?: number
  bodyPreview?: string
  reason?: string
  createdAt: number
  expiresAt: number
  state: "waiting" | "running" | "done" | "denied" | "failed"
  decidedBy: string | null
  /** Why it waits for an approver. */
  why?: string
}

export interface AccessActivity {
  at: number
  person: string
  agent?: string
  computer?: string
  action: "use" | "reveal" | "approve" | "deny" | "signin" | "change"
  credential?: string
  target?: string
  outcome: string
}

/** One way a rule lets this person use a credential. */
export interface AccessUse {
  ruleId: string
  decision: AccessDecision
  methods: string[]
  path: string
  reveal: boolean
  expiresAt?: number | null
  limit?: number | null
}

export interface AccessAvailable {
  id: string
  name: string
  kind: AccessKind
  destinations: string[]
  note: string
  /** The hub makes short-lived tokens from it. */
  shortLived?: boolean
  uses: AccessUse[]
}

export interface AccessSso {
  issuer: string
  clientId: string
  claim: string
  passwordless: boolean
  /** Fixed loopback port for the browser's return; unset means any free port. */
  redirectPort?: number
}

/** The whole grid, for approvers, auditors and admins. */
export interface AccessOverview {
  owner: string
  people: AccessPerson[]
  credentials: AccessCredential[]
  rules: AccessRule[]
  waiting: AccessRequest[]
  activity: AccessActivity[]
  settings: { requireTwoStep: boolean }
  sso: AccessSso | null
}

/** What the signed-in person sees. */
export interface AccessMe {
  person: AccessPerson
  company: string
  accessId: string
  available: AccessAvailable[]
  requests: AccessRequest[]
  /** Nobody else can approve in this grid, so this person may approve their own requests. */
  canApproveOwn: boolean
  /** This sign-in had a second factor. */
  strong: boolean
  /** This computer's ID among the person's devices. */
  device: string | null
  twoStepRequired: boolean
  /** The grid requires two-step and this sign-in had none: nothing can be used until it does. */
  blocked: boolean
  sso: { issuer: string; passwordless: boolean } | null
  overview?: AccessOverview
}

export interface AccessTunnel {
  kind: "quick" | "domain"
  domain: string | null
  url: string | null
  connected: boolean
  error: string | null
}

/** The hub this computer runs. */
export interface AccessHub {
  id: string
  company: string
  address: string
  port: number
  fingerprint: string
  createdAt: number
  tunnelPort: number | null
  owner: string | null
  people: number
  credentials: number
  rules: number
  waiting: number
  signedIn: number
  invite?: string
  tunnel?: AccessTunnel
  /** Scheduled for deletion: paused until `until`; `gone` once deleted. */
  closing?: { requestedAt: number; until: number; gone: boolean } | null
  sso: boolean
  requireTwoStep: boolean
}

/** This person's sign-in on this computer. */
export interface AccessMember {
  accessId: string
  company: string
  hub: string
  fingerprint: string
  username: string
  signedInAt: number
  connected: boolean
  error: string | null
  deviceId?: string
  /** The hub ended this computer's sign-in; sign in again. */
  needsSignIn?: boolean
}

export interface AccessStatus {
  hub: AccessHub | null
  hubError: string | null
  member: AccessMember | null
  memberError: string | null
  me: AccessMe | null
  suggestedAddress: string | null
  mcp: { command: string; args: string[] }
}

export interface AccessResult {
  message?: string
  [key: string]: unknown
}

/** What a password sign-in says when the account has two-step sign-in on and no code was given. */
export const TWO_STEP_MESSAGE = "Enter the six-digit code from your authenticator app"

const empty: AccessStatus = { hub: null, hubError: null, member: null, memberError: null, me: null, suggestedAddress: null, mcp: { command: "yougori", args: ["access", "mcp"] } }
const desktop = () => { throw new Error("Open Yougori Desktop to host or sign in to an Access Grid") }

export const accessApi = {
  status: () => run<AccessStatus>("access_status", {}, () => empty),
  create: (company: string, address: string, username: string, name: string, password: string, tunnel?: string) =>
    run<AccessStatus & AccessResult>("access_create", { company, address, username, name: name || null, password, tunnel: tunnel ?? null }, desktop),
  /** `later` pauses the grid for three days first; `now` deletes it at once; `forget` removes it from this computer. */
  delete: (when: "later" | "now" | "forget" = "later") => run<AccessResult>("access_delete", { when }, desktop),
  restore: () => run<AccessResult>("access_restore", {}, desktop),
  signIn: (invite: string, username: string, password: string, code?: string) => run<AccessStatus & AccessResult>("access_signin", { invite, username, password, code: code || null, sso: null }, desktop),
  /** Opens the company's identity provider in the browser and signs in when it comes back. */
  signInSso: (invite: string) => run<AccessStatus & AccessResult>("access_signin", { invite, username: null, password: null, code: null, sso: true }, desktop),
  signOut: () => run<AccessResult>("access_signout", {}, desktop),
  manage: (request: Record<string, unknown>) => run<AccessResult>("access_manage", { request }, desktop),
  /** The signed-in person's own account: twoStepStart, twoStepConfirm {code}, twoStepOff {code}, password {password, code?}, signOutOthers, deviceForget {device}. */
  account: (request: Record<string, unknown>) => run<AccessResult>("access_account", { request }, desktop),
  backup: (output: string, passphrase: string) => run<AccessResult>("access_backup", { output, passphrase }, desktop),
  restoreBackup: (file: string, passphrase: string, address: string) => run<AccessStatus & AccessResult>("access_restore_backup", { file, passphrase, address }, desktop),
}
