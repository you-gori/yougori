// Written by scripts/grid-core-roles.mjs from grid/src/core/identity.rs. Do not edit by hand.
//
// This mirrors the engine's table so the client can grey out a control and give a sentence
// without a round trip. It grants nothing: every call is checked again by the engine, by the
// hub that holds the data, and by Grid Core at the moment it acts.
import type { Action, Role } from "@/api/grids/types"

/** What one role may do, on its own. */
export const ROLE_ACTIONS: Record<Role, readonly Action[]> = {
  user: ["useWorkspace", "callModel", "readOwn"],
  operator: ["useWorkspace", "callModel", "readOwn", "readRealm", "placeWork", "drainHost"],
  researcher: ["readOwn", "readRealm", "doResearch"],
  workspaceAdmin: ["readOwn", "readRealm", "placeWork", "manageWorkspaces"],
  modelAdmin: ["readOwn", "readRealm", "placeWork", "manageModels"],
  credentialAdmin: ["readOwn", "readRealm", "manageCredentials"],
  credentialApprover: ["readOwn", "readRealm", "approveCredential"],
  researchApprover: ["readOwn", "readRealm", "approveResearch"],
  securityAdmin: ["readOwn", "readRealm", "readAudit", "manageSecurity", "drainHost", "revokeDevice"],
  auditor: ["readRealm", "readAudit"],
  realmAdmin: ["readOwn", "readRealm", "readAudit", "placeWork", "drainHost", "revokeDevice", "manageWorkspaces", "manageModels", "manageCredentials", "managePeople", "manageSecurity", "doResearch"],
}

/** What else comes with a role. */
export const ROLE_IMPLIES: Record<Role, readonly Role[]> = {
  user: [],
  operator: [],
  researcher: [],
  workspaceAdmin: [],
  modelAdmin: [],
  credentialAdmin: [],
  credentialApprover: [],
  researchApprover: [],
  securityAdmin: [],
  auditor: [],
  realmAdmin: ["credentialApprover", "researchApprover"],
}

/** How to say an action to a person. */
export const ACTION_NAMES: Record<Action, string> = {
  readOwn: "read own",
  readRealm: "read realm",
  readAudit: "read audit",
  useWorkspace: "use workspace",
  callModel: "call model",
  placeWork: "place work",
  drainHost: "drain host",
  revokeDevice: "revoke device",
  manageWorkspaces: "manage workspaces",
  manageModels: "manage models",
  manageCredentials: "manage credentials",
  managePeople: "manage people",
  manageSecurity: "manage security",
  doResearch: "do research",
  approveCredential: "approve a credential request",
  approveResearch: "approve research",
}
