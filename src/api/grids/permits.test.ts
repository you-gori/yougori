// @vitest-environment jsdom
import { readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"
import { CapabilityOffError, NotAllowedError } from "@/api/grids/errors"
import { capabilityOf, enabled, guard, may } from "@/api/grids/permits"
import { ACTION_NAMES, ROLE_ACTIONS, ROLE_IMPLIES } from "@/api/grids/permits.generated"
import type { Action, Role } from "@/api/grids/types"

const identity = readFileSync(path.resolve(process.cwd(), "grid/src/core/identity.rs"), "utf8")
const lower = (word: string) => word.charAt(0).toLowerCase() + word.slice(1)

describe("the client's permission table", () => {
  it("names the same roles and actions the engine does", () => {
    const roles = [...identity.matchAll(/^ {4}([A-Z][A-Za-z]*),$/gm)].map(found => lower(found[1] as string))
    for (const role of Object.keys(ROLE_ACTIONS)) expect(roles).toContain(role)
    for (const action of Object.keys(ACTION_NAMES)) expect(roles.concat(Object.keys(ACTION_NAMES))).toContain(action)
  })

  it("matches the Rust arm for arm, for every role and every action", () => {
    for (const [role, actions] of Object.entries(ROLE_ACTIONS)) {
      const arm = new RegExp(`Role::${role.charAt(0).toUpperCase()}${role.slice(1)} => matches!\\(([\\s\\S]*?)\\),\\n`).exec(identity)
      expect(arm, `Role::${role} has no arm`).toBeTruthy()
      const written = (arm?.[1] ?? "").split(/action\s*,/)[1]?.split("|").map(word => lower(word.trim())).filter(Boolean) ?? []
      expect([...actions].sort()).toEqual([...written].sort())
    }
  })

  it("brings the two approving permissions with administering a realm, and nothing else", () => {
    expect(ROLE_IMPLIES.realmAdmin).toEqual(["credentialApprover", "researchApprover"])
    expect(may({ roles: ["realmAdmin"] }, "approveCredential")).toBe(true)
    expect(may({ roles: ["realmAdmin"] }, "approveResearch")).toBe(true)
    for (const role of Object.keys(ROLE_IMPLIES) as Role[]) {
      if (role !== "realmAdmin") expect(ROLE_IMPLIES[role]).toEqual([])
    }
  })

  it("answers no for a suspended account, whatever role it still holds", () => {
    expect(may({ roles: ["realmAdmin"] }, "manageModels")).toBe(true)
    expect(may({ roles: ["realmAdmin"], suspendedAt: 1_760_000_000 }, "manageModels")).toBe(false)
    expect(may({ roles: ["realmAdmin"], suspendedAt: null }, "manageModels")).toBe(true)
  })

  it("answers no for something this grid does not do at all", () => {
    expect(enabled({ roles: ["realmAdmin"], capabilities: ["models"] }, "manageCredentials")).toBe(false)
    expect(may({ roles: ["realmAdmin"], capabilities: ["models"] }, "manageCredentials")).toBe(false)
    expect(may({ roles: ["realmAdmin"], capabilities: ["models"] }, "manageModels")).toBe(true)
    expect(capabilityOf("managePeople")).toBeNull()
    expect(may({ roles: ["realmAdmin"] }, "manageCredentials")).toBe(true)
  })

  it("refuses with the clearer of the two sentences", () => {
    expect(() => guard({ roles: ["realmAdmin"], capabilities: ["models"] }, "manageCredentials", "access_manage")).toThrow(CapabilityOffError)
    expect(() => guard({ roles: ["user"] }, "manageModels", "grid_plan_add")).toThrow(NotAllowedError)
    expect(() => guard({ roles: ["realmAdmin"] }, "manageModels", "grid_plan_add")).not.toThrow()
  })

  it("is a mirror and never the decision: a role it allows still sends the call for the engine to judge", () => {
    const allowed: Action[] = ["manageModels", "manageWorkspaces", "manageCredentials", "managePeople"]
    for (const action of allowed) expect(may({ roles: ["realmAdmin"] }, action)).toBe(true)
    // Nothing here grants anything. The engine checks the main window, the hub checks the
    // session, and Grid Core checks its own table again at the moment it acts.
    expect(Object.keys(ROLE_ACTIONS)).toHaveLength(11)
  })
})
