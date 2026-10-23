import { expect, it } from "vitest"
import {
  allowedIn, capabilitiesSentence, chooseCapability, COMPANY_CAPABILITIES, kindFor, may, offers, shows,
} from "@/lib/grid-capability"
import type { Held } from "@/api/grids/permits"

const admin: Held = { roles: ["realmAdmin"] }
const auditor: Held = { roles: ["auditor"] }

it("offers a research grid only research, and never offers a company grid research", () => {
  expect(allowedIn("research")).toEqual(["research"])
  expect(allowedIn("primary")).toEqual([...COMPANY_CAPABILITIES])
  expect(allowedIn("primary")).not.toContain("research")
})

it("keeps research alone in its grid whichever way somebody picks", () => {
  expect(chooseCapability(["models", "workspaces"], "research")).toEqual(["research"])
  expect(chooseCapability(["research"], "models")).toEqual(["models"])
  expect(chooseCapability(["models"], "credentials")).toEqual(["models", "credentials"])
  // Picking the same one again takes it off, and the kind follows what is left.
  expect(chooseCapability(["models", "credentials"], "models")).toEqual(["credentials"])
  expect(kindFor(["research"])).toBe("research")
  expect(kindFor(["models", "credentials"])).toBe("primary")
  expect(kindFor([])).toBe("primary")
})

it("needs both the capability and the permission before a panel is shown", () => {
  const credentialsGrid = { capabilities: ["credentials"] as const }
  const modelsGrid = { capabilities: ["models"] as const }
  // The grid can, and the person may.
  expect(shows(credentialsGrid, admin, "credentials", "manageCredentials")).toBe(true)
  // The person may, but this grid does not do it at all.
  expect(may(admin, "manageCredentials")).toBe(true)
  expect(shows(modelsGrid, admin, "credentials", "manageCredentials")).toBe(false)
  // The grid does it, but this person may not.
  expect(shows(credentialsGrid, auditor, "credentials", "manageCredentials")).toBe(false)
  // An auditor still reads what happened.
  expect(shows(credentialsGrid, auditor, "credentials", "readAudit")).toBe(true)
})

it("says what a grid does in a sentence rather than a list of words", () => {
  expect(offers({ capabilities: ["models"] }, "models")).toBe(true)
  expect(offers({ capabilities: ["models"] }, "workspaces")).toBe(false)
  expect(capabilitiesSentence(["models"])).toBe("serving models")
  expect(capabilitiesSentence(["models", "workspaces", "credentials"]))
    .toBe("serving models, sandbox workspaces and credential access")
  expect(capabilitiesSentence([])).toBe("nothing yet")
})

it("never lets a suspended person be offered anything", () => {
  const suspended: Held = { roles: ["realmAdmin"], suspendedAt: 1 }
  expect(shows({ capabilities: ["credentials"] }, suspended, "credentials", "manageCredentials")).toBe(false)
  expect(shows({ capabilities: ["credentials"] }, suspended, "credentials", "readAudit")).toBe(false)
})
