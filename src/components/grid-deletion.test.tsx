// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import { afterEach, expect, it } from "vitest"
import { ClosingLine } from "./grid-deletion"
import { TELL_FOR } from "@/lib/grid-closing"
import { credentialsRealm } from "@/lib/grid-realm"
import type { AccessStatus } from "@/api/access-api"

afterEach(cleanup)

const cleans = "clean up what this grid put there"
const keeps = "Every computer keeps its credentials until then."

it("counts the computers that heard, only for a grid that keeps that record", () => {
  render(<ClosingLine closing={{ requestedAt: 0, until: 100, gone: true, told: 1, computers: 3, tellUntil: 200 }} cleans={cleans} keeps={keeps} />)
  expect(screen.getByRole("status")).toHaveTextContent("1 of 3 computers have heard")
})

it("does not invent a count for a grid that keeps no record of who was told", () => {
  render(<ClosingLine closing={{ requestedAt: 0, until: 100, gone: true, tellUntil: 200 }} cleans={cleans} keeps={keeps} />)
  const said = screen.getByRole("status")
  expect(said).toHaveTextContent("People’s computers hear it when they come online")
  expect(said.textContent).not.toContain("0 of 0")
})

it("reads a deleted Access Grid as a sentence about computers it never counted", () => {
  const deleted = { until: 1_700_000_000, requestedAt: 1_699_000_000, gone: true }
  const status = {
    hub: {
      id: "a1", company: "Acme", address: "192.168.1.20", port: 7465, fingerprint: "AB:CD", createdAt: 0,
      tunnelPort: null, owner: "ada", people: 1, credentials: 0, rules: 0, waiting: 0, signedIn: 1,
      closing: deleted, sso: false, requireTwoStep: false,
    },
    hubError: null, member: null, memberError: null, me: null,
  } as unknown as AccessStatus
  const closing = credentialsRealm(status, "Studio PC").closing
  expect(closing?.told).toBeUndefined()
  expect(closing?.computers).toBeUndefined()
  // The hub really does keep telling computers for thirty days past the deletion.
  expect(closing?.tellUntil).toBe(deleted.until + TELL_FOR)
  render(<ClosingLine closing={closing} cleans={cleans} keeps={keeps} />)
  expect(screen.getByRole("status").textContent).not.toMatch(/\d+ of \d+/)
})
