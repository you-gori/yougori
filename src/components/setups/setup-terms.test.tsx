// @vitest-environment jsdom
import "@testing-library/jest-dom/vitest"
import { cleanup, render, screen } from "@testing-library/react"
import userEvent from "@testing-library/user-event"
import { afterEach, expect, it, vi } from "vitest"
import type { OperationView } from "@/api/setups/progress"

const api = vi.hoisted(() => ({ agreeToTerms: vi.fn() }))
vi.mock("@/api/setups/setups-api", async importOriginal => {
  const actual = await importOriginal<typeof import("@/api/setups/setups-api")>()
  return { ...actual, setupsApi: { ...actual.setupsApi, agreeToTerms: api.agreeToTerms } }
})

import { SetupProgress } from "./setup-views"
import { termsToAgree } from "./setup-words"

afterEach(() => {
  cleanup()
  api.agreeToTerms.mockReset()
})

const TERMS = "Read what the review you join asks before its worker starts. Project: Their Shop. What may be tested: \"Their shop's source only.\". To agree to exactly these terms, choose Agree to these terms, or continue this change with accept_terms set to abcdef012345."

const waiting = (code: string, message = TERMS): OperationView => ({
  state: "awaiting_input",
  error: { code, message, severity: "error", retryable: false, nextActions: [{ kind: "continue" }, { kind: "cancel" }] } as OperationView["error"],
  events: [],
  truncated: false,
})

it("reads the terms' digest only from a change waiting for them", () => {
  expect(termsToAgree(waiting("terms_to_accept").error)).toBe("abcdef012345")
  expect(termsToAgree(waiting("secret_needed").error)).toBeNull()
  expect(termsToAgree(waiting("terms_to_accept", "Agree with accept_terms set to xyz").error)).toBeNull()
  expect(termsToAgree(null)).toBeNull()
})

it("shows the joined review's terms and agrees to exactly those from the window", async () => {
  api.agreeToTerms.mockResolvedValue({ operationId: "op-1", setupId: "s1" })
  const user = userEvent.setup()
  render(<SetupProgress operation={waiting("terms_to_accept")} agreeFor={{ setupId: "s1", operationId: "op-1" }} />)
  expect(screen.getByRole("alert")).toHaveTextContent("Their shop's source only.")
  await user.click(screen.getByRole("button", { name: "Agree to these terms" }))
  expect(api.agreeToTerms).toHaveBeenCalledWith("s1", "op-1", "abcdef012345")
})

it("offers no agreement for any other wait, or where the setup isn't known", () => {
  const { rerender } = render(<SetupProgress operation={waiting("secret_needed", "It needs the invitation again.")} agreeFor={{ setupId: "s1", operationId: "op-1" }} />)
  expect(screen.queryByRole("button", { name: "Agree to these terms" })).not.toBeInTheDocument()
  rerender(<SetupProgress operation={waiting("terms_to_accept")} />)
  expect(screen.queryByRole("button", { name: "Agree to these terms" })).not.toBeInTheDocument()
})

it("says plainly when agreeing didn't go through", async () => {
  api.agreeToTerms.mockRejectedValue(new Error("The project changed; review it again"))
  const user = userEvent.setup()
  render(<SetupProgress operation={waiting("terms_to_accept")} agreeFor={{ setupId: "s1", operationId: "op-1" }} />)
  await user.click(screen.getByRole("button", { name: "Agree to these terms" }))
  expect(await screen.findByText("The project changed; review it again")).toBeInTheDocument()
})
