import { afterEach, expect, it } from "vitest"
import { desksApi } from "@/api/desks-api"
import { resetTransport, setTransport } from "@/api/grids/wire"

afterEach(resetTransport)

const answering = (answer: Record<string, unknown>) =>
  setTransport(async () => answer as never)

it("shows the new authenticator key when a person turns on two-step", async () => {
  answering({ secret: "JBSWY3DPEHPK3PXP", otpauth: "otpauth://totp/desk?secret=JBSWY3DPEHPK3PXP" })
  expect(await desksApi.manage({ action: "mfaEnroll" })).toEqual({ secret: "JBSWY3DPEHPK3PXP", otpauth: "otpauth://totp/desk?secret=JBSWY3DPEHPK3PXP" })
})

it("still redacts a secret in every other answer", async () => {
  answering({ secret: "JBSWY3DPEHPK3PXP", password: "hunter2" })
  expect(await desksApi.manage({ action: "status" })).toEqual({ secret: "[redacted]", password: "[redacted]" })
  answering({ secret: "x", otpauth: "otpauth://totp/desk?secret=x", password: "hunter2" })
  expect(await desksApi.manage({ action: "mfaEnroll" })).toMatchObject({ password: "[redacted]" })
})
