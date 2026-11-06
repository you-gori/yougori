// @vitest-environment jsdom
import { expect, it } from "vitest"
import { desksApi } from "@/api/desks-api"

it("needs the desktop to reconnect a shared sandbox, and never pretends in the browser", async () => {
  await expect(desksApi.refreshDesk()).rejects.toThrow("requires Yougori Desktop")
})
