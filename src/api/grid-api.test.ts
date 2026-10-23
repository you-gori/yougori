import { describe, expect, it } from "vitest"
import { readInvite } from "@/api/grid-api"

// Encoded the way the engine does: the JSON's UTF-8 bytes, base64url.
const encode = (wire: object) => "grid-invite:" + btoa(String.fromCharCode(...new TextEncoder().encode(JSON.stringify(wire)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "")

describe("readInvite", () => {
  it("reads the company, address and fingerprint, tolerating pasted line breaks", () => {
    const code = encode({ v: 1, c: "Acme", a: "https://grid.acme.com", f: "ab:cd:ef" })
    expect(readInvite(code)).toEqual({ company: "Acme", address: "https://grid.acme.com", fingerprint: "ABCDEF" })
    expect(readInvite(` ${code.slice(0, 20)}\n${code.slice(20)} `)?.company).toBe("Acme")
  })

  it("keeps a company name with letters outside ASCII intact", () => {
    expect(readInvite(encode({ v: 1, c: "Żółć 東京", a: "https://grid.acme.com", f: "AB" }))?.company).toBe("Żółć 東京")
  })

  it("refuses anything that is not a whole invite", () => {
    expect(readInvite("hello")).toBeNull()
    expect(readInvite("grid-invite:not base64 at all!")).toBeNull()
    expect(readInvite(encode({ v: 1, c: "", a: "https://grid.acme.com", f: "AB" }))).toBeNull()
    expect(readInvite(encode({ v: 1, c: "Acme", a: "https://grid.acme.com" }))).toBeNull()
  })
})
