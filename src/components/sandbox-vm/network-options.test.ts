import { describe, expect, it } from "vitest"
import { defaultNetworkOptions, networkLaunchFields } from "./network-options"

describe("VM connection permissions", () => {
  it("does not grant outgoing access when either the parent or outgoing switch is off", () => {
    for (const internet of [true, false]) for (const outgoing of [true, false]) {
      expect(networkLaunchFields({ ...defaultNetworkOptions(), internet, outgoing }))
        .toEqual(internet && outgoing ? { internet: true } : {})
    }
  })
  it("refuses unsupported incoming access and ignores it when the parent is off", () => {
    for (const outgoing of [true, false]) {
      const options = { ...defaultNetworkOptions(), internet: true, incoming: true, outgoing }
      expect(() => networkLaunchFields(options)).toThrow("Incoming access to all VM ports is not supported")
      options.internet = false
      expect(networkLaunchFields(options)).toEqual({})
    }
  })
  it("allows selected online requests when general outgoing access is off", () => {
    const options = { ...defaultNetworkOptions(), internet: true, outgoing: false, online: true, requests: [{ address: "https://example.com/health", method: "GET" }] }
    const fields = networkLaunchFields(options)
    expect(fields.internet).toBeUndefined()
    expect(fields.routes).toEqual([expect.objectContaining({ host: "example.com", port: 443 })])
  })
  it("full internet explicitly replaces selected routes and retains app settings", () => {
    const options = { ...defaultNetworkOptions(), internet: true, online: true, advanced: true, rules: "invalid old rules", sharing: true }
    expect(networkLaunchFields(options)).toEqual({ internet: true, publish: "web=3000" })
    options.internet = false; options.online = false
    expect(networkLaunchFields(options)).toEqual({ publish: "web=3000" })
  })
  it("sends no permissions for defaults or disabled options, even with invalid saved values", () => {
    const options = defaultNetworkOptions()
    expect(networkLaunchFields(options)).toEqual({})
    options.requests = [{ address: "not a URL", method: "POST" }]
    options.apps = [{ name: "bad name", port: "99999" }]
    options.connections = [{ name: "api", port: "0" }]
    options.advanced = true; options.rules = "not JSON"
    expect(networkLaunchFields(options)).toEqual({})
  })

  it("groups exact requests on the same server and preserves write effects, ports and query keys", () => {
    const options = defaultNetworkOptions()
    options.online = true
    options.requests = [
      { address: "https://api.example.com/v1/models?page=1", method: "GET" },
      { address: "https://api.example.com/v1/models?limit=10", method: "GET" },
      { address: "https://api.example.com/v1/chat/completions", method: "POST" },
      { address: "https://other.example.com:8443/health", method: "GET" },
    ]
    expect(networkLaunchFields(options)).toEqual({ routes: [
      { name: "online-1", host: "api.example.com", port: 443, operations: [
        { name: "request-1", method: "GET", path: "/v1/models", query_keys: ["limit", "page"], effect: "read_only" },
        { name: "request-3", method: "POST", path: "/v1/chat/completions", query_keys: [], effect: "external" },
      ] },
      { name: "online-2", host: "other.example.com", port: 8443, operations: [
        { name: "request-4", method: "GET", path: "/health", query_keys: [], effect: "read_only" },
      ] },
    ] })
  })

  it.each(["", "api.example.com", "http://api.example.com", "https://user:password@api.example.com", "https://api.example.com/#fragment", "https://api.example.com/a%20b", "https://api.example.com/v1/"])("refuses unsupported or ambiguous online address %s", address => {
    expect(() => networkLaunchFields({ ...defaultNetworkOptions(), online: true, requests: [{ address, method: "GET" }] })).toThrow()
  })

  it("keeps manual credentials and budgets intact, and ignores manual rules when guided mode is selected", () => {
    const routes = [{ name: "provider", host: "api.example.com", operations: [{ name: "models", method: "GET", path: "/v1/models", effect: "read_only" }], credential: { name: "saved-key", provider: "example" } }]
    const options = { ...defaultNetworkOptions(), online: true, advanced: true, rules: JSON.stringify(routes) }
    expect(networkLaunchFields(options)).toEqual({ routes })
    options.advanced = false
    expect(() => networkLaunchFields(options)).toThrow(/full HTTPS address/)
  })

  it("refuses empty enabled lists, invalid ports, duplicate apps, and port conflicts", () => {
    expect(() => networkLaunchFields({ ...defaultNetworkOptions(), online: true, requests: [] })).toThrow(/Add an online address/)
    expect(() => networkLaunchFields({ ...defaultNetworkOptions(), sharing: true, apps: [] })).toThrow(/Add an app/)
    for (const port of ["0", "65536", "1.5", "1e3", ""]) {
      expect(() => networkLaunchFields({ ...defaultNetworkOptions(), sharing: true, apps: [{ name: "web", port }] })).toThrow(/port from 1 to 65535/)
    }
    expect(() => networkLaunchFields({ ...defaultNetworkOptions(), sharing: true, apps: [{ name: "web", port: "3000" }, { name: "other", port: "3000" }] })).toThrow(/different port/)
    expect(() => networkLaunchFields({ ...defaultNetworkOptions(), connecting: true, connections: [{ name: "API", port: "8080" }, { name: "api", port: "8081" }] })).toThrow(/different name/)
    expect(() => networkLaunchFields({ ...defaultNetworkOptions(), sharing: true, connecting: true, apps: [{ name: "web", port: "8080" }] })).toThrow(/already used by an app/)
  })
})
