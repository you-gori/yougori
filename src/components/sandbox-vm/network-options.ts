import type { LaunchRequest } from "@/api/sandbox-vm-api"

export const requestMethods = [
  ["GET", "Read data"], ["POST", "Send data"], ["PUT", "Replace data"],
  ["PATCH", "Update data"], ["DELETE", "Delete data"],
] as const
export interface OnlineRequest { address: string; method: string }
export interface AppConnection { name: string; port: string }
export interface NetworkOptions {
  internet: boolean
  outgoing: boolean
  incoming: boolean
  online: boolean
  requests: OnlineRequest[]
  advanced: boolean
  rules: string
  sharing: boolean
  apps: AppConnection[]
  connecting: boolean
  connections: AppConnection[]
}

export function defaultNetworkOptions(): NetworkOptions {
  return {
    internet: false, outgoing: true, incoming: false,
    online: false, requests: [{ address: "", method: "GET" }], advanced: false, rules: "",
    sharing: false, apps: [{ name: "web", port: "3000" }],
    connecting: false, connections: [{ name: "api", port: "8080" }],
  }
}

interface Route {
  name: string; host: string; port: number
  operations: { name: string; method: string; path: string; query_keys: string[]; effect: "read_only" | "external" }[]
}

function onlineRoutes(requests: OnlineRequest[]): Route[] {
  if (!requests.length) throw new Error("Add an online address, or turn online access off.")
  const routes = new Map<string, Route>()
  for (const [index, request] of requests.entries()) {
    let address: URL
    try { address = new URL(request.address.trim()) }
    catch { throw new Error(`Online address ${index + 1}: enter a full HTTPS address, such as https://api.example.com/v1/models.`) }
    if (address.protocol !== "https:" || address.username || address.password || address.hash || address.port === "0") {
      throw new Error(`Online address ${index + 1}: use HTTPS without a password or #fragment in the address.`)
    }
    if (!requestMethods.some(([method]) => method === request.method)) throw new Error("Choose an action for each online address.")
    // Match the engine's literal PathTemplate syntax; broader templates belong in advanced rules.
    if (!/^\/(?:[A-Za-z0-9._~-]+(?:\/[A-Za-z0-9._~-]+)*)?$/.test(address.pathname)) {
      throw new Error(`Online address ${index + 1}: use a simple API path without spaces, encoded characters, or a trailing slash.`)
    }
    const route: Route = routes.get(address.origin) ?? { name: `online-${routes.size + 1}`, host: address.hostname, port: Number(address.port || 443), operations: [] }
    const queryKeys = [...new Set(address.searchParams.keys())].sort()
    const previous = route.operations.find(operation => operation.path === address.pathname && operation.method === request.method)
    if (previous) previous.query_keys = [...new Set([...previous.query_keys, ...queryKeys])].sort()
    else route.operations.push({ name: `request-${index + 1}`, method: request.method, path: address.pathname, query_keys: queryKeys, effect: request.method === "GET" ? "read_only" : "external" })
    routes.set(address.origin, route)
  }
  if (routes.size > 24) throw new Error("Choose up to 24 online servers for one sandbox.")
  return [...routes.values()]
}

function appPairs(rows: AppConnection[], kind: "app" | "connection"): string {
  if (!rows.length) throw new Error(`Add an ${kind === "app" ? "app" : "API connection"}, or turn this option off.`)
  if (rows.length > 8) throw new Error(`Choose up to 8 ${kind}s for one sandbox.`)
  const names = new Set<string>()
  const ports = new Set<number>()
  return rows.map((row, index) => {
    const name = row.name.trim().toLowerCase()
    const namePattern = kind === "app" ? /^[a-z][a-z0-9._-]*$/ : /^[a-z][a-z0-9-]*$/
    if (!namePattern.test(name)) throw new Error(`${kind === "app" ? "App" : "Connection"} ${index + 1}: start the name with a letter and use letters, numbers, or hyphens.`)
    const port = Number(row.port)
    if (!/^\d+$/.test(row.port.trim()) || !Number.isInteger(port) || port < 1 || port > 65535) throw new Error(`${name}: choose a port from 1 to 65535.`)
    if (names.has(name)) throw new Error(`Each ${kind} needs a different name; ${name} appears twice.`)
    if (kind === "app" && ports.has(port)) throw new Error(`Each app needs a different port; ${port} appears twice.`)
    names.add(name); ports.add(port)
    return `${name}=${port}`
  }).join(",")
}

/** Disabled controls never grant access, even when their previous values remain in the form. */
export function networkLaunchFields(options: NetworkOptions): Pick<LaunchRequest, "internet" | "routes" | "publish" | "connect"> {
  const fields: Pick<LaunchRequest, "internet" | "routes" | "publish" | "connect"> = {}
  // No backend currently provides all-port ingress. Never silently drop a request
  // for it, or substitute a single published app for that permission.
  if (options.internet && options.incoming) throw new Error("Incoming access to all VM ports is not supported yet. You can share individual apps below.")
  if (options.internet && options.outgoing) fields.internet = true
  else if (options.online) {
    if (options.advanced) {
      let parsed: unknown
      try { parsed = JSON.parse(options.rules) } catch { throw new Error("Check the advanced connection rules: the JSON is not valid.") }
      if (!Array.isArray(parsed) || !parsed.length || parsed.some(route => !route || typeof route !== "object" || Array.isArray(route))) {
        throw new Error("Advanced connection rules must be a non-empty list of route objects.")
      }
      fields.routes = parsed
    } else fields.routes = onlineRoutes(options.requests)
  }
  if (options.sharing) fields.publish = appPairs(options.apps, "app")
  if (options.connecting) fields.connect = appPairs(options.connections, "connection")
  if (options.sharing && options.connecting) {
    const conflict = options.connections.find(connection => options.apps.some(app => Number(app.port) === Number(connection.port)))
    if (conflict) throw new Error(`Port ${Number(conflict.port)} is already used by an app in this sandbox. Choose another port for ${conflict.name}.`)
  }
  return fields
}
