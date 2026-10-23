// Writes src/api/grids/permits.generated.ts from grid/src/core/identity.rs, so the table the
// user interface reads cannot quietly drift from the one the engine enforces.
//
// The engine and the hub decide what actually happens. This table only decides what the client
// offers and how quickly it can say no. Run `node scripts/grid-core-roles.mjs` after changing a
// role in Rust; `--check` re-renders in memory and fails when the checked-in file differs.
import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath, pathToFileURL } from "node:url"
import path from "node:path"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
export const SOURCE = path.join(root, "grid", "src", "core", "identity.rs")
export const TARGET = path.join(root, "src", "api", "grids", "permits.generated.ts")

const lower = word => word.charAt(0).toLowerCase() + word.slice(1)

/** The body of `name {` up to its matching close brace. */
function block(text, name) {
  const start = text.indexOf(name)
  if (start < 0) throw new Error(`grid/src/core/identity.rs no longer contains ${name}`)
  let depth = 0
  for (let at = text.indexOf("{", start); at < text.length; at += 1) {
    if (text[at] === "{") depth += 1
    else if (text[at] === "}") {
      depth -= 1
      if (depth === 0) return text.slice(text.indexOf("{", start) + 1, at)
    }
  }
  throw new Error(`grid/src/core/identity.rs has an unclosed ${name}`)
}

/** Variant names of a Rust enum body, ignoring comments and attributes. */
const variants = body => body
  .split("\n")
  .map(line => line.trim())
  .filter(line => /^[A-Z][A-Za-z]*,$/.test(line))
  .map(line => line.slice(0, -1))

export function read(source = readFileSync(SOURCE, "utf8")) {
  const roles = variants(block(source, "pub enum Role"))
  const actions = variants(block(source, "pub enum Action"))
  const may = block(source, "pub fn may(self, action: Action) -> bool")
  const permissions = {}
  for (const role of roles) {
    const arm = may.indexOf(`Role::${role} => matches!(`)
    if (arm < 0) throw new Error(`Role::${role} has no arm in Role::may`)
    const open = may.indexOf("(", may.indexOf("matches!", arm))
    let depth = 0
    let close = open
    for (; close < may.length; close += 1) {
      if (may[close] === "(") depth += 1
      else if (may[close] === ")") {
        depth -= 1
        if (depth === 0) break
      }
    }
    const inside = may.slice(open + 1, close).replace(/\/\/[^\n]*/g, "")
    const [, rest = ""] = inside.split(/action\s*,/)
    permissions[lower(role)] = rest.split("|").map(word => word.trim()).filter(Boolean).map(lower)
  }
  const implies = {}
  const impliesBody = block(source, "pub fn implies(self) -> &'static [Role]")
  for (const role of roles) {
    const arm = new RegExp(`Role::${role}\\s*=>\\s*&\\[([^\\]]*)\\]`).exec(impliesBody)
    implies[lower(role)] = arm ? arm[1].split(",").map(word => word.trim().replace("Role::", "")).filter(Boolean).map(lower) : []
  }
  const names = {}
  const nameBody = block(source, "pub fn name(self) -> &'static str {\n        use Action::*")
  for (const action of actions) {
    const arm = new RegExp(`${action}\\s*=>\\s*"([^"]*)"`).exec(nameBody)
    if (!arm) throw new Error(`Action::${action} has no sentence in Action::name`)
    names[lower(action)] = arm[1]
  }
  return { roles: roles.map(lower), actions: actions.map(lower), permissions, implies, names }
}

const list = items => items.length ? `[${items.map(item => `"${item}"`).join(", ")}]` : "[]"

export function render(table) {
  const lines = [
    "// Written by scripts/grid-core-roles.mjs from grid/src/core/identity.rs. Do not edit by hand.",
    "//",
    "// This mirrors the engine's table so the client can grey out a control and give a sentence",
    "// without a round trip. It grants nothing: every call is checked again by the engine, by the",
    "// hub that holds the data, and by Grid Core at the moment it acts.",
    `import type { Action, Role } from "@/api/grids/types"`,
    "",
    "/** What one role may do, on its own. */",
    "export const ROLE_ACTIONS: Record<Role, readonly Action[]> = {",
    ...table.roles.map(role => `  ${role}: ${list(table.permissions[role])},`),
    "}",
    "",
    "/** What else comes with a role. */",
    "export const ROLE_IMPLIES: Record<Role, readonly Role[]> = {",
    ...table.roles.map(role => `  ${role}: ${list(table.implies[role])},`),
    "}",
    "",
    "/** How to say an action to a person. */",
    "export const ACTION_NAMES: Record<Action, string> = {",
    ...table.actions.map(action => `  ${action}: "${table.names[action]}",`),
    "}",
    "",
  ]
  return lines.join("\n")
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const wanted = render(read())
  if (process.argv.includes("--check")) {
    const found = readFileSync(TARGET, "utf8").replace(/\r\n/g, "\n")
    if (found !== wanted) {
      console.error("src/api/grids/permits.generated.ts no longer matches grid/src/core/identity.rs. Run: node scripts/grid-core-roles.mjs")
      process.exit(1)
    }
    console.log("The client's permission table matches the engine's.")
  } else {
    writeFileSync(TARGET, wanted)
    console.log(`Wrote ${path.relative(root, TARGET)}`)
  }
}
