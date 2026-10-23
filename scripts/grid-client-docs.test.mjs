import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import path from "node:path"
import test from "node:test"
import assert from "node:assert/strict"
import { commands, render, TARGET } from "./grid-client-docs.mjs"
import { read, render as renderRoles, TARGET as ROLES } from "./grid-core-roles.mjs"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const run = (script, ...args) => execFileSync(process.execPath, [path.join(root, "scripts", script), ...args], { encoding: "utf8" })

test("the checked-in guide is what the client would write today", () => {
  const { text, problems } = render()
  assert.deepEqual(problems, [], problems.join("\n"))
  assert.equal(readFileSync(TARGET, "utf8").replace(/\r\n/g, "\n"), text)
  assert.doesNotThrow(() => run("grid-client-docs.mjs", "--check"))
})

test("every method says where it goes, and a command it names really exists", () => {
  const known = commands()
  assert.ok(known.has("grid_status"), "grid_status is a desktop command and should be known")
  assert.ok(known.has("grid_password"), "grid_password is on the wire only and should still be known")
  assert.ok(known.has("access_use"), "access_use is on the wire only and should still be known")
  assert.ok(!known.has("grids_invented"), "a name nobody registered must not look known")
  const guide = readFileSync(TARGET, "utf8")
  for (const row of guide.matchAll(/\| `([a-z_]+)` \|$/gm)) assert.ok(known.has(row[1]), `${row[1]} is named in the guide and is not a command`)
})

test("the guide names what replaces what, for every product module", () => {
  const guide = readFileSync(TARGET, "utf8")
  for (const module of ["grid-api", "desks-api", "swarm-api", "bounty-api", "access-api"]) {
    assert.ok(guide.includes(`| \`${module}\` |`), `${module} is missing from the table of what replaces what`)
  }
  assert.ok(guide.includes("src/api/access-api.ts` is not changed"), "the guide should say that module is left alone")
})

test("the client's permission table is what the engine's table says today", () => {
  assert.equal(readFileSync(ROLES, "utf8").replace(/\r\n/g, "\n"), renderRoles(read()))
  assert.doesNotThrow(() => run("grid-core-roles.mjs", "--check"))
})

test("the permission table is read from the Rust, not copied into the script", () => {
  const source = `
pub enum Role {
    Reader,
    Keeper,
}
impl Role {
    pub fn implies(self) -> &'static [Role] {
        match self {
            Role::Keeper => &[Role::Reader],
            _ => &[],
        }
    }
    pub fn may(self, action: Action) -> bool {
        use Action::*;
        match self {
            Role::Reader => matches!(action, ReadOwn),
            Role::Keeper => matches!(action, ReadOwn | KeepThings),
        }
    }
}
pub enum Action {
    ReadOwn,
    KeepThings,
}
impl Action {
    pub fn name(self) -> &'static str {
        use Action::*;
        match self {
            ReadOwn => "read own",
            KeepThings => "keep things",
        }
    }
}
`
  const table = read(source)
  assert.deepEqual(table.roles, ["reader", "keeper"])
  assert.deepEqual(table.permissions.keeper, ["readOwn", "keepThings"])
  assert.deepEqual(table.implies.keeper, ["reader"])
  assert.deepEqual(table.implies.reader, [])
  assert.equal(table.names.keepThings, "keep things")
  assert.ok(renderRoles(table).includes(`keeper: ["readOwn", "keepThings"],`))
})

test("a role changed in the Rust and not regenerated is caught", () => {
  const table = read()
  const drifted = { ...table, permissions: { ...table.permissions, auditor: ["readRealm"] } }
  assert.notEqual(renderRoles(drifted), readFileSync(ROLES, "utf8").replace(/\r\n/g, "\n"))
})
