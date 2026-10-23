// Writes docs/grid-core/typescript-api.md from the client itself, so the guide cannot quietly
// go out of date. It reads src/api/grids with the TypeScript compiler, which is already a
// development dependency here, so nothing is fetched and nothing is run.
//
// Every method has to say where it goes, with exactly one of three tags:
//   @command NAME   an engine command, which must really exist
//   @via NAME       another module this one wraps, such as accessApi
//   @local          answered on this computer, with no call at all
// A method without one fails this script, which is how the guide stays true. The same idea as
// cli/src/help_coverage.rs, which fails the command line's tests when a route is missing.
//
// `--check` renders in memory and exits non-zero when the checked-in file differs.
import { readFileSync, writeFileSync } from "node:fs"
import { fileURLToPath, pathToFileURL } from "node:url"
import path from "node:path"
import ts from "typescript"

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
export const TARGET = path.join(root, "docs", "grid-core", "typescript-api.md")

const PROFILES = [
  ["models", "Closed Neo Grid", "src/api/grids/profiles/models.ts"],
  ["workspaces", "Sandbox Grid", "src/api/grids/profiles/workspaces.ts"],
  ["credentials", "Access Grid", "src/api/grids/profiles/credentials.ts"],
  ["research", "Swarm Mining and closed bounties", "src/api/grids/profiles/research.ts"],
]

const PIECES = [
  ["src/api/grids/types.ts", "Types", "The vocabulary: realms, principals, devices, hosts, plans, workspaces, credentials, approvals, research jobs and audit events."],
  ["src/api/grids/errors.ts", "Refusals", "One class per kind of refusal, each carrying the command and the call's name. The engine's own words are kept exactly."],
  ["src/api/grids/page.ts", "Pages and filters", "Asking for no page asks for the whole list. Every filter left out narrows nothing."],
  ["src/api/grids/permits.ts", "What the client offers", "A mirror of the engine's table. It grants nothing; the engine, the hub and Grid Core each check again."],
  ["src/api/grids/redact.ts", "Redaction", "A second line of defence over answers, not enforcement. Opt-in per field, and it never walks somebody else's document."],
  ["src/api/grids/events.ts", "Events and the shared read", "One desktop event as an accelerator, with reads as the truth and one shared poller behind every watcher."],
  ["src/api/grids/wire.ts", "The one call path", "Request names, optimistic versions, the transport seam and the typed refusal."],
  ["src/api/grids/compat.ts", "Mapping tables", "Where the four products' words meet Grid Core's, one table per state that differs."],
]

const parse = file => ts.createSourceFile(file, readFileSync(path.join(root, file), "utf8"), ts.ScriptTarget.ES2022, true)

/** The engine commands that exist, from both doors. */
export function commands() {
  const found = new Set()
  const handler = readFileSync(path.join(root, "src-tauri", "src", "lib.rs"), "utf8")
  const list = handler.slice(handler.indexOf("tauri::generate_handler!["))
  for (const entry of list.slice(0, list.indexOf("]")).split(",")) {
    const name = entry.trim().split("::").pop()
    if (name && /^[a-z_0-9]+$/.test(name)) found.add(name)
  }
  const wire = readFileSync(path.join(root, "src-tauri", "src", "automation", "dispatch.rs"), "utf8")
  for (const arm of wire.matchAll(/"([a-z][a-z_0-9]*)"\s*=>/g)) found.add(arm[1])
  return found
}

const doc = node => {
  const [comment] = ts.getJSDocCommentsAndTags(node)
  if (!comment) return { text: "", tag: null, target: "" }
  const text = (ts.getTextOfJSDocComment(comment.comment) ?? "").replace(/\s+/g, " ").trim()
  for (const tag of comment.tags ?? []) {
    const name = tag.tagName.escapedText
    if (name === "command" || name === "via" || name === "local") {
      return { text, tag: name, target: (ts.getTextOfJSDocComment(tag.comment) ?? "").trim() }
    }
  }
  return { text, tag: null, target: "" }
}

const signature = (name, value) => {
  if (ts.isArrowFunction(value) || ts.isFunctionExpression(value)) {
    return `${name}(${value.parameters.map(parameter => parameter.getText()).join(", ")})`
  }
  return name
}

/** Every method of one exported object, including one level of nesting. */
function methods(file, exported) {
  const source = parse(file)
  const out = []
  const walk = (object, prefix) => {
    for (const property of object.properties) {
      if (ts.isMethodDeclaration(property)) {
        out.push({ ...doc(property), name: `${prefix}${signature(property.name.getText(), property)}`, plain: `${prefix}${property.name.getText()}` })
        continue
      }
      if (!ts.isPropertyAssignment(property)) continue
      const name = property.name.getText()
      if (ts.isObjectLiteralExpression(property.initializer)) { walk(property.initializer, `${prefix}${name}.`); continue }
      out.push({ ...doc(property), name: `${prefix}${signature(name, property.initializer)}`, plain: `${prefix}${name}` })
    }
  }
  for (const statement of source.statements) {
    if (!ts.isVariableStatement(statement)) continue
    for (const declaration of statement.declarationList.declarations) {
      if (declaration.name.getText() !== exported || !declaration.initializer || !ts.isObjectLiteralExpression(declaration.initializer)) continue
      walk(declaration.initializer, "")
    }
  }
  return out
}

/** Everything one file exports by name, so the guide lists what is really there. */
function exports_(file) {
  const source = parse(file)
  const names = []
  const add = name => { if (name && !names.includes(name)) names.push(name) }
  for (const statement of source.statements) {
    const shared = statement.modifiers?.some(modifier => modifier.kind === ts.SyntaxKind.ExportKeyword)
    if (!shared) continue
    if (ts.isVariableStatement(statement)) for (const declaration of statement.declarationList.declarations) add(declaration.name.getText())
    else if (ts.isFunctionDeclaration(statement) || ts.isClassDeclaration(statement) || ts.isInterfaceDeclaration(statement) || ts.isTypeAliasDeclaration(statement)) add(statement.name?.getText())
  }
  return names
}

/** The rows of LEGACY_METHODS in compat.ts, read rather than copied. */
function legacy() {
  const source = parse("src/api/grids/compat.ts")
  const rows = []
  const visit = node => {
    if (ts.isVariableDeclaration(node) && node.name.getText() === "LEGACY_METHODS" && node.initializer) {
      for (const entry of node.initializer.getChildren().flatMap(child => child.kind === ts.SyntaxKind.SyntaxList ? child.getChildren() : [])) {
        if (!ts.isObjectLiteralExpression(entry)) continue
        const row = {}
        for (const property of entry.properties) {
          if (ts.isPropertyAssignment(property)) row[property.name.getText()] = property.initializer.getText().replace(/^"|"$/g, "")
        }
        rows.push(row)
      }
    }
    ts.forEachChild(node, visit)
  }
  visit(source)
  return rows
}

const where = entry => entry.tag === "command" ? `\`${entry.target}\`` : entry.tag === "via" ? `through \`${entry.target}\`` : "on this computer"

export function render() {
  const known = commands()
  const problems = []
  const lines = [
    "# The TypeScript client",
    "",
    "Written by `scripts/grid-client-docs.mjs` from `src/api/grids`. Do not edit by hand; change the",
    "code and run `node scripts/grid-client-docs.mjs`.",
    "",
    "One client, four grids. `grids.models`, `grids.workspaces`, `grids.credentials` and",
    "`grids.research` speak Grid Core's vocabulary over the engine commands that exist today. The",
    "four product modules keep their own paths, their own types and their own answers, and they now",
    "send through the same one call path, so a request name, a typed refusal and the redaction pass",
    "cover what the pages already do. A page moves to `grids` when its own test moves with it.",
    "",
    "Every method below says where it goes: an engine command, another module it wraps, or this",
    "computer. A method that says nothing fails the generator.",
    "",
  ]
  for (const [name, product, file] of PROFILES) {
    lines.push(`## grids.${name}`, "", `${product}.`, "", "| Method | What it does | Where it goes |", "| --- | --- | --- |")
    for (const entry of methods(file, name)) {
      if (!entry.tag) problems.push(`${file}: ${entry.plain} says nothing about where it goes`)
      if (entry.tag === "command" && entry.target !== "plugin-dialog" && !known.has(entry.target)) {
        problems.push(`${file}: ${entry.plain} names ${entry.target}, which is not a command in lib.rs or automation/dispatch.rs`)
      }
      lines.push(`| \`${entry.name}\` | ${entry.text || ""} | ${where(entry)} |`)
    }
    lines.push("")
  }
  lines.push("## The shared pieces", "")
  for (const [file, title, says] of PIECES) {
    lines.push(`### ${title}`, "", says, "", `\`${file}\` exports: ${exports_(file).map(name => `\`${name}\``).join(", ")}.`, "")
  }
  lines.push(
    "## What replaces what",
    "",
    "Every method the four product modules export today, and what a page calls once it moves. The",
    "engine command is the same on both sides, so nothing changes on the engine the day a page moves.",
    "",
    "| Module | Today | After it moves | Engine command |",
    "| --- | --- | --- | --- |",
  )
  for (const row of legacy()) lines.push(`| \`${row.module}\` | \`${row.legacy}\` | \`${row.next}\` | \`${row.command}\` |`)
  lines.push(
    "",
    "`src/api/access-api.ts` is not changed by any of this. `grids.credentials` calls it, which is",
    "why that grid's answers are handed to the redaction pass in the profile rather than in the call",
    "path, and why `use`, `check` and `reveal` name the command line: they exist on the local wire",
    "only, with no desktop command at all.",
    "",
  )
  return { text: lines.join("\n"), problems }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const { text, problems } = render()
  if (problems.length) {
    for (const problem of problems) console.error(problem)
    process.exit(1)
  }
  if (process.argv.includes("--check")) {
    const found = readFileSync(TARGET, "utf8").replace(/\r\n/g, "\n")
    if (found !== text) {
      console.error("docs/grid-core/typescript-api.md no longer matches the client. Run: node scripts/grid-client-docs.mjs")
      process.exit(1)
    }
    console.log("The TypeScript client guide matches the client.")
  } else {
    writeFileSync(TARGET, text)
    console.log(`Wrote ${path.relative(root, TARGET)}`)
  }
}
