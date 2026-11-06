// Measures the removal ledger against a Git tree without checking out or changing that tree.
// Counts are lexical source/content lines, not a claim that a legacy responsibility was removed.
import { spawnSync } from "node:child_process"
import { readFileSync } from "node:fs"
import path from "node:path"
import { fileURLToPath, pathToFileURL } from "node:url"

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const KINDS = ["production", "tests", "docs", "generated"]
const SOURCE = /\.(?:rs|tsx?|jsx?|mjs|cjs|py|go|sh|ps1|css|html|ya?ml|json|toml|txt|md|lock)$/i
const EXCLUDED = /(?:^|\/)(?:target|node_modules|\.git|__pycache__|\.venv|dist)(?:\/|$)/

// A module also includes its adjacent test/spec file; directory scopes include their contents.
// The scopes are explicit so a changed ledger can be reviewed rather than parsed as prose.
export const AREAS = [
  { id: "L1", name: "Creation wizards", paths: ["src/components/grid-create-wizard.tsx", "src/lib/grid-blueprint.ts", "src/components/grid-host-dialog.tsx", "src/components/grid-join-dialog.tsx", "src/components/access-dialogs.tsx", "src/components/swarm-dialogs.tsx", "src/components/closed-bounty-dialog.tsx", "src/components/desk-login-dialog.tsx", "cli/src/launcher/grid_setup.rs", "src/components/setups", "cli/src/hub/setups.rs", "cli/src/hub/plan.rs", "setup/src/draft.rs"] },
  { id: "L2", name: "Template orchestration", paths: ["cli/src/hub/run.rs", "cli/src/hub/lifecycle.rs", "cli/src/hub/tools.rs", "cli/src/hub/instances.rs", "cli/src/hub/client.rs", "cli/src/hub/publish.rs", "cli/src/template_models.rs", "src-tauri/src/template_hub.rs", "src-tauri/src/setups"] },
  { id: "L3", name: "Registries and singleton lookups", paths: ["src-tauri/src/grids/registry.rs", "src-tauri/src/grid.rs", "src-tauri/src/grid", "src-tauri/src/deskgrid.rs", "src-tauri/src/desks/instances.rs", "src-tauri/src/accessgrid.rs", "src-tauri/src/accessgrid_tests.rs", "src-tauri/src/bounty.rs", "src-tauri/src/setups/store.rs", "src-tauri/src/setups/adopt.rs", "src-tauri/src/setups/model.rs", "grid/src/access/instances.rs"] },
  { id: "L4", name: "Lifecycle and publication", paths: ["src-tauri/src/grid.rs", "src-tauri/src/deskgrid.rs", "src-tauri/src/accessgrid.rs", "src-tauri/src/bounty.rs", "src-tauri/src/desks.rs", "src-tauri/src/hub_tunnel.rs", "src-tauri/src/setups"] },
  { id: "L5", name: "Navigation and product views", paths: ["src/pages/desks-page.tsx", "src/pages/neocloud-page.tsx", "src/pages/access-page.tsx", "src/pages/swarm-mining-page.tsx", "src/pages/grids-page.tsx", "src/components/grid-realm-view.tsx", "src/components/grid-controls.tsx", "src/components/grid-timeline.tsx", "src/components/grid-deletion.tsx", "src/api/grids", "src/api/setups", "src/components/setups", "src/pages/setups-page.tsx", "src/components/app-shell.tsx", "src/App.tsx", "src/app.tsx"] },
  { id: "L6", name: "Tool setup and sign-in", paths: ["cli/src/container_tools.rs", "cli/src/tool_credentials.rs", "cli/src/terminal", "examples/hub/my-api", "examples/hub/ai-workspace", "src-tauri/src/setups/ordinary.rs"] },
  { id: "L7", name: "Legacy command parsers", paths: ["cli/src/grid.rs", "cli/src/access.rs", "cli/src/closed_bounty.rs", "cli/src/parse.rs", "cli/src/grids", "src-tauri/src/grids.rs", "cli/src/hub/setups.rs"] },
  { id: "L8", name: "Domain logic to keep", paths: [] },
]

export const DOMAINS = [
  { id: "D1", name: "Model serving", paths: ["grid/src/hub.rs", "grid/src/harness.rs", "grid/src/member.rs", ...["policy", "schedule", "activity", "net", "tunnel", "invite", "password"].map(name => `grid/src/${name}.rs`)] },
  { id: "D2", name: "Workspaces", paths: ["grid/src/desks.rs", "grid/src/hub/enterprise.rs", "grid/src/enterprise.rs", "grid/src/provisioning.rs", "grid/src/hub.rs", "grid/src/relay.rs", "grid/src/totp.rs", "grid/src/jwt.rs", "src-tauri/src/desks.rs", "src-tauri/src/desks", "src-tauri/src/peer_sharing.rs"] },
  { id: "D3", name: "Credential brokering", paths: ["grid/src/access", "grid/src/access.rs"] },
  { id: "D4", name: "Research", paths: ["src-tauri/src/swarm", "grid/src/bounty.rs", "grid/src/bounty_coordination.rs", "grid/src/bounty_project.rs", "src-tauri/src/bounty_project.rs", "cli/src/bounty.rs"] },
  { id: "D5", name: "Rented compute", paths: ["src-tauri/src/grid_neocloud.rs", "src-tauri/src/rented_gpu.rs", "src-tauri/src/neocloud"] },
  { id: "D6", name: "Template format and recipes", paths: [...["format", "render", "refs", "pattern", "unicode", "scan", "review", "components"].map(name => `cli/src/hub/${name}.rs`), "cli/src/manifest.rs", "setup", "examples/hub", "docs/hub.md", "docs/template-platform/adr-0001-format-v2.md", "docs/template-platform/adr-0002-setup-engine.md", "docs/template-platform/capabilities.md"] },
]
AREAS.find(area => area.id === "L8").paths = [...new Set(DOMAINS.flatMap(area => area.paths))]

const normal = name => name.replaceAll("\\", "/")

export function inScope(name, scopes) {
  const file = normal(name)
  return scopes.some(scope => {
    scope = normal(scope)
    if (file === scope || file.startsWith(`${scope}/`)) return true
    const extension = path.posix.extname(scope)
    const stem = scope.slice(0, -extension.length)
    return Boolean(extension) && (file === `${stem}.test${extension}` || file === `${stem}.spec${extension}`)
  })
}

export function category(name, source = "") {
  const file = normal(name)
  const header = source.split(/\r?\n/).slice(0, 12).join("\n")
  if (/\.generated\.[^/]+$|(?:^|\/)(?:Cargo|package|pnpm|yarn)\.lock$/.test(file)
    || file.startsWith("setup/tests/fixtures/") || file === "setup/tests/contract/contract.json"
    || /(?:@generated|auto[- ]generated|generated (?:by|from)|do not edit (?:by hand|manually))/i.test(header)) return "generated"
  if (/(?:^|\/)(?:tests?|__tests__|fixtures|answers|e2e)(?:\/|$)|(?:\.test|\.spec)(?:\.|$)|(?:^|\/)test_[^/]+\.py$|(?:^|\/)[^/]+_test\.(?:go|py|rs)$/.test(file)) return "tests"
  if (/\.(?:md|txt)$/i.test(file) || /(?:^|\/)(?:LICENSE|NOTICE|COPYING)(?:\.[^/]+)?$/.test(file)) return "docs"
  return "production"
}

/** Mask comments and literal contents, retaining a marker on nonblank literal lines. */
export function sourceLines(source, name) {
  const rust = name.endsWith(".rs")
  const hashComments = /\.(?:py|sh|ps1|ya?ml|toml)$/.test(name)
  const slashComments = /\.(?:rs|tsx?|jsx?|mjs|cjs|go|css)$/.test(name)
  const htmlComments = /\.(?:html|md)$/.test(name)
  let blocks = 0
  let quote = ""
  let rawEnd = ""
  let escaped = false
  let html = false
  return source.replace(/^\uFEFF/, "").split(/\r?\n/).map(line => {
    let clean = ""
    for (let i = 0; i < line.length;) {
      const rest = line.slice(i)
      if (html) {
        const end = line.indexOf("-->", i)
        if (end < 0) break
        html = false; i = end + 3; continue
      }
      if (blocks) {
        if (rust && rest.startsWith("/*")) { blocks += 1; i += 2 }
        else if (rest.startsWith("*/")) { blocks -= 1; i += 2 }
        else i += 1
        continue
      }
      if (rawEnd) {
        const end = line.indexOf(rawEnd, i)
        if (line.slice(i, end < 0 ? undefined : end).trim()) clean += "@"
        if (end < 0) break
        i = end + rawEnd.length; rawEnd = ""; clean += "@"; continue
      }
      if (quote) {
        const char = line[i++]
        if (!/\s/.test(char)) clean += "@"
        if (escaped) { escaped = false; continue }
        if (char === "\\") { escaped = true; continue }
        if (char === quote) quote = ""
        continue
      }
      if (htmlComments && rest.startsWith("<!--")) { html = true; i += 4; continue }
      if (slashComments && rest.startsWith("//")) break
      if (slashComments && rest.startsWith("/*")) { blocks = 1; i += 2; continue }
      if (hashComments && line[i] === "#") break
      if (rust && /^(?:br|r)#{0,255}"/.test(rest) && (i === 0 || !/\w/.test(line[i - 1]))) {
        const start = /^(?:br|r)(#{0,255})"/.exec(rest)
        rawEnd = `"${start[1]}`; i += start[0].length; clean += "@"; continue
      }
      const char = line[i]
      if (char === '"' || (!rust && (char === "'" || char === "`")) || (rust && char === "'" && /^'(?:\\.|[^'\\])'/.test(rest))) {
        quote = char; clean += "@"; i += 1; continue
      }
      clean += char; i += 1
    }
    // Escapes do not carry across a line except a literal's explicit continuation.
    escaped = false
    return { clean, counted: Boolean(clean.trim()) }
  })
}

/** Rust inline #[cfg(test)] modules/functions are tests even in production-named files. */
export function countLines(name, source) {
  const result = Object.fromEntries(KINDS.map(kind => [kind, 0]))
  const kind = category(name, source)
  const rust = normal(name).endsWith(".rs")
  let depth = 0
  let testDepth = null
  let pending = false
  for (const line of sourceLines(source, normal(name))) {
    if (!line.counted) continue
    if (kind === "production" && rust) {
      const marked = /#\[\s*cfg\s*\(\s*test\s*\)\s*\]|#\[\s*(?:[\w]+::)?test(?:\s*\([^\]]*\))?\s*\]/.test(line.clean)
      if (marked && testDepth === null) pending = true
      result[testDepth !== null || pending ? "tests" : "production"] += 1
      for (const char of line.clean) {
        if (char === "{") {
          if (pending && testDepth === null) { testDepth = depth; pending = false }
          depth += 1
        } else if (char === "}") {
          depth -= 1
          if (testDepth !== null && depth === testDepth) testDepth = null
        }
      }
      if (pending && /;\s*$/.test(line.clean)) pending = false
    } else result[kind] += 1
  }
  return result
}

function git(root, args, optional = false) {
  const got = spawnSync("git", args, { cwd: root, encoding: "utf8", maxBuffer: 32 * 1024 * 1024, windowsHide: true })
  if (got.error) throw new Error("Git could not be started")
  if (got.status !== 0) {
    if (optional) return null
    throw new Error(`Read-only Git command failed: git ${args[0]}`)
  }
  return got.stdout
}

function include(name) {
  return !EXCLUDED.test(name) && (SOURCE.test(name) || /(?:^|\/)(?:LICENSE|NOTICE|COPYING)(?:\.[^/]+)?$/.test(name))
}

function sum(files, counts) {
  const result = Object.fromEntries(KINDS.map(kind => [kind, 0]))
  for (const file of files) for (const kind of KINDS) result[kind] += counts.get(file)?.[kind] ?? 0
  return result
}

export function measure(root = ROOT, baseline = "da2b00c", io = {}) {
  const runGit = io.git ?? git
  const read = io.readFile ?? readFileSync
  const commit = runGit(root, ["rev-parse", "--verify", `${baseline}^{commit}`]).trim()
  const oldFiles = runGit(root, ["ls-tree", "-r", "--name-only", "-z", commit]).split("\0").filter(Boolean)
  const nowFiles = runGit(root, ["ls-files", "--cached", "--others", "--exclude-standard", "-z"]).split("\0").filter(Boolean)
  const universe = [...new Set([...oldFiles, ...nowFiles])].filter(include).sort()
  const scoped = universe.filter(file => inScope(file, AREAS.flatMap(area => area.paths)))
  const before = new Map()
  const after = new Map()
  const old = new Set(oldFiles)
  for (const file of scoped) {
    if (old.has(file)) before.set(file, countLines(file, runGit(root, ["show", `${commit}:${file}`])))
    try { after.set(file, countLines(file, read(path.join(root, file), "utf8"))) }
    catch (error) { if (error.code !== "ENOENT") throw new Error(`Cannot read ${file}`) }
  }
  const rows = areas => areas.map(area => {
    const files = scoped.filter(file => inScope(file, area.paths))
    return { id: area.id, name: area.name, files, before: sum(files, before), after: sum(files, after) }
  })
  return {
    baseline: commit,
    definition: "Nonblank source/content lines; standalone and block comments excluded. Inline Rust test regions are tests. Whole modules are measured where the ledger cites partial responsibilities. Rows overlap; only the unique total can be summed.",
    areas: rows(AREAS), domains: rows(DOMAINS),
    total: { files: scoped.length, before: sum(scoped, before), after: sum(scoped, after) },
  }
}

export function markdown(report) {
  const table = rows => [
    "| Area | Production before | Production now | Tests before | Tests now | Docs before | Docs now | Generated before | Generated now |",
    "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ...rows.map(row => `| ${row.id ? `${row.id} ` : ""}${row.name} | ${KINDS.flatMap(kind => [row.before[kind], row.after[kind]]).join(" | ")} |`),
  ].join("\n")
  return [
    `Baseline: \`${report.baseline}\`.`, report.definition,
    table(report.areas),
    "Domain breakdown of L8 (also overlapping; do not add it to the first table):",
    table(report.domains),
    table([{ name: `Unique total (${report.total.files} files)`, before: report.total.before, after: report.total.after }]),
  ].join("\n\n")
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    const args = process.argv.slice(2)
    if (args.some(arg => !["--json"].includes(arg))) throw new Error("Usage: node scripts/measure-template-platform.mjs [--json]")
    const report = measure()
    process.stdout.write((args.includes("--json") ? JSON.stringify(report, null, 2) : markdown(report)) + "\n")
  } catch (error) {
    process.stderr.write(`${error.message}\n`)
    process.exitCode = 1
  }
}
