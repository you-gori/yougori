import assert from "node:assert/strict"
import path from "node:path"
import test from "node:test"
import { category, countLines, inScope, markdown, measure } from "./measure-template-platform.mjs"

test("classifies generated fixtures before tests and separates docs and test paths", () => {
  for (const name of ["src/api/setups/capabilities.generated.ts", "setup/tests/fixtures/x.plan.json", "setup/tests/contract/contract.json", "setup/Cargo.lock"]) assert.equal(category(name), "generated", name)
  for (const name of ["src/a.test.tsx", "e2e/a.spec.ts", "setup/tests/planning.rs", "examples/hub/a/answers/demo.json", "scripts/test_flow.py", "agent/a_test.go"]) assert.equal(category(name), "tests", name)
  for (const name of ["docs/hub.md", "examples/hub/a/LICENSE", "docs/rules.txt"]) assert.equal(category(name), "docs", name)
  assert.equal(category("src/main.rs"), "production")
  assert.equal(category("src/table.rs", "// Generated from Unicode data.\nconst TABLE: &[u8] = &[];"), "generated")
})

test("ignores blanks and comments but counts code beside comments and comment-like strings", () => {
  assert.deepEqual(countLines("src/a.ts", '// comment\n\n/* block\nstill comment */\nconst url = "https://example.invalid"; // tail\nconst literal = "/* kept */";\n'), { production: 2, tests: 0, docs: 0, generated: 0 })
  assert.equal(countLines("src/a.rs", "/* outer /* nested */ done */\nfn a() {} /* tail */\n").production, 1)
  assert.equal(countLines("a.yaml", '# comment\nvalue: "# literal"\n').production, 1)
  assert.equal(countLines("docs/a.md", '<!-- hidden\nmore -->\n# Title\n\nWords\n').docs, 2)
})

test("attributes inline Rust test modules/functions without treating literal data as syntax", () => {
  const source = 'pub fn a() {}\n#[cfg(test)]\nmod tests {\n // omitted\n #[test]\n fn b() { assert_eq!("}", "{"); }\n}\npub fn c() {}\n#[test]\nfn d() {}\npub fn e() {}\n'
  assert.deepEqual(countLines("src/a.rs", source), { production: 3, tests: 7, docs: 0, generated: 0 })
  const literal = 'const TEXT: &str = r##"\n#[cfg(test)]\n// literal\n{ }\n"##;\nfn real() {}\n'
  assert.deepEqual(countLines("src/a.rs", literal), { production: 6, tests: 0, docs: 0, generated: 0 })
  assert.equal(countLines("src/a.rs", "fn f<'a>(s: &'a str) { let ch = '}'; }\n").production, 1)
})

test("counts a cfg(test) semicolon item without swallowing following production code", () => {
  assert.deepEqual(countLines("src/a.rs", '#[cfg(test)]\nuse crate::fixture;\nfn real() {}\n'), { production: 1, tests: 2, docs: 0, generated: 0 })
})

test("selects exact modules, their adjacent tests and directory descendants only", () => {
  assert.ok(inScope("src/a.test.tsx", ["src/a.tsx"]))
  assert.ok(inScope("src\\api\\a.ts", ["src/api"]))
  assert.ok(!inScope("src/api-old/a.ts", ["src/api"]))
  assert.ok(!inScope("src/another.tsx", ["src/a.tsx"]))
})

test("compares additions/deletions and deduplicates overlapping areas using read-only Git calls", () => {
  const root = path.resolve("fixture")
  const baseline = "a".repeat(40)
  const before = new Map([
    ["src-tauri/src/grid.rs", "fn old() {}\n#[cfg(test)]\nmod tests {\n fn old_test() {}\n}\n"],
    ["src/pages/grids-page.tsx", "export const old = 1;\n"],
  ])
  const after = new Map([
    ["src-tauri/src/grid.rs", "fn new_a() {}\nfn new_b() {}\n"],
    ["setup/src/lib.rs", "pub fn plan() {}\n"],
    ["setup/tests/fixtures/x.json", '{"format":2}\n'],
  ])
  const calls = []
  const report = measure(root, baseline, {
    git(_root, args) {
      calls.push(args)
      if (args[0] === "rev-parse") return baseline
      if (args[0] === "ls-tree") return [...before.keys()].join("\0")
      if (args[0] === "ls-files") return [...new Set([...before.keys(), ...after.keys()])].join("\0")
      if (args[0] === "show") return before.get(args[1].slice(baseline.length + 1))
      assert.fail(`Unexpected Git operation: ${args[0]}`)
    },
    readFile(file) {
      const name = path.relative(root, file).replaceAll("\\", "/")
      if (!after.has(name)) throw Object.assign(new Error("Missing fixture"), { code: "ENOENT" })
      return after.get(name)
    },
  })
  assert.equal(report.total.before.production, 2)
  assert.equal(report.total.before.tests, 4)
  assert.equal(report.total.after.production, 3)
  assert.equal(report.total.after.generated, 1)
  assert.equal(report.total.files, 4)
  assert.ok(report.areas.reduce((sum, area) => sum + area.before.production, 0) > report.total.before.production)
  assert.ok(calls.every(([command]) => ["rev-parse", "ls-tree", "ls-files", "show"].includes(command)))
  assert.match(markdown(report), /Rows overlap; only the unique total/)
  assert.match(markdown(report), /Unique total \(4 files\)/)
})
