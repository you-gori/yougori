import { readdirSync, readFileSync } from "node:fs"
import path from "node:path"
import { describe, expect, it } from "vitest"
import { migrationHeading, outcomeWords, permissionWords, productText, PRODUCT_CONTRACT_VERSION, readProduct, recordedWords, type ProductView } from "@/api/setups/product"

/** The golden documents the Rust contract pins (`foundation::product::fixtures`); the engine's
 *  conversions are tested to produce exactly these, so reading them here keeps the two in step. */
const root = path.resolve(process.cwd(), "src-tauri/src/foundation/product/fixtures")
const fixture = (version: string, name: string) => JSON.parse(readFileSync(path.join(root, version, `${name}.json`), "utf8")) as Record<string, unknown>

describe("the setup's product document", () => {
  it("refuses malformed nested fields and another setup's document before rendering", () => {
    const valid = fixture("v2", "migration_needs_decision")
    for (const change of [
      { permissions: [null] },
      { permissions: [{ kind: "run", text: "Run", status: null }] },
      { refusals: [{ reason: "a reason", remedy_text: 42 }] },
      { migration: { status: { status: "pending" }, items: [{ subject: "x", recorded: null }] } },
      { migration: { status: { status: "in_progress", completed: 3, total: 2 }, items: [] } },
      { shown_at: {} },
    ]) expect(readProduct({ ...valid, ...change })?.readable).toBe(false)
    expect(readProduct(valid, "another-setup")?.readable).toBe(false)
    expect(readProduct(valid, "legacy-lab")?.readable).toBe(true)
  })

  it("makes control and direction-changing characters visible", () => {
    expect(productText("safe\u001b]52;c;payload\u0007\u202eapproved\n"))
      .toBe("safe\\u{1b}]52;c;payload\\u{7}\\u{202e}approved\\u{a}")
  })
  it("reads every current golden fixture and reads none of an older version as current", () => {
    const current = readdirSync(path.join(root, `v${PRODUCT_CONTRACT_VERSION}`)).filter(name => name.endsWith(".json"))
    expect(current.length).toBeGreaterThanOrEqual(6)
    for (const name of current) {
      const read = readProduct(JSON.parse(readFileSync(path.join(root, `v${PRODUCT_CONTRACT_VERSION}`, name), "utf8")))
      expect(read?.readable, name).toBe(true)
    }
    for (const name of readdirSync(path.join(root, "v1")).filter(file => file.endsWith(".json"))) {
      const read = readProduct(JSON.parse(readFileSync(path.join(root, "v1", name), "utf8")))
      expect(read?.readable, name).toBe(false)
    }
  })

  it("words the migration inventory exactly as the terminal does", () => {
    const read = readProduct(fixture("v2", "migration_needs_decision"))
    if (!read?.readable) throw new Error("the migration fixture should read")
    const view: ProductView = read.view
    expect(migrationHeading(view.migration!.status)).toBe("Move to VM sandboxes (an inventory; nothing has changed)")
    const lines = view.migration!.items.map(item => `${item.subject} (${recordedWords(item.recorded)}): ${outcomeWords(item.outcome)}`)
    expect(lines[0]).toBe("web (vm): stays a VM sandbox")
    expect(lines[1]).toMatch(/^api \(container\): becomes a VM sandbox: the container now runs inside a VM sandbox/)
    expect(lines[2]).toBe("trainer (gpu): a decision is needed before it moves: a VM sandbox or GPU runtime (shared kernel), not a sandbox")
    expect(lines[4]).toBe("shared-db (shared): follows the setup that owns it")
    expect(lines[6]).toMatch(/^scratch \(tier T1\): refused: tier T1 was a shared kernel/)
    expect(lines[7]).toBe("metal-runner (host process model runtime): keeps its label: model runtime (host process, sandbox profile), not a sandbox")
    expect(view.refusals?.map(refusal => refusal.code.code)).toEqual(["migration_decision_required", "migration_decision_required"])
  })

  it("never words a requested permission as granted", () => {
    expect(permissionWords({ status: "requested" })).toBe("requested; asking grants nothing")
    const ready = readProduct(fixture("v2", "vm_sandbox_ready"))
    if (!ready?.readable) throw new Error("the sandbox fixture should read")
    const words = (ready.view.permissions ?? []).map(line => permissionWords(line.status))
    expect(words).toContain("requested; asking grants nothing")
    expect(words).toContain("permitted by the contract")
  })

  it("says plainly when a document can't be read, and nothing when there is none", () => {
    expect(readProduct(undefined)).toBeNull()
    expect(readProduct({ ...fixture("v2", "migration_needs_decision"), contract_version: 3 })).toEqual({ readable: false, reason: "The setup's product document was written by a newer Yougori. Update Yougori to read it." })
    expect(readProduct({ contract_version: 2 })?.readable).toBe(false)
    expect(readProduct([1, 2])?.readable).toBe(false)
  })
})
