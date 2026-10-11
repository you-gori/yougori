import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import { resolve } from "node:path"
import { expect, test } from "vitest"
import { BACKUP_EXTENSION } from "./legacy-names"

const read = (path: string) => readFileSync(resolve(process.cwd(), path), "utf8")

function repositoryFiles(): string[] | null {
  try {
    const listed = execFileSync("git", ["ls-files", "-z", "--cached", "--others", "--exclude-standard"], { encoding: "utf8" })
    return listed.split("\0").filter(Boolean)
  } catch {
    return null
  }
}

test.skipIf(repositoryFiles() === null)("the pre-rename product name appears only in the legacy-name files", () => {
  // The legacy files hold the old name for existing installs; compliance records and
  // past audit outputs describe what earlier releases actually shipped.
  const oldName = BACKUP_EXTENSION
  const allowed = [
    "appliance/agent/legacy_names.go",
    "appliance/boot/upgrade-root.sh",
    "appliance/boot/test_upgrade_root.py",
    "appliance/boot/smoke_legacy_overlay.py",
    "cli/src/legacy_names.rs",
    "src/lib/legacy-names.ts",
    "compliance/",
    "output/",
  ]
  const offenders = repositoryFiles()!.filter(path => {
    if (allowed.some(entry => path === entry || (entry.endsWith("/") && path.startsWith(entry)))) return false
    let contents: Buffer
    try {
      contents = readFileSync(resolve(process.cwd(), path))
    } catch {
      return false
    }
    // Binary files are rebuilt separately and checked by their own build records.
    if (contents.subarray(0, 8192).includes(0)) return false
    return contents.toString("utf8").toLowerCase().includes(oldName)
  })
  expect(offenders).toEqual([])
})

test("desktop and package branding use Yougori while migrating existing app data", () => {
  const config = JSON.parse(read("src-tauri/tauri.conf.json"))
  expect(config.productName).toBe("Yougori")
  expect(config.app.windows[0].title).toBe("Yougori")
  expect(config.identifier).toBe("com.yougori.desktop")
  expect(read("src-tauri/src/lib.rs")).toContain('migrate_legacy_app_data(&app_directory)')
  expect(read("src-tauri/src/workspace/cloudflare.rs")).toContain('const VAULT_SERVICE: &str = "Yougori.CloudflareTunnel.v1"')
  expect(read("src-tauri/src/backup.rs")).toContain('const CREDENTIAL_SERVICE: &str = "com.yougori.desktop.backup"')
  expect(JSON.parse(read("package.json")).name).toBe("yougori")
  expect(JSON.parse(read("package-lock.json")).name).toBe("yougori")
  expect(read("src-tauri/Cargo.toml")).toContain('name = "yougori"')
  expect(read("src-tauri/windows-app-manifest.xml")).toContain('name="Yougori"')
})

test("new backups and agent setup use the new name while old backups remain selectable", () => {
  expect(read("src-tauri/src/local_backup.rs")).toContain('const MANIFEST: &str = "backup.yougori"')
  expect(read("src/api/local-backup-api.ts")).toContain('extensions: ["yougori", BACKUP_EXTENSION]')
  expect(read("skills/yougori/SKILL.txt")).toMatch(/name: yougori\r?\n/)
  expect(read("cli/src/skills.rs")).toContain('root.join("skills/yougori")')
  expect(read("scripts/bundle-cli.mjs")).toContain('"yougori-cli.exe"')
  // Only the current CLI names are bundled; no copy under the pre-rename name.
  expect(read("scripts/bundle-cli.mjs")).not.toContain("legacyName")
})
