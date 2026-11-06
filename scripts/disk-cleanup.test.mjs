import test from "node:test"
import assert from "node:assert/strict"
import { spawnSync } from "node:child_process"
import { mkdtempSync, mkdirSync, writeFileSync, existsSync, rmSync, symlinkSync, utimesSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"

const available = spawnSync("pwsh", ["-NoProfile", "-Command", "exit 0"], { windowsHide: true }).status === 0
const script = resolve("scripts/disk-cleanup.ps1")

test("disk cleanup keeps the newest releases and leaves unrelated data alone", { skip: !available }, () => {
  const root = mkdtempSync(join(tmpdir(), "yougori disk cleanup "))
  const drive = join(root, "drive")
  const temp = join(root, "temp")
  const workspace = join(root, "checkout")
  const outside = join(root, "outside")
  const scratch = join(root, "scratch")
  const run = (...args) => spawnSync("pwsh", ["-NoProfile", "-File", script, "-ReleaseRoot", drive, "-ScratchRoot", scratch,
    "-TempRoot", temp, "-WorkspaceRoot", workspace, "-SkipWsl", ...args], { encoding: "utf8", windowsHide: true })
  try {
    mkdirSync(join(workspace, "src-tauri"), { recursive: true })
    writeFileSync(join(workspace, "src-tauri", "Cargo.toml"), "[package]\nname='fixture'\n")
    mkdirSync(outside)
    writeFileSync(join(outside, "important"), "preserve")
    // 1.0.10 is newer than 1.0.9: versions sort numerically, not by name.
    for (const version of ["1.0.9", "1.0.10", "1.1.0", "1.1.1"]) {
      mkdirSync(join(drive, `yougori-${version}`, "linux"), { recursive: true })
      writeFileSync(join(drive, `yougori-${version}`, "linux", "app"), version)
    }
    mkdirSync(join(drive, "DATA TO NOT TOUCH"))
    writeFileSync(join(drive, "DATA TO NOT TOUCH", "photo"), "private")
    mkdirSync(join(drive, "yougori-1.1.1-notes"))
    symlinkSync(outside, join(drive, "yougori-0.9.0"), process.platform === "win32" ? "junction" : "dir")
    // A target linked to a build folder that was since deleted must not stop the report.
    mkdirSync(join(drive, "YougoriBuildCache", "native-release"), { recursive: true })
    mkdirSync(join(workspace, "src-tauri", "target"))
    symlinkSync(join(drive, "YougoriBuildCache", "native-release"), join(workspace, "src-tauri", "target", "release"), process.platform === "win32" ? "junction" : "dir")
    rmSync(join(drive, "YougoriBuildCache", "native-release"), { recursive: true })
    // Ad hoc session targets in the scratch folder are compiler caches too.
    const sessionProfile = join(scratch, "yougori-engine-target", "debug")
    mkdirSync(join(sessionProfile, ".fingerprint"), { recursive: true })
    mkdirSync(join(sessionProfile, "deps"))
    writeFileSync(join(sessionProfile, ".cargo-lock"), "")
    writeFileSync(join(sessionProfile, "deps", "cache"), "cache")

    const old = (Date.now() - 3 * 86_400_000) / 1000
    // Interrupted Git LFS copies; a recent one may still be in use.
    const lfsTemp = join(workspace, ".git", "lfs", "tmp")
    mkdirSync(lfsTemp, { recursive: true })
    writeFileSync(join(lfsTemp, "1733514961"), "partial copy")
    utimesSync(join(lfsTemp, "1733514961"), old, old)
    writeFileSync(join(lfsTemp, "3100897187"), "in progress")
    for (const [name, file] of [["leak", "realm.db"], ["minting", "minting.db"], ["fresh", "realm.db"], ["other", "notes.db"]]) {
      mkdirSync(join(temp, name), { recursive: true })
      writeFileSync(join(temp, name, file), "db")
      if (name !== "fresh") utimesSync(join(temp, name), old, old)
    }

    let result = run()
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /Reclaimable:/)
    assert.doesNotMatch(result.stdout + result.stderr, /Skipped compiler caches/)
    assert.match(result.stdout, /yougori-1\.0\.9/)
    assert.ok(result.stdout.includes(join(sessionProfile, "deps")), result.stdout)
    assert.ok(existsSync(join(sessionProfile, "deps", "cache")))
    assert.ok(existsSync(join(drive, "yougori-1.0.9", "linux", "app")))
    assert.ok(existsSync(join(temp, "leak", "realm.db")))

    result = run("-Clean")
    assert.equal(result.status, 0, result.stderr)
    assert.match(result.stdout, /Removed:/)
    for (const gone of ["yougori-1.0.9", "yougori-1.0.10"]) assert.equal(existsSync(join(drive, gone)), false)
    for (const kept of ["yougori-1.1.0/linux/app", "yougori-1.1.1/linux/app", "DATA TO NOT TOUCH/photo", "yougori-1.1.1-notes"]) {
      assert.ok(existsSync(join(drive, kept)), kept)
    }
    // A linked release name is never followed or deleted.
    assert.ok(existsSync(join(drive, "yougori-0.9.0")))
    assert.ok(existsSync(join(outside, "important")))
    for (const gone of ["leak", "minting"]) assert.equal(existsSync(join(temp, gone)), false)
    for (const kept of ["fresh/realm.db", "other/notes.db"]) assert.ok(existsSync(join(temp, kept)), kept)
    assert.equal(existsSync(join(lfsTemp, "1733514961")), false)
    assert.ok(existsSync(join(lfsTemp, "3100897187")))

    result = run("-Clean", "-KeepReleases", "0")
    assert.notEqual(result.status, 0)
    assert.ok(existsSync(join(drive, "yougori-1.1.0")))
  } finally {
    rmSync(root, { recursive: true, force: true })
  }
})
