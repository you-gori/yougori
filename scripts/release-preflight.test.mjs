import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import test from "node:test"
import { assertPortableCli, assertMacCli, assertLinuxCli, releaseArchitecture, nativeTarget, macIntelTarget, macArmTarget, parseManifest, portableCliBuildEnv, releaseTarget, verifyRuntimeDirectory, verifyVersions, windowsPeImports, windowsTarget, linuxTarget, linuxArmTarget } from "./release-preflight.mjs"
import { macosPaths } from "./macos-setup.mjs"

const hash = value => createHash("sha256").update(value).digest("hex")

test("release packaging rejects mismatched CLI, engine and vault versions", async t => {
  const root = await mkdtemp(join(tmpdir(), "yougori-release-versions-"))
  t.after(() => rm(root, { recursive: true, force: true }))
  await writeFile(join(root, "package.json"), JSON.stringify({ version: "1.2.3" }))
  for (const component of ["src-tauri", "cli", "engine", "vault"]) {
    await mkdir(join(root, component))
    await writeFile(join(root, component, "Cargo.toml"), '[package]\nversion = "1.2.3"\n')
  }
  await writeFile(join(root, "src-tauri/tauri.conf.json"), JSON.stringify({ version: "1.2.3" }))
  await verifyVersions(root)
  for (const component of ["cli", "engine", "vault"]) {
    await writeFile(join(root, component, "Cargo.toml"), '[package]\nversion = "1.0.0"\n')
    await assert.rejects(() => verifyVersions(root), new RegExp(`${component} version must match`))
    await writeFile(join(root, component, "Cargo.toml"), '[package]\nversion = "1.2.3"\n')
  }
})

function peFixture(dll) {
  const buffer = Buffer.alloc(1024)
  buffer.write("MZ")
  buffer.writeUInt32LE(128, 60)
  buffer.writeUInt32LE(0x4550, 128)
  buffer.writeUInt16LE(0x8664, 132)
  buffer.writeUInt16LE(1, 134)
  buffer.writeUInt16LE(240, 148)
  buffer.writeUInt16LE(0x20b, 152)
  buffer.writeUInt32LE(4096, 152 + 120)
  buffer.writeUInt32LE(40, 152 + 124)
  buffer.writeUInt32LE(4096, 392 + 12)
  buffer.writeUInt32LE(512, 392 + 16)
  buffer.writeUInt32LE(512, 392 + 20)
  buffer.writeUInt32LE(4096 + 64, 512 + 12)
  buffer.write(dll + "\0", 576)
  return buffer
}

test("bundled CLI opts into static CRT without discarding caller build flags", () => {
  assert.equal(portableCliBuildEnv({}, "win32").RUSTFLAGS, "-C target-feature=+crt-static")
  const original = { RUSTFLAGS: "-C debuginfo=0", CARGO_TARGET_DIR: "custom target" }
  assert.equal(portableCliBuildEnv(original, "win32").RUSTFLAGS, "-C debuginfo=0 -C target-feature=+crt-static")
  assert.equal(portableCliBuildEnv(original, "win32").CARGO_TARGET_DIR, "custom target")
  assert.equal(original.RUSTFLAGS, "-C debuginfo=0")
  assert.equal(portableCliBuildEnv({ CARGO_ENCODED_RUSTFLAGS: "--cfg\u001fcustom flag" }, "win32").CARGO_ENCODED_RUSTFLAGS,
    "--cfg\u001fcustom flag\u001f-C\u001ftarget-feature=+crt-static")
})

test("CLI PE verification rejects external Visual C++ DLL dependencies and invalid architectures", () => {
  assert.deepEqual(assertPortableCli(peFixture("KERNEL32.dll")), ["KERNEL32.dll"])
  for (const name of ["VCRUNTIME140.dll", "vcruntime140_1.dll", "MSVCP140.dll", "CONCRT140.dll"]) {
    assert.throws(() => assertPortableCli(peFixture(name)), /unbundled Visual C\+\+ runtime/)
  }
  assert.throws(() => windowsPeImports(Buffer.alloc(20)), /Cannot verify/)
  const arm = peFixture("KERNEL32.dll")
  arm.writeUInt16LE(0xaa64, 132)
  assert.throws(() => assertPortableCli(arm), /x64 PE/)
})

test("Windows installer upgrade policy rejects downgrades without abandoning existing data", async () => {
  const config = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"))
  assert.equal(config.bundle.windows.allowDowngrades, false)
  assert.equal(config.identifier, "com.yougori.desktop")
})

test("release target matches the bundled Windows x64 runtime", () => {
  assert.equal(releaseTarget({}, "win32", "x64"), null)
  assert.equal(releaseTarget({ TAURI_ENV_TARGET_TRIPLE: windowsTarget }, "win32", "x64"), windowsTarget)
  assert.equal(releaseTarget({ CARGO_BUILD_TARGET: windowsTarget }, "win32", "x64"), windowsTarget)
  assert.equal(releaseTarget({ CARGO_BUILD_TARGET: linuxTarget }, "linux", "x64"), linuxTarget)
  assert.deepEqual(portableCliBuildEnv({ RUSTFLAGS: "-C debuginfo=0" }, "linux"), { RUSTFLAGS: "-C debuginfo=0" })
  assert.equal(nativeTarget("linux", "arm64"), linuxArmTarget)
  assert.equal(releaseTarget({ CARGO_BUILD_TARGET: linuxArmTarget }, "linux", "arm64"), linuxArmTarget)
  for (const [platform, arch] of [["linux", "ia32"], ["darwin", "ia32"], ["win32", "arm64"], ["win32", "ia32"]]) {
    assert.throws(() => releaseTarget({}, platform, arch), /Supported desktop builds/)
  }
  for (const variable of ["TAURI_ENV_TARGET_TRIPLE", "CARGO_BUILD_TARGET"]) {
    assert.throws(() => releaseTarget({ [variable]: "aarch64-pc-windows-msvc" }, "win32", "x64"), /Unsupported/)
  }
  assert.throws(() => releaseTarget({ VITE_YOUGORI_TEST_ADAPTER: "1" }, "win32", "x64"), /test adapter/)
})

test("Linux cross packaging requires an explicit architecture and rejects foreign payloads", () => {
  assert.equal(releaseArchitecture({ YOUGORI_RELEASE_ARCH: "arm64" }, "linux", "x64"), "arm64")
  assert.throws(() => releaseArchitecture({ YOUGORI_RELEASE_ARCH: "arm64" }, "win32", "x64"), /Linux only/)
  assert.throws(() => releaseTarget({ CARGO_BUILD_TARGET: linuxArmTarget }, "linux", "x64"), /Unsupported/)
  for (const [arch, machine] of [["x64", 62], ["arm64", 183]]) {
    const elf = Buffer.alloc(64)
    elf.write("\x7fELF")
    elf[4] = 2
    elf[5] = 1
    elf.writeUInt16LE(3, 16)
    elf.writeUInt16LE(machine, 18)
    assertLinuxCli(elf, arch)
    assert.throws(() => assertLinuxCli(elf, arch === "x64" ? "arm64" : "x64"), /Linux ELF/)
    elf[5] = 2
    assert.throws(() => assertLinuxCli(elf, arch), /Linux ELF/)
  }
})

test("runtime manifests reject ambiguous, duplicate and escaping Windows paths", () => {
  for (const path of ["../secret", "/secret", "C:/secret", "dir\\secret", "dir/../secret", "dir//secret", "dir/file:stream", "dir /file", "dir/file.", "SHA256SUMS"]) {
    assert.throws(() => parseManifest(`${hash("ok")}  ${path}\n`))
  }
  assert.throws(() => parseManifest(`${hash("ok")}  A.dll\n${hash("ok")}  a.dll`), /Duplicate/)
  assert.throws(() => parseManifest("not-a-manifest"), /Malformed/)
  assert.equal(parseManifest(`${hash("ok")}  dir/A.dll\r\n`).get("dir/A.dll"), hash("ok"))
})

test("macOS builds require a native matching CLI, no cross-target or universal shortcut", () => {
  for (const [arch, target, cpu] of [["x64", macIntelTarget, 0x01000007], ["arm64", macArmTarget, 0x0100000c]]) {
    assert.equal(nativeTarget("darwin", arch), target)
    assert.equal(releaseTarget({ TAURI_ENV_TARGET_TRIPLE: target }, "darwin", arch), target)
    assert.deepEqual(portableCliBuildEnv({}, "darwin"), {})
    const binary = Buffer.alloc(32)
    binary.writeUInt32LE(0xfeedfacf, 0)
    binary.writeUInt32LE(cpu, 4)
    binary.writeUInt32LE(2, 12)
    assert.doesNotThrow(() => assertMacCli(binary, arch))
    assert.throws(() => assertMacCli(binary, arch === "x64" ? "arm64" : "x64"), /Mach-O/)
    binary.writeUInt32LE(6, 12)
    assert.throws(() => assertMacCli(binary, arch), /Mach-O/)
    assert.throws(() => releaseTarget({ TAURI_ENV_TARGET_TRIPLE: "universal-apple-darwin" }, "darwin", arch), /Unsupported/)
    assert.throws(() => releaseTarget({ CARGO_BUILD_TARGET: linuxTarget }, "darwin", arch), /Unsupported/)
    assert.throws(() => releaseTarget({ VITE_YOUGORI_TEST_ADAPTER: "1" }, "darwin", arch), /test adapter/)
  }
  assert.throws(() => assertMacCli(Buffer.alloc(3), "arm64"), /Mach-O/)
  assert.throws(() => assertMacCli(peFixture("KERNEL32.dll"), "x64"), /Mach-O/)
})

test("Mac installer is architecture-local and bundles QEMU built from pinned sources", async () => {
  const config = JSON.parse(await readFile(new URL("../src-tauri/tauri.macos.conf.json", import.meta.url), "utf8"))
  assert.deepEqual(config.bundle.targets, ["app", "dmg"])
  assert.equal(config.bundle.macOS.minimumSystemVersion, "14.0")
  assert.equal(config.bundle.macOS.hardenedRuntime, true)
  assert.equal(config.bundle.resources["../build/macos-runtime/qemu/"], "runtime/qemu/")
  // Never the Windows QEMU folder or the whole resources tree.
  for (const path of Object.keys(config.bundle.resources)) assert.doesNotMatch(path, /\.exe|\.dll|resources\/runtime\/qemu|resources\/$/)
  const inputs = JSON.parse(await readFile(new URL("./macos-runtime/inputs.json", import.meta.url), "utf8"))
  assert.equal(inputs.deploymentTarget, config.bundle.macOS.minimumSystemVersion)
  assert.equal(inputs.sources.at(-1).name, "qemu")
  for (const source of inputs.sources) {
    assert.match(source.url, /^https:\/\//)
    assert.match(source.sha256, /^[0-9a-f]{64}$/)
    assert.ok(source.license && source.version, source.name)
  }
  // Development builds without a runtime fall back to native Homebrew QEMU.
  assert.equal(macosPaths("arm64").qemu, "/opt/homebrew/opt/qemu/bin/qemu-system-x86_64")
  assert.equal(macosPaths("x64").qemu, "/usr/local/opt/qemu/bin/qemu-system-x86_64")
  assert.throws(() => macosPaths("ia32"), /Supported/)
})

test("Linux packages declare QEMU dependencies and never bundle Windows binaries", async () => {
  const base = JSON.parse(await readFile(new URL("../src-tauri/tauri.conf.json", import.meta.url), "utf8"))
  const linux = JSON.parse(await readFile(new URL("../src-tauri/tauri.linux.conf.json", import.meta.url), "utf8"))
  const windows = JSON.parse(await readFile(new URL("../src-tauri/tauri.windows.conf.json", import.meta.url), "utf8"))
  assert.equal(base.bundle.resources, undefined)
  assert.deepEqual(linux.bundle.targets, ["deb"])
  assert.ok(linux.bundle.linux.deb.depends.some(name => name.startsWith("qemu-system-x86")))
  assert.ok(linux.bundle.linux.deb.depends.includes("ovmf"))
  for (const path of Object.keys(linux.bundle.resources)) assert.doesNotMatch(path, /\.exe|\.dll|qemu|runtime\/$|resources\/$/)
  assert.ok(windows.bundle.resources["resources/cli/yougori-cli.exe"])
  assert.ok(!windows.bundle.resources["resources/cli/"])
})

test("release verification finds corrupt, missing, and accidentally bundled extra payloads", async t => {
  const root = await mkdtemp(join(tmpdir(), "yougori-release-check-"))
  t.after(() => rm(root, { recursive: true, force: true }))
  await mkdir(join(root, "sub"))
  await writeFile(join(root, "sub", "payload.dll"), "verified")
  await writeFile(join(root, "SHA256SUMS"), `${hash("verified")}  sub/payload.dll\n`)
  assert.deepEqual(await verifyRuntimeDirectory(root), { files: 1, bytes: 8 })
  await assert.rejects(() => verifyRuntimeDirectory(root, [], ["missing.exe"]), /Required runtime payload/)
  await writeFile(join(root, "sub", "payload.dll"), "corrupt")
  await assert.rejects(() => verifyRuntimeDirectory(root), /checksum mismatch/)
  await writeFile(join(root, "sub", "payload.dll"), "verified")
  await writeFile(join(root, "forgotten-private-file.txt"), "not in manifest")
  await assert.rejects(() => verifyRuntimeDirectory(root), /Unverified runtime payload/)
  await rm(join(root, "forgotten-private-file.txt"))
  await rm(join(root, "sub", "payload.dll"))
  await assert.rejects(() => verifyRuntimeDirectory(root), /ENOENT/)
})
