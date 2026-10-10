import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import { readFileSync } from "node:fs"
import test from "node:test"

const root = new URL("../", import.meta.url)
const read = path => readFileSync(new URL(path, root))
const json = path => JSON.parse(read(path))
const hash = bytes => createHash("sha256").update(bytes).digest("hex")
const manifest = json("src-tauri/installer/manifest.json")

test("installer artwork is built from the current Yougori logo and generator", () => {
  assert.equal(manifest.source, "logo1.png")
  assert.equal(manifest.sourceSha256, hash(read("logo1.png")))
  assert.equal(manifest.iconSha256, hash(read("src-tauri/icons/icon-source.png")))
  assert.equal(manifest.generatorSha256, hash(read("scripts/generate-installer-branding.mjs").toString().replace(/\r\n?/g, "\n")))
})

const expectedAssets = [
  ["nsis-header.bmp", 150, 57],
  ["nsis-sidebar.bmp", 164, 314],
  ["wix-banner.bmp", 493, 58],
  ["wix-dialog.bmp", 493, 312],
  ["dmg-background.png", 720, 460],
]

function bmpPixel(bytes, x, y) {
  const width = bytes.readInt32LE(18)
  const height = bytes.readInt32LE(22)
  const offset = 54 + (height - 1 - y) * Math.ceil(width * 3 / 4) * 4 + x * 3
  return [...bytes.subarray(offset, offset + 3)].reverse()
}

test("welcome artwork contains the current icon, not an empty image placeholder", () => {
  const bytes = read("src-tauri/installer/nsis-sidebar.bmp")
  let logoPixels = 0
  for (let y = 63; y < 183; y++) {
    for (let x = 22; x < 142; x++) {
      const [red, , blue] = bmpPixel(bytes, x, y)
      if (blue > red + 25 && blue > 80) logoPixels++
    }
  }
  assert.ok(logoPixels > 500, "The blue icon details must be visible on the sidebar")
})

test("WiX native text areas stay white and unobstructed", () => {
  const dialog = read("src-tauri/installer/wix-dialog.bmp")
  for (let y = 0; y < 312; y += 4) {
    for (let x = 168; x < 493; x += 4) {
      assert.deepEqual(bmpPixel(dialog, x, y), [255, 255, 255])
    }
  }
  const banner = read("src-tauri/installer/wix-banner.bmp")
  for (let y = 0; y < 56; y += 4) {
    for (let x = 0; x < 425; x += 4) {
      assert.deepEqual(bmpPixel(banner, x, y), [255, 255, 255])
    }
  }
})

for (const [file, width, height] of expectedAssets) {
  test(`${file} has the native format, dimensions and verified artwork`, () => {
    const bytes = read(`src-tauri/installer/${file}`)
    const item = manifest.assets.find(asset => asset.file === file)
    assert.deepEqual(item, { file, width, height, sha256: hash(bytes) })
    if (file.endsWith(".bmp")) {
      assert.equal(bytes.toString("ascii", 0, 2), "BM")
      assert.equal(bytes.readUInt32LE(2), bytes.length)
      assert.equal(bytes.readUInt32LE(10), 54)
      assert.equal(bytes.readInt32LE(18), width)
      assert.equal(bytes.readInt32LE(22), height)
      assert.equal(bytes.readUInt16LE(26), 1)
      assert.equal(bytes.readUInt16LE(28), 24)
      assert.equal(bytes.readUInt32LE(30), 0, "Native installers need uncompressed bitmaps")
      assert.equal(bytes.length, 54 + Math.ceil(width * 3 / 4) * 4 * height)
    } else {
      assert.equal(bytes.subarray(0, 8).toString("hex"), "89504e470d0a1a0a")
      assert.equal(bytes.readUInt32BE(16), width)
      assert.equal(bytes.readUInt32BE(20), height)
    }
  })
}

test("all desktop packages retain the logo, identity and license", () => {
  const config = json("src-tauri/tauri.conf.json")
  assert.equal(config.productName, "Yougori")
  assert.equal(config.identifier, "com.yougori.desktop")
  assert.equal(config.bundle.publisher, "Yougori")
  assert.equal(config.bundle.licenseFile, "../COPYING")
  assert.equal(config.bundle.windows.allowDowngrades, false)
  for (const icon of ["icons/icon.ico", "icons/icon.icns", "icons/128x128.png"]) {
    assert.ok(config.bundle.icon.includes(icon))
    assert.ok(read(`src-tauri/${icon}`).length > 0)
  }
})

test("Windows setup and uninstall retain branded art and the public CLI integration", () => {
  const { nsis, wix } = json("src-tauri/tauri.windows.conf.json").bundle.windows
  assert.equal(nsis.installerIcon, "icons/icon.ico")
  assert.equal(nsis.uninstallerIcon, "icons/icon.ico")
  assert.equal(nsis.headerImage, "installer/nsis-header.bmp")
  assert.equal(nsis.uninstallerHeaderImage, nsis.headerImage)
  assert.equal(nsis.sidebarImage, "installer/nsis-sidebar.bmp")
  assert.equal(wix.bannerPath, "installer/wix-banner.bmp")
  assert.equal(wix.dialogImagePath, "installer/wix-dialog.bmp")
  assert.equal(nsis.template, undefined)
  assert.equal(nsis.installerHooks, "installer/cli-hooks.nsh")
  const hooks = read(`src-tauri/${nsis.installerHooks}`).toString()
  assert.match(hooks, /!macro NSIS_HOOK_POSTINSTALL[\s\S]*install-cli-path\.ps1[\s\S]*-Action Install/)
  assert.match(hooks, /!macro NSIS_HOOK_PREUNINSTALL[\s\S]*install-cli-path\.ps1[\s\S]*-Action Uninstall/)
  assert.ok(read("scripts/install-cli-path.ps1").length > 0)
  assert.deepEqual(wix.fragmentPaths, ["installer/cli-path.wxs"])
  assert.deepEqual(wix.componentRefs, ["YougoriPublicCliPath"])
  assert.match(read("src-tauri/installer/cli-path.wxs").toString(), /Name="PATH"[^>]*Permanent="no"/)
  assert.equal(nsis.installMode, undefined, "Keep the existing installation scope")
  assert.equal(wix.template, undefined)
})

test("macOS install icons align with the background and stay inside the window", () => {
  const { dmg, hardenedRuntime, minimumSystemVersion } = json("src-tauri/tauri.macos.conf.json").bundle.macOS
  assert.equal(dmg.background, "installer/dmg-background.png")
  assert.deepEqual(dmg.windowSize, { width: 720, height: 460 })
  assert.deepEqual(dmg.appPosition, { x: 200, y: 267 })
  assert.deepEqual(dmg.applicationFolderPosition, { x: 520, y: 267 })
  assert.equal(hardenedRuntime, true)
  assert.equal(minimumSystemVersion, "14.0")
  assert.ok(dmg.applicationFolderPosition.x + 80 < dmg.windowSize.width)
  assert.ok(dmg.appPosition.y + 90 < dmg.windowSize.height)
})
