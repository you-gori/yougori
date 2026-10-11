// Compile the current app icon and installer artwork into native formats.
// Run explicitly when branding changes; normal builds use the checked-in assets.
import { createHash } from "node:crypto"
import { mkdir, readFile, writeFile } from "node:fs/promises"
import { fileURLToPath } from "node:url"
import { chromium } from "@playwright/test"

const root = new URL("../", import.meta.url)
const output = new URL("src-tauri/installer/", root)
const sourceLogo = await readFile(new URL("logo1.png", root))
const logo = await readFile(new URL("src-tauri/icons/icon-source.png", root))
const logoUrl = `data:image/png;base64,${logo.toString("base64")}`
const font = 'font-family="Segoe UI, Arial, sans-serif"'
const mark = (x, y, size) => `<image href="${logoUrl}" x="${x}" y="${y}" width="${size}" height="${size}"/>`
const text = (x, y, size, fill, value, extra = "") => `<text x="${x}" y="${y}" font-size="${size}" fill="${fill}" ${font} ${extra}>${value}</text>`
const svg = (width, height, content) => `<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}">${content}</svg>`

function sidebar(height) {
  return `<defs><clipPath id="sidebar-clip"><rect width="164" height="${height}"/></clipPath></defs>
    <g clip-path="url(#sidebar-clip)"><rect width="164" height="${height}" fill="#191c21"/>
    <path d="M-35 173L82 105l117 68v136L82 377-35 309Z M-8 189l90-52 90 52v104l-90 52-90-52Z" fill="none" stroke="#30363e" stroke-width="0.7"/>
    ${text(20, 30, 10, "#f5f2ec", "YOUGORI", 'letter-spacing="2.1" font-weight="600"')}
    ${mark(22, 63, 120)}
    <path d="M20 207h24" stroke="#a7bcad" stroke-width="2"/>
    ${text(20, 237, 23, "#f5f2ec", "Built around", 'font-weight="600" letter-spacing="-0.8"')}
    ${text(20, 264, 23, "#f5f2ec", "you.", 'font-weight="600" letter-spacing="-0.8"')}
    ${text(20, height - 17, 7.7, "#bbc0c6", "YOUR LOCAL WORKSPACE", 'letter-spacing="0.8"')}</g>`
}

const artwork = [
  { name: "nsis-sidebar.bmp", width: 164, height: 314, content: sidebar(314) },
  { name: "nsis-header.bmp", width: 150, height: 57, content: `<rect width="150" height="57" fill="white"/>${mark(8, 9, 39)}${text(55, 35, 18, "#191c21", "Yougori", 'font-weight="600" letter-spacing="-0.5"')}` },
  // WiX draws its own headings/body copy on the white areas of these images.
  { name: "wix-dialog.bmp", width: 493, height: 312, content: `<rect width="493" height="312" fill="white"/>${sidebar(312)}` },
  { name: "wix-banner.bmp", width: 493, height: 58, content: `<rect width="493" height="58" fill="white"/>${mark(439, 8, 42)}<path d="M0 57.5h493" stroke="#e5e2dc"/>` },
  { name: "dmg-background.png", width: 720, height: 460, content: `
    <rect width="720" height="460" fill="#f5f2ec"/>
    <path d="M512-36l211 122v244L512 452 301 330V86Z M547-13l174 101v202L547 391 373 290V88Z" fill="none" stroke="#e8e4dc"/>
    ${mark(34, 29, 49)}${text(96, 63, 28, "#191c21", "Yougori", 'font-weight="600" letter-spacing="-0.8"')}
    ${text(675, 58, 10, "#6e746d", "DESKTOP", 'text-anchor="end" letter-spacing="2"')}
    <path d="M40 104h640" stroke="#d9d4cb"/>
    ${text(40, 152, 30, "#191c21", "A workspace of your own.", 'font-weight="600" letter-spacing="-0.8"')}
    ${text(41, 181, 14, "#666b65", "Drag Yougori into Applications to install.")}
    <rect x="118" y="217" width="164" height="132" rx="22" fill="#ebe7df" stroke="#ddd7cd"/>
    <rect x="438" y="217" width="164" height="132" rx="22" fill="#ebe7df" stroke="#ddd7cd"/>
    <path d="M326 267h64m-13-13 13 13-13 13" fill="none" stroke="#6e8074" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/>
    <path d="M40 389h640" stroke="#d9d4cb"/>
    ${text(40, 420, 12, "#666b65", "Containers. Virtual machines. One workspace.")}
    ${text(680, 420, 11, "#666b65", "Yougori", 'text-anchor="end"')}` },
]

// NSIS/WiX require uncompressed, bottom-up 24-bit Windows bitmaps, not PNGs
// with a .bmp suffix. Pad each row to a four-byte boundary.
function bitmap(width, height, rgba) {
  const stride = Math.ceil(width * 3 / 4) * 4
  const buffer = Buffer.alloc(54 + stride * height)
  buffer.write("BM")
  buffer.writeUInt32LE(buffer.length, 2)
  buffer.writeUInt32LE(54, 10)
  buffer.writeUInt32LE(40, 14)
  buffer.writeInt32LE(width, 18)
  buffer.writeInt32LE(height, 22)
  buffer.writeUInt16LE(1, 26)
  buffer.writeUInt16LE(24, 28)
  buffer.writeUInt32LE(stride * height, 34)
  for (let y = 0; y < height; y++) {
    for (let x = 0; x < width; x++) {
      const source = (y * width + x) * 4
      const destination = 54 + (height - 1 - y) * stride + x * 3
      buffer[destination] = rgba[source + 2]
      buffer[destination + 1] = rgba[source + 1]
      buffer[destination + 2] = rgba[source]
    }
  }
  return buffer
}

await mkdir(output, { recursive: true })
const preview = new URL("artifacts/installer-branding/", root)
await mkdir(preview, { recursive: true })
const hash = value => createHash("sha256").update(value).digest("hex")
const manifest = {
  source: "logo1.png",
  sourceSha256: hash(sourceLogo),
  iconSha256: hash(logo),
  generatorSha256: hash((await readFile(fileURLToPath(import.meta.url), "utf8")).replace(/\r\n?/g, "\n")),
  assets: [],
}
const browser = await chromium.launch({ channel: "chromium" })
try {
  const page = await browser.newPage({ deviceScaleFactor: 1 })
  for (const asset of artwork) {
    const source = svg(asset.width, asset.height, asset.content)
    const rendered = await page.evaluate(async ({ source, width, height }) => {
      const image = new Image()
      image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(source)}`
      await image.decode()
      const canvas = document.createElement("canvas")
      canvas.width = width
      canvas.height = height
      const context = canvas.getContext("2d")
      context.drawImage(image, 0, 0)
      return { png: canvas.toDataURL("image/png").split(",")[1], rgba: Array.from(context.getImageData(0, 0, width, height).data) }
    }, { source, width: asset.width, height: asset.height })
    const png = Buffer.from(rendered.png, "base64")
    const bytes = asset.name.endsWith(".bmp") ? bitmap(asset.width, asset.height, rendered.rgba) : png
    await writeFile(new URL(asset.name, output), bytes)
    await writeFile(new URL(asset.name.replace(/\.bmp$/, ".png"), preview), png)
    manifest.assets.push({ file: asset.name, width: asset.width, height: asset.height, sha256: hash(bytes) })
    console.log(`Generated ${asset.name} (${asset.width} x ${asset.height})`)
  }
} finally {
  await browser.close()
}
await writeFile(new URL("manifest.json", output), JSON.stringify(manifest, null, 2) + "\n")
console.log("Native installer assets ready. PNG previews are in artifacts/installer-branding/.")
