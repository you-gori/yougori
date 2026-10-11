// Earlier development checkouts patched noVNC with a viewport extension. Releases
// ship unmodified noVNC, so stop if that extension is still installed: reinstall the
// dependency instead of building or testing with it. Never modify node_modules here.
import { readFile } from "node:fs/promises"
const root = new URL("../node_modules/@novnc/novnc/", import.meta.url)
const pkg = JSON.parse(await readFile(new URL("package.json", root), "utf8"))
if (pkg.version !== "1.7.0") throw new Error("Review the unmodified-noVNC check before upgrading noVNC")
for (const file of ["core/display.js", "core/rfb.js"]) {
  const source = await readFile(new URL(file, root), "utf8")
  if (source.includes("_stretchViewport") || source.includes("this._scaleY")) {
    throw new Error(`node_modules/@novnc/novnc/${file} still contains a viewport extension from an earlier development setup. Run npm ci to reinstall unmodified noVNC.`)
  }
}
