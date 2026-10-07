import { expect, test, type Locator, type Page } from "@playwright/test"
import seed from "../src/data/seed.json" with { type: "json" }
import type { Environment, PlatformState } from "../src/types/platform"
import { spawn } from "node:child_process"
import { createServer } from "node:net"
import { resolve } from "node:path"
import { readFile } from "node:fs/promises"
import { createHash } from "node:crypto"
import { terminalInstallers } from "../src/lib/terminal-installers"
import { overviewSteps } from "../src/lib/instructions-tour"
import { waitForVnc } from "../scripts/wait-for-vnc.mjs"

for (const newline of ["\n", "\r\n", "\r"]) test(`shared file browser uploads chunks, edits, downloads and respects read-only and disconnect (${JSON.stringify(newline)} line endings)`, async ({ page }) => {
  const html = (await readFile(resolve("src-tauri/src/runtime/connection_files.html"), "utf8")).replace(/\r\n?|\n/g, newline)
  const script = html.replace(/\r\n?/g, "\n").split("<script>")[1].split("</script>")[0]
  const hash = createHash("sha256").update(script).digest("base64")
  const files = new Map<string, Buffer>([["project.txt", Buffer.from("before")]])
  let writable = true, active = true, writes = 0
  await page.route("http://10.192.0.1:7444/**", async route => {
    const request = route.request(), path = new URL(request.url()).pathname
    if (path === "/") return route.fulfill({ contentType: "text/html", body: html, headers: { "Content-Security-Policy": `default-src 'none'; script-src 'sha256-${hash}'; style-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'` } })
    if (path === "/connections") return route.fulfill({ json: active ? [{ id: "conn-browser", label: "Container ↔ Windows", writable }] : [] })
    const body = request.postDataJSON()
    expect(request.headers()["x-yougori-files"]).toBe("1")
    expect(body.connectionId).toBe("conn-browser")
    if (!active || !writable && !["list", "stat", "read"].includes(body.operation)) return route.fulfill({ status: 403, json: { error: "Access revoked or read-only" } })
    switch (body.operation) {
      case "list": return route.fulfill({ json: { entries: [...files].map(([name, bytes]) => ({ name, size: bytes.length, directory: false })) } })
      case "create":
        if (files.has(body.path)) return route.fulfill({ status: 409, json: { error: "Already exists" } })
        files.set(body.path, Buffer.alloc(0)); break
      case "read": return route.fulfill({ json: { data: files.get(body.path)!.subarray(body.offset, body.offset + body.length).toString("base64") } })
      case "write": {
        writes++
        const bytes = Buffer.from(body.data, "base64"), old = files.get(body.path)!, next = Buffer.alloc(Math.max(old.length, body.offset + bytes.length))
        old.copy(next); bytes.copy(next, body.offset); files.set(body.path, next); break
      }
      case "truncate": files.set(body.path, files.get(body.path)!.subarray(0, body.length)); break
      case "remove": files.delete(body.path); break
      default: throw Error(`Unexpected file operation: ${body.operation}`)
    }
    await route.fulfill({ json: {} })
  })
  await page.goto("http://10.192.0.1:7444/")
  const row = page.getByRole("row").filter({ hasText: "project.txt" })
  await row.getByRole("button", { name: "Edit", exact: true }).click()
  await expect(page.getByRole("textbox", { name: "File contents" })).toHaveValue("before")
  await page.getByRole("textbox", { name: "File contents" }).fill("edited ✓")
  await page.getByRole("button", { name: "Save changes" }).click()
  await expect.poll(() => files.get("project.txt")!.toString()).toBe("edited ✓")
  const payload = Buffer.alloc(300_000, 65)
  // The write reaches the fixture before save/truncate/list finish. Use the
  // visible button so actionability waits for the browser to leave its busy state.
  const choosing = page.waitForEvent("filechooser")
  await page.getByRole("button", { name: "Upload files", exact: true }).click()
  await (await choosing).setFiles({ name: "data.bin", mimeType: "application/octet-stream", buffer: payload })
  await expect(page.getByRole("row").filter({ hasText: "data.bin" })).toBeVisible()
  expect(files.get("data.bin")).toEqual(payload)
  expect(writes).toBeGreaterThanOrEqual(4)
  const downloading = page.waitForEvent("download")
  await row.getByRole("button", { name: "Download", exact: true }).click()
  const download = await downloading
  expect(download.suggestedFilename()).toBe("project.txt")
  expect(await readFile((await download.path())!, "utf8")).toBe("edited ✓")
  writable = false
  await page.getByRole("button", { name: "Refresh", exact: true }).click()
  await expect(page.getByRole("button", { name: "Upload files" })).toBeDisabled()
  await expect(row.getByRole("button", { name: "Edit", exact: true })).toBeDisabled()
  active = false
  await page.getByRole("button", { name: "Refresh", exact: true }).click()
  await expect(page.getByRole("status")).toContainText("No active shared folders")
  await expect(page.locator("#entries tr")).toHaveCount(0)
})

test("VM and MicroVM nodes have working private connection handles", async ({ page }) => {
  await openGraph(page, [fixture("Micro", "microVm"), fixture("VM", "fullVm"), fixture("Container")])
  for (const name of ["Micro", "VM", "Container"]) {
    await expect(page.locator(`[aria-label="Connect ${name} to another environment"]`)).toBeVisible()
    await expect(page.locator(`[aria-label="Connect another environment to ${name}"]`)).toBeVisible()
  }
  const from = await center(page.locator('[aria-label="Connect Micro to another environment"]'))
  const to = await center(page.locator('[aria-label="Connect another environment to VM"]'))
  await page.mouse.move(from.x, from.y); await page.mouse.down(); await page.mouse.move(to.x, to.y, { steps: 15 }); await page.mouse.up()
  const dialog = await expandedConnectionDialog(page)
  await expect(dialog).toBeVisible()
  await expect(dialog.getByRole("combobox", { name: "From", exact: true })).toContainText("Micro")
  await expect(dialog.getByRole("combobox", { name: "To", exact: true })).toContainText("VM")
  await expect(dialog.getByRole("checkbox", { name: "Share data", exact: true })).toBeChecked()
  await expect(dialog.getByRole("checkbox", { name: "Ports", exact: true })).toBeVisible()
  await portsOnly(dialog)
  await dialog.getByRole("textbox", { name: /Allowed TCP ports/ }).fill("22, 3000")
  await dialog.getByRole("button", { name: "Create connection", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const connections = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).connections)
  expect(connections).toEqual(expect.arrayContaining([expect.objectContaining({ sourceId: "Micro", targetId: "VM", permissions: ["ports"], ports: ["22", "3000"] })]))
  await page.getByRole("button", { name: "Configure Micro", exact: true }).click()
  await page.getByRole("button", { name: "Disconnect from VM", exact: true }).click()
  await expect(page.getByRole("button", { name: "Reconnect to VM", exact: true })).toBeVisible()
  await page.getByRole("button", { name: "Reconnect to VM", exact: true }).click()
  await expect(page.getByRole("button", { name: "Disconnect from VM", exact: true })).toBeVisible()
  await page.getByRole("button", { name: "Remove connection with VM", exact: true }).click()
  await expect(page.getByRole("button", { name: "Remove connection with VM", exact: true })).toHaveCount(0)
})

test("cloud environment from creation popup adds a verified server node with Open and a hidden address", async ({ page }) => {
  test.setTimeout(90000)
  await openGraph(page)
  const toolbar = page.getByRole("group", { name: "Dashboard actions", exact: true })
  await expect(toolbar.getByRole("button", { name: "Cloud environment", exact: true })).toHaveCount(0)
  const createButton = toolbar.getByRole("button", { name: "New environment", exact: true })
  await createButton.click()
  const creation = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(creation.getByText("Computer branch", { exact: true })).toHaveCount(0)
  await creation.getByText("Cloud environment", { exact: true }).click()
  await expect(creation).toBeVisible()
  await expect(page.getByRole("dialog")).toHaveCount(1)
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(dialog.getByText("Server identity", { exact: true })).toHaveCount(0)
  await expect(dialog.getByRole("button", { name: "Check identity" })).toHaveCount(0)
  await dialog.getByRole("textbox", { name: "Node name" }).fill("  Cloud database  ")
  await dialog.getByRole("textbox", { name: "Server address" }).fill("server.example.com")
  await dialog.getByRole("textbox", { name: "SSH username" }).fill("ubuntu")
  await dialog.getByRole("textbox", { name: "SSH identity file" }).fill("C:/Keys/cloud key.pem")
  const add = dialog.getByRole("button", { name: "Add cloud node" })
  const connect = dialog.getByRole("button", { name: "Connect", exact: true })
  await expect(add).toBeDisabled()
  await page.keyboard.press("Escape")
  await expect(dialog).not.toBeVisible()
  await createButton.click()
  await page.getByRole("dialog", { name: "New environment", exact: true }).getByText("Cloud environment", { exact: true }).click()
  await expect(dialog.getByRole("textbox", { name: "Node name" })).toHaveValue("  Cloud database  ")
  await expect(dialog.getByRole("textbox", { name: "Server address" })).toHaveValue("server.example.com")
  await expect(dialog.getByRole("textbox", { name: "SSH username" })).toHaveValue("ubuntu")
  await expect(dialog.getByRole("textbox", { name: "SSH identity file" })).toHaveValue(/C:\/Keys\/cloud key.pem/)
  await connect.click()
  await expect(dialog.getByRole("status")).toHaveText("Connection successful")
  await expect(dialog.getByRole("textbox", { name: "Node name" })).toHaveValue("  Cloud database  ")
  await expect(dialog.getByRole("textbox", { name: "Server address" })).toHaveValue("server.example.com")
  await expect(dialog.getByRole("textbox", { name: "SSH identity file" })).toHaveValue("C:/Keys/cloud key.pem")
  await expect(add).toBeEnabled()
  await dialog.getByRole("textbox", { name: "Server address" }).fill("other.example.com")
  await expect(add).toBeDisabled()
  await connect.click()
  await expect(add).toBeEnabled()
  await add.click()
  await expect(dialog).not.toBeVisible()
  const savedProfile = await page.evaluate(() => {
    const state = JSON.parse(localStorage.getItem("yougori.platform.v1")!)
    const environment = state.environments.find((e: { name: string }) => e.name === "Cloud database")
    return JSON.parse(localStorage.getItem(`yougori.cloud.${environment.id}`)!)
  })
  expect(savedProfile).toMatchObject({ name: "  Cloud database  ", host: "other.example.com", username: "ubuntu", identityFile: "C:/Keys/cloud key.pem" })
  const node = page.locator('[data-environment-id]').filter({ has: page.getByText("Cloud database", { exact: true }) })
  await expect(node.getByRole("button", { name: "Open", exact: true })).toBeVisible()
  await expect(node.getByRole("button", { name: "Start", exact: true })).toHaveCount(0)
  await expect(node).not.toContainText("other.example.com")
  await expect(node.locator('[title*="other.example.com"]')).toHaveCount(0)
  await node.getByRole("button", { name: "Show cloud address" }).click()
  await expect(node).toContainText("ubuntu@other.example.com")
  await node.getByRole("button", { name: "Hide cloud address" }).click()
  await expect(node).not.toContainText("other.example.com")
  await expect(node.locator('[data-environment-connection-point]')).toHaveCount(0)
  await expect(node.locator('.react-flow__handle')).toHaveCount(2)
  await page.evaluate(async () => { const { platformApi } = await import("/src/api/platform-api.ts"); platformApi.openEnvironmentWindow = async () => true })
  await node.getByRole("button", { name: "Open", exact: true }).click()
  await expect(node.getByText("Connected", { exact: true })).toBeVisible()
  await expect(node.getByRole("button", { name: "Open", exact: true })).toBeVisible()
  await expect(node.getByRole("button", { name: /Pause|Shut down/ })).toHaveCount(0)
  await expect(node.getByRole("button", { name: "Disconnect", exact: true })).toHaveCount(0)
  await expect(node.locator('[data-tour="node-open"]')).toHaveCount(0)
  await node.getByRole("button", { name: "Configure Cloud database", exact: true }).click()
  const settings = page.getByRole("dialog", { name: "Cloud database", exact: true })
  await expect(settings.getByRole("heading", { name: "SSH connection", exact: true })).toBeVisible()
  await expect(settings.getByRole("tab")).toHaveCount(0)
  await settings.getByRole("button", { name: "Disconnect", exact: true }).click()
  await expect(settings.getByText("Cloud environment · Disconnected", { exact: true })).toBeVisible()
  const box = (await settings.boundingBox())!
  expect(box.width).toBeGreaterThan(1100)
  expect(Math.abs(box.x + box.width / 2 - page.viewportSize()!.width / 2)).toBeLessThan(2)
  expect(Math.abs(box.y + box.height / 2 - page.viewportSize()!.height / 2)).toBeLessThan(2)
  await settings.getByRole("button", { name: "Remove node", exact: true }).click()
  const confirmation = page.getByRole("alertdialog", { name: "Remove cloud node?", exact: true })
  await expect(confirmation).toBeVisible()
  await confirmation.getByRole("button", { name: "Cancel", exact: true }).click()
  await settings.getByRole("button", { name: "Close", exact: true }).click()
  await expect(settings).not.toBeVisible()
})

test("cloud setup requires successful SSH access and preserves failed drafts", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(async () => {
    const { cloudApi } = await import("/src/api/cloud-api.ts")
    cloudApi.testConnection = async request => {
      localStorage.setItem("cloud-test-request", JSON.stringify(request))
      throw new Error("Permission denied (publickey)")
    }
  })
  const toolbar = page.getByRole("group", { name: "Dashboard actions", exact: true })
  await toolbar.getByRole("button", { name: "New environment", exact: true }).click()
  await page.getByRole("dialog", { name: "New environment", exact: true }).getByText("Cloud environment", { exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  const name = dialog.getByRole("textbox", { name: "Node name" })
  const username = dialog.getByRole("textbox", { name: "SSH username" })
  const identity = dialog.getByRole("textbox", { name: "SSH identity file" })
  const connect = dialog.getByRole("button", { name: "Connect", exact: true })
  const add = dialog.getByRole("button", { name: "Add cloud node" })
  await name.fill("   ")
  await dialog.getByRole("textbox", { name: "Server address" }).fill(" server.example.com ")
  await username.fill(" ubuntu ")
  await identity.fill("  ecdsa-sha2-nistp256 AAAAE2 test= google-ssh  ")
  await expect(connect).toBeEnabled()
  await connect.click()
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem("cloud-test-request") || "null"))).toMatchObject({
    name: "   ", host: " server.example.com ", username: " ubuntu ", identityFile: "  ecdsa-sha2-nistp256 AAAAE2 test= google-ssh  ",
  })
  await expect(identity).toHaveValue("  ecdsa-sha2-nistp256 AAAAE2 test= google-ssh  ")
  await name.fill("Retry server")
  await username.fill("ubuntu")
  await dialog.getByRole("textbox", { name: "Server address" }).fill("server.example.com")
  await identity.fill("C:/Keys/cloud.pem")
  await connect.click()
  await expect(dialog.getByRole("alert")).toHaveText("Permission denied (publickey)")
  await expect(add).toBeDisabled()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  // Reopen through the other entry point; it shares the same unfinished draft.
  await toolbar.getByRole("button", { name: "New environment", exact: true }).click()
  await page.getByRole("dialog", { name: "New environment", exact: true }).getByText("Cloud environment", { exact: true }).click()
  await expect(name).toHaveValue("Retry server")
  await expect(identity).toHaveValue("C:/Keys/cloud.pem")
  await expect(add).toBeDisabled()
  await page.evaluate(async () => {
    const { cloudApi } = await import("/src/api/cloud-api.ts")
    cloudApi.testConnection = async request => {
      await new Promise(resolve => setTimeout(resolve, 500))
      return { ...request, hostKey: "ssh-ed25519 TEST-PREVIEW-ONLY" }
    }
  })
  await connect.click()
  await expect(connect).toBeDisabled()
  await expect(add).toBeDisabled()
  await expect(identity).toBeDisabled()
  await expect(add).toBeEnabled()
  await username.fill("admin")
  await expect(add).toBeDisabled()
  await connect.click()
  await expect(add).toBeEnabled()
  await identity.fill("C:/Keys/other.pem")
  await expect(add).toBeDisabled()
  await connect.click()
  await expect(add).toBeEnabled()
  await dialog.getByRole("spinbutton", { name: "SSH port" }).fill("2222")
  await expect(add).toBeDisabled()
  await connect.click()
  await expect(add).toBeEnabled()
  await add.click()
  await expect(dialog).not.toBeVisible()
  await toolbar.getByRole("button", { name: "New environment", exact: true }).click()
  await page.getByRole("dialog", { name: "New environment", exact: true }).getByText("Cloud environment", { exact: true }).click()
  await expect(name).toHaveValue("")
  await expect(identity).toHaveValue("")
  await expect(add).toBeDisabled()
})

test("cloud setup accepts a pasted public key and explains a missing matching agent key", async ({ page }) => {
  await openGraph(page)
  const publicKey = "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTY= google-ssh"
  const help = "This is a public SSH key. Load its matching private key into this PC's SSH agent, or use Browse to select the private key file. A public key alone cannot sign in."
  await page.evaluate(async message => {
    const { cloudApi } = await import("/src/api/cloud-api.ts")
    cloudApi.testConnection = async () => { throw new Error(message) }
  }, help)
  await page.getByRole("group", { name: "Dashboard actions", exact: true }).getByRole("button", { name: "New environment", exact: true }).click()
  await page.getByRole("dialog", { name: "New environment", exact: true }).getByText("Cloud environment", { exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await dialog.getByRole("textbox", { name: "Node name" }).fill("Agent server")
  await dialog.getByRole("textbox", { name: "Server address" }).fill("server.example.test")
  const identity = dialog.getByRole("textbox", { name: "SSH identity file" })
  await identity.fill(publicKey)
  await dialog.getByRole("button", { name: "Connect", exact: true }).click()
  await expect(dialog.getByRole("alert")).toHaveText(help)
  await expect(identity).toHaveValue(publicKey)
  await expect(dialog.getByRole("button", { name: "Add cloud node" })).toBeDisabled()
  await page.evaluate(async () => {
    const { cloudApi } = await import("/src/api/cloud-api.ts")
    cloudApi.testConnection = async request => ({ ...request, hostKey: "ssh-ed25519 TEST-PREVIEW-ONLY" })
  })
  await dialog.getByRole("button", { name: "Connect", exact: true }).click()
  await dialog.getByRole("button", { name: "Add cloud node" }).click()
  await expect(dialog).not.toBeVisible()
  const saved = await page.evaluate(() => {
    const state = JSON.parse(localStorage.getItem("yougori.platform.v1")!)
    const environment = state.environments.find((e: { name: string }) => e.name === "Agent server")
    return JSON.parse(localStorage.getItem(`yougori.cloud.${environment.id}`)!).identityFile
  })
  expect(saved).toBe(publicKey)
})

for (const localKind of ["container", "microVm", "fullVm"] as const) {
  test(`cloud node connects files and TCP ports to ${localKind} without publishing controls`, async ({ page }) => {
    await openGraph(page, [{ ...fixture("Cloud", "cloud"), provider: "cloudSsh", status: "running" }, fixture("Local", localKind)])
    await connectNodes(page, "Cloud", "Local")
    const dialog = await expandedConnectionDialog(page)
    await dialog.getByRole("button", { name: "Share folder", exact: true }).click()
    await dialog.getByRole("checkbox", { name: "Ports", exact: true }).check()
    await dialog.getByRole("textbox", { name: /TCP ports/i }).fill("5432")
    await dialog.getByRole("button", { name: "Create connection", exact: true }).click()
    await expect(dialog).not.toBeVisible()
    const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).connections.find((c: { sourceId: string }) => c.sourceId === "Cloud"))
    expect(saved).toMatchObject({ sourceId: "Cloud", targetId: "Local", permissions: ["data", "ports"], ports: ["5432"], direction: "bidirectional" })
    const cloud = page.locator('[data-environment-id="Cloud"]')
    await expect(cloud.getByRole("button", { name: /Add service|capabilities/ })).toHaveCount(0)
    await cloud.getByRole("button", { name: "Configure Cloud" }).click()
    const sheet = page.getByRole("dialog", { name: "Cloud", exact: true })
    await expect(sheet.getByRole("button", { name: "Disconnect", exact: true })).toBeVisible()
    await expect(sheet.getByText("Local network and Public access are blocked.", { exact: false })).toBeVisible()
    await expect(sheet.getByRole("button", { name: /Factory reset|Save policy|Start|Stop/ })).toHaveCount(0)
  })
}

for (const kind of ["container", "microVm", "fullVm"] as const) test(`connection Skills can be read and copied from a ${kind} window`, async ({ page, context }) => {
  await context.grantPermissions(["clipboard-read", "clipboard-write"])
  const environment = fixture("env-skills-source", kind)
  environment.status = "running"
  const peer = fixture("skills-peer", kind); peer.status = "running"
  const state = structuredClone(seed) as PlatformState; state.environments = [environment, peer]
  state.connections = [{ id: "conn-skills", sourceId: environment.id, targetId: peer.id, direction: "bidirectional", permissions: ["files"], ports: [], active: true, createdAt: "test", enforcementStatus: "enforced" }]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.addInitScript(({ id, mounted }) => localStorage.setItem("yougori.workspace.v1", JSON.stringify({ [id]: {
    services: [], publications: [], notice: "", shares: [
      { id: "share-input", environmentId: id, path: "C:\\Shared input", readOnly: true, mountPath: mounted ? "/yougori/shared/my-pc/share-input" : null, guestUrl: "http://10.0.2.2:54321/private-input-token/" },
      { id: "share-project", environmentId: id, path: "C:\\Shared project", readOnly: !mounted, mountPath: mounted ? "/yougori/shared/my-pc/share-project" : null, guestUrl: "http://10.0.2.2:54322/private-project-token/" },
      { id: "share-other", environmentId: "env-other", path: "C:\\Not shared here", readOnly: false, mountPath: "/other", guestUrl: "http://10.0.2.2:54323/private-other-token/" },
    ],
  } })), { id: environment.id, mounted: kind !== "fullVm" })
  await page.goto("/?environment=env-skills-source")
  await expect(page.getByRole("button", { name: "Connection skills", exact: true })).toBeVisible({ timeout: 20000 })
  await page.getByRole("button", { name: "Connection skills", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Connection skills", exact: true })
  await expect(dialog.getByRole("textbox", { name: "AI agent connection instructions" })).toHaveValue(/Yougori connection skill/)
  await expect(dialog.getByRole("list", { name: "Connected nodes" })).toContainText("skills-peer")
  await expect(dialog.getByRole("list", { name: "Connected nodes" })).toContainText("Connection ready")
  // Backend changes after opening: Copy must fetch again, not copy the old ready state.
  await page.evaluate(() => {
    const state = JSON.parse(localStorage.getItem("yougori.platform.v1")!)
    state.environments.find((e: { id: string }) => e.id === "skills-peer").status = "stopped"
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
  })
  await dialog.getByRole("button", { name: "Copy skills", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "Copied", exact: true })).toBeVisible()
  const copied = (await page.evaluate(() => navigator.clipboard.readText())).replaceAll("\r\n", "\n")
  expect(copied).toContain("Copying this skill does not grant access")
  expect(copied).toContain("PEER_STOPPED")
  await expect(dialog.getByRole("list", { name: "Connected nodes" })).toContainText("turned off")
  const pc = JSON.parse(copied.split("```json\n")[1]!.split("\n```")[0]!).myPc
  expect(pc.connected).toBe(true)
  expect(pc.folders).toHaveLength(2)
  expect(pc.folders[0]).toMatchObject({ shareId: "share-input", hostPath: "C:\\Shared input", readOnly: true, writable: false, usableNow: true })
  expect(pc.folders[1]).toMatchObject({ shareId: "share-project", writable: kind !== "fullVm", privateLinkRequired: kind === "fullVm" })
  expect(copied).not.toContain("private-input-token")
  expect(copied).not.toContain("private-project-token")
  expect(copied).not.toContain("Not shared here")
  if (kind === "container") {
    await page.evaluate(async () => {
      const module = "/src/api/platform-api.ts", { platformApi } = await import(module)
      const original = platformApi.connectionSkills
      Object.assign(window, { restoreSkills: () => { platformApi.connectionSkills = original } })
      platformApi.connectionSkills = async () => { throw new Error("Fixture: connection state unavailable") }
    })
    await dialog.getByRole("button", { name: /^(Copy skills|Copied)$/ }).click()
    await expect(dialog.getByRole("alert")).toContainText("No cached instructions were copied")
    expect((await page.evaluate(() => navigator.clipboard.readText())).replaceAll("\r\n", "\n")).toBe(copied)
    await page.evaluate(() => (window as unknown as { restoreSkills(): void }).restoreSkills())
    await dialog.getByRole("button", { name: "Refresh skills" }).click()
    await expect(dialog.getByRole("alert")).toHaveCount(0)
    await expect(dialog.getByRole("button", { name: "Copy skills", exact: true })).toBeEnabled()
  }
  await page.keyboard.press("Escape")
  await page.evaluate(async () => {
    const module = "/src/api/workspace-api.ts", { workspaceApi } = await import(module)
    await workspaceApi.unshare("share-input")
    await workspaceApi.unshare("share-project")
  })
  await page.getByRole("button", { name: "Connection skills", exact: true }).click()
  await expect(dialog.getByRole("textbox", { name: "AI agent connection instructions" })).toHaveValue(/"connected": false/)
  await expect(dialog.getByRole("textbox", { name: "AI agent connection instructions" })).not.toHaveValue(/Shared input|Shared project/)
})

for (const kind of ["container", "microVm", "fullVm"] as const) test(`Skills stays available without node links and shows disabled/offline peers in a ${kind}`, async ({ page }) => {
  const a = fixture("env-skills-A", kind), b = fixture("env-skills-B", "fullVm"), c = fixture("env-skills-C", "container"), d = fixture("env-skills-D", "microVm")
  a.status = "running"; c.status = "paused"
  const state = structuredClone(seed) as PlatformState; state.environments = [a, b, c, d]; state.connections = []
  await page.addInitScript(state => { if (!localStorage.getItem("yougori.platform.v1")) localStorage.setItem("yougori.platform.v1", JSON.stringify(state)) }, state)
  await page.addInitScript(() => localStorage.setItem("yougori.workspace.v1", JSON.stringify({ "env-skills-A": { services: [], publications: [], notice: "", shares: [{ id: "only-pc", environmentId: "env-skills-A", path: "C:\\Chosen", readOnly: true, mountPath: "/my-pc", guestUrl: "private-token" }] } })))
  await page.goto("/?environment=env-skills-A")
  await expect(page.getByRole("combobox", { name: "Switch environment" })).toBeVisible({ timeout: 20000 })
  await expect(page.getByRole("button", { name: "Connection skills", exact: true })).toBeVisible()
  await page.evaluate(() => {
    const state = JSON.parse(localStorage.getItem("yougori.platform.v1")!)
    state.connections = [
      { id: "AB", sourceId: "env-skills-A", targetId: "env-skills-B", direction: "bidirectional", permissions: ["files"], ports: [], active: true, createdAt: "test", enforcementStatus: "pending" },
      { id: "CA", sourceId: "env-skills-C", targetId: "env-skills-A", direction: "oneWay", permissions: ["ports"], ports: ["3000"], active: false, createdAt: "test", enforcementStatus: "enforced" },
      { id: "BD", sourceId: "env-skills-B", targetId: "env-skills-D", direction: "bidirectional", permissions: ["files"], ports: [], active: true, createdAt: "test", enforcementStatus: "enforced" },
    ]
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
  })
  await page.reload()
  await page.getByRole("button", { name: "Connection skills", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Connection skills", exact: true }), list = dialog.getByRole("list", { name: "Connected nodes" })
  await expect(list).toContainText("env-skills-B")
  await expect(list).toContainText("env-skills-C")
  await expect(list).not.toContainText("env-skills-D")
  await expect(list).toContainText("turned off")
  await expect(list).toContainText("paused")
  await expect(list).toContainText("switched off")
  await page.keyboard.press("Escape")
  await page.evaluate(() => {
    const state = JSON.parse(localStorage.getItem("yougori.platform.v1")!); state.connections = []
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
  })
  await page.reload()
  await expect(page.getByRole("combobox", { name: "Switch environment" })).toBeVisible()
  await expect(page.getByRole("button", { name: "Connection skills", exact: true })).toBeVisible()
})

function fixture(id: string, kind: Environment["kind"] = "container"): Environment {
  return {
    id, name: id, kind, provider: kind === "container" ? "yougoriOci" : "qemu", status: "stopped",
    runtime: kind === "container" ? "alpine:latest" : "builtin:alpine", description: "", createdAt: "2026-01-01T00:00:00Z",
    networkAccess: false, gpuAccess: false, cpuUsage: 0, memoryUsageGb: 0, storageDeltaGb: 0, networkRxMbps: 0,
    resourcePolicy: { cpu: { min: 0.1, preferred: 0.25, max: 0.5, current: 0 }, memoryGb: { min: 0.125, preferred: 0.25, max: 0.5, current: 0 }, priority: "normal", dynamic: false },
  }
}

async function connectNodes(page: Page, source: string, target: string) {
  const sourceHandle = page.locator(`[aria-label="Connect ${source} to another environment"]`)
  await sourceHandle.hover()
  const from = await center(sourceHandle)
  const to = await center(page.locator(`[aria-label="Connect another environment to ${target}"]`))
  await page.mouse.move(from.x, from.y)
  await page.mouse.down()
  await page.mouse.move(to.x, to.y, { steps: 15 })
  await page.mouse.up()
}

// Network policy controls are deliberately collapsed in the current UI.
async function expandedConnectionDialog(page: Page) {
  const dialog = page.getByRole("dialog", { name: "New connection", exact: true })
  await dialog.getByText("Network and legacy access", { exact: true }).click()
  return dialog
}

async function portsOnly(dialog: Locator) {
  await dialog.getByRole("checkbox", { name: "Share data", exact: true }).uncheck()
  const advanced = dialog.locator("details.connection-advanced")
  if (!await advanced.evaluate(el => (el as HTMLDetailsElement).open)) await advanced.locator("summary").click()
  await dialog.getByRole("checkbox", { name: "Ports", exact: true }).check()
}

for (const source of ["container", "microVm", "fullVm"] as const) for (const target of ["container", "microVm", "fullVm"] as const) {
  test(`folder sharing requires explicit selection from ${source} to ${target}`, async ({ page }) => {
    await openGraph(page, [fixture("Source", source), fixture("Target", target)])
    await connectNodes(page, "Source", "Target")
    const dialog = await expandedConnectionDialog(page)
    await expect(dialog.getByRole("checkbox", { name: "Share data", exact: true })).toBeChecked()
    await expect(dialog.locator('input[type="radio"][value="bidirectional"]')).toBeChecked()
    await dialog.getByRole("button", { name: "Create connection", exact: true }).click()
    await expect(dialog.getByRole("alert")).toContainText("Choose at least one folder")
    const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).connections)
    expect(saved).toEqual([])
  })
}

async function openGraph(page: Page, environments = [fixture("Alpha"), fixture("Beta")]) {
  const state = structuredClone(seed) as PlatformState
  state.host.totalCpu = 8
  state.host.totalMemoryGb = 16
  state.host.totalStorageGb = 1024
  state.host.usedStorageGb = 128
  state.environments = environments
  const seedKey = `opendock.test.seed.${Date.now()}.${Math.random()}`
  await page.addInitScript(({ state, seedKey }) => {
    if (!sessionStorage.getItem(seedKey)) {
      if (!localStorage.getItem("yougori.workspace-view")) localStorage.setItem("yougori.workspace-view", "nodes")
      localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
      sessionStorage.setItem(seedKey, "1")
    }
  }, { state, seedKey })
  // The first dev-server visit compiles the lazy graph and its UI modules.
  // Keep that cold-start budget separate from normal locator/action waits.
  test.setTimeout(Math.max(test.info().timeout, 60_000))
  await page.goto("/")
  await page.waitForFunction(() => document.querySelector('[data-environment-canvas]') || document.querySelector('.startup-screen [role="alert"]'), undefined, { polling: 100, timeout: 45_000 })
  if (await page.locator('.startup-screen [role="alert"]').count()) await page.reload()
  await expect(page.locator('[data-environment-id]')).toHaveCount(environments.length, { timeout: 45_000 })
}

for (const kind of ["container", "gpu", "microVm", "fullVm"] as const) test(`native folder drop shows an independent copy on the ${kind} node`, async ({ page }) => {
  await page.route("**/src/api/file-import-api.ts*", async route => {
    const response = await route.fetch()
    await route.fulfill({ response, body: await response.text() + `
      fileImportApi.listen = async callback => {
        const listener = event => callback(event.detail);
        window.addEventListener("test-native-drop", listener);
        return () => window.removeEventListener("test-native-drop", listener);
      };
      fileImportApi.copy = async (id, paths, report) => {
        document.documentElement.dataset.importCall = JSON.stringify({ id, paths });
        report({ phase: "copying", completedBytes: 50, totalBytes: 100 });
        return new Promise(resolve => window.addEventListener("test-copy-finish", event => resolve(event.detail), { once: true }));
      };
    ` })
  })
  const environment = fixture("Drop target", kind === "gpu" ? "container" : kind)
  environment.status = "running"
  if (kind === "gpu") { environment.provider = "yougoriCuda"; environment.gpuAccess = true }
  await openGraph(page, [environment, fixture("Other")])
  const node = page.locator('[data-environment-id="Drop target"]')
  const point = await center(node)
  const paths = ["C:\\Projects\\My folder", "C:\\notes.txt"]
  await page.evaluate(({ point, paths }) => {
    const position = { x: point.x * devicePixelRatio, y: point.y * devicePixelRatio }
    window.dispatchEvent(new CustomEvent("test-native-drop", { detail: { type: "drop", position, paths } }))
  }, { point, paths })
  await expect(node).toHaveAttribute("aria-busy", "true")
  await expect(node.getByRole("status")).toContainText("Copying files · 50%")
  await expect(node).toContainText("Originals stay on your computer")
  await expect(page.getByRole("dialog")).toHaveCount(0)
  await expect(page.locator('[data-environment-id="Other"]').getByRole("button", { name: "Start", exact: true })).toBeEnabled()
  expect(await page.evaluate(() => JSON.parse(document.documentElement.dataset.importCall!))).toEqual({ id: environment.id, paths })
  const destination = kind === "fullVm" ? "YOUGORI · 12345678" : "/yougori-import-12345678"
  await page.evaluate(({ destination, drive }) => window.dispatchEvent(new CustomEvent("test-copy-finish", { detail: { destination, files: 2, bytes: 100, skippedLinks: 0, delivery: drive ? "drive" : "directory" } })), { destination, drive: kind === "fullVm" })
  await expect(node).toHaveAttribute("aria-busy", "false")
  await expect(node.getByRole("status")).toContainText(destination)
  if (kind === "fullVm") await expect(node).toContainText("Open the YOUGORI drive inside your VM")
})

test("VM imported drives can be disconnected and reconnected while stopped", async ({ page }) => {
  await openGraph(page, [fixture("Import VM", "fullVm")])
  await page.evaluate(async () => {
    const url = "/src/api/file-import-api.ts"
    const { fileImportApi } = await import(url)
    const drive = { id: "12345678123456781234567812345678", attached: true, bytes: 67108864 }
    fileImportApi.drives = async () => [drive]
    fileImportApi.setDriveAttached = async (environmentId: string, transferId: string, attached: boolean) => {
      if (environmentId !== "Import VM" || transferId !== drive.id) throw Error("Wrong imported drive")
      return [{ ...drive, attached }]
    }
  })
  await page.getByRole("button", { name: "Configure Import VM", exact: true }).click()
  const section = page.getByRole("region", { name: "Imported files", exact: true })
  await expect(section).toContainText("Disconnected copies stay saved")
  await section.getByRole("button", { name: "Disconnect drive" }).click()
  await expect(section).toContainText("Saved")
  await section.getByRole("button", { name: "Connect drive" }).click()
  await expect(section).toContainText("Connected")
})

async function seedServices(page: Page, id = "Alpha") {
  await page.addInitScript(id => localStorage.setItem("yougori.workspace.v1", JSON.stringify({ [id]: { services: [{ port: 4200, protocol: "tcp", name: "Dev server", address: "127.0.0.1" }, { port: 8080, protocol: "tcp", name: "Web server", address: "0.0.0.0" }], publications: [], shares: [], notice: "" } })), id)
}

const port = (page: Page, id = "Alpha") => page.locator(`[data-environment-connection-point="${id}"]`)
const dockPort = (page: Page, capability: string) => page.locator(`[data-capability-connection-point="${capability}"]`)
const line = (page: Page, capability: string, id = "Alpha") => page.locator(`[data-capability-line="${capability}:${id}"]`)

async function center(locator: Locator) {
  const bounds = await locator.boundingBox()
  if (!bounds) throw new Error("Missing connector")
  return { x: bounds.x + bounds.width / 2, y: bounds.y + bounds.height / 2 }
}

async function assertRoundedPath(path: Locator) {
  const d = (await path.getAttribute("d"))!
  expect(d).toMatch(/^M/)
  expect(d).toContain("C")
  expect(d).not.toMatch(/NaN|Infinity/)
}

async function drag(page: Page, from: Locator, to: Locator, offset = { x: 0, y: 0 }) {
  // Wait for closing dialogs to release pointer events before starting a real gesture.
  await from.hover()
  const start = await center(from)
  const end = await center(to)
  await page.mouse.move(start.x, start.y)
  await page.mouse.down()
  await page.mouse.move(end.x + offset.x, end.y + offset.y, { steps: 12 })
  await expect(page.locator("[data-connection-preview]")).toBeAttached()
  await assertRoundedPath(page.locator("[data-connection-preview]"))
  await page.mouse.up()
}

async function assertLineAligned(page: Page, capability: string, id = "Alpha") {
  await expect(line(page, capability, id)).toBeAttached()
  await assertRoundedPath(line(page, capability, id))
  await expect.poll(() => page.evaluate(({ capability, id }) => {
    const path = document.querySelector<SVGPathElement>(`[data-capability-line="${capability}:${id}"]`)
    const source = document.querySelector(`[data-capability-connection-point="${capability}"]`)
    const target = document.querySelector(`[data-environment-connection-point="${id}"]`)
    const svg = document.querySelector("[data-capability-lines]")
    if (!path || !source || !target || !svg) return false
    const bounds = svg.getBoundingClientRect(), a = source.getBoundingClientRect(), b = target.getBoundingClientRect()
    const start = path.getPointAtLength(0), end = path.getPointAtLength(path.getTotalLength())
    return Math.abs(start.x + bounds.left - a.left - a.width / 2) < 0.5
      && Math.abs(start.y + bounds.top - a.top - a.height / 2) < 0.5
      && Math.abs(end.x + bounds.left - b.left - b.width / 2) < 0.5
      && Math.abs(end.y + bounds.top - b.top - b.height / 2) < 0.5
  }, { capability, id })).toBe(true)
}

test("drags from either endpoint, previews, snaps, saves and detaches", async ({ page }) => {
  await openGraph(page)
  await drag(page, dockPort(page, "internet"), port(page), { x: 15, y: 9 })
  await assertLineAligned(page, "internet")
  await expect(page.locator("[data-connection-preview]")).toHaveCount(0)
  await expect(page.locator("[data-environment-graph]")).toHaveAttribute("data-connecting", "false")
  await expect(page.locator('[role="dialog"][aria-modal="true"]')).toHaveCount(0)
  await page.getByRole("button", { name: "Detach Internet access from Alpha", exact: true }).click()
  await drag(page, port(page), dockPort(page, "internet"))
  await assertLineAligned(page, "internet")
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])
  expect(saved.networkAccess).toBe(true)
  expect(saved.resourcePolicy.dynamic).toBe(true)
  await page.getByRole("button", { name: "Detach Internet access from Alpha", exact: true }).click()
  await expect(line(page, "internet")).toHaveCount(0)
  await expect(page.locator('[data-capability-kind="gpu"]')).toHaveCount(0)
})

test("graph uses the available width and a taller responsive canvas", async ({ page }) => {
  await page.setViewportSize({ width: 1920, height: 1080 })
  await openGraph(page)
  const graph = (await page.locator("[data-environment-graph]").boundingBox())!
  const canvas = (await page.locator("[data-environment-canvas]").boundingBox())!
  expect(graph.width).toBeGreaterThan(1800)
  // The redesigned workspace fills the space left by its toolbar and docks,
  // rather than imposing the old fixed 640px minimum and scrolling the page.
  expect(canvas.height).toBeGreaterThan(1080 / 2)
  expect(graph.y + graph.height).toBeLessThanOrEqual(1080)
  await page.setViewportSize({ width: 1920, height: 880 })
  await expect.poll(async () => (await page.locator("[data-environment-canvas]").boundingBox())!.height).toBeCloseTo(canvas.height - 200, 0)
})

for (const kind of ["container", "microVm", "fullVm"] as const) {
  test(`plugs and unplugs internet on a running ${kind} without stopping it`, async ({ page }) => {
    const env = fixture("Alpha", kind)
    env.status = "running"
    await openGraph(page, [env])
    await drag(page, dockPort(page, "internet"), port(page))
    await assertLineAligned(page, "internet")
    await page.getByRole("button", { name: "Detach Internet access from Alpha", exact: true }).click()
    await expect(line(page, "internet")).toHaveCount(0)
    const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])
    expect(saved.status).toBe("running")
    expect(saved.networkAccess).toBe(false)
    await drag(page, dockPort(page, "internet"), port(page))
    await assertLineAligned(page, "internet")
    await page.reload()
    await assertLineAligned(page, "internet")
  })
}

test("capability labels stay compact with service destinations above and file access below the canvas", async ({ page }) => {
  const env = fixture("Alpha"); env.networkAccess = true; env.gpuAccess = true; env.resourcePolicy.dynamic = true
  await openGraph(page, [env])
  const labels = page.getByLabel("Attached capabilities")
  await expect(page.locator('[data-capability-card="dynamic"]')).toHaveCount(0)
  await expect(page.getByRole("button", { name: /Detach Dynamic allocation/ })).toHaveCount(0)
  const layout = await labels.evaluate(element => {
    const boxes = [...element.children].map(child => child.getBoundingClientRect())
    return { sameRow: boxes.every(box => Math.abs(box.top - boxes[0].top) < 1), height: element.getBoundingClientRect().height }
  })
  expect(layout.sameRow).toBe(true); expect(layout.height).toBeLessThanOrEqual(21)
  const canvas = (await page.locator("[data-environment-canvas]").boundingBox())!
  const dock = page.getByRole("region", { name: "Environment capabilities", exact: true })
  const pc = (await dock.getByRole("button", { name: "My PC files", exact: true }).boundingBox())!
  expect(pc.y).toBeGreaterThanOrEqual(canvas.y + canvas.height)
  for (const name of ["Internet access"]) {
    const box = (await dock.getByRole("button", { name, exact: true }).boundingBox())!
    expect(Math.abs(box.y - pc.y)).toBeLessThan(1)
    expect(pc.x + pc.width).toBeLessThan(box.x)
  }
  await expect(dockPort(page, "pc")).toHaveAttribute("data-connection-side", "top")
  await expect(page.getByRole("complementary", { name: "PC folder access" })).toHaveCount(0)
  const local = (await page.locator('[data-publication-card="local"]').boundingBox())!
  const publicAccess = (await page.locator('[data-publication-card="public"]').boundingBox())!
  expect(local.x + local.width).toBeLessThan(publicAccess.x)
  expect(Math.abs(local.y - publicAccess.y)).toBeLessThan(1)
  expect(local.y + local.height).toBeLessThanOrEqual(canvas.y)
  await expect(page.locator('[data-publication-connection-point="local"]')).toHaveAttribute("data-connection-side", "bottom")
  await expect(page.locator('[data-publication-card]')).toHaveCount(2)
  await expect(page.getByRole("button", { name: "Public access / Cloudflare Tunnel", exact: true })).toBeVisible()
  await expect(page.locator('[data-publication-connection-point="cloudflare"]')).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Add or manage saved domain setups" })).toBeVisible()
  for (const dock of await page.locator('.workspace-connection-dock').all()) expect((await dock.boundingBox())!.height).toBeLessThan(90)
})

test("service destinations stay on one row and scroll to additional saved setups", async ({ page }) => {
  await page.addInitScript(() => {
    localStorage.setItem("yougori.public-access-presets.v1", JSON.stringify(Array.from({ length: 6 }, (_, index) => ({
      id: `00000000-0000-4000-8000-${String(index + 1).padStart(12, "0")}`,
      credentialEnvironmentId: "public-presets",
      port: 3000 + index,
      hostname: `app-${index + 1}.example.com`,
      hostPort: 45000 + index,
    }))))
  })
  await openGraph(page)
  const strip = page.locator("[data-service-destinations-scroll]")
  const cards = page.locator("[data-preset-card]")
  await expect(cards).toHaveCount(6)
  expect(await strip.evaluate(element => element.scrollWidth > element.clientWidth)).toBe(true)
  const first = (await cards.first().boundingBox())!
  const last = (await cards.last().boundingBox())!
  expect(Math.abs(first.y - last.y)).toBeLessThan(1)
  await strip.evaluate(element => { element.scrollLeft = element.scrollWidth })
  await expect(cards.last()).toBeInViewport()
  await expect(page.locator('[data-preset-connection-point="00000000-0000-4000-8000-000000000006"]')).toBeInViewport()
})

test("saved public domain setups connect the chosen environment port without storing tokens in browser storage", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  const other = fixture("Beta"); other.status = "running"
  await seedServices(page)
  await page.addInitScript(() => {
    const data = JSON.parse(localStorage.getItem("yougori.workspace.v1") ?? "{}")
    data.Beta = structuredClone(data.Alpha)
    localStorage.setItem("yougori.workspace.v1", JSON.stringify(data))
  })
  await openGraph(page, [env, other])
  await page.getByRole("button", { name: "Add or manage saved domain setups" }).click()
  const dialog = page.getByRole("dialog", { name: "Public access setups" })
  await expect(dialog.getByRole("combobox", { name: "Environment" })).toHaveCount(0)
  await dialog.getByRole("textbox", { name: "App port" }).fill("4200")
  await dialog.getByRole("textbox", { name: "Domain" }).fill("crm.example.com")
  await dialog.getByRole("textbox", { name: "Local tunnel port" }).fill("45000")
  await dialog.getByRole("textbox", { name: "Cloudflare tunnel token" }).fill("synthetic-secret-for-test")
  await dialog.getByRole("button", { name: "Save and connect tunnel" }).click()
  await expect(dialog.getByText("crm.example.com · :4200")).toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem("yougori.public-access-presets.v1"))).not.toContain("synthetic-secret-for-test")
  await expect(dialog.getByRole("button", { name: "Connect", exact: true })).toHaveCount(0)
  await dialog.getByRole("button", { name: "Done" }).click()
  await drag(page, page.locator('[data-service-connection-point="Alpha:4200"]'), page.locator('[data-publication-connection-point="public"]'))
  await expect(page.locator('[data-service-card="Alpha:4200"]')).toContainText("CF")
  const publications = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.v1") ?? "{}").Alpha?.publications ?? [])
  expect(publications).toEqual(expect.arrayContaining([expect.objectContaining({ port: 4200, hostPort: 45000, urls: ["https://crm.example.com"] })]))
  await drag(page, page.locator('[data-service-connection-point="Beta:4200"]'), page.locator('[data-publication-connection-point="public"]'))
  await expect(dialog.getByRole("alert")).toContainText("already connected to Alpha")
  await dialog.getByRole("button", { name: "Done" }).click()
  await page.evaluate(async () => {
    const url = "/src/api/workspace-api.ts", { workspaceApi } = await import(url)
    const publication = (await workspaceApi.services("Alpha")).publications.find(item => item.kind === "cloudflare" && item.port === 4200)!
    await workspaceApi.unpublish(publication.id)
  })
  await expect(page.locator('[data-service-card="Alpha:4200"]')).not.toContainText("CF")
  await drag(page, page.locator('[data-service-connection-point="Beta:4200"]'), page.locator('[data-publication-connection-point="public"]'))
  await expect(page.locator('[data-service-card="Beta:4200"]')).toContainText("CF")
  const otherPublications = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.v1") ?? "{}").Beta?.publications ?? [])
  expect(otherPublications).toEqual(expect.arrayContaining([expect.objectContaining({ urls: ["https://crm.example.com"] })]))
  await expect(dialog).toHaveCount(0)
  await page.evaluate(async () => {
    const url = "/src/api/workspace-api.ts", { workspaceApi } = await import(url)
    const publication = (await workspaceApi.services("Beta")).publications.find(item => item.kind === "cloudflare" && item.port === 4200)!
    await workspaceApi.unpublish(publication.id)
  })
  await expect(page.locator('[data-service-card="Beta:4200"]')).not.toContainText("CF")
  await page.getByRole("button", { name: "Add or manage saved domain setups" }).click()
  await dialog.getByRole("textbox", { name: "App port" }).fill("4200")
  await dialog.getByRole("textbox", { name: "Domain" }).fill("api.example.com")
  await dialog.getByRole("textbox", { name: "Local tunnel port" }).fill("45001")
  await dialog.getByRole("textbox", { name: "Cloudflare tunnel token" }).fill("another-synthetic-secret")
  await dialog.getByRole("button", { name: "Save and connect tunnel" }).click()
  await expect(dialog.getByText("api.example.com · :4200")).toBeVisible()
  await dialog.getByRole("button", { name: "Done" }).click()
  await drag(page, page.locator('[data-service-connection-point="Beta:4200"]'), page.locator('[data-publication-connection-point="public"]'))
  await expect(dialog).toBeVisible()
  await expect(dialog.getByText("Choose a saved setup for this port.")).toBeVisible()
  await dialog.getByText("api.example.com · :4200").locator("../..").getByRole("button", { name: "Connect app", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "Connected" })).toBeVisible()
  const selected = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.v1") ?? "{}").Beta?.publications ?? [])
  expect(selected).toEqual(expect.arrayContaining([expect.objectContaining({ urls: ["https://api.example.com"] })]))
})

test("errored containers keep deletion failures visible and require explicit runtime recovery", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "error"; env.lastError = "The old runtime is locking serial.log"
  await openGraph(page, [env, fixture("Beta")])
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts"
    const { platformApi } = await import(url)
    const original = platformApi.deleteEnvironment
    platformApi.deleteEnvironment = async (id: string, recover = false) => {
      if (!recover) throw new Error("[YOUGORI_RUNTIME_BUSY] Test orphan holds the container disk")
      await new Promise(resolve => window.addEventListener("complete-recovery", resolve, { once: true }))
      return original(id, recover)
    }
  })
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await expect(page.getByLabel("Environment needs attention")).toContainText("locking serial.log")
  await page.getByRole("button", { name: "More environment actions", exact: true }).click()
  await page.getByRole("menuitem", { name: "Delete environment", exact: true }).click()
  const dialog = page.getByRole("alertdialog")
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.locator('[data-environment-id="Alpha"]')).toBeAttached()
  await page.getByRole("button", { name: "More environment actions", exact: true }).click()
  await page.getByRole("menuitem", { name: "Delete environment", exact: true }).click()
  await dialog.getByRole("button", { name: "Delete environment", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.locator('[data-slot="toast-description"]').filter({ hasText: "Test orphan holds the container disk" })).toBeVisible()
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await page.getByRole("button", { name: "More environment actions", exact: true }).click()
  await page.getByRole("menuitem", { name: "Delete environment", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("Test orphan holds the container disk")
  await expect(page.locator('[data-environment-id="Alpha"]')).toBeAttached()
  await expect(dialog).toContainText("interrupts any containers")
  await dialog.getByRole("button", { name: "Recover runtime and delete", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.locator('[data-environment-id="Alpha"]')).toHaveAttribute("aria-busy", "true")
  await page.getByRole("button", { name: "Configure Beta", exact: true }).click()
  await expect(page.getByRole("dialog", { name: "Beta", exact: true })).toBeVisible()
  await page.getByRole("dialog", { name: "Beta", exact: true }).getByRole("button", { name: "Close", exact: true }).click()
  await page.evaluate(() => window.dispatchEvent(new Event("complete-recovery")))
  await expect(dialog).not.toBeVisible()
  await expect(page.locator('[data-environment-id="Alpha"]')).toHaveCount(0)
  await expect(page.locator('[data-environment-id="Beta"]')).toBeAttached()
})

test("normal deletion remains available from the environment menu", async ({ page }) => {
  await openGraph(page)
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await page.getByRole("button", { name: "More environment actions", exact: true }).click()
  await page.getByRole("menuitem", { name: "Delete environment", exact: true }).click()
  const dialog = page.getByRole("alertdialog")
  await expect(dialog.getByRole("heading", { name: "Delete Alpha?" })).toBeVisible()
  await expect(dialog.getByRole("button", { name: "Recover runtime and delete", exact: true })).toHaveCount(0)
  await dialog.getByRole("button", { name: "Delete environment", exact: true }).click()
  await expect(page.locator('[data-environment-id="Alpha"]')).toHaveCount(0)
  await expect(page.locator('[data-environment-id="Beta"]')).toBeAttached()
})

test("VM memory errors offer recovery and allocation actions instead of deletion", async ({ page }) => {
  const vm = fixture("Windows memory", "fullVm")
  vm.status = "error"
  vm.lastError = "Not enough memory to start this environment. It needs 27.00 GB but Windows can allocate only 15.50 GB."
  await openGraph(page, [vm])
  await page.getByRole("button", { name: "Configure Windows memory", exact: true }).click()
  const attention = page.getByLabel("Environment needs attention")
  await expect(attention.getByRole("button", { name: "Retry Start", exact: true })).toBeVisible()
  await expect(attention.getByRole("button", { name: "Stop", exact: true })).toBeVisible()
  await expect(attention.getByRole("button", { name: "Delete environment", exact: true })).toHaveCount(0)
  await attention.getByRole("button", { name: "Adjust memory", exact: true }).click()
  await expect(page.getByRole("region", { name: "Resource allocation", exact: true })).toBeFocused()
})

test("VM Stop remains available when stale state says stopped", async ({ page }) => {
  const vm = fixture("Leftover VM", "fullVm")
  await openGraph(page, [vm])
  await expect(page.getByRole("button", { name: "Shut down Leftover VM", exact: true })).toHaveCount(0)
  await page.getByRole("button", { name: "Configure Leftover VM", exact: true }).click()
  await page.getByRole("dialog", { name: "Leftover VM", exact: true }).getByRole("button", { name: "More environment actions", exact: true }).click()
  await expect(page.getByRole("menuitem", { name: "Shut down", exact: true })).toBeEnabled()
})

test("environment accents are distinct and match their capability lines", async ({ page }) => {
  const a = fixture("Alpha"), b = fixture("Beta")
  a.networkAccess = true; b.networkAccess = true
  await openGraph(page, [a, b])
  const alpha = await page.locator('[data-environment-id="Alpha"]').getAttribute("data-environment-color")
  const beta = await page.locator('[data-environment-id="Beta"]').getAttribute("data-environment-color")
  expect(alpha).toBeTruthy()
  expect(beta).toBeTruthy()
  expect(alpha).not.toBe(beta)
  await expect(page.locator('[data-capability-line="internet:Alpha"]')).toHaveAttribute("stroke", alpha!)
  await expect(page.locator('[data-capability-line="internet:Beta"]')).toHaveAttribute("stroke", beta!)
})

test("deletion updates runtime drive storage and explains incomplete cleanup", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts"
    const { platformApi } = await import(url)
    const remove = platformApi.deleteEnvironment
    platformApi.deleteEnvironment = async (id: string) => {
      const result = await remove(id)
      result.host.storageDrive = "C:\\"
      result.host.totalStorageGb = 100
      result.host.usedStorageGb = 80
      result.storageCleanup = { reclaimedCacheBytes: 0, warnings: ["Cached images were kept because a disk could not be inspected. Other environments are safe."] }
      return result
    }
  })
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await page.getByRole("button", { name: "More environment actions", exact: true }).click()
  await page.getByRole("menuitem", { name: "Delete environment", exact: true }).click()
  const dialog = page.getByRole("alertdialog")
  await expect(dialog.getByText(/Only the space actually used is reclaimed/)).toBeVisible()
  await dialog.getByRole("button", { name: "Delete environment", exact: true }).click()
  await expect(page.locator('[data-environment-id="Alpha"]')).toHaveCount(0)
  await expect(page.getByText("Environment removed — cleanup incomplete", { exact: true })).toBeVisible()
  await expect(page.getByText("C:", { exact: true })).toBeVisible()
  await expect(page.getByText("20.0 GB free", { exact: true })).toBeVisible()
  await expect(page.locator('[data-environment-id="Beta"]')).toBeAttached()
})

test("environment download links open from the node menu, survive closing their dialog and turn off", async ({ page }) => {
  await openGraph(page, [{ ...fixture("Alpha"), provider: "yougoriOci", status: "stopped" }])
  await page.locator('[data-id="Alpha"]').click({ button: "right" })
  await page.getByRole("menuitem", { name: "Create a download link" }).click()
  const dialog = page.getByRole("dialog", { name: "Environment download link" })
  await expect(dialog.getByRole("button", { name: "Create download link" })).toBeDisabled()
  await dialog.getByRole("checkbox").check()
  await dialog.getByRole("button", { name: "Create download link" }).click()
  await expect(dialog.getByRole("textbox", { name: "Download link" })).toHaveValue("https://download-preview.invalid/temporary")
  await expect(dialog.getByText("Downloads (all time): 0")).toBeVisible()
  await dialog.getByRole("button", { name: "Close", exact: true }).first().click()
  await expect(page.getByText("1 download link on")).toBeVisible()
  await page.getByRole("button", { name: "Turn off", exact: true }).click()
  await expect(page.getByText("1 download link on")).not.toBeVisible()
})

test("local backups choose a folder, show errors and confirm a verified save", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(async () => {
    const url = "/src/api/local-backup-api.ts"
    const { localBackupApi } = await import(url)
    let attempts = 0
    localBackupApi.export = async (id: string, folder: string) => {
      if (id !== "Alpha" || folder !== "C:\\Backups") throw new Error("Wrong backup target")
      if (!attempts++) throw new Error("Destination is full")
      return "C:\\Backups\\Yougori-backup-test\\backup.opendock"
    }
  })
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await page.getByRole("button", { name: "Back up to this PC", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Back up Alpha", exact: true })
  await expect(dialog).toContainText("not encrypted")
  await expect(dialog.getByRole("button", { name: "Create local backup", exact: true })).toBeDisabled()
  await dialog.getByRole("button", { name: "Choose destination folder", exact: true }).click()
  await dialog.getByRole("button", { name: "Create local backup", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("Destination is full")
  await dialog.getByRole("button", { name: "Create local backup", exact: true }).click()
  await expect(dialog.getByRole("status")).toContainText("Backup saved and verified")
  await dialog.getByRole("button", { name: "Done", exact: true }).click()
})

test("local restore is available without nodes and retains failures for retry", async ({ page }) => {
  await openGraph(page, [])
  const header = page.getByRole("banner")
  await expect(header.getByRole("button", { name: "Load local backup", exact: true })).toHaveCount(0)
  await expect(header.getByRole("button", { name: "Deploy to cloud", exact: true })).toHaveCount(0)
  await header.getByRole("button", { name: "New environment", exact: true }).click()
  const creation = page.getByRole("dialog", { name: "New environment", exact: true })
  await creation.getByText("Neocloud", { exact: true }).click()
  await expect(creation.getByRole("heading", { name: "Rent GPUs in the cloud", exact: true })).toBeVisible()
  await expect(page.getByRole("dialog")).toHaveCount(1)
  await creation.getByText("Cloud environment", { exact: true }).click()
  await expect(creation.getByRole("textbox", { name: "Server address" })).toBeVisible()
  await expect(page.getByRole("dialog")).toHaveCount(1)
  const backup = creation.getByText("Load local backup", { exact: true })
  await backup.click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(dialog).toContainText("Existing nodes are not overwritten")
  await dialog.getByRole("button", { name: "Choose backup file", exact: true }).click()
  await dialog.getByRole("button", { name: "Restore as new environment", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("require the desktop app")
  await expect(dialog).toBeVisible()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
})

test("running environments cannot start a local disk backup", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await openGraph(page, [env])
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await page.getByRole("button", { name: "Back up to this PC", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Back up Alpha", exact: true })
  await expect(dialog.getByRole("alert")).toContainText("Stop this environment")
  await expect(dialog.getByRole("button", { name: "Choose destination folder", exact: true })).toBeDisabled()
})

for (const gpu of [false, true]) test(`container startup command can be saved and cleared in configuration (GPU ${gpu})`, async ({ page }) => {
  const env = fixture("Alpha")
  env.containerCommand = "sleep 2147483647"
  if (gpu) { env.provider = "yougoriCuda"; env.gpuAccess = true }
  await openGraph(page, [env])
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  const sheet = page.getByRole("dialog", { name: "Alpha", exact: true })
  const input = sheet.getByRole("textbox", { name: "Startup command", exact: true })
  await expect(input).toHaveValue("sleep 2147483647")
  await expect(sheet.getByRole("button", { name: "Save startup command", exact: true })).toHaveCount(0)
  await input.fill("cd /project\nexec npm start")
  await sheet.getByRole("button", { name: "Save changes", exact: true }).click()
  await expect(sheet.getByRole("status").filter({ hasText: "Changes saved." })).toBeVisible()
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0].containerCommand)).toBe("cd /project\nexec npm start")
  // Closing and reopening the configuration shows the saved command.
  await page.keyboard.press("Escape")
  await expect(sheet).toHaveCount(0)
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await expect(input).toHaveValue("cd /project\nexec npm start")
  await input.fill("")
  await sheet.getByRole("button", { name: "Save changes", exact: true }).click()
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0].containerCommand)).toBeUndefined()
})

test("configuration popup is centered with all settings on one compact page", async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 })
  await openGraph(page)
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Alpha", exact: true })
  await expect(dialog.getByRole("tab")).toHaveCount(0)
  await expect(dialog.getByLabel("Environment usage")).toHaveCount(0)
  await expect(dialog.getByRole("slider", { name: "Storage limit", exact: true })).toBeVisible()
  for (const dark of [false, true]) {
    await page.evaluate(dark => document.documentElement.classList.toggle("dark", dark), dark)
    for (const name of ["Environment information", "Resource allocation", "Restore points", "Environment connections"]) {
      await expect(dialog.getByRole("region", { name, exact: true })).toBeInViewport({ ratio: 1 })
    }
    const box = (await dialog.boundingBox())!
    expect(box.width).toBeGreaterThan(1100)
    expect(Math.abs(box.x + box.width / 2 - 720)).toBeLessThan(2)
    expect(Math.abs(box.y + box.height / 2 - 450)).toBeLessThan(2)
    expect(await dialog.locator('[data-slot="scroll-area-viewport"]').first().evaluate(e => e.scrollHeight <= e.clientHeight + 1)).toBe(true)
  }
  await page.setViewportSize({ width: 1280, height: 800 })
  expect(await dialog.locator('[data-slot="scroll-area-viewport"]').first().evaluate(e => e.scrollHeight <= e.clientHeight + 1)).toBe(true)
  await dialog.getByRole("button", { name: "Storage allocation help", exact: true }).focus()
  await page.keyboard.press("Shift+Tab")
  await page.keyboard.press("Tab")
  await expect(page.getByRole("tooltip")).toContainText("Writable files")
  await page.keyboard.press("Escape")
  await expect(dialog).toBeVisible()
  for (const viewport of [{ width: 1024, height: 768 }, { width: 390, height: 650 }, { width: 320, height: 568 }]) {
    await page.setViewportSize(viewport)
    const header = (await dialog.locator('[data-slot="dialog-header"]').boundingBox())!
    await dialog.locator('[data-slot="scroll-area-viewport"]').first().evaluate(element => { element.scrollTop = element.scrollHeight })
    await expect(dialog.getByRole("button", { name: "More environment actions", exact: true })).toBeInViewport()
    await expect(dialog.getByRole("button", { name: "Save changes", exact: true })).toBeInViewport()
    await expect(dialog.getByRole("button", { name: "Open", exact: true })).toBeInViewport()
    expect((await dialog.locator('[data-slot="dialog-header"]').boundingBox())!.y).toBe(header.y)
    expect(await dialog.evaluate(element => {
      const box = element.getBoundingClientRect()
      const viewport = element.querySelector('[data-slot="scroll-area-viewport"]')!
      return box.left >= 0 && box.right <= innerWidth && viewport.scrollWidth <= viewport.clientWidth + 1
    })).toBe(true)
  }
  await dialog.getByRole("button", { name: "Close", exact: true }).click()
  await expect(dialog).not.toBeVisible()
})

test("configuration popup saves fixed values and preserves drafts", async ({ page }) => {
  await openGraph(page)
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  const sheet = page.getByRole("dialog", { name: "Alpha", exact: true })
  const saveChanges = sheet.getByRole("button", { name: "Save changes", exact: true })
  await expect(sheet.locator(".inspector-footer").getByRole("button", { name: "Save changes", exact: true })).toBeVisible()
  await expect(sheet.getByText("Changes apply when saved", { exact: true })).toHaveCount(0)
  const saveBox = await saveChanges.boundingBox()
  const openBox = await sheet.getByRole("button", { name: "Open", exact: true }).boundingBox()
  expect(saveBox!.x + saveBox!.width).toBeLessThanOrEqual(openBox!.x)
  expect(Math.abs(saveBox!.y - openBox!.y)).toBeLessThan(2)
  await expect(sheet.getByRole("slider")).toHaveCount(3)
  await expect(sheet.getByRole("spinbutton")).toHaveCount(3)
  const cpu = sheet.getByRole("slider", { name: "CPU allocation", exact: true })
  await cpu.focus(); await page.keyboard.press("ArrowRight")
  await expect(cpu).toHaveValue("0.3")
  const memory = sheet.getByRole("slider", { name: "Memory allocation", exact: true })
  await memory.focus(); await page.keyboard.press("ArrowRight")
  await expect(memory).toHaveAttribute("aria-valuetext", "0.375 GB")
  await expect(sheet.getByRole("radiogroup", { name: "Scheduling priority", exact: true })).toHaveCount(0)
  await expect(sheet.getByRole("button", { name: "Exact values", exact: true })).toHaveCount(0)
  await expect(cpu).toHaveValue("0.3")
  await expect(memory).toHaveValue("0.375")
  const preferred = sheet.getByRole("spinbutton", { name: "Memory value", exact: true })
  await preferred.fill("0")
  await expect(sheet.getByRole("alert")).toBeVisible()
  await expect(sheet.getByRole("button", { name: "Save changes", exact: true })).toBeDisabled()
  await preferred.fill("0.375")
  await expect(sheet.getByRole("alert")).toHaveCount(0)
  await sheet.getByRole("button", { name: "Save changes", exact: true }).click()
  await expect(sheet.getByRole("status").filter({ hasText: "Changes saved." })).toBeVisible()
  const policy = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0].resourcePolicy)
  expect(policy.cpu.preferred).toBe(0.3); expect(policy.memoryGb.preferred).toBe(0.375); expect(policy.priority).toBe("normal")
  expect(policy.cpu).toMatchObject({ min: 0.3, preferred: 0.3, max: 0.3 })
  expect(policy.memoryGb).toMatchObject({ min: 0.375, preferred: 0.375, max: 0.375 })
  await sheet.getByRole("button", { name: "Close", exact: true }).click()
  await page.reload()
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await expect(sheet.getByRole("spinbutton", { name: "CPU value", exact: true })).toHaveValue("0.3")
  await expect(sheet.getByRole("spinbutton", { name: "Memory value", exact: true })).toHaveValue("0.375")
})

test("configuration popup start failures stay visible and actions unlock for retry", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts", { platformApi } = await import(url)
    const original = platformApi.setEnvironmentStatus
    platformApi.setEnvironmentStatus = async () => {
      await new Promise(resolve => window.addEventListener("finish-start-test", resolve, { once: true }))
      platformApi.setEnvironmentStatus = original
      throw new Error("Runtime could not start. Please retry.")
    }
  })
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  const sheet = page.getByRole("dialog", { name: "Alpha", exact: true })
  await sheet.getByRole("button", { name: "Start", exact: true }).click()
  await expect(sheet.locator(".inspector-footer").getByRole("status")).toHaveText("Starting…")
  await expect(sheet.getByRole("button", { name: "Start", exact: true })).toHaveAttribute("aria-busy", "true")
  await expect(sheet.getByRole("button", { name: "Start", exact: true })).toBeDisabled()
  // The inspector may close while a background start continues.
  await expect(sheet.getByRole("button", { name: "Close", exact: true })).toBeEnabled()
  await expect(sheet.getByRole("button", { name: "More environment actions", exact: true })).toBeDisabled()
  await page.evaluate(() => window.dispatchEvent(new Event("finish-start-test")))
  await expect(sheet.getByRole("alert")).toContainText("Please retry")
  await sheet.getByRole("button", { name: "Start", exact: true }).click()
  await expect(sheet.getByRole("alert")).toHaveCount(0)
  await expect(sheet.locator('[data-slot="dialog-header"]')).toContainText("Running")
  await expect(sheet.getByRole("button", { name: "Open", exact: true })).toBeEnabled()
})

async function holdAction(page: Page, method: "setEnvironmentStatus" | "openEnvironmentWindow", fail = false) {
  await page.evaluate(async ({ method, fail }) => {
    const url = "/src/api/platform-api.ts", { platformApi } = await import(url)
    const api = platformApi as Record<string, (...args: unknown[]) => Promise<unknown>>
    const original = api[method]!
    localStorage.setItem(`test-calls:${method}`, "0")
    api[method] = async (...args) => {
      localStorage.setItem(`test-calls:${method}`, String(Number(localStorage.getItem(`test-calls:${method}`)) + 1))
      await new Promise(resolve => window.addEventListener(`finish:${method}`, resolve, { once: true }))
      api[method] = original
      if (fail) throw new Error("Test operation failed. Please retry.")
      return method === "openEnvironmentWindow" ? true : original(...args)
    }
  }, { method, fail })
}

test("dashboard action styling stays compact, accessible and usable in both themes", async ({ page }) => {
  await openGraph(page)
  const toolbar = page.getByRole("group", { name: "Dashboard actions", exact: true })
  const themeButton = page.getByRole("button", { name: "Theme", exact: true })
  for (const width of [1440, 768, 360]) {
    await page.setViewportSize({ width, height: 1000 })
    for (const dark of [false, true]) {
      await themeButton.click()
      const appearance = page.getByRole("dialog", { name: "Appearance", exact: true })
      const choice = appearance.getByRole("button", { name: dark ? "Dark" : "Light", exact: true })
      await choice.click()
      await expect(choice).toHaveAttribute("aria-pressed", "true")
      await appearance.getByRole("button", { name: "Close", exact: true }).click()
      await expect(page.locator("html")).toHaveClass(dark ? /dark/ : /^(?!.*dark)/)
      await expect(page.getByRole("region", { name: "Host resources and storage" })).toBeVisible()
      await expect(page.getByRole("button", { name: "Instructions", exact: true })).toBeVisible()
      for (const name of ["Personal Vault MCP", "Huggingface", "Neo Grid", "Settings", "New environment"]) {
        await expect(toolbar.getByRole("button", { name, exact: true })).toBeVisible()
      }
      await expect(toolbar.locator("svg")).toHaveCount(0)
      const boxes = await toolbar.locator(".dashboard-action").evaluateAll(elements => elements.map(element => {
        const box = element.getBoundingClientRect()
        return { x: box.x, y: box.y, right: box.right, height: box.height, width: box.width, radius: getComputedStyle(element).borderRadius, primary: element.classList.contains("dashboard-action-primary"), backgroundImage: getComputedStyle(element).backgroundImage }
      }))
      expect(boxes).toHaveLength(5)
      for (const box of boxes) {
        expect(box.x).toBeGreaterThanOrEqual(0)
        expect(box.right).toBeLessThanOrEqual(width)
        expect(box.height).toBe(box.primary ? 36 : 28)
        expect(box.width).toBeGreaterThanOrEqual(36)
        expect(box.radius).toBe(box.primary ? "10px" : "8px")
        if (box.primary) expect(box.backgroundImage).toContain("linear-gradient")
        else expect(box.backgroundImage).toBe("none")
      }
      // The toolbar now wraps naturally instead of imposing two fixed columns.
      for (let i = 0; i < boxes.length; i++) for (const other of boxes.slice(i + 1)) {
        const box = boxes[i]
        expect(box.right <= other.x || other.right <= box.x || box.y + box.height <= other.y || other.y + other.height <= box.y).toBe(true)
      }
      const launch = page.locator('[data-environment-id="Alpha"] .node-launch')
      expect(await launch.evaluate(element => getComputedStyle(element).height)).toBe("28px")
      await expect(launch).toHaveAccessibleName("Start")
      await expect(launch.locator("svg")).toHaveCount(0)
      expect(await launch.evaluate(element => getComputedStyle(element).backgroundImage)).toBe("none")
    }
  }
  await toolbar.getByRole("button", { name: "New environment", exact: true }).click()
  await page.getByRole("dialog", { name: "New environment", exact: true }).getByText("Load local backup", { exact: true }).click()
  const backup = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(backup).toBeVisible()
  await backup.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(backup).not.toBeVisible()
  await page.keyboard.press("Escape")
  const create = toolbar.getByRole("button", { name: "New environment", exact: true })
  await create.focus()
  await page.keyboard.press("Enter")
  await expect(page.getByRole("dialog", { name: "New environment", exact: true })).toBeVisible()
})

test("persistent notifications do not block mobile dialog actions and can be dismissed", async ({ page }) => {
  await page.setViewportSize({ width: 360, height: 640 })
  await openGraph(page)
  expect((await page.locator("[data-environment-canvas]").boundingBox())!.height).toBeGreaterThanOrEqual(320)
  await page.evaluate(async () => {
    const path = "/src/components/ui/toast.tsx"
    const { toastManager } = await import(path)
    toastManager.add({ title: "Persistent test warning", description: "This notice stays until dismissed.", timeout: 0, type: "warning" })
  })
  await expect(page.getByText("Persistent test warning", { exact: true })).toBeVisible()
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  await page.getByRole("dialog", { name: "New environment", exact: true }).getByText("Load local backup", { exact: true }).click()
  const backup = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(backup).toBeVisible()
  // A real click must reach the modal even while the persistent toast is present.
  await backup.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(backup).not.toBeVisible()
  await page.keyboard.press("Escape")
  await expect(page.getByText("Persistent test warning", { exact: true })).toBeVisible()
  await page.getByRole("button", { name: "Dismiss notification", exact: true }).click()
  await expect(page.getByText("Persistent test warning", { exact: true })).toBeHidden()
})

test("environment action loading spans start through window opening without blocking other nodes", async ({ page }) => {
  await openGraph(page)
  await holdAction(page, "setEnvironmentStatus")
  await holdAction(page, "openEnvironmentWindow")
  const node = page.locator('[data-environment-id="Alpha"]')
  const other = page.locator('[data-environment-id="Beta"]')
  await node.getByRole("button", { name: "Start", exact: true }).click()
  await expect(node.getByRole("status")).toHaveText("Starting…")
  await expect(node.getByRole("button", { name: "Start", exact: true })).toHaveAttribute("aria-busy", "true")
  await expect(node.locator('[data-slot="button-loading-indicator"]')).toHaveCount(1)
  expect(await node.locator(".node-launch").evaluate(element => getComputedStyle(element).color)).toBe("rgba(0, 0, 0, 0)")
  await expect(other.getByRole("button", { name: "Start", exact: true })).toBeEnabled()
  await expect(other).toHaveAttribute("aria-busy", "false")
  // Opening settings mid-operation must show the same pending state.
  await node.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  const sheet = page.getByRole("dialog", { name: "Alpha", exact: true })
  await expect(sheet.getByRole("button", { name: "Start", exact: true })).toHaveAttribute("aria-busy", "true")
  await expect(sheet.getByRole("button", { name: "Open", exact: true })).toBeDisabled()
  await page.evaluate(() => window.dispatchEvent(new Event("finish:setEnvironmentStatus")))
  await expect(sheet.locator(".inspector-footer").getByRole("status")).toHaveText("Opening…")
  await expect(node.locator('button[data-loading]')).toHaveAttribute("aria-busy", "true")
  await expect(node.locator(".node-launch")).toBeDisabled()
  await expect(sheet.getByRole("button", { name: "Open", exact: true })).toHaveAttribute("aria-busy", "true")
  expect(await page.evaluate(() => localStorage.getItem("test-calls:setEnvironmentStatus"))).toBe("1")
  expect(await page.evaluate(() => localStorage.getItem("test-calls:openEnvironmentWindow"))).toBe("1")
  await page.evaluate(() => window.dispatchEvent(new Event("finish:openEnvironmentWindow")))
  await expect(node.getByRole("button", { name: "Open", exact: true })).toBeEnabled()
  await expect(node.locator('[data-slot="button-loading-indicator"]')).toHaveCount(0)
  await expect(sheet).toHaveCount(0)
})

test("pause and stop show loading on the clicked node control and failure unlocks retry", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await openGraph(page, [env])
  const node = page.locator('[data-environment-id="Alpha"]')
  await holdAction(page, "setEnvironmentStatus", true)
  await node.getByRole("button", { name: "Pause Alpha", exact: true }).click()
  await expect(node.getByRole("button", { name: "Pause Alpha", exact: true })).toHaveAttribute("aria-busy", "true")
  await expect(node.getByRole("status")).toHaveText("Pausing…")
  await expect(node.getByRole("button", { name: "Stop", exact: true })).toBeDisabled()
  await page.evaluate(() => window.dispatchEvent(new Event("finish:setEnvironmentStatus")))
  await expect(node.getByRole("button", { name: "Pause Alpha", exact: true })).toBeEnabled()
  await expect(node.locator('[data-slot="button-loading-indicator"]')).toHaveCount(0)
  await expect(page.getByText("Test operation failed. Please retry.").first()).toBeVisible()
  await holdAction(page, "setEnvironmentStatus")
  await node.getByRole("button", { name: "Stop", exact: true }).click()
  await expect(node.getByRole("button", { name: "Stop", exact: true })).toHaveAttribute("aria-busy", "true")
  await expect(node.getByRole("status")).toHaveText("Stopping…")
  await page.evaluate(() => window.dispatchEvent(new Event("finish:setEnvironmentStatus")))
  await expect(node.getByRole("button", { name: "Start", exact: true })).toBeEnabled()
  await expect(node.locator('[data-slot="button-loading-indicator"]')).toHaveCount(0)
})

test("opening failure clears the node spinner and allows a new attempt", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await openGraph(page, [env])
  const node = page.locator('[data-environment-id="Alpha"]')
  await holdAction(page, "openEnvironmentWindow", true)
  await node.getByRole("button", { name: "Open", exact: true }).click()
  await expect(node.getByRole("button", { name: "Open", exact: true })).toHaveAttribute("aria-busy", "true")
  await page.evaluate(() => window.dispatchEvent(new Event("finish:openEnvironmentWindow")))
  await expect(node.getByRole("button", { name: "Open", exact: true })).toBeEnabled()
  await expect(page.getByText("Test operation failed. Please retry.").first()).toBeVisible()
  await holdAction(page, "openEnvironmentWindow")
  await node.getByRole("button", { name: "Open", exact: true }).click()
  await expect(node.getByRole("status")).toHaveText("Opening…")
  await page.evaluate(() => window.dispatchEvent(new Event("finish:openEnvironmentWindow")))
  await expect(node.getByRole("button", { name: "Open", exact: true })).toBeEnabled()
})

test("workspace window and lifecycle controls show pending spinners until completion", async ({ page }) => {
  const env = fixture("env-loading"); env.status = "running"
  const state = structuredClone(seed) as PlatformState; state.environments = [env]
  state.host.totalCpu = 8; state.host.totalMemoryGb = 16
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-loading")
  await expect(page.getByRole("tabpanel").locator(".xterm")).toBeVisible()
  await holdAction(page, "openEnvironmentWindow", true)
  await page.getByRole("button", { name: "New window", exact: true }).click()
  await expect(page.getByRole("button", { name: "New window", exact: true })).toHaveAttribute("aria-busy", "true")
  await expect(page.getByRole("button", { name: "Workspace actions", exact: true })).toBeDisabled()
  await page.evaluate(() => window.dispatchEvent(new Event("finish:openEnvironmentWindow")))
  await expect(page.getByRole("button", { name: "New window", exact: true })).toBeEnabled()
  await expect(page.getByRole("alert")).toContainText("Please retry")
  await holdAction(page, "setEnvironmentStatus")
  await page.getByRole("button", { name: "Workspace actions", exact: true }).click()
  await page.getByRole("menuitem", { name: "Stop environment", exact: true }).click()
  await expect(page.getByRole("button", { name: "Workspace actions", exact: true })).toHaveAttribute("aria-busy", "true")
  await expect(page.getByRole("status")).toContainText("Stopping…")
  await page.evaluate(() => window.dispatchEvent(new Event("finish:setEnvironmentStatus")))
  await expect(page.getByRole("button", { name: "Start environment", exact: true })).toBeVisible()
  await holdAction(page, "setEnvironmentStatus")
  await page.getByRole("button", { name: "Start environment", exact: true }).click()
  await expect(page.getByRole("button", { name: "Start environment", exact: true })).toHaveAttribute("aria-busy", "true")
  await page.evaluate(() => window.dispatchEvent(new Event("finish:setEnvironmentStatus")))
  await expect(page.getByRole("tabpanel").locator(".xterm")).toBeVisible()
  await expect(page.getByRole("button", { name: "New window", exact: true })).toBeEnabled()
})

test("configuration popup creates snapshots and preserves restore confirmation", async ({ page }) => {
  await openGraph(page)
  await page.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  const sheet = page.getByRole("dialog", { name: "Alpha", exact: true })
  await expect(sheet).toContainText("No snapshots for this environment")
  await sheet.getByRole("button", { name: "New snapshot", exact: true }).click()
  const create = page.getByRole("dialog", { name: "Create snapshot", exact: true })
  await create.getByRole("textbox", { name: "Name", exact: true }).fill("Before migration")
  await create.getByRole("button", { name: "Create snapshot", exact: true }).click()
  await expect(create).not.toBeVisible()
  await expect(sheet).toContainText("Before migration")
  await sheet.getByRole("button", { name: "Restore", exact: true }).click()
  const confirm = page.getByRole("alertdialog", { name: "Restore Before migration?", exact: true })
  await expect(confirm).toContainText("shut down and return to this point")
  await confirm.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(confirm).not.toBeVisible()
  await sheet.getByRole("button", { name: "Delete", exact: true }).click()
  await expect(sheet).toContainText("No snapshots for this environment")
})

test("My PC chooses folders, defaults to read-only, mounts and disconnects", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await openGraph(page, [env])
  await drag(page, dockPort(page, "pc"), port(page))
  const dialog = page.getByRole("dialog")
  await expect(dialog.getByRole("heading", { name: "My PC · Alpha" })).toBeVisible()
  await expect(dialog.getByRole("radio", { name: "View Only — read files", exact: true })).toBeChecked()
  await dialog.getByRole("button", { name: "Choose folders", exact: true }).click()
  await expect(dialog.getByText("C:\\Shared project", { exact: true })).toBeVisible()
  await expect(line(page, "pc")).toHaveCount(0)
  await dialog.getByRole("button", { name: "Connect selected folders", exact: true }).click()
  await expect(dialog.locator("code")).toContainText("/yougori/shared/my-pc/")
  await dialog.getByRole("button", { name: "Done", exact: true }).click()
  await assertLineAligned(page, "pc")
  await dockPort(page, "pc").click(); await port(page).click()
  await dialog.getByRole("button", { name: "Disconnect C:\\Shared project", exact: true }).click()
  await expect(line(page, "pc")).toHaveCount(0)
})

test("GPU is a category and legacy CUDA nodes have no Shared GPU connector", async ({ page }) => {
  const env = { ...fixture("Alpha"), provider: "yougoriCuda", gpuAccess: true }
  await openGraph(page, [env])
  await expect(page.locator('[data-environment-id="Alpha"]')).toContainText("GPU · NVIDIA CUDA")
  await expect(page.locator('[data-capability-kind="gpu"]')).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Choose shared GPU", exact: true })).toHaveCount(0)
  await expect(page.locator('[data-capability-kind="pc"]')).toBeVisible()
  await expect(page.locator('[data-capability-kind="internet"]')).toBeVisible()
})

test("GPU creation explains unsupported browser hardware and cannot claim CUDA works", async ({ page }) => {
  await openGraph(page)
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await dialog.getByRole("switch", { name: "GPU access", exact: true }).check()
  await expect(dialog.getByRole("region", { name: "NVIDIA CUDA runtime" })).toContainText("desktop app")
  await expect(dialog.getByRole("button", { name: "Set up CUDA", exact: true })).toBeDisabled()
  await expect(dialog.getByRole("button", { name: "Create environment", exact: true })).toBeDisabled()
})

test("public access uses only Cloudflare and preserves independent local connections", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await seedServices(page); await openGraph(page, [env])
  const service = page.locator('[data-service-connection-point="Alpha:4200"]')
  await expect(service).toBeAttached()
  const dialog = page.getByRole("dialog")
  for (const kind of ["local", "cloudflare"]) {
    const destination = page.locator(`[data-publication-connection-point="${kind === "local" ? "local" : "public"}"]`)
    // Exercise both drag directions against the combined public connector.
    await drag(page, kind === "cloudflare" ? destination : service, kind === "cloudflare" ? service : destination)
    await expect(dialog.getByRole("heading", { name: "Port 4200 · Alpha" })).toBeVisible()
    const dialogBox = (await dialog.boundingBox())!
    expect(dialogBox.width).toBeGreaterThan(760)
    expect(dialogBox.width).toBeLessThan(1050)
    const choices = await dialog.getByRole("radiogroup", { name: "Publish to", exact: true }).getByRole("radio").all()
    const choiceBoxes = await Promise.all(choices.map(choice => choice.boundingBox()))
    expect(choiceBoxes[1]!.y).toBeGreaterThan(choiceBoxes[0]!.y)
    if (kind === "cloudflare") expect((await dialog.getByRole("region", { name: "Cloudflare configuration and status" }).boundingBox())!.x).toBeGreaterThan(choiceBoxes[0]!.x)
    await expect(dialog.getByRole("radiogroup", { name: "Publish to", exact: true }).getByRole("radio")).toHaveCount(2)
    await expect(dialog.getByRole("radio", { name: "Direct public IP", exact: true })).toHaveCount(0)
    await expect(dialog.getByRole("radiogroup", { name: "Public access method", exact: true })).toHaveCount(0)
    if (kind === "cloudflare") await expect(dialog.getByRole("radio", { name: "Quick link — no account", exact: true })).toBeChecked()
    await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.v1")!).Alpha.publications.length)).toBe(["local", "cloudflare"].indexOf(kind))
    await dialog.getByRole("button", { name: kind === "local" ? "Connect local network" : "Publish service", exact: true }).click()
    await expect(dialog.getByRole("button", { name: `Disconnect ${kind} from port 4200`, exact: true })).toBeVisible()
    await dialog.getByRole("button", { name: "Done", exact: true }).click()
  }
  await expect(page.locator('[data-service-card="Alpha:4200"]')).toContainText("LAN · CF")
  await expect(page.locator('[data-service-card="Alpha:8080"]')).not.toContainText("LAN")
  await expect(page.locator('[data-capability-line^="pub-"]')).toHaveCount(2)
  for (const dark of [false, true]) {
    await page.evaluate(dark => document.documentElement.classList.toggle("dark", dark), dark)
    // The opaque dock surface must not sit above the wire layer. Cards remain
    // above wires, so the lines reach sockets without crossing button labels.
    expect(await page.locator(".workspace-connection-dock-top").evaluate(section => {
      const surface = getComputedStyle(section, "::before")
      const dock = getComputedStyle(section)
      const wireLayer = getComputedStyle(document.querySelector("[data-capability-lines]")!)
      const card = getComputedStyle(section.querySelector("[data-publication-card]")!)
      return dock.zIndex === "auto" && dock.backgroundColor === "rgba(0, 0, 0, 0)"
        && Number(surface.zIndex) < Number(wireLayer.zIndex)
        && Number(card.zIndex) > Number(wireLayer.zIndex)
    })).toBe(true)
  }
  await expect(page.locator('[data-publication-card="public"]').getByLabel("1 connected")).toBeVisible()
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  await dialog.getByRole("button", { name: "Disconnect cloudflare from port 4200", exact: true }).click()
  await expect(page.locator('[data-capability-line^="pub-"]')).toHaveCount(1)
  await expect(dialog.getByRole("button", { name: "Disconnect local from port 4200", exact: true })).toBeVisible()
})

test("CLI project proxy connects to its saved domain and local network cards", async ({ page }) => {
  const presetId = "5a75d123-6789-4cde-8f01-23456789abcd"
  await page.addInitScript(({ presetId }) => {
    localStorage.setItem("yougori.public-access-presets.v1", JSON.stringify([{ id: presetId, credentialEnvironmentId: "public-presets", port: 5281, hostname: "crm.example.com", hostPort: 5281 }]))
    localStorage.setItem("yougori.workspace.v1", JSON.stringify({ Alpha: {
      services: [{ port: 5281, name: "Vite", protocol: "tcp", address: "127.0.0.1" }, { port: 43119, name: "Yougori proxy", protocol: "tcp", address: "0.0.0.0" }], shares: [], notice: "",
      publications: [
        { id: "pub-domain", environmentId: "Alpha", kind: "cloudflare", port: 43119, hostPort: 5281, urls: ["https://crm.example.com"], status: "active", message: "" },
        { id: "pub-lan", environmentId: "Alpha", kind: "local", port: 43119, hostPort: 60983, urls: ["http://127.0.0.1:60983", "http://192.168.1.8:60983"], status: "active", message: "" },
      ],
    } }))
  }, { presetId })
  const environment = fixture("Alpha"); environment.status = "running"
  await openGraph(page, [environment])
  await expect(page.locator(`[data-capability-line="pub-Alpha:43119:preset:${presetId}"]`)).toHaveCount(1)
  await expect(page.locator('[data-capability-line="pub-Alpha:43119:publication:local"]')).toHaveCount(1)
  await expect(page.locator('[data-capability-line="pub-Alpha:43119:publication:public"]')).toHaveCount(0)
})

test("existing direct public connections can still be disconnected", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await page.addInitScript(() => localStorage.setItem("yougori.workspace.v1", JSON.stringify({ Alpha: {
    services: [], shares: [], notice: "", publications: [{ id: "legacy-public", environmentId: "Alpha", port: 4200, kind: "public", hostPort: 14200, urls: ["http://127.0.0.1:14200"], status: "active", message: "Existing connection" }],
  } })))
  await openGraph(page, [env])
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await expect(dialog.getByRole("radio", { name: "Direct public IP", exact: true })).toHaveCount(0)
  await expect(dialog.getByRole("radio", { name: "Quick link — no account", exact: true })).toBeChecked()
  await dialog.getByRole("button", { name: "Disconnect public from port 4200", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "Disconnect public from port 4200", exact: true })).toHaveCount(0)
  await expect.poll(() => page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.v1")!).Alpha.publications.length)).toBe(0)
})

test("desktop VM manual ports validate before adding a connectable service", async ({ page }) => {
  const env = fixture("Alpha", "fullVm"); env.status = "running"
  await openGraph(page, [env])
  await page.getByRole("button", { name: "Add service port to Alpha", exact: true }).click()
  await page.getByRole("textbox", { name: "Guest TCP port" }).fill("70000")
  await page.getByRole("button", { name: "Add port", exact: true }).click()
  await expect(page.getByRole("alert")).toContainText("Enter a port")
  await page.getByRole("textbox", { name: "Guest TCP port" }).fill("3000")
  await page.getByRole("button", { name: "Add port", exact: true }).click()
  await expect(page.getByRole("heading", { name: "Port 3000 · Alpha" })).toBeVisible()
  await page.getByRole("button", { name: "Done", exact: true }).click()
  await expect(page.locator('[data-service-connection-point="Alpha:3000"]')).toBeAttached()
})

test("PORT labels open service ports on containers, MicroVMs and VMs and the guide highlights PORT", async ({ page }) => {
  await openGraph(page, [fixture("Container"), fixture("Micro", "microVm"), fixture("VM", "fullVm")])
  for (const name of ["Container", "Micro", "VM"]) {
    const button = page.getByRole("button", { name: `Add service port to ${name}`, exact: true })
    await expect(button).toHaveText("PORT")
    await expect(button.locator("svg")).toHaveCount(0)
    await button.click()
    const dialog = page.getByRole("dialog", { name: `Add a service port · ${name}`, exact: true })
    await expect(dialog).toBeVisible()
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  }
  const before = await page.evaluate(() => [localStorage.getItem("yougori.platform.v1"), localStorage.getItem("yougori.workspace.manual.v2")])
  await page.getByRole("button", { name: "Instructions", exact: true }).click()
  await page.getByRole("dialog", { name: "Instructions", exact: true }).getByRole("button", { name: "Replay walkthrough", exact: true }).click()
  const guide = page.locator(".tour-card")
  for (const expected of overviewSteps.slice(1, overviewSteps.indexOf("service-ports") + 1)) {
    await guide.getByRole("button", { name: "Next", exact: true }).click()
    await expect(page.locator("[data-tour-step]")).toHaveAttribute("data-tour-step", expected)
  }
  await expect(guide.getByRole("heading", { name: "Add a service port", exact: true })).toBeVisible()
  // The overview targets its temporary preview, not an existing node whose
  // position in React Flow's DOM can change independently of the guide.
  const previewPort = page.locator('[data-tour-preview] [data-tour="node-port"]')
  await expect(previewPort).toBeInViewport({ ratio: 1 })
  await expect.poll(() => previewPort.evaluate(element => {
    const button = element.getBoundingClientRect()
    return [...document.querySelectorAll("[data-tour-highlight]")].some(element => {
      const ring = element.getBoundingClientRect()
      return ring.left <= button.left && ring.top <= button.top && ring.right >= button.right && ring.bottom >= button.bottom
    })
  })).toBe(true)
  await guide.getByRole("button", { name: "Next", exact: true }).click()
  await expect(page.locator("[data-tour-step]")).toHaveAttribute("data-tour-step", "connections")
  await expect(guide.getByRole("heading", { name: "Connect environments privately", exact: true })).toBeVisible()
  await guide.getByRole("button", { name: "Skip to hands-on", exact: true }).click()
  await expect(page.locator("[data-tour-step]")).toHaveAttribute("data-tour-step", "create-open")
  await guide.getByRole("button", { name: "Skip", exact: true }).click()
  await expect(guide).toBeHidden()
  expect(await page.evaluate(() => [localStorage.getItem("yougori.platform.v1"), localStorage.getItem("yougori.workspace.manual.v2")])).toEqual(before)
})

test("add service port has a compact responsive layout with long environment names", async ({ page }) => {
  const env = fixture("Alpha"); env.name = "Development workspace with a very long descriptive name for the database service"
  await openGraph(page, [env])
  await page.getByRole("button", { name: `Add service port to ${env.name}`, exact: true }).click()
  const dialog = page.getByRole("dialog", { name: `Add a service port · ${env.name}`, exact: true })
  await expect(dialog.getByRole("textbox", { name: "Guest TCP port", exact: true })).toBeFocused()
  for (const dark of [false, true]) {
    await page.evaluate(dark => document.documentElement.classList.toggle("dark", dark), dark)
    const bounds = (await dialog.boundingBox())!
    expect(bounds.width).toBeGreaterThanOrEqual(800)
    expect(bounds.height).toBeLessThan(550)
    expect((await dialog.locator('[data-slot="dialog-header"]').boundingBox())!.height).toBeLessThanOrEqual(58)
  }
  for (const viewport of [{ width: 900, height: 600 }, { width: 390, height: 650 }, { width: 320, height: 568 }]) {
    await page.setViewportSize(viewport)
    await expect.poll(() => dialog.evaluate(element => {
      const bounds = element.getBoundingClientRect()
      const footer = element.querySelector('[data-slot="dialog-footer"]')!.getBoundingClientRect()
      const overflow = [...element.querySelectorAll('[data-slot="scroll-area-viewport"]')].some(el => el.scrollWidth > el.clientWidth + 1)
      return bounds.left >= 0 && bounds.right <= innerWidth && bounds.bottom <= innerHeight && footer.bottom <= bounds.bottom && !overflow
    })).toBe(true)
    await expect(dialog.getByRole("button", { name: "Add port", exact: true })).toBeInViewport()
  }
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  expect(await page.evaluate(() => localStorage.getItem("yougori.manual-ports.v1"))).toBeNull()
})

test("add service port presets only fill the field and Enter opens unpublished connection options", async ({ page }) => {
  await openGraph(page, [fixture("Alpha")])
  await page.getByRole("button", { name: "Add service port to Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Add a service port · Alpha", exact: true })
  await expect(dialog.getByRole("status")).toContainText("Start this environment before connecting")
  for (const value of ["3000", "4200", "5173", "8080", "27017"]) {
    await dialog.getByRole("button", { name: value, exact: true }).click()
    await expect(dialog.getByRole("textbox", { name: "Guest TCP port", exact: true })).toHaveValue(value)
    await expect(dialog.getByRole("button", { name: value, exact: true })).toHaveAttribute("aria-pressed", "true")
    expect(await page.evaluate(() => localStorage.getItem("yougori.manual-ports.v1"))).toBeNull()
  }
  await dialog.getByRole("textbox", { name: "Guest TCP port", exact: true }).press("Enter")
  const connections = page.getByRole("dialog", { name: "Port 27017 · Alpha", exact: true })
  await expect(connections).toBeVisible()
  await expect(connections.getByRole("button", { name: "Connect local network", exact: true })).toBeDisabled()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.manual.v2")!).Alpha)).toEqual([27017])
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.v1") ?? "{}").Alpha?.publications ?? [])).toEqual([])
  await connections.getByRole("button", { name: "Done", exact: true }).click()
  await expect(page.locator('[data-service-connection-point="Alpha:27017"]')).toBeAttached()
  await page.getByRole("button", { name: "Add service port to Alpha", exact: true }).click()
  await expect(dialog.getByRole("textbox", { name: "Guest TCP port", exact: true })).toHaveValue("")
  await dialog.getByRole("button", { name: "27017", exact: true }).click()
  await dialog.getByRole("button", { name: "Add port", exact: true }).click()
  await expect(connections).toBeVisible()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.workspace.manual.v2")!).Alpha)).toEqual([27017])
})

test("add service port rejects invalid and reserved values without truncation or mutation", async ({ page }) => {
  await openGraph(page, [fixture("Alpha", "fullVm")])
  await page.getByRole("button", { name: "Add service port to Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Add a service port · Alpha", exact: true })
  const portInput = dialog.getByRole("textbox", { name: "Guest TCP port", exact: true })
  await expect(dialog).toContainText("0.0.0.0")
  for (const value of ["", "0", "-1", "7443", "65536", "655350", "3.5", "abc", "3000,4200"]) {
    await portInput.fill(value)
    await dialog.getByRole("button", { name: "Add port", exact: true }).click()
    await expect(dialog.getByRole("alert")).toContainText("Enter a port from 1 to 65535")
    await expect(portInput).toHaveValue(value)
    await expect(portInput).toBeFocused()
    expect(await page.evaluate(() => localStorage.getItem("yougori.manual-ports.v1"))).toBeNull()
  }
  await portInput.fill(" 65535 ")
  await expect(dialog.getByRole("alert")).toHaveCount(0)
  await portInput.press("Enter")
  await expect(page.getByRole("heading", { name: "Port 65535 · Alpha", exact: true })).toBeVisible()
})

test("independent terminal tabs retain output when switching environments", async ({ page }) => {
  const first = fixture("env-Alpha"), second = fixture("env-Beta"); first.status = "running"; second.status = "running"
  const state = structuredClone(seed) as PlatformState; state.environments = [first, second]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-Alpha")
  const screen = () => page.getByRole("tabpanel")
  await expect(screen().locator(".xterm")).toBeVisible()
  await expect(screen().locator(".xterm-screen")).toContainText("Yougori test terminal")
  await screen().locator(".xterm-helper-textarea").focus(); await page.keyboard.type("echo first-tab"); await page.keyboard.press("Enter")
  await expect(screen().locator(".xterm-screen")).toContainText("first-tab")
  await page.getByRole("button", { name: "New terminal or desktop tab", exact: true }).click()
  await expect(page.getByRole("tab")).toHaveCount(2)
  await expect(screen().locator(".xterm-screen")).toContainText("Yougori test terminal")
  await expect(screen().locator(".xterm-screen")).not.toContainText("first-tab")
  await screen().locator(".xterm-helper-textarea").focus(); await page.keyboard.type("echo second-tab"); await page.keyboard.press("Enter")
  await page.getByRole("tab", { name: "env-Alpha · Terminal 1", exact: true }).click()
  await expect(screen().locator(".xterm-screen")).toContainText("first-tab")
  await expect(screen().locator(".xterm-screen")).not.toContainText("second-tab")
  await page.getByRole("combobox", { name: "Switch environment", exact: true }).click()
  await page.getByRole("option", { name: "env-Beta", exact: true }).click()
  await expect(page.getByRole("tab", { selected: true })).toHaveText("env-Beta · Terminal 1")
  await expect(page.getByRole("tab")).toHaveCount(3)
  await page.getByRole("button", { name: "Close env-Alpha tab 2", exact: true }).click()
  await expect(page.getByRole("tab")).toHaveCount(2)
})

async function chooseInstaller(page: Page, name = "Codex") {
  await page.getByRole("button", { name: "Install tools", exact: true }).click()
  await page.getByRole("menuitem", { name: `Install ${name}`, exact: true }).click()
}

test("coding-tool dropdown starts automatically in fresh container terminals without touching existing input", async ({ page }) => {
  test.setTimeout(90000)
  const state = structuredClone(seed) as PlatformState
  const first = fixture("env-install"), second = fixture("env-install-other")
  first.status = "running"; second.status = "running"; first.networkAccess = true; second.networkAccess = true
  state.environments = [first, second]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-install")
  // A cold Vite start must compile the lazy workspace and terminal modules.
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeEnabled({ timeout: 60000 })
  await page.evaluate(async () => {
    const module = "/src/api/workspace-api.ts", { workspaceApi } = await import(module)
    const original = workspaceApi.terminal
    const writes: { environmentId: string; sessionId: string; data: string }[] = []
    Object.assign(window, { installerWrites: writes })
    workspaceApi.terminal = (...args: Parameters<typeof original>) => {
      if (args[2] === "write") writes.push({ environmentId: args[0], sessionId: args[1], data: atob(args[3]?.data ?? "") })
      return original(...args)
    }
  })
  for (const [index, { name, id }] of terminalInstallers.entries()) {
    if (index) await page.getByRole("button", { name: "New terminal or desktop tab", exact: true }).click()
    await chooseInstaller(page, name)
    await expect(page.getByRole("menu")).toHaveCount(0)
    await expect(page.getByRole("status")).toContainText("installation starts automatically")
    if (id === "ollama") await expect(page.getByRole("status")).toContainText("No model is downloaded")
    await expect.poll(() => page.evaluate(() => (window as unknown as { installerWrites: unknown[] }).installerWrites.length)).toBe(index + 1)
    await expect(page.getByRole("tabpanel").locator(".xterm-helper-textarea")).toBeFocused()
    await expect(page.getByRole("tab", { selected: true })).toContainText("Install " + name)
    await chooseInstaller(page, name)
    expect(await page.evaluate(() => (window as unknown as { installerWrites: unknown[] }).installerWrites.length)).toBe(index + 1)
    const selectedTab = page.getByRole("tab", { selected: true })
    const number = (await selectedTab.getAttribute("aria-label"))!.split(" ").at(-1)!
    await page.getByRole("button", { name: "Close env-install tab " + number, exact: true }).click()
  }
  const writes = await page.evaluate(() => (window as unknown as { installerWrites: { environmentId: string; sessionId: string; data: string }[] }).installerWrites)
  expect(new Set(writes.map(write => write.sessionId)).size).toBe(terminalInstallers.length)
  expect(writes.every(write => write.environmentId === "env-install" && write.data.endsWith("\r") && write.data.length < 200)).toBe(true)
  for (const [index, tool] of terminalInstallers.entries()) expect(writes[index]!.data).toBe(`exec sh '/tmp/yougori-install.${tool.id}/install.sh'\r`)
  await page.getByRole("combobox", { name: "Switch environment", exact: true }).click()
  await page.getByRole("option", { name: "env-install-other", exact: true }).click()
  await chooseInstaller(page)
  await expect.poll(() => page.evaluate(() => (window as unknown as { installerWrites: { environmentId: string }[] }).installerWrites.at(-1)?.environmentId)).toBe("env-install-other")
})

test("coding-tool installation requires internet without enabling it automatically", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  const env = fixture("env-install-offline"); env.status = "running"
  state.environments = [env]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-install-offline")
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeEnabled()
  await chooseInstaller(page)
  await expect(page.getByRole("alert")).toContainText("Connect Internet access")
  await expect(page.getByRole("tab")).toHaveCount(1)
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0].networkAccess)).toBe(false)
})

test("installer preparation failure preserves the existing prompt and can be retried", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  const env = fixture("env-install-retry"); env.status = "running"; env.networkAccess = true
  state.environments = [env]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-install-retry")
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeEnabled()
  await page.getByRole("tabpanel").locator(".xterm-helper-textarea").focus()
  await page.keyboard.type("echo unfinished")
  await expect(page.getByRole("tabpanel").locator(".xterm-screen")).toContainText("echo unfinished")
  await page.evaluate(async () => {
    const module = "/src/api/workspace-api.ts", { workspaceApi } = await import(module)
    const prepare = workspaceApi.prepareInstaller
    workspaceApi.prepareInstaller = async () => { workspaceApi.prepareInstaller = prepare; throw new Error("Fixture: image has no writable /tmp") }
  })
  await chooseInstaller(page)
  await expect(page.getByRole("alert")).toContainText("image has no writable /tmp")
  await page.getByRole("tab", { name: "env-install-retry · Terminal 1", exact: true }).click()
  await expect(page.getByRole("tabpanel").locator(".xterm-screen")).toContainText("echo unfinished")
  await expect(page.getByRole("tabpanel").locator(".xterm-screen")).not.toContainText("exec sh")
  await chooseInstaller(page)
  await expect(page.getByRole("tabpanel").locator(".xterm-screen")).toContainText("yougori-install.codex/install.sh")
})

test("closing a preparing install tab prevents delayed command execution", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  const env = fixture("env-install-cancel"); env.status = "running"; env.networkAccess = true
  state.environments = [env]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-install-cancel")
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeEnabled()
  await page.evaluate(async () => {
    const module = "/src/api/workspace-api.ts", { workspaceApi } = await import(module)
    workspaceApi.prepareInstaller = async () => {
      document.documentElement.setAttribute("data-install-preparing", "true")
      await new Promise<void>(resolve => window.addEventListener("finish-install-prepare", () => resolve(), { once: true }))
      document.documentElement.setAttribute("data-install-prepared", "true")
      return "exec sh '/tmp/yougori-install.cancel/install.sh'"
    }
    const terminal = workspaceApi.terminal
    workspaceApi.terminal = (...args: Parameters<typeof terminal>) => {
      if (args[2] === "write") document.documentElement.setAttribute("data-install-written", "true")
      return terminal(...args)
    }
  })
  await chooseInstaller(page)
  await chooseInstaller(page)
  await expect(page.locator("html")).toHaveAttribute("data-install-preparing", "true")
  await expect(page.getByRole("tab")).toHaveCount(2)
  await page.getByRole("button", { name: "Close env-install-cancel tab 2", exact: true }).click()
  await page.evaluate(() => window.dispatchEvent(new Event("finish-install-prepare")))
  await expect(page.locator("html")).toHaveAttribute("data-install-prepared", "true")
  await expect(page.locator("html")).not.toHaveAttribute("data-install-written")
  await expect(page.getByRole("tab")).toHaveCount(1)
})

test("coding-tool controls stay left of New window at desktop and narrow widths", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  const env = fixture("env-installer-layout"); env.status = "running"
  state.environments = [env]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-installer-layout")
  for (const width of [1440, 720, 360]) {
    await page.setViewportSize({ width, height: 600 })
    const newWindow = await page.getByRole("button", { name: "New window", exact: true }).boundingBox()
    const button = page.getByRole("button", { name: "Install tools", exact: true })
    await expect(button).toBeInViewport()
    const bounds = await button.boundingBox()
    expect(bounds!.x + bounds!.width).toBeLessThanOrEqual(newWindow!.x)
    await expect(page.getByRole("menuitem")).toHaveCount(0)
    await button.click()
    for (const { name } of terminalInstallers) await expect(page.getByRole("menuitem", { name: `Install ${name}`, exact: true })).toBeInViewport()
    await page.keyboard.press("Escape")
    await expect(button).toBeFocused()
    await expect(page.getByRole("menu")).toHaveCount(0)
    expect((await page.locator("[data-workspace-toolbar]").boundingBox())!.height).toBeLessThanOrEqual(44)
  }
})

test("coding-tool dropdown is disabled for stopped or ended terminals and absent on VM desktops", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  state.host.totalCpu = 8
  state.host.totalMemoryGb = 16
  state.environments = [fixture("env-install-stopped"), fixture("env-install-desktop", "fullVm")]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-install-stopped")
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeDisabled()
  await page.evaluate(async () => {
    const module = "/src/api/workspace-api.ts", { workspaceApi } = await import(module)
    const original = workspaceApi.terminal
    workspaceApi.terminal = async (...args: Parameters<typeof original>) => args[2] === "read" ? { data: "", offset: 0, done: true } : original(...args)
  })
  await page.getByRole("button", { name: "Start environment", exact: true }).click()
  await expect(page.getByRole("tabpanel").locator(".xterm-screen")).toContainText("Session ended")
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeDisabled()
  await page.getByRole("combobox", { name: "Switch environment", exact: true }).click()
  await page.getByRole("option", { name: "env-install-desktop", exact: true }).click()
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toHaveCount(0)
})

test("terminal keyboard copy and paste work without duplicate input", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  const environment = fixture("env-clipboard"); environment.status = "running"; state.environments = [environment]
  await page.addInitScript(state => {
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
    // Isolated clipboard: never read or overwrite the user's real clipboard.
    let text = "echo pasted-once"
    Object.defineProperty(navigator, "clipboard", { configurable: true, value: { readText: async () => text, writeText: async (value: string) => { text = value } } })
  }, state)
  await page.goto("/?environment=env-clipboard")
  const terminal = page.getByRole("tabpanel").locator(".xterm")
  await expect(terminal.locator(".xterm-screen")).toContainText("Yougori test terminal")
  await terminal.locator(".xterm-helper-textarea").focus()
  await page.keyboard.press("Control+v")
  await expect(terminal.locator(".xterm-rows > div").nth(1)).toHaveText("$ echo pasted-once")
  await page.keyboard.press("Enter")
  await expect(terminal.locator(".xterm-rows > div").nth(2)).toHaveText("pasted-once")
  await terminal.locator(".xterm-rows > div").nth(2).dblclick({ position: { x: 15, y: 8 } })
  await page.keyboard.press("Control+c")
  await expect.poll(() => page.evaluate(() => navigator.clipboard.readText())).toBe("pasted-once")
  await page.getByRole("button", { name: "New terminal or desktop tab", exact: true }).click()
  await expect(terminal.locator(".xterm-screen")).toContainText("Yougori test terminal")
  await page.evaluate(() => navigator.clipboard.writeText("echo shift-paste"))
  await terminal.locator(".xterm-helper-textarea").focus(); await page.keyboard.press("Control+Shift+v")
  await expect(terminal.locator(".xterm-rows > div").nth(1)).toHaveText("$ echo shift-paste")
})

test("terminal output automatically gets local QR cards scoped to its tab", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  const environment = fixture("env-qr"); environment.status = "running"; state.environments = [environment]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-qr")
  const terminal = () => page.getByRole("tabpanel").locator(".xterm")
  await expect(terminal().locator(".xterm-screen")).toContainText("Yougori test terminal")
  await terminal().locator(".xterm-helper-textarea").focus()
  const panel = () => page.getByRole("tabpanel")
  // Force a scan between output chunks. A URL still being typed must be
  // replaced as it grows, rather than retained as another historical QR card.
  await page.keyboard.type("echo https://example.com/setup?code=a")
  await expect(panel().locator('[data-terminal-link="https://example.com/setup?code=a"]')).toBeVisible()
  await terminal().locator(".xterm-helper-textarea").focus()
  await page.keyboard.type("bc http://localhost:3000/"); await page.keyboard.press("Enter")
  await expect(panel().locator("[data-terminal-link]")).toHaveCount(2)
  await expect(panel().getByRole("img", { name: "QR code for https://example.com/setup?code=abc", exact: true })).toBeVisible()
  await expect(panel().getByText("Localhost is device-only.", { exact: false })).toBeVisible()
  await expect(terminal().locator(".xterm-screen")).toContainText("https://example.com/setup?code=abc")
  await page.getByRole("button", { name: "New terminal or desktop tab", exact: true }).click()
  await expect(panel().locator("[data-terminal-link]")).toHaveCount(0)
  await page.getByRole("tab", { name: "env-qr · Terminal 1", exact: true }).click()
  await expect(panel().locator("[data-terminal-link]")).toHaveCount(2)
  await panel().getByRole("button", { name: "Dismiss QR code for https://example.com/setup?code=abc", exact: true }).click()
  await expect(panel().locator("[data-terminal-link]")).toHaveCount(1)
  await terminal().locator(".xterm-helper-textarea").focus()
  await page.keyboard.type("echo https://example.org/new"); await page.keyboard.press("Enter")
  // New output forces another scan of the old URL as well as the new one.
  await expect(panel().locator('[data-terminal-link="https://example.org/new"]')).toBeVisible()
  await expect(panel().locator('[data-terminal-link="https://example.com/setup?code=abc"]')).toHaveCount(0)
  await panel().getByRole("button", { name: "Dismiss QR code for http://localhost:3000/", exact: true }).click()
  await panel().getByRole("button", { name: "Dismiss QR code for https://example.org/new", exact: true }).focus()
  await page.keyboard.press("Enter")
  await expect(panel().getByRole("region", { name: "Terminal link QR codes" })).toHaveCount(0)
  await page.getByRole("tab", { name: "env-qr · Terminal 2", exact: true }).click()
  await terminal().locator(".xterm-helper-textarea").focus()
  await page.keyboard.type("echo https://example.com/setup?code=abc"); await page.keyboard.press("Enter")
  await expect(panel().locator("[data-terminal-link]")).toHaveCount(1)
  await page.getByRole("tab", { name: "env-qr · Terminal 1", exact: true }).click()
  await expect(panel().locator("[data-terminal-link]")).toHaveCount(0)
})

test("workspace chrome stays compact with long names and many tabs", async ({ page }) => {
  const environment = fixture("env-long-workspace")
  environment.name = "Development environment with a very long project name"
  environment.status = "running"
  const state = structuredClone(seed) as PlatformState
  state.environments = [environment]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.setViewportSize({ width: 720, height: 480 })
  await page.goto("/?environment=env-long-workspace")
  await expect(page.getByRole("tabpanel").locator(".xterm")).toBeVisible()
  const firstTab = await page.getByRole("tab").boundingBox()
  const addTab = await page.getByRole("button", { name: "New terminal or desktop tab", exact: true }).boundingBox()
  expect(firstTab).not.toBeNull(); expect(addTab).not.toBeNull()
  expect(addTab!.x - (firstTab!.x + firstTab!.width)).toBeLessThan(48)
  for (let index = 0; index < 5; index++) await page.getByRole("button", { name: "New terminal or desktop tab", exact: true }).click()
  await expect(page.getByRole("tab")).toHaveCount(6)
  await expect(page.getByRole("tab", { selected: true })).toBeInViewport()
  for (const width of [720, 360]) {
    await page.setViewportSize({ width, height: 480 })
    const measurements = await page.locator("[data-guest-workspace]").evaluate(element => {
      const toolbar = element.querySelector("[data-workspace-toolbar]")!
      const tabs = element.querySelector("[data-workspace-tabs]")!
      return { width: element.clientWidth, scrollWidth: element.scrollWidth, toolbar: toolbar.getBoundingClientRect().height, tabs: tabs.getBoundingClientRect().height }
    })
    expect(measurements.scrollWidth).toBeLessThanOrEqual(measurements.width)
    expect(measurements.toolbar).toBeLessThanOrEqual(44)
    expect(measurements.tabs).toBeLessThanOrEqual(36)
    await expect(page.getByRole("button", { name: "Workspace actions", exact: true })).toBeInViewport()
    await expect(page.getByRole("combobox", { name: "Switch environment", exact: true })).toBeInViewport()
  }
  await page.getByRole("button", { name: "Switch window", exact: true }).click()
  await expect(page.getByRole("menu")).toBeVisible()
  await expect(page.getByText("No other windows open.", { exact: true })).toBeVisible()
  await page.keyboard.press("Escape")
  await expect(page.getByRole("menu")).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Switch window", exact: true })).toBeFocused()
  await page.getByRole("button", { name: `Close ${environment.name} tab 6`, exact: true }).click()
  await expect(page.getByRole("tab", { selected: true })).toHaveAccessibleName(`${environment.name} · Terminal 5`)
  await expect(page.getByRole("tabpanel")).toHaveCount(1)
})

for (const accelerated of [false, true]) test(`real QEMU ${accelerated ? "accelerated" : "basic"} viewer preserves proportions before guest drivers load`, async ({ page }) => {
  test.skip(process.platform !== "win32", "Uses the bundled Windows QEMU executable")
  test.setTimeout(60_000)
  const availablePort = () => new Promise<number>((resolvePort, reject) => {
    const server = createServer()
    server.on("error", reject)
    server.listen(0, "127.0.0.1", () => {
      const address = server.address()
      if (!address || typeof address === "string") { server.close(); reject(new Error("No test port")); return }
      server.close(error => error ? reject(error) : resolvePort(address.port))
    })
  })
  const rfbPort = await availablePort()
  let websocketPort = await availablePort()
  while (websocketPort === rfbPort) websocketPort = await availablePort()
  // A paused, diskless, networkless test machine. Never open a user VM image.
  const directory = resolve("src-tauri/resources/runtime/qemu-secure")
  const qemu = spawn(resolve(directory, "qemu-system-x86_64.exe"), [
    "-L", resolve("src-tauri/resources/runtime/qemu/share"),
    "-machine", "q35", "-accel", "tcg", "-m", "64", "-nodefaults", "-S",
    "-device", accelerated ? "virtio-vga-gl,id=opendock-display,max_outputs=1" : "VGA",
    "-display", accelerated ? "egl-headless" : "none", "-monitor", "none",
    "-vnc", `127.0.0.1:${rfbPort - 5900},websocket=127.0.0.1:${websocketPort},share=force-shared`,
  ], { cwd: directory, windowsHide: true, stdio: ["ignore", "ignore", "pipe"] })
  let startupError = ""
  const stopped = new AbortController()
  const viewerErrors: string[] = []
  page.on("console", message => { if (message.type() === "error") { viewerErrors.push(message.text()); if (viewerErrors.length > 10) viewerErrors.shift() } })
  qemu.stderr.on("data", data => { startupError = (startupError + String(data)).slice(-4096) })
  qemu.on("error", error => { startupError = error.message; stopped.abort(error) })
  qemu.once("exit", (code, signal) => stopped.abort(new Error(`Disposable QEMU exited (${signal ?? code})`)))
  const exited = new Promise<void>(done => qemu.once("close", () => done()))
  try {
    const state = structuredClone(seed) as PlatformState
    state.environments = [fixture("env-vnc-fixture", "fullVm")]
    await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
    await page.goto("/?environment=env-vnc-fixture")
    const websocketUrl = `ws://127.0.0.1:${websocketPort}`
    await waitForVnc(websocketUrl, { signal: stopped.signal })
    await page.evaluate(async url => {
      const modulePath = "/node_modules/@novnc/novnc/core/rfb.js"
      const { default: RFB } = await import(modulePath)
      const target = document.createElement("div")
      target.id = "real-vnc-fixture"
      target.style.cssText = "position:fixed;inset:0 auto auto 0;width:800px;height:500px;z-index:99999;overflow:hidden"
      document.body.append(target)
      const client = new RFB(target, url, { shared: true })
      client.scaleViewport = true
      client.resizeSession = true
      ;(window as unknown as { displayFixture: { disconnect(): void } }).displayFixture = client
      await new Promise<void>((resolveConnection, reject) => {
        const timeout = setTimeout(() => reject(new Error("Disposable VNC connection timed out")), 15_000)
        client.addEventListener("connect", () => { clearTimeout(timeout); resolveConnection() }, { once: true })
        client.addEventListener("disconnect", () => { clearTimeout(timeout); reject(new Error("Disposable VNC disconnected")) }, { once: true })
      })
    }, websocketUrl)
    const target = page.locator("#real-vnc-fixture"), canvas = target.locator("canvas")
    for (const [width, height] of [[800, 500], [500, 800], [1234, 777]]) {
      await target.evaluate((element, size) => { element.style.width = `${size[0]}px`; element.style.height = `${size[1]}px` }, [width, height])
      await expect.poll(async () => {
        const bounds = await canvas.boundingBox()
        const source = await canvas.evaluate(element => [element.width, element.height])
        return Boolean(bounds && Math.abs(bounds.width / bounds.height - source[0]! / source[1]!) < 0.001
          && bounds.width <= width + 1 && bounds.height <= height + 1
          && (Math.abs(bounds.width - width) < 1 || Math.abs(bounds.height - height) < 1))
      }).toBe(true)
    }
    // Matching the viewport to the actual framebuffer removes bars without
    // changing pixels, cropping the desktop, or pretending VGA supports resize.
    const source = await canvas.evaluate(element => [element.width, element.height])
    await target.evaluate((element, size) => { element.style.width = `${size[0]}px`; element.style.height = `${size[1]}px` }, source)
    await expect.poll(async () => {
      const bounds = await canvas.boundingBox()
      return bounds ? [Math.round(bounds.width), Math.round(bounds.height)] : null
    }).toEqual(source)
    await page.evaluate(() => { (window as unknown as { displayFixture: { disconnect(): void } }).displayFixture.disconnect() })
  } catch (error) {
    throw new Error(`${error instanceof Error ? error.message : String(error)}\nQEMU exit: ${qemu.signalCode ?? qemu.exitCode ?? "still running"}\nQEMU stderr: ${startupError || "(empty)"}\nViewer errors: ${viewerErrors.join("\n") || "(empty)"}`, { cause: error })
  } finally {
    // This child has no disks and has never run a guest instruction.
    if (qemu.exitCode === null) qemu.kill()
    await exited
  }
})

test("VM workspace offers real resolution resizing without a stretching mode", async ({ page }) => {
  const state = structuredClone(seed) as PlatformState
  state.environments = [fixture("env-display-options", "fullVm")]
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-display-options")
  await page.getByRole("button", { name: "Workspace actions", exact: true }).click()
  await expect(page.getByRole("menuitem", { name: "Fit window to desktop", exact: true })).toBeVisible()
  await expect(page.getByRole("menu")).toContainText("Asks the guest to match the focused window")
  await expect(page.getByRole("menu")).toContainText("never stretched or cropped")
  await expect(page.getByRole("menu")).toContainText("move the pointer out to release it")
  await page.getByRole("menuitem", { name: "Keep guest resolution", exact: true }).click()
  await page.getByRole("button", { name: "Workspace actions", exact: true }).click()
  await expect(page.getByRole("menu")).toContainText("Keeps the resolution set inside the guest")
  await page.getByRole("menuitem", { name: "Auto-resize guest resolution", exact: true }).click()
  await page.getByRole("button", { name: "Workspace actions", exact: true }).click()
  await expect(page.getByRole("menuitem", { name: "Keep guest resolution", exact: true })).toBeVisible()
  await expect(page.getByRole("menuitem", { name: "Fill window edge to edge", exact: true })).toHaveCount(0)
})

test("workspace actions separate stopping from window navigation", async ({ page }) => {
  const environment = fixture("env-workspace-actions"); environment.status = "running"
  const state = structuredClone(seed) as PlatformState; state.environments = [environment]
  state.host.totalCpu = 8
  state.host.totalMemoryGb = 16
  await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
  await page.goto("/?environment=env-workspace-actions")
  await expect(page.getByRole("tabpanel").locator(".xterm")).toBeVisible()
  await expect(page.getByRole("button", { name: "Stop environment", exact: true })).toHaveCount(0)
  await page.getByRole("button", { name: "Workspace actions", exact: true }).click()
  await expect(page.getByRole("menuitem", { name: "Close window", exact: true })).toBeVisible()
  await page.getByRole("menuitem", { name: "Stop environment", exact: true }).click()
  await expect(page.getByRole("button", { name: "Start environment", exact: true })).toBeVisible()
  await expect(page.getByRole("button", { name: "New window", exact: true })).toBeDisabled()
  await page.getByRole("button", { name: "Start environment", exact: true }).click()
  await expect(page.getByRole("tabpanel").locator(".xterm")).toBeVisible()
  await expect(page.getByRole("button", { name: "New window", exact: true })).toBeEnabled()
})

for (const theme of ["light", "dark"]) {
  test(`workspace selection and fullscreen controls work in ${theme} mode`, async ({ page }) => {
    const state = structuredClone(seed) as PlatformState
    state.environments = [fixture("env-keyboard", "fullVm"), fixture("env-shell")]
    await page.addInitScript(state => localStorage.setItem("yougori.platform.v1", JSON.stringify(state)), state)
    await page.goto("/?environment=env-keyboard")
    await expect(page.getByRole("tab", { name: "env-keyboard · Desktop 1", exact: true })).toBeVisible()
    await page.evaluate(theme => document.documentElement.classList.toggle("dark", theme === "dark"), theme)
    const picker = page.getByRole("combobox", { name: "Switch environment", exact: true })
    await picker.focus(); await page.keyboard.press("Enter")
    await expect(page.getByRole("option", { name: "env-shell", exact: true })).toContainText("Container · Stopped")
    await page.keyboard.press("End"); await page.keyboard.press("Enter")
    await expect(page.getByRole("tab", { selected: true })).toHaveAccessibleName("env-shell · Terminal 1")
    await page.getByRole("tab", { selected: true }).focus(); await page.keyboard.press("ArrowLeft")
    await expect(page.getByRole("tab", { name: "env-keyboard · Desktop 1", exact: true })).toBeFocused()
    await page.keyboard.press("Enter")
    await expect(page.getByRole("tab", { selected: true })).toHaveAccessibleName("env-keyboard · Desktop 1")
    const fullscreen = page.getByRole("button", { name: "Toggle fullscreen", exact: true })
    await fullscreen.click()
    await expect(fullscreen).toHaveAttribute("aria-pressed", "true")
    await fullscreen.click()
    await expect(fullscreen).toHaveAttribute("aria-pressed", "false")
  })
}

test("connects with clicks or keyboard, accepts whole cards, and cancels cleanly", async ({ page }) => {
  await openGraph(page)
  await dockPort(page, "internet").focus()
  await page.keyboard.press("Enter")
  await port(page).focus()
  await page.keyboard.press("Enter")
  await assertLineAligned(page, "internet")
  await expect(page.locator('[data-capability-kind="gpu"]')).toHaveCount(0)
  await page.locator('[data-capability-kind="internet"]').click()
  await page.locator('[data-environment-id="Beta"] dl').click()
  await assertLineAligned(page, "internet", "Beta")
  await dockPort(page, "internet").click()
  await page.keyboard.press("Escape")
  await expect(page.locator("[data-environment-graph]")).toHaveAttribute("data-connecting", "false")
  await expect(page.locator("[data-connection-preview]")).toHaveCount(0)
  await port(page).click()
  await page.locator("[data-environment-canvas]").click({ position: { x: 12, y: 12 } })
  await expect(page.locator("[data-environment-graph]")).toHaveAttribute("data-connecting", "false")
})

test("cancelled drops never change settings or open a dialog", async ({ page }) => {
  const running = fixture("Running")
  running.status = "running"
  await openGraph(page, [fixture("Alpha", "microVm"), running])
  await expect(line(page, "internet")).toHaveCount(0)
  await expect(dockPort(page, "gpu")).toHaveCount(0)
  const start = await center(dockPort(page, "internet"))
  await page.mouse.move(start.x, start.y)
  await page.mouse.down()
  await page.mouse.move(5, 5, { steps: 10 })
  await page.mouse.up()
  await expect(page.locator("[data-environment-graph]")).toHaveAttribute("data-connecting", "false")
  await expect(page.locator("[data-capability-line]")).toHaveCount(0)
  await expect(page.locator('[role="dialog"][aria-modal="true"]')).toHaveCount(0)
  await drag(page, dockPort(page, "internet"), port(page, "Running"))
  await assertLineAligned(page, "internet", "Running")
})

test("ports keep their size and wires follow movement, zoom, resize and card growth", async ({ page }) => {
  await openGraph(page)
  await drag(page, dockPort(page, "internet"), port(page))
  const dockBefore = await center(dockPort(page, "internet"))
  const grip = page.locator('[data-environment-id="Alpha"] [data-node-drag-grip]')
  const start = await center(grip)
  const nodeBefore = await center(port(page))
  await page.mouse.move(start.x, start.y)
  await page.mouse.down()
  await page.mouse.move(start.x + 60, start.y - 35, { steps: 10 })
  await page.mouse.up()
  const nodeAfter = await center(port(page))
  expect(nodeAfter.x - nodeBefore.x).toBeGreaterThan(50)
  expect(await center(dockPort(page, "internet"))).toEqual(dockBefore)
  await assertLineAligned(page, "internet")
  await page.getByRole("button", { name: "Zoom out", exact: true }).click({ clickCount: 3 })
  await assertLineAligned(page, "internet")
  expect((await port(page).boundingBox())!.width).toBeGreaterThanOrEqual(43)
  await page.getByRole("button", { name: "Fit environments", exact: true }).click()
  await assertLineAligned(page, "internet")
  await page.setViewportSize({ width: 390, height: 1100 })
  await page.getByRole("button", { name: "Fit environments", exact: true }).click()
  await assertLineAligned(page, "internet")
  const layout = await page.evaluate(() => {
    const points = [...document.querySelectorAll('section[aria-label="Environment capabilities"] [data-capability-connection-point]')].map(el => el.getBoundingClientRect())
    return { sameRow: points.every(point => Math.abs(point.top - points[0].top) < 1), overflow: document.documentElement.scrollWidth > innerWidth }
  })
  expect(layout).toEqual({ sameRow: true, overflow: false })
  expect((await port(page).boundingBox())!.width).toBeGreaterThanOrEqual(43)
})

test("touch drag connects through pointer capture", async ({ page, context }) => {
  await openGraph(page, [fixture("Alpha")])
  const session = await context.newCDPSession(page)
  await session.send("Emulation.setTouchEmulationEnabled", { enabled: true })
  const a = await center(dockPort(page, "internet")), b = await center(port(page))
  await session.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ x: a.x, y: a.y }] })
  for (let step = 1; step <= 10; step++) {
    await session.send("Input.dispatchTouchEvent", { type: "touchMove", touchPoints: [{ x: a.x + (b.x - a.x) * step / 10, y: a.y + (b.y - a.y) * step / 10 }] })
  }
  await expect(page.locator("[data-connection-preview]")).toBeAttached()
  await session.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] })
  await assertLineAligned(page, "internet")
  await session.detach()
})

test("panning keeps the dock fixed and hides wires to off-screen nodes", async ({ page }) => {
  await openGraph(page, [fixture("Alpha")])
  await drag(page, dockPort(page, "internet"), port(page))
  const dockBefore = await center(dockPort(page, "internet"))
  const canvas = (await page.locator("[data-environment-canvas]").boundingBox())!
  await page.mouse.move(canvas.x + 25, canvas.y + canvas.height - 40)
  await page.mouse.down()
  await page.mouse.move(canvas.x + 25, canvas.y + 20, { steps: 10 })
  await page.mouse.up()
  await expect(line(page, "internet")).toHaveCount(0)
  expect(await center(dockPort(page, "internet"))).toEqual(dockBefore)
  await page.getByRole("button", { name: "Fit environments", exact: true }).click()
  await assertLineAligned(page, "internet")
})

test("network handles stay anchored on hover and still open the connection form", async ({ page }) => {
  await openGraph(page)
  const source = page.locator('[data-environment-id="Alpha"] .react-flow__handle-right')
  const target = page.locator('[data-environment-id="Beta"] .react-flow__handle-left')
  for (const handle of [source, target]) {
    const before = await center(handle)
    await handle.hover()
    // An immediate assertion can pass before the hover transition has moved
    // the handle. Check its final position on both sides of the node.
    await handle.evaluate(element => Promise.all(element.getAnimations().map(animation => animation.finished)))
    await expect.poll(async () => {
      const after = await center(handle)
      return Math.hypot(after.x - before.x, after.y - before.y)
    }).toBeLessThan(0.5)
  }
  await source.hover()
  const end = await center(target)
  await page.mouse.down()
  await page.mouse.move(end.x, end.y, { steps: 15 })
  await page.mouse.up()
  await expect(page.getByRole("dialog", { name: "New connection" })).toBeVisible()
})

test("connection form is wide, compact and readable in both themes", async ({ page }) => {
  await openGraph(page)
  await connectNodes(page, "Alpha", "Beta")
  const dialog = await expandedConnectionDialog(page)
  await expect(dialog.getByRole("combobox", { name: "From", exact: true })).toContainText("Alpha")
  await expect(dialog.getByRole("combobox", { name: "To", exact: true })).toContainText("Beta")
  for (const dark of [false, true]) {
    await page.evaluate(dark => document.documentElement.classList.toggle("dark", dark), dark)
    const layout = await dialog.evaluate(element => {
      const box = element.getBoundingClientRect()
      const header = element.querySelector('[data-slot="dialog-header"]')!.getBoundingClientRect()
      const left = element.querySelector('.connection-permissions')!.getBoundingClientRect()
      const right = element.querySelector('.connection-details')!.getBoundingClientRect()
      const controls = [...element.querySelectorAll('.connection-direction')].map(el => el.getBoundingClientRect())
      return { width: box.width, height: box.height, header: header.height, sameRow: controls.every(control => Math.abs(control.top - controls[0].top) < 1), columns: right.left >= left.right - 1, fits: box.bottom <= innerHeight && box.left >= 0 }
    })
    expect(layout.width).toBeGreaterThanOrEqual(1000)
    expect(layout.height).toBeLessThanOrEqual(page.viewportSize()!.height - 32)
    expect(layout.header).toBeLessThanOrEqual(58)
    expect(layout.sameRow && layout.columns && layout.fits).toBe(true)
  }
  await expect(dialog.getByRole("checkbox")).toHaveCount(6)
  await expect(dialog.getByRole("checkbox", { name: "SSH / SFTP port", exact: true })).not.toBeChecked()
  await expect(dialog.getByRole("checkbox", { name: "Share data", exact: true })).toBeChecked()
})

test("connection form swaps endpoints and saves the selected rules", async ({ page }) => {
  await openGraph(page)
  await connectNodes(page, "Alpha", "Beta")
  const dialog = await expandedConnectionDialog(page)
  await portsOnly(dialog)
  await dialog.getByRole("button", { name: "Swap source and destination" }).click()
  await expect(dialog.getByRole("combobox", { name: "From", exact: true })).toContainText("Beta")
  await dialog.getByRole("combobox", { name: "To", exact: true }).click()
  await expect(page.getByRole("option", { name: "Beta", exact: true })).toBeDisabled()
  await page.keyboard.press("Escape")
  await dialog.getByText("Bidirectional", { exact: true }).click()
  await portsOnly(dialog)
  await dialog.getByRole("checkbox", { name: "Secrets", exact: true }).check()
  await dialog.getByPlaceholder("443, 5432, 6379").fill("3000, 5432")
  await expect(dialog.getByRole("group", { name: "Access summary" })).toContainText("restricted to your allowed TCP ports")
  await dialog.getByRole("button", { name: "Create connection", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).connections.find((connection: { sourceId: string }) => connection.sourceId === "Beta"))
  expect(saved).toMatchObject({ sourceId: "Beta", targetId: "Alpha", direction: "bidirectional", permissions: ["ports", "secrets"], ports: ["3000", "5432"] })
})

test("connection form validates empty, invalid and duplicate TCP ports before saving", async ({ page }) => {
  await openGraph(page)
  await connectNodes(page, "Alpha", "Beta")
  const dialog = await expandedConnectionDialog(page)
  await portsOnly(dialog)
  const submit = dialog.getByRole("button", { name: "Create connection", exact: true })
  await submit.click()
  await expect(dialog.getByRole("alert")).toContainText("Enter at least one TCP port")
  for (const value of ["65536", "0", "3000-3005", "1.5", "hello"]) {
    await dialog.getByPlaceholder("443, 5432, 6379").fill(value)
    await submit.click()
    await expect(dialog.getByRole("alert")).toContainText("between 1 and 65535")
  }
  await dialog.getByPlaceholder("443, 5432, 6379").fill("443, 0443")
  await submit.click()
  await expect(dialog.getByRole("alert")).toContainText("only be listed once")
  await dialog.getByRole("checkbox", { name: "Ports", exact: true }).uncheck()
  await submit.click()
  await expect(dialog.getByRole("alert")).toContainText("Choose at least one capability")
})

test("connection form never submits hidden port values", async ({ page }) => {
  await openGraph(page)
  await connectNodes(page, "Alpha", "Beta")
  const dialog = await expandedConnectionDialog(page)
  await portsOnly(dialog)
  await dialog.getByPlaceholder("443, 5432, 6379").fill("invalid old draft")
  await dialog.getByRole("checkbox", { name: "Secrets", exact: true }).check()
  await dialog.getByRole("checkbox", { name: "Network access", exact: true }).check()
  await expect(dialog.getByRole("group", { name: "Access summary" })).toContainText("TCP port list does not restrict")
  await dialog.getByRole("checkbox", { name: "Ports", exact: true }).uncheck()
  await dialog.getByRole("checkbox", { name: "Secrets", exact: true }).uncheck()
  await expect(dialog.getByRole("textbox")).toHaveCount(0)
  await dialog.getByRole("button", { name: "Create connection", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).connections.find((connection: { sourceId: string }) => connection.sourceId === "Alpha"))
  expect(saved.permissions).toEqual(["network"])
  expect(saved.ports).toEqual([])
  expect(saved.volume).toBeUndefined()
})

test("connection form blocks duplicate submission and preserves a failed draft for retry", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts", { platformApi } = await import(url)
    const original = platformApi.createConnection
    platformApi.createConnection = async () => {
      await new Promise(resolve => window.addEventListener("finish-connection-test", resolve, { once: true }))
      platformApi.createConnection = original
      throw new Error("Connection could not be saved. Please retry.")
    }
  })
  await connectNodes(page, "Alpha", "Beta")
  const dialog = await expandedConnectionDialog(page)
  await portsOnly(dialog)
  const ports = dialog.getByPlaceholder("443, 5432, 6379")
  await ports.fill("4200")
  const submit = dialog.getByRole("button", { name: "Create connection", exact: true })
  await submit.click()
  await expect(submit).toBeDisabled()
  await expect(ports).toBeDisabled()
  await expect(dialog.getByRole("button", { name: "Cancel", exact: true })).toBeDisabled()
  await expect(dialog.getByRole("button", { name: "Close", exact: true })).toBeDisabled()
  await page.keyboard.press("Escape")
  await expect(dialog).toBeVisible()
  await page.evaluate(() => window.dispatchEvent(new Event("finish-connection-test")))
  await expect(dialog.getByRole("alert")).toContainText("Please retry")
  await expect(ports).toHaveValue("4200")
  await expect(submit).toBeEnabled()
  await submit.click()
  await expect(dialog).not.toBeVisible()
})

test("connection form keeps drafts through telemetry and resets only when reopened", async ({ page }) => {
  await page.clock.install()
  const alpha = fixture("Alpha"); alpha.status = "running"
  await openGraph(page, [alpha, fixture("Beta")])
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts", { platformApi } = await import(url)
    const original = platformApi.refreshHostMetrics
    platformApi.refreshHostMetrics = async () => {
      const state = await original()
      document.documentElement.setAttribute("data-connection-poll", "done")
      return state
    }
  })
  await connectNodes(page, "Alpha", "Beta")
  const dialog = await expandedConnectionDialog(page)
  await portsOnly(dialog)
  await dialog.getByPlaceholder("443, 5432, 6379").fill("8080, 3000")
  await dialog.getByRole("radio", { name: "One-way", exact: true }).focus()
  await page.keyboard.press("ArrowRight")
  await dialog.getByRole("checkbox", { name: "Share data", exact: true }).check()
  await page.clock.fastForward(12_500)
  await expect(page.locator("html")).toHaveAttribute("data-connection-poll", "done")
  await expect(dialog.getByPlaceholder("443, 5432, 6379")).toHaveValue("8080, 3000")
  await expect(dialog.getByRole("checkbox", { name: "Share data", exact: true })).toBeChecked()
  await expect(dialog.locator('input[type="radio"][value="bidirectional"]')).toBeChecked()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await connectNodes(page, "Alpha", "Beta")
  await expect(dialog.getByRole("checkbox", { name: "Share data", exact: true })).toBeChecked()
  await portsOnly(dialog)
  await expect(dialog.getByPlaceholder("443, 5432, 6379")).toHaveValue("")
  await expect(dialog.getByRole("checkbox", { name: "Share data", exact: true })).not.toBeChecked()
})

test("connection form fits small windows, supports keyboard input and handles missing peers", async ({ page }) => {
  await openGraph(page)
  await connectNodes(page, "Alpha", "Beta")
  const dialog = await expandedConnectionDialog(page)
  await portsOnly(dialog)
  for (const viewport of [{ width: 900, height: 700 }, { width: 390, height: 650 }, { width: 320, height: 568 }]) {
    await page.setViewportSize(viewport)
    await expect.poll(() => dialog.evaluate(element => {
      const bounds = element.getBoundingClientRect()
      const footer = element.querySelector('[data-slot="dialog-footer"]')!.getBoundingClientRect()
      const overflow = [...element.querySelectorAll('[data-slot="scroll-area-viewport"]')].some(el => el.scrollWidth > el.clientWidth + 1)
      return bounds.left >= 0 && bounds.right <= innerWidth && bounds.bottom <= innerHeight && footer.bottom <= bounds.bottom && !overflow
    })).toBe(true)
    await expect(dialog.getByRole("button", { name: "Create connection", exact: true })).toBeInViewport()
  }
  const ports = dialog.getByPlaceholder("443, 5432, 6379")
  await ports.fill("3000")
  await ports.press("Enter")
  await expect(dialog).not.toBeVisible()
  await page.setViewportSize({ width: 1280, height: 1000 })
  await openGraph(page, [fixture("Alone"), fixture("Branch", "computerBranch")])
  await expect(page.getByRole("button", { name: "Connect Alone", exact: true })).toHaveCount(0)
  await expect(page.locator('[aria-label="Connect another environment to Branch"]')).toHaveCount(0)
  const from = await center(page.locator('[aria-label="Connect Alone to another environment"]'))
  const to = await center(page.locator('[data-environment-id="Branch"]'))
  await page.mouse.move(from.x, from.y)
  await page.mouse.down()
  await page.mouse.move(to.x, to.y, { steps: 15 })
  await page.mouse.up()
  await expect(dialog).not.toBeVisible()
})

test("workspace redesign keeps toolbar and metrics readable across desktop sizes", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(() => {
    const key = "yougori.platform.v1"
    const state = JSON.parse(localStorage.getItem(key)!)
    state.host.storageDrives = [
      { path: "C:\\", name: "System", fileSystem: "NTFS", totalGb: 100, freeGb: 10.7, readOnly: false, removable: false },
      { path: "D:\\", name: "Data", fileSystem: "NTFS", totalGb: 1000, freeGb: 655.5, readOnly: false, removable: false },
    ]
    localStorage.setItem(key, JSON.stringify(state))
  })
  await page.reload()
  await expect(page.getByRole("region", { name: "Host resources and storage" }).getByText("D:", { exact: true })).toBeVisible()
  for (const width of [480, 640, 800, 980, 1280, 1920]) {
    await page.setViewportSize({ width, height: width === 980 ? 680 : 900 })
    for (const dark of [false, true]) {
      await page.evaluate(dark => document.documentElement.classList.toggle("dark", dark), dark)
      const controls = page.locator('.dashboard-actions > button, .dashboard-actions > label')
      expect(await controls.evaluateAll(elements => elements.every(element => {
        const rect = element.getBoundingClientRect()
        return rect.left >= 0 && rect.right <= innerWidth && rect.height >= 30
          && element.scrollWidth <= element.clientWidth + 2
      }))).toBe(true)
      expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true)
      if (width >= 768) expect(await page.evaluate(() => document.documentElement.scrollHeight <= innerHeight)).toBe(true)
      const canvas = await page.locator("[data-environment-canvas]").boundingBox()
      expect(canvas!.height).toBeGreaterThan(120)
      const capabilities = await page.getByRole("region", { name: "Environment capabilities", exact: true }).boundingBox()
      if (width >= 768) expect(capabilities!.y + capabilities!.height).toBeLessThanOrEqual(page.viewportSize()!.height)
      const footer = page.locator(".workspace-graph-caption")
      expect(await footer.evaluate(element => {
        const bounds = element.getBoundingClientRect()
        const items = [...element.querySelectorAll('.workspace-footer-counts, .workspace-footer-metric, .workspace-footer-running, .workspace-footer-actions button')]
        const boxes = items.map(item => item.getBoundingClientRect()).filter(box => box.width && box.height)
        return boxes.every((box, index) => box.left >= bounds.left && box.right <= bounds.right && boxes.slice(index + 1).every(other =>
          box.right <= other.left || other.right <= box.left || box.bottom <= other.top || other.bottom <= box.top))
      })).toBe(true)
      if (width <= 1200) {
        const resources = (await page.locator('.workspace-footer-resources').boundingBox())!
        const actions = (await page.locator('.workspace-footer-actions').boundingBox())!
        expect(actions.y).toBeGreaterThanOrEqual(resources.y + resources.height)
      }
      await expect(page.getByRole("region", { name: "Host resources and storage" })).toBeVisible()
      await expect(page.getByRole("button", { name: "New environment", exact: true })).toBeVisible()
      expect(await page.locator(".workspace-node").first().evaluate(element => getComputedStyle(element).borderTopWidth)).toBe("3px")
    }
  }
})

test("connectors are reachable above both light and dark surfaces", async ({ page }) => {
  await openGraph(page)
  for (const dark of [false, true]) {
    await page.evaluate(dark => document.documentElement.classList.toggle("dark", dark), dark)
    const reachable = await page.locator("[data-environment-connection-point], [data-capability-connection-point]").evaluateAll(elements => elements.every(element => {
      const bounds = element.getBoundingClientRect()
      const hit = document.elementFromPoint(bounds.left + bounds.width / 2, bounds.top + bounds.height / 2)
      const dot = element.querySelector("span")!
      return bounds.width >= 43 && (hit === element || element.contains(hit)) && getComputedStyle(dot).backgroundColor !== "rgba(0, 0, 0, 0)"
    }))
    expect(reachable).toBe(true)
  }
})

test("newly created nodes stay visible and do not overlap existing cards", async ({ page }) => {
  await openGraph(page, [])
  for (const name of ["First", "Second"]) {
    await page.getByRole("button", { name: "New environment", exact: true }).click()
    await page.getByPlaceholder("Ubuntu Development").fill(name)
    await page.getByRole("dialog", { name: "New environment" }).getByRole("button", { name: "Create environment", exact: true }).click()
    await expect(page.getByRole("button", { name: `Connect capabilities to ${name}`, exact: true })).toBeVisible()
  }
  await expect.poll(() => page.evaluate(() => {
    const canvas = document.querySelector("[data-environment-canvas]")!.getBoundingClientRect()
    const cards = [...document.querySelectorAll("[data-environment-id]")].map(el => el.getBoundingClientRect())
    return cards.length === 2 && cards.every(card => card.top >= canvas.top && card.bottom < canvas.bottom && card.left >= canvas.left && card.right <= canvas.right)
      && (cards[0].bottom <= cards[1].top || cards[1].bottom <= cards[0].top || cards[0].right <= cards[1].left || cards[1].right <= cards[0].left)
  })).toBe(true)
  await drag(page, dockPort(page, "internet"), page.getByRole("button", { name: "Connect capabilities to Second", exact: true }))
  await expect(page.getByRole("button", { name: "Detach Internet access from Second", exact: true })).toBeVisible()
})

test("MicroVM creation saves one fixed allocation from sliders and editable values", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await dialog.getByText("MicroVM", { exact: true }).click()
  await dialog.getByPlaceholder("Ubuntu Development").fill("Micro memory")
  const memory = dialog.getByRole("slider", { name: "Memory allocation", exact: true })
  await expect(memory).toHaveValue("1")
  await expect(dialog.getByRole("slider")).toHaveCount(3)
  await memory.focus()
  await memory.press("ArrowRight")
  await expect(dialog.getByRole("spinbutton", { name: "Memory value", exact: true })).toHaveValue("1.125")
  await dialog.getByRole("spinbutton", { name: "Memory value", exact: true }).fill("1.5")
  await dialog.getByRole("spinbutton", { name: "CPU value", exact: true }).fill("2")
  await expect(memory).toHaveValue("1.5")
  await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
  await expect(page.getByRole("button", { name: "Configure Micro memory", exact: true })).toBeVisible()
  const policy = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0].resourcePolicy)
  expect(policy.memoryGb).toMatchObject({ min: 1.5, preferred: 1.5, max: 1.5 })
  expect(policy.cpu).toMatchObject({ min: 2, preferred: 2, max: 2 })
})

test("creation stays centered with margins, no visible header, and usable sliders on small screens", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(dialog.getByRole("region", { name: "Connections after creation", exact: true })).toHaveCount(0)
  await expect(dialog.getByText("All disconnected", { exact: true })).toHaveCount(0)
  for (const viewport of [{ width: 1600, height: 900 }, { width: 1024, height: 720 }, { width: 390, height: 700 }, { width: 360, height: 640 }, { width: 800, height: 400 }]) {
    await page.setViewportSize(viewport)
    await expect.poll(async () => dialog.evaluate(element => {
      const rect = element.getBoundingClientRect()
      return rect.width >= Math.min(1120, innerWidth - 32) - 1 && rect.left > 0 && rect.top > 0 && rect.right < innerWidth && rect.bottom < innerHeight
    })).toBe(true)
    await expect(dialog.locator('[data-slot="dialog-header"]')).toHaveCount(0)
    const types = dialog.getByRole("radiogroup", { name: "Environment type", exact: true })
    await expect(types.locator(".creation-type")).toHaveCount(7)
    for (const name of ["Container", "MicroVM", "VM"]) await expect(types.getByRole("radio", { name, exact: true })).toHaveCount(1)
    await expect(types.getByRole("radio", { name: "Cloud environment", exact: true })).toBeEnabled()
    expect(await types.evaluate(element => {
      const positions = Array.from(element.querySelectorAll(".creation-type")).map(item => {
        const rect = item.getBoundingClientRect()
        return rect.top + rect.height / 2
      })
      return Math.max(...positions) - Math.min(...positions) < 1
    })).toBe(true)
    await types.getByText("Shared environment", { exact: true }).scrollIntoViewIfNeeded()
    await expect(types.getByText("Shared environment", { exact: true })).toBeInViewport()
    await expect(dialog.getByRole("spinbutton")).toHaveCount(3)
    await expect(dialog.getByRole("slider")).toHaveCount(3)
    const slider = dialog.getByRole("slider", { name: "Memory allocation", exact: true })
    await slider.scrollIntoViewIfNeeded()
    const bounds = (await slider.boundingBox())!
    expect(bounds.width).toBeGreaterThan(80)
    await slider.click({ position: { x: bounds.width * 0.75, y: bounds.height / 2 } })
    expect(Number(await slider.inputValue())).toBeGreaterThan(0.25)
    await expect(dialog.getByRole("radiogroup", { name: "Resource priority", exact: true })).toHaveCount(0)
    const create = (await dialog.getByRole("button", { name: "Create environment", exact: true }).boundingBox())!
    expect(create.y + create.height).toBeLessThan(viewport.height)
    expect(create.x).toBeGreaterThanOrEqual(0)
    expect(await dialog.evaluate(element => Array.from(element.querySelectorAll('[data-slot="scroll-area-viewport"]')).every(viewport => viewport.scrollWidth <= viewport.clientWidth + 1))).toBe(true)
  }
})

test("fixed creation values validate host limits and reset when isolation changes", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  const memory = dialog.getByRole("spinbutton", { name: "Memory value", exact: true })
  for (const [kind, floor, value] of [["MicroVM", "1", "1"], ["VM", "1", "4"], ["Container", "0.5", "0.5"]] as const) {
    await dialog.getByText(kind, { exact: true }).click()
    await expect(memory).toHaveAttribute("min", floor)
    await expect(memory).toHaveAttribute("max", "16")
    await expect(memory).toHaveValue(value)
    await expect(dialog.getByRole("spinbutton", { name: "CPU value", exact: true })).toHaveAttribute("max", "8")
  }
  const create = dialog.getByRole("button", { name: "Create environment", exact: true })
  await memory.fill("17")
  await expect(create).toBeDisabled()
  await expect(dialog.getByRole("alert")).toContainText("between")
  await memory.fill("")
  await expect(create).toBeDisabled()
  await memory.fill("0.6")
  await expect(create).toBeDisabled()
  await expect(dialog.getByRole("alert")).toContainText("increments")
  await memory.fill("0.625")
  await expect(create).toBeEnabled()
  await expect(dialog.getByRole("slider", { name: "Memory allocation", exact: true })).toHaveValue("0.625")
  await dialog.getByText("VM", { exact: true }).click()
  await expect(memory).toHaveValue("4")
  await dialog.getByText("Container", { exact: true }).click()
  await expect(memory).toHaveValue("0.5")
})

for (const theme of ["light", "dark"]) {
  test(`creation workbench keeps readable controls and a live summary in ${theme} mode`, async ({ page }) => {
    await page.setViewportSize({ width: 1440, height: 900 })
    await openGraph(page, [])
    await page.evaluate(theme => document.documentElement.classList.toggle("dark", theme === "dark"), theme)
    await page.getByRole("button", { name: "New environment", exact: true }).click()
    const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
    const name = dialog.getByRole("textbox", { name: "Name", exact: true })
    await name.fill("Research workspace")
    const summary = dialog.getByLabel("Startup summary", { exact: true })
    await expect(summary).toContainText("Research workspace")
    const preferred = dialog.getByRole("slider", { name: "Memory allocation", exact: true })
    await preferred.focus()
    await preferred.press("ArrowRight")
    await expect(summary).toContainText("0.625 GB")
    expect((await name.boundingBox())!.height).toBeGreaterThanOrEqual(40)
    const configuration = (await dialog.getByRole("region", { name: "Environment configuration", exact: true }).boundingBox())!
    const resources = (await dialog.getByRole("region", { name: "Resource allocation", exact: true }).boundingBox())!
    expect(resources.x).toBeGreaterThanOrEqual(configuration.x + configuration.width - 1)
    expect((await preferred.boundingBox())!.width).toBeGreaterThan(resources.width * 0.75)
    const contrast = await dialog.locator(".creation-resource-note").first().evaluate(element => {
      const foreground = getComputedStyle(element).color
      const background = getComputedStyle(element.closest(".creation-resources")!).backgroundColor
      const luminance = (color: string) => {
        const [r, g, b] = color.match(/[\d.]+/g)!.slice(0, 3).map(value => {
          const channel = Number(value) / 255
          return channel <= 0.04045 ? channel / 12.92 : ((channel + 0.055) / 1.055) ** 2.4
        })
        return r! * 0.2126 + g! * 0.7152 + b! * 0.0722
      }
      const a = luminance(foreground), b = luminance(background)
      return (Math.max(a, b) + 0.05) / (Math.min(a, b) + 0.05)
    })
    expect(contrast).toBeGreaterThanOrEqual(4.5)
    await name.fill("A very long environment name ".repeat(2))
    await expect(dialog.getByRole("button", { name: "Create environment", exact: true })).toBeInViewport()
    expect(await dialog.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
  })
}

test("an early creation failure leaves the popup closed and preserves the next draft", async ({ page }) => {
  await openGraph(page, [])
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts"
    const { platformApi } = await import(url)
    const original = platformApi.createEnvironment
    platformApi.createEnvironment = async () => {
      try {
        await new Promise((_, reject) => window.addEventListener("fail-create", () => reject(new Error("Unable to prepare this image")), { once: true }))
      } finally { platformApi.createEnvironment = original }
    }
  })
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("Retry workspace")
  await dialog.getByRole("button", { name: "SaaS", exact: true }).click()
  await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
  await expect(dialog).toHaveCount(0)
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  await expect(dialog).toBeVisible()
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("Keep my next draft")
  await page.evaluate(() => window.dispatchEvent(new Event("fail-create")))
  await expect(page.locator('[data-slot="toast-description"]').filter({ hasText: "Unable to prepare this image" })).toBeVisible()
  await expect(dialog.getByRole("alert")).toHaveCount(0)
  await expect(dialog.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("Keep my next draft")
  await expect(dialog.getByRole("slider", { name: "Memory allocation", exact: true })).toBeEnabled()
  await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  await expect(page.getByRole("button", { name: "Connect capabilities to Keep my next draft", exact: true })).toBeVisible()
})

for (const category of ["Container", "GPU", "MicroVM", "VM"]) for (const fails of [false, true]) {
  test(`${category} creation leaves the popup and keeps its node through ${fails ? "failure" : "completion"}`, async ({ page }) => {
    await openGraph(page, [])
    await page.evaluate(async fails => {
      localStorage.setItem("yougori.cuda.fixture", JSON.stringify({ supported: true, installed: true, running: false, detail: "Browser creation fixture" }))
      const url = "/src/api/platform-api.ts", { platformApi } = await import(url)
      const original = platformApi.createEnvironment
      platformApi.createEnvironment = async (request: Parameters<typeof original>[0]) => {
        const pending = await original(request)
        const environment = pending.environments.find((item: Environment) => item.name === request.name)!
        environment.status = "provisioning"
        localStorage.setItem("yougori.platform.v1", JSON.stringify(pending))
        await new Promise(resolve => window.addEventListener("finish-environment-creation", resolve, { once: true }))
        platformApi.createEnvironment = original
        const finished = JSON.parse(localStorage.getItem("yougori.platform.v1")!) as PlatformState
        const node = finished.environments.find(item => item.id === environment.id)!
        node.status = fails ? "error" : "stopped"
        if (fails) node.lastError = "Environment creation failed: Disk is full. Delete this node and create the environment again."
        localStorage.setItem("yougori.platform.v1", JSON.stringify(finished))
        if (fails) throw new Error(node.lastError)
        return finished
      }
    }, fails)
    await page.getByRole("button", { name: "New environment", exact: true }).click()
    const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
    if (category === "GPU") await dialog.getByRole("switch", { name: "GPU access", exact: true }).check()
    else await dialog.getByText(category, { exact: true }).click()
    await expect(dialog.getByText("Full OS", { exact: true })).toHaveCount(0)
    await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("Background VM")
    if (category === "VM") await dialog.getByRole("textbox", { name: "Installer ISO or virtual disk", exact: true }).fill("C:\\test\\installer.iso")
    await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
    await expect(dialog).toHaveCount(0)
    const node = page.locator("[data-environment-id]").filter({ hasText: "Background VM" })
    await expect(node).toBeVisible()
    const id = await node.getAttribute("data-environment-id")
    await expect(node).toHaveAttribute("aria-busy", "true")
    await expect(node.getByRole("button", { name: "Creating…", exact: true })).toBeDisabled()
    await expect(node.getByRole("button", { name: "Creating…", exact: true }).locator(".animate-spin")).toBeVisible()
    await expect(node.locator(".node-launch")).toBeDisabled()
    // Inspecting the pending node must not trap the user in another popup.
    await node.getByRole("button", { name: "Configure Background VM", exact: true }).click()
    const sheet = page.getByRole("dialog", { name: "Background VM", exact: true })
    await expect(sheet).toBeVisible({ timeout: 30_000 })
    await expect(sheet.getByRole("button", { name: "Open", exact: true })).toBeDisabled()
    await sheet.getByRole("button", { name: "Close", exact: true }).click()
    // Completing the old request must not close or clear a newly opened form.
    await page.getByRole("button", { name: "New environment", exact: true }).click()
    await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("Keep my next draft")
    await page.evaluate(() => window.dispatchEvent(new Event("finish-environment-creation")))
    await expect(node).toHaveAttribute("aria-busy", "false")
    await expect(node).toHaveAttribute("data-environment-id", id!)
    await expect(dialog.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("Keep my next draft")
    await expect(dialog.getByRole("alert")).toHaveCount(0)
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
    await expect(node.getByRole("button", { name: "Start", exact: true })).toBeEnabled()
    if (fails) {
      await expect(node).toContainText("Needs attention")
      await expect(node).not.toContainText("Disk is full")
      await node.getByRole("button", { name: "Configure Background VM", exact: true }).click()
      await expect(sheet.getByLabel("Environment needs attention")).toContainText("Disk is full")
      await expect(sheet.getByRole("button", { name: "Retry Start", exact: true })).toBeEnabled()
    } else {
      await expect(node).toContainText("Stopped")
    }
    expect(await page.locator("[data-environment-id]").count()).toBe(1)
  })
}

test("resource drafts survive telemetry, show save failures and preserve MicroVM boot RAM", async ({ page }) => {
  await page.clock.install()
  const env = fixture("Micro", "microVm")
  env.status = "running"
  env.resourcePolicy.cpu = { min: 1, preferred: 1, max: 2, current: 1 }
  env.resourcePolicy.memoryGb.current = 0.25
  env.resourcePolicy.dynamic = true
  await openGraph(page, [env])
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts"
    const { platformApi } = await import(url)
    const refresh = platformApi.refreshHostMetrics
    platformApi.refreshHostMetrics = async () => {
      const state = await refresh()
      document.documentElement.setAttribute("data-resource-poll", "done")
      return state
    }
    const save = platformApi.updateResourcePolicy
    platformApi.updateResourcePolicy = async () => {
      platformApi.updateResourcePolicy = save
      throw new Error("Resource save test failure")
    }
  })
  await page.getByRole("button", { name: "Configure Micro", exact: true }).click()
  const preferred = page.getByRole("spinbutton", { name: "Memory value", exact: true })
  await preferred.fill("0.375")
  await page.clock.fastForward(12_500)
  await expect(page.locator("html")).toHaveAttribute("data-resource-poll", "done")
  await expect(preferred).toHaveValue("0.375")
  await expect(page.getByText("Restart required for memory:", { exact: false })).toContainText("running with 0.25 GB; next boot uses 0.375 GB")
  await page.getByRole("button", { name: "Save changes", exact: true }).click()
  await expect(page.getByRole("alert").filter({ hasText: "Resource save test failure" }).first()).toBeVisible()
  await expect(preferred).toHaveValue("0.375")
  await page.getByRole("button", { name: "Save changes", exact: true }).click()
  await expect(page.getByText("Changes saved.", { exact: true })).toBeVisible()
  const policy = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0].resourcePolicy)
  expect(policy.memoryGb.preferred).toBe(0.375)
  expect(policy.memoryGb.current).toBe(0.25)
  expect(policy.dynamic).toBe(true)
})

test("MongoDB uses its service entrypoint while Linux keeps a terminal alive", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  const command = dialog.getByRole("textbox", { name: "Startup command (optional)", exact: true })
  await expect(command).toHaveValue("sleep 2147483647")
  await dialog.getByRole("combobox", { name: "OCI image", exact: true }).click()
  await page.getByRole("combobox", { name: "Search OCI images", exact: true }).fill("MongoDB")
  await page.locator('[data-slot="combobox-popup"]').getByRole("option").filter({ hasText: "MongoDB" }).click()
  await expect(command).toHaveValue("")
  await dialog.getByPlaceholder("Ubuntu Development").fill("Mongo test")
  await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
  await expect(page.getByRole("button", { name: "Connect capabilities to Mongo test", exact: true })).toBeVisible()
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])
  expect(saved.containerCommand).toBe("")
  expect(saved.resourcePolicy.memoryGb.preferred).toBe(0.5)
})

test("container purpose shortcuts select base images and preserve the rest of the draft", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  const purposes = dialog.getByRole("group", { name: "What are you building?", exact: true })
  const image = dialog.getByRole("combobox", { name: "OCI image", exact: true })
  const command = dialog.getByRole("textbox", { name: "Startup command (optional)", exact: true })
  await expect(dialog.getByText("Quick start", { exact: true })).toHaveCount(0)
  await expect(purposes.getByRole("button")).toHaveCount(6)
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("My project")
  await dialog.getByRole("textbox", { name: "Description optional", exact: true }).fill("Keep my notes")
  for (const [purpose, reference, startup] of [
    ["Website", "node:alpine", "sleep 2147483647"],
    ["SaaS", "node:slim", "sleep 2147483647"],
    ["Database", "mongo:latest", ""],
    ["API", "python:slim", "sleep 2147483647"],
    ["Static site", "nginx:alpine", ""],
    ["Automation", "python:alpine", "sleep 2147483647"],
  ]) {
    await purposes.getByRole("button", { name: purpose, exact: true }).click()
    await expect(image).toContainText(`docker.io/library/${reference}`)
    await expect(command).toHaveValue(startup)
    await expect(purposes.locator('[aria-pressed="true"]')).toHaveText(purpose)
    await expect(dialog.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("My project")
    await expect(dialog.getByRole("textbox", { name: "Description optional", exact: true })).toHaveValue("Keep my notes")
  }
  await purposes.getByRole("button", { name: "Database", exact: true }).click()
  await dialog.getByText("MicroVM", { exact: true }).click()
  await expect(purposes).toHaveCount(0)
  await dialog.getByText("Container", { exact: true }).click()
  await expect(image).toContainText("docker.io/library/alpine:3.24")
  await expect(command).toHaveValue("sleep 2147483647")
  await expect(purposes.locator('[aria-pressed="true"]')).toHaveCount(0)
  await purposes.getByRole("button", { name: "SaaS", exact: true }).click()
  await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])
  expect(saved.runtime).toBe("docker.io/library/node:slim")
  expect(saved.containerCommand).toBe("sleep 2147483647")
  expect(saved.description).toBe("Keep my notes")
  expect(saved.networkAccess).toBe(true)
  expect(saved.gpuAccess).toBe(false)
  expect(saved.resourcePolicy.dynamic).toBe(true)
})

test("OCI image search opens focused, filters by purpose and registry, and supports keyboard selection", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  const trigger = dialog.getByRole("combobox", { name: "OCI image", exact: true })
  const search = page.getByRole("combobox", { name: "Search OCI images", exact: true })
  await dialog.getByRole("button", { name: "Website", exact: true }).click()
  await trigger.click()
  await expect(search).toBeFocused()
  await expect(search).toHaveValue("")
  await expect(page.locator('[data-slot="combobox-group-label"]')).toHaveText([
    "Operating systems", "Languages", "Web servers", "Data services", "Developer tools",
  ])
  const nameBounds = await dialog.locator(".creation-name").boundingBox()
  const triggerBounds = await trigger.boundingBox()
  const popupBounds = await page.locator(".creation-image-popup").boundingBox()
  expect(nameBounds).not.toBeNull()
  expect(triggerBounds).not.toBeNull()
  expect(popupBounds).not.toBeNull()
  expect(Math.abs(triggerBounds!.width - nameBounds!.width)).toBeLessThanOrEqual(2)
  expect(Math.abs(popupBounds!.width - nameBounds!.width)).toBeLessThanOrEqual(2)
  await expect(page.getByRole("group", { name: "Operating systems", exact: true }).getByRole("option")).toHaveCount(19)
  await expect(page.getByRole("group", { name: "Languages", exact: true }).getByRole("option")).toHaveCount(19)
  await search.fill("  NoDe  docker hub  ")
  await expect(page.locator('[data-slot="combobox-popup"]').getByRole("option")).toHaveCount(2)
  await expect(page.locator('[data-slot="combobox-group-label"]')).toHaveText(["Languages"])
  await search.fill("next.js")
  await expect(page.locator('[data-slot="combobox-popup"]').getByRole("option")).toHaveCount(1)
  await expect(page.locator('[data-slot="combobox-popup"]').getByRole("option")).toContainText("Node.js Slim")
  await search.press("Escape")
  await expect(search).not.toBeVisible()
  await expect(dialog).toBeVisible()
  await expect(trigger).toBeFocused()
  await expect(trigger).toContainText("node:alpine")
  await expect(dialog.getByRole("button", { name: "Website", exact: true })).toHaveAttribute("aria-pressed", "true")
  await trigger.press("ArrowDown")
  await expect(search).toHaveValue("")
  await expect(page.locator('[data-slot="combobox-popup"]').getByRole("option").filter({ hasText: "Custom image" })).toHaveCount(1)
  await search.fill("postgres")
  await expect(page.locator('[data-slot="combobox-popup"]').getByRole("option")).toHaveCount(1)
  await search.press("ArrowDown")
  await search.press("Enter")
  await expect(search).not.toBeVisible()
  await expect(trigger).toContainText("postgres:latest")
  await expect(dialog.locator('.creation-purpose[aria-pressed="true"]')).toHaveCount(0)
  await expect(dialog.getByRole("textbox", { name: "Startup command (optional)", exact: true })).toHaveValue("")
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments)).toHaveLength(0)
})

test("OCI image search has a usable no-results custom reference path", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  const trigger = dialog.getByRole("combobox", { name: "OCI image", exact: true })
  await trigger.click()
  await page.getByRole("combobox", { name: "Search OCI images", exact: true }).fill("nonexistent-test-image-xyz")
  await expect(page.locator('[data-slot="combobox-popup"]').getByRole("option")).toHaveCount(0)
  await expect(page.getByText(/No matching images in the catalog/)).toBeVisible()
  await page.getByRole("button", { name: "Use custom image", exact: true }).click()
  const custom = dialog.getByRole("textbox", { name: "Custom OCI image reference", exact: true })
  await expect(custom).toBeVisible()
  await expect(custom).toHaveValue("")
  await expect(trigger).toContainText("Custom image")
  const reference = "registry.example.test/team/my-app:v1.2.3"
  await custom.fill(reference)
  await trigger.click()
  await expect(page.getByRole("combobox", { name: "Search OCI images", exact: true })).toHaveValue("")
  await page.keyboard.press("Escape")
  await expect(custom).toHaveValue(reference)
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("Custom project")
  await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])
  expect(saved.runtime).toBe(reference)
  expect(saved.containerCommand).toBe("")
})

test("OCI image picker stays inside the viewport with readable results in both themes", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  for (const dark of [false, true]) {
    await page.evaluate(dark => document.documentElement.classList.toggle("dark", dark), dark)
    for (const viewport of [{ width: 1440, height: 900 }, { width: 900, height: 650 }, { width: 390, height: 650 }, { width: 320, height: 568 }]) {
      await page.setViewportSize(viewport)
      await dialog.getByRole("combobox", { name: "OCI image", exact: true }).click()
      const search = page.getByRole("combobox", { name: "Search OCI images", exact: true })
      await expect(search).toBeFocused()
      const popup = page.locator(".creation-image-popup")
      const box = (await popup.boundingBox())!
      expect(box.x).toBeGreaterThanOrEqual(0)
      expect(box.y).toBeGreaterThanOrEqual(0)
      expect(box.x + box.width).toBeLessThanOrEqual(viewport.width)
      expect(box.y + box.height).toBeLessThanOrEqual(viewport.height)
      await expect(search).toBeInViewport()
      await expect(page.getByRole("button", { name: "Use custom image", exact: true })).toBeInViewport()
      expect(await popup.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
      await search.fill("mcr.microsoft.com")
      await expect(page.locator('[data-slot="combobox-popup"]').getByRole("option")).toHaveCount(4)
      expect(await popup.evaluate(element => [...element.querySelectorAll('[data-slot="scroll-area-viewport"]')].every(viewport => viewport.scrollWidth <= viewport.clientWidth + 1))).toBe(true)
      await search.press("Escape")
      const purposes = dialog.getByRole("group", { name: "What are you building?", exact: true })
      expect(await purposes.evaluate(element => element.scrollWidth <= element.clientWidth + 1)).toBe(true)
    }
  }
})

test("failed saves clear the busy state and allow a retry without a phantom wire", async ({ page }) => {
  await openGraph(page, [fixture("Alpha")])
  const statsBeforeError = (await page.getByRole("region", { name: "Host resources and storage" }).boundingBox())!
  const graphBeforeError = (await page.locator("[data-environment-graph]").boundingBox())!
  await page.evaluate(async () => {
    const url = "/src/api/platform-api.ts"
    const { platformApi } = await import(url)
    const original = platformApi.updateContainerNetwork
    platformApi.updateContainerNetwork = async () => {
      try {
        await new Promise((_, reject) => window.addEventListener("fail-graph-save", () => reject(new Error("Test save failed")), { once: true }))
      } finally { platformApi.updateContainerNetwork = original }
    }
  })
  await drag(page, dockPort(page, "internet"), port(page))
  await expect(port(page)).toBeDisabled()
  await expect(page.locator('[data-environment-id="Alpha"]')).toHaveAttribute("aria-busy", "true")
  await expect(line(page, "internet")).toHaveCount(0)
  await page.evaluate(() => window.dispatchEvent(new Event("fail-graph-save")))
  const error = page.getByRole("alert").filter({ hasText: "Test save failed" })
  await expect(error).toBeVisible()
  await expect(page.locator("[data-environment-graph]").getByRole("alert")).toHaveCount(0)
  const errorBox = (await error.boundingBox())!
  const statsBox = (await page.getByRole("region", { name: "Host resources and storage" }).boundingBox())!
  expect(errorBox.y + errorBox.height).toBeLessThan(statsBox.y)
  expect(errorBox.y).toBeGreaterThanOrEqual(0)
  expect(errorBox.y + errorBox.height).toBeLessThanOrEqual(page.viewportSize()!.height)
  expect(statsBox).toEqual(statsBeforeError)
  expect(await page.locator("[data-environment-graph]").boundingBox()).toEqual(graphBeforeError)
  await error.getByRole("button", { name: "Dismiss graph error" }).click()
  await expect(error).toHaveCount(0)
  await expect(port(page)).toBeEnabled()
  await expect(line(page, "internet")).toHaveCount(0)
  await drag(page, dockPort(page, "internet"), port(page))
  await assertLineAligned(page, "internet")
})

test("an overlapping node receives the drop on the card that is actually on top", async ({ page }) => {
  await openGraph(page)
  const a = await center(page.locator('[data-environment-id="Alpha"] [data-node-drag-grip]'))
  const b = await center(page.locator('[data-environment-id="Beta"] [data-node-drag-grip]'))
  await page.mouse.move(b.x, b.y)
  await page.mouse.down()
  await page.mouse.move(a.x, a.y, { steps: 12 })
  await page.mouse.up()
  await drag(page, dockPort(page, "internet"), port(page, "Beta"))
  await assertLineAligned(page, "internet", "Beta")
  await expect(line(page, "internet", "Alpha")).toHaveCount(0)
})

test("MicroVM apps install on demand, open separate windows, reopen and stop", async ({ page }) => {
  const env = fixture("env-app-launcher", "microVm")
  env.status = "running"
  env.resourcePolicy.memoryGb = { min: 0.5, preferred: 2, max: 2, current: 2 }
  await openGraph(page, [env])
  await page.evaluate(async () => {
    const url = "/src/api/guest-apps-api.ts"
    const { guestAppsApi } = await import(url)
    guestAppsApi.openWindow = async (environmentId: string, sessionId: string) => {
      document.documentElement.setAttribute("data-open-app", `${environmentId}:${sessionId}`)
      return true
    }
    const original = guestAppsApi.install
    guestAppsApi.install = async () => { guestAppsApi.install = original; throw new Error("Test package download failed") }
  })
  await page.getByRole("button", { name: "Configure env-app-launcher", exact: true }).click()
  await page.getByRole("button", { name: "Apps", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Apps · env-app-launcher", exact: true })
  await dialog.getByRole("button", { name: "Graphical terminal", exact: true }).click()
  const launch = dialog.getByRole("button", { name: "Launch in new window", exact: true })
  await expect(launch).toBeDisabled()
  await dialog.getByRole("button", { name: "Install app support", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("Test package download failed")
  await dialog.getByRole("button", { name: "Install app support", exact: true }).click()
  await expect(launch).toBeEnabled()
  await launch.click()
  await expect(page.locator("html")).toHaveAttribute("data-open-app", /^env-app-launcher:app-/)
  await expect(dialog.getByRole("region", { name: "App sessions", exact: true })).toContainText("Graphical terminal")
  await page.evaluate(() => document.documentElement.removeAttribute("data-open-app"))
  await dialog.getByRole("button", { name: "Open Graphical terminal window", exact: true }).click()
  await expect(page.locator("html")).toHaveAttribute("data-open-app", /^env-app-launcher:app-/)
  await dialog.getByRole("button", { name: "Stop Graphical terminal", exact: true }).click()
  await expect(dialog.getByRole("region", { name: "App sessions", exact: true })).toHaveCount(0)
})

test("MicroVM app launcher requires adequate running memory and keeps Linux limitations visible", async ({ page }) => {
  const env = fixture("env-low-memory", "microVm")
  env.status = "running"
  env.resourcePolicy.memoryGb.current = 0.25
  await openGraph(page, [env])
  await page.getByRole("button", { name: "Configure env-low-memory", exact: true }).click()
  await page.getByRole("button", { name: "Apps", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Apps · env-low-memory", exact: true })
  await expect(dialog).toContainText("running with 0.25 GB")
  await expect(dialog).toContainText("Windows .exe files and incompatible Linux builds will not work")
  await expect(dialog.getByRole("button", { name: "Launch in new window", exact: true })).toBeDisabled()
  await expect(dialog).not.toContainText("MiB")
})

test("removed PC Apps entry is not offered in the toolbar", async ({ page }) => {
  await openGraph(page, [])
  await expect(page.getByRole("banner").getByRole("button", { name: "Apps from your PC", exact: true })).toHaveCount(0)
  await expect(page.getByRole("button", { name: "New environment", exact: true })).toBeVisible()
})

test("Cloudflare quick links can still be chosen when saved credentials are unavailable", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await seedServices(page); await openGraph(page, [env])
  await page.evaluate(async () => {
    const url = "/src/api/workspace-api.ts", { workspaceApi } = await import(url)
    workspaceApi.savedCloudflare = async () => { throw new Error("Vault unavailable") }
    const original = workspaceApi.publish
    workspaceApi.publish = (...args: Parameters<typeof original>) => {
      if (args[4] !== undefined) throw new Error("Quick link received account credentials")
      return original(...args)
    }
  })
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await expect(dialog.getByRole("radio", { name: "Quick link — no account", exact: true })).toBeChecked()
  await expect(dialog.getByLabel("Tunnel token", { exact: true })).toHaveCount(0)
  await expect(dialog.getByRole("alert")).toHaveCount(0)
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "https://test-tunnel.example.test", exact: true })).toBeVisible()
})

test("port settings offer matching saved Cloudflare domains and show other ports", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  const matching = "00000000-0000-4000-8000-000000000101"
  const other = "00000000-0000-4000-8000-000000000102"
  await page.addInitScript(({ matching, other }) => localStorage.setItem("yougori.public-access-presets.v1", JSON.stringify([
    { id: matching, credentialEnvironmentId: "public-presets", port: 4200, hostname: "app.example.com", hostPort: 45000 },
    { id: other, credentialEnvironmentId: "public-presets", port: 8080, hostname: "other.example.com", hostPort: 45001 },
  ])), { matching, other })
  await seedServices(page); await openGraph(page, [env])
  await page.evaluate(async matching => {
    const url = "/src/api/workspace-api.ts", { workspaceApi } = await import(url)
    await workspaceApi.saveCloudflarePreset("public-presets", 4200, matching, "app.example.com", 45000, "test-only-token")
  }, matching)
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await expect(dialog.getByRole("radio", { name: "Use app.example.com for app port 4200" })).toBeVisible()
  await expect(dialog.getByRole("radio", { name: "Use other.example.com for app port 8080" })).toBeDisabled()
  await dialog.getByRole("radio", { name: "Use app.example.com for app port 4200" }).check()
  await expect(dialog.getByLabel("Tunnel token", { exact: true })).toHaveCount(0)
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "https://app.example.com", exact: true })).toBeVisible()
})

test("remembering a tunnel adds a reusable saved setup without storing its token in browser storage", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await seedServices(page); await openGraph(page, [env])
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await dialog.getByRole("radio", { name: "Use my Cloudflare account (optional)", exact: true }).check()
  await dialog.getByLabel("Public hostname", { exact: true }).fill("saved.example.com")
  await dialog.getByLabel("Local tunnel port", { exact: true }).fill("45000")
  await dialog.getByLabel("Tunnel token", { exact: true }).fill("test-only-remembered-token")
  await dialog.getByRole("checkbox", { name: "I reviewed this dedicated tunnel’s routes", exact: true }).check()
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "https://saved.example.com", exact: true })).toBeVisible()
  await expect(page.locator('[data-preset-card]')).toHaveCount(1)
  await expect(dialog.getByRole("radio", { name: "Use saved.example.com for app port 4200" })).toBeVisible()
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain("test-only-remembered-token")
  await dialog.getByRole("button", { name: "Disconnect cloudflare from port 4200", exact: true }).click()
  await dialog.getByRole("radio", { name: "Use saved.example.com for app port 4200" }).check()
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "https://saved.example.com", exact: true })).toBeVisible()
})

test("an account tunnel used without Remember does not create a saved setup", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await seedServices(page); await openGraph(page, [env])
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await dialog.getByRole("radio", { name: "Use my Cloudflare account (optional)", exact: true }).check()
  await dialog.getByLabel("Public hostname", { exact: true }).fill("one-time.example.com")
  await dialog.getByLabel("Local tunnel port", { exact: true }).fill("45000")
  await dialog.getByLabel("Tunnel token", { exact: true }).fill("test-only-one-time-token")
  await dialog.getByRole("checkbox", { name: "Remember for this node and port", exact: true }).uncheck()
  await dialog.getByRole("checkbox", { name: "I reviewed this dedicated tunnel’s routes", exact: true }).check()
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "https://one-time.example.com", exact: true })).toBeVisible()
  await expect(page.locator('[data-preset-card]')).toHaveCount(0)
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain("test-only-one-time-token")
})

test("Cloudflare account tokens stay masked, authenticate optionally, and can be forgotten", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await seedServices(page); await openGraph(page, [env])
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await dialog.getByRole("radio", { name: "Use my Cloudflare account (optional)", exact: true }).check()
  await expect(dialog).toContainText("free and paid Cloudflare accounts")
  await expect(dialog).toContainText("Account authentication does not make visitors log in")
  const token = dialog.getByLabel("Tunnel token", { exact: true })
  await expect(token).toHaveAttribute("type", "password")
  await expect(dialog.getByRole("checkbox", { name: "Remember for this node and port", exact: true })).toBeChecked()
  await dialog.getByLabel("Public hostname", { exact: true }).fill("app.example.com")
  await dialog.getByLabel("Local tunnel port", { exact: true }).fill("45000")
  await expect(dialog.getByLabel("Cloudflare service URL", { exact: true })).toHaveText("http://127.0.0.1:45000")
  await token.fill("fake-test-only-token")
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("Review the dedicated tunnel")
  await expect(dialog.getByRole("button", { name: "Disconnect cloudflare from port 4200", exact: true })).toHaveCount(0)
  await dialog.getByRole("checkbox", { name: "I reviewed this dedicated tunnel’s routes", exact: true }).check()
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "https://app.example.com", exact: true })).toBeVisible()
  await expect(token).toHaveValue("")
  await expect(dialog.getByRole("button", { name: "Forget token for this node", exact: true })).toBeVisible()
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain("fake-test-only-token")
  await dialog.getByRole("button", { name: "Disconnect cloudflare from port 4200", exact: true }).click()
  await dialog.getByRole("button", { name: "Done", exact: true }).click()
  // Reconnecting the same node/port uses the vault without opening setup.
  await drag(page, page.locator('[data-service-connection-point="Alpha:4200"]'), page.locator('[data-publication-connection-point="public"]'))
  await expect(page.locator('[data-service-card="Alpha:4200"]')).toContainText("CF")
  await expect(dialog).toHaveCount(0)
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await expect(dialog.getByRole("radio", { name: "Use my Cloudflare account (optional)", exact: true })).toBeChecked()
  await expect(dialog.getByLabel("Public hostname", { exact: true })).toHaveValue("app.example.com")
  await expect(dialog.getByLabel("Local tunnel port", { exact: true })).toHaveValue("45000")
  await expect(token).toHaveValue("")
  await expect(dialog.getByRole("checkbox", { name: "I reviewed this dedicated tunnel’s routes", exact: true })).toBeChecked()
  await expect(dialog.getByRole("button", { name: "https://app.example.com", exact: true })).toBeVisible()
  await dialog.getByRole("button", { name: "Forget token for this node", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "Forget token for this node", exact: true })).toHaveCount(0)
  await expect(dialog.getByRole("button", { name: "Disconnect cloudflare from port 4200", exact: true })).toBeVisible()
  await dialog.getByRole("button", { name: "Disconnect cloudflare from port 4200", exact: true }).click()
  await dialog.getByRole("button", { name: "Done", exact: true }).click()
  await drag(page, page.locator('[data-service-connection-point="Alpha:4200"]'), page.locator('[data-publication-connection-point="public"]'))
  await expect(dialog).toHaveCount(0)
  await expect(page.locator('[data-service-card="Alpha:4200"]')).toContainText("CF")
})

test("remembered Cloudflare reconnect errors reopen account settings", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await seedServices(page); await openGraph(page, [env])
  await page.evaluate(async () => {
    const url = "/src/api/workspace-api.ts", { workspaceApi } = await import(url)
    const publication = await workspaceApi.publish("Alpha", 4200, "cloudflare", 45000, { hostname: "app.example.com", token: "fake-test-only-token", remember: true, routesReviewed: true })
    await workspaceApi.unpublish(publication.id)
    workspaceApi.publish = async () => { throw new Error("Saved tunnel token has expired") }
  })
  await drag(page, page.locator('[data-service-connection-point="Alpha:4200"]'), page.locator('[data-publication-connection-point="public"]'))
  const dialog = page.getByRole("dialog")
  await expect(dialog.getByRole("alert")).toContainText("Saved tunnel token has expired")
  await expect(dialog.getByRole("radio", { name: "Use my Cloudflare account (optional)", exact: true })).toBeChecked()
  await expect(dialog.getByLabel("Public hostname", { exact: true })).toHaveValue("app.example.com")
  await expect(dialog.getByLabel("Tunnel token", { exact: true })).toHaveValue("")
  await expect(page.locator('[data-service-card="Alpha:4200"]')).not.toContainText("CF")
})

test("Cloudflare account failure allows retry without an anonymous fallback or exposing the token", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await seedServices(page); await openGraph(page, [env])
  await page.evaluate(async () => {
    const url = "/src/api/workspace-api.ts", { workspaceApi } = await import(url)
    const original = workspaceApi.publish
    workspaceApi.publish = async () => { workspaceApi.publish = original; throw new Error("Cloudflare rejected authentication. Check the token.") }
  })
  await page.getByRole("button", { name: "Port 4200 in Alpha", exact: true }).click()
  const dialog = page.getByRole("dialog")
  await dialog.getByRole("radio", { name: "Public access / Cloudflare Tunnel", exact: true }).check()
  await dialog.getByRole("radio", { name: "Use my Cloudflare account (optional)", exact: true }).check()
  await dialog.getByLabel("Public hostname", { exact: true }).fill("app.example.com")
  await dialog.getByLabel("Local tunnel port", { exact: true }).fill("45000")
  await dialog.getByLabel("Tunnel token", { exact: true }).fill("fake-test-only-token")
  await dialog.getByRole("checkbox", { name: "I reviewed this dedicated tunnel’s routes", exact: true }).check()
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("rejected authentication")
  await expect(dialog.getByRole("button", { name: "Disconnect cloudflare from port 4200", exact: true })).toHaveCount(0)
  await expect(dialog.getByRole("button", { name: "Publish service", exact: true })).toBeEnabled()
  await expect(dialog.getByRole("radio", { name: "Use my Cloudflare account (optional)", exact: true })).toBeChecked()
  await dialog.getByRole("button", { name: "Publish service", exact: true }).click()
  await expect(dialog.getByRole("button", { name: "https://app.example.com", exact: true })).toBeVisible()
})


test("environment list keeps permissions and configuration across reloads", async ({ page }) => {
  await openGraph(page)
  const list = page.getByRole("table", { name: "Environments", exact: true })
  await expect(list.locator("tbody tr")).toHaveCount(2)
  await expect(page.getByRole("button", { name: "Fit environments", exact: true })).toHaveCount(0)
  await expect(page.getByRole("region", { name: "Host resources and storage" })).toBeVisible()
  const alpha = list.locator('[data-environment-id="Alpha"]')
  await alpha.getByRole("switch", { name: "Internet access for Alpha", exact: true }).click()
  await expect(alpha.getByRole("switch", { name: "Internet access for Alpha", exact: true })).toBeChecked()
  await expect(alpha.getByRole("button", { name: "Connect Alpha", exact: true })).toHaveCount(0)
  await alpha.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await expect(page.getByRole("region", { name: "Resource allocation", exact: true })).toBeVisible()
  await page.keyboard.press("Escape")
  await page.reload()
  await expect(list.locator("tbody tr")).toHaveCount(2)
  await page.setViewportSize({ width: 390, height: 844 })
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(true)
  await expect(alpha.getByRole("button", { name: "Configure Alpha", exact: true })).toBeVisible()
})

test("list uses one state-aware lifecycle button and double-click configuration", async ({ page }) => {
  const alpha = fixture("Alpha")
  alpha.networkAccess = true
  await openGraph(page, [alpha])
  await page.evaluate(async () => {
    const { platformApi } = await import("/src/api/platform-api.ts")
    platformApi.openEnvironmentWindow = async () => true
  })
  const item = page.locator('[data-environment-id="Alpha"]')
  const actions = item.locator(".environment-card-actions")
  await expect(actions.getByRole("button", { name: /Shut down|Configure Alpha|Connect Alpha/ })).toHaveCount(0)
  await item.locator(".environment-list-type").dblclick()
  const settings = page.getByRole("dialog", { name: "Alpha", exact: true })
  await expect(settings).toBeVisible()
  await page.keyboard.press("Escape")
  await item.getByRole("button", { name: "Start", exact: true }).click()
  await expect(item.getByRole("button", { name: "Stop", exact: true })).toBeEnabled()
  await expect(item.getByRole("button", { name: "Open", exact: true })).toBeEnabled()
  await expect(item.getByRole("button", { name: "Pause Alpha", exact: true })).toHaveCount(0)
  await item.getByRole("button", { name: "Stop", exact: true }).click()
  await expect(item.getByRole("button", { name: "Start", exact: true })).toBeEnabled()
  await expect(settings).toHaveCount(0)
  // The environment name remains keyboard-accessible without a settings icon.
  await item.getByRole("button", { name: "Configure Alpha", exact: true }).focus()
  await page.keyboard.press("Enter")
  await expect(settings).toBeVisible()
})

test("list searches, filters, sorts, expands details, shows links and acts on selected rows", async ({ page }) => {
  const alpha = fixture("Alpha"), beta = fixture("Beta", "microVm"), gamma = fixture("Gamma")
  alpha.status = "running"; alpha.cpuUsage = 12; beta.cpuUsage = 0; gamma.status = "error"
  await openGraph(page, [alpha, beta, gamma])
  await page.evaluate(() => {
    const state = JSON.parse(localStorage.getItem("yougori.platform.v1")!)
    state.connections = [{ id: "link-ab", sourceId: "Alpha", targetId: "Beta", direction: "oneWay", permissions: [], ports: [], active: true, createdAt: "2026-01-01T00:00:00Z", enforcementStatus: "enforced" }]
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
  })
  await page.reload()
  const table = page.getByRole("table", { name: "Environments", exact: true })
  const rows = table.locator("tbody tr[data-environment-id]")
  const toolbar = page.getByRole("toolbar", { name: "Filter and sort environments" })
  await expect(rows).toHaveCount(3)
  await expect(table.locator('[data-environment-id="Alpha"]').getByRole("button", { name: "Connection to Beta, active", exact: true })).toBeVisible()
  await expect(table.locator('[data-environment-id="Beta"]').getByRole("button", { name: "Connection from Alpha, active", exact: true })).toBeVisible()

  await page.keyboard.press("/")
  await expect(toolbar.getByRole("searchbox", { name: "Search environments" })).toBeFocused()
  await page.keyboard.type("microvm")
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toHaveAttribute("data-environment-id", "Beta")
  await page.keyboard.press("Escape")
  await expect(rows).toHaveCount(3)

  await toolbar.getByRole("group", { name: "Status filter" }).getByRole("button", { name: /^Attention/ }).click()
  await expect(rows).toHaveCount(1)
  await expect(rows.first()).toHaveAttribute("data-environment-id", "Gamma")
  await toolbar.getByRole("group", { name: "Status filter" }).getByRole("button", { name: /^All/ }).click()

  await table.getByRole("button", { name: "CPU", exact: true }).click()
  await expect(table.getByRole("columnheader", { name: "CPU" })).toHaveAttribute("aria-sort", "descending")
  await expect(rows.first()).toHaveAttribute("data-environment-id", "Alpha")

  await table.getByRole("button", { name: "Show details for Alpha", exact: true }).click()
  await expect(page.getByRole("region", { name: "Resources of Alpha" })).toContainText("0.25 cores")
  await expect(page.getByRole("region", { name: "Connections of Alpha" })).toContainText("To Beta")
  await table.getByRole("button", { name: "Hide details for Alpha", exact: true }).click()
  await expect(page.getByRole("region", { name: "Resources of Alpha" })).toHaveCount(0)

  await table.getByRole("checkbox", { name: "Select Alpha", exact: true }).check()
  await table.getByRole("checkbox", { name: "Select Beta", exact: true }).check()
  const bulk = toolbar.getByRole("group", { name: "Selected environments" })
  await expect(bulk).toContainText("2 selected")
  await bulk.getByRole("button", { name: "Start 1", exact: true }).click()
  await expect(table.locator('[data-environment-id="Beta"]').getByRole("button", { name: "Stop", exact: true })).toBeEnabled()
  await bulk.getByRole("button", { name: "Stop 2", exact: true }).click()
  await expect(table.locator('[data-environment-id="Alpha"]').getByRole("button", { name: "Start", exact: true })).toBeEnabled()
  await expect(table.locator('[data-environment-id="Beta"]').getByRole("button", { name: "Start", exact: true })).toBeEnabled()
  await bulk.getByRole("button", { name: "Clear", exact: true }).click()
  await expect(bulk).toHaveCount(0)

  await toolbar.getByRole("combobox").filter({ hasText: "None" }).selectOption("type")
  await expect(table.locator("tr.environment-list-group")).toHaveCount(2)
  await page.reload()
  await expect(table.locator("tr.environment-list-group")).toHaveCount(2)
})

test("list access switches reflect saved permissions and recover from disconnect failures", async ({ page }) => {
  const env = fixture("Alpha"); env.status = "running"
  await openGraph(page, [env])
  const row = page.locator('[data-environment-id="Alpha"]')
  const internet = row.getByRole("switch", { name: "Internet access for Alpha", exact: true })
  const pc = row.getByRole("switch", { name: "My PC access for Alpha", exact: true })
  await expect(internet).not.toBeChecked()
  await internet.check()
  await expect(internet).toBeChecked()
  await internet.uncheck()
  await expect(internet).not.toBeChecked()
  await expect(row.getByRole("button", { name: "Stop", exact: true })).toBeEnabled()
  await expect(pc).not.toBeChecked()
  await pc.click()
  const shares = page.getByRole("dialog", { name: "My PC · Alpha", exact: true })
  await expect(shares).toBeVisible()
  await page.keyboard.press("Escape")
  await expect(pc).not.toBeChecked()
  await pc.click()
  await shares.getByRole("button", { name: "Choose folders", exact: true }).click()
  await shares.getByRole("button", { name: "Connect selected folders", exact: true }).click()
  await expect(shares.getByText("PC access: selected folders only", { exact: true })).toBeVisible()
  await page.keyboard.press("Escape")
  await expect(pc).toBeChecked()
  await page.evaluate(async () => {
    const { workspaceApi } = await import("/src/api/workspace-api.ts")
    const original = workspaceApi.unshare
    workspaceApi.unshare = async id => {
      workspaceApi.unshare = original
      throw new Error(`Could not disconnect shared folder ${id}`)
    }
  })
  await pc.click()
  await expect(page.getByText(/Could not disconnect shared folder/)).toBeVisible()
  await expect(pc).toBeChecked()
  await expect(pc).toBeEnabled()
  await pc.click()
  await expect(pc).not.toBeChecked()
  const saved = await page.evaluate(async () => {
    const { workspaceApi } = await import("/src/api/workspace-api.ts")
    return workspaceApi.services("Alpha")
  })
  expect(saved.shares).toHaveLength(0)
})

test("all drives appear in the footer and new environments use the selected drive capacity", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(() => {
    const state = JSON.parse(localStorage.getItem("yougori.platform.v1")!)
    state.host.storageDrive = "C:\\"
    state.host.totalStorageGb = 100
    state.host.usedStorageGb = 99
    state.host.storageDrives = [
      { path: "C:\\", name: "System", fileSystem: "NTFS", totalGb: 100, freeGb: 1, readOnly: false, removable: false },
      { path: "D:\\", name: "Data", fileSystem: "NTFS", totalGb: 500, freeGb: 200, readOnly: false, removable: false },
      { path: "E:\\", name: "Read-only media", fileSystem: "UDF", totalGb: 8, freeGb: 0, readOnly: true, removable: true },
    ]
    localStorage.setItem("yougori.platform.v1", JSON.stringify(state))
  })
  await page.reload()
  const footer = page.getByRole("region", { name: "Host resources and storage" })
  for (const drive of ["C:", "D:", "E:"]) await expect(footer.getByText(drive, { exact: true })).toBeVisible()
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(dialog.getByText(/Not enough free space/)).toBeVisible()
  const drive = dialog.getByRole("combobox", { name: "Storage drive", exact: true })
  await expect(drive.locator('option[value="E:\\\\"]')).toHaveAttribute("disabled", "")
  await drive.selectOption("D:\\")
  await expect(dialog.getByRole("slider", { name: "Storage limit", exact: true })).toHaveAttribute("max", "198")
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("Stored on D")
  await dialog.getByRole("button", { name: "Create environment", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments.find((e: Environment) => e.name === "Stored on D"))
  expect(saved.storageDrive).toBe("D:\\")
  await page.reload()
  expect(await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments.find((e: Environment) => e.name === "Stored on D").storageDrive)).toBe("D:\\")
})

test("list view keeps the empty workspace guidance", async ({ page }) => {
  await openGraph(page, [])
  await expect(page.getByText("Your workspace starts here", { exact: true })).toBeVisible()
  await expect(page.getByRole("table", { name: "Environments" }).locator("tbody tr")).toHaveCount(0)
})


test("list columns align and environment errors stay in configuration", async ({ page }) => {
  const broken = fixture("Alpha")
  broken.status = "error"
  broken.lastError = "Internal runtime failure: serial.log is locked"
  await openGraph(page, [broken, fixture("Beta", "microVm")])
  const node = page.locator('[data-environment-id="Alpha"]')
  await expect(node.getByText("Needs attention", { exact: true })).toBeVisible()
  await expect(node).not.toContainText(broken.lastError)
  await expect(node.locator('[title]').filter({ hasText: broken.lastError })).toHaveCount(0)
  const table = page.getByRole("table", { name: "Environments" })
  await expect(table.getByRole("columnheader")).toHaveText(["", "Environment", "Status", "CPU", "GPU", "Memory", "Storage", "Connections", "Access", "Services", "Actions"])
  await expect(node.getByText("Needs attention", { exact: true })).toBeVisible()
  await expect(table).not.toContainText(broken.lastError)
  const aligned = await table.evaluate(element => {
    const headers = [...element.querySelectorAll('thead th')].map(cell => cell.getBoundingClientRect().x)
    return [...element.querySelectorAll('tbody tr')].every(row => [...row.children].every((cell, index) => Math.abs(cell.getBoundingClientRect().x - headers[index]) < 1))
  })
  expect(aligned).toBe(true)
  await node.getByRole("button", { name: "Configure Alpha", exact: true }).click()
  await expect(page.getByText(broken.lastError, { exact: true })).toBeVisible()
})


test("CLI shares the environments canvas and keeps its session across views", async ({ page }) => {
  await openGraph(page)
  const views = page.locator(".workspace-footer-actions")
  await expect(page.getByRole("button", { name: "Nodes", exact: true })).toHaveCount(0)
  await views.getByRole("button", { name: "CLI", exact: true }).click()
  const panel = page.getByRole("region", { name: "Yougori CLI" })
  await expect(panel).toBeVisible()
  await expect(page.locator('[data-environment-canvas] #host-terminal-panel')).toBeVisible()
  await expect(page.getByRole("region", { name: "Environment capabilities" })).toHaveCount(0)
  await expect(page.getByRole("table", { name: "Environments" })).toHaveCount(0)
  const marker = await panel.evaluate(element => { element.setAttribute("data-session-test", "retained"); return element.getBoundingClientRect().bottom })
  expect(marker).toBeLessThanOrEqual(1000)
  await expect(panel.locator('[data-workspace-toolbar]')).toHaveCount(0)
  await expect(panel.getByRole("combobox")).toHaveCount(0)
  await panel.getByRole("button", { name: "CLI access" }).click()
  const access = page.getByRole("dialog", { name: "CLI access" })
  await expect(access).toBeVisible()
  await expect(access).toContainText("All local environments")
  await expect(access).toContainText("Yougori\\Workspace")
  await expect(access.getByRole("switch")).toHaveCount(0)
  await page.keyboard.press("Escape")
  await expect(access).toBeHidden()
  await expect(panel.getByRole("button", { name: "Connection skills" })).toHaveCount(0)
  await expect(panel.getByRole("button", { name: "Install tools", exact: true })).toHaveCount(0)
  await panel.getByRole("button", { name: "CLI actions" }).click()
  await page.getByRole("menuitem", { name: "Skills", exact: true }).click()
  await expect(page.getByRole("dialog", { name: "Skills", exact: true })).toBeVisible()
  await page.keyboard.press("Escape")
  await panel.getByRole("button", { name: "CLI actions" }).click()
  await expect(page.getByRole("menuitem", { name: "Install tools", exact: true })).toBeEnabled()
  await page.getByRole("menuitem", { name: "Install tools", exact: true }).hover()
  for (const tool of terminalInstallers) await expect(page.getByRole("menuitem", { name: `Install ${tool.name}`, exact: true })).toBeVisible()
  await page.evaluate(async () => {
    const module = "/src/api/host-terminal-api.ts", { hostTerminalApi } = await import(module)
    const original = hostTerminalApi.terminal
    Object.assign(window, { cliInstallerWrites: [] as string[] })
    hostTerminalApi.terminal = (request: Parameters<typeof original>[0]) => {
      if (request.action === "write") (window as unknown as { cliInstallerWrites: string[] }).cliInstallerWrites.push(atob(request.data ?? ""))
      return original(request)
    }
  })
  await page.getByRole("menuitem", { name: "Install Codex", exact: true }).click()
  await expect(panel.getByRole("tab", { selected: true })).toHaveAccessibleName(/Install Codex/)
  await expect.poll(() => page.evaluate(() => (window as unknown as { cliInstallerWrites: string[] }).cliInstallerWrites.join(""))).toContain("npm.cmd install --global @openai/codex")
  await panel.getByRole("button", { name: "CLI actions" }).click()
  await page.getByRole("menuitem", { name: "Hide CLI" }).click()
  await expect(page.locator("[data-environment-graph]")).toHaveAttribute("data-view", "list")
  await page.keyboard.press("Control+Backquote")
  await expect(panel).toBeVisible()
  await expect(panel).toHaveAttribute("data-session-test", "retained")
  await page.reload()
  await expect(views.getByRole("button", { name: "CLI", exact: true })).toHaveAttribute("aria-pressed", "true")
  await expect(panel).toBeVisible()
  await page.locator(".workspace-view-toolbar").getByRole("button", { name: "Environments", exact: true }).click()
  await expect(page.getByRole("table", { name: "Environments" })).toBeVisible()
  await expect(panel).toBeHidden()
})


test("closing instructions restores List, CLI and its keyboard shortcut", async ({ page }) => {
  await openGraph(page)
  await page.evaluate(async () => {
    const module = "/src/lib/instructions-tour.ts"
    const { startInstructions, stopInstructions } = await import(module)
    startInstructions()
    stopInstructions()
  })
  const views = page.locator(".workspace-footer-actions")
  await expect(views.getByRole("button", { name: "CLI", exact: true })).toBeEnabled()
  await expect(page.getByRole("table", { name: "Environments" })).toBeVisible()
  await views.getByRole("button", { name: "CLI", exact: true }).click()
  await expect(page.getByRole("region", { name: "Yougori CLI" })).toBeVisible()
  await page.keyboard.press("Control+Backquote")
  await expect(page.locator("[data-environment-graph]")).toHaveAttribute("data-view", "list")
  await page.reload()
  await expect(page.locator("[data-environment-graph]")).toHaveAttribute("data-view", "list")
  await views.getByRole("button", { name: "CLI", exact: true }).click()
  await expect(page.getByRole("region", { name: "Yougori CLI" })).toBeVisible()
})


test("terminal tolerates a missed read and allows dismissing and reconnecting after disconnection", async ({ page }) => {
  const environment = fixture("env-reconnect"); environment.status = "running"
  await openGraph(page, [environment])
  await page.goto("/?environment=env-reconnect")
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeEnabled()
  await page.evaluate(async () => {
    const module = "/src/api/workspace-api.ts", { workspaceApi } = await import(module)
    const original = workspaceApi.terminal
    const control = { failures: 1, successfulReads: 0, creates: 0, closes: 0 }
    Object.assign(window, { terminalRecovery: control })
    workspaceApi.terminal = (...args: Parameters<typeof original>) => {
      if (args[2] === "create") control.creates++
      if (args[2] === "close") control.closes++
      if (args[2] === "read") {
        if (control.failures > 0) { control.failures--; return Promise.reject(new Error("error sending request for url (http://127.0.0.1:63683/v1/terminal/read)")) }
        control.successfulReads++
      }
      return original(...args)
    }
  })
  await expect.poll(() => page.evaluate(() => (window as unknown as { terminalRecovery: { successfulReads: number } }).terminalRecovery.successfulReads)).toBeGreaterThan(0)
  await expect(page.getByRole("alert")).toHaveCount(0)
  expect(await page.evaluate(() => (window as unknown as { terminalRecovery: { closes: number } }).terminalRecovery.closes)).toBe(0)
  await page.evaluate(() => { (window as unknown as { terminalRecovery: { failures: number } }).terminalRecovery.failures = 4 })
  await expect(page.getByRole("alert")).toContainText("Lost connection to the environment", { timeout: 10000 })
  await expect(page.getByRole("alert")).not.toContainText("127.0.0.1")
  await page.getByRole("button", { name: "Dismiss terminal error" }).click()
  await expect(page.getByRole("alert")).toHaveCount(0)
  await page.getByRole("button", { name: "Reconnect", exact: true }).click()
  await expect.poll(() => page.evaluate(() => (window as unknown as { terminalRecovery: { creates: number } }).terminalRecovery.creates)).toBe(1)
  await expect(page.getByText("Session disconnected", { exact: true })).toHaveCount(0)
  await expect(page.getByRole("button", { name: "Install tools", exact: true })).toBeEnabled()
  await expect(page.getByRole("alert")).toHaveCount(0)
})

for (const view of ["nodes", "list"] as const) test(`duplication destinations and placement work in ${view}`, async ({ page }) => {
  const cloud = { ...fixture("Cloud", "cloud"), provider: "cloudSsh" as const, runtime: "user@example.com" }
  await openGraph(page, [fixture("Alpha"), cloud])
  if (view === "list") await page.getByRole("button", { name: "List", exact: true }).click()
  const local = page.locator('[data-environment-id="Alpha"]')
  const remote = page.locator('[data-environment-id="Cloud"]')
  for (const [row, predecessor, name] of [[local, view === "list" ? "Ports & access for Alpha" : "Add service port to Alpha", "Alpha"], [remote, "Configuration for Cloud", "Cloud"]] as const) {
    const before = await row.getByRole("button", { name: predecessor, exact: true }).boundingBox()
    const after = await row.getByRole("button", { name: `Duplicate ${name}`, exact: true }).boundingBox()
    expect(after!.x).toBeGreaterThan(before!.x)
    await row.getByRole("button", { name: `Duplicate ${name}`, exact: true }).click()
    await expect(page.getByRole("menuitem", { name: "Local", exact: true })).toBeVisible()
    await expect(page.getByRole("menuitem", { name: "Cloud", exact: true })).toBeVisible()
    await page.getByRole("menuitem", { name: "Local", exact: true }).click()
    const dialog = page.getByRole("dialog", { name: "Duplicate environment", exact: true })
    await expect(dialog.getByRole("textbox", { name: "Name", exact: true })).toHaveValue(`${name} copy`)
    await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  }
})

test("local duplication retains failures and protects running sources", async ({ page }) => {
  await openGraph(page, [fixture("Alpha"), { ...fixture("Running"), status: "running" }])
  await page.getByRole("button", { name: "Duplicate Running", exact: true }).click()
  await page.getByRole("menuitem", { name: "Local", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Duplicate environment", exact: true })
  await expect(dialog).toContainText("Stop this environment")
  await expect(dialog.getByRole("button", { name: "Duplicate", exact: true })).toBeDisabled()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  await page.getByRole("button", { name: "Duplicate Alpha", exact: true }).click()
  await page.getByRole("menuitem", { name: "Local", exact: true }).click()
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("Alpha")
  await expect(dialog.getByRole("button", { name: "Duplicate", exact: true })).toBeDisabled()
  await dialog.getByRole("textbox", { name: "Name", exact: true }).fill("My copy")
  await dialog.getByRole("button", { name: "Duplicate", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("requires the desktop app")
  await expect(dialog.getByRole("textbox", { name: "Name", exact: true })).toHaveValue("My copy")
  await expect(dialog.getByRole("button", { name: "Duplicate", exact: true })).toBeEnabled()
})

for (const provider of ["aws", "azure", "google"] as const) for (const routeName of ["local-to-cloud", "cloud-to-cloud"] as const) test(`full disk duplication setup ${provider} ${routeName}`, async ({ page }) => {
  await page.route("**/src/api/duplication-api.ts*", async route => {
    const response = await route.fetch()
    await route.fulfill({ response, body: await response.text() + `
      duplicationApi.inspectSource = async (environmentId, source) => ({ ready: true, disk: "verified-source", bootMode: "uefi" });
      duplicationApi.duplicate = async request => {
        document.documentElement.dataset.duplicationRequest = JSON.stringify(request);
        const state = JSON.parse(localStorage.getItem("yougori.platform.v1"));
        const source = state.environments.find(e => e.id === request.environmentId);
        state.environments.push({ ...source, id: "copied-environment", name: request.name, kind: request.destination === "cloud" ? "cloud" : "fullVm", provider: request.destination === "cloud" ? "cloudSsh" : "qemu", status: "stopped" });
        localStorage.setItem("yougori.platform.v1", JSON.stringify(state));
        return state;
      };
    ` })
  })
  const cloud = routeName !== "local-to-cloud"
  const env = fixture("Source", cloud ? "cloud" : "fullVm")
  if (cloud) env.provider = "cloudSsh"
  await openGraph(page, [env])
  await page.getByRole("button", { name: "Duplicate Source", exact: true }).click()
  await page.getByRole("menuitem", { name: "Cloud", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Duplicate environment", exact: true })
  const providerName = provider === "aws" ? "AWS" : provider === "azure" ? "Azure" : "Google Cloud"
  if (cloud) {
    const source = dialog.getByRole("region", { name: "Source cloud VM", exact: true })
    await source.getByRole("button", { name: providerName, exact: true }).click()
    for (const label of [provider === "aws" ? "Source AWS CLI profile" : provider === "azure" ? "Source Subscription ID" : "Source Project ID", provider === "google" ? "Source zone" : "Source region", provider === "aws" ? "Instance ID" : "VM name"]) await source.getByRole("textbox", { name: label, exact: true }).fill("source-value")
    if (provider === "azure") await source.getByRole("textbox", { name: "Source resource group", exact: true }).fill("source-group")
    else await source.getByRole("textbox", { name: "Source transfer bucket", exact: true }).fill("source-transfer")
    await expect(dialog.getByRole("button", { name: "Duplicate", exact: true })).toBeDisabled()
    await source.getByRole("button", { name: "Check source", exact: true }).click()
    await expect(source.getByRole("button", { name: "Source verified", exact: true })).toBeVisible()
  }
  {
    const target = dialog.getByRole("region", { name: "Destination cloud VM", exact: true })
    await target.getByRole("button", { name: providerName, exact: true }).click()
    for (const label of [provider === "aws" ? "AWS CLI profile" : provider === "azure" ? "Subscription ID" : "Project ID", provider === "google" ? "Zone" : "Region", "Machine size", "Existing subnet", "SSH username"]) await target.getByRole("textbox", { name: label, exact: true }).fill("destination-value")
    if (provider === "azure") for (const label of ["Resource group", "Network security group"]) await target.getByRole("textbox", { name: label, exact: true }).fill("existing-value")
    else {
      await target.getByRole("textbox", { name: "Destination transfer bucket", exact: true }).fill("destination-transfer")
      if (provider === "aws") for (const label of ["Security group ID", "SSH key pair name"]) await target.getByRole("textbox", { name: label, exact: true }).fill("existing-value")
      else await target.getByRole("textbox", { name: "SSH public key", exact: true }).fill("ssh-ed25519 AAAA")
    }
  }
  await expect(dialog.getByRole("complementary", { name: "Cloud deployment risks" })).toBeVisible()
  await dialog.getByRole("checkbox").check()
  await dialog.getByRole("button", { name: "Duplicate", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const request = await page.evaluate(() => JSON.parse(document.documentElement.dataset.duplicationRequest!))
  expect(request.environmentId).toBe("Source")
  expect(request.reviewed).toBe(true)
  expect(request.operationId).toMatch(/^[a-f0-9-]{36}$/)
  expect(request.destination).toBe("cloud")
  if (cloud) expect(request.source.provider).toBe(provider)
  else expect(request.source).toBeNull()
  expect(request.target.provider).toBe(provider)
})

test("failed cloud copies reopen from history and resume the original operation", async ({ page }) => {
  await page.route("**/src/api/duplication-api.ts*", async route => {
    const response = await route.fetch()
    await route.fulfill({ response, body: await response.text() + `
      duplicationApi.duplicate = async request => {
        const calls = JSON.parse(document.documentElement.dataset.copyAttempts || "[]");
        calls.push(request.operationId); document.documentElement.dataset.copyAttempts = JSON.stringify(calls);
        const state = JSON.parse(localStorage.getItem("yougori.platform.v1"));
        state.duplicationJobs ||= {};
        state.duplicationJobs[request.operationId] = { request, environmentId: "copy", status: calls.length === 1 ? "failed" : "complete", phase: calls.length === 1 ? "Uploading disk" : "Copy complete", error: calls.length === 1 ? "Upload interrupted" : null, resources: ["Private transfer object"], completed: calls.length === 1 ? {} : {cleanup: true} };
        if (calls.length > 1) state.environments.push({...state.environments[0], id:"copy", name:request.name, kind:"cloud", provider:"cloudSsh", status:"stopped"});
        localStorage.setItem("yougori.platform.v1", JSON.stringify(state));
        if (calls.length === 1) throw new Error("Upload interrupted");
        return state;
      };
    ` })
  })
  await openGraph(page, [fixture("VM", "fullVm")])
  await page.getByRole("button", { name: "Duplicate VM", exact: true }).click()
  await page.getByRole("menuitem", { name: "Cloud", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Duplicate environment", exact: true })
  await dialog.getByRole("checkbox").check()
  await dialog.getByRole("button", { name: "Duplicate", exact: true }).click()
  await expect(dialog.getByRole("alert")).toContainText("Upload interrupted")
  await expect(dialog.getByRole("textbox", { name: "Name", exact: true })).toBeDisabled()
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click()
  const dismiss = page.getByRole("button", { name: "Dismiss notification", exact: true })
  if (await dismiss.count()) {
    // This toast may expire while the slow cloud-copy dialog is being checked.
    await dismiss.click({ timeout: 1000 }).catch(async error => {
      if (await dismiss.count()) throw error
    })
  }
  await page.getByRole("button", { name: "Copies", exact: true }).click()
  const history = page.getByRole("dialog", { name: "Environment copies", exact: true })
  await history.getByRole("button", { name: "Resume copy", exact: true }).click()
  await expect(history).toContainText("Copy complete")
  await expect(history).toContainText("Transfer resources cleaned up")
  const attempts = await page.evaluate(() => JSON.parse(document.documentElement.dataset.copyAttempts!))
  expect(attempts).toHaveLength(2)
  expect(attempts[0]).toBe(attempts[1])
})


test("cloud to local copies selected folders into the chosen image without provider snapshots", async ({ page }) => {
  await page.route("**/src/api/duplication-api.ts*", async route => {
    const response = await route.fetch()
    await route.fulfill({ response, body: await response.text() + `
      duplicationApi.inspectSource = async () => { throw new Error("Provider inspection must not run for file copies"); };
      duplicationApi.duplicate = async request => {
        document.documentElement.dataset.fileCopyRequest = JSON.stringify(request);
        return JSON.parse(localStorage.getItem("yougori.platform.v1"));
      };
    ` })
  })
  const cloud = fixture("Cloud files", "cloud")
  cloud.provider = "cloudSsh"
  await openGraph(page, [cloud])
  await page.getByRole("button", { name: "Duplicate Cloud files", exact: true }).click()
  await page.getByRole("menuitem", { name: "Local", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Duplicate environment", exact: true })
  await expect(dialog).toContainText("Local container image")
  await dialog.getByRole("combobox", { name: "Local container image", exact: true }).click()
  await page.getByRole("combobox", { name: "Search OCI images", exact: true }).fill("Ubuntu")
  await page.locator('[data-slot="combobox-popup"]').getByRole("option").filter({ hasText: "Popular Debian-based Linux" }).click()
  await expect(dialog.getByRole("button", { name: "Check source", exact: true })).toHaveCount(0)
  await expect(dialog.getByRole("textbox", { name: "Source AWS CLI profile" })).toHaveCount(0)
  await dialog.getByRole("textbox", { name: "Cloud files and folders", exact: true }).fill("/srv/my project\n~/documents")
  await expect(dialog.getByRole("button", { name: "Copy files", exact: true })).toBeDisabled()
  await dialog.getByRole("checkbox").check()
  await dialog.getByRole("spinbutton", { name: "Local storage (GB)", exact: true }).fill("30")
  await expect(dialog.getByRole("checkbox")).not.toBeChecked()
  await dialog.getByRole("checkbox").check()
  await dialog.getByRole("button", { name: "Copy files", exact: true }).click()
  await expect(dialog).not.toBeVisible()
  const request = await page.evaluate(() => JSON.parse(document.documentElement.dataset.fileCopyRequest!))
  expect(request.source).toBeNull()
  expect(request.target).toBeNull()
  expect(request.destination).toBe("local")
  expect(request.localFiles).toEqual({ image: "docker.io/library/ubuntu:latest", paths: ["/srv/my project", "~/documents"], storageGb: 30 })
})


test("new environment offers Neocloud instead of the retired deployment entry", async ({ page }) => {
  await openGraph(page, [])
  await page.getByRole("button", { name: "New environment", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "New environment", exact: true })
  await expect(dialog.getByText("Deploy to cloud", { exact: true })).toHaveCount(0)
  await dialog.getByText("Neocloud", { exact: true }).click()
  await expect(dialog.getByRole("heading", { name: "Rent GPUs in the cloud", exact: true })).toBeVisible()
})

test("saved domain ports can be edited and the new tunnel route is shown", async ({ page }) => {
  await openGraph(page, [fixture("Alpha")])
  await page.getByRole("button", { name: "Add or manage saved domain setups" }).click()
  const dialog = page.getByRole("dialog", { name: "Public access setups" })
  await dialog.getByRole("textbox", { name: "App port" }).fill("4200")
  await dialog.getByRole("textbox", { name: "Domain" }).fill("crm.example.com")
  await dialog.getByRole("textbox", { name: "Local tunnel port" }).fill("45000")
  await dialog.getByRole("textbox", { name: "Cloudflare tunnel token" }).fill("synthetic-secret-for-test")
  await dialog.getByRole("button", { name: "Save and connect tunnel" }).click()
  await expect(dialog.getByText("crm.example.com · :4200")).toBeVisible()
  await dialog.getByRole("button", { name: "Edit ports for crm.example.com" }).click()
  const edit = dialog.getByRole("form", { name: "Edit crm.example.com" })
  await edit.getByRole("textbox", { name: "App port" }).fill("3000")
  await edit.getByRole("textbox", { name: "Local tunnel port" }).fill("45010")
  await expect(edit).toContainText("http://localhost:45010")
  await edit.getByRole("button", { name: "Save ports" }).click()
  await expect(dialog.getByText("crm.example.com · :3000")).toBeVisible()
  await expect(dialog.getByText("Any environment · local bridge :45010")).toBeVisible()
  await expect(dialog.getByLabel("Cloudflare tunnel setup")).toContainText("http://localhost:45010")
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.public-access-presets.v1") ?? "[]"))
  expect(saved).toEqual([expect.objectContaining({ hostname: "crm.example.com", port: 3000, hostPort: 45010 })])
})

test("one Save changes stores a VM's new name without a separate name button", async ({ page }) => {
  await openGraph(page, [fixture("VM", "fullVm")])
  await page.getByRole("button", { name: "Configure VM", exact: true }).click()
  const sheet = page.getByRole("dialog", { name: "VM", exact: true })
  for (const name of ["Save name", "Expand storage", "Save startup command"]) await expect(sheet.getByRole("button", { name, exact: true })).toHaveCount(0)
  await sheet.getByRole("textbox", { name: "VM name", exact: true }).fill("Work VM")
  await sheet.getByRole("button", { name: "Save changes", exact: true }).click()
  await expect(page.getByRole("status").filter({ hasText: "Changes saved." })).toBeVisible()
  const saved = await page.evaluate(() => JSON.parse(localStorage.getItem("yougori.platform.v1")!).environments[0])
  expect(saved.name).toBe("Work VM")
})
