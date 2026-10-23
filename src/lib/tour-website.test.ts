import { spawn, spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import { describe, expect, it, vi } from "vitest"
import { buildHelloWebsite, helloWebsiteCheck, helloWebsiteCommand, helloWebsitePython, helloWebsiteSetupPython, verifyHelloWebsite } from "./tour-website"

describe("Hello World tutorial", () => {
  it("generates a bounded API command with native Python setup and no file sharing", () => {
    const command = helloWebsiteCommand("test-run")
    expect(command).not.toMatch(/[\r\n]/)
    expect(Buffer.byteLength(helloWebsiteCommand("x".repeat(80)))).toBeLessThanOrEqual(32768)
    for (const manager of ["apk", "apt-get", "dnf", "microdnf", "yum", "zypper"]) expect(command).toContain(manager)
    expect(command).not.toContain("http.server --directory")
    expect(helloWebsitePython("test-run")).not.toContain("SimpleHTTPRequestHandler")
    expect(helloWebsiteCheck("test-run")).toContain("127.0.0.1:3000")
    expect(helloWebsiteCheck("test-run")).toContain("timeout=3")
    expect(helloWebsiteCheck("test-run")).toContain("read(32768)")
    for (const invalid of ["", "bad'; run-this", "x".repeat(81)]) expect(() => helloWebsiteCommand(invalid)).toThrow("Invalid tutorial")
  })
  it("dispatches once to the chosen container, reports errors and permits an explicit retry", async () => {
    let finish!: (value: { exitCode: number; stdout: string; stderr: string }) => void
    const execute = vi.fn(() => new Promise<{ exitCode: number; stdout: string; stderr: string }>(resolve => { finish = resolve }))
    const first = buildHelloWebsite(execute, "env-first", "test-run")
    const repeated = buildHelloWebsite(execute, "env-first", "test-run")
    expect(repeated).toBe(first)
    await Promise.resolve()
    expect(execute).toHaveBeenCalledExactlyOnceWith("env-first", helloWebsiteCommand("test-run"))
    finish({ exitCode: 1, stdout: "", stderr: "Package download failed" })
    await expect(first).rejects.toThrow("Package download failed")
    const retry = buildHelloWebsite(execute, "env-first", "test-run")
    await Promise.resolve()
    finish({ exitCode: 0, stdout: "Installed Python\nyougori-hello-test-run\n", stderr: "" })
    await expect(retry).resolves.toBeUndefined()
    expect(execute).toHaveBeenCalledTimes(2)
  })
  it("checks the exact current tutorial's response, not merely an open port", async () => {
    const execute = vi.fn().mockResolvedValue({ exitCode: 0, stdout: "yougori-hello-test-run\n", stderr: "" })
    await verifyHelloWebsite(execute, "env-first", "test-run")
    expect(execute).toHaveBeenCalledWith("env-first", helloWebsiteCheck("test-run"))
    for (const result of [{ exitCode: 1, stdout: "yougori-hello-test-run" }, { exitCode: 0, stdout: "yougori-hello-old-run" }, { exitCode: 0, stdout: "some other website" }]) {
      execute.mockResolvedValueOnce({ ...result, stderr: "" })
      await expect(verifyHelloWebsite(execute, "env-first", "test-run")).rejects.toThrow("do not publish")
    }
  })
})

const python = process.platform === "win32" ? "py" : "python3"
const pythonArgs = process.platform === "win32" ? ["-3"] : []
const hasPython = spawnSync(python, [...pythonArgs, "--version"]).status === 0
it.skipIf(!hasPython)("serves Hello World without DNS lookups, disclosing files or reflecting requests", async () => {
  // An ephemeral loopback-only process. No container, public tunnel or files.
  // HTTPServer normally reverse-resolves the host before listening. This page
  // never uses the name, and a machine with unavailable DNS must still start.
  const noDns = "import socket\ndef reject_dns(*args):\n    raise RuntimeError('Tutorial startup must not reverse-resolve its host')\nsocket.getfqdn = reject_dns\n"
  const child = spawn(python, [...pythonArgs, "-u", "-c", noDns + helloWebsitePython("test-run", "127.0.0.1", 0)], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] })
  let stderr = ""
  child.stderr.on("data", data => { stderr = (stderr + String(data)).slice(-4096) })
  const closed = new Promise<void>(resolve => child.once("close", () => resolve()))
  try {
    const port = await new Promise<number>((resolve, reject) => {
      let output = ""
      const timeout = setTimeout(() => reject(new Error(`Demo server did not start: ${stderr}`)), 8000)
      child.once("error", error => { clearTimeout(timeout); reject(error) })
      child.once("exit", code => { clearTimeout(timeout); reject(new Error(`Demo server exited before ready (${code}): ${stderr}`)) })
      child.stdout.on("data", data => { output += String(data); const match = /ready on port (\d+)/.exec(output); if (match) { clearTimeout(timeout); resolve(Number(match[1])) } })
    })
    for (const path of ["/", "/etc/passwd", "/.env?token=DO_NOT_REFLECT", "/../secret.txt"]) {
      const response = await fetch(`http://127.0.0.1:${port}${path}`, { signal: AbortSignal.timeout(3000) })
      expect(response.status).toBe(200)
      expect(response.headers.get("cache-control")).toBe("no-store")
      const body = await response.text()
      expect(body).toContain('<h1 id="hello">Hello<br><span>World!</span></h1>')
      expect(response.headers.get("content-security-policy")).toContain("style-src 'unsafe-inline'")
      expect(response.headers.get("x-yougori-tutorial")).toBe("yougori-hello-test-run")
      expect(body).toContain("yougori-hello-test-run")
      expect(body).not.toContain("DO_NOT_REFLECT")
      expect(body).not.toContain("root:")
    }
    const response = await fetch(`http://127.0.0.1:${port}/`, { method: "POST", body: "do not execute", signal: AbortSignal.timeout(3000) })
    expect(response.status).toBe(501)
  } finally { child.kill(); await closed }
}, 15000)

const bash = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "/bin/bash"
// These start real interpreters. Start-up time on a busy machine is outside the test's control
// (about 0.2 s idle, but nearly 2 s each under parallel builds), so 5 s, vitest's default, is no limit for them.
const SPAWN_TIMEOUT = 20_000
it.skipIf(!hasPython)("the staged website and setup are valid Python", () => {
  // One interpreter compiles all three programs; one start-up each made this the slowest test here.
  const programs = [helloWebsitePython("test-run"), helloWebsitePython("test-run", "0.0.0.0", 3000, true), helloWebsiteSetupPython("test-run")]
  const compileAll = "import json, sys; [compile(code, '<website %d>' % index, 'exec') for index, code in enumerate(json.load(sys.stdin))]"
  const result = spawnSync(python, [...pythonArgs, "-c", compileAll], { input: JSON.stringify(programs), encoding: "utf8", windowsHide: true, timeout: SPAWN_TIMEOUT })
  expect(result.error).toBeUndefined()
  expect(result.stderr).toBe("")
  expect(result.status).toBe(0)
}, SPAWN_TIMEOUT)
it.skipIf(!existsSync(bash))("both generated commands pass real shell syntax checking", () => {
  for (const command of [helloWebsiteCommand("test-run"), helloWebsiteCheck("test-run")]) {
    const result = spawnSync(bash, ["-n"], { input: command, encoding: "utf8", windowsHide: true, timeout: SPAWN_TIMEOUT })
    expect(result.stderr).toBe("")
    expect(result.status).toBe(0)
  }
  // Inspect the nested sh -c payload too, without executing its package setup.
  const nested = spawnSync(bash, ["-s"], { input: `sh() { printf '%s' "$2" | bash -n; }; ${helloWebsiteCommand("test-run")}`, encoding: "utf8", windowsHide: true, timeout: SPAWN_TIMEOUT })
  expect(nested.stderr).toBe("")
  expect(nested.status).toBe(0)
}, SPAWN_TIMEOUT)
