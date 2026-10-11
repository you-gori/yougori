// @vitest-environment node
import { execFileSync } from "node:child_process"
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join, resolve } from "node:path"
import { describe, expect, it } from "vitest"
import { terminalInstallerInput, terminalInstallers } from "./terminal-installers"

const shell = process.platform === "win32" ? "C:/Program Files/Git/bin/bash.exe" : "/bin/bash"
const sourcePath = resolve("src-tauri/src/workspace/install-tools.sh")
const script = readFileSync(sourcePath, "utf8").replaceAll("\r\n", "\n")
const unixPath = (path: string) => path.replaceAll("\\", "/").replace(/^([A-Z]):/i, (_, drive: string) => "/" + drive.toLowerCase())

// Each case runs the real installer script in a shell; process start-up is slow under a loaded run.
describe("automatic coding-tool installation", { timeout: 30_000 }, () => {
  it("offers OpenClaw in the shared menu catalog and both CLI installer methods", () => {
    expect(terminalInstallers.find(tool => tool.id === "openclaw")).toMatchObject({ name: "OpenClaw", docs: "https://docs.openclaw.ai/install" })
    const catalog = readFileSync(resolve("cli/src/catalog.rs"), "utf8")
    for (const method of ["prepare_terminal_installer", "install_terminal_tool"]) {
      expect(catalog.split("\n").find(line => line.includes(`method!(${method},`))).toContain("|openclaw")
    }
  })
  it("sends a short validated launcher plus Enter, never a giant command paste", () => {
    for (const tool of terminalInstallers) {
      const command = "exec sh '/tmp/yougori-install." + tool.id + "/install.sh'"
      expect(terminalInstallerInput(command)).toBe(command + "\r")
      expect(command.length).toBeLessThan(200)
    }
    for (const bad of ["", "sh -c 'bad'", "exec sh '/etc/profile'", "exec sh '/tmp/yougori-install.a/../bad/install.sh'", "exec sh '/tmp/yougori-install.a/install.sh'; whoami", "exec sh '/tmp/yougori-install.a/install.sh'\r"]) {
      expect(() => terminalInstallerInput(bad)).toThrow("Invalid")
    }
  })
  it.skipIf(!existsSync(shell))("parses the complete staged script without running an installer", () => {
    // Feed stdin, avoiding Windows command-line length/quoting limits.
    execFileSync(shell, ["-n"], { windowsHide: true, input: script })
    expect(script).toContain("CODEX_NON_INTERACTIVE=1")
    expect(script).toContain("sha256sum -c -")
    expect(script).not.toContain("--dangerously-skip-permissions")
  })
  for (const manager of ["apk", "apt-get", "dnf", "microdnf", "yum", "zypper", "pacman", "swupd"]) {
    for (const tool of terminalInstallers) {
      it.skipIf(!existsSync(shell))(tool.name + " completes with the " + manager + " image family", () => {
        const result = exerciseInstaller(tool.id, manager)
        expect(result.output).toContain("Detected package manager: " + manager)
        expect(result.output).toContain(tool.id + " installed.")
        expect(result.packages).toContain(manager)
        if (manager === "apk" && tool.id === "claude") expect(result.packages).toContain("libgcc libstdc++ ripgrep")
        if (manager === "apt-get") expect(result.packages).toContain("install -y --no-install-recommends")
        expect(result.profile).toContain("Keep existing profile")
        expect(result.profile).toContain("tool-env.sh")
        expect(result.lockExists).toBe(false)
      })
    }
  }
  it.skipIf(!existsSync(shell))("Codex runs without the musl app-server daemon ahead of upstream's self-updated link", () => {
    const result = exerciseInstaller("codex", "apk")
    expect(result.codexWrapper).toContain('[ ! -x "$HOME/.local/bin/codex" ] || exec "$HOME/.local/bin/codex" --no-daemon "$@"')
    expect(result.codexWrapper).toContain('exec codex --no-daemon "$@"')
    expect(result.toolEnv).toContain('export PATH="$HOME/.local/share/yougori/bin:$HOME/.local/bin:$PATH"')
  })
  it.skipIf(!existsSync(shell))("explains package-manager-free and unprivileged images", () => {
    expect(exerciseInstaller("codex", "none").output).toContain("no supported package manager")
    expect(exerciseInstaller("claude", "apt-get", "nonroot").output).toContain("non-root user without sudo/doas")
  })
  it.skipIf(!existsSync(shell))("a failed download is never run or reported as installed and releases its lock", () => {
    const result = exerciseInstaller("codex", "apk", "download-failure")
    expect(result.output).toContain("Installation failed (exit 22)")
    expect(result.output).not.toContain("codex installed.")
    expect(result.lockExists).toBe(false)
  })
  it.skipIf(!existsSync(shell))("Gemini verifies and uses a private Node when the image Node is too old", () => {
    const result = exerciseInstaller("gemini", "apt-get", "old-node")
    expect(result.output).toContain("gemini installed.")
    expect(result.packages.indexOf("verify-checksum")).toBeLessThan(result.packages.indexOf("extract-node"))
    expect(result.packages.indexOf("extract-node")).toBeLessThan(result.packages.indexOf("npm install"))
    expect(result.nodePath).toContain("yougori/v22.1.0-x64/bin/node")
    expect(result.originalNode).toContain("mock version 1.0")
  })
  it.skipIf(!existsSync(shell))("Gemini refuses a mismatching Node archive before extraction or npm", () => {
    const result = exerciseInstaller("gemini", "apt-get", "bad-checksum")
    expect(result.output).toContain("Installation failed")
    expect(result.packages).toContain("verify-checksum")
    expect(result.packages).not.toContain("extract-node")
    expect(result.packages).not.toContain("npm install")
  })
  it.skipIf(!existsSync(shell))("Kilo installs the official CLI using a verified private Node when needed", () => {
    const result = exerciseInstaller("kilo", "apt-get", "old-node")
    expect(result.output).toContain("kilo installed.")
    expect(result.output).toContain("use /connect")
    expect(result.packages).toContain("@kilocode/cli")
    expect(result.packages.indexOf("verify-checksum")).toBeLessThan(result.packages.indexOf("npm install"))
    expect(result.nodePath).toContain("yougori/v22.1.0-x64/bin/node")
    expect(result.originalNode).toContain("mock version 1.0")
  })
  it.skipIf(!existsSync(shell))("OpenCode uses its official platform-aware installer without replacing profiles", () => {
    const result = exerciseInstaller("opencode", "apk")
    expect(result.packages).toContain("https://opencode.ai/install")
    expect(result.packages).not.toContain("npm install")
    expect(result.output).toContain("opencode installed.")
    expect(script).toContain('bash "$od_work/download" --no-modify-path')
  })
  for (const mode of ["success", "old-node", "arm64"]) {
    it.skipIf(!existsSync(shell))(`OpenClaw uses its private official installer and verifies the wrapper (${mode})`, () => {
      const result = exerciseInstaller("openclaw", "apt-get", mode)
      expect(result.packages).toContain("https://openclaw.ai/install-cli.sh")
      expect(result.packages).toContain("upstream-openclaw --prefix ")
      expect(result.packages).toContain("/.local/share/yougori/openclaw --install-method npm --version latest --no-onboard")
      expect(result.packages).toContain("openclaw --version")
      expect(result.packages).not.toContain("nodejs.org/dist/latest-v22")
      expect(result.packages).not.toContain("openclaw onboard")
      expect(result.packages).not.toContain("gateway run")
      expect(result.output).toContain("openclaw installed.")
      expect(result.output).toContain("openclaw onboard")
      expect(result.output).toContain("openclaw gateway run")
      expect(result.originalNode).toContain("mock version 1.0")
      expect(result.lockExists).toBe(false)
    })
  }
  for (const [manager, mode] of [["apt-get", "download-failure"], ["apt-get", "upstream-failure"], ["apt-get", "version-failure"], ["apt-get", "unsupported-arch"], ["apk", "upstream-failure"]]) {
    it.skipIf(!existsSync(shell))(`OpenClaw reports ${mode} on ${manager} and unlocks retry`, () => {
      const result = exerciseInstaller("openclaw", manager!, mode)
      expect(result.output).toContain("Installation failed")
      expect(result.output).not.toContain("openclaw installed.")
      expect(result.lockExists).toBe(false)
      if (mode === "download-failure" || mode === "unsupported-arch") expect(result.packages).not.toContain("upstream-openclaw")
      if (mode === "upstream-failure") expect(result.output).toContain("exit 37")
      if (mode === "version-failure") expect(result.output).toContain("exit 42")
      if (manager === "apk") expect(result.output).toContain("Do not bypass its runtime safety checks")
    })
  }
  it.skipIf(!existsSync(shell))("Ollama uses Alpine's package rather than a glibc download", () => {
    const result = exerciseInstaller("ollama", "apk")
    expect(result.packages).toContain("apk add --no-cache ollama")
    expect(result.packages).not.toContain("ollama.com/download")
    expect(result.output).toContain("uses CPU inference")
    expect(result.output).toContain("No models were downloaded and no server was started")
    expect(result.output).not.toContain("to sign in")
  })
  for (const [mode, arch] of [["success", "amd64"], ["arm64", "arm64"]]) {
    it.skipIf(!existsSync(shell))(`Ollama downloads the official ${arch} bundle without starting services`, () => {
      const result = exerciseInstaller("ollama", "apt-get", mode)
      expect(result.packages).toContain(`https://ollama.com/download/ollama-linux-${arch}.tar.zst`)
      expect(result.packages).toContain("decompress-ollama")
      expect(result.packages).toContain("extract-ollama")
      expect(script).toContain("bash -o pipefail")
      expect(result.uncompressedArchiveExists).toBe(false)
      expect(result.output).toContain("ollama installed.")
      expect(result.output).toContain("ollama serve")
      expect(result.packages).not.toMatch(/systemctl|nvidia|rocm/)
    })
  }
  for (const [tool, manager, mode] of [["ollama", "apk", "package-failure"], ["ollama", "apt-get", "extract-failure"], ["ollama", "apt-get", "decompress-failure"], ["ollama", "apt-get", "unsupported-arch"], ["ollama", "apt-get", "download-failure"], ["opencode", "apk", "download-failure"], ["kilo", "apt-get", "package-failure"], ["kilo", "apt-get", "bad-checksum"]] as const) {
    it.skipIf(!existsSync(shell))(`${tool} reports ${mode} without a false success and unlocks retry`, () => {
      const result = exerciseInstaller(tool, manager, mode)
      expect(result.output).toContain("Installation failed")
      expect(result.output).not.toContain(`${tool} installed.`)
      expect(result.lockExists).toBe(false)
    })
  }
})

function exerciseInstaller(tool: string, manager: string, mode = "success") {
  const root = mkdtempSync(join(tmpdir(), "yougori-installer-test-"))
  const fixtureHome = join(root, "guest-home")
  mkdirSync(fixtureHome)
  writeFileSync(join(fixtureHome, ".profile"), "# Keep existing profile\n")
  const mock = join(root, "mock.sh")
  writeFileSync(mock, readFileSync(resolve("src/lib/terminal-installers.fixture.sh"), "utf8").replaceAll("\r\n", "\n"))
  writeFileSync(join(root, "install.sh"), script)
  writeFileSync(join(root, "node"), "#!/bin/sh\nprintf 'mock version 1.0\\n'\n", { mode: 0o755 })
  try {
    let output = ""
    try {
      output = execFileSync(shell, [unixPath(mock), tool, manager, unixPath(join(root, "install.sh")), mode, unixPath(root)], { windowsHide: true, encoding: "utf8", env: { ...process.env, HOME: unixPath(fixtureHome) }, stdio: "pipe" })
    } catch (error) {
      const failure = error as { stdout: string; stderr: string }
      output = String(failure.stdout) + String(failure.stderr)
    }
    const nodeFile = join(fixtureHome, `.local/share/yougori/${tool}/node-path`)
    const read = (path: string) => existsSync(join(fixtureHome, path)) ? readFileSync(join(fixtureHome, path), "utf8") : ""
    return { codexWrapper: read(".local/share/yougori/bin/codex"), toolEnv: read(".local/share/yougori/tool-env.sh"), output, packages: existsSync(join(root, "packages")) ? readFileSync(join(root, "packages"), "utf8") : "", profile: readFileSync(join(fixtureHome, ".profile"), "utf8"), lockExists: existsSync(join(fixtureHome, ".local/share/yougori/install.lock")), nodePath: existsSync(nodeFile) ? readFileSync(nodeFile, "utf8") : "", originalNode: readFileSync(join(root, "node"), "utf8"), uncompressedArchiveExists: existsSync(join(root, "ollama.tar")) }
  } finally {
    // This path comes only from mkdtemp, never from user/guest input.
    rmSync(root, { recursive: true, force: true })
  }
}
