import { test, expect, type Page } from "@playwright/test"

test.beforeEach(async ({ page }) => { await page.addInitScript(() => localStorage.setItem("yougori.instructions.seen.v1", "1")) })

/** Replaces the Access Grid API with an in-page hub that records every call. */
async function mockAccess(page: Page) {
  await page.evaluate(async () => {
    const path = "/src/api/access-api.ts"
    const { accessApi, TWO_STEP_MESSAGE } = await import(path)
    type Call = { method: string; args: unknown[] }
    const calls: Call[] = []
    const now = Math.floor(Date.now() / 1000)
    const device = (id: string, computer: string) => ({ id, computer, createdAt: now, lastUsedAt: now, strong: false })
    const ada = { id: "person-ada", username: "ada", name: "Ada Lovelace", permission: "admin", teams: [] as string[], createdAt: now, lastSeenAt: now, email: null, twoStep: false, devices: [device("device-1", "This PC")] }
    const state = {
      hub: null as Record<string, unknown> | null,
      member: null as Record<string, unknown> | null,
      people: [ada] as Array<Record<string, unknown>>,
      credentials: [] as Array<Record<string, unknown>>,
      rules: [] as Array<Record<string, unknown>>,
      waiting: [] as Array<Record<string, unknown>>,
      settings: { requireTwoStep: false },
      sso: null as Record<string, unknown> | null,
      me: null as Record<string, unknown> | null,
    }
    const record = (method: string, args: unknown[]) => { calls.push({ method, args }) }
    const overview = () => ({ owner: "person-ada", people: state.people, credentials: state.credentials.map(credential => ({ ...credential, rules: state.rules.filter(rule => rule.credential === credential.id).length })), rules: state.rules, waiting: state.waiting, settings: state.settings, sso: state.sso, activity: [{ at: now, person: "ada", action: "signin", outcome: "signed in" }] })
    const status = () => ({
      hub: state.hub ? { ...state.hub, people: state.people.length, credentials: state.credentials.length, rules: state.rules.length, waiting: state.waiting.length, requireTwoStep: state.settings.requireTwoStep, sso: Boolean(state.sso) } : null,
      hubError: null, member: state.member, memberError: null,
      me: state.me ? { ...state.me, overview: (state.me.person as { permission: string }).permission === "member" ? undefined : overview() } : null,
      suggestedAddress: state.hub ? null : "192.168.1.20",
      mcp: { command: "yougori", args: ["access", "mcp"] },
    })
    const meOf = (person: Record<string, unknown>, extra: Record<string, unknown> = {}) => ({ person, company: "Acme", accessId: "access-1", available: [], requests: [], canApproveOwn: true, strong: false, device: "device-1", twoStepRequired: false, blocked: false, sso: null, ...extra })
    Object.assign(window, { __access: { calls, state } })
    accessApi.status = async () => status() as never
    accessApi.create = async (...args: unknown[]) => {
      record("create", args)
      state.hub = { id: "access-1", company: String(args[0]), address: String(args[1]), port: 7465, fingerprint: "AB:CD", createdAt: now, tunnelPort: null, owner: "ada", signedIn: 1, invite: "access-invite:eyJ2IjoxfQ", closing: null }
      state.member = { accessId: "access-1", company: String(args[0]), hub: `${String(args[1])}:7465`, fingerprint: "AB:CD", username: String(args[2]), deviceId: "device-1", signedInAt: now, connected: true, error: null }
      state.me = meOf(ada)
      return { ...status(), message: "Acme's Access Grid is running and you are its admin." } as never
    }
    accessApi.signIn = async (...args: unknown[]) => {
      record("signIn", args)
      if (!args[3]) throw new Error(TWO_STEP_MESSAGE)
      const grace = { id: "person-grace", username: String(args[1]), name: "Grace Hopper", permission: "member", teams: ["Research"], createdAt: now, email: "grace@acme.example", twoStep: true, devices: [device("device-1", "This PC"), device("device-2", "Old laptop")] }
      state.member = { accessId: "access-1", company: "Acme", hub: "192.168.1.20:7465", fingerprint: "AB:CD", username: String(args[1]), deviceId: "device-1", signedInAt: now, connected: true, error: null }
      state.me = meOf(grace, { canApproveOwn: false, strong: true,
        available: [{ id: "cred-1", name: "GitHub", kind: "github-app", shortLived: true, destinations: ["https://api.github.com"], note: "Company org", uses: [{ ruleId: "rule-1", decision: "allow", methods: ["GET"], path: "/repos/acme", reveal: false, limit: 100 }, { ruleId: "rule-2", decision: "ask", methods: ["POST"], path: "", reveal: false }] }],
        requests: [{ id: "req-1", person: String(args[1]), agent: "Claude Code 2.1", computer: "LAPTOP", credential: "GitHub", credentialId: "cred-1", kind: "use", method: "POST", url: "https://api.github.com/repos/acme/app/issues", createdAt: now, expiresAt: now + 600, state: "waiting", decidedBy: null, why: "a rule says an approver decides" }] })
      return { ...status(), message: "Signed in to Acme's Access Grid as grace." } as never
    }
    accessApi.signOut = async (...args: unknown[]) => { record("signOut", args); state.member = null; state.me = null; return { message: "Signed out" } as never }
    accessApi.delete = async (...args: unknown[]) => {
      record("delete", args)
      if (args[0] === "later" && state.hub) state.hub = { ...state.hub, closing: { requestedAt: now, until: now + 3 * 86400, gone: false }, invite: undefined }
      else { state.hub = null; state.member = null; state.me = null }
      return { message: "Done" } as never
    }
    accessApi.restore = async (...args: unknown[]) => { record("restore", args); if (state.hub) state.hub = { ...state.hub, closing: null, invite: "access-invite:eyJ2IjoxfQ" }; return { message: "Restored" } as never }
    accessApi.account = async (request: Record<string, unknown>) => {
      record("account", [request])
      if (request.action === "twoStepStart") return { secret: "JBSWY3DPEHPK3PXP", link: "otpauth://totp/Acme%20Access%20Grid:ada?secret=JBSWY3DPEHPK3PXP" } as never
      if (request.action === "twoStepConfirm" && state.me) state.me = { ...state.me, strong: true, person: { ...(state.me.person as Record<string, unknown>), twoStep: true } }
      if (request.action === "deviceForget" && state.me) { const person = state.me.person as { devices: Array<{ id: string }> }; state.me = { ...state.me, person: { ...person, devices: person.devices.filter(own => own.id !== request.device) } } }
      return { message: "Done" } as never
    }
    accessApi.manage = async (request: Record<string, unknown>) => {
      record("manage", [request])
      if (request.action === "personAdd") state.people.push({ id: `person-${String(request.username)}`, username: request.username, name: request.name || request.username, email: request.email || null, permission: request.permission, teams: request.teams, createdAt: now, twoStep: false, devices: [] })
      if (request.action === "credentialAdd") state.credentials.push({ id: `cred-${state.credentials.length + 1}`, name: request.name, kind: request.kind, field: request.field, destinations: request.destinations, note: request.note, hint: "", createdAt: now, createdBy: "ada", updatedAt: now, config: request.config })
      if (request.action === "ruleAdd") state.rules.push({ id: `rule-${state.rules.length + 1}`, credential: request.credential, credentialName: state.credentials.find(credential => credential.id === request.credential)?.name, who: request.who, whoLabel: String(request.who).replace("team:", "team "), methods: request.methods, path: request.path, decision: request.decision, reveal: request.reveal, limit: request.limit ?? null, note: "", createdAt: now, createdBy: "ada" })
      if (request.action === "decide") state.waiting = state.waiting.filter(waiting => waiting.id !== request.request)
      if (request.action === "settingsSet") state.settings = { requireTwoStep: Boolean(request.requireTwoStep) }
      if (request.action === "ssoSet") state.sso = { issuer: request.issuer, clientId: request.clientId, claim: request.claim, passwordless: request.passwordless }
      if (request.action === "activityVerify") return { ok: true, entries: 12 } as never
      return { message: "Done" } as never
    }
  })
}

const calls = (page: Page) => page.evaluate(() => (window as unknown as { __access: { calls: Array<{ method: string; args: unknown[] }> } }).__access.calls)
const managed = async (page: Page, action: string) => (await calls(page)).filter(call => call.method === "manage" && (call.args[0] as { action: string }).action === action).map(call => call.args[0])

async function openAccess(page: Page) {
  page.on("pageerror", error => { console.log(`PAGEERROR ${error.message}\n${error.stack ?? ""}`) })
  await page.goto("/")
  await expect(page.getByRole("region", { name: "Environments workspace", exact: true })).toBeVisible({ timeout: 60000 })
  await mockAccess(page)
  await page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Access Grid", exact: true }).click()
  await expect(page.getByRole("region", { name: "Access Grid workspace" })).toBeVisible()
}

test("An admin hosts the Access Grid, sets it up, decides a request, and pauses it for deletion", async ({ page }) => {
  await openAccess(page)
  await expect(page.getByText("Host or sign in to an access grid")).toBeVisible()
  await page.getByRole("button", { name: "Host an access grid", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Host an access grid" })
  await expect(dialog.getByLabel("This computer's address")).toHaveValue("192.168.1.20")
  await expect(dialog).toContainText("port 7465")
  await dialog.getByLabel("Company name").fill("Acme")
  await dialog.getByLabel("Your username").fill("ada")
  await dialog.getByLabel("Your name").fill("Ada Lovelace")
  await dialog.getByLabel("Your password").fill("correct horse battery")
  await dialog.getByLabel("Type it again").fill("correct horse battery")
  await dialog.getByRole("button", { name: "Host access grid", exact: true }).click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).find(call => call.method === "create")?.args).toEqual(["Acme", "192.168.1.20", "ada", "Ada Lovelace", "correct horse battery", undefined])

  const workspace = page.getByRole("region", { name: "Access Grid workspace" })
  await expect(workspace.getByRole("region", { name: "Hosted access grid" })).toContainText("Hosted here · 192.168.1.20:7465")
  await expect(workspace.getByRole("region", { name: "Your sign-in" })).toContainText("Administrator at Acme's access grid")
  await expect(page.getByRole("navigation", { name: "Sections" }).getByRole("button", { name: "Access Grid", exact: true })).toContainText("1 person · 0 credentials")

  // Credentials: a preset fills the form; a minting kind asks for its settings.
  await workspace.getByRole("tab", { name: /Credentials/ }).click()
  const credential = workspace.getByRole("form", { name: "Add a credential" })
  await credential.getByLabel("Start from").selectOption("Microsoft Graph")
  await expect(credential.getByLabel("Name")).toHaveValue("Microsoft Graph")
  await expect(credential.getByLabel("Sent as")).toHaveValue("oauth")
  await credential.getByLabel("Client ID").fill("app-1")
  await credential.getByLabel("Client secret").fill("graph-secret")
  await credential.getByRole("button", { name: "Add credential" }).click()
  expect((await managed(page, "credentialAdd"))[0]).toMatchObject({ name: "Microsoft Graph", kind: "oauth", destinations: ["https://graph.microsoft.com"], value: "graph-secret", config: { tokenUrl: "https://login.microsoftonline.com/TENANT/oauth2/v2.0/token", clientId: "app-1", scope: "https://graph.microsoft.com/.default" } })
  await expect(workspace.getByRole("tabpanel")).toContainText("OAuth client credentials · token url")

  // People, with the email single sign-on matches.
  await workspace.getByRole("tab", { name: /People/ }).click()
  const person = workspace.getByRole("form", { name: "Add a person" })
  await person.getByLabel("Username").fill("grace")
  await person.getByLabel("Email").fill("grace@acme.example")
  await person.getByLabel("Teams").fill("Research")
  await person.getByLabel("Password", { exact: true }).fill("grace password 1")
  await person.getByLabel("Type it again").fill("grace password 1")
  await person.getByRole("button", { name: "Add person" }).click()
  await expect(workspace.getByRole("tabpanel")).toContainText("grace · grace@acme.example · Member · Research · two-step off")

  // Rules: a team may read at once, up to 50 an hour.
  await workspace.getByRole("tab", { name: /Rules/ }).click()
  const rule = workspace.getByRole("form", { name: "Add a rule" })
  await rule.getByLabel("Who").selectOption("team:Research")
  await rule.getByRole("group", { name: "Methods" }).getByLabel("GET").check()
  await rule.getByLabel("Uses an hour at once").fill("50")
  await rule.getByRole("button", { name: "Add rule" }).click()
  expect((await managed(page, "ruleAdd"))[0]).toEqual({ action: "ruleAdd", credential: "cred-1", who: "team:Research", methods: ["GET"], path: "", decision: "allow", reveal: false, limit: 50 })
  await expect(workspace.getByRole("tabpanel")).toContainText("GET any path · at once · 50 an hour, then an approver decides")

  // Settings: two-step required, and single sign-on.
  await workspace.getByRole("tab", { name: "Settings" }).click()
  await workspace.getByRole("tabpanel").getByRole("button", { name: "Require" }).click()
  expect((await managed(page, "settingsSet"))[0]).toEqual({ action: "settingsSet", requireTwoStep: true })
  const sso = workspace.getByRole("form", { name: "Single sign-on" })
  await sso.getByLabel("Issuer").fill("https://acme.okta.com")
  await sso.getByLabel("Client ID").fill("yougori-access")
  await sso.getByLabel("Sign-in port").fill("80")
  await expect(sso.getByRole("button", { name: "Turn on single sign-on" })).toBeDisabled()
  await sso.getByLabel("Sign-in port").fill("8765")
  await expect(sso).toContainText("http://127.0.0.1:8765/callback")
  await sso.getByRole("button", { name: "Turn on single sign-on" }).click()
  expect((await managed(page, "ssoSet"))[0]).toEqual({ action: "ssoSet", issuer: "https://acme.okta.com", clientId: "yougori-access", claim: "email", passwordless: false, redirectPort: 8765 })
  await workspace.getByRole("tab", { name: "Activity" }).click()
  await workspace.getByRole("button", { name: "Check the chain" }).click()
  await expect(workspace.getByRole("tabpanel")).toContainText("The chain checks out: 12 entries.")

  // A request waits for an approver, with what it would send and why.
  await page.evaluate(() => {
    const now = Math.floor(Date.now() / 1000)
    ;(window as unknown as { __access: { state: { waiting: unknown[] } } }).__access.state.waiting.push({ id: "req-9", person: "grace", agent: "Claude Code 2.1", computer: "LAPTOP", credential: "Microsoft Graph", credentialId: "cred-1", kind: "use", method: "POST", url: "https://graph.microsoft.com/v1.0/users", bodyBytes: 15, bodyPreview: "{\"title\":\"Bug\"}", createdAt: now, expiresAt: now + 840, state: "waiting", decidedBy: null, why: "past the hourly limit of 50 uses" })
  })
  const approvals = workspace.getByRole("region", { name: "Waiting for approval" })
  await expect(approvals).toContainText("grace via Claude Code 2.1 on LAPTOP · POST https://graph.microsoft.com/v1.0/users with Microsoft Graph", { timeout: 10000 })
  await expect(approvals).toContainText("Waits because past the hourly limit of 50 uses.")
  await approvals.getByRole("button", { name: "Approve for 1 hour" }).click()
  expect((await managed(page, "decide"))[0]).toEqual({ action: "decide", request: "req-9", approve: true, hours: 1 })
  await expect(approvals).toContainText("nothing right now")

  // Turning on two-step for the admin's own account.
  const account = workspace.getByRole("region", { name: "Your account" })
  await account.getByRole("button", { name: "Turn on" }).click()
  const confirm = account.getByRole("form", { name: "Confirm two-step sign-in" })
  await expect(confirm).toContainText("JBSWY3DPEHPK3PXP")
  await confirm.getByLabel("Six-digit code").fill("123456")
  await confirm.getByRole("button", { name: "Confirm" }).click()
  await expect(account).toContainText("On: new sign-ins ask for the code")
  expect((await calls(page)).filter(call => call.method === "account").map(call => (call.args[0] as { action: string }).action)).toEqual(["twoStepStart", "twoStepConfirm"])

  // Deleting asks when; in three days pauses it, and Restore takes it back.
  await workspace.getByRole("button", { name: "Delete grid" }).click()
  await workspace.getByRole("group", { name: "Delete the access grid" }).getByRole("button", { name: "In 3 days" }).click()
  await expect(workspace.getByRole("region", { name: "Hosted access grid" }).locator("..")).toContainText("Paused: deleted on")
  expect((await calls(page)).find(call => call.method === "delete")?.args).toEqual(["later"])
  await workspace.getByRole("button", { name: "Restore", exact: true }).click()
  await expect(workspace.getByRole("button", { name: "Delete grid" })).toBeVisible()
})

test("A person signs in with a two-step code, sees what their agents may use, and manages their computers", async ({ page }) => {
  await openAccess(page)
  await page.getByRole("button", { name: "Sign in", exact: true }).click()
  const dialog = page.getByRole("dialog", { name: "Sign in to an access grid" })
  await dialog.getByLabel("Invite").fill("access-invite:eyJ2IjoxfQ")
  await dialog.getByLabel("Username").fill("grace")
  await dialog.getByLabel("Password").fill("grace password 1")
  await dialog.getByRole("button", { name: "Sign in", exact: true }).click()
  await dialog.getByLabel("Two-step code").fill("654321")
  await dialog.getByRole("button", { name: "Sign in", exact: true }).click()
  await expect(dialog).toBeHidden()
  expect((await calls(page)).filter(call => call.method === "signIn").map(call => call.args)).toEqual([["access-invite:eyJ2IjoxfQ", "grace", "grace password 1", undefined], ["access-invite:eyJ2IjoxfQ", "grace", "grace password 1", "654321"]])

  const workspace = page.getByRole("region", { name: "Access Grid workspace" })
  await expect(workspace.getByRole("region", { name: "Your sign-in" })).toContainText("grace · Member at Acme's access grid · Research")
  const available = workspace.getByRole("region", { name: "What your agents can use" })
  await expect(available).toContainText("GitHub")
  await expect(available).toContainText("sent as short-lived tokens")
  await expect(available).toContainText("GET /repos/acme · at once · 100 an hour, then an approver decides")
  await expect(available).toContainText("POST any path · an approver decides")
  await expect(workspace.getByRole("region", { name: "Your requests" })).toContainText("waiting")
  await expect(workspace.getByRole("region", { name: "Waiting for approval" })).toHaveCount(0)
  await expect(workspace.getByRole("tab", { name: /Credentials/ })).toHaveCount(0)

  const account = workspace.getByRole("region", { name: "Your account" })
  await expect(account).toContainText("On: new sign-ins ask for the code")
  const computers = account.getByRole("list", { name: "Your computers" })
  await expect(computers).toContainText("This PC (this one)")
  await computers.getByRole("listitem").filter({ hasText: "Old laptop" }).getByRole("button", { name: "Sign out" }).click()
  await computers.getByRole("listitem").filter({ hasText: "Old laptop" }).getByRole("button", { name: "Confirm" }).click()
  await expect(computers).not.toContainText("Old laptop")

  await workspace.getByRole("region", { name: "Your sign-in" }).getByRole("button", { name: "Sign out" }).click()
  await workspace.getByRole("button", { name: "Confirm sign out" }).click()
  await expect(page.getByText("Host or sign in to an access grid")).toBeVisible()
})
