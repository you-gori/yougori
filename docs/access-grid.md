# Access Grid: company credentials agents use without holding them

Implementation notes, 18 October 2026. This describes the source checkout, not an installed release.

Personal Vault MCP keeps one person's secrets on their own computer and asks them about every request. Access Grid is the company version: one trusted computer keeps the company's API keys and tokens, named people sign in from their own computers, and rules decide who may use which credential, for what, how often, and whether an approver must agree first. The central idea is that agents **use** credentials rather than **receive** them. An agent asks the hub to send an HTTP request with a credential; the hub adds the credential itself, sends the request only to that credential's destinations and returns the answer with the value hidden. For OAuth, GitHub App and AWS credentials the hub goes further and only ever sends, or hands out, short-lived tokens and signatures made from the long-lived secret.

It is its own grid, beside the Neo Grid and the Sandbox Grid: hub port 7465 (tunnel entry 7466), invite prefix `access-invite:`, record `grid/access-hub.json`, activity `grid/access-activity.jsonl`, sign-in `grid/access-member.json`, OS-vault entries `yougori-access-hub-key` (TLS key), `yougori-access-hub-seal` (sealing key) and `yougori-access-device` (this computer's device token). The desktop app has its own sidebar section, **Access Grid**; the CLI has `yougori access …` and an Access Grid submenu under MCP Vault.

## People and sign-in

- **Permissions**: member (uses what rules allow), approver (also decides requests and reads the grid), auditor (reads people, credentials without values, rules and activity), admin (everything). The owner, who created the grid on its computer, cannot be demoted or removed. Nobody decides their own request while someone else in the grid can.
- **Password sign-in**: the person's computer pins the hub's certificate by the invite's fingerprint, checks the company name, asks for the salt (unknown usernames get a stable decoy salt), derives the scrypt key locally and sends it over the pinned connection. The hub keeps only a SHA-256 hash of that key. Ten failed sign-ins from one address in ten minutes lock that address out for ten minutes.
- **Remembered computers**: every full sign-in returns an eight-hour session and a device token. The computer keeps the token in its OS vault (never the password or its key) and signs itself in again with it. The hub keeps only the token's hash, per person, with the computer's name and last use. A token lapses 30 days after its last use and ends at once when the person's password changes, two-step is reset, they or an admin sign them out everywhere, or that computer is signed out. A person keeps at most 20.
- **Two-step sign-in**: the person turns it on themselves (a TOTP secret and `otpauth://` link, confirmed with a first code). The secret is sealed like a credential. Password sign-ins then need the current code. With "require two-step", sign-ins without a second factor can enroll but cannot use, see or manage anything. The computer that confirmed the code counts as signed in with it.
- **Single sign-on (OpenID Connect)**: a public native app with PKCE, no client secret. The person's computer opens the provider in the browser, receives the code at `http://127.0.0.1:PORT/callback`, trades it for an ID token and brings that to the hub; the hub checks the signature against keys it fetches from the issuer itself (RS256/ES256), the issuer (the configured one, or the one its discovery document names, since Entra tokens carry the tenant's ID where an admin may type its domain name), audience, expiry and nonce, then matches the email claim (or another claim) against people's emails, else usernames; when `email` is missing, as Microsoft Entra sends it by default, `preferred_username` or `upn` stands in. Providers that require a client secret even for desktop apps (Google's) are not supported. The provider's own second factor counts. Entra ignores the port of a loopback redirect, so the app registers `http://127.0.0.1/callback` (in the manifest, as the portal refuses `http`) and any free port is used; Okta matches the port, so the admin sets a fixed sign-in port and registers it. Passwordless mode stops password sign-ins except the owner's.

## Credentials

- Values are sealed with ChaCha20-Poly1305 (ring), a fresh random nonce each time, bound to the credential's ID. A destination is `https://host[:port]` with an optional path prefix; plain `http://` is accepted only for private addresses. URLs with credentials, fragments, dot segments (also `..;`), `//` or encoded slashes and dots are refused.
- **Plain kinds**: bearer, header, basic, query. The hub puts the value on the request.
- **OAuth client credentials**: the value is the client secret; the hub fetches an access token from the token URL (client secret in Basic auth or the form body), caches it until five minutes before it lapses and sends that.
- **GitHub App**: the value is the App's private key (PEM, checked at entry by signing with it); the hub signs a ten-minute RS256 JWT, issued by the App's client ID (GitHub's recommendation) or its numeric App ID, and asks GitHub for a one-hour installation token, cached the same way.
- **AWS**: the value is `ACCESS_KEY_ID:SECRET_ACCESS_KEY`; the hub signs each request with SigV4 (region and service from the credential or the host). With a role ARN it first takes temporary keys from STS AssumeRole, the session named after the person, cached per person, so AWS's own CloudTrail says who. The session length (`sessionSeconds`, 3600 unless set) must not exceed the role's maximum session duration.
- **Reveal**: only where a rule has reveal on, and an approver decides every time. Plain kinds hand out the value; the minting kinds hand out a fresh short-lived token (OAuth, GitHub) or temporary AWS keys (AssumeRole, or GetSessionToken without a role), never the long-lived secret.

## Rules and requests

A rule names a credential, the people it covers (everyone, a team or one person), optional methods and path prefix (matched on whole segments, case-insensitively and with encoded letters decoded, so a `never` cannot be dodged by spelling), a decision (allow, ask, never), an optional hourly limit, an optional lapse, and whether reveal is allowed. A matching never wins; otherwise allow wins over ask; with no match the request is refused. Past an allow rule's hourly limit (counted per person), a request waits for an approver instead of failing.

Allowed requests are sent at once; the answer comes back directly when it arrives within eight seconds, otherwise the caller checks back with the request ID. Requests waiting for an approver wait up to 15 minutes; approvers see who asked, through which agent and computer, why it waits, the method, the URL without its query and up to 4 KB of the body. Approvers approve once, approve for up to 24 hours (a temporary allow rule for that person, method and path), or deny with a reason. Before sending an approved request the hub checks again that the person, the credential and its destination still exist and that no rule now forbids it. Answers lose `Set-Cookie`; the value and every token made from it are hidden wherever a service echoes them (raw, percent-encoded, JSON-escaped, and the Basic `user:value` base64); the agent gets at most 256 KiB of the body.

Approvers are notified on Windows when a request starts waiting for them, and in the app's sidebar and as an in-app notice.

## Activity log

Every use, refusal, decision, expiry, sign-in and change is appended to `access-activity.jsonl` (rotated at 8 MB into `.jsonl.1`; the chain carries on). Each entry holds an HMAC over itself and the previous entry's HMAC, keyed from the sealing key, so an edited, removed, inserted or reordered entry breaks the chain where it happened (`yougori access log --verify`, the page's "Check the chain"). Auditors export entries with their MACs (`yougori access log --export FILE`) to keep somewhere the hub's administrators cannot write; whoever controls the hub's OS account holds the key and could rewrite the whole chain, so the export is the real record.

## Lifecycle

- **Deleting**: later (default) pauses the grid for three days: every request is answered "paused" and the owner can restore it. Then, or with now, its credentials, people, rules and single sign-on are wiped from the record at once; the hub keeps answering "deleted" for 30 days so people's computers sign themselves out, then removes itself. forget removes it at once.
- **Backup and restore**: one file with the record, the activity log and both keys, sealed with a passphrase (scrypt, then ChaCha20-Poly1305). Restoring it on another computer at its own address keeps the certificate, so people's computers keep trusting it; pasting the new invite moves them there with their device token, without a password, and their remembered sign-ins carry over.
- **Moving address**: the same applies to a new tunnel link: an invite with the same fingerprint moves the sign-in.

## Trust boundaries and limits

- The hub computer, its administrators and its OS account are trusted: whoever controls that account can read the record and the sealing key together. Keep it on a computer that stays on, back it up, and keep the backup apart from its passphrase.
- On a person's computer, any program running as that person can ask the local engine to use what that person may use, as with their other Yougori sign-ins. Approvals, hourly limits and narrow rules are the controls for sensitive operations.
- A destination-bound credential still allows anything that destination's API allows within the rule; a prompt-injected agent can misuse a legitimate rule. Narrow methods and paths, hourly limits and ask rules for writes limit that.
- A revealed plain value leaves the company's control and cannot be recalled; prefer the minting kinds.
- The hub answers only private LAN/VPN addresses directly; people elsewhere use the optional Cloudflare tunnel, which relays the grid's own TLS pinned to the hub's certificate.
- Single hub, no failover; backups are the recovery. Limits: 1,024 people, 512 credentials, 4,096 rules, 16 destinations per credential, 20 computers per person, 16 open requests per person, 512 in flight, 2 MB request bodies, 60 seconds per request.
- Not merged into the Personal Vault MCP connection: agents connect to `yougori access mcp` separately, because the Personal Vault broker is a separately installed, signed process that identifies its clients by OS process.

## Code map

- Policy, sealing, sending, minting, SigV4, activity, backup, hub and client: `grid/src/access.rs`, `grid/src/access/{policy,seal,forward,mint,sigv4,activity,backup,hub,member}.rs`, `grid/src/access/hub/{people,admin,requests}.rs`; end-to-end tests over real pinned TLS with local mock services (token endpoint, GitHub, STS, an identity provider): `grid/src/access/tests.rs`. Invite prefix: `grid/src/invite.rs`. Reuses `grid/src/totp.rs` and `grid/src/jwt.rs`.
- Engine (hosting, sign-in, device tokens, methods, notifications, desktop commands): `src-tauri/src/accessgrid.rs`; dispatch group `dispatch_group_16` in `src-tauri/src/automation/dispatch.rs`; fast paths in `automation/queue.rs`.
- CLI and MCP server: `cli/src/access.rs`; contracts in `cli/src/catalog.rs`; launcher submenu in `cli/src/launcher/menu.rs`; guide section "Access Grid (company credentials for agents)" in `skills/yougori/references/cli.txt` (reference and schema topic `access-grid`).
- Desktop: `src/pages/access-page.tsx`, `src/components/access-admin.tsx`, `src/components/access-account.tsx`, `src/components/access-dialogs.tsx`, `src/components/use-access-status.ts`, `src/components/access-grid.css`, `src/api/access-api.ts`; sidebar entry in `src/components/app-shell.tsx`; browser flows in `e2e/access-grid.spec.ts`.

## Validation on this checkout

- Access Grid tests in the grid crate (`access::`): 26 passed, including SigV4 against AWS's published test vectors, OAuth and GitHub App minting against local mock services (the GitHub App test makes a throwaway RSA key with OpenSSL at test time), AWS AssumeRole and request signing checked by a mock service that verifies the signature itself, OpenID Connect sign-in against a mock identity provider, two-step codes, device tokens, hourly limits, deletion phases, and a backup restored on a new port with sign-ins and credentials still working.
- CLI library: 330 passed (help coverage, guide structure and schema topics included); CLI integration tests: 24 passed.
- `cargo check` and `cargo clippy` of the desktop native library: passed with no Access Grid warnings. The native test target does not build on this checkout because of unrelated in-progress files, so the dispatch contract was verified by script instead.
- Frontend: `tsc -b`, ESLint on the Access Grid files, Vitest, and the Playwright Access Grid flows (screenshots, traces and video off): passed.

Not done: a real installed build, the desktop app live against a real hub on two computers, real identity providers (Entra, Okta, Google) and real GitHub/AWS/OAuth services, Linux/macOS key storage, and load tests.
