---
name: edit-inference-solver
description: Customize or extend this Inference Solver template's website, model receiver, private accounts and API relay while preserving its setup and access contracts.
---

# Edit Inference Solver

Work from this template's root. Read `README.md` for delivered capabilities and
limits; do not turn a catalog entry into a claim of a verified harness adapter.
This template is separate from My API.

The UI uses elements of prompx.com, the owner's site: one `site/style.css` with the
bundled Hanken Grotesk, a pale blue page in blues (no orange), two-tone headings, pills ending in an arrow
circle (added by `pill()` in `app.js`; the full label stays the accessible name),
light blue badges, flat square panels, and light/dark themes. The owner rejected several
decorative designs (pixel type, blueprint panels, gradients, oversized footers); do
not add decoration, hero illustrations or new sections. Tools show in four columns
and retain their existing card markup, spacing, colors and typography. Do not
redesign the cards. Clicking a harness opens its installation instructions inline
on the catalog page, never in a popup or a separate harness page. Harness filters and blue accents
come from `site/categories.json`; add categories there and assign harnesses in
`harnesses.json`. The model catalog's filters are Censored and Uncensored.

- `site/index.html`, `style.css`, `app.js`: design and interaction. Harnesses remain
  the first view, visible without sign-in along with Models. Account routes and
  inference remain authenticated. Escape user/model strings before inserting HTML; configuration
  values are data, never interpolated shell commands. Keep CSP-compatible external
  scripts/styles and narrow-screen layouts.
- `site/compute-ui.js`, `compute.py`, `compute_adapter.py`: inline, side-by-side
  Admin controls for local compute and cloud rental. All management runs on the
  website's backend, never the visiting admin's PC. Only fixed Yougori methods are
  allowed. Preserve fresh quotes, explicit cost approval, purchase idempotency,
  retained rental identities after errors, and automatic model registration.
  Model credentials stay on the node; provider login secrets are delivered once
  in memory, not written into jobs or exposed in snapshots. A website without a
  Yougori backend must report that limitation, not present a working rental.
- `site/compute_node.py`: optional contributor connector, with owner-selected
  model sharing, short-code approval and an optional join password. Contributors
  receive only inference and explicitly owner-authorized Sandbox VM jobs, never
  host shell commands, provider purchases or model-management jobs. Host revocation closes active relays and removes
  its models. Test with `tests/test_compute.py`; provider tests use a disposable
  transport, never a real purchase. Contributor installation reuses the verified
  Windows runtime preparation; it is separate from the VM harness runtime.
  The primary flow is `yougori inference connect URL` and
  `yougori inference run HARNESS --server URL`. Client code ships inside the
  Yougori CLI; never make users install separate solver commands or run a remote
  PowerShell installer. Both flows prepare and start immediately. Keep the
  original installer endpoints for explicit callers, without advertising them.
  Inference workloads use owner-managed timers (zero means until stopped),
  preserving stop, revoke, disconnect, engine supervision and resource limits.
  Use the shared `installCommand` for contributor and harness install commands.
  Contributor bundles include `harnesses/transport.py` for isolated `.localhost`
  origins. Run `tests/runtime_contributor_install.py` for the actual Yougori
  commands against a development VM, without contributing
  user resources or changing the user's PATH.
- `site/server.py`: sessions, authorization, CSRF and routes. Only CLI bootstrap
  creates the first administrator. `ACCOUNT_MODE` / `--account-mode` controls public signup
  versus private invitation-only access, independently of `WEB_ACCESS` or the URL.
  Signup creates members; only an existing admin can invite an admin or promote a
  member. Protect the last administrator atomically. Show signup on desktop and
  mobile only in public mode; reject its API in private mode. Enforce password,
  duplicate-account, same-origin and rate-limit checks on the server. Use the
  backend role check for every admin mutation, not only a hidden button.
- `site/store.py`: short-lived SQLite connections and transactions. Never share a
  connection across HTTP threads. API keys are hashed and shown once. Preserve
  existing local data; no migration work is in scope.
- `site/hosted.py`: website-created development VM bootstrap. Preserve per-instance
  identity, immutable account mode and imported onboarding credentials. Hosted
  SQLite uses a private working copy and an atomic staged-workspace snapshot before
  acknowledging writes; snapshot failures block further database work. Never grant
  this guest host engine access or silently enable cloud rental/payment settlement.
  Run `tests/test_hosted.py`; real multi-VM acceptance lives in the website repo.
  Hosted harness manifests contain publisher-verified immutable archives. Only
  these public bytes may use the development host's separate download endpoint;
  credentials and model requests remain bound to the VM site. Preserve the narrow
  origin check and hash/size verification in `vm_host.py`, the `.localhost`
  loopback pinning in `harnesses/transport.py`, and the matching PowerShell path.
  Test with `test_hosted_downloads.py` and `runtime_hosted_downloads.py`.
- `site/device_auth.py` and `site/harnesses/device_login.py`: short-code browser
  approval instead of manual key copying. Require an authenticated same-origin
  CSRF-protected decision, single-use expiring codes, rate limits and per-tool
  credentials. Only hashes are stored on the server. The CLI generates and saves
  its credential privately; it opens only its configured server, never a returned
  redirect URL. Test with `tests/test_device_auth.py` and `tests/device_browser.mjs`.
- `site/upstream.py` and `gateway.py`: pin validated network addresses, retain TLS
  hostname verification, reject metadata addresses, and never follow credentialed
  redirects. Enforce model scope before upstream traffic. Record failures and
  unknown token counts honestly; do not log prompts or secrets.
- `site/routing.py`: one public name per model across its replicas (connected computers
  and model servers). Keep a conversation on the replica holding its cache unless that one
  is full and another has room; fail over only before the first byte reaches the caller,
  never on a 400. Session hints (`X-Session-ID`, `prompt_cache_key`, `metadata.user_id`)
  only route and are never forwarded. Cached input tokens come from the server's report
  only. Test with `tests/test_routing.py`.
- `site/compute.py` connector stream (`action: stream`, `ack`): requests are pushed the
  moment they are queued, never more than the connector's capacity; an unacknowledged one
  fails over after `ACK_SECONDS`. Keep `poll`/`chunk` working for connectors already
  shipped in the CLI.
- `site/harnesses/`: downloaded source launcher, per-tool profiles, blue PTY and
  native Sandbox VM relay. Runtime clients use Yougori's VM API with no external
  network, host home, credential or container-engine mounts and no host fallback.
  Selected workspaces are staged copies. The real service key belongs only to the
  host relay. Dependency downloads happen while building OCI images before runtime.
  Test actual clients with `tests/runtime_harnesses.py`; configuration files alone
  do not establish runtime compatibility. Keep unavailable platforms explicit.
- `site/sandbox_grid.py`, `grid_adapter.py`, `sandboxes-ui.js`, `infrastructure-ui.js`:
  website VM scheduling, contributor limits and owner-bound job results. The
  Sandboxes page sits beside Models, shows contributed/free capacity, and manages
  guests without a setup. Admin retains the enable switch and contribution limits.
  Preserve idempotent launch, bounded leases, host-side capacity checks and no host
  filesystem access. Never retry an ambiguous launch or guest command automatically.
- `site/payments.py`, `payment_chain.py`, `payments-ui.js`: receiving wallets,
  mainnet invoice verification and atomic credit accounting. Read `docs/payments.md`.
  Preserve owner-bound random references, pinned tokens/chain identities, finality,
  unique transaction credits, integer amounts and concurrent request reservations.
  Admin prices are USD per million input/output tokens. Reserve a financial ceiling,
  bill only measured upstream usage, and commit usage with the charge. Missing or
  invalid counts release the hold and remain explicitly unbilled. Keep checkout
  inline. Never test by signing/broadcasting real transfers. A saved wallet alone
  is not evidence that a payment was received; fixtures are not live paid evidence.
- `site/control_panel.py`, `control-ui.js`: admin-only bounded telemetry, charts,
  presence and activity. Missing sensors remain unknown; never label cached data
  as a fresh host reading. Public capacity responses exclude private guest details.
- `site/install-harness.ps1`, `harness_download.py`, `harnesses/cli_entry.py`:
  retained explicit Windows installers. The primary UI uses the native Yougori inference commands. Keep PowerShell 5.1
  support, deterministic hashed archives, pinned private Python, safe extraction,
  per-user PATH registration, and independent commands for different servers.
  No installer credentials or machine-wide Python changes. Exercise the actual
  installer with `tests/windows_installer.py` in its disposable portable folder.
  Harness installation starts the command automatically after releasing the
  installer lock; only automation uses `INFERENCE_SOLVER_NO_LAUNCH=1`. Keep the
  inline install steps and later-use command. The retained contributor script
  does not auto-start; the native Yougori connect command does. Availability requires current published VM/tool artifacts,
  not just an implemented source profile. Run against the normal packaged guest
  as well as a fixture: a current isolated guest hid an outdated installed importer.
  Pi/Shannon must use the local chat contract (no provider storage extension,
  bounded output tokens); a permissive inference fixture is insufficient evidence.
  Shannon's default command stays at its in-VM prompt; check is explicit and must
  return to that prompt. No automatic scan. Preserve one VM across commands and
  stop it on exit. Tools are still prepared separately for each new VM. Keep
  internal worker output in the guest log, expose failures and preserve exit codes.
  `tests/runtime_shannon_session.py` checks repeated model calls, shell input and
  cleanup through the real VM, without running a scan.
- `site/protocols.py`, `google_protocol.py`: text/function adapters reuse gateway
  authorization and usage. Preserve namespaces/call IDs across turns. Buffered SSE
  is not native streaming; unsupported media/hosted tools must not be fabricated.
- `site/attached.py`: the `yougori-models.yaml` receiver consumes a temporary JSON
  file. Attach/detach are idempotent by model environment identity; changing the
  URL or key keeps model IDs stable. Delete the input file even on failure. Print
  only a final sanitized JSON acknowledgement. Detached endpoints lose their keys.

Keep manifest questions aligned with implemented behavior. Format-2 resource
`when` controls inclusion; question `when` alone only controls prompting. Do not
fix host ports. Read the current Yougori `docs/hub.md` when changing the manifest
or adding capabilities. Engine extensions belong in the shared planner/handlers,
not in an unrestricted engine shell endpoint exposed by this website.

Run `python -I -B tests/test_service.py`; from a checkout with Playwright installed,
run `node tests/browser.mjs` for UI changes. Run `yougori template check .` for
manifest edits. These checks are isolated and do not purchase GPUs or publish the
service. Runtime setup should use its own data, and be reported separately from
fixture-based verification. Do not package databases, credentials or `__pycache__`.
