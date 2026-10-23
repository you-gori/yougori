# Sandbox Grid: managed workspaces and enterprise connections

Implementation notes, 17 October 2026. This describes the source checkout, not an installed release or a certified enterprise deployment.

Sandbox Grid now has named administrative permissions, versioned prepared images, workspace roles, account-to-desk assignments, private image distribution, restricted desktop sessions, inbound file/folder uploads, and role-filtered launch connections for Citrix, Azure Virtual Desktop, Windows 365, and Omnissa Horizon.

The four provider connections open an existing customer deployment. They do **not** provision vendor infrastructure, install vendor agents, synchronize identities, apply vendor policies, or verify compliance. Customers can configure the connections themselves; the product developer does not need a personal tenant. Broker API adapters and a vendor validation lab remain future work.

## Customer setup

1. In Sandbox Grid, host a grid on a trusted computer. Use a stable private LAN/VPN address. The hub must remain available for management and desk authorization.
2. Join local machines and cloud machines using the grid invitation and computer-joining password. Set each computer's CPU, memory, disk, and availability allowance. Cloud hosts need a private route to users, generally through the customer's VPN.
3. In **Images**, publish a prepared disk with the operating system, desktop and required applications already installed. The local grid owner can choose a disk file; Yougori copies and hashes it. Alternatively, publish an HTTPS source and its SHA-256, or an immutable OCI reference containing `@sha256:`. Remote administrators use HTTPS/OCI sources, not paths on the hub filesystem.
4. In **Workspace roles**, select an image and access policy. Examples: “IT operations — India” and “Research — Kazakhstan”. The names describe teams; location does not establish data residency. Placement follows available host resources, not a regional policy.
5. In **People**, add named administrators and users. Choosing a workspace role while adding a person also orders their first desk atomically. A bad role or invalid account leaves neither half-created.
6. Users sign in with the grid invitation, their username and their own password. Their portal refreshes assignments and renewed invitations automatically. Open a ready desk to use its desktop and upload files or a folder.
7. In **Enterprise connections**, select the provider, enter the customer's HTTPS workspace URL and choose the roles that see it. An empty role selection shows it to all signed-in people. Users authenticate with the provider separately; Yougori does not store those credentials.

Prepared disks must be standalone, unencrypted, bootable with Yougori's VM firmware, and compatible with the host architecture and virtual hardware. An installer ISO or an application list is not a ready workspace. Applications listed in the catalog are descriptive: software must already be installed in the disk. Generalize reusable OS images and handle guest accounts, activation, licenses, updates and recovery credentials in the customer's image preparation process. VM boot and guest usability still require testing with each actual customer image.

## Administrative permissions

| Permission | Own assigned desks and portal | Read management status | Order, assign, retry desks; allocate computer resources | Accounts, catalog, roles, removals and connections |
| --- | --- | --- | --- | --- |
| User | Yes | No | No | No |
| Auditor | Yes | Yes | No | No |
| Operator | Yes | Yes | Yes | No |
| Administrator | Yes | Yes | Yes | Yes |
| Local grid owner | Local host control | Yes | Yes | Yes |

Administrative permission and workspace role are separate. An administrator can use a restricted desk while managing the grid. Editing a person's workspace role changes their portal connections and the default used for future desks; it does not silently replace existing desktops or their data. Publish a new image version and order replacement desks to roll out different software or access policies.

Management writes are authorized on the hub against the person's **current** role, then saved atomically. Sessions expire after eight hours, are kept in memory at the hub, and are invalidated by password changes or account removal. Password derivation occurs locally; passwords are removed before sending the management request. Saved client credentials use the existing OS vault. The latest 2,000 successful management changes form an operational activity log; this is not an external, tamper-proof compliance archive.

## Images, scheduling and lifecycle

Image name/version pairs are immutable. Referenced images and roles cannot be removed. Role-based orders include their pinned image, checksum, access policy and assignment generation. A host advertises desk protocol version 2 before receiving those orders; older hosts cannot accidentally run a managed desk without its policy.

For a local image, the hub retains `<grid-data>/images/<sha256>.img`. The authenticated member host fetches it as raw pieces of up to 8 MiB (`POST /grid/v1/desks/image`, the size in `X-Image-Size`), only while it is assigned a desk using that image; a 20 GB disk is a few thousand requests, hashed as they land. Person/admin sessions cannot use this download route. HTTPS images are downloaded without following redirects or accepting embedded URL credentials. Every host hashes the downloaded bytes and checks cached copies before use. Provisioning inspects the standalone disk format and virtual capacity, so a sparse file cannot silently exceed its declared disk allocation. OCI access depends on the host's existing registry configuration.

There is no default product limit on the **number of registered computers**. An administrator can optionally set one. This is not a claim of unlimited throughput: the current hub still bounds people to 512, desks to 256, workspace roles to 512, image versions to 1,024 and enterprise connections to 128. It is a single-hub service with no implemented HA failover or region-aware placement.

An unavailable or failing desk retains its order and reserved resources. Hosts wait for an initial successful check-in before reconciliation, so restarting with an empty in-memory order list does not delete retained desktops. Ownership is recorded before starting a new guest. Assignment generations reject stale reports and old invitations. Desk removal revokes access and deletes the guest on its host; host ownership remains tracked until deletion succeeds, allowing failed cleanup to retry. Delete desks only after arranging any administrator-managed retention or backup.

Catalog removal does not currently garbage-collect cached image bytes. Host administrators manage cache storage and backups. Existing legacy desks retain standard access; they are not retroactively relabelled as restricted.

## Restricted workspace boundary

Restricted roles require a full VM. The host creates it with guest networking disabled and checks its kind/network setting again when serving requests. A current hub lease is required for every recipient operation; an unreachable hub fails closed. Reassignment, password reset and account removal invalidate the previous assignment generation.

| Channel | Restricted desk behavior |
| --- | --- |
| Desktop | Pixels, keyboard and pointer interaction |
| Clipboard | Client-to-guest text permitted; guest-to-client clipboard blocked |
| Files and folders | Inbound upload batches only; no recipient read/download endpoint |
| Terminal, command output and logs | Refused by the host |
| Disk/image export and snapshots | No recipient operation exposed |
| Guest network | Disabled |
| Unknown desktop extensions | Refused; no file-transfer/extended clipboard negotiation |

The RFB 3.8 guard parses fragmented messages and negotiates raw pixels and desktop-size updates. It removes server clipboard messages before they reach the recipient. This favors a narrow protocol over bandwidth efficiency. Standard roles retain guest command/network access and are not appropriate for an upload-only data policy.

Uploads preserve relative folder paths, reject traversal/unsafe names and duplicate paths, check chunk offsets and declared lengths, and stage privately before creating an import drive. Current bounds are 1,000 files, 100 MiB per file, 512 MiB per batch, 16 staged batches per host, two per recipient, and 1 GiB total active staging. Abandoned staging expires after five minutes. There is no antivirus or content-disarm service in this change; customers must prepare guest-side controls if they need them.

Grid and host administrators, the host OS and the VM runtime are trusted. The policy does not stop photography, transcription, information encoded in visible pixels, malicious host administrators, or hypervisor vulnerabilities. It does not supply endpoint screen-capture prevention, watermarking, an Internet allowlist, or a complete enterprise DLP system. A launch connection to a vendor portal does not inherit these Yougori protocol controls.

Desk invitations are scoped to an assignment and expire independently of the eight-hour management session. Local sign-out removes the saved invitation; password reset/reassignment/removal is the mechanism for revoking a copied invitation. Sign-in itself can be a password, a password with a second step, or the company's identity provider (next section).

## Sign-in: two-step and the company's identity provider

- **Two-step** is the person's own: `mfaEnroll` (from the portal) shows a secret once as an `otpauth://` link, `mfaConfirm` with a first code turns it on, `mfaDisable` with a code turns it off. The hub keeps the secret only to check codes (RFC 6238, one step of drift either way) and never shows it again; an administrator can only `mfaReset` it, which also ends the person's sessions. A sign-in with two-step on answers `mfa_required` until the code is given (`desk login --code 123456`).
- **Company sign-in** (`ssoSet` with `issuer`, `clientId`, optional `usernameClaim` and `passwordless`) is OpenID Connect with a public native app and PKCE; there is no client secret anywhere. `GET /grid/v1/person/sso` tells a person's computer the issuer, client ID and endpoints (from the issuer's discovery document, fetched by the hub and kept for a day). The computer binds a loopback port, opens the browser on the authorization endpoint with `state`, `nonce` and an S256 challenge, takes the code the provider sends back, exchanges it at the token endpoint with the verifier, and posts the ID token and the nonce to `POST /grid/v1/person/sso` over the pinned connection. The hub verifies the signature (RS256 or ES256, `grid/src/jwt.rs`) against the keys it fetched itself from `jwks_uri` (kept an hour; fetched again at most once a minute when a token names an unknown key), then the issuer, the audience, the expiry and the nonce, and matches the `email` claim (or `usernameClaim`) to a person's email, set with `personUpdate {email}` or under Permissions. Wrong tokens count toward the same ten-strikes lockout as wrong passwords. `passwordless: true` refuses password sign-ins. The provider's own second factor counts; the grid's two-step is not asked after a company sign-in.

## Provider setup and research

The product includes provider policy-guide links in the connection form. Customers need their own deployment, supported clients, identity configuration, licenses and administrative access.

| Provider | Connection target | Customer-side configuration |
| --- | --- | --- |
| Citrix | Workspace or StoreFront web URL | Configure delivery-group entitlements and the applicable HDX policies. Check clipboard direction and separate file/drive/USB/print channels. Citrix documents clipboard as a channel separate from file transfer and drag/drop. [Citrix clipboard overview](https://docs.citrix.com/en-us/citrix-virtual-apps-desktops/policies/reference/ica-policy-settings/clipboard-redirection/overview.html) |
| Azure Virtual Desktop | Customer's Windows App web workspace | Configure Entra identities and application-group assignments. Clipboard policy combines host configuration and host-pool RDP properties; the most restrictive setting wins. Direction-specific support must be checked for the actual OS/client version. [Microsoft clipboard configuration](https://learn.microsoft.com/en-us/azure/virtual-desktop/redirection-configure-clipboard) |
| Windows 365 | Customer's Windows App / Cloud PC portal | Provision and assign Cloud PCs in the customer's tenant. Manage redirection with Intune or Group Policy; a portal link cannot apply those settings. [Windows 365 redirection administration](https://learn.microsoft.com/en-us/windows-365/enterprise/manage-rdp-device-redirections), [Microsoft clipboard configuration](https://learn.microsoft.com/en-us/azure/virtual-desktop/redirection-configure-clipboard) |
| Omnissa Horizon | Customer's Horizon HTML Access portal | Configure pool entitlements and Horizon Agent/client policies. Clipboard behavior depends on administrator policy and the client. Evaluate drive, USB, printing and browser file transfer separately. [Horizon clipboard documentation](https://docs.omnissa.com/HorizonClientLinuxGuide-Vmulti/CopyingandPastingText) |

For an inbound-only customer policy, validate every supported client and OS combination: allow the required inbound route, attempt outbound clipboard/files, check drive/USB/printing, and check guest network paths. Keep unsupported channels disabled. A browser launch, account entitlement or policy document by itself is not evidence of an effective restriction. Tenant-policy verification and directory synchronization are not done by Yougori; provisioning is, with the administrator's own credential, as follows.

### Connectors: assigning people at the provider

Like an automation tool, Yougori does nothing at a provider until the administrator enters that provider's credential. `connectionAdd` (or `connectionCredential` on an existing connection) with a `credential` object splits it on the hub computer: the one secret field (`clientSecret`, or Horizon's `password`) goes to that computer's OS vault (`yougori-desks-connection-<id>`) and into the running hub's memory; the identifiers (`target`) go to the record, where status shows them with `credentialSet` and `credentialAt`. Credentials are therefore entered on the computer that hosts the grid. `connectionCredential {set:false}` deletes the secret; `connectionRemove` deletes it too and leaves the provider as it is.

Tasks are queued in the record (`enterprise.provisioning`: `test`, `assign`, `revoke`; `pending → running → done|failed` with a note) by `connectionTest`, `connectionProvision {id, personId}` and `connectionRevoke`, and by `personRemove` for every connector whose last finished word on that person was an assignment. The hub computer runs them (`src-tauri/src/deskgrid.rs::provisioning_tick` → `grid/src/provisioning.rs`) and reports the outcome; the same task is not queued twice while one waits, and a failed task is never retried on its own. People are matched by their email, which the person must have on the grid. Notes never contain the secret; provider error messages are quoted after the status code.

| Provider | Credential (`target` + secret) | What `assign` does | `test` |
| --- | --- | --- | --- |
| Azure Virtual Desktop | `tenantId`, `clientId`, `clientSecret`, `subscriptionId`, `resourceGroup`, `applicationGroup` | Client-credentials tokens from Entra ID for Microsoft Graph and Azure Resource Manager; the person's object ID from Graph (`/v1.0/users/{email}`); a role assignment of **Desktop Virtualization User** (`1d18fff3-a72a-46b5-b4a9-9b93932cf3e9`) scoped to the application group. `revoke` lists the assignments at that scope for that principal and deletes only those with that role. The app needs `User.Read.All` and User Access Administrator on the application group. | Reads the application group and names its host pool. |
| Windows 365 | `tenantId`, `clientId`, `clientSecret`, `groupId` | Adds the person to the Entra group the provisioning policy is assigned to (`POST /v1.0/groups/{id}/members/$ref`); Windows 365 provisions the Cloud PC by its policy. `revoke` removes the membership. The app needs `GroupMember.ReadWrite.All` and `User.Read.All`. | Reads the group. |
| Citrix Cloud | `customerId`, `clientId`, `clientSecret`, `deliveryGroup` | A token from `cctrustoauth2`, the site from `cvad/manage/me` (`Citrix-InstanceId`), then the DaaS "edit delivery group" call (`PATCH DeliveryGroups/{name}`) with `Users: [email]`; `revoke` sends `RemoveUsers`. | Reads the delivery group and its desktop count. |
| Omnissa Horizon | `username`, `domain`, `password`, `pool` (API under the connection's URL) | `POST /rest/login`, the directory user from `/rest/external/v1/ad-users-or-groups` by user principal name, then `POST /rest/entitlements/v1/desktop-pools` with the pool and the user; `revoke` is the `DELETE` of the same. | Reads the desktop pool. |

The connectors are tested against mock servers that record every call (`grid/src/provisioning.rs` tests, `grid/src/end_to_end.rs`), not against the four live services; the request shapes follow each provider's published management API and may need adjusting on first contact with a real tenant. Clipboard, drive and network policies, session limits and the providers' own MFA remain the providers'.

### Parking and a cloud computer

Both take the administrator's own credentials once, on the hub computer, through the Settings tab or `desks manage`:

- `parkingSet {provider: awsS3|s3Compatible, location, accessKey, secretKey}`: the place is on record, the keys in the hub computer's vault and the running hub only. A moving desk is packed into the bucket by the computer giving it up and fetched by the one taking over; the keys reach only those two computers, for that move, over the pinned connection; the parked copy is deleted once the new computer reports the desk running. Lifts the 64 GB limit of hub parking. `parkingClear` forgets the keys.
- `cloudFallbackSet {provider: aws|google|azure, account, region, image, imageProject, machineType, subnet, securityGroup, keyPair, resourceGroup, sshPublicKey, username, identityFile, maxComputers}`: when a desk has waited an hour with no room anywhere, the hub computer runs the admin's own signed-in `aws`, `gcloud` or `az` to create one Linux VM, installs Yougori over SSH with `identityFile`, and hands it a ready-made membership (`preregister_member`; the token travels over SSH, never printed) that it takes up with `yougori desks adopt`. The grid must be reachable from the cloud (`--tunnel`). A cloud computer that hosts nothing for an hour is deleted. `cloudFallbackClear` turns it off.

## CLI and implementation map

There is one management core, `grid/src/hub/enterprise.rs::manage`: every change to people, desks, computers' shares and the catalog goes through it, whether it arrives from the local owner's `yougori desks add-person|add-desk|share|remove…` commands and the desktop page, or from a signed-in administrator's `desks manage` session. The same authorization, atomic save, session and invitation invalidation and audit entry apply to all of them. `personAdd` and `deskOrder` take either a workspace `roleId` (image and policy from the catalog) or a plain `spec` (`{kind,cpu,memoryGb,diskGb,gpu,image}`), which is what the page's "Add person and their desk" form sends: a standard container of that size, no catalog needed. `computerRemove` takes the computer out and puts its desks back into waiting to be placed again (a desk that had failed there is tried elsewhere up to the usual limit); their data stays on the removed computer and the trail leads back to it if it rejoins.

`yougori desks manage --file - --yes` accepts an object with a `request` property. The dispatcher uses the local owner or the signed-in named administrator. Use stdin for passwords, never shell arguments. `yougori desk refresh` refreshes portal assignments; `yougori desk logout --yes` removes the local sign-in.

Example management request (no credentials):

```json
{"request":{"action":"imageImport","path":"C:/Prepared/research.qcow2","name":"Research workstation","version":"2026.10","applications":["Python","RStudio"],"spec":{"kind":"vm","image":"","cpu":2,"memoryGb":4,"diskGb":40,"gpu":false}}}
```

`imageImport` is local-owner-only. After publishing, use `roleAdd` with the image ID and `access: "restricted"`, then `personAdd` with the role ID and a password supplied on stdin. Other actions are documented by `yougori schema desks_manage`.

- Policy/model and real TLS tests: `grid/src/enterprise.rs`, `grid/src/hub/enterprise.rs`, `grid/src/enterprise_tests.rs`, `grid/src/end_to_end.rs`.
- Sign-in: `grid/src/totp.rs` (two-step), `grid/src/jwt.rs` and `grid/src/https.rs` (identity provider tokens and keys), `member::person_login_sso` (the PKCE flow on the person's computer).
- Connectors, parking and the cloud computer: `grid/src/provisioning.rs`, `src-tauri/src/desks/parking.rs`, `src-tauri/src/desks/moving.rs`, `src-tauri/src/desks/cloud.rs`.
- Native management, placement follow-through and session refresh: `src-tauri/src/deskgrid.rs`, `src-tauri/src/desks.rs`.
- Image transfer and inbound staging: `src-tauri/src/desks/media.rs`, `src-tauri/src/desks/uploads.rs`.
- Recipient enforcement: `src-tauri/src/peer_sharing.rs`, `src-tauri/src/remote_access/rfb_guard.rs`, `src-tauri/src/remote_access/desktop.rs`.
- Admin UI and user portal: `src/components/sandbox-grid-admin.tsx`, `src/components/desk-portal.tsx`, `src/components/desk-upload.tsx`.

## Validation and remaining release work

Checks completed on this checkout:

- Grid library: **104 passed, one ignored** (sign-in through a mock identity provider, connector tasks, the four provider mocks, parking, cloud membership, deletion, hand-off). The ignored test opens a live Cloudflare tunnel.
- CLI library, including parser/catalog/help and embedded skill contracts: **329 passed, two ignored**.
- Focused UI tests (admin, upload, remote workspace and display): **15 passed**.
- Playwright Sandbox Grid flows: **three passed**, with screenshots/video/traces disabled.
- RFB guard tests compiled directly from the actual source with `rustc --test`: **six passed**, including fragmented authentication and clipboard frames.
- `npm run lint` and `npm run build`: passed. Vite reports existing mixed static/dynamic import warnings.
- Desktop native library `cargo check --locked --manifest-path src-tauri/Cargo.toml --lib`: passed.
- Standalone engine `cargo check --locked --manifest-path engine/Cargo.toml`: passed. The engine lockfile was synchronized with the checkout's existing ZIP feature configuration. Shared Tauri handle imports were corrected for the engine-only runtime.
- `npm run check:native -- --message-format short`: **blocked** by the existing SW-001 finding: `src-tauri/src/swarm/practice.rs:619-620` references removed `bounty_practice::oracle`. Full native tests, including the upload module's unit tests, remain unverified. The separate RFB tests do not replace a full native run.

Browser tests use a mocked engine and do not prove VM boot or provider interoperability. Core integration tests use real pinned loopback TLS and disposable accounts; they cover permission changes, revocation, atomicity, image access and computer limits.

Before claiming production readiness, run prepared-image boot/upload tests on the supported host OSes, customer VPN connectivity tests, adverse lifecycle/storage tests, scale/load tests, and the vendor-specific client/policy matrix. No live vendor tenant or production deployment was available or modified. No installer was built or installed by this change.
