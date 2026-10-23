# Enterprise adapter matrix

What a Yougori grid can connect to, and the honest state of each one. The plan this implements
names more than a hundred systems. Nineteen of them have met something.

This page is not written by hand. It is rendered from one table, `INTEGRATIONS` in
`grid/src/core/connector/registry.rs`, and a test in that module fails when the two stop agreeing.
A row cannot be improved here without being improved in the code, and a connector that grows
cannot leave this page saying something kinder than the truth.

## Nothing here has been tested against a real system, and here is why

There is no live tenant in this repository. There is no vendor library in it, and no customer
credential. Reaching a live target from here is forbidden, so nothing below has met a real system
and nothing below claims to have. That is not a gap waiting to be filled in by running the tests
somewhere else: it is a rule this work was done under, and a row that said otherwise would be the
one thing this page exists to prevent.

What the connectors that are exercised have met is a server running on this computer that answers
the way the provider's published API documents. For two of them it does more than answer: the
Amazon fixtures recompute the Signature Version 4 signature from the canonical request and refuse
one that does not match, so a signing mistake is a failed test rather than a passing one.

Three of the nineteen are not connectors and met no server at all. They are the hardware rows,
where this computer reads itself: battery and power state, processors and memory and disk, and
whether a card is present and how much memory it has. What is exercised for those three is a set
of parsers over fixture bytes, plus one test that reads whatever computer the suite is running on.
Each of the three says so in its own evidence, and the sentence beside the state in the table
below says it too.

That proves the shape of each request, the order of the calls, which token goes to which address,
and that a secret is sent only to the provider's own sign-in. It proves nothing whatever about a
real tenant. A provider may want a header nobody documented, may answer a conflict where the
documentation says it answers success, or may have changed its API since this was written. The
request shapes may need adjusting on first contact, and saying so here is better than a customer
finding out.

For the four audit sinks that render a vendor's envelope, there is a second thing that cannot be
known from here and never will be, which is **acceptance**. The bytes can be asserted against the
published format. Whether a Splunk index exists, whether a Microsoft Sentinel data collection rule
is bound to a stream, whether an Elastic data stream will take a write, and whether any of the
three rejects a batch for a reason that is not in its documentation are four questions this
repository cannot ask. Those rows say so in the same words, and they stay where they are however
carefully the envelope is rendered.

## How to read the table

The state is about this connector seam and only about it. A row can say there is no connector
while the product already does the same job another way, because having a shipped feature is not
having a connector. The last column is where that is said, in the same row, so neither fact can be
read without the other.

Some rows are not remote systems at all, and they are in the table because leaving them out would
make the table look like the whole answer when it is not. The operating system's credential vault
is on the computer the grid runs on, and real code reads and writes it; what has never been
exercised is the vault of whoever is running the tests, because doing that would write into a
person's own Credential Manager or Keychain. The hardware rows are this computer reporting on
itself, which has no credential and no tenant. Both say so in their own words.

A row that names several systems can carry one state only while all of them are in it. Four rows
that used to bundle several were split in this phase, because one member of each had moved and the
others had not, and a test now refuses to let a split row come back.

## What the states mean

| State | Rows | Means |
| --- | --- | --- |
| **Live-tested** | 0 | A connector exercised against the real system, with the result recorded. Nothing here is in this state. |
| **Mock-tested** | 19 | A connector written against the provider's published management API and exercised against a server on this computer that imitates it. It has never met a real tenant. Three rows in this state are not connectors and met no server at all: they are this computer reading itself, with their parsers exercised over fixture bytes, and each says so in its own evidence. |
| **Interface only** | 17 | A connector that implements the trait with no provider behind it. |
| **Roadmap** | 34 | Named in the plan, with no connector written. The last column says what the product already does another way, when anything does. |

## Desktop and session platforms

Seating a named person at a desktop the company already runs. This is the only area with connectors in it.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| Azure Virtual Desktop | The Desktop Virtualization User role on an application group, through Entra ID for the token, Microsoft Graph for the person and Azure Resource Manager for the assignment | Mock-tested | grid/src/provisioning.rs, exercised against a loopback server that imitates Entra ID, Graph and Resource Manager; behind this seam through core::connector::desktop, which wraps it without changing it | The Sandbox Grid assigns and takes back desktops here when an administrator has entered a credential |
| Windows 365 | Membership of the group a provisioning policy is assigned to, through Microsoft Graph | Mock-tested | grid/src/provisioning.rs, exercised against a loopback server that imitates Entra ID and Graph; behind this seam through core::connector::desktop | The Sandbox Grid adds and removes people from the policy's group when an administrator has entered a credential |
| Citrix DaaS | The users of a delivery group, through the Citrix Cloud DaaS management API | Mock-tested | grid/src/provisioning.rs, exercised against a loopback server that imitates Citrix Cloud; behind this seam through core::connector::desktop. Citrix Cloud only | The Sandbox Grid edits the delivery group's users when an administrator has entered a credential |
| Omnissa Horizon | Desktop pool entitlements, through the Connection Server REST API | Mock-tested | grid/src/provisioning.rs, exercised against a loopback server that imitates a Connection Server; behind this seam through core::connector::desktop | The Sandbox Grid entitles and disentitles people on the pool when an administrator has entered a credential |
| Citrix Virtual Apps and Desktops on premises | The users of a delivery group on a site the customer runs themselves | Roadmap | No code anywhere in this repository. The Citrix connector that exists speaks Citrix Cloud and nothing else | Nothing |
| Amazon WorkSpaces | Directory assignment of a workspace to a person | Roadmap | No code anywhere in this repository | Nothing |
| Amazon AppStream 2.0 | Stack entitlement for a person | Roadmap | No code anywhere in this repository | Nothing |
| Google Cloud virtual workstations | Workstation assignment for a person | Roadmap | No code anywhere in this repository | Nothing |

## Identity

Who somebody is, decided by the company's own provider rather than by us.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| OpenID Connect sign-in | A person signs in at their own provider and the hub checks the token against keys it fetched from the issuer | Roadmap | Not a connector and does not implement this trait; there is nothing here to discover, plan or revoke | Both grids already sign people in this way. grid/src/jwt.rs checks RS256 and ES256 tokens against the issuer's own keys, exercised against a local issuer in its tests |
| Local password and two-step | A password proof plus a code from an authenticator app | Roadmap | Not a connector; there is no outside system in it | Ships in both grids: grid/src/password.rs and grid/src/totp.rs, each with its own tests |
| SAML 2.0 | Signed assertions, for federations that require them | Roadmap | No code anywhere in this repository | Nothing |
| SCIM 2.0 | Group membership for a named person, through the client half of RFC 7644: find them by userName, read the group, and patch its members | Mock-tested | grid/src/core/connector/scim.rs, exercised against a loopback server that answers the way RFC 7644 describes, including answering a second add with 204 rather than a conflict. Only the client direction; a SCIM server, where the company's directory pushes people at this grid, is not a connector and is not written | Nothing |
| Microsoft Entra ID as a management target | A client-credentials token at the tenant's own endpoint, and Microsoft Graph for the person behind an email | Mock-tested | grid/src/provisioning.rs microsoft_token and graph_user, exercised against a loopback server that imitates Entra ID and Graph. It sits inside the Azure Virtual Desktop and Windows 365 connectors rather than being a connector of its own, and this row exists because that work was invisible in this table | Both desktop connectors sign in this way |
| Okta | Sign-in through the issuer's own discovery document, and later SCIM for provisioning | Roadmap | No code anywhere in this repository names Okta. The generic OpenID Connect path would sign a person in and has never been pointed at Okta; the SCIM client in this repository has never been pointed at Okta either | Nothing |
| Auth0 | Sign-in through the issuer's own discovery document | Roadmap | No code anywhere in this repository names Auth0, for the same reason as the row above it | Nothing |
| LDAP | Directory lookup over the wire protocol a directory speaks | Roadmap | No code anywhere in this repository, and it should not be written here: LDAP is BER over TCP, and a client and a fixture both written in this repository would prove only that they agree with each other, which is not interoperability with a real directory. The Horizon connector asks Horizon to do its own directory lookup; it speaks no directory protocol itself | Nothing |
| Active Directory | Directory lookup and group membership at a domain the customer runs | Roadmap | No code anywhere in this repository. LDAP's problem, and then SASL with GSSAPI on top of it, which is out of reach here. Where a directory is genuinely needed, Microsoft Graph is the route that is exercised | Nothing |
| WebAuthn and FIDO2 | Sign-in bound to a device the person holds | Roadmap | No code anywhere in this repository. Checking an assertion is offline-verifiable in principle, with ring for the signature and a software authenticator written in a test, and it needs a CBOR decoder this build does not have. Checking an attestation statement is a larger job again and should not be bundled with it | Nothing |
| Smart cards | Sign-in with a certificate on a card the person holds | Roadmap | No code anywhere in this repository. It needs client-certificate TLS, which this grid's HTTP client does not do, and a reader on the person's own computer | Nothing |

## Compute, virtualisation and orchestration

Where work runs when it does not run on a computer the grid already holds.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| Amazon EC2 | Read only: the instances a credential reaches in one region, through the Query API, signed with Signature Version 4 | Mock-tested | grid/src/core/connector/cloud.rs, exercised against a loopback server that recomputes the Signature Version 4 signature from the canonical request and refuses one that does not match. Read only, and structurally so: every step of its plan reads, and core::connector::cleared refuses to carry out a plan with no altering step | An administrator can create a cloud computer from the app: src-tauri/src/cloud_deployment.rs runs their own signed-in aws command, which is not this connector and reaches no account from this repository |
| Amazon ECS | Read only: the clusters a credential reaches, through the JSON API that names what it wants in an X-Amz-Target header | Mock-tested | grid/src/core/connector/cloud.rs, exercised against the same loopback server, which checks the signature the same way. Read only | Nothing |
| Amazon EKS | Read only: the clusters a credential reaches, through the control plane's REST API | Mock-tested | grid/src/core/connector/cloud.rs, exercised against the same loopback server. Read only. The control plane only: authenticating inside a cluster is a pre-signed STS URL and is not written | Nothing |
| Azure virtual machines | Read only: the machines in a resource group, through Azure Resource Manager, with a client-credentials token from the tenant's own endpoint | Mock-tested | grid/src/core/connector/cloud.rs, exercised against a loopback server that imitates Entra ID and Resource Manager and refuses a token it did not mint. Read only. The test asserts the client secret goes to the sign-in and nowhere else | An administrator can create a cloud computer from the app with their own signed-in az command |
| Google Cloud compute | Creating a machine and joining it to the grid | Roadmap | No connector. It is the cheapest of the three to describe and the dearest to build here: a service account signs a JWT assertion with RS256 and exchanges it for a token, and grid/src/jwt.rs only checks RS256 signatures, it does not make them. That is new code nobody has written, not an existing path pointed somewhere else. src-tauri/src/cloud_deployment.rs runs the administrator's own signed-in gcloud command | An administrator can create a cloud computer from the app and join it to the grid |
| A machine the administrator already has, over SSH | Installing on a server somebody already owns and joining it to the grid | Roadmap | No connector. src-tauri/src/runtime/cloud runs Yougori on an existing server over pinned SSH, and src-tauri/src/desks/cloud.rs does the same for a computer the hub created; neither is exercised against a server in this repository | An administrator can connect an existing server from the app |
| A container as a research enclosure | An unprivileged OCI container holding one research run, with no network interface unless its plan names one | Roadmap | No connector, and not this trait: grid/src/core/research.rs defines the Enclosure seam and holds no implementation of it. The container runtime it would be built from is src-tauri/src/runtime, and src-tauri/src/commands.rs::update_container_network opens and closes a container's network | Yougori runs unprivileged OCI containers on this computer, and the Sandbox Grid builds desks in them |
| A microVM as a research enclosure | A microVM holding one research run, with the host filtering its one shared interface | Roadmap | No connector, and not this trait. src-tauri/src/runtime/microvm_network.rs already filters that interface on the host side, where the guest cannot undo it; nothing wires it to a research plan | Yougori runs microVMs on this computer with host-side network filtering |
| A virtual machine as a research enclosure | A full virtual machine with its own firmware holding one research run | Roadmap | No connector, and not this trait. src-tauri/src/runtime/vm.rs and vm_security.rs are the machines and the Windows secure profile; nothing wires either to a research plan | Yougori runs full virtual machines on this computer |
| A GPU sandbox as a research enclosure | A machine with a card attached holding one research run, where the card's isolation has been recorded | Roadmap | No connector, and not this trait. src-tauri/src/runtime/gpu.rs and cuda.rs attach cards; what a card's isolation really is still comes from a person asserting it through Core::set_gpu_isolation, and nothing here reads it from a driver | Yougori runs NVIDIA GPU containers, and the scheduler refuses to share a card whose isolation nobody has recorded |
| VMware vSphere | Virtual machines on a cluster the customer runs | Roadmap | No code anywhere in this repository. The REST API is JSON with a session header and could be built to the same state as the rows above it; the older SOAP management API could not, and a connector would have to say which of the two it speaks the way the Citrix row already says Citrix Cloud only | Nothing |
| OpenStack | Read only: the instances of one project, through Nova, with a Keystone token got from a password | Mock-tested | grid/src/core/connector/cloud.rs, exercised against a loopback Keystone that answers with its token in X-Subject-Token the way the standard says, and a loopback Nova that refuses any other token. Read only | Nothing |
| Hyper-V, Proxmox, Nutanix and KVM managers | Virtual machines on a hypervisor fleet the customer runs | Roadmap | No code anywhere in this repository. Yougori runs its own containers, microVMs and VMs on a computer and manages no hypervisor fleet | Nothing |
| Kubernetes | Read only: the nodes of a cluster and whether each one is ready, through the API server with a bearer token | Mock-tested | grid/src/core/connector/cloud.rs, exercised against a loopback API server that refuses any other token. Read only, and bearer tokens only: a cluster that authenticates with a client certificate needs mutual TLS, which grid/src/https.rs does not do, and nothing here claims otherwise | Nothing |
| Slurm, Nomad and Ray | Submitting work to a scheduler the customer runs | Roadmap | No code anywhere in this repository | Nothing |

## Remote access

Reaching a desktop or a shell on a machine somewhere else.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| RDP | Opening a Windows desktop session on a machine elsewhere | Roadmap | No code anywhere in this repository | Remote desktop here is VNC carried over the authenticated gateway, in src-tauri/src/remote_access/desktop.rs |
| WinRM | Running a command on a Windows machine elsewhere | Roadmap | No code anywhere in this repository | Nothing |

## Storage

Where a workspace's packed-up data waits while it moves, and where backups go.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| S3 and S3-compatible object storage | Read only: what a credential reaches in one bucket, through the REST API with XML listings, signed with Signature Version 4 | Mock-tested | grid/src/core/connector/cloud.rs, exercised against a loopback server that recomputes the signature and refuses one that does not match. Read only. Separately, src-tauri/src/desks/parking.rs parks data through the object_store crate, and its tests run against a folder on this computer, so that path's S3 protocol is exercised nowhere here | A desk's data parks in the company's bucket while it moves, when an administrator sets one |
| Azure Blob Storage | Read only: what a credential reaches in one container, signed with the account's shared key | Mock-tested | grid/src/core/connector/cloud.rs, with the shared-key signature asserted against the exact string Microsoft documents and exercised against a loopback server. Read only. The key signs each request and never travels on one | Nothing |
| Google Cloud Storage | The same parking, in a Google bucket | Roadmap | No connector. It needs the same service-account assertion the Google compute row needs, which is RS256 signing that nothing in this repository does | Nothing |
| NFS and SMB | The same parking, on a file server | Roadmap | No code anywhere in this repository, and none should be written: both are binary protocols with their own authentication, and the honest design is to let the operating system mount them and treat the result as a path, which is not a connector at all | Nothing |
| Ceph | The same parking, on a cluster the customer runs | Roadmap | No code anywhere in this repository. Reachable as S3 through its own gateway, in which case it is the S3 connector pointed elsewhere; librados is a C library and is out of reach here | Nothing |

## Secret keepers

Where the values a grid brokers are actually kept. These are `core::vault::Vault`, not this nine-operation connector trait, so none of them is a connector and every row says Roadmap or Interface only for that reason alone. The question of where a realm's own signing key lives is a different one and is in the hardware area.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| the operating system's credential vault | Windows Credential Manager, the macOS Keychain and the Linux Secret Service, through the keyring layer this app already has | Roadmap | Not a connector and does not implement this trait; it is a core::vault::Vault, which has four operations and no tenant to discover, plan or revoke. src-tauri/src/core_vault.rs is the whole of it, and nothing in the test suite opens the real vault of whoever runs it, so what is proved here is the framing on the way in and out and not the store itself | The credential broker reads every value from here. The bytes are written and read through the one byte API, with a header that says which encoding this grid wrote, because the text API on Windows stores UTF-16 and a byte read would then hand back something that is not the value |
| HashiCorp Vault | A key-value secret at a path, at a given version, in a namespace | Interface only | No code speaks to it. core::vault::Unconnected answers for it, and every read fails, so a grid pointed at it refuses to send rather than sending without a credential. Leases, renewal and namespaces are not in the four operations this seam has, so the shape is not known to fit | Nothing |
| Azure Key Vault | A secret in a vault, at a given version | Interface only | No code speaks to it. core::vault::Unconnected answers for it and every read fails | Nothing |
| AWS Secrets Manager | A secret and one of its staging labels | Interface only | No code speaks to it. core::vault::Unconnected answers for it and every read fails. Staging labels are not version numbers, so this seam's version would have to be mapped onto them | Nothing |
| Google Secret Manager | A secret version in a project | Interface only | No code speaks to it. core::vault::Unconnected answers for it and every read fails | Nothing |
| CyberArk | An account in a safe, fetched through the Central Credential Provider | Interface only | No code speaks to it. core::vault::Unconnected answers for it and every read fails | Nothing |
| BeyondTrust | A managed account's password, checked out and checked back in | Interface only | No code speaks to it. core::vault::Unconnected answers for it and every read fails. Checking a password out and back in is a lifecycle these four operations do not have | Nothing |
| A hardware security module (PKCS#11) | A value held where it cannot be read out, used by the module rather than handed over | Interface only | No code anywhere in this repository binds PKCS#11. core::vault::Unconnected answers for it and every read fails. A module that will not hand a value over cannot answer Vault::read at all, so wiring this one would change the seam and not only fill it in | Nothing |
| TPM-backed key storage | A value sealed to this computer's own measurements | Interface only | No code anywhere in this repository reads a TPM. core::vault::Unconnected answers for it and every read fails, and core::identity::Attestation is still a computer's self-report rather than a measurement | Nothing |

## Audit, telemetry and operations

Getting what happened out of this computer, and telling somebody when it matters.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| Sealed local audit chain | Every decision recorded in order, sealed with the realm's own key | Roadmap | Not a connector; there is no outside system in it. This seam's export_audit hands a connector's own notes to the realm so they can join this chain | grid/src/core/audit.rs seals every event and its tests show an altered chain failing to verify |
| Syslog over TCP to a collector on this computer | Every sealed event as an RFC 5424 message, framed by octet count the way RFC 6587 describes | Mock-tested | grid/src/core/export.rs, with the message asserted field by field against a header written out by hand from the specification, and the framing exercised against a collector on this computer that is handed the bytes and keeps them. Plain TCP, and only to this computer: an address anywhere else is refused rather than sent a sealed history in the clear | Nothing |
| Syslog over TLS (RFC 5425) | The same messages to a collector somewhere else, inside TLS, which is the only way they may leave this computer | Roadmap | No code anywhere in this repository speaks TLS to a collector. RFC 5425 is syslog inside TLS and wiring it needs a client certificate path this grid's TLS client does not have, so the sink refuses any address that is not on this computer instead | Nothing |
| OpenTelemetry | Every sealed event as an OTLP log record, over HTTP with JSON encoding | Mock-tested | grid/src/core/export.rs, with the proto3 JSON mapping asserted field by field, including a 64-bit time encoded as a string and not a number, and exercised against a collector on this computer. OTLP over gRPC is not built: it needs protobuf and a gRPC stack that are not in this build, and nothing could be verified against them here | Nothing |
| SIEM webhook | Newline-delimited JSON at an address the customer names, with an HMAC over the body | Interface only | The envelope is rendered in grid/src/core/export.rs and nothing has ever sent it. The signature is the reason: it is an HMAC over the body with a key from the vault, and this grid's broker presents a credential rather than handing a key out for a caller to sign arbitrary bytes with, so the signing has nowhere to happen yet | Nothing |
| Splunk | The HTTP Event Collector: concatenated JSON objects, each wrapping one event | Interface only | The envelope is rendered in grid/src/core/export.rs and asserted against the published format, including that the objects are concatenated with no separator. Nothing has ever sent it, and whether the index exists, whether the token is scoped to it and whether the service accepts a batch cannot be known from this repository | Nothing |
| Microsoft Sentinel | The logs ingestion API: one JSON array with TimeGenerated on every row | Interface only | The envelope is rendered in grid/src/core/export.rs and asserted against the published format. Nothing has ever sent it, and whether a data collection rule is bound to the stream and whether a token's scope covers it cannot be known from this repository. The Entra half of the token path is exercised elsewhere, which is not the same as having delivered anything | Nothing |
| Elastic | The bulk API: alternating action and document lines, with the trailing newline it requires | Interface only | The envelope is rendered in grid/src/core/export.rs and asserted against the published format, including the trailing newline people forget. Nothing has ever sent it, and whether the data stream exists and whether the credential may write to it cannot be known from this repository | Nothing |
| Audit export to object storage | A sealed batch written to the company's own bucket, so the record outlives this computer | Roadmap | No code. It is the shortest of these to build, because the S3 connector already signs requests this way, and it is not built: a read-only connector cannot write an object, and writing one would be the first thing in this area that changed a tenant | Nothing |
| ServiceNow, Jira, PagerDuty and chat | Telling a person, or raising a ticket, when something needs deciding | Roadmap | No code anywhere in this repository | Nothing |

## Hardware and attestation

What a computer can prove about itself, and what the scheduler is therefore allowed to believe.

| Integration | What it maps to | State | Evidence here | What ships today, by another route |
| --- | --- | --- | --- | --- |
| Battery and power state of a computer | Refusing to put a desk on a computer that is about to sleep | Mock-tested | Not a connector; this is the computer reporting on itself, through core::hardware::Probe. grid/src/power.rs reads it with a system call on Windows, files under /sys on Linux and pmset on macOS, and its tests show that an unknown battery is not assumed to be low | The placement rules in core use it, and a computer on battery takes no new desk |
| Processors, memory and disk | How large a computer is, so a realm knows what it can place there | Mock-tested | Not a connector; this is the computer reporting on itself. core::hardware reads the processor count and memory here; free disk comes from the application through the probe seam, because it measures it already and reading the same hardware twice is two answers that can disagree. A fact nothing measured contributes nothing rather than a default, so a computer that cannot say how large it is is offered nothing | The product measures all three and the scheduler places work with them |
| GPU presence and memory | Knowing whether a computer has a card and how much memory it has | Mock-tested | Not a connector; this is the computer reporting on itself. core::hardware reads cards from /sys on Linux and takes them from the application's own probe program through the probe seam on Windows; what nvidia-smi prints is read by a tested parser that answers nothing for a line it does not recognise exactly. On a platform with no module, every card field is unmeasured rather than absent | The product reads it on Windows and the scheduler places GPU work with it |
| NVIDIA CUDA, AMD ROCm, Intel and Apple compute | Which compute stack is installed beside a card | Interface only | core::hardware has the type and tested parsers for what nvidia-smi and rocm-smi print, and nothing in this build runs either: there is no way to run a child process with a timeout and a bounded output with what this crate depends on, and a hardware probe that can hang waiting for a prompt is worse than one that says it did not look. A host that can run tools safely supplies them through the probe seam. Finding a stack installed is not finding a working driver, and nothing here claims it is. Intel Level Zero and Apple Metal are types with no reader at all | src-tauri/src/runtime/cuda.rs decides whether the bundled CUDA runtime is installed, which is not whether a working driver is present |
| Partitioned and virtual GPUs | Knowing which isolation a card really has before two pieces of work share it | Interface only | No code reads a partition's real isolation from the driver. core::hardware will call a card partitioned only when nvidia-smi listed MIG instances and the work is pinned to one of them, which is a tested parser over fixture bytes and not a reading from any driver. Everything else stays unknown, which core::work refuses to share, and a computer with one unmeasured card is unknown as a whole. Virtual GPUs have no reader at all | core::work records the isolation a person asserted and the scheduler refuses to share a card nobody has recorded |
| TPM and Secure Boot | A computer proving what it booted before it is trusted with anything | Interface only | core::hardware reads both from /sys on Linux and reads neither on Windows or macOS, where it says so in a sentence rather than answering no. A TPM nothing read is unknown and not a computer without one, which is the rule this module is built on. What a computer that answers both is worth is capped at core::hardware::CEILING, which is selfReported: nothing here mints a key inside a TPM, asks for a quote over platform registers or checks a manufacturer's certificate chain, and a realm demanding more than that takes no computer at all | A computer that cannot prove its state is shown as unverified rather than assumed safe |
| BitLocker, FileVault and LUKS | Whether the disk a computer boots from is encrypted at rest | Interface only | core::hardware reads LUKS from /sys on Linux and has tested parsers for what manage-bde and fdesetup print, accepting only the exact phrases Microsoft and Apple document and answering nothing for a locale this build does not recognise. Neither tool is run here, for the reason in the compute stack row, so on Windows and macOS the answer is unknown rather than no | Nothing |
| Network interfaces | Which interfaces a computer has, whether the link is up and how fast it is | Interface only | core::hardware reads them from /sys/class/net on Linux and nowhere else. A link state the kernel calls unknown, which is what a virtual interface reports, is not down and is recorded as nothing. Whether an interface is physical is read from whether the kernel gave it a device, never guessed from its name | src-tauri/src/runtime/host_addresses.rs enumerates local addresses for a different purpose, with no interface name, link state or speed, and reports none of it to a realm |
| Signed device attestation | A key the operating system holds signing a statement this grid asked for, so an old report cannot be replayed | Roadmap | No code anywhere in this repository. core::hardware::Trust has the rung and core::hardware::CEILING refuses to reach it, so a later change that claims it without writing the code fails a test here rather than an audit at a customer | Nothing |
| HSM and PKCS#11 key storage | Keeping a realm's signing key somewhere it cannot be read out | Roadmap | No code anywhere in this repository. A realm's key lives in the operating system's vault | Nothing |

## The adapter interface

Every connector implements the same nine operations, in `grid/src/core/connector.rs`: `discover`,
`plan`, `validate`, `dry_run`, `observe`, `apply`, `reconcile`, `revoke` and `export_audit`. The
first five only read. A connector that can do those and nothing else is still worth shipping, and
is shipped that way rather than waiting until it can change somebody's tenant.

Four things about the seam are worth stating here, because they are what a reviewer should check.

No argument of any operation can carry a secret, and that is a fact about the types rather than a
rule somebody has to remember. Every argument is one of the types defined in that file.
`Settings` refuses a key whose name promises a secret and a value carrying one of the markers only
a secret carries, so there is no free-form map to smuggle a password through. `Ticket` is read
from a permission the realm minted and keeps what the permission says rather than the bearer
string, so a connector learns which credential it may use and holds nothing it could replay or
copy into a log. Where a value does have to be read, it is read through a type a connector is
built with and that no operation takes: `desktop::Keyring` for the four that were wrapped, and
`wire::Keys` for everything written since. A connector written against `wire` holds a
`Box<dyn Wire>`, and `Wire` has no method that returns a value, so it is not that such a connector
is written carefully enough to hold no secret. There is nothing it could call to get one.

Nothing changes a provider until that exact plan has been checked. `validate` is the only thing
that returns a `Checked`; `apply`, `reconcile` and `revoke` all require one; a `Checked` covers
one plan's fingerprint and lapses after fifteen minutes, which is the same quarter hour an
approval request waits. Calling apply before validate is not a mistake caught at run time. It is
a call with nothing to pass, so it does not compile.

A connector that only reads cannot be made to change a tenant. `Connector::alters_anything`
answers yes by default, so the connectors that already existed are untouched by the question being
asked at all, and a read-only connector answers no. What makes the answer bite is not the answer:
every plan a read-only connector makes has reading steps and nothing else, and `cleared`, which is
the gate every connector calls before it changes anything, refuses a plan with no altering step.
The read-only connectors in this repository are written as if their author had forgotten the rule,
and a test drives them that way, because the point is that the rule does not depend on the author
remembering it. The refusal is one sentence in one place, `connector::reads_only`, so every
read-only connector says the same thing to an administrator.

A connector cannot touch a realm. Nothing in the seam is given a `Core` or a `Store`. An
operation returns what happened and a list of notes, and whoever called it decides what the realm
records. A connector that fails, including one that changes a provider and then fails, therefore
cannot leave the realm's database in a state nobody chose.

## What that last guarantee leaves open, and what answers it

A connector that cannot write to a realm is a connector that cannot record a provider it just
moved. When `apply` comes back saying something was changed and then failed, the provider has
moved and the realm has no record that anything was even attempted; a hub restarted at that moment
has no idea somebody is seated at a desktop it never granted.

So the realm writes the row first. `Core::open_connector_task` records what a connector is about
to be asked to do before it is asked, and `Core::settle_connector_task` records how it ended,
together with every note the connector kept, in one transaction. A connector never sees one of
these rows, cannot write one and cannot read one. The worst case becomes a realm that says it does
not know, which a person or the sweeper can act on, rather than a realm that believes something
false.

Five separate things stop a connector failure corrupting realm state, and each one can be checked
on its own:

1. No handle. Nothing in the seam is given a `Core` or a `Store`.
2. Write before you ask. The row exists before the request does.
3. One transaction for one account. The ending and the notes land together or not at all, each
   sealed over the one before it.
4. The database refuses the bad transitions, not the code. Schema version 8 has four triggers:
   what was asked is never editable, a settled task stays settled, attempts only rise, and nothing
   unsettled is forgotten. A partial unique index refuses a second open task for the same person,
   credential, target and direction. A second process, or a person with sqlite3, hits the same
   wall.
5. A fresh permission on every attempt. The sweeper never carries the permission a task opened
   with, so suspension, a withdrawn grant, a revoked computer and a retired credential all bite at
   the moment of the attempt rather than at whenever the task was first asked for.

`grid/src/core/connector/sweep.rs` is where rollback lives, and it has no generic form on purpose.
Undoing a plan is `revoke` of that same plan, which each connector already implements by reversing
the change it was asked for; there is nothing a sweeper could do on a connector's behalf. What the
sweeper adds is the deciding. It mints a fresh permission, makes the plan again and compares the
fingerprint with the one the row recorded, and refuses to act on a plan it cannot reproduce: a
connection whose settings changed since the task was asked for would make a different plan now,
and carrying that out because it has the same name is how somebody ends up in a pool nobody chose.
After three attempts the row says a person has to look at it, rather than being retried for ever.

One case is worth naming because the honest answer is the unhelpful one. When the realm has
withdrawn the credential, the sweeper cannot reach the provider in either direction: putting a
change right and taking it back both need a credential the realm has just refused to lend. The row
says exactly that, and does not report a rollback that never happened.

## Rate limits, retries and breakers

`grid/src/core/connector/limits.rs` keeps three questions apart, because they have different
answers and different failure modes.

A budget is about the provider's patience. One connection allows itself a burst of thirty requests
and five a second after that, held in a token bucket on the connection rather than anywhere a
connector could reach. Being throttled inside a customer's tenant is worse for them than being
slow, because a throttle applies to everything their own people are doing at the same time. Both
numbers are a deliberately low guess and not a measurement: nobody here has reached a real
provider or read a real throttle header, and the test proves the arithmetic rather than the
suitability.

A retry is about whether asking again could help, and the one case where it never can is the case
that matters. `may_retry` is false for a half-done change, always, because something at the
provider moved and asking again is how one change becomes two. It is false for a permission
problem and for a missing setting, because waiting does not fix either. What is left is a provider
that refused an operation that reads, and that may be tried again three times. `apply` is never
retried automatically; the recovery for a failed apply is the sweeper's reconcile under a fresh
check, not a loop holding a check that is about to lapse.

A breaker is about a provider that is down. Five answers in the five-hundreds in a row and the
connection stops sending for a minute, refusing without reaching anybody. A provider's own refusal
of one request is the connector's business and not the breaker's: a wrong path answering 404 for
ever must not look like an outage, and a test holds that apart.

Rotation needs no cache to invalidate. The vault is read on each operation, so a rotated
credential is picked up on the next call, a minted token is keyed by the version it was made from
so a rotation retires it, and every note a connector writes carries the version that authorised
the request it describes. The value never appears in the history and the version always does,
which is what makes a rotation visible without making it readable.

## Hardware discovery is not a connector

`grid/src/core/hardware.rs` is a second seam, with two operations instead of nine, and it is
separate for a reason in the types. `Connector::plan` takes a `Request`, a `Request` carries a
`Subject`, and a `Subject` is a person's email. A computer reporting on itself is inbound, has no
credential, no destination and no person, and `revoke` would mean nothing for it.

One rule runs through the whole module, and it is the rule `identity::Attestation` already
followed rather than a second one invented beside it: a fact that was not measured is reported as
not measured, never as no. A computer with no TPM and a computer whose TPM this build cannot reach
are not the same computer, and reporting both as having no TPM would make the second look like the
first. Every fact also carries how it was learned and when, and a gap is a sentence somebody reads
rather than a missing field somebody has to notice.

There is a `Probe` trait and not only a function because of the dependency direction. Some of what
a realm wants to know is already measured by the application this crate is part of, where the code
to do it lives: the graphics adapters come from a probe program that ships beside the app, the
disks from a crate the app depends on. That application depends on this crate and not the other
way round, so the core cannot call any of it, and reading the same hardware twice would be two
answers that can disagree. `src-tauri/src/grid_hardware.rs` is the host side of that seam, and it
measures nothing new: it hands over what the application already had, with how it was learned
attached, and the core's own readings win where both have one.

What the core can read on its own is deliberately modest. It will not run a vendor tool: there is
no way to run a child process with a timeout and a bounded output with what this crate depends on,
and a hardware probe that can hang on an elevation prompt is worse than one that says it did not
look. So the parsers for what `nvidia-smi`, `rocm-smi`, `manage-bde` and `fdesetup` print are
written and tested against bytes written out by hand, and the running of those tools belongs to a
host that can do it safely. Every one of those parsers answers nothing for an input it does not
recognise exactly, including a locale this build does not know, which is the difference between an
unreadable answer and a wrong one.

## What a computer can prove about itself, which is less than it looks

`hardware::Trust` has four rungs: unverified, self-reported, device-signed and hardware-attested.
The gap between the second and the third is the whole point of the type. Everything a computer
measures about itself, however carefully, is still that computer telling the realm about that
computer, and an administrator on that computer can change what it says.

`hardware::CEILING` is self-reported, and `trust` clamps to it. Nothing in this repository mints a
key inside a TPM, asks for a quote over platform registers, or checks a certificate chain to a
manufacturer root, so nothing in this repository can honestly produce more. A realm that demands
more takes no computer at all, and the sentence it refuses with says that plainly rather than
leaving an administrator to work out why nothing is running. The constant exists so that a later
change claiming more without writing the code fails a test here rather than an audit at a customer.

Two other things the ladder refuses to count. A measurement older than a day is not a measurement
about today, and neither is one stamped more than a day in the future, which means the clock that
stamped it does not agree with this realm's; inside that day in either direction it counts,
because two computers' clocks are never exactly the same. And a report with nothing saying how or
when it was measured is a
report from a build that did not record either, which is not evidence whatever it claims; a
computer enrolled before this existed therefore reads as unverified rather than as a measurement,
which is the safe direction to be wrong in.

## Getting the history off this computer

`grid/src/core/export.rs` is the third seam, for the same reason the second one exists: a batch of
events is not a person, and `revoke` has no meaning for an event already sent. A `Sink` has two
operations. `render` produces exactly the bytes it would send and sends nothing, which is why a
wire format can be checked on a computer with no network at all, and it is what the tests assert
on.

Two sinks are built and exercised. Syslog is an RFC 5424 message framed by octet count the way RFC
6587 describes, with the message asserted field by field against a header written out by hand from
the specification, and the framing read back apart by a test that takes the count and then that
many bytes. OpenTelemetry is OTLP over HTTP with JSON encoding, with the proto3 mapping asserted
field by field, including a 64-bit time encoded as a string and not as a number, which is exactly
the detail a renderer gets wrong and a fixture catches. OTLP over gRPC is not built: it needs
protobuf and a gRPC stack that are not in this build, and nothing here could verify one.

Two honesty items are in the code rather than only on this page. The syslog structured data
element uses enterprise number zero, which is not registered with IANA; the constant is called
`PLACEHOLDER_ENTERPRISE_NUMBER` so nobody mistakes it for a real one, and a customer shipping this
needs their own. And the TLS half of RFC 5425 is not built, so this sends only to a collector on
this computer and refuses an address anywhere else rather than putting a sealed history on a plain
connection.

Exporting marks events exported, which is what lets the local chain be trimmed: events are dropped
only as far as the marker, so a realm nobody ever carries anything out of keeps everything it has
written, for ever. Three rules keep that marker honest. The chain is verified before anything is
sent, so a history somebody edited is never laundered into a customer's collector. The marker
moves only as far as a sink actually confirmed. And a sink that cannot tell which of a batch were
accepted confirms nothing at all, which is why a collector reporting that it dropped some records
without saying which moves the marker not at all.

What `exported_to` means, even at its best, is that the bytes left this computer. No sink in this
repository has been pointed at a real collector, and none of them can say that the far end stored
what it acknowledged.

A realm that can reach nothing has no sink at all, which is the research realm by design. It gets
a `Bundle` instead: every event that has not left this computer, written to one file an operator
can carry away on a disk, with every seal in the written file read back and checked before it is
called written. Writing it marks nothing, because a file beside the realm is not a copy of
anything. `Core::carried_out` is the second step, once the file is somewhere else, and it is keyed
on the file rather than on a number: the bundle has to belong to this realm, verify under this
realm's key, and end on the event this realm holds at that number with the same seal. The trim
rule is untouched by any of it: an unexported event is still never dropped, and the database still
refuses to drop one.

## How the four desktop connectors were adapted

They were wrapped, not rewritten, and that was deliberate. All four live in
`grid/src/provisioning.rs` and they were the only connectors in this repository that had been
exercised against anything. Rewriting them into a new shape would have thrown that away and
replaced it with a shape nobody has run, so the requests they make, the order they make them in,
the headers they set and the sentences they return are untouched, and their own tests still
exercise them directly. `grid/src/core/connector/desktop.rs` is the wrapper.

Wrapping also puts the one awkward thing in exactly one place. A `provisioning::Task` carries the
secret part of the credential, because it is the thing that makes the request, and the seam must
never carry one. So the value is read from this computer's vault, by the name the permission gave,
between the permission being checked and the task being built, and nowhere else.

What wrapping honestly costs is detail in the failures. A connector underneath returns one
sentence, so the wrapper cannot tell a refusal that changed nothing from a change that half
finished, and it says the provider refused rather than guessing. That is why reconciling after a
failure is worth doing even when the failure looked clean.

## Rules for adding one

1. Read-only first. `discover` and `observe` ship before anything that changes a tenant, and a
   connector that will never change one answers `alters_anything` with no and makes plans whose
   steps all read.
2. A permission naming a credential, never a value, and the least privilege written down. A new
   connector takes a `Box<dyn Wire>` and not a key source of its own.
3. A test against a server on this computer that records every call, asserting that no secret
   leaves except to the provider's own sign-in.
4. A dry run that shows exactly what would change, and changes nothing.
5. A compensating action for every change, because a change nobody can undo is a change nobody
   should have made.
6. Idempotence that is read rather than remembered. Carrying a plan out twice has to leave the
   provider where carrying it out once left it, and `Outcome.already` has to be what the provider
   said rather than what the connector recalls.
7. A row in the table in `registry.rs`, in its true state, with the evidence beside it, and
   `cargo test rewrite_the_adapter_matrix -- --ignored` run so this page and the code agree.
