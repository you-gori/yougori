//! Every integration the plan names, and what is actually true about each one here.
//!
//! There is one table, `INTEGRATIONS`, and it is the only place any of this is written down.
//! `docs/grid-core/adapters.md` is rendered from it by `matrix()`, and a test in this module
//! refuses to pass unless the committed document still is what the table renders. That is what
//! stops the product and the documentation drifting apart: a row cannot be improved in the
//! document without being improved in the code, and a connector that grows cannot quietly leave
//! the document saying something kinder than the truth.
//!
//! The state is about this connector seam, and only about it. A row can be `Roadmap` here while
//! the product already does the same job another way, because having a shipped feature is not
//! having a connector; the `today` column is where that is said, in the same row, so neither fact
//! can be read without the other.
//!
//! No row is `LiveTested` and none can be. There is no tenant, no vendor library and no customer
//! credential in this repository, and reaching a live target from here is forbidden.

/// How far an integration has actually got through this seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum State {
    /// A connector that has met the real system, with the result recorded.
    LiveTested,
    /// A connector written against the provider's published management API and exercised against
    /// a server on this computer that imitates it.
    ///
    /// Three rows carry this state without being connectors and without having met any server:
    /// the hardware rows, where this computer reads itself and the parsers are exercised over
    /// fixture bytes. They are here rather than in a state of their own because a fourth state
    /// would say less than the sentence `means` now carries, and each of the three says what it
    /// is in its own evidence.
    MockTested,
    /// A connector that implements the trait with nothing behind it.
    InterfaceOnly,
    /// Named in the plan. No connector.
    Roadmap,
}

impl State {
    pub fn name(self) -> &'static str {
        match self {
            State::LiveTested => "Live-tested",
            State::MockTested => "Mock-tested",
            State::InterfaceOnly => "Interface only",
            State::Roadmap => "Roadmap",
        }
    }

    pub fn means(self) -> &'static str {
        match self {
            State::LiveTested => "A connector exercised against the real system, with the result recorded. Nothing here is in this state.",
            State::MockTested => "A connector written against the provider's published management API and exercised against a server on this computer that imitates it. It has never met a real tenant. Three rows in this state are not connectors and met no server at all: they are this computer reading itself, with their parsers exercised over fixture bytes, and each says so in its own evidence.",
            State::InterfaceOnly => "A connector that implements the trait with no provider behind it.",
            State::Roadmap => "Named in the plan, with no connector written. The last column says what the product already does another way, when anything does.",
        }
    }

    /// Whether a connector in this state may change anybody's tenant at all.
    pub fn may_change_a_tenant(self) -> bool {
        matches!(self, State::LiveTested | State::MockTested)
    }
}

/// Which part of a company's estate an integration belongs to.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Area {
    Desktops,
    Identity,
    Compute,
    RemoteAccess,
    Storage,
    Secrets,
    Operations,
    Hardware,
}

impl Area {
    /// Every area, in the order the document lists them.
    pub fn all() -> &'static [Area] {
        &[Area::Desktops, Area::Identity, Area::Compute, Area::RemoteAccess, Area::Storage, Area::Secrets, Area::Operations, Area::Hardware]
    }

    pub fn title(self) -> &'static str {
        match self {
            Area::Desktops => "Desktop and session platforms",
            Area::Identity => "Identity",
            Area::Compute => "Compute, virtualisation and orchestration",
            Area::RemoteAccess => "Remote access",
            Area::Storage => "Storage",
            Area::Secrets => "Secret keepers",
            Area::Operations => "Audit, telemetry and operations",
            Area::Hardware => "Hardware and attestation",
        }
    }

    pub fn about(self) -> &'static str {
        match self {
            Area::Desktops => "Seating a named person at a desktop the company already runs. This is the only area with connectors in it.",
            Area::Identity => "Who somebody is, decided by the company's own provider rather than by us.",
            Area::Compute => "Where work runs when it does not run on a computer the grid already holds.",
            Area::RemoteAccess => "Reaching a desktop or a shell on a machine somewhere else.",
            Area::Storage => "Where a workspace's packed-up data waits while it moves, and where backups go.",
            Area::Secrets => "Where the values a grid brokers are actually kept. These are `core::vault::Vault`, not this nine-operation connector trait, so none of them is a connector and every row says Roadmap or Interface only for that reason alone. The question of where a realm's own signing key lives is a different one and is in the hardware area.",
            Area::Operations => "Getting what happened out of this computer, and telling somebody when it matters.",
            Area::Hardware => "What a computer can prove about itself, and what the scheduler is therefore allowed to believe.",
        }
    }
}

/// One integration, and the whole truth about it.
#[derive(Clone, Copy, Debug)]
pub struct Integration {
    pub area: Area,
    /// The name a connector gives in `Connector::integration`, and the name the document shows.
    pub name: &'static str,
    pub maps_to: &'static str,
    pub state: State,
    /// Where the proof is in this repository, or plainly what is missing. Never a promise.
    pub evidence: &'static str,
    /// What the product already does by another route, when anything does. Empty when nothing
    /// does, and an empty one is printed as "Nothing" rather than left blank.
    pub today: &'static str,
}

impl Integration {
    pub fn today_or_nothing(&self) -> &'static str {
        if self.today.is_empty() {
            "Nothing"
        } else {
            self.today
        }
    }
}

/// The one table. Everything else in this module reads it, and so does the document.
pub const INTEGRATIONS: &[Integration] = &[
    Integration {
        area: Area::Desktops,
        name: "Azure Virtual Desktop",
        maps_to: "The Desktop Virtualization User role on an application group, through Entra ID for the token, Microsoft Graph for the person and Azure Resource Manager for the assignment",
        state: State::MockTested,
        evidence: "grid/src/provisioning.rs, exercised against a loopback server that imitates Entra ID, Graph and Resource Manager; behind this seam through core::connector::desktop, which wraps it without changing it",
        today: "The Sandbox Grid assigns and takes back desktops here when an administrator has entered a credential",
    },
    Integration {
        area: Area::Desktops,
        name: "Windows 365",
        maps_to: "Membership of the group a provisioning policy is assigned to, through Microsoft Graph",
        state: State::MockTested,
        evidence: "grid/src/provisioning.rs, exercised against a loopback server that imitates Entra ID and Graph; behind this seam through core::connector::desktop",
        today: "The Sandbox Grid adds and removes people from the policy's group when an administrator has entered a credential",
    },
    Integration {
        area: Area::Desktops,
        name: "Citrix DaaS",
        maps_to: "The users of a delivery group, through the Citrix Cloud DaaS management API",
        state: State::MockTested,
        evidence: "grid/src/provisioning.rs, exercised against a loopback server that imitates Citrix Cloud; behind this seam through core::connector::desktop. Citrix Cloud only",
        today: "The Sandbox Grid edits the delivery group's users when an administrator has entered a credential",
    },
    Integration {
        area: Area::Desktops,
        name: "Omnissa Horizon",
        maps_to: "Desktop pool entitlements, through the Connection Server REST API",
        state: State::MockTested,
        evidence: "grid/src/provisioning.rs, exercised against a loopback server that imitates a Connection Server; behind this seam through core::connector::desktop",
        today: "The Sandbox Grid entitles and disentitles people on the pool when an administrator has entered a credential",
    },
    Integration {
        area: Area::Desktops,
        name: "Citrix Virtual Apps and Desktops on premises",
        maps_to: "The users of a delivery group on a site the customer runs themselves",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. The Citrix connector that exists speaks Citrix Cloud and nothing else",
        today: "",
    },
    Integration {
        area: Area::Desktops,
        name: "Amazon WorkSpaces",
        maps_to: "Directory assignment of a workspace to a person",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "",
    },
    Integration {
        area: Area::Desktops,
        name: "Amazon AppStream 2.0",
        maps_to: "Stack entitlement for a person",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "",
    },
    Integration {
        area: Area::Desktops,
        name: "Google Cloud virtual workstations",
        maps_to: "Workstation assignment for a person",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "OpenID Connect sign-in",
        maps_to: "A person signs in at their own provider and the hub checks the token against keys it fetched from the issuer",
        state: State::Roadmap,
        evidence: "Not a connector and does not implement this trait; there is nothing here to discover, plan or revoke",
        today: "Both grids already sign people in this way. grid/src/jwt.rs checks RS256 and ES256 tokens against the issuer's own keys, exercised against a local issuer in its tests",
    },
    Integration {
        area: Area::Identity,
        name: "Local password and two-step",
        maps_to: "A password proof plus a code from an authenticator app",
        state: State::Roadmap,
        evidence: "Not a connector; there is no outside system in it",
        today: "Ships in both grids: grid/src/password.rs and grid/src/totp.rs, each with its own tests",
    },
    Integration {
        area: Area::Identity,
        name: "SAML 2.0",
        maps_to: "Signed assertions, for federations that require them",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "SCIM 2.0",
        maps_to: "Group membership for a named person, through the client half of RFC 7644: find them by userName, read the group, and patch its members",
        state: State::MockTested,
        evidence: "grid/src/core/connector/scim.rs, exercised against a loopback server that answers the way RFC 7644 describes, including answering a second add with 204 rather than a conflict. Only the client direction; a SCIM server, where the company's directory pushes people at this grid, is not a connector and is not written",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "Microsoft Entra ID as a management target",
        maps_to: "A client-credentials token at the tenant's own endpoint, and Microsoft Graph for the person behind an email",
        state: State::MockTested,
        evidence: "grid/src/provisioning.rs microsoft_token and graph_user, exercised against a loopback server that imitates Entra ID and Graph. It sits inside the Azure Virtual Desktop and Windows 365 connectors rather than being a connector of its own, and this row exists because that work was invisible in this table",
        today: "Both desktop connectors sign in this way",
    },
    Integration {
        area: Area::Identity,
        name: "Okta",
        maps_to: "Sign-in through the issuer's own discovery document, and later SCIM for provisioning",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository names Okta. The generic OpenID Connect path would sign a person in and has never been pointed at Okta; the SCIM client in this repository has never been pointed at Okta either",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "Auth0",
        maps_to: "Sign-in through the issuer's own discovery document",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository names Auth0, for the same reason as the row above it",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "LDAP",
        maps_to: "Directory lookup over the wire protocol a directory speaks",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository, and it should not be written here: LDAP is BER over TCP, and a client and a fixture both written in this repository would prove only that they agree with each other, which is not interoperability with a real directory. The Horizon connector asks Horizon to do its own directory lookup; it speaks no directory protocol itself",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "Active Directory",
        maps_to: "Directory lookup and group membership at a domain the customer runs",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. LDAP's problem, and then SASL with GSSAPI on top of it, which is out of reach here. Where a directory is genuinely needed, Microsoft Graph is the route that is exercised",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "WebAuthn and FIDO2",
        maps_to: "Sign-in bound to a device the person holds",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. Checking an assertion is offline-verifiable in principle, with ring for the signature and a software authenticator written in a test, and it needs a CBOR decoder this build does not have. Checking an attestation statement is a larger job again and should not be bundled with it",
        today: "",
    },
    Integration {
        area: Area::Identity,
        name: "Smart cards",
        maps_to: "Sign-in with a certificate on a card the person holds",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. It needs client-certificate TLS, which this grid's HTTP client does not do, and a reader on the person's own computer",
        today: "",
    },
    Integration {
        area: Area::Compute,
        name: "Amazon EC2",
        maps_to: "Read only: the instances a credential reaches in one region, through the Query API, signed with Signature Version 4",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, exercised against a loopback server that recomputes the Signature Version 4 signature from the canonical request and refuses one that does not match. Read only, and structurally so: every step of its plan reads, and core::connector::cleared refuses to carry out a plan with no altering step",
        today: "An administrator can create a cloud computer from the app: src-tauri/src/cloud_deployment.rs runs their own signed-in aws command, which is not this connector and reaches no account from this repository",
    },
    Integration {
        area: Area::Compute,
        name: "Amazon ECS",
        maps_to: "Read only: the clusters a credential reaches, through the JSON API that names what it wants in an X-Amz-Target header",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, exercised against the same loopback server, which checks the signature the same way. Read only",
        today: "",
    },
    Integration {
        area: Area::Compute,
        name: "Amazon EKS",
        maps_to: "Read only: the clusters a credential reaches, through the control plane's REST API",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, exercised against the same loopback server. Read only. The control plane only: authenticating inside a cluster is a pre-signed STS URL and is not written",
        today: "",
    },
    Integration {
        area: Area::Compute,
        name: "Azure virtual machines",
        maps_to: "Read only: the machines in a resource group, through Azure Resource Manager, with a client-credentials token from the tenant's own endpoint",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, exercised against a loopback server that imitates Entra ID and Resource Manager and refuses a token it did not mint. Read only. The test asserts the client secret goes to the sign-in and nowhere else",
        today: "An administrator can create a cloud computer from the app with their own signed-in az command",
    },
    Integration {
        area: Area::Compute,
        name: "Google Cloud compute",
        maps_to: "Creating a machine and joining it to the grid",
        state: State::Roadmap,
        evidence: "No connector. It is the cheapest of the three to describe and the dearest to build here: a service account signs a JWT assertion with RS256 and exchanges it for a token, and grid/src/jwt.rs only checks RS256 signatures, it does not make them. That is new code nobody has written, not an existing path pointed somewhere else. src-tauri/src/cloud_deployment.rs runs the administrator's own signed-in gcloud command",
        today: "An administrator can create a cloud computer from the app and join it to the grid",
    },
    Integration {
        area: Area::Compute,
        name: "A machine the administrator already has, over SSH",
        maps_to: "Installing on a server somebody already owns and joining it to the grid",
        state: State::Roadmap,
        evidence: "No connector. src-tauri/src/runtime/cloud runs Yougori on an existing server over pinned SSH, and src-tauri/src/desks/cloud.rs does the same for a computer the hub created; neither is exercised against a server in this repository",
        today: "An administrator can connect an existing server from the app",
    },
    // The four isolated places authorised research runs in. None of them is a connector, and the
    // state says Roadmap for that reason alone: `core::research::Enclosure` is a seam of its own
    // with five operations and no tenant to discover, plan or revoke, and nothing in this
    // repository implements it. The runtime each would be built from already ships, and the last
    // column says so, because a row that only said Roadmap would read as if the product could not
    // run a container.
    Integration {
        area: Area::Compute,
        name: "A container as a research enclosure",
        maps_to: "An unprivileged OCI container holding one research run, with no network interface unless its plan names one",
        state: State::Roadmap,
        evidence: "No connector, and not this trait: grid/src/core/research.rs defines the Enclosure seam and holds no implementation of it. The container runtime it would be built from is src-tauri/src/runtime, and src-tauri/src/commands.rs::update_container_network opens and closes a container's network",
        today: "Yougori runs unprivileged OCI containers on this computer, and the Sandbox Grid builds desks in them",
    },
    Integration {
        area: Area::Compute,
        name: "A microVM as a research enclosure",
        maps_to: "A microVM holding one research run, with the host filtering its one shared interface",
        state: State::Roadmap,
        evidence: "No connector, and not this trait. src-tauri/src/runtime/microvm_network.rs already filters that interface on the host side, where the guest cannot undo it; nothing wires it to a research plan",
        today: "Yougori runs microVMs on this computer with host-side network filtering",
    },
    Integration {
        area: Area::Compute,
        name: "A virtual machine as a research enclosure",
        maps_to: "A full virtual machine with its own firmware holding one research run",
        state: State::Roadmap,
        evidence: "No connector, and not this trait. src-tauri/src/runtime/vm.rs and vm_security.rs are the machines and the Windows secure profile; nothing wires either to a research plan",
        today: "Yougori runs full virtual machines on this computer",
    },
    Integration {
        area: Area::Compute,
        name: "A GPU sandbox as a research enclosure",
        maps_to: "A machine with a card attached holding one research run, where the card's isolation has been recorded",
        state: State::Roadmap,
        evidence: "No connector, and not this trait. src-tauri/src/runtime/gpu.rs and cuda.rs attach cards; what a card's isolation really is still comes from a person asserting it through Core::set_gpu_isolation, and nothing here reads it from a driver",
        today: "Yougori runs NVIDIA GPU containers, and the scheduler refuses to share a card whose isolation nobody has recorded",
    },
    Integration {
        area: Area::Compute,
        name: "VMware vSphere",
        maps_to: "Virtual machines on a cluster the customer runs",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. The REST API is JSON with a session header and could be built to the same state as the rows above it; the older SOAP management API could not, and a connector would have to say which of the two it speaks the way the Citrix row already says Citrix Cloud only",
        today: "",
    },
    Integration {
        area: Area::Compute,
        name: "OpenStack",
        maps_to: "Read only: the instances of one project, through Nova, with a Keystone token got from a password",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, exercised against a loopback Keystone that answers with its token in X-Subject-Token the way the standard says, and a loopback Nova that refuses any other token. Read only",
        today: "",
    },
    Integration {
        area: Area::Compute,
        name: "Hyper-V, Proxmox, Nutanix and KVM managers",
        maps_to: "Virtual machines on a hypervisor fleet the customer runs",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. Yougori runs its own containers, microVMs and VMs on a computer and manages no hypervisor fleet",
        today: "",
    },
    Integration {
        area: Area::Compute,
        name: "Kubernetes",
        maps_to: "Read only: the nodes of a cluster and whether each one is ready, through the API server with a bearer token",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, exercised against a loopback API server that refuses any other token. Read only, and bearer tokens only: a cluster that authenticates with a client certificate needs mutual TLS, which grid/src/https.rs does not do, and nothing here claims otherwise",
        today: "",
    },
    Integration {
        area: Area::Compute,
        name: "Slurm, Nomad and Ray",
        maps_to: "Submitting work to a scheduler the customer runs",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "",
    },
    Integration {
        area: Area::RemoteAccess,
        name: "RDP",
        maps_to: "Opening a Windows desktop session on a machine elsewhere",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "Remote desktop here is VNC carried over the authenticated gateway, in src-tauri/src/remote_access/desktop.rs",
    },
    Integration {
        area: Area::RemoteAccess,
        name: "WinRM",
        maps_to: "Running a command on a Windows machine elsewhere",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "",
    },
    Integration {
        area: Area::Storage,
        name: "S3 and S3-compatible object storage",
        maps_to: "Read only: what a credential reaches in one bucket, through the REST API with XML listings, signed with Signature Version 4",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, exercised against a loopback server that recomputes the signature and refuses one that does not match. Read only. Separately, src-tauri/src/desks/parking.rs parks data through the object_store crate, and its tests run against a folder on this computer, so that path's S3 protocol is exercised nowhere here",
        today: "A desk's data parks in the company's bucket while it moves, when an administrator sets one",
    },
    Integration {
        area: Area::Storage,
        name: "Azure Blob Storage",
        maps_to: "Read only: what a credential reaches in one container, signed with the account's shared key",
        state: State::MockTested,
        evidence: "grid/src/core/connector/cloud.rs, with the shared-key signature asserted against the exact string Microsoft documents and exercised against a loopback server. Read only. The key signs each request and never travels on one",
        today: "",
    },
    Integration {
        area: Area::Storage,
        name: "Google Cloud Storage",
        maps_to: "The same parking, in a Google bucket",
        state: State::Roadmap,
        evidence: "No connector. It needs the same service-account assertion the Google compute row needs, which is RS256 signing that nothing in this repository does",
        today: "",
    },
    Integration {
        area: Area::Storage,
        name: "NFS and SMB",
        maps_to: "The same parking, on a file server",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository, and none should be written: both are binary protocols with their own authentication, and the honest design is to let the operating system mount them and treat the result as a path, which is not a connector at all",
        today: "",
    },
    Integration {
        area: Area::Storage,
        name: "Ceph",
        maps_to: "The same parking, on a cluster the customer runs",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. Reachable as S3 through its own gateway, in which case it is the S3 connector pointed elsewhere; librados is a C library and is out of reach here",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "the operating system's credential vault",
        maps_to: "Windows Credential Manager, the macOS Keychain and the Linux Secret Service, through the keyring layer this app already has",
        state: State::Roadmap,
        evidence: "Not a connector and does not implement this trait; it is a core::vault::Vault, which has four operations and no tenant to discover, plan or revoke. src-tauri/src/core_vault.rs is the whole of it, and nothing in the test suite opens the real vault of whoever runs it, so what is proved here is the framing on the way in and out and not the store itself",
        today: "The credential broker reads every value from here. The bytes are written and read through the one byte API, with a header that says which encoding this grid wrote, because the text API on Windows stores UTF-16 and a byte read would then hand back something that is not the value",
    },
    Integration {
        area: Area::Secrets,
        name: "HashiCorp Vault",
        maps_to: "A key-value secret at a path, at a given version, in a namespace",
        state: State::InterfaceOnly,
        evidence: "No code speaks to it. core::vault::Unconnected answers for it, and every read fails, so a grid pointed at it refuses to send rather than sending without a credential. Leases, renewal and namespaces are not in the four operations this seam has, so the shape is not known to fit",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "Azure Key Vault",
        maps_to: "A secret in a vault, at a given version",
        state: State::InterfaceOnly,
        evidence: "No code speaks to it. core::vault::Unconnected answers for it and every read fails",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "AWS Secrets Manager",
        maps_to: "A secret and one of its staging labels",
        state: State::InterfaceOnly,
        evidence: "No code speaks to it. core::vault::Unconnected answers for it and every read fails. Staging labels are not version numbers, so this seam's version would have to be mapped onto them",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "Google Secret Manager",
        maps_to: "A secret version in a project",
        state: State::InterfaceOnly,
        evidence: "No code speaks to it. core::vault::Unconnected answers for it and every read fails",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "CyberArk",
        maps_to: "An account in a safe, fetched through the Central Credential Provider",
        state: State::InterfaceOnly,
        evidence: "No code speaks to it. core::vault::Unconnected answers for it and every read fails",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "BeyondTrust",
        maps_to: "A managed account's password, checked out and checked back in",
        state: State::InterfaceOnly,
        evidence: "No code speaks to it. core::vault::Unconnected answers for it and every read fails. Checking a password out and back in is a lifecycle these four operations do not have",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "A hardware security module (PKCS#11)",
        maps_to: "A value held where it cannot be read out, used by the module rather than handed over",
        state: State::InterfaceOnly,
        evidence: "No code anywhere in this repository binds PKCS#11. core::vault::Unconnected answers for it and every read fails. A module that will not hand a value over cannot answer Vault::read at all, so wiring this one would change the seam and not only fill it in",
        today: "",
    },
    Integration {
        area: Area::Secrets,
        name: "TPM-backed key storage",
        maps_to: "A value sealed to this computer's own measurements",
        state: State::InterfaceOnly,
        evidence: "No code anywhere in this repository reads a TPM. core::vault::Unconnected answers for it and every read fails, and core::identity::Attestation is still a computer's self-report rather than a measurement",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "Sealed local audit chain",
        maps_to: "Every decision recorded in order, sealed with the realm's own key",
        state: State::Roadmap,
        evidence: "Not a connector; there is no outside system in it. This seam's export_audit hands a connector's own notes to the realm so they can join this chain",
        today: "grid/src/core/audit.rs seals every event and its tests show an altered chain failing to verify",
    },
    Integration {
        area: Area::Operations,
        name: "Syslog over TCP to a collector on this computer",
        maps_to: "Every sealed event as an RFC 5424 message, framed by octet count the way RFC 6587 describes",
        state: State::MockTested,
        evidence: "grid/src/core/export.rs, with the message asserted field by field against a header written out by hand from the specification, and the framing exercised against a collector on this computer that is handed the bytes and keeps them. Plain TCP, and only to this computer: an address anywhere else is refused rather than sent a sealed history in the clear",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "Syslog over TLS (RFC 5425)",
        maps_to: "The same messages to a collector somewhere else, inside TLS, which is the only way they may leave this computer",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository speaks TLS to a collector. RFC 5425 is syslog inside TLS and wiring it needs a client certificate path this grid's TLS client does not have, so the sink refuses any address that is not on this computer instead",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "OpenTelemetry",
        maps_to: "Every sealed event as an OTLP log record, over HTTP with JSON encoding",
        state: State::MockTested,
        evidence: "grid/src/core/export.rs, with the proto3 JSON mapping asserted field by field, including a 64-bit time encoded as a string and not a number, and exercised against a collector on this computer. OTLP over gRPC is not built: it needs protobuf and a gRPC stack that are not in this build, and nothing could be verified against them here",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "SIEM webhook",
        maps_to: "Newline-delimited JSON at an address the customer names, with an HMAC over the body",
        state: State::InterfaceOnly,
        evidence: "The envelope is rendered in grid/src/core/export.rs and nothing has ever sent it. The signature is the reason: it is an HMAC over the body with a key from the vault, and this grid's broker presents a credential rather than handing a key out for a caller to sign arbitrary bytes with, so the signing has nowhere to happen yet",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "Splunk",
        maps_to: "The HTTP Event Collector: concatenated JSON objects, each wrapping one event",
        state: State::InterfaceOnly,
        evidence: "The envelope is rendered in grid/src/core/export.rs and asserted against the published format, including that the objects are concatenated with no separator. Nothing has ever sent it, and whether the index exists, whether the token is scoped to it and whether the service accepts a batch cannot be known from this repository",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "Microsoft Sentinel",
        maps_to: "The logs ingestion API: one JSON array with TimeGenerated on every row",
        state: State::InterfaceOnly,
        evidence: "The envelope is rendered in grid/src/core/export.rs and asserted against the published format. Nothing has ever sent it, and whether a data collection rule is bound to the stream and whether a token's scope covers it cannot be known from this repository. The Entra half of the token path is exercised elsewhere, which is not the same as having delivered anything",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "Elastic",
        maps_to: "The bulk API: alternating action and document lines, with the trailing newline it requires",
        state: State::InterfaceOnly,
        evidence: "The envelope is rendered in grid/src/core/export.rs and asserted against the published format, including the trailing newline people forget. Nothing has ever sent it, and whether the data stream exists and whether the credential may write to it cannot be known from this repository",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "Audit export to object storage",
        maps_to: "A sealed batch written to the company's own bucket, so the record outlives this computer",
        state: State::Roadmap,
        evidence: "No code. It is the shortest of these to build, because the S3 connector already signs requests this way, and it is not built: a read-only connector cannot write an object, and writing one would be the first thing in this area that changed a tenant",
        today: "",
    },
    Integration {
        area: Area::Operations,
        name: "ServiceNow, Jira, PagerDuty and chat",
        maps_to: "Telling a person, or raising a ticket, when something needs deciding",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository",
        today: "",
    },
    Integration {
        area: Area::Hardware,
        name: "Battery and power state of a computer",
        maps_to: "Refusing to put a desk on a computer that is about to sleep",
        state: State::MockTested,
        evidence: "Not a connector; this is the computer reporting on itself, through core::hardware::Probe. grid/src/power.rs reads it with a system call on Windows, files under /sys on Linux and pmset on macOS, and its tests show that an unknown battery is not assumed to be low",
        today: "The placement rules in core use it, and a computer on battery takes no new desk",
    },
    Integration {
        area: Area::Hardware,
        name: "Processors, memory and disk",
        maps_to: "How large a computer is, so a realm knows what it can place there",
        state: State::MockTested,
        evidence: "Not a connector; this is the computer reporting on itself. core::hardware reads the processor count and memory here; free disk comes from the application through the probe seam, because it measures it already and reading the same hardware twice is two answers that can disagree. A fact nothing measured contributes nothing rather than a default, so a computer that cannot say how large it is is offered nothing",
        today: "The product measures all three and the scheduler places work with them",
    },
    Integration {
        area: Area::Hardware,
        name: "GPU presence and memory",
        maps_to: "Knowing whether a computer has a card and how much memory it has",
        state: State::MockTested,
        evidence: "Not a connector; this is the computer reporting on itself. core::hardware reads cards from /sys on Linux and takes them from the application's own probe program through the probe seam on Windows; what nvidia-smi prints is read by a tested parser that answers nothing for a line it does not recognise exactly. On a platform with no module, every card field is unmeasured rather than absent",
        today: "The product reads it on Windows and the scheduler places GPU work with it",
    },
    Integration {
        area: Area::Hardware,
        name: "NVIDIA CUDA, AMD ROCm, Intel and Apple compute",
        maps_to: "Which compute stack is installed beside a card",
        state: State::InterfaceOnly,
        evidence: "core::hardware has the type and tested parsers for what nvidia-smi and rocm-smi print, and nothing in this build runs either: there is no way to run a child process with a timeout and a bounded output with what this crate depends on, and a hardware probe that can hang waiting for a prompt is worse than one that says it did not look. A host that can run tools safely supplies them through the probe seam. Finding a stack installed is not finding a working driver, and nothing here claims it is. Intel Level Zero and Apple Metal are types with no reader at all",
        today: "src-tauri/src/runtime/cuda.rs decides whether the bundled CUDA runtime is installed, which is not whether a working driver is present",
    },
    Integration {
        area: Area::Hardware,
        name: "Partitioned and virtual GPUs",
        maps_to: "Knowing which isolation a card really has before two pieces of work share it",
        state: State::InterfaceOnly,
        evidence: "No code reads a partition's real isolation from the driver. core::hardware will call a card partitioned only when nvidia-smi listed MIG instances and the work is pinned to one of them, which is a tested parser over fixture bytes and not a reading from any driver. Everything else stays unknown, which core::work refuses to share, and a computer with one unmeasured card is unknown as a whole. Virtual GPUs have no reader at all",
        today: "core::work records the isolation a person asserted and the scheduler refuses to share a card nobody has recorded",
    },
    Integration {
        area: Area::Hardware,
        name: "TPM and Secure Boot",
        maps_to: "A computer proving what it booted before it is trusted with anything",
        state: State::InterfaceOnly,
        evidence: "core::hardware reads both from /sys on Linux and reads neither on Windows or macOS, where it says so in a sentence rather than answering no. A TPM nothing read is unknown and not a computer without one, which is the rule this module is built on. What a computer that answers both is worth is capped at core::hardware::CEILING, which is selfReported: nothing here mints a key inside a TPM, asks for a quote over platform registers or checks a manufacturer's certificate chain, and a realm demanding more than that takes no computer at all",
        today: "A computer that cannot prove its state is shown as unverified rather than assumed safe",
    },
    Integration {
        area: Area::Hardware,
        name: "BitLocker, FileVault and LUKS",
        maps_to: "Whether the disk a computer boots from is encrypted at rest",
        state: State::InterfaceOnly,
        evidence: "core::hardware reads LUKS from /sys on Linux and has tested parsers for what manage-bde and fdesetup print, accepting only the exact phrases Microsoft and Apple document and answering nothing for a locale this build does not recognise. Neither tool is run here, for the reason in the compute stack row, so on Windows and macOS the answer is unknown rather than no",
        today: "",
    },
    Integration {
        area: Area::Hardware,
        name: "Network interfaces",
        maps_to: "Which interfaces a computer has, whether the link is up and how fast it is",
        state: State::InterfaceOnly,
        evidence: "core::hardware reads them from /sys/class/net on Linux and nowhere else. A link state the kernel calls unknown, which is what a virtual interface reports, is not down and is recorded as nothing. Whether an interface is physical is read from whether the kernel gave it a device, never guessed from its name",
        today: "src-tauri/src/runtime/host_addresses.rs enumerates local addresses for a different purpose, with no interface name, link state or speed, and reports none of it to a realm",
    },
    Integration {
        area: Area::Hardware,
        name: "Signed device attestation",
        maps_to: "A key the operating system holds signing a statement this grid asked for, so an old report cannot be replayed",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. core::hardware::Trust has the rung and core::hardware::CEILING refuses to reach it, so a later change that claims it without writing the code fails a test here rather than an audit at a customer",
        today: "",
    },
    Integration {
        area: Area::Hardware,
        name: "HSM and PKCS#11 key storage",
        maps_to: "Keeping a realm's signing key somewhere it cannot be read out",
        state: State::Roadmap,
        evidence: "No code anywhere in this repository. A realm's key lives in the operating system's vault",
        today: "",
    },
];

/// The state of one named integration, or nothing when no row has that name.
pub fn state_of(name: &str) -> Option<State> {
    INTEGRATIONS.iter().find(|row| row.name == name).map(|row| row.state)
}

/// One named integration, whole.
pub fn find(name: &str) -> Option<&'static Integration> {
    INTEGRATIONS.iter().find(|row| row.name == name)
}

/// The rows of one area, in the order they were written.
pub fn in_area(area: Area) -> Vec<&'static Integration> {
    INTEGRATIONS.iter().filter(|row| row.area == area).collect()
}

/// How many rows are in each state, for anyone who wants the headline without reading the table.
pub fn counted(state: State) -> usize {
    INTEGRATIONS.iter().filter(|row| row.state == state).count()
}

/// A markdown cell: the pipe is the one character that would break the table.
fn cell(text: &str) -> String {
    text.replace('|', "\\|")
}

/// The document's body, rendered from the table above. `docs/grid-core/adapters.md` contains
/// exactly this, and a test in this module fails when it does not.
pub fn matrix() -> String {
    let mut out = String::from("## What the states mean\n\n| State | Rows | Means |\n| --- | --- | --- |\n");
    for state in [State::LiveTested, State::MockTested, State::InterfaceOnly, State::Roadmap] {
        out.push_str(&format!("| **{}** | {} | {} |\n", state.name(), counted(state), cell(state.means())));
    }
    for area in Area::all() {
        let rows = in_area(*area);
        if rows.is_empty() {
            continue;
        }
        out.push_str(&format!("\n## {}\n\n{}\n\n| Integration | What it maps to | State | Evidence here | What ships today, by another route |\n| --- | --- | --- | --- | --- |\n", area.title(), cell(area.about())));
        for row in rows {
            out.push_str(&format!("| {} | {} | {} | {} | {} |\n", cell(row.name), cell(row.maps_to), row.state.name(), cell(row.evidence), cell(row.today_or_nothing())));
        }
    }
    out
}
