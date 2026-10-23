//! Who acts in a realm, and from which computer.
//!
//! A principal is a person or a service. A device is the computer or installation they act from,
//! enrolled once and revocable at any moment. A host is a computer that offers its resources to
//! the realm. Every one of them belongs to exactly one realm.
use serde::{Deserialize, Serialize};

/// What a principal is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrincipalKind {
    Person,
    Service,
}

/// What someone may do. A role is a bundle of permissions, and holding one never implies another.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Role {
    /// Uses what they have been given: their workspace, the model endpoints they may call.
    User,
    /// Places and retries work, drains computers; changes no accounts and no credentials.
    Operator,
    /// Works on an authorised research scope: writes a scope, acquires the source it was given,
    /// places research work and records what it found. Approves nothing, including their own.
    Researcher,
    /// Images, workspace roles and who has which workspace.
    WorkspaceAdmin,
    /// Model plans and how they are served.
    ModelAdmin,
    /// Adds and rotates credentials; never approves their own use.
    CredentialAdmin,
    /// Approves a credential request someone else made.
    CredentialApprover,
    /// Approves research source, scope and participants.
    ResearchApprover,
    /// Network rules, attestation and the stop switches.
    SecurityAdmin,
    /// Reads policy and audit; changes nothing.
    Auditor,
    /// Runs the realm, and still cannot approve their own sensitive requests.
    RealmAdmin,
}

impl Role {
    /// Every role there is. Written out because Rust cannot list the variants of an enum on its
    /// own, and `every_role_is_in_the_list` fails if one is ever added without being added here.
    pub fn every() -> &'static [Role] {
        &[
            Role::User,
            Role::Operator,
            Role::Researcher,
            Role::WorkspaceAdmin,
            Role::ModelAdmin,
            Role::CredentialAdmin,
            Role::CredentialApprover,
            Role::ResearchApprover,
            Role::SecurityAdmin,
            Role::Auditor,
            Role::RealmAdmin,
        ]
    }

    pub fn name(self) -> &'static str {
        match self {
            Role::User => "user",
            Role::Operator => "operator",
            Role::Researcher => "researcher",
            Role::WorkspaceAdmin => "workspace administrator",
            Role::ModelAdmin => "model administrator",
            Role::CredentialAdmin => "credential administrator",
            Role::CredentialApprover => "credential approver",
            Role::ResearchApprover => "research approver",
            Role::SecurityAdmin => "security administrator",
            Role::Auditor => "auditor",
            Role::RealmAdmin => "realm administrator",
        }
    }

    /// What else comes with this role.
    ///
    /// Administering a realm brings the approving permissions with it, so a realm is never stuck
    /// with nobody able to decide. They are held as permissions in their own right, each naming
    /// the role it came from, so administering and approving are never the same record and either
    /// can be taken away on its own. Approving still never lets anyone decide their own request
    /// while someone else can; that rule lives in `approval` and applies to administrators too.
    pub fn implies(self) -> &'static [Role] {
        match self {
            Role::RealmAdmin => &[Role::CredentialApprover, Role::ResearchApprover],
            _ => &[],
        }
    }

    /// Whether this role, on its own, may do `action`. Administering does not approve: an
    /// administrator approves because they hold the approver permission, which is recorded
    /// separately and can be withdrawn without taking the realm away from them.
    pub fn may(self, action: Action) -> bool {
        use Action::*;
        match self {
            Role::User => matches!(action, UseWorkspace | CallModel | ReadOwn),
            Role::Operator => matches!(action, UseWorkspace | CallModel | ReadOwn | ReadRealm | PlaceWork | DrainHost),
            // Deliberately not PlaceWork: a researcher places research work and nothing else, and
            // `Core::submit` admits that on DoResearch rather than on the general permission.
            Role::Researcher => matches!(action, ReadOwn | ReadRealm | DoResearch),
            Role::WorkspaceAdmin => matches!(action, ReadOwn | ReadRealm | PlaceWork | ManageWorkspaces),
            Role::ModelAdmin => matches!(action, ReadOwn | ReadRealm | PlaceWork | ManageModels),
            Role::CredentialAdmin => matches!(action, ReadOwn | ReadRealm | ManageCredentials),
            Role::CredentialApprover => matches!(action, ReadOwn | ReadRealm | ApproveCredential),
            Role::ResearchApprover => matches!(action, ReadOwn | ReadRealm | ApproveResearch),
            Role::SecurityAdmin => matches!(action, ReadOwn | ReadRealm | ReadAudit | ManageSecurity | DrainHost | RevokeDevice),
            Role::Auditor => matches!(action, ReadRealm | ReadAudit),
            Role::RealmAdmin => matches!(
                action,
                ReadOwn
                    | ReadRealm
                    | ReadAudit
                    | PlaceWork
                    | DrainHost
                    | RevokeDevice
                    | ManageWorkspaces
                    | ManageModels
                    | ManageCredentials
                    | ManagePeople
                    | ManageSecurity
                    | DoResearch
            ),
        }
    }
}

/// Something a principal may try to do in a realm.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    ReadOwn,
    ReadRealm,
    ReadAudit,
    UseWorkspace,
    CallModel,
    PlaceWork,
    DrainHost,
    RevokeDevice,
    ManageWorkspaces,
    ManageModels,
    ManageCredentials,
    ManagePeople,
    ManageSecurity,
    /// Working on an authorised research scope. Not an approval: a researcher asks, and somebody
    /// else agrees, exactly as a credential request does.
    DoResearch,
    ApproveCredential,
    ApproveResearch,
}

impl Action {
    pub fn name(self) -> &'static str {
        use Action::*;
        match self {
            ReadOwn => "read own",
            ReadRealm => "read realm",
            ReadAudit => "read audit",
            UseWorkspace => "use workspace",
            CallModel => "call model",
            PlaceWork => "place work",
            DrainHost => "drain host",
            RevokeDevice => "revoke device",
            ManageWorkspaces => "manage workspaces",
            ManageModels => "manage models",
            ManageCredentials => "manage credentials",
            ManagePeople => "manage people",
            ManageSecurity => "manage security",
            DoResearch => "do research",
            ApproveCredential => "approve a credential request",
            ApproveResearch => "approve research",
        }
    }

    /// Whether doing this needs someone other than the requester to agree.
    pub fn needs_another(self) -> bool {
        matches!(self, Action::ApproveCredential | Action::ApproveResearch)
    }
}

/// A person or a service that acts in one realm.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Principal {
    pub id: String,
    pub realm_id: String,
    pub kind: PrincipalKind,
    pub name: String,
    /// The email their identity provider knows them by, when a provider signs them in.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub roles: Vec<Role>,
    pub created_at: i64,
    /// Set when they are suspended: nothing they hold works from that moment.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_at: Option<i64>,
}

impl Principal {
    pub fn new(realm_id: &str, kind: PrincipalKind, name: &str, roles: &[Role], now: i64) -> Result<Principal, String> {
        let mut roles = roles.to_vec();
        roles.sort();
        roles.dedup();
        Ok(Principal {
            id: format!("principal-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            kind,
            name: crate::label(name, "name")?,
            email: None,
            roles,
            created_at: now,
            suspended_at: None,
        })
    }

    pub fn active(&self) -> bool {
        self.suspended_at.is_none()
    }

    /// Whether this principal may do `action` right now.
    pub fn may(&self, action: Action) -> bool {
        self.active() && self.roles.iter().any(|role| role.may(action))
    }
}

/// A computer or installation a principal acts from. Its secret is kept as a hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Device {
    pub id: String,
    pub realm_id: String,
    pub principal_id: String,
    pub name: String,
    pub platform: String,
    pub token_hash: String,
    pub enrolled_at: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<i64>,
    /// Set when the device is revoked; from then on nothing it holds is accepted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<i64>,
    /// What the computer could prove about itself when it enrolled.
    #[serde(default)]
    pub attestation: Attestation,
}

/// What a computer could show about its own state. Absent is reported as unverified rather than
/// assumed to be safe.
///
/// The three fields added below are all `serde(default)`, so a computer enrolled before they
/// existed still loads: the column is text holding this struct, and a row written by an earlier
/// build has none of them, which is exactly true of it. It was measured by a build that did not
/// record how or when, and `hardware::trust` reads that as unverified rather than as a
/// measurement, which is the safe direction to be wrong in.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Attestation {
    pub secure_boot: Option<bool>,
    pub tpm: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_version: Option<String>,
    /// How the two answers above were learned.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<super::hardware::Source>,
    /// When the computer last measured itself. A measurement older than `hardware::STALE_AFTER` is
    /// not a current measurement, and the trust ladder does not count it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub measured_at: Option<i64>,
    /// What that build could not measure on that computer, in words.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub could_not_measure: Vec<String>,
}

impl Attestation {
    /// Whether this computer proved enough to join a pool that requires it.
    pub fn verified(&self) -> bool {
        self.secure_boot == Some(true) && self.tpm == Some(true)
    }

    /// What to show an admin about it, which is never "secure" when nothing was proved.
    pub fn describe(&self) -> &'static str {
        match (self.secure_boot, self.tpm) {
            (Some(true), Some(true)) => "verified: secure boot and a TPM",
            (Some(false), _) | (_, Some(false)) => "unverified: this computer reports no secure boot or TPM",
            _ => "unverified: this computer cannot report its own state",
        }
    }

    /// What this has shown, as of `now`, which is never more than that the computer said so.
    ///
    /// `verified` and `describe` keep their own words and their own behaviour. This is a second
    /// question: not "did it report both" but "how good is the report", and it is a different
    /// question because a report with no source and no time behind it is not evidence.
    pub fn trust(&self, now: i64) -> super::hardware::Trust {
        super::hardware::trust(self, now)
    }
}

impl Device {
    /// Enrols a computer and returns it with the secret the caller must hand over once.
    pub fn enrol(realm_id: &str, principal_id: &str, name: &str, platform: &str, now: i64) -> Result<(Device, String), String> {
        let secret = crate::token();
        let device = Device {
            id: format!("device-{}", &crate::token()[..16]),
            realm_id: realm_id.to_owned(),
            principal_id: principal_id.to_owned(),
            name: crate::label(name, "computer name")?,
            platform: platform.chars().filter(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_')).take(32).collect(),
            token_hash: crate::digest("device", &secret),
            enrolled_at: now,
            last_seen_at: None,
            revoked_at: None,
            attestation: Attestation::default(),
        };
        Ok((device, secret))
    }

    pub fn active(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// Whether `secret` is this device's, compared without leaking where it differs.
    pub fn holds(&self, secret: &str) -> bool {
        crate::desks::same_hash(&self.token_hash, &crate::digest("device", secret))
    }
}
