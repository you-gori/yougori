//! SSH management: host-key enrollment, the management identity and capability evidence
//! (VM-W41; VM part §7.6 line 2244; §1.3; VM-P40, VM-P42).
//!
//! - A host key is accepted only through a supported enrollment flow, and every trust
//!   assumption the flow rests on is recorded with the enrollment and carried into every
//!   identity and observation made from it. First-use trust is refused unless the policy
//!   permits it, and when permitted it is recorded as [`TrustAssumption::FirstUse`],
//!   never hidden (§7.6). A changed host key is refused; nothing here updates a key in
//!   place. Re-enrolling a retired host needs a flow other than first use and gets a new
//!   generation, so identities from the old one are stale.
//! - A host seen presenting another key has that enrollment rejected
//!   ([`KnownHosts::record_rejection`], M16E): from then on every check refuses it, until
//!   the host is enrolled again through a supported flow under a new generation.
//! - The [`ManagementIdentity`] that launches and supervises the remote VM is its own
//!   type. It has no field, constructor or conversion for workload authority, and its
//!   serialized form refuses unknown fields, so it cannot carry workload grants; workload
//!   authority is the CORE-04 lease alone.
//! - [`RemoteCapabilityEvidence`] records which context an observation comes from. A
//!   remote host shell is not the sandbox (VM-W41): evidence from it, or from a provider
//!   container, never satisfies a VM predicate, and an emulated VM never satisfies one
//!   either (VM-P42).

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};

use super::offering::RegionName;
use super::rejection::{
    HostKeyRejection, RejectionBook, RejectionEvidence, RejectionObserver, RejectionRefusal,
};
use crate::foundation::evidence::{ProviderKind, SupportDetail};
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionCategory, MonotonicTime};
use crate::foundation::transfer::CredentialRef;
use crate::sandbox_contract::policy::SecurityPredicate;

mod persistence;
pub use persistence::{KnownHostsRestoreRefusal, KnownHostsState};

/// Longest accepted host public key.
pub const MAX_HOST_KEY_BYTES: usize = 16 * 1024;

/// The SSH host-key algorithms accepted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKeyAlgorithm {
    Ed25519,
    EcdsaNistp256,
    EcdsaNistp384,
    RsaSha2_512,
}

impl HostKeyAlgorithm {
    /// The SSH algorithm name.
    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ed25519 => "ssh-ed25519",
            Self::EcdsaNistp256 => "ecdsa-sha2-nistp256",
            Self::EcdsaNistp384 => "ecdsa-sha2-nistp384",
            Self::RsaSha2_512 => "rsa-sha2-512",
        }
    }
}

strict_remote_enum! {
    /// Why a host key was refused.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum HostKeyProblem tag "problem" {
        Empty,
        TooLong { max_bytes: u64 },
    }
}

impl fmt::Display for HostKeyProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the host key is empty"),
            Self::TooLong { max_bytes } => {
                write!(f, "the host key is longer than {max_bytes} bytes")
            }
        }
    }
}

impl std::error::Error for HostKeyProblem {}

/// A host public key as the SSH transport presented it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HostKey {
    algorithm: HostKeyAlgorithm,
    public_key: Vec<u8>,
}

impl HostKey {
    /// Accepts 1 to [`MAX_HOST_KEY_BYTES`] bytes of public key.
    pub fn new(algorithm: HostKeyAlgorithm, public_key: Vec<u8>) -> Result<Self, HostKeyProblem> {
        if public_key.is_empty() {
            return Err(HostKeyProblem::Empty);
        }
        if public_key.len() > MAX_HOST_KEY_BYTES {
            return Err(HostKeyProblem::TooLong {
                max_bytes: u64::try_from(MAX_HOST_KEY_BYTES).unwrap_or(u64::MAX),
            });
        }
        Ok(Self {
            algorithm,
            public_key,
        })
    }

    pub fn algorithm(&self) -> HostKeyAlgorithm {
        self.algorithm
    }

    /// The key's identity under [`HostKeyFingerprint::DOMAIN`].
    pub fn fingerprint(&self) -> HostKeyFingerprint {
        HostKeyFingerprint(
            DigestBuilder::new(HostKeyFingerprint::DOMAIN)
                .str(self.algorithm.tag())
                .bytes(&self.public_key)
                .finish(),
        )
    }
}

/// The identity of a host key: its algorithm and public bytes under
/// [`HostKeyFingerprint::DOMAIN`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HostKeyFingerprint(Digest);

impl HostKeyFingerprint {
    pub const DOMAIN: &'static str = "yougori/remote/ssh-host-key/v1";

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Display for HostKeyFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// One provisioned remote host, by provider, region and the provider's instance identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RemoteHostId(Digest);

impl RemoteHostId {
    pub const DOMAIN: &'static str = "yougori/remote/host/v1";

    /// The host of `instance` in `region` of `provider`.
    pub fn of(provider: ProviderKind, region: &RegionName, instance: &Digest) -> Self {
        Self(
            DigestBuilder::new(Self::DOMAIN)
                .str(provider.tag())
                .str(region.as_str())
                .digest(instance)
                .finish(),
        )
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

impl fmt::Display for RemoteHostId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// One enrollment of a host key, the shared generation type: every enrollment gets a
/// higher one, so an identity from an earlier enrollment is recognisably stale.
pub use crate::foundation::ids::EnrollmentGeneration;

/// A supported host-key enrollment flow (§7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentFlow {
    /// The home host generated the host key and the provider installed it at
    /// provisioning.
    InjectedAtProvisioning,
    /// The provider's authenticated API reported the key for this instance.
    ProviderApi,
    /// The key was read from the instance's console output through the provider's API.
    ProviderConsole,
    /// The owner supplied the exact expected public-key fingerprint.
    OwnerPinned,
    /// The key was accepted the first time it was seen.
    FirstUse,
}

strict_remote_enum! {
    /// What a flow checked the presented key against.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum EnrollmentEvidence tag "flow" {
        InjectedAtProvisioning { injected: HostKeyFingerprint },
        ProviderApi { reported: HostKeyFingerprint },
        ProviderConsole { reported: HostKeyFingerprint },
        OwnerPinned { expected: HostKeyFingerprint },
        /// Nothing: the key is trusted because it is the first one seen.
        FirstUse,
    }
}

impl EnrollmentEvidence {
    pub const fn flow(&self) -> EnrollmentFlow {
        match self {
            Self::InjectedAtProvisioning { .. } => EnrollmentFlow::InjectedAtProvisioning,
            Self::ProviderApi { .. } => EnrollmentFlow::ProviderApi,
            Self::ProviderConsole { .. } => EnrollmentFlow::ProviderConsole,
            Self::OwnerPinned { .. } => EnrollmentFlow::OwnerPinned,
            Self::FirstUse => EnrollmentFlow::FirstUse,
        }
    }

    fn expected(&self) -> Option<HostKeyFingerprint> {
        match self {
            Self::InjectedAtProvisioning { injected } => Some(*injected),
            Self::ProviderApi { reported } | Self::ProviderConsole { reported } => Some(*reported),
            Self::OwnerPinned { expected } => Some(*expected),
            Self::FirstUse => None,
        }
    }

    fn assumptions(&self) -> BTreeSet<TrustAssumption> {
        BTreeSet::from([match self {
            Self::InjectedAtProvisioning { .. } => TrustAssumption::ProviderDeliveredKey,
            Self::ProviderApi { .. } | Self::ProviderConsole { .. } => {
                TrustAssumption::ProviderReportedKey
            }
            Self::FirstUse => TrustAssumption::FirstUse,
            Self::OwnerPinned { .. } => TrustAssumption::OwnerVerifiedKey,
        }])
    }
}

/// A trust assumption an enrollment rests on; recorded, never hidden (§7.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustAssumption {
    /// The owner obtained the key through a channel they trust. This is not a
    /// provider assertion or TEE attestation; the SSH host operator is trusted.
    OwnerVerifiedKey,
    /// The key was accepted the first time it was seen, with nothing to check it against;
    /// an interceptor present at that moment is not detected.
    FirstUse,
    /// The provider carried the host's private key to the instance, so the provider
    /// could impersonate the host.
    ProviderDeliveredKey,
    /// The provider reported the key; a provider that reports a false one is not
    /// detected.
    ProviderReportedKey,
}

/// Which enrollment flows the host accepts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrollmentPolicy {
    /// First-use trust is refused unless this is set explicitly.
    pub allow_first_use: bool,
}

/// One enrolled host key, with the flow and the assumptions it rests on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostEnrollment {
    pub host: RemoteHostId,
    pub fingerprint: HostKeyFingerprint,
    pub flow: EnrollmentFlow,
    pub assumptions: BTreeSet<TrustAssumption>,
    pub generation: EnrollmentGeneration,
    pub enrolled_at: MonotonicTime,
}

strict_remote_enum! {
    /// Why an enrollment was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum EnrollmentRefusal tag "refusal" {
        /// The policy does not permit first-use trust.
        FirstUseNotPermitted,
        /// The host was enrolled before, so this is not a first use.
        NotFirstUse { host: RemoteHostId },
        /// The flow's evidence names another key than the one presented.
        EvidenceMismatch {
            flow: EnrollmentFlow,
            expected: HostKeyFingerprint,
            presented: HostKeyFingerprint,
        },
        /// The host is enrolled with another key; it is never replaced in place.
        HostKeyChanged {
            host: RemoteHostId,
            enrolled: HostKeyFingerprint,
            presented: HostKeyFingerprint,
        },
        GenerationsExhausted,
    }
}

impl fmt::Display for EnrollmentRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirstUseNotPermitted => f.write_str(
                "first-use trust is not permitted; enroll the host key through the provider",
            ),
            Self::NotFirstUse { .. } => {
                f.write_str("this host was enrolled before, so first-use trust does not apply")
            }
            Self::EvidenceMismatch { flow, .. } => write!(
                f,
                "the key presented differs from the one the {flow:?} flow names"
            ),
            Self::HostKeyChanged { host, .. } => write!(
                f,
                "host {host} presented a different host key; it is refused, not replaced"
            ),
            Self::GenerationsExhausted => f.write_str("no enrollment generations are left"),
        }
    }
}

impl std::error::Error for EnrollmentRefusal {}

strict_remote_enum! {
    /// Why a presented host key was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum HostKeyRefusal tag "refusal" {
        NotEnrolled { host: RemoteHostId },
        /// The host presented another key than the enrolled one (VM-W41).
        Changed {
            host: RemoteHostId,
            enrolled: HostKeyFingerprint,
            presented: HostKeyFingerprint,
        },
        /// The host's enrollment was rejected after it presented another key; no key
        /// verifies against it until the host is enrolled again (M16E).
        Rejected {
            host: RemoteHostId,
            generation: EnrollmentGeneration,
        },
    }
}

impl fmt::Display for HostKeyRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotEnrolled { host } => write!(f, "host {host} has no enrolled key"),
            Self::Changed { host, .. } => write!(
                f,
                "host {host} presented a different host key than the enrolled one; refused"
            ),
            Self::Rejected { host, generation } => write!(
                f,
                "enrollment {generation} of host {host} was rejected after the host presented \
                 another key; enroll the host again through a supported flow"
            ),
        }
    }
}

impl std::error::Error for HostKeyRefusal {}

/// The enrolled host keys, and every rejected enrollment.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownHosts {
    active: BTreeMap<RemoteHostId, HostEnrollment>,
    ever_enrolled: BTreeSet<RemoteHostId>,
    next: EnrollmentGeneration,
    /// Written through a shared reference; see [`KnownHosts::record_rejection`].
    rejections: RejectionBook,
}

impl Default for KnownHosts {
    fn default() -> Self {
        Self::new()
    }
}

impl KnownHosts {
    /// No host enrolled.
    pub fn new() -> Self {
        Self {
            active: BTreeMap::new(),
            ever_enrolled: BTreeSet::new(),
            next: EnrollmentGeneration::FIRST,
            rejections: RejectionBook::default(),
        }
    }

    /// Enrolls `presented` for `host` through the flow `evidence` belongs to. Enrolling
    /// the same key again returns the existing enrollment; another key is refused. A
    /// rejected enrollment no longer holds the host: it is enrolled again like a retired
    /// one, through a flow other than first use, under a new generation.
    pub fn enroll(
        &mut self,
        host: RemoteHostId,
        presented: &HostKey,
        evidence: EnrollmentEvidence,
        policy: EnrollmentPolicy,
        now: MonotonicTime,
    ) -> Result<HostEnrollment, EnrollmentRefusal> {
        let fingerprint = presented.fingerprint();
        if let Some(existing) = self.enrollment(&host) {
            if existing.fingerprint == fingerprint {
                return Ok(existing.clone());
            }
            return Err(EnrollmentRefusal::HostKeyChanged {
                host,
                enrolled: existing.fingerprint,
                presented: fingerprint,
            });
        }
        match evidence.expected() {
            Some(expected) if expected != fingerprint => {
                return Err(EnrollmentRefusal::EvidenceMismatch {
                    flow: evidence.flow(),
                    expected,
                    presented: fingerprint,
                })
            }
            Some(_) => {}
            None => {
                if !policy.allow_first_use {
                    return Err(EnrollmentRefusal::FirstUseNotPermitted);
                }
                if self.ever_enrolled.contains(&host) {
                    return Err(EnrollmentRefusal::NotFirstUse { host });
                }
            }
        }
        let generation = self.next;
        self.next = generation
            .next()
            .ok_or(EnrollmentRefusal::GenerationsExhausted)?;
        let enrollment = HostEnrollment {
            host,
            fingerprint,
            flow: evidence.flow(),
            assumptions: evidence.assumptions(),
            generation,
            enrolled_at: now,
        };
        self.active.insert(host, enrollment.clone());
        self.ever_enrolled.insert(host);
        Ok(enrollment)
    }

    /// The enrollment `presented` matches; a changed key is refused (VM-W41), and so is
    /// every key once the enrollment was rejected.
    pub fn verify(
        &self,
        host: &RemoteHostId,
        presented: &HostKey,
    ) -> Result<&HostEnrollment, HostKeyRefusal> {
        let enrollment = self
            .active
            .get(host)
            .ok_or(HostKeyRefusal::NotEnrolled { host: *host })?;
        if self.rejections.contains(host, enrollment.generation) {
            return Err(HostKeyRefusal::Rejected {
                host: *host,
                generation: enrollment.generation,
            });
        }
        let fingerprint = presented.fingerprint();
        if enrollment.fingerprint != fingerprint {
            return Err(HostKeyRefusal::Changed {
                host: *host,
                enrolled: enrollment.fingerprint,
                presented: fingerprint,
            });
        }
        Ok(enrollment)
    }

    /// The host's current enrollment; none once it was retired or rejected.
    pub fn enrollment(&self, host: &RemoteHostId) -> Option<&HostEnrollment> {
        self.active
            .get(host)
            .filter(|enrollment| !self.rejections.contains(host, enrollment.generation))
    }

    /// Ends `host`'s enrollment explicitly; a later enrollment cannot use first use.
    pub fn retire(&mut self, host: &RemoteHostId) -> Option<HostEnrollment> {
        self.active.remove(host)
    }

    /// Records that `host`, enrolled under `generation`, presented another key than the
    /// enrolled one, as `observer` saw it with `evidence` (M16E). From then on that
    /// enrollment is refused by [`KnownHosts::verify`] for every key, is no longer
    /// [`KnownHosts::enrollment`], and fails [`ManagementIdentity::check_current`], until
    /// the host is enrolled again. A shared reference suffices: a rejection only ever
    /// narrows what this book accepts, and every holder sees it at once. The first record
    /// for an enrollment is kept and returned again; a generation that is not the host's
    /// current one is refused and nothing is recorded.
    pub fn record_rejection(
        &self,
        host: &RemoteHostId,
        generation: EnrollmentGeneration,
        observer: RejectionObserver,
        evidence: RejectionEvidence,
        now: MonotonicTime,
    ) -> Result<HostKeyRejection, RejectionRefusal> {
        if let Some(existing) = self.rejections.get(host, generation) {
            return Ok(existing);
        }
        match self.active.get(host) {
            Some(enrollment) if enrollment.generation == generation => {
                Ok(self.rejections.insert_first(HostKeyRejection {
                    enrollment: enrollment.clone(),
                    observer,
                    evidence,
                    rejected_at: now,
                }))
            }
            current => Err(RejectionRefusal::NotCurrent {
                host: *host,
                current: current.map(|enrollment| enrollment.generation),
                presented: generation,
            }),
        }
    }

    /// The rejection of `host`'s enrollment `generation`, if one was recorded.
    pub fn rejection(
        &self,
        host: &RemoteHostId,
        generation: EnrollmentGeneration,
    ) -> Option<HostKeyRejection> {
        self.rejections.get(host, generation)
    }

    /// Every rejection recorded, by host and generation.
    pub fn rejections(&self) -> Vec<HostKeyRejection> {
        self.rejections.all()
    }
}

/// A POSIX account name on the remote host: 1–32 characters, a lowercase letter or `_`
/// first, then lowercase letters, digits, `_` or `-`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct RemoteAccountName(String);

impl RemoteAccountName {
    pub const MAX_LEN: usize = 32;

    pub fn new(value: impl Into<String>) -> Result<Self, ManagementRefusal> {
        let value = value.into();
        let mut bytes = value.bytes();
        let first_ok = bytes
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte == b'_');
        let rest_ok = bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        });
        if !first_ok || !rest_ok || value.len() > Self::MAX_LEN {
            return Err(ManagementRefusal::InvalidAccount);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RemoteAccountName {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The login shell of the remote management account. Only a POSIX shell is supported,
/// because the argv encoder targets POSIX quoting only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteShellKind {
    Posix,
    Csh,
    Fish,
    Other,
}

/// What the management identity may do (VM-W41). None of these is workload authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ManagementAction {
    LaunchVm,
    SuperviseVm,
    TerminateVm,
    /// VM-D14: replace the bootstrap Jupyter password over SSH after the pod runs.
    ReplaceJupyterPassword,
    CollectLogs,
}

impl ManagementAction {
    pub const ALL: [Self; 5] = [
        Self::LaunchVm,
        Self::SuperviseVm,
        Self::TerminateVm,
        Self::ReplaceJupyterPassword,
        Self::CollectLogs,
    ];
}

strict_remote_enum! {
    /// Why a management step was refused.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum ManagementRefusal tag "refusal" {
        InvalidAccount,
        /// Only a POSIX login shell is supported.
        UnsupportedShell { shell: RemoteShellKind },
        NoActions,
        ActionNotPermitted { action: ManagementAction },
        /// The identity belongs to an enrollment that is no longer the host's current one.
        StaleEnrollment {
            host: RemoteHostId,
            current: Option<EnrollmentGeneration>,
            presented: EnrollmentGeneration,
        },
        /// The identity's enrollment was rejected after the host presented another key
        /// (M16E).
        HostKeyRejected {
            host: RemoteHostId,
            generation: EnrollmentGeneration,
        },
        /// The context names another host than the identity's.
        WrongHost { identity: RemoteHostId, context: RemoteHostId },
        /// The action does not run in this context.
        WrongContext { action: ManagementAction },
    }
}

impl fmt::Display for ManagementRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAccount => f.write_str(
                "a remote account name is 1-32 lowercase letters, digits, '_' or '-', starting \
                 with a letter or '_'",
            ),
            Self::UnsupportedShell { shell } => write!(
                f,
                "the remote account's shell is {shell:?}; only a POSIX shell is supported"
            ),
            Self::NoActions => f.write_str("a management identity needs at least one action"),
            Self::ActionNotPermitted { action } => {
                write!(f, "the management identity may not {action:?}")
            }
            Self::StaleEnrollment { host, .. } => write!(
                f,
                "the management identity belongs to an earlier enrollment of host {host}"
            ),
            Self::HostKeyRejected { host, generation } => write!(
                f,
                "the management identity belongs to enrollment {generation} of host {host}, \
                 rejected after the host presented another key"
            ),
            Self::WrongHost { .. } => {
                f.write_str("the command targets another host than the management identity's")
            }
            Self::WrongContext { action } => {
                write!(f, "{action:?} does not run in this execution context")
            }
        }
    }
}

impl std::error::Error for ManagementRefusal {}

/// The identity that launches and supervises a remote VM over SSH (VM-W41). It is
/// separate from workload authority: it holds no lease, grant or permission tuple and
/// cannot be given one, and reading it refuses unknown fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagementIdentity {
    host: RemoteHostId,
    enrollment: EnrollmentGeneration,
    fingerprint: HostKeyFingerprint,
    account: RemoteAccountName,
    /// The SSH client key held at home, named by handle. This identity is not a vault grant.
    client_key: CredentialRef,
    actions: BTreeSet<ManagementAction>,
}

impl ManagementIdentity {
    /// An identity for `account` on an enrolled host. Only a POSIX login shell is
    /// accepted, and at least one action.
    pub fn new(
        enrollment: &HostEnrollment,
        account: RemoteAccountName,
        client_key: CredentialRef,
        shell: RemoteShellKind,
        actions: BTreeSet<ManagementAction>,
    ) -> Result<Self, ManagementRefusal> {
        if shell != RemoteShellKind::Posix {
            return Err(ManagementRefusal::UnsupportedShell { shell });
        }
        if actions.is_empty() {
            return Err(ManagementRefusal::NoActions);
        }
        Ok(Self {
            host: enrollment.host,
            enrollment: enrollment.generation,
            fingerprint: enrollment.fingerprint,
            account,
            client_key,
            actions,
        })
    }

    pub fn host(&self) -> RemoteHostId {
        self.host
    }

    pub fn enrollment(&self) -> EnrollmentGeneration {
        self.enrollment
    }

    pub fn account(&self) -> &RemoteAccountName {
        &self.account
    }

    pub fn client_key(&self) -> CredentialRef {
        self.client_key
    }

    pub fn actions(&self) -> &BTreeSet<ManagementAction> {
        &self.actions
    }

    /// Refuses an action the identity was not given.
    pub fn permits(&self, action: ManagementAction) -> Result<(), ManagementRefusal> {
        if self.actions.contains(&action) {
            Ok(())
        } else {
            Err(ManagementRefusal::ActionNotPermitted { action })
        }
    }

    /// Refuses the identity once its enrollment is no longer the host's current one, or
    /// was rejected.
    pub fn check_current(&self, known: &KnownHosts) -> Result<(), ManagementRefusal> {
        if known.rejection(&self.host, self.enrollment).is_some() {
            return Err(ManagementRefusal::HostKeyRejected {
                host: self.host,
                generation: self.enrollment,
            });
        }
        match known.enrollment(&self.host) {
            Some(current)
                if current.generation == self.enrollment
                    && current.fingerprint == self.fingerprint =>
            {
                Ok(())
            }
            current => Err(ManagementRefusal::StaleEnrollment {
                host: self.host,
                current: current.map(|enrollment| enrollment.generation),
                presented: self.enrollment,
            }),
        }
    }
}

/// One VM launched on a remote host, by the digest of its stable handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RemoteVmId(Digest);

impl RemoteVmId {
    pub const fn new(digest: Digest) -> Self {
        Self(digest)
    }

    pub const fn digest(&self) -> &Digest {
        &self.0
    }
}

strict_remote_enum! {
    /// Where a remote command runs or an observation comes from (VM-W41: a host shell is
    /// not the sandbox).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum ExecutionContext tag "context" {
        /// A shell on the remote host itself, outside any VM.
        RemoteHostShell { host: RemoteHostId },
        /// A shell inside a provider container, a labelled runtime (VM-D5).
        ProviderContainer { host: RemoteHostId },
        /// The workload VM launched on the host.
        VmWorkload { host: RemoteHostId, vm: RemoteVmId },
    }
}

impl ExecutionContext {
    pub const fn host(&self) -> RemoteHostId {
        match self {
            Self::RemoteHostShell { host }
            | Self::ProviderContainer { host }
            | Self::VmWorkload { host, .. } => *host,
        }
    }
}

strict_remote_enum! {
    /// What a management observation saw.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum RemoteCapability tag "capability" {
        /// A command ran.
        ShellCommand,
        /// The host reports hardware virtualization, such as /dev/kvm.
        HardwareVirtualization { available: bool },
        /// A VM is running, on the hardware accelerator or emulated.
        VmRunning { hardware_accelerated: bool },
    }
}

strict_remote_enum! {
    /// Why remote evidence does not satisfy a predicate.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RemoteEvidenceRefusal tag "refusal" {
        /// A remote host shell is not the sandbox (VM-W41).
        HostShellIsNotTheSandbox { predicate: SecurityPredicate },
        /// A provider container is a labelled runtime, never a VM sandbox (VM-D5).
        ProviderContainerIsNotASandbox { predicate: SecurityPredicate },
        /// An emulated VM is never a compliant sandbox (VM-P42: no TCG).
        EmulatedVm { predicate: SecurityPredicate },
        /// Management observes nothing that could satisfy this predicate.
        NotObservedByManagement { predicate: SecurityPredicate },
    }
}

impl fmt::Display for RemoteEvidenceRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostShellIsNotTheSandbox { predicate } => write!(
                f,
                "a remote host shell is not the sandbox, so it never shows {predicate}"
            ),
            Self::ProviderContainerIsNotASandbox { predicate } => write!(
                f,
                "a remote runtime (provider container) is not a sandbox, so it never shows \
                 {predicate}"
            ),
            Self::EmulatedVm { predicate } => {
                write!(f, "an emulated VM never shows {predicate}")
            }
            Self::NotObservedByManagement { predicate } => {
                write!(f, "management observations do not show {predicate}")
            }
        }
    }
}

impl std::error::Error for RemoteEvidenceRefusal {}

/// One observation made through the management identity, with its context and the
/// trust assumptions of the enrollment it was made under.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteCapabilityEvidence {
    pub context: ExecutionContext,
    pub capability: RemoteCapability,
    pub enrollment: EnrollmentGeneration,
    pub assumptions: BTreeSet<TrustAssumption>,
    pub observed_at: MonotonicTime,
}

impl RemoteCapabilityEvidence {
    /// An observation under `enrollment`, carrying its assumptions.
    pub fn observed(
        enrollment: &HostEnrollment,
        context: ExecutionContext,
        capability: RemoteCapability,
        observed_at: MonotonicTime,
    ) -> Self {
        Self {
            context,
            capability,
            enrollment: enrollment.generation,
            assumptions: enrollment.assumptions.clone(),
            observed_at,
        }
    }

    /// Whether this evidence can stand for `predicate`. Only a hardware-accelerated VM
    /// workload can, and only for [`SecurityPredicate::VmSandbox`] and
    /// [`SecurityPredicate::HardwareAcceleratedBoot`]; a host shell or a provider
    /// container never can.
    pub fn supports(
        &self,
        predicate: SecurityPredicate,
    ) -> Result<VmWorkloadEvidence, RemoteEvidenceRefusal> {
        let (host, vm) = match self.context {
            ExecutionContext::RemoteHostShell { .. } => {
                return Err(RemoteEvidenceRefusal::HostShellIsNotTheSandbox { predicate })
            }
            ExecutionContext::ProviderContainer { .. } => {
                return Err(RemoteEvidenceRefusal::ProviderContainerIsNotASandbox { predicate })
            }
            ExecutionContext::VmWorkload { host, vm } => (host, vm),
        };
        if !matches!(
            predicate,
            SecurityPredicate::VmSandbox | SecurityPredicate::HardwareAcceleratedBoot
        ) {
            return Err(RemoteEvidenceRefusal::NotObservedByManagement { predicate });
        }
        match self.capability {
            RemoteCapability::VmRunning {
                hardware_accelerated: true,
            } => Ok(VmWorkloadEvidence {
                host,
                vm,
                enrollment: self.enrollment,
                assumptions: self.assumptions.clone(),
            }),
            RemoteCapability::VmRunning {
                hardware_accelerated: false,
            } => Err(RemoteEvidenceRefusal::EmulatedVm { predicate }),
            RemoteCapability::ShellCommand | RemoteCapability::HardwareVirtualization { .. } => {
                Err(RemoteEvidenceRefusal::NotObservedByManagement { predicate })
            }
        }
    }
}

/// A hardware-accelerated VM workload as management observed it. It is input for a
/// CORE-01 runtime-category observation, not a verdict: CORE-01 still decides whether its
/// source suffices.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct VmWorkloadEvidence {
    pub host: RemoteHostId,
    pub vm: RemoteVmId,
    pub enrollment: EnrollmentGeneration,
    pub assumptions: BTreeSet<TrustAssumption>,
}

impl VmWorkloadEvidence {
    /// The CORE-01 runtime instance this evidence is about: the VM, never the host.
    pub fn instance(&self) -> Digest {
        *self.vm.digest()
    }

    /// The CORE-01 detail a runtime-category observation of the VM reports.
    pub fn runtime_detail(&self) -> SupportDetail {
        SupportDetail::RuntimeCategory {
            category: ExecutionCategory::VmSandbox,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox_contract::remote::fakes::{host_id, host_key, mgmt_key, vm_id};

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * 1_000_000_000)
    }

    fn strict() -> EnrollmentPolicy {
        EnrollmentPolicy::default()
    }

    #[test]
    fn fingerprints_bind_algorithm_and_key() {
        let a = HostKey::new(HostKeyAlgorithm::Ed25519, vec![1; 32]).unwrap();
        let b = HostKey::new(HostKeyAlgorithm::EcdsaNistp256, vec![1; 32]).unwrap();
        let c = HostKey::new(HostKeyAlgorithm::Ed25519, vec![2; 32]).unwrap();
        assert_ne!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.fingerprint(), c.fingerprint());
        assert_eq!(a.fingerprint(), a.clone().fingerprint());
        assert_eq!(
            HostKey::new(HostKeyAlgorithm::Ed25519, Vec::new()),
            Err(HostKeyProblem::Empty)
        );
        assert!(matches!(
            HostKey::new(HostKeyAlgorithm::Ed25519, vec![0; MAX_HOST_KEY_BYTES + 1]),
            Err(HostKeyProblem::TooLong { .. })
        ));
    }

    #[test]
    fn supported_flows_enroll_and_record_their_assumptions() {
        let key = host_key(1);
        for (evidence, assumption) in [
            (
                EnrollmentEvidence::OwnerPinned {
                    expected: key.fingerprint(),
                },
                TrustAssumption::OwnerVerifiedKey,
            ),
            (
                EnrollmentEvidence::InjectedAtProvisioning {
                    injected: key.fingerprint(),
                },
                TrustAssumption::ProviderDeliveredKey,
            ),
            (
                EnrollmentEvidence::ProviderApi {
                    reported: key.fingerprint(),
                },
                TrustAssumption::ProviderReportedKey,
            ),
            (
                EnrollmentEvidence::ProviderConsole {
                    reported: key.fingerprint(),
                },
                TrustAssumption::ProviderReportedKey,
            ),
        ] {
            let mut known = KnownHosts::new();
            let enrollment = known
                .enroll(host_id(1), &key, evidence, strict(), at(5))
                .unwrap();
            assert_eq!(enrollment.flow, evidence.flow());
            assert_eq!(enrollment.assumptions, BTreeSet::from([assumption]));
            assert_eq!(enrollment.generation, EnrollmentGeneration::FIRST);
            assert_eq!(known.verify(&host_id(1), &key), Ok(&enrollment));
        }
    }

    #[test]
    fn first_use_is_refused_unless_permitted_and_then_recorded_never_hidden() {
        let mut known = KnownHosts::new();
        assert_eq!(
            known.enroll(
                host_id(1),
                &host_key(1),
                EnrollmentEvidence::FirstUse,
                strict(),
                at(0)
            ),
            Err(EnrollmentRefusal::FirstUseNotPermitted)
        );
        let permitted = EnrollmentPolicy {
            allow_first_use: true,
        };
        let enrollment = known
            .enroll(
                host_id(1),
                &host_key(1),
                EnrollmentEvidence::FirstUse,
                permitted,
                at(0),
            )
            .unwrap();
        assert_eq!(
            enrollment.assumptions,
            BTreeSet::from([TrustAssumption::FirstUse])
        );
        // The assumption travels into every observation made under the enrollment.
        let evidence = RemoteCapabilityEvidence::observed(
            &enrollment,
            ExecutionContext::RemoteHostShell { host: host_id(1) },
            RemoteCapability::ShellCommand,
            at(1),
        );
        assert!(evidence.assumptions.contains(&TrustAssumption::FirstUse));
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["assumptions"], serde_json::json!(["first_use"]));
    }

    #[test]
    fn owner_pin_must_match_and_cannot_replace_an_existing_key() {
        let mut known = KnownHosts::new();
        let expected = EnrollmentEvidence::OwnerPinned {
            expected: host_key(1).fingerprint(),
        };
        assert!(matches!(
            known.enroll(host_id(1), &host_key(2), expected, strict(), at(0)),
            Err(EnrollmentRefusal::EvidenceMismatch { .. })
        ));
        assert!(known.enrollment(&host_id(1)).is_none());
        known
            .enroll(host_id(1), &host_key(1), expected, strict(), at(1))
            .unwrap();
        assert!(matches!(
            known.enroll(
                host_id(1),
                &host_key(2),
                EnrollmentEvidence::OwnerPinned {
                    expected: host_key(2).fingerprint()
                },
                strict(),
                at(2)
            ),
            Err(EnrollmentRefusal::HostKeyChanged { .. })
        ));
    }

    #[test]
    fn a_changed_host_key_is_refused_and_never_replaced_in_place() {
        let mut known = KnownHosts::new();
        let original = known
            .enroll(
                host_id(1),
                &host_key(1),
                EnrollmentEvidence::ProviderApi {
                    reported: host_key(1).fingerprint(),
                },
                strict(),
                at(0),
            )
            .unwrap();
        assert_eq!(
            known.verify(&host_id(1), &host_key(2)),
            Err(HostKeyRefusal::Changed {
                host: host_id(1),
                enrolled: host_key(1).fingerprint(),
                presented: host_key(2).fingerprint(),
            })
        );
        // Even with matching provider evidence for the new key, no in-place replacement.
        assert!(matches!(
            known.enroll(
                host_id(1),
                &host_key(2),
                EnrollmentEvidence::ProviderApi {
                    reported: host_key(2).fingerprint()
                },
                strict(),
                at(1)
            ),
            Err(EnrollmentRefusal::HostKeyChanged { .. })
        ));
        assert_eq!(known.enrollment(&host_id(1)), Some(&original));
        assert_eq!(
            known.verify(&host_id(2), &host_key(1)),
            Err(HostKeyRefusal::NotEnrolled { host: host_id(2) })
        );
    }

    #[test]
    fn re_enrollment_needs_a_supported_flow_and_a_new_generation() {
        let mut known = KnownHosts::new();
        let permitted = EnrollmentPolicy {
            allow_first_use: true,
        };
        let first = known
            .enroll(
                host_id(1),
                &host_key(1),
                EnrollmentEvidence::FirstUse,
                permitted,
                at(0),
            )
            .unwrap();
        known.retire(&host_id(1));
        assert_eq!(
            known.enroll(
                host_id(1),
                &host_key(2),
                EnrollmentEvidence::FirstUse,
                permitted,
                at(1)
            ),
            Err(EnrollmentRefusal::NotFirstUse { host: host_id(1) })
        );
        let second = known
            .enroll(
                host_id(1),
                &host_key(2),
                EnrollmentEvidence::InjectedAtProvisioning {
                    injected: host_key(2).fingerprint(),
                },
                permitted,
                at(2),
            )
            .unwrap();
        assert!(second.generation > first.generation);
    }

    #[test]
    fn evidence_for_another_key_is_refused() {
        let mut known = KnownHosts::new();
        assert!(matches!(
            known.enroll(
                host_id(1),
                &host_key(1),
                EnrollmentEvidence::ProviderConsole {
                    reported: host_key(9).fingerprint()
                },
                strict(),
                at(0)
            ),
            Err(EnrollmentRefusal::EvidenceMismatch {
                flow: EnrollmentFlow::ProviderConsole,
                ..
            })
        ));
        assert!(known.enrollment(&host_id(1)).is_none());
    }

    fn enrolled(known: &mut KnownHosts) -> HostEnrollment {
        known
            .enroll(
                host_id(1),
                &host_key(1),
                EnrollmentEvidence::ProviderApi {
                    reported: host_key(1).fingerprint(),
                },
                strict(),
                at(0),
            )
            .unwrap()
    }

    #[test]
    fn the_management_identity_cannot_carry_workload_grants() {
        let mut known = KnownHosts::new();
        let enrollment = enrolled(&mut known);
        let identity = ManagementIdentity::new(
            &enrollment,
            RemoteAccountName::new("yougori").unwrap(),
            mgmt_key(),
            RemoteShellKind::Posix,
            BTreeSet::from([ManagementAction::LaunchVm]),
        )
        .unwrap();
        let value = serde_json::to_value(&identity).unwrap();
        assert_eq!(
            serde_json::from_value::<ManagementIdentity>(value.clone()).unwrap(),
            identity
        );
        for smuggled in ["lease", "grants", "permitted", "workload"] {
            let mut tampered = value.clone();
            tampered[smuggled] = serde_json::json!([]);
            assert!(
                serde_json::from_value::<ManagementIdentity>(tampered).is_err(),
                "{smuggled}"
            );
        }
        // Workload operations are not management actions.
        for workload in ["network_connect", "volume_write", "device_use", "run"] {
            assert!(
                serde_json::from_value::<ManagementAction>(serde_json::json!(workload)).is_err()
            );
        }
        assert_eq!(identity.permits(ManagementAction::LaunchVm), Ok(()));
        assert_eq!(
            identity.permits(ManagementAction::ReplaceJupyterPassword),
            Err(ManagementRefusal::ActionNotPermitted {
                action: ManagementAction::ReplaceJupyterPassword
            })
        );
    }

    #[test]
    fn only_a_posix_shell_is_supported_and_identities_go_stale_with_their_enrollment() {
        let mut known = KnownHosts::new();
        let enrollment = enrolled(&mut known);
        for shell in [
            RemoteShellKind::Csh,
            RemoteShellKind::Fish,
            RemoteShellKind::Other,
        ] {
            assert_eq!(
                ManagementIdentity::new(
                    &enrollment,
                    RemoteAccountName::new("yougori").unwrap(),
                    mgmt_key(),
                    shell,
                    BTreeSet::from([ManagementAction::SuperviseVm]),
                ),
                Err(ManagementRefusal::UnsupportedShell { shell })
            );
        }
        assert_eq!(
            ManagementIdentity::new(
                &enrollment,
                RemoteAccountName::new("yougori").unwrap(),
                mgmt_key(),
                RemoteShellKind::Posix,
                BTreeSet::new(),
            ),
            Err(ManagementRefusal::NoActions)
        );
        let identity = ManagementIdentity::new(
            &enrollment,
            RemoteAccountName::new("yougori").unwrap(),
            mgmt_key(),
            RemoteShellKind::Posix,
            BTreeSet::from([ManagementAction::SuperviseVm]),
        )
        .unwrap();
        assert_eq!(identity.check_current(&known), Ok(()));
        known.retire(&host_id(1));
        known
            .enroll(
                host_id(1),
                &host_key(2),
                EnrollmentEvidence::ProviderApi {
                    reported: host_key(2).fingerprint(),
                },
                strict(),
                at(3),
            )
            .unwrap();
        assert!(matches!(
            identity.check_current(&known),
            Err(ManagementRefusal::StaleEnrollment { .. })
        ));
    }

    #[test]
    fn account_names_are_posix_names() {
        for good in ["yougori", "_svc", "a-b_9"] {
            assert!(RemoteAccountName::new(good).is_ok(), "{good}");
        }
        for bad in ["", "Root", "9lives", "a b", "a;b", "a$(x)", &"a".repeat(33)] {
            assert_eq!(
                RemoteAccountName::new(bad),
                Err(ManagementRefusal::InvalidAccount),
                "{bad}"
            );
        }
    }

    #[test]
    fn a_host_shell_never_satisfies_any_predicate() {
        let mut known = KnownHosts::new();
        let enrollment = enrolled(&mut known);
        for capability in [
            RemoteCapability::ShellCommand,
            RemoteCapability::HardwareVirtualization { available: true },
            RemoteCapability::VmRunning {
                hardware_accelerated: true,
            },
        ] {
            let evidence = RemoteCapabilityEvidence::observed(
                &enrollment,
                ExecutionContext::RemoteHostShell { host: host_id(1) },
                capability,
                at(1),
            );
            for predicate in SecurityPredicate::ALL {
                assert_eq!(
                    evidence.supports(predicate),
                    Err(RemoteEvidenceRefusal::HostShellIsNotTheSandbox { predicate })
                );
            }
            let container = RemoteCapabilityEvidence {
                context: ExecutionContext::ProviderContainer { host: host_id(1) },
                ..evidence
            };
            for predicate in SecurityPredicate::ALL {
                assert_eq!(
                    container.supports(predicate),
                    Err(RemoteEvidenceRefusal::ProviderContainerIsNotASandbox { predicate })
                );
            }
        }
    }

    #[test]
    fn an_accelerated_vm_workload_supports_the_vm_predicate_and_an_emulated_one_never() {
        let mut known = KnownHosts::new();
        let enrollment = enrolled(&mut known);
        let workload = ExecutionContext::VmWorkload {
            host: host_id(1),
            vm: vm_id(1),
        };
        let accelerated = RemoteCapabilityEvidence::observed(
            &enrollment,
            workload,
            RemoteCapability::VmRunning {
                hardware_accelerated: true,
            },
            at(1),
        );
        let supported = accelerated.supports(SecurityPredicate::VmSandbox).unwrap();
        assert_eq!(supported.instance(), *vm_id(1).digest());
        assert_ne!(supported.instance(), *host_id(1).digest());
        assert_eq!(
            supported.runtime_detail(),
            SupportDetail::RuntimeCategory {
                category: ExecutionCategory::VmSandbox
            }
        );
        assert_eq!(
            accelerated.supports(SecurityPredicate::VerifiedConfidentialVm),
            Err(RemoteEvidenceRefusal::NotObservedByManagement {
                predicate: SecurityPredicate::VerifiedConfidentialVm
            })
        );
        let emulated = RemoteCapabilityEvidence {
            capability: RemoteCapability::VmRunning {
                hardware_accelerated: false,
            },
            ..accelerated
        };
        assert_eq!(
            emulated.supports(SecurityPredicate::VmSandbox),
            Err(RemoteEvidenceRefusal::EmulatedVm {
                predicate: SecurityPredicate::VmSandbox
            })
        );
    }

    #[test]
    fn contexts_are_read_strictly() {
        let context = ExecutionContext::RemoteHostShell { host: host_id(1) };
        let mut value = serde_json::to_value(context).unwrap();
        assert_eq!(value["context"], "remote_host_shell");
        value["vm"] = serde_json::json!(vm_id(1));
        assert!(serde_json::from_value::<ExecutionContext>(value).is_err());
        let evidence = EnrollmentEvidence::FirstUse;
        let mut value = serde_json::to_value(evidence).unwrap();
        value["reported"] = serde_json::json!(host_key(1).fingerprint());
        assert!(serde_json::from_value::<EnrollmentEvidence>(value).is_err());
    }
}
