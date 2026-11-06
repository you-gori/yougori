//! M16E: a rejected host key ends delegation and holds everywhere (M16 (c4); VM-W41
//! acceptance "host-key changes rejected"; VM part §6.3, §7.6; VM-P40).
//!
//! A host that presents another key than its enrolled one is not known to be the enrolled
//! host. [`KnownHosts`] keeps one [`HostKeyRejection`] per host and enrollment generation:
//! the enrollment rejected, when, which observer saw it (the adapter's control connect or a
//! management SSH call) and the evidence (the presented key's fingerprint when the
//! observer had the key, or what the SSH client printed).
//!
//! - Once recorded, [`KnownHosts::verify`] refuses that enrollment for every key, the
//!   enrolled one included, [`KnownHosts::enrollment`] no longer returns it and
//!   [`ManagementIdentity::check_current`] refuses identities made from it, so every check
//!   built on them refuses too: management invocations, the `known_hosts` file the SSH
//!   layer renders from the enrollment, a control reconnect.
//! - It holds until the host is enrolled again through a supported flow, never first use
//!   (the host was enrolled before), which makes a new generation. The record is kept.
//! - Recording takes a shared reference. A rejection only ever narrows what the book
//!   accepts, so whoever checks keys against it may record one, and every check through
//!   any reference sees it at once. The book is append-only and keeps the first record
//!   for an enrollment.
//! - [`RemoteVmAdapter::connect`] records a changed key it is shown, and
//!   [`RemoteVmAdapter::report_host_key_mismatch`] records what management's SSH client
//!   reported; either ends the run's delegated authority at once.
//!
//! `KnownHosts` itself is not persisted; the record's strict serialized form is what
//! survives (its serde round trip refuses unknown fields).
//!
//! [`KnownHosts`]: super::KnownHosts
//! [`KnownHosts::verify`]: super::KnownHosts::verify
//! [`KnownHosts::enrollment`]: super::KnownHosts::enrollment
//! [`ManagementIdentity::check_current`]: super::ManagementIdentity::check_current
//! [`RemoteVmAdapter::connect`]: super::RemoteVmAdapter::connect
//! [`RemoteVmAdapter::report_host_key_mismatch`]: super::RemoteVmAdapter::report_host_key_mismatch

use std::collections::BTreeMap;
use std::fmt;
use std::sync::{Mutex, MutexGuard, PoisonError};

use serde::{Deserialize, Serialize};

use super::ssh::{EnrollmentGeneration, HostEnrollment, HostKeyFingerprint, RemoteHostId};
use crate::foundation::ids::MonotonicTime;

/// Longest fingerprint text an SSH client printed that a record keeps.
pub const MAX_PRINTED_FINGERPRINT_BYTES: usize = 128;

/// Who saw the host present another key than the enrolled one.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectionObserver {
    /// The adapter checked the key a control connection presented.
    ControlConnect,
    /// The SSH client of a management call refused the host's key.
    ManagementSsh,
}

strict_remote_enum! {
    /// Why a rejection was not recorded, or its evidence not accepted.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RejectionRefusal tag "refusal" {
        /// The enrollment named is not the host's current one, so there is nothing to
        /// reject: the host was retired or enrolled again since.
        NotCurrent {
            host: RemoteHostId,
            current: Option<EnrollmentGeneration>,
            presented: EnrollmentGeneration,
        },
        /// Printed fingerprint text is 1 to `max_bytes` printable ASCII characters, no
        /// space.
        InvalidPrintedFingerprint { max_bytes: u64 },
    }
}

impl fmt::Display for RejectionRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotCurrent {
                host, presented, ..
            } => write!(
                f,
                "enrollment {presented} is not the current enrollment of host {host}, so it \
                 cannot be rejected"
            ),
            Self::InvalidPrintedFingerprint { max_bytes } => write!(
                f,
                "a printed host-key fingerprint is 1 to {max_bytes} printable ASCII \
                 characters without spaces"
            ),
        }
    }
}

impl std::error::Error for RejectionRefusal {}

/// A host-key fingerprint as an SSH client printed it, such as OpenSSH's `SHA256:` and 43
/// base64 characters. It is the client's digest of the presented key, not a
/// [`HostKeyFingerprint`], so it is kept as text: 1 to [`MAX_PRINTED_FINGERPRINT_BYTES`]
/// printable ASCII characters, no space. The SSH layer that read it checks its format.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct PrintedFingerprint(String);

impl PrintedFingerprint {
    /// Accepts 1 to [`MAX_PRINTED_FINGERPRINT_BYTES`] printable ASCII characters, no space.
    pub fn new(text: impl Into<String>) -> Result<Self, RejectionRefusal> {
        let text = text.into();
        if text.is_empty()
            || text.len() > MAX_PRINTED_FINGERPRINT_BYTES
            || !text.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(RejectionRefusal::InvalidPrintedFingerprint {
                max_bytes: u64::try_from(MAX_PRINTED_FINGERPRINT_BYTES).unwrap_or(u64::MAX),
            });
        }
        Ok(Self(text))
    }

    /// The text as printed.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrintedFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for PrintedFingerprint {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

strict_remote_enum! {
    /// What the observer had of the key presented instead of the enrolled one.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub enum RejectionEvidence tag "evidence" {
        /// The presented key itself, by its fingerprint.
        PresentedKey { presented: HostKeyFingerprint },
        /// The SSH client reported that the host key changed; `printed` is the
        /// fingerprint it printed for the presented key, when it printed one.
        SshKeyChanged { printed: Option<PrintedFingerprint> },
        /// The SSH client found that the host does not offer the enrolled key's
        /// algorithm, so it cannot present the enrolled key.
        SshAlgorithmNotOffered,
        /// The SSH client failed host-key verification for a reason not recognised.
        SshUnverified,
    }
}

/// One rejected enrollment: its host presented another key than the enrolled one
/// (VM-W41). The enrollment is refused from then on; see the module notes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostKeyRejection {
    /// The enrollment rejected, with its host, generation, key, flow and assumptions.
    pub enrollment: HostEnrollment,
    pub observer: RejectionObserver,
    pub evidence: RejectionEvidence,
    /// When the observer reported it, on the host clock.
    pub rejected_at: MonotonicTime,
}

impl HostKeyRejection {
    /// The host whose enrollment was rejected.
    pub fn host(&self) -> RemoteHostId {
        self.enrollment.host
    }

    /// The enrollment generation rejected.
    pub fn generation(&self) -> EnrollmentGeneration {
        self.enrollment.generation
    }
}

type RejectionMap = BTreeMap<(RemoteHostId, EnrollmentGeneration), HostKeyRejection>;

/// Every rejection, by host and generation, behind a lock so that a shared reference can
/// add to it. Append-only: a record is never replaced or removed. A clone is a separate
/// copy.
#[derive(Debug, Default)]
pub(super) struct RejectionBook(Mutex<RejectionMap>);

impl RejectionBook {
    fn records(&self) -> MutexGuard<'_, RejectionMap> {
        // Each step under the lock is one lookup or one insertion, so a panic elsewhere
        // while it was held leaves the map whole.
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether `host`'s enrollment `generation` was rejected.
    pub(super) fn contains(&self, host: &RemoteHostId, generation: EnrollmentGeneration) -> bool {
        self.records().contains_key(&(*host, generation))
    }

    /// The rejection of `host`'s enrollment `generation`, if one was recorded.
    pub(super) fn get(
        &self,
        host: &RemoteHostId,
        generation: EnrollmentGeneration,
    ) -> Option<HostKeyRejection> {
        self.records().get(&(*host, generation)).cloned()
    }

    /// Records `rejection` unless its enrollment already has one; returns the record kept.
    pub(super) fn insert_first(&self, rejection: HostKeyRejection) -> HostKeyRejection {
        self.records()
            .entry((rejection.host(), rejection.generation()))
            .or_insert(rejection)
            .clone()
    }

    /// Every record, by host and generation.
    pub(super) fn all(&self) -> Vec<HostKeyRejection> {
        self.records().values().cloned().collect()
    }
}

impl Clone for RejectionBook {
    fn clone(&self) -> Self {
        Self(Mutex::new(self.records().clone()))
    }
}

impl PartialEq for RejectionBook {
    fn eq(&self, other: &Self) -> bool {
        // One lock at a time: locking a mutex twice on one thread is not allowed, and
        // holding both could deadlock against a comparison the other way round.
        if std::ptr::eq(self, other) {
            return true;
        }
        let mine = self.records().clone();
        mine == *other.records()
    }
}

impl Eq for RejectionBook {}
