//! File grants (VM part §5.1 lines 2045–2057; VM-W14).
//!
//! A grant binds a host-selected root handle, permitted operations, trust scope, expiry
//! and quota. The guest names a file only relative to the root; which host directory the
//! handle opens stays with the host. Three modes exist: a read-only snapshot, quarantine
//! output and a live workspace. A live grant carries the acknowledged statement that the
//! workload can damage files there and implant executable content, and it never claims
//! that host-executed state stays unchanged (line 2057).

use std::collections::BTreeSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use super::names::GuestName;
use crate::foundation::evidence::ClockSession;
use crate::foundation::ids::{digest, Digest, ExecutionCategory, MonotonicTime, TrustScope};

/// The statement a live workspace grant shows and binds (line 2055: show that the workload
/// can damage or implant executable content there).
pub const LIVE_WORKSPACE_DISCLOSURE: &str = "The sandboxed workload can change, delete or \
damage any file in this folder, and can add or change executable content such as scripts, \
hooks and build files that this computer may later run. The VM boundary does not protect \
this folder.";

const DISCLOSURE_DOMAIN: &str = "yougori/sandbox/files/live-workspace-disclosure/v1";

/// An opaque reference to a root directory the host opened and selected (§5.1). Only the
/// host makes one; the guest never supplies a host path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct RootHandle(Digest);

impl RootHandle {
    /// The handle the host assigned when it opened the root.
    pub const fn from_host(identity: Digest) -> Self {
        Self(identity)
    }

    pub const fn digest(self) -> Digest {
        self.0
    }
}

/// One file operation a grant may permit (§5.1 "permitted operations").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileOperation {
    Read,
    List,
    Create,
    Write,
    Delete,
    Rename,
    SetExecutable,
}

impl FileOperation {
    /// Whether the operation changes the tree.
    pub const fn mutates(self) -> bool {
        !matches!(self, Self::Read | Self::List)
    }
}

/// The user's acknowledgment of [`LIVE_WORKSPACE_DISCLOSURE`]: the digest of the exact
/// statement shown, so a changed statement needs a new acknowledgment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DisclosureAcknowledgment(Digest);

impl DisclosureAcknowledgment {
    /// Acknowledges the statement shown today.
    pub fn of_current_statement() -> Self {
        Self(digest(
            DISCLOSURE_DOMAIN,
            &[LIVE_WORKSPACE_DISCLOSURE.as_bytes()],
        ))
    }

    /// An acknowledgment read back from a record.
    pub const fn from_digest(statement: Digest) -> Self {
        Self(statement)
    }

    pub fn is_current(self) -> bool {
        self == Self::of_current_statement()
    }
}

strict_tagged_enum! {
    /// The three grant modes of §5.1 (lines 2051–2055).
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub enum GrantMode (tag = "mode", wire = GrantModeWire, wire_name = "GrantModeWire") {
        /// An immutable input version, preferred for private analysis and reproducible
        /// builds.
        ReadOnlySnapshot { snapshot: Digest },
        /// Writes stay isolated until exact promotion.
        QuarantineOutput,
        /// Explicitly granted mutable scope for development, with the acknowledged
        /// disclosure.
        LiveWorkspace { acknowledgment: DisclosureAcknowledgment },
    }
}

impl GrantMode {
    /// Whether the mode allows `operation` at all.
    pub fn permits(self, operation: FileOperation) -> bool {
        match self {
            Self::ReadOnlySnapshot { .. } => !operation.mutates(),
            Self::QuarantineOutput | Self::LiveWorkspace { .. } => true,
        }
    }

    /// What the mode lets the product claim about host files (line 2057).
    pub fn host_state_claim(self) -> HostStateClaim {
        match self {
            Self::ReadOnlySnapshot { .. } => HostStateClaim::InputImmutable,
            Self::QuarantineOutput => HostStateClaim::IsolatedUntilPromotion,
            Self::LiveWorkspace { .. } => HostStateClaim::WorkloadCanChangeHostFiles {
                disclosure: LIVE_WORKSPACE_DISCLOSURE,
            },
        }
    }
}

/// What a grant lets the product say about host files (§5.1 line 2057).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "claim", rename_all = "snake_case")]
pub enum HostStateClaim {
    /// The workload reads a fixed version and cannot change it.
    InputImmutable,
    /// Writes reach the host only through an exact promotion.
    IsolatedUntilPromotion,
    /// Weaker host-artifact protection: the workload can change files the host may later
    /// execute.
    WorkloadCanChangeHostFiles { disclosure: &'static str },
}

impl HostStateClaim {
    /// Whether the product may say that no host-executed state can change. Never for a
    /// live workspace (line 2057).
    pub const fn host_executed_state_unchanged(self) -> bool {
        !matches!(self, Self::WorkloadCanChangeHostFiles { .. })
    }
}

/// Quota of one grant (§5.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileQuota {
    pub max_total_bytes: u64,
    pub max_entries: u64,
    pub max_file_bytes: u64,
}

/// What the granted root holds now, as the file service counts it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuotaUsage {
    pub total_bytes: u64,
    pub entries: u64,
}

/// Why a grant could not be made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum GrantProblem {
    NoOperations,
    /// The mode does not allow the operation, such as a write to a read-only snapshot.
    OperationOutsideMode {
        operation: FileOperation,
    },
    /// File grants belong to VM sandboxes; a labelled runtime is never one.
    NotAVmSandboxScope {
        category: ExecutionCategory,
    },
    /// The live workspace statement was not acknowledged as shown today.
    DisclosureNotAcknowledged,
}

impl fmt::Display for GrantProblem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoOperations => f.write_str("a grant needs at least one operation"),
            Self::OperationOutsideMode { operation } => {
                write!(f, "the grant's mode does not allow {operation:?}")
            }
            Self::NotAVmSandboxScope { category } => {
                write!(f, "\"{}\" is not a VM sandbox scope", category.label())
            }
            Self::DisclosureNotAcknowledged => {
                f.write_str("the live workspace statement was not acknowledged")
            }
        }
    }
}

impl std::error::Error for GrantProblem {}

/// One request against a grant. Sizes are the file's size before and after the request.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FileRequest {
    pub root: RootHandle,
    pub scope: TrustScope,
    pub operation: FileOperation,
    pub name: GuestName,
    pub previous_file_bytes: u64,
    pub resulting_file_bytes: u64,
}

/// Why a request was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "refusal", rename_all = "snake_case")]
pub enum GrantRefusal {
    /// The time was read on another clock session, such as after a restart.
    OtherClock,
    Expired {
        expired_at: MonotonicTime,
    },
    WrongRoot,
    WrongScope,
    OperationNotGranted {
        operation: FileOperation,
    },
    FileTooLarge {
        resulting_file_bytes: u64,
        max_file_bytes: u64,
    },
    TotalQuotaExceeded {
        resulting_total_bytes: u64,
        max_total_bytes: u64,
    },
    EntryQuotaExceeded {
        max_entries: u64,
    },
}

impl fmt::Display for GrantRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OtherClock => f.write_str("the grant was stamped on another clock session"),
            Self::Expired { expired_at } => {
                write!(f, "the grant expired at {} ns", expired_at.as_nanos())
            }
            Self::WrongRoot => f.write_str("the request names another root"),
            Self::WrongScope => f.write_str("the request comes from another trust scope"),
            Self::OperationNotGranted { operation } => {
                write!(f, "{operation:?} is not granted")
            }
            Self::FileTooLarge {
                resulting_file_bytes,
                max_file_bytes,
            } => write!(
                f,
                "the file would have {resulting_file_bytes} bytes; at most {max_file_bytes}"
            ),
            Self::TotalQuotaExceeded {
                resulting_total_bytes,
                max_total_bytes,
            } => write!(
                f,
                "the root would hold {resulting_total_bytes} bytes; at most {max_total_bytes}"
            ),
            Self::EntryQuotaExceeded { max_entries } => {
                write!(f, "the root already holds its {max_entries} entries")
            }
        }
    }
}

impl std::error::Error for GrantRefusal {}

/// A file grant (§5.1): root handle, operations, trust scope, expiry and quota.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "FileGrantWire")]
pub struct FileGrant {
    root: RootHandle,
    mode: GrantMode,
    operations: BTreeSet<FileOperation>,
    scope: TrustScope,
    clock: ClockSession,
    expires_at: MonotonicTime,
    quota: FileQuota,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FileGrantWire {
    root: RootHandle,
    mode: GrantMode,
    operations: BTreeSet<FileOperation>,
    scope: TrustScope,
    clock: ClockSession,
    expires_at: MonotonicTime,
    quota: FileQuota,
}

impl TryFrom<FileGrantWire> for FileGrant {
    type Error = GrantProblem;

    fn try_from(wire: FileGrantWire) -> Result<Self, Self::Error> {
        Self::new(
            wire.root,
            wire.mode,
            wire.operations,
            wire.scope,
            wire.clock,
            wire.expires_at,
            wire.quota,
        )
    }
}

impl FileGrant {
    /// A grant, refused when the mode cannot allow an operation, the scope is not a VM
    /// sandbox's, or a live workspace lacks the current acknowledgment.
    pub fn new(
        root: RootHandle,
        mode: GrantMode,
        operations: BTreeSet<FileOperation>,
        scope: TrustScope,
        clock: ClockSession,
        expires_at: MonotonicTime,
        quota: FileQuota,
    ) -> Result<Self, GrantProblem> {
        if operations.is_empty() {
            return Err(GrantProblem::NoOperations);
        }
        if let Some(operation) = operations
            .iter()
            .find(|operation| !mode.permits(**operation))
        {
            return Err(GrantProblem::OperationOutsideMode {
                operation: *operation,
            });
        }
        if !scope.category.is_vm_sandbox() {
            return Err(GrantProblem::NotAVmSandboxScope {
                category: scope.category,
            });
        }
        if let GrantMode::LiveWorkspace { acknowledgment } = mode {
            if !acknowledgment.is_current() {
                return Err(GrantProblem::DisclosureNotAcknowledged);
            }
        }
        Ok(Self {
            root,
            mode,
            operations,
            scope,
            clock,
            expires_at,
            quota,
        })
    }

    pub fn root(&self) -> RootHandle {
        self.root
    }

    pub fn mode(&self) -> GrantMode {
        self.mode
    }

    pub fn operations(&self) -> &BTreeSet<FileOperation> {
        &self.operations
    }

    pub fn scope(&self) -> TrustScope {
        self.scope
    }

    pub fn expires_at(&self) -> MonotonicTime {
        self.expires_at
    }

    pub fn quota(&self) -> FileQuota {
        self.quota
    }

    pub fn host_state_claim(&self) -> HostStateClaim {
        self.mode.host_state_claim()
    }

    /// Checks what does not depend on a name or sizes: the clock session, expiry, root,
    /// trust scope and that `operation` is granted. A listing of the root itself, which has
    /// no guest name, is authorized with this alone.
    pub fn authorize_operation(
        &self,
        operation: FileOperation,
        root: RootHandle,
        scope: TrustScope,
        now: MonotonicTime,
        session: ClockSession,
    ) -> Result<(), GrantRefusal> {
        if session != self.clock {
            return Err(GrantRefusal::OtherClock);
        }
        if now >= self.expires_at {
            return Err(GrantRefusal::Expired {
                expired_at: self.expires_at,
            });
        }
        if root != self.root {
            return Err(GrantRefusal::WrongRoot);
        }
        if scope != self.scope {
            return Err(GrantRefusal::WrongScope);
        }
        if !self.operations.contains(&operation) {
            return Err(GrantRefusal::OperationNotGranted { operation });
        }
        Ok(())
    }

    /// Checks one request at `now` on `session` against what the root holds (`usage`).
    pub fn authorize(
        &self,
        request: &FileRequest,
        now: MonotonicTime,
        session: ClockSession,
        usage: QuotaUsage,
    ) -> Result<(), GrantRefusal> {
        self.authorize_operation(request.operation, request.root, request.scope, now, session)?;
        if !matches!(
            request.operation,
            FileOperation::Create | FileOperation::Write
        ) {
            return Ok(());
        }
        if request.resulting_file_bytes > self.quota.max_file_bytes {
            return Err(GrantRefusal::FileTooLarge {
                resulting_file_bytes: request.resulting_file_bytes,
                max_file_bytes: self.quota.max_file_bytes,
            });
        }
        let resulting_total_bytes = usage
            .total_bytes
            .saturating_sub(request.previous_file_bytes)
            .saturating_add(request.resulting_file_bytes);
        if resulting_total_bytes > self.quota.max_total_bytes {
            return Err(GrantRefusal::TotalQuotaExceeded {
                resulting_total_bytes,
                max_total_bytes: self.quota.max_total_bytes,
            });
        }
        if request.operation == FileOperation::Create
            && usage.entries.saturating_add(1) > self.quota.max_entries
        {
            return Err(GrantRefusal::EntryQuotaExceeded {
                max_entries: self.quota.max_entries,
            });
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECOND_NANOS: u64 = 1_000_000_000;

    fn session(number: u128) -> ClockSession {
        ClockSession::from_uuid(uuid::Uuid::from_u128(number))
    }

    fn root() -> RootHandle {
        RootHandle::from_host(digest("yougori/test/root/v1", &[b"workspace"]))
    }

    fn scope() -> TrustScope {
        TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-a")
    }

    fn quota() -> FileQuota {
        FileQuota {
            max_total_bytes: 1_000,
            max_entries: 3,
            max_file_bytes: 600,
        }
    }

    fn at(seconds: u64) -> MonotonicTime {
        MonotonicTime::from_nanos(seconds * SECOND_NANOS)
    }

    fn grant(mode: GrantMode, operations: &[FileOperation]) -> Result<FileGrant, GrantProblem> {
        FileGrant::new(
            root(),
            mode,
            operations.iter().copied().collect(),
            scope(),
            session(1),
            at(100),
            quota(),
        )
    }

    fn request(operation: FileOperation, previous: u64, resulting: u64) -> FileRequest {
        FileRequest {
            root: root(),
            scope: scope(),
            operation,
            name: GuestName::parse("out/report.txt").unwrap(),
            previous_file_bytes: previous,
            resulting_file_bytes: resulting,
        }
    }

    fn live() -> GrantMode {
        GrantMode::LiveWorkspace {
            acknowledgment: DisclosureAcknowledgment::of_current_statement(),
        }
    }

    #[test]
    fn a_read_only_snapshot_can_never_be_granted_a_write() {
        let snapshot = GrantMode::ReadOnlySnapshot {
            snapshot: digest("yougori/test/snapshot/v1", &[b"v1"]),
        };
        for operation in [
            FileOperation::Create,
            FileOperation::Write,
            FileOperation::Delete,
            FileOperation::Rename,
            FileOperation::SetExecutable,
        ] {
            assert_eq!(
                grant(snapshot, &[FileOperation::Read, operation]),
                Err(GrantProblem::OperationOutsideMode { operation })
            );
        }
        let reader = grant(snapshot, &[FileOperation::Read, FileOperation::List]).unwrap();
        assert_eq!(reader.host_state_claim(), HostStateClaim::InputImmutable);
        assert_eq!(
            reader.authorize(
                &request(FileOperation::Write, 0, 1),
                at(1),
                session(1),
                QuotaUsage::default()
            ),
            Err(GrantRefusal::OperationNotGranted {
                operation: FileOperation::Write
            })
        );
    }

    #[test]
    fn a_live_workspace_needs_the_disclosure_and_never_claims_unchanged_host_state() {
        let stale = GrantMode::LiveWorkspace {
            acknowledgment: DisclosureAcknowledgment::from_digest(digest(
                DISCLOSURE_DOMAIN,
                &[b"an older, softer statement"],
            )),
        };
        assert_eq!(
            grant(stale, &[FileOperation::Write]),
            Err(GrantProblem::DisclosureNotAcknowledged)
        );
        let granted = grant(live(), &[FileOperation::Write]).unwrap();
        let claim = granted.host_state_claim();
        assert!(!claim.host_executed_state_unchanged());
        match claim {
            HostStateClaim::WorkloadCanChangeHostFiles { disclosure } => {
                assert!(disclosure.contains("damage"));
                assert!(disclosure.contains("executable content"));
            }
            other => panic!("{other:?}"),
        }
        assert!(HostStateClaim::InputImmutable.host_executed_state_unchanged());
        assert!(HostStateClaim::IsolatedUntilPromotion.host_executed_state_unchanged());
    }

    #[test]
    fn a_grant_belongs_to_a_vm_sandbox_scope_and_needs_an_operation() {
        let labelled = FileGrant::new(
            root(),
            GrantMode::QuarantineOutput,
            BTreeSet::from([FileOperation::Create]),
            TrustScope::named(ExecutionCategory::SharedKernelGpuRuntime, "wsl"),
            session(1),
            at(100),
            quota(),
        );
        assert_eq!(
            labelled,
            Err(GrantProblem::NotAVmSandboxScope {
                category: ExecutionCategory::SharedKernelGpuRuntime
            })
        );
        assert_eq!(
            grant(GrantMode::QuarantineOutput, &[]),
            Err(GrantProblem::NoOperations)
        );
    }

    #[test]
    fn requests_are_bound_to_root_scope_clock_and_expiry() {
        let output = grant(
            GrantMode::QuarantineOutput,
            &[FileOperation::Create, FileOperation::Read],
        )
        .unwrap();
        let create = request(FileOperation::Create, 0, 10);
        let usage = QuotaUsage::default();
        assert_eq!(output.authorize(&create, at(99), session(1), usage), Ok(()));
        assert_eq!(
            output.authorize(&create, at(100), session(1), usage),
            Err(GrantRefusal::Expired {
                expired_at: at(100)
            })
        );
        assert_eq!(
            output.authorize(&create, at(1), session(2), usage),
            Err(GrantRefusal::OtherClock)
        );
        let mut elsewhere = create.clone();
        elsewhere.root = RootHandle::from_host(digest("yougori/test/root/v1", &[b"home"]));
        assert_eq!(
            output.authorize(&elsewhere, at(1), session(1), usage),
            Err(GrantRefusal::WrongRoot)
        );
        let mut other = create.clone();
        other.scope = TrustScope::named(ExecutionCategory::VmSandbox, "sandbox-b");
        assert_eq!(
            output.authorize(&other, at(1), session(1), usage),
            Err(GrantRefusal::WrongScope)
        );
        assert_eq!(
            output.authorize(
                &request(FileOperation::Delete, 10, 0),
                at(1),
                session(1),
                usage
            ),
            Err(GrantRefusal::OperationNotGranted {
                operation: FileOperation::Delete
            })
        );
    }

    #[test]
    fn quotas_bound_file_size_total_bytes_and_entries() {
        let output = grant(
            GrantMode::QuarantineOutput,
            &[FileOperation::Create, FileOperation::Write],
        )
        .unwrap();
        let now = at(1);
        assert_eq!(
            output.authorize(
                &request(FileOperation::Create, 0, 601),
                now,
                session(1),
                QuotaUsage::default()
            ),
            Err(GrantRefusal::FileTooLarge {
                resulting_file_bytes: 601,
                max_file_bytes: 600
            })
        );
        let used = QuotaUsage {
            total_bytes: 900,
            entries: 2,
        };
        assert_eq!(
            output.authorize(
                &request(FileOperation::Create, 0, 101),
                now,
                session(1),
                used
            ),
            Err(GrantRefusal::TotalQuotaExceeded {
                resulting_total_bytes: 1_001,
                max_total_bytes: 1_000
            })
        );
        assert_eq!(
            output.authorize(
                &request(FileOperation::Create, 0, 100),
                now,
                session(1),
                used
            ),
            Ok(())
        );
        // Rewriting a 400-byte file as 500 bytes adds 100: 900 - 400 + 500 = 1,000.
        assert_eq!(
            output.authorize(
                &request(FileOperation::Write, 400, 500),
                now,
                session(1),
                used
            ),
            Ok(())
        );
        let full = QuotaUsage {
            total_bytes: 0,
            entries: 3,
        };
        assert_eq!(
            output.authorize(&request(FileOperation::Create, 0, 1), now, session(1), full),
            Err(GrantRefusal::EntryQuotaExceeded { max_entries: 3 })
        );
    }

    #[test]
    fn a_grant_reads_back_only_when_still_valid() {
        let granted = grant(live(), &[FileOperation::Read, FileOperation::Write]).unwrap();
        let text = serde_json::to_string(&granted).unwrap();
        assert_eq!(serde_json::from_str::<FileGrant>(&text).unwrap(), granted);
        let snapshot = grant(
            GrantMode::ReadOnlySnapshot {
                snapshot: digest("yougori/test/snapshot/v1", &[b"v1"]),
            },
            &[FileOperation::Read],
        )
        .unwrap();
        let tampered = serde_json::to_string(&snapshot)
            .unwrap()
            .replace("\"read\"", "\"write\"");
        assert!(serde_json::from_str::<FileGrant>(&tampered).is_err());
        let extra = serde_json::to_string(&snapshot).unwrap().replace(
            "{\"mode\":\"read_only_snapshot\"",
            "{\"mode\":\"read_only_snapshot\",\"x\":1",
        );
        assert!(serde_json::from_str::<FileGrant>(&extra).is_err());
        let quarantine = serde_json::json!({"mode": "quarantine_output", "extra": true});
        assert!(serde_json::from_value::<GrantMode>(quarantine).is_err());
    }
}
