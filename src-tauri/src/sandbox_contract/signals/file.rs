//! The file service's refusals as signals (M12 [`FileService`]; VM part §5.1
//! "Capability-rooted access"; VM-W14; VM-P15 and VM-CP-15: "the file broker's case corpus
//! ... cannot escape the granted root").
//!
//! The guest reaches files only through the service, which creates regular files and
//! directories and nothing else, so the guest cannot plant a link, device or socket. What
//! one met while resolving a name means depends on who writes the root, the grant's
//! [`GrantMode`]:
//!
//! - in a live workspace the user writes too, and links and sockets are legitimate there
//!   (package-manager hard links, a development server's socket): the refusal is ordinary;
//! - beneath a read-only snapshot or quarantine output only the host and the service
//!   write, so one there is a host-side anomaly
//!   ([`HostAnomaly::LinkInHostRoot`](super::HostAnomaly),
//!   [`HostAnomaly::DeviceInHostRoot`](super::HostAnomaly)): V14's uncertain result, never
//!   a guest violation.
//!
//! A case alias is a second spelling of a stored name, refused; nothing was planted, so it
//! is ordinary. Every other refusal is ordinary too (a missing or existing entry, a quota
//! or size limit, an operation the grant does not permit, an expired grant, a race the
//! service refused, an I/O failure), except one: the grant presented from another trust
//! scope than the one it binds. The transport names the requesting sandbox's scope from its
//! channel, so that request came from that sandbox's guest holding another sandbox's grant,
//! reaching for a root its own grants do not bind: [`ViolationKind::FileRootEscape`], which
//! the [`HostObserver::Supervisor`] sees as it checks bindings. The grant
//! itself is compromised, so the violation names it, by the CORE-04 identity the host
//! issued it under, and a sandbox that holds it loses it too.

use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId, GrantId, TrustScope};
use crate::sandbox_contract::files::{
    FileService, GrantMode, GrantRefusal, GuestName, RequestContext, ResolveRefusal, RootHandle,
    ServiceRefusal,
};
use crate::sandbox_contract::response::{HostObserver, ViolationKind};

use super::observed::{Classification, Finding, HostAnomaly, Observed, Ordinary, ScopeMismatch};

/// The observer every file service signal and notice names.
pub const FILE_SERVICE_OBSERVER: HostObserver = HostObserver::Supervisor;
/// The kind a file service violation is filed under.
pub const FILE_VIOLATION_KIND: ViolationKind = ViolationKind::FileRootEscape;
/// The digest domain of a file service signal's subject.
pub const FILE_SUBJECT_DOMAIN: &str = "yougori/sandbox/signals/file-subject/v1";

/// What made a file service refusal a guest violation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FileViolation {
    /// The grant presented from another trust scope than the one it binds.
    ForeignScope,
}

/// The file request a refusal answered, as the host knows it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FileServiceContext {
    /// The requesting sandbox and the host clock reading the request was checked at.
    pub observed: Observed,
    /// The root the service's grant binds.
    pub root: RootHandle,
    /// The grant's mode: who writes the root.
    pub mode: GrantMode,
    /// The CORE-04 identity the host issued the service's file grant under.
    pub grant: GrantId,
}

impl FileServiceContext {
    /// The context of a request `sandbox`, of host-assigned trust scope `sandbox_scope`,
    /// made to `service` under `request`, whose grant the host issued as `grant`.
    pub fn of_request(
        sandbox: ExecutionId,
        sandbox_scope: TrustScope,
        request: &RequestContext,
        service: &FileService,
        grant: GrantId,
    ) -> Result<Self, ScopeMismatch> {
        Ok(Self {
            observed: Observed::of_request(sandbox, sandbox_scope, request)?,
            root: service.grant().root(),
            mode: service.grant().mode(),
            grant,
        })
    }
}

/// The subject of a file service signal or notice: the entry beneath `root`, or the root
/// itself. Only its digest is kept; the guest's name never reaches an audit field.
pub fn file_subject(root: RootHandle, entry: Option<&GuestName>) -> Digest {
    let builder = DigestBuilder::new(FILE_SUBJECT_DOMAIN).digest(&root.digest());
    match entry {
        Some(name) => builder.str("entry").str(name.as_str()),
        None => builder.str("root"),
    }
    .finish()
}

/// A link or device met beneath a root of `mode`: ordinary in a live workspace, a host
/// anomaly where only the host and the service write.
fn unexpected_entry(mode: GrantMode, anomaly: HostAnomaly) -> Finding<FileViolation> {
    match mode {
        GrantMode::LiveWorkspace { .. } => Finding::Ordinary(Ordinary::WorkspaceEntry),
        GrantMode::ReadOnlySnapshot { .. } | GrantMode::QuarantineOutput => {
            Finding::Anomaly(anomaly)
        }
    }
}

/// Classifies one refusal beneath a root of `mode`, with the entry it concerns.
fn classify(
    refusal: &ServiceRefusal,
    mode: GrantMode,
) -> (Finding<FileViolation>, Option<&GuestName>) {
    match refusal {
        ServiceRefusal::Resolve { refusal } => match refusal {
            ResolveRefusal::LinkRefused { at, link } => (
                unexpected_entry(mode, HostAnomaly::LinkInHostRoot { link: *link }),
                Some(at),
            ),
            ResolveRefusal::DeviceRefused { at } => (
                unexpected_entry(mode, HostAnomaly::DeviceInHostRoot),
                Some(at),
            ),
            ResolveRefusal::CaseAlias { .. } => (Finding::Ordinary(Ordinary::CaseSpelling), None),
            ResolveRefusal::NotFound { .. } | ResolveRefusal::NotADirectory { .. } => {
                (Finding::Ordinary(Ordinary::NotFound), None)
            }
            ResolveRefusal::Io { .. } => (Finding::Ordinary(Ordinary::HostFault), None),
        },
        ServiceRefusal::Grant { refusal } => (
            match refusal {
                GrantRefusal::WrongScope => Finding::Violation(FileViolation::ForeignScope),
                GrantRefusal::OtherClock | GrantRefusal::Expired { .. } => {
                    Finding::Ordinary(Ordinary::NotCurrent)
                }
                GrantRefusal::OperationNotGranted { .. } => {
                    Finding::Ordinary(Ordinary::NotPermitted)
                }
                GrantRefusal::FileTooLarge { .. }
                | GrantRefusal::TotalQuotaExceeded { .. }
                | GrantRefusal::EntryQuotaExceeded { .. } => {
                    Finding::Ordinary(Ordinary::LimitReached)
                }
                // The service always names its own root; another one is a host call.
                GrantRefusal::WrongRoot => Finding::Ordinary(Ordinary::HostConfiguration),
            },
            None,
        ),
        ServiceRefusal::RootMismatch => (Finding::Ordinary(Ordinary::HostConfiguration), None),
        ServiceRefusal::NotAFile { .. }
        | ServiceRefusal::AlreadyExists { .. }
        | ServiceRefusal::DirectoryNotEmpty { .. } => {
            (Finding::Ordinary(Ordinary::EntryState), None)
        }
        ServiceRefusal::ReadTooLarge { .. } | ServiceRefusal::TooManyUploads { .. } => {
            (Finding::Ordinary(Ordinary::LimitReached), None)
        }
        // An upload is only ever within its own grant: one that ended or names another file
        // is the guest's own bookkeeping, and a grant without uploads permits none.
        ServiceRefusal::UnknownUpload { .. } | ServiceRefusal::UploadNameMismatch { .. } => {
            (Finding::Ordinary(Ordinary::EntryState), None)
        }
        ServiceRefusal::UploadsUnavailable => (Finding::Ordinary(Ordinary::NotPermitted), None),
        ServiceRefusal::Changed { .. } => (Finding::Ordinary(Ordinary::ChangedDuringRequest), None),
        ServiceRefusal::UsageUnknown | ServiceRefusal::Io { .. } => {
            (Finding::Ordinary(Ordinary::HostFault), None)
        }
    }
}

/// The signal of one file service refusal (pure): a guest violation the supervisor
/// observed, about the requesting sandbox and against the compromised file grant; a host
/// anomaly about the entry; or why the refusal drafts nothing.
pub fn file_refusal_signal(
    refusal: &ServiceRefusal,
    context: &FileServiceContext,
) -> Classification<FileViolation> {
    let (finding, entry) = classify(refusal, context.mode);
    let subject = file_subject(context.root, entry);
    match finding {
        Finding::Violation(cause) => Classification::Violation {
            cause,
            draft: context.observed.violation(
                FILE_VIOLATION_KIND,
                FILE_SERVICE_OBSERVER,
                subject,
                Some(context.grant),
            ),
        },
        Finding::Anomaly(anomaly) => Classification::HostAnomaly {
            notice: context
                .observed
                .anomaly(anomaly, FILE_SERVICE_OBSERVER, subject),
        },
        Finding::Ordinary(reason) => Classification::Ordinary { reason },
    }
}
