//! Guest reports: every fact that arrives over the channel is typed with CORE-01's guest
//! source class, bound to the host's identity of the VM, and can never become a
//! host-observed fact through this module (VM-P29 line 2804: "root forges init/agent
//! reports; host-authoritative VM/channel identity and policy cannot be replaced";
//! VM-CP-25 line 3175: "a forged init or agent report claiming 'all probes passed' does
//! not satisfy any host-only requirement").

use serde::Serialize;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::SourceClass;
use crate::foundation::ids::{MonotonicTime, SandboxBootGeneration};

use super::connection::Connection;
use super::messages::ReportBody;

/// A report the guest sent. The VM, boot generation and connection are the host's
/// binding of the link, never a value the guest supplied; the source class is fixed. The
/// type is `Serialize` only: a record of a guest report is never hand-written, and there
/// is no constructor that takes another source class.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GuestReport {
    source: SourceClass,
    vm: VmInstanceId,
    boot: SandboxBootGeneration,
    /// Not written for an unchallenged link, so such records read as before.
    #[serde(skip_serializing_if = "Connection::is_unchallenged")]
    connection: Connection,
    received_at: MonotonicTime,
    sequence: u64,
    body: ReportBody,
}

impl GuestReport {
    /// The only source class a guest report has (CORE-01 "source of observation").
    pub const SOURCE: SourceClass = SourceClass::GuestReport;

    pub(super) fn new(
        vm: VmInstanceId,
        boot: SandboxBootGeneration,
        connection: Connection,
        received_at: MonotonicTime,
        sequence: u64,
        body: ReportBody,
    ) -> Self {
        Self {
            source: Self::SOURCE,
            vm,
            boot,
            connection,
            received_at,
            sequence,
            body,
        }
    }

    pub const fn source(&self) -> SourceClass {
        self.source
    }

    /// The VM the host bound the link to.
    pub const fn vm(&self) -> VmInstanceId {
        self.vm
    }

    pub const fn boot(&self) -> SandboxBootGeneration {
        self.boot
    }

    /// The connection the report arrived on; its sequence counts from 1 on that
    /// connection.
    pub const fn connection(&self) -> Connection {
        self.connection
    }

    pub const fn received_at(&self) -> MonotonicTime {
        self.received_at
    }

    /// The guest-to-host sequence the report arrived with, on its connection.
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    pub const fn body(&self) -> &ReportBody {
        &self.body
    }

    /// Whether this report could satisfy a requirement whose minimum source is
    /// `minimum`, by CORE-01's trust order. A host-only requirement is never satisfied.
    pub fn satisfies(&self, minimum: SourceClass) -> bool {
        self.source.satisfies(minimum)
    }
}
