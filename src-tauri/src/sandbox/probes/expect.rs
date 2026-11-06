//! The expected observations of the §17 checks (plan lines 3151–3185) as typed data: each
//! [`Expectation`] names one observation a check makes, which part of the check it
//! belongs to, the host operating systems it applies to, whether it is an observation or
//! the positive control, and the typed predicate ([`Expect`]) an [`Observed`] value must
//! meet. No expectation is a command: a runner observes and reports typed values, and
//! this module only judges them.

use std::fmt;

use serde::{Serialize, Serializer};

use super::catalog::{CheckId, CorroboratingFact, Part};
use crate::foundation::evidence::OsKind;
use crate::foundation::ids::Digest;

/// The name of one expectation, such as `cp01.accelerator`. Only the table makes one, so
/// every name refers to a row; [`ExpectationId::named`] looks a name up.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ExpectationId(&'static str);

impl ExpectationId {
    /// A name written into this module's tables; the table test checks each is a row.
    pub(super) const fn of(name: &'static str) -> Self {
        Self(name)
    }

    /// The expectation named `name`, if the table has one.
    pub fn named(name: &str) -> Option<Self> {
        TABLE
            .iter()
            .find(|entry| entry.id.0 == name)
            .map(|entry| entry.id)
    }

    pub const fn as_str(self) -> &'static str {
        self.0
    }
}

impl fmt::Display for ExpectationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl fmt::Debug for ExpectationId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

impl Serialize for ExpectationId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.0)
    }
}

/// The host operating systems an expectation applies to (VM-CP-04, VM-CP-11 and VM-CP-33
/// list per-platform observations; VM-CP-31's device assignment checks are Linux's, §7.5
/// line 2398).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "scope", content = "os", rename_all = "snake_case")]
pub enum HostScope {
    AnyHost,
    Only(OsKind),
}

impl HostScope {
    pub fn applies(self, os: OsKind) -> bool {
        match self {
            Self::AnyHost => true,
            Self::Only(only) => only == os,
        }
    }
}

/// Whether an expectation is one of the check's observations or its positive control.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Observation,
    /// Must hold in the same run, or the check's result is inconclusive (§17 line 3147).
    PositiveControl,
}

/// A value a runner observed, typed by what kind of observation it is.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Observed {
    /// An operation was attempted, and refused or not.
    Attempt { refused: bool },
    /// Something is present or absent.
    Presence { present: bool },
    /// An event happened or did not, such as a detection, an expiry or a recorded figure.
    Event { happened: bool },
    /// A named value, such as an accelerator.
    Value { value: String },
    /// A count with the limit it is judged against (the limit comes from the profile).
    Bounded { value: u64, limit: u64 },
    /// An observed digest and the reference it must equal.
    Comparison { observed: Digest, reference: Digest },
    /// Identities that must be pairwise distinct.
    Identities { values: Vec<Digest> },
}

impl Observed {
    pub const fn kind(&self) -> ObservedKind {
        match self {
            Self::Attempt { .. } => ObservedKind::Attempt,
            Self::Presence { .. } => ObservedKind::Presence,
            Self::Event { .. } => ObservedKind::Event,
            Self::Value { .. } => ObservedKind::Value,
            Self::Bounded { .. } => ObservedKind::Bounded,
            Self::Comparison { .. } => ObservedKind::Comparison,
            Self::Identities { .. } => ObservedKind::Identities,
        }
    }
}

/// The kind of an [`Observed`] value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedKind {
    Attempt,
    Presence,
    Event,
    Value,
    Bounded,
    Comparison,
    Identities,
}

/// The typed predicate an observation must meet.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "expect", content = "values", rename_all = "snake_case")]
pub enum Expect {
    /// The attempt was refused.
    Refused,
    /// The attempt succeeded.
    Succeeds,
    Absent,
    Present,
    Happens,
    NeverHappens,
    /// The value is one of these.
    OneOf(&'static [&'static str]),
    /// The count is at or below its limit.
    WithinLimit,
    /// The observed digest equals its reference.
    Matches,
    /// At least two identities, all pairwise distinct.
    AllDistinct,
}

impl Expect {
    /// The kind of observation this predicate judges.
    pub const fn judges(self) -> ObservedKind {
        match self {
            Self::Refused | Self::Succeeds => ObservedKind::Attempt,
            Self::Absent | Self::Present => ObservedKind::Presence,
            Self::Happens | Self::NeverHappens => ObservedKind::Event,
            Self::OneOf(_) => ObservedKind::Value,
            Self::WithinLimit => ObservedKind::Bounded,
            Self::Matches => ObservedKind::Comparison,
            Self::AllDistinct => ObservedKind::Identities,
        }
    }

    /// Whether `observed` meets the predicate; an observation of another kind, or too few
    /// identities to compare, is an error, never a pass.
    pub fn holds(self, observed: &Observed) -> Result<bool, ObservationError> {
        match (self, observed) {
            (Self::Refused, Observed::Attempt { refused }) => Ok(*refused),
            (Self::Succeeds, Observed::Attempt { refused }) => Ok(!*refused),
            (Self::Absent, Observed::Presence { present }) => Ok(!*present),
            (Self::Present, Observed::Presence { present }) => Ok(*present),
            (Self::Happens, Observed::Event { happened }) => Ok(*happened),
            (Self::NeverHappens, Observed::Event { happened }) => Ok(!*happened),
            (Self::OneOf(allowed), Observed::Value { value }) => {
                Ok(allowed.iter().any(|candidate| *candidate == value))
            }
            (Self::WithinLimit, Observed::Bounded { value, limit }) => Ok(value <= limit),
            (
                Self::Matches,
                Observed::Comparison {
                    observed,
                    reference,
                },
            ) => Ok(observed == reference),
            (Self::AllDistinct, Observed::Identities { values }) => {
                if values.len() < 2 {
                    return Err(ObservationError::TooFewIdentities {
                        found: values.len(),
                    });
                }
                let distinct: std::collections::BTreeSet<&Digest> = values.iter().collect();
                Ok(distinct.len() == values.len())
            }
            (expect, observed) => Err(ObservationError::WrongKind {
                expected: expect.judges(),
                found: observed.kind(),
            }),
        }
    }
}

/// Why an observation could not be judged.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "error", rename_all = "snake_case")]
pub enum ObservationError {
    WrongKind {
        expected: ObservedKind,
        found: ObservedKind,
    },
    TooFewIdentities {
        found: usize,
    },
}

impl fmt::Display for ObservationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WrongKind { expected, found } => write!(
                f,
                "the runner reported a {found:?} observation where a {expected:?} one was expected"
            ),
            Self::TooFewIdentities { found } => {
                write!(f, "{found} identities cannot show that clones are distinct")
            }
        }
    }
}

impl std::error::Error for ObservationError {}

/// One expected observation of one check.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Expectation {
    pub id: ExpectationId,
    pub check: CheckId,
    pub part: Part,
    pub scope: HostScope,
    pub role: Role,
    pub expect: Expect,
    /// What the plan expects, in its words.
    pub says: &'static str,
}

/// The whole table, in check order.
pub fn expectations() -> &'static [Expectation] {
    &TABLE
}

/// The expectation `id` names.
pub fn expectation(id: ExpectationId) -> Option<&'static Expectation> {
    TABLE.iter().find(|entry| entry.id == id)
}

/// The accelerators VM-CP-01 accepts (line 3151: "names an accelerator in {kvm, whpx,
/// hvf, vz}").
pub const VM_CP_01_ACCELERATORS: &[&str] = &["kvm", "whpx", "hvf", "vz"];

const P: Part = Part::Primary;
const ANY: HostScope = HostScope::AnyHost;
const LINUX: HostScope = HostScope::Only(OsKind::Linux);
const WINDOWS: HostScope = HostScope::Only(OsKind::Windows);
const MACOS: HostScope = HostScope::Only(OsKind::MacOs);

const fn by(fact: CorroboratingFact) -> Part {
    Part::Corroboration { fact }
}

const fn obs(
    id: &'static str,
    check: u8,
    part: Part,
    scope: HostScope,
    expect: Expect,
    says: &'static str,
) -> Expectation {
    Expectation {
        id: ExpectationId(id),
        check: CheckId::of(check),
        part,
        scope,
        role: Role::Observation,
        expect,
        says,
    }
}

const fn ctl(
    id: &'static str,
    check: u8,
    part: Part,
    expect: Expect,
    says: &'static str,
) -> Expectation {
    Expectation {
        id: ExpectationId(id),
        check: CheckId::of(check),
        part,
        scope: ANY,
        role: Role::PositiveControl,
        expect,
        says,
    }
}

use CorroboratingFact::{
    BootedRootImage, CloneIdentities, KernelBuildRecord, NoGuestNetworkDevice,
    PreSnapshotApprovalRefused,
};
use Expect::{
    Absent, AllDistinct, Happens, Matches, NeverHappens, OneOf, Present, Refused, Succeeds,
    WithinLimit,
};

static TABLE: [Expectation; 174] = [
    // VM-CP-01 (line 3151).
    obs("cp01.accelerator", 1, P, ANY, OneOf(VM_CP_01_ACCELERATORS), "the backend's launch record names an accelerator in {kvm, whpx, hvf, vz}"),
    obs("cp01.forced-unavailable-refused", 1, P, ANY, Refused, "with the accelerator forced unavailable in a test build the launch is refused"),
    obs("cp01.no-tcg-hypervisor", 1, P, ANY, Absent, "the host process list shows no hypervisor running with a TCG argument"),
    ctl("cp01.normal-launch-records-accelerator", 1, P, Succeeds, "a normal launch on the same host succeeds and records the accelerator"),
    // VM-CP-02 (line 3152).
    obs("cp02.golden-configuration", 2, P, ANY, Matches, "the hypervisor configuration matches the approved profile's golden file"),
    obs("cp02.network-device", 2, P, ANY, Absent, "no network device"),
    obs("cp02.console", 2, P, ANY, Absent, "no console"),
    obs("cp02.balloon", 2, P, ANY, Absent, "no balloon"),
    obs("cp02.undeclared-pci-transport", 2, P, ANY, Absent, "no PCI transport unless the device profile declares it"),
    // VM-CP-03 (line 3153).
    obs("cp03.shared-filesystem-device", 3, P, ANY, Absent, "no 9p, virtiofs or HGFS device"),
    obs("cp03.management-tcp-listener", 3, P, ANY, Absent, "no QMP or HMP TCP listener"),
    obs("cp03.qmp-socket-private", 3, P, ANY, Present, "the QMP socket is in a private directory"),
    obs("cp03.old-agent-port-forward", 3, P, ANY, Absent, "no host port forward to the old agent port"),
    ctl("cp03.planted-share-device-detected", 3, P, Happens, "a test launch with a deliberately added share device fails the check"),
    // VM-CP-04 (line 3154).
    obs("cp04.linux.unprivileged-uid", 4, P, LINUX, Present, "the hypervisor process runs as the launcher's unprivileged uid"),
    obs("cp04.linux.no-new-privs", 4, P, LINUX, Present, "NoNewPrivs: 1"),
    obs("cp04.linux.seccomp-filter", 4, P, LINUX, Present, "Seccomp: 2"),
    obs("cp04.linux.network-namespace-only-lo", 4, P, LINUX, Present, "the hypervisor's network namespace lists only lo"),
    obs("cp04.linux.cgroup-limits", 4, P, LINUX, Present, "cgroup limits present"),
    obs("cp04.linux.descriptors", 4, P, LINUX, WithinLimit, "open descriptor count at or below the profile's number"),
    obs("cp04.windows.restricted-low-integrity-token", 4, P, WINDOWS, Present, "the token is restricted and low integrity"),
    obs("cp04.windows.job-limits", 4, P, WINDOWS, Present, "job limits present, queried from the job object"),
    obs("cp04.macos.helper-profile", 4, P, MACOS, Present, "the helper's profile is applied"),
    ctl("cp04.unjailed-launch-difference-reported", 4, P, Happens, "the same checks on an unjailed test launch report the difference"),
    // VM-CP-05 (line 3155).
    obs("cp05.io-uring-setup", 5, P, ANY, Refused, "io_uring_setup fails with ENOSYS or EPERM inside the inner container"),
    obs("cp05.af-vsock", 5, P, ANY, Refused, "socket(AF_VSOCK) fails with EPERM"),
    obs("cp05.capability-set", 5, P, ANY, Matches, "the capability set equals the profile"),
    obs("cp05.protected-path-write", 5, P, ANY, Refused, "a write to ~/.bashrc or .git/hooks/ fails with EROFS or EACCES"),
    obs("cp05.booted-root-image", 5, by(BootedRootImage), ANY, Matches, "the booted root image digest matches the signed manifest"),
    obs("cp05.kernel-build-record", 5, by(KernelBuildRecord), ANY, Matches, "the kernel build record (CONFIG_IO_URING absent) matches the signed manifest"),
    ctl("cp05.io-uring-image-fails-kernel-check", 5, by(KernelBuildRecord), Happens, "a test image with io_uring enabled fails the kernel-record check on the host"),
    // VM-CP-06 (line 3156).
    obs("cp06.forbidden-address-class", 6, P, ANY, Refused, "a connection from the guest to a controlled listener on a forbidden address class fails"),
    obs("cp06.allowed-endpoint", 6, P, ANY, Succeeds, "a connection to a controlled allowed endpoint succeeds"),
    ctl("cp06.forbidden-listener-reachable-unconfined", 6, P, Succeeds, "the forbidden listener is reachable from an unconfined host process during the same run"),
    // VM-CP-07 (line 3157).
    obs("cp07.private-answer", 7, P, ANY, Refused, "an answer of 10.0.0.5 for an allowed name is refused with address_blocked"),
    obs("cp07.cname-into-private-range", 7, P, ANY, Refused, "a CNAME chain into a private range is refused"),
    obs("cp07.ttl-change-revalidates", 7, P, ANY, Happens, "a TTL change mid-session triggers revalidation"),
    obs("cp07.canary-name-upstream-query", 7, P, ANY, Absent, "the canary name produces no upstream query"),
    ctl("cp07.public-answer-connects", 7, P, Succeeds, "a public answer for the same name connects"),
    // VM-CP-08 (line 3158).
    obs("cp08.ipv4-mapped-ipv6", 8, P, ANY, Refused, "::ffff:10.0.0.1 is refused"),
    obs("cp08.unspecified", 8, P, ANY, Refused, "0.0.0.0 is refused"),
    obs("cp08.short-decimal-octal-forms", 8, P, ANY, Refused, "127.1, decimal and octal forms are refused"),
    obs("cp08.metadata-address", 8, P, ANY, Refused, "169.254.169.254 is refused"),
    obs("cp08.ipv6-link-local", 8, P, ANY, Refused, "fe80:: is refused"),
    obs("cp08.ipv6-unique-local", 8, P, ANY, Refused, "ULA addresses are refused"),
    obs("cp08.multicast", 8, P, ANY, Refused, "multicast is refused"),
    obs("cp08.broadcast", 8, P, ANY, Refused, "the broadcast range is refused"),
    obs("cp08.host-inventory", 8, P, ANY, Refused, "every address in the host inventory is refused"),
    ctl("cp08.public-test-address-passes", 8, P, Succeeds, "the public test address passes the same normalizer"),
    // VM-CP-09 (line 3159).
    obs("cp09.direct-https-without-proxy", 9, P, ANY, Refused, "with proxy variables unset, a direct HTTPS request to a public address fails"),
    obs("cp09.raw-socket", 9, P, ANY, Refused, "a raw socket to a public address fails"),
    obs("cp09.alternate-dns", 9, P, ANY, Refused, "a query to an alternate DNS server fails"),
    obs("cp09.packet-from-vm", 9, by(NoGuestNetworkDevice), ANY, Absent, "the host observes no packet from the VM because no network device exists"),
    ctl("cp09.approved-route-succeeds", 9, P, Succeeds, "the same commands through the approved proxy or route succeed"),
    // VM-CP-10 (line 3160).
    obs("cp10.host-header-mismatch", 10, P, ANY, Refused, "a Host header that differs from the authorized name is refused"),
    obs("cp10.connect-non-443", 10, P, ANY, Refused, "CONNECT to a non-443 port is refused"),
    obs("cp10.ambiguous-framing", 10, P, ANY, Refused, "duplicate Content-Length or conflicting Transfer-Encoding is refused"),
    obs("cp10.redirect-to-private", 10, P, ANY, Refused, "a redirect to a private address is refused"),
    obs("cp10.undeclared-upgrade", 10, P, ANY, Refused, "an upgrade the route does not declare is refused"),
    ctl("cp10.well-formed-request-succeeds", 10, P, Succeeds, "the well-formed request on the same route succeeds"),
    // VM-CP-11 (line 3161).
    obs("cp11.broker-identity-blocked", 11, P, ANY, Refused, "with the broker's own filter disabled, the broker identity cannot reach the forbidden listener because the kernel perimeter blocks it"),
    obs("cp11.windows.explicit-block-precedes-allows", 11, P, WINDOWS, Present, "the explicit block for the broker executable takes precedence over allows"),
    obs("cp11.macos.pf-counter-increases", 11, P, MACOS, Happens, "pf counters for the group-scoped rule increase"),
    ctl("cp11.broker-reaches-allowed-endpoint", 11, P, Succeeds, "the broker identity reaches the controlled allowed endpoint under the same rules"),
    // VM-CP-12 (line 3162).
    obs("cp12.launch-specification", 12, P, ANY, Absent, "the launch specification contains no fixture value"),
    obs("cp12.relay-inputs-and-logs", 12, P, ANY, Absent, "the relay's inputs and logs contain no fixture value"),
    obs("cp12.audit", 12, P, ANY, Absent, "the audit contains no fixture value"),
    obs("cp12.echoed-response", 12, P, ANY, Absent, "the fake provider's echoed response contains no fixture value"),
    obs("cp12.executor-request", 12, P, ANY, Present, "the executor's outbound request contains the fixture value"),
    obs("cp12.coverage-stated", 12, P, ANY, Happens, "the check states that it covers only the scanned locations"),
    // VM-CP-13 (line 3163).
    obs("cp13.expired-capability", 13, P, ANY, Refused, "an expired capability is refused"),
    obs("cp13.revoked-capability", 13, P, ANY, Refused, "a revoked capability is refused"),
    obs("cp13.foreign-generation-capability", 13, P, ANY, Refused, "a foreign-generation capability is refused"),
    obs("cp13.wrong-executor-capability", 13, P, ANY, Refused, "a wrong-executor capability is refused"),
    obs("cp13.provider-call", 13, P, ANY, Absent, "the fake provider records no call"),
    ctl("cp13.valid-capability-succeeds", 13, P, Succeeds, "a valid capability for the same operation succeeds"),
    // VM-CP-14 (line 3164).
    obs("cp14.epoch-advance-time", 14, P, ANY, Happens, "the durable epoch advance time is measured"),
    obs("cp14.first-denial-time", 14, P, ANY, Happens, "the first denied new authorization time is measured"),
    obs("cp14.channel-closure-time", 14, P, ANY, Happens, "the channel closure time is measured"),
    obs("cp14.vm-stop-time", 14, P, ANY, Happens, "the VM stop time is measured"),
    obs("cp14.cleanup-time", 14, P, ANY, Happens, "the cleanup completion time is measured"),
    obs("cp14.percentiles", 14, P, ANY, Happens, "the drill records p50, p95 and p99"),
    // VM-CP-15 (line 3165).
    obs("cp15.links", 15, P, ANY, Refused, "symlinks, hard links, junctions and reparse points cannot escape the granted root"),
    obs("cp15.streams-and-device-paths", 15, P, ANY, Refused, "alternate data streams, UNC and device paths cannot escape the granted root"),
    obs("cp15.name-aliases", 15, P, ANY, Refused, "case aliases, Unicode normalization and long paths cannot escape the granted root"),
    obs("cp15.rename-race", 15, P, ANY, Refused, "a rename race during an open cannot escape the granted root"),
    ctl("cp15.in-root-relative-path-resolves", 15, P, Succeeds, "an in-root relative path resolves"),
    // VM-CP-16 (line 3166).
    obs("cp16.content-changed", 16, P, ANY, Refused, "mutating the artifact content after approval makes promotion fail"),
    obs("cp16.destination-changed", 16, P, ANY, Refused, "mutating the destination makes promotion fail"),
    obs("cp16.destination-base-changed", 16, P, ANY, Refused, "mutating the destination's base state makes promotion fail"),
    obs("cp16.originals-unchanged", 16, P, ANY, Matches, "the user's original files hash identically before and after"),
    ctl("cp16.unmodified-promotion-applies", 16, P, Succeeds, "an unmodified promotion applies"),
    // VM-CP-17 (line 3167).
    obs("cp17.next-generation-signed-base", 17, P, ANY, Matches, "the next generation boots the signed base whose digest the host verifies at launch"),
    obs("cp17.persisted-writable-inventory", 17, P, ANY, Happens, "the persisted volume inventory lists the writable paths that survived"),
    // VM-CP-18 (line 3168).
    obs("cp18.idle-expiry", 18, P, ANY, Happens, "idle-lease expiry happens despite a clock jump, a busy stream, a stalled engine and a disconnected UI"),
    obs("cp18.absolute-expiry", 18, P, ANY, Happens, "absolute-lease expiry happens despite them"),
    obs("cp18.service-lease-expiry", 18, P, ANY, Happens, "service-lease expiry happens despite them; the supervisor acts on its own timers"),
    // VM-CP-19 (line 3169).
    obs("cp19.engine-death-class-policy", 19, P, ANY, Happens, "engine death follows the per-class policy of VM-D7"),
    obs("cp19.supervisor-death-cleanup", 19, P, ANY, Happens, "supervisor death leads to the OS cleanup declared for the platform"),
    obs("cp19.reused-pid-signalled", 19, P, ANY, NeverHappens, "a stale PID reused by another process is never signalled"),
    // VM-CP-20 (line 3170).
    obs("cp20.cpu", 20, P, ANY, WithinLimit, "a fork bomb stays within the host CPU reservation"),
    obs("cp20.memory", 20, P, ANY, WithinLimit, "a memory hog stays within the host memory reservation"),
    obs("cp20.processes", 20, P, ANY, WithinLimit, "a fork bomb stays within the process reservation"),
    obs("cp20.disk", 20, P, ANY, WithinLimit, "a disk fill stays within the disk reservation"),
    obs("cp20.protocol-flood", 20, P, ANY, WithinLimit, "a protocol flood stays within its buffers"),
    obs("cp20.revocation-during-flood", 20, P, ANY, WithinLimit, "a revocation issued during the flood completes within the target"),
    // VM-CP-21 (line 3171).
    obs("cp21.canary-values", 21, P, ANY, AllDistinct, "two clones from one golden snapshot have distinct canary values"),
    obs("cp21.application-identifiers", 21, P, ANY, AllDistinct, "distinct application-level identifiers in a test application"),
    obs("cp21.generation-ids", 21, by(CloneIdentities), ANY, AllDistinct, "distinct generation ids"),
    obs("cp21.boot-ids", 21, by(CloneIdentities), ANY, AllDistinct, "distinct boot ids"),
    obs("cp21.pre-snapshot-approval", 21, by(PreSnapshotApprovalRefused), ANY, Refused, "an approval issued before the snapshot is refused in both clones"),
    // VM-CP-22 (line 3172).
    obs("cp22.concurrent-writers", 22, P, ANY, Happens, "concurrent writers are detected by the audit verification"),
    obs("cp22.disk-full", 22, P, ANY, Happens, "disk-full is detected"),
    obs("cp22.truncated-file", 22, P, ANY, Happens, "a truncated file is detected"),
    obs("cp22.rewritten-record", 22, P, ANY, Happens, "a rewritten record is detected"),
    obs("cp22.restart", 22, P, ANY, Happens, "a restart is detected"),
    obs("cp22.shutdown-blocked", 22, P, ANY, NeverHappens, "shutdown is not blocked by audit failure"),
    // VM-CP-23 (line 3173).
    obs("cp23.root-image-byte-change", 23, P, ANY, Refused, "a one-byte change in the root image is refused at the launch boundary"),
    obs("cp23.unsigned-manifest", 23, P, ANY, Refused, "an unsigned manifest is refused"),
    obs("cp23.expired-metadata", 23, P, ANY, Refused, "expired metadata is refused"),
    obs("cp23.rolled-back-version", 23, P, ANY, Refused, "a rolled-back version is refused"),
    obs("cp23.mixed-version-set", 23, P, ANY, Refused, "a mixed-version component set is refused"),
    ctl("cp23.signed-set-launches", 23, P, Succeeds, "the signed set launches"),
    // VM-CP-24 (line 3174).
    obs("cp24.tool-task-completes", 24, P, ANY, Succeeds, "a real supported tool completes a staged-workspace task against a fake provider"),
    obs("cp24.approvals-match-effects", 24, P, ANY, Matches, "approvals shown match the effects performed"),
    obs("cp24.repeated-approval", 24, P, ANY, NeverHappens, "no repeated approvals for a valid narrow grant"),
    // VM-CP-25 (line 3175).
    obs("cp25.mutation-corpus-bounds", 25, P, ANY, WithinLimit, "the link parser survives the mutation corpus within its bounds"),
    obs("cp25.forged-report-satisfies", 25, P, ANY, Refused, "a forged init or agent report claiming all probes passed satisfies no host-only requirement"),
    // VM-CP-26 (line 3176).
    obs("cp26.mutated-bound-field", 26, P, ANY, Refused, "mutating each bound field of an effect description makes the executor refuse"),
    obs("cp26.lost-response-outcome-unknown", 26, P, ANY, Happens, "a simulated provider commit with a lost response yields outcome_unknown"),
    obs("cp26.blind-retry", 26, P, ANY, NeverHappens, "no blind retry"),
    obs("cp26.visible-reconciliation", 26, P, ANY, Happens, "a visible reconciliation"),
    ctl("cp26.unmodified-effect-dispatches-once", 26, P, Succeeds, "the unmodified effect dispatches once"),
    // VM-CP-27 (line 3177).
    obs("cp27.release-bytes-counted", 27, P, ANY, Happens, "bytes in URLs, headers, resolved names and published-service responses count toward the release budget"),
    obs("cp27.header-only-exfiltration", 27, P, ANY, Refused, "a header-only exfiltration attempt exhausts the budget and is refused"),
    // VM-CP-28 (line 3178).
    obs("cp28.hostile-git-configuration-executes", 28, P, ANY, NeverHappens, "hostile .git/hooks, .git/config and credential-helper settings never execute on the host push path"),
    obs("cp28.dangerous-control-sequences", 28, P, ANY, Absent, "an OSC 52 clipboard sequence and other dangerous control sequences are stripped by the terminal renderer"),
    obs("cp28.preview-isolated-origin", 28, P, ANY, Present, "an HTML preview is served from an isolated origin"),
    // VM-CP-29 (line 3179).
    obs("cp29.ungranted-connection", 29, P, ANY, Refused, "two sandboxes without an explicit mutual grant cannot connect"),
    obs("cp29.shared-caches-and-volumes", 29, P, ANY, Absent, "caches and volumes are not shared"),
    obs("cp29.granted-port", 29, P, ANY, Succeeds, "with a grant, the granted port passes"),
    obs("cp29.other-ports", 29, P, ANY, Refused, "with a grant, only the granted port passes"),
    obs("cp29.expired-grant", 29, P, ANY, Refused, "a connection whose grant expired is refused"),
    obs("cp29.revoked-grant", 29, P, ANY, Refused, "a connection whose grant was withdrawn is refused"),
    obs("cp29.transitive-connection", 29, P, ANY, Refused, "with grants from A to B and from B to C, A cannot reach C: transitive access is not inferred"),
    ctl("cp29.second-grant-passes", 29, P, Succeeds, "the grant from B to C passes in the same run"),
    // VM-CP-30 (line 3180).
    obs("cp30.archive-bomb", 30, P, ANY, Refused, "an archive bomb is refused by the importer"),
    obs("cp30.unsafe-path", 30, P, ANY, Refused, "an unsafe path is refused"),
    obs("cp30.corrupt-layer", 30, P, ANY, Refused, "a corrupt layer is refused"),
    obs("cp30.forged-provenance", 30, P, ANY, Refused, "forged provenance is refused"),
    obs("cp30.interrupted-migration-resumes", 30, P, ANY, Happens, "an interrupted migration resumes"),
    obs("cp30.user-data-hashes", 30, P, ANY, Matches, "user data hashes match before and after"),
    // VM-CP-31 (line 3181), on Linux hosts: §7.5 (line 2398) states these checks for Linux
    // device assignment, and other GPU VM support is a later validated backend (line 2411).
    obs("cp31.incomplete-iommu-group", 31, P, LINUX, Refused, "an incomplete IOMMU group is refused"),
    obs("cp31.display-owning-gpu", 31, P, LINUX, Refused, "a display-owning GPU is refused"),
    obs("cp31.reset-capability-checked", 31, P, LINUX, Present, "reset capability is checked before assignment"),
    obs("cp31.acs-state-checked", 31, P, LINUX, Present, "ACS state is checked before assignment"),
    ctl("cp31.qualifying-device-assigns", 31, P, Succeeds, "a qualifying device assigns and nvidia-smi runs in the guest"),
    // VM-CP-32 (line 3182).
    obs("cp32.partitioned-lease-renewal", 32, P, ANY, Refused, "a lease expires under a simulated partition and cannot be renewed by the remote side"),
    obs("cp32.stale-nonce", 32, P, ANY, Refused, "an attestation fixture with a stale nonce is refused"),
    obs("cp32.wrong-measurement", 32, P, ANY, Refused, "a wrong measurement is refused"),
    obs("cp32.debug-flag", 32, P, ANY, Refused, "a debug flag is refused"),
    obs("cp32.unsupported-security-version", 32, P, ANY, Refused, "an unsupported security version is refused"),
    ctl("cp32.valid-attestation-accepted", 32, P, Succeeds, "a valid fixture report is accepted and recorded"),
    // VM-CP-33 (line 3183).
    obs("cp33.linux.kvm-unavailable", 33, P, LINUX, Refused, "with KVM simulated unavailable, the launch is refused"),
    obs("cp33.windows.whpx-unavailable", 33, P, WINDOWS, Refused, "with WHPX simulated unavailable, the launch is refused"),
    obs("cp33.macos.framework-unavailable", 33, P, MACOS, Refused, "with the framework simulated unavailable, the launch is refused"),
    obs("cp33.gpu-path-unavailable", 33, P, ANY, Refused, "with the GPU path simulated unavailable, the launch is refused"),
    obs("cp33.fallback-start", 33, P, ANY, Absent, "the process list shows no native, emulated or container start"),
    // VM-CP-34 (line 3184).
    obs("cp34.single-guard-disabled", 34, P, ANY, Happens, "disabling one guard at a time matches the VM-N3 model's predicted containment or produces a counterexample trace"),
    obs("cp34.late-lookup-unconstrained-fetch", 34, P, ANY, Refused, "a VM-N1 or VM-N4 task with private data cannot turn a late object lookup into an unconstrained fetch"),
    // VM-CP-35 (line 3185).
    obs("cp35.broader-rights", 35, P, ANY, Refused, "a template requesting broader rights is governed by host policy"),
    obs("cp35.missing-required-capability", 35, P, ANY, Refused, "a template omitting a required capability is governed by host policy"),
    obs("cp35.unknown-schema-version", 35, P, ANY, Refused, "an unknown schema version is governed by host policy"),
    obs("cp35.skipped-hardware-shown-not-tested", 35, P, ANY, Happens, "a skipped hardware test appears as not tested, never as a pass"),
];
