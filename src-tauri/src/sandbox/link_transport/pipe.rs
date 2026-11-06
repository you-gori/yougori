//! The Windows named pipe of one VM's link and who may write to it (M06 carry-forward:
//! "restrict transport writers"; §3.2 line 2061: a supported point-to-point transport per
//! backend, lines 2073–2074: bind the host's channel to the VM object it launched; VM-R64
//! line 2929: OS permissions on the host endpoint; §7.3 lines 2376–2386: low-privilege
//! identity for the hypervisor on Windows; VM-P03 line 2778: no undeclared agent socket).
//!
//! The host creates the pipe before the hypervisor starts and is its server end. The
//! policy fixes everything the creating call passes:
//!
//! - one name per VM instance and boot generation, under the local namespace only;
//! - [`FILE_FLAG_FIRST_PIPE_INSTANCE`], so creation fails if any process holds the name
//!   already, and at most one instance, so no second client can be served;
//! - [`PIPE_REJECT_REMOTE_CLIENTS`] and a byte stream in blocking mode;
//! - a descriptor whose owner is the host and whose protected DACL has exactly two
//!   entries: the host with full access and the hypervisor's own per-instance SID with
//!   [`HYPERVISOR_PIPE_ACCESS`] (read and write the stream, read attributes, wait), and a
//!   low mandatory label with no write up, so a low-integrity hypervisor may write and
//!   nothing below low integrity may.
//!
//! [`NamedPipePolicy::check`] compares an observed pipe with the policy: the creation
//! flags the launcher recorded (the first-instance flag cannot be read back from a
//! handle), the pipe mode and instance limit read from the handle, and the descriptor read
//! back as SDDL, parsed strictly by [`sddl`](super::sddl). The descriptor's group is not
//! part of the policy and is not compared.
//!
//! The DACL admits the host's own account, so another process of that account can still
//! connect before the hypervisor does; the adapter must also check the connecting
//! client's process (as `sandbox_contract::relay_link` does through PX1). Creating the
//! pipe with this descriptor needs the Windows API and `unsafe`, and is not part of this
//! module; the constants here are checked against `windows-sys` on Windows.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::sddl::{Ace, Acl, AclFlags, SddlError, SecurityDescriptor, Sid};
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::SandboxBootGeneration;

/// The local pipe namespace; nothing on another computer.
pub const PIPE_NAMESPACE: &str = r"\\.\pipe\";
/// The start of every link pipe's own name.
pub const LINK_PIPE_PREFIX: &str = "yougori-link-";

/// `PIPE_ACCESS_DUPLEX`: the server end reads and writes.
pub const PIPE_ACCESS_DUPLEX: u32 = 0x0000_0003;
/// `FILE_FLAG_FIRST_PIPE_INSTANCE`: creation fails when the name exists.
pub const FILE_FLAG_FIRST_PIPE_INSTANCE: u32 = 0x0008_0000;
/// `FILE_FLAG_OVERLAPPED`: waits on the pipe can be bounded.
pub const FILE_FLAG_OVERLAPPED: u32 = 0x4000_0000;
/// `PIPE_NOWAIT`: deprecated non-blocking mode.
pub const PIPE_NOWAIT: u32 = 0x0000_0001;
/// `PIPE_READMODE_MESSAGE`.
pub const PIPE_READMODE_MESSAGE: u32 = 0x0000_0002;
/// `PIPE_TYPE_MESSAGE`.
pub const PIPE_TYPE_MESSAGE: u32 = 0x0000_0004;
/// `PIPE_REJECT_REMOTE_CLIENTS`: no client through the network redirector.
pub const PIPE_REJECT_REMOTE_CLIENTS: u32 = 0x0000_0008;
/// `FILE_ALL_ACCESS`, the host's right.
pub const FILE_ALL_ACCESS: u32 = 0x001f_01ff;
/// `FILE_READ_DATA | FILE_WRITE_DATA | FILE_READ_ATTRIBUTES | SYNCHRONIZE`: the
/// hypervisor's right. No new pipe instance (`FILE_CREATE_PIPE_INSTANCE`), no attribute
/// or extended-attribute write, no change of DACL or owner, no delete.
pub const HYPERVISOR_PIPE_ACCESS: u32 = 0x0010_0083;
/// `SYSTEM_MANDATORY_LABEL_NO_WRITE_UP`.
pub const SYSTEM_MANDATORY_LABEL_NO_WRITE_UP: u32 = 0x0000_0001;

/// The `dwOpenMode` of the link pipe.
pub const LINK_PIPE_OPEN_MODE: u32 =
    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
/// The `dwPipeMode` of the link pipe: byte type, byte read mode, blocking
/// (`PIPE_TYPE_BYTE`, `PIPE_READMODE_BYTE` and `PIPE_WAIT` are zero), remote clients
/// rejected.
pub const LINK_PIPE_MODE: u32 = PIPE_REJECT_REMOTE_CLIENTS;
/// The `nMaxInstances` of the link pipe.
pub const LINK_PIPE_MAX_INSTANCES: u32 = 1;

/// Open-mode bits the policy may set; any other is a finding.
const KNOWN_OPEN_MODE: u32 =
    PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE | FILE_FLAG_OVERLAPPED;
/// Pipe-mode bits with a meaning the check reports; any other is a finding.
const KNOWN_PIPE_MODE: u32 =
    PIPE_NOWAIT | PIPE_READMODE_MESSAGE | PIPE_TYPE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS;

/// What the host is on Windows.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostKind {
    /// The account the engine runs as: a local or domain account (`S-1-5-21-` and four
    /// sub-authorities) or an Entra ID account (`S-1-12-1-` and four).
    User,
    /// `LocalSystem` (`S-1-5-18`), for a supervisor that runs as a service.
    LocalSystem,
}

/// The host's identity: the pipe's owner, granted full access.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct HostIdentity {
    kind: HostKind,
    sid: Sid,
}

impl HostIdentity {
    /// Classifies `sid`; anything but a user account or `LocalSystem` (a group, an alias
    /// such as Administrators or Everyone, a service or logon SID) is refused.
    pub fn classify(sid: Sid) -> Result<Self, PipePolicyError> {
        let subs = sid.sub_authorities();
        let kind = match (sid.authority(), subs) {
            (5, [18]) => HostKind::LocalSystem,
            (5, [21, _, _, _, _]) | (12, [1, _, _, _, _]) => HostKind::User,
            _ => return Err(PipePolicyError::HostNotAnAccount { sid }),
        };
        Ok(Self { kind, sid })
    }

    pub fn kind(&self) -> HostKind {
        self.kind
    }

    pub fn sid(&self) -> &Sid {
        &self.sid
    }
}

/// What identity the hypervisor process of one VM runs under. Each names one instance,
/// never a group every VM or every process of the user shares.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HypervisorKind {
    /// An AppContainer's package SID (`S-1-15-2-` and seven sub-authorities): a QEMU
    /// launched in a container of its own.
    AppContainer,
    /// A Hyper-V VM's own account (`S-1-5-83-1-` and four sub-authorities): the worker
    /// process of one HCS VM.
    VirtualMachine,
    /// A logon session (`S-1-5-5-X-Y`): the session SID of a restricted token the
    /// launcher created for this hypervisor.
    LogonSession,
}

/// The hypervisor's identity: the one other SID the DACL grants.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct HypervisorIdentity {
    kind: HypervisorKind,
    sid: Sid,
}

impl HypervisorIdentity {
    /// Classifies `sid`; a SID shared by more than one instance (all application
    /// packages, all VMs `S-1-5-83-0`, Everyone, Users, the restricted-code SID) and any
    /// account SID are refused.
    pub fn classify(sid: Sid) -> Result<Self, PipePolicyError> {
        let kind = match (sid.authority(), sid.sub_authorities()) {
            (15, [2, _, _, _, _, _, _, _]) => HypervisorKind::AppContainer,
            (5, [83, 1, _, _, _, _]) => HypervisorKind::VirtualMachine,
            (5, [5, _, _]) => HypervisorKind::LogonSession,
            _ => return Err(PipePolicyError::HypervisorNotPerInstance { sid }),
        };
        Ok(Self { kind, sid })
    }

    pub fn kind(&self) -> HypervisorKind {
        self.kind
    }

    pub fn sid(&self) -> &Sid {
        &self.sid
    }
}

/// Why a pipe policy could not be made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "pipe_policy_error", rename_all = "snake_case")]
pub enum PipePolicyError {
    HostNotAnAccount { sid: Sid },
    HypervisorNotPerInstance { sid: Sid },
}

impl fmt::Display for PipePolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HostNotAnAccount { sid } => write!(
                f,
                "{sid} is not a user account or LocalSystem and cannot own the link pipe"
            ),
            Self::HypervisorNotPerInstance { sid } => write!(
                f,
                "{sid} does not name one hypervisor instance (an AppContainer, a VM account or \
                 a logon session)"
            ),
        }
    }
}

impl std::error::Error for PipePolicyError {}

/// The link pipe of one VM instance and boot generation: its name, creation flags and
/// descriptor. Computed, never read from a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NamedPipePolicy {
    name: String,
    host: HostIdentity,
    hypervisor: HypervisorIdentity,
}

impl NamedPipePolicy {
    /// The policy of the link pipe for `vm` at `boot`, owned by `host` and writable by
    /// `hypervisor`.
    pub fn new(
        vm: VmInstanceId,
        boot: SandboxBootGeneration,
        host: HostIdentity,
        hypervisor: HypervisorIdentity,
    ) -> Self {
        Self {
            name: format!(
                "{PIPE_NAMESPACE}{LINK_PIPE_PREFIX}{}-{}",
                vm.digest().to_hex(),
                boot.get()
            ),
            host,
            hypervisor,
        }
    }

    /// The full pipe name, `\\.\pipe\yougori-link-<vm>-<boot>`.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn host(&self) -> &HostIdentity {
        &self.host
    }

    pub fn hypervisor(&self) -> &HypervisorIdentity {
        &self.hypervisor
    }

    pub const fn open_mode(&self) -> u32 {
        LINK_PIPE_OPEN_MODE
    }

    pub const fn pipe_mode(&self) -> u32 {
        LINK_PIPE_MODE
    }

    pub const fn max_instances(&self) -> u32 {
        LINK_PIPE_MAX_INSTANCES
    }

    /// The descriptor: owner the host, a protected DACL granting the host
    /// [`FILE_ALL_ACCESS`] and the hypervisor [`HYPERVISOR_PIPE_ACCESS`], a low label
    /// with no write up.
    pub fn descriptor(&self) -> SecurityDescriptor {
        SecurityDescriptor {
            owner: Some(self.host.sid.clone()),
            group: None,
            dacl: Some(Acl {
                flags: AclFlags {
                    protected: true,
                    ..AclFlags::default()
                },
                null: false,
                aces: vec![
                    Ace::allow(FILE_ALL_ACCESS, self.host.sid.clone()),
                    Ace::allow(HYPERVISOR_PIPE_ACCESS, self.hypervisor.sid.clone()),
                ],
            }),
            sacl: Some(Acl {
                aces: vec![Ace::label(
                    SYSTEM_MANDATORY_LABEL_NO_WRITE_UP,
                    Sid::low_mandatory_level(),
                )],
                ..Acl::default()
            }),
        }
    }

    /// The descriptor as SDDL, for `ConvertStringSecurityDescriptorToSecurityDescriptorW`.
    pub fn sddl(&self) -> String {
        self.descriptor().to_sddl()
    }

    /// Compares an observed pipe with the policy; an empty list means it matches.
    pub fn check(&self, observed: &ObservedPipe) -> Vec<PipeFinding> {
        let mut findings = Vec::new();
        if observed.name != self.name {
            findings.push(PipeFinding::NameDiffers {
                expected: self.name.clone(),
                found: observed.name.clone(),
            });
        }
        let access = observed.open_mode & PIPE_ACCESS_DUPLEX;
        if access != PIPE_ACCESS_DUPLEX {
            findings.push(PipeFinding::NotDuplex { access });
        }
        if observed.open_mode & FILE_FLAG_FIRST_PIPE_INSTANCE == 0 {
            findings.push(PipeFinding::NotFirstInstance);
        }
        let extra = observed.open_mode & !KNOWN_OPEN_MODE;
        if extra != 0 {
            findings.push(PipeFinding::UnexpectedOpenModeFlags { flags: extra });
        }
        if observed.pipe_mode & PIPE_REJECT_REMOTE_CLIENTS == 0 {
            findings.push(PipeFinding::RemoteClientsAccepted);
        }
        let message = observed.pipe_mode & (PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE);
        if message != 0 {
            findings.push(PipeFinding::NotByteStream { flags: message });
        }
        if observed.pipe_mode & PIPE_NOWAIT != 0 {
            findings.push(PipeFinding::NonBlocking);
        }
        let unknown = observed.pipe_mode & !KNOWN_PIPE_MODE;
        if unknown != 0 {
            findings.push(PipeFinding::UnknownPipeModeFlags { flags: unknown });
        }
        if observed.max_instances != LINK_PIPE_MAX_INSTANCES {
            findings.push(PipeFinding::InstanceLimit {
                found: observed.max_instances,
            });
        }
        match SecurityDescriptor::parse(&observed.descriptor) {
            Ok(found) => self.check_descriptor(&found, &mut findings),
            Err(error) => findings.push(PipeFinding::DescriptorUnreadable(error)),
        }
        findings
    }

    fn check_descriptor(&self, found: &SecurityDescriptor, findings: &mut Vec<PipeFinding>) {
        let expected = self.descriptor();
        if found.owner != expected.owner {
            findings.push(PipeFinding::OwnerDiffers {
                expected: self.host.sid.clone(),
                found: found.owner.clone(),
            });
        }
        let (Some(want), Some(have)) = (&expected.dacl, &found.dacl) else {
            findings.push(PipeFinding::DaclMissing);
            return check_label(&expected, found, findings);
        };
        if have.null {
            findings.push(PipeFinding::DaclNull);
        } else {
            if have.flags != want.flags {
                findings.push(PipeFinding::DaclFlagsDiffer { found: have.flags });
            }
            compare_aces(&want.aces, &have.aces, findings);
        }
        check_label(&expected, found, findings);
    }
}

fn compare_aces(expected: &[Ace], found: &[Ace], findings: &mut Vec<PipeFinding>) {
    let before = findings.len();
    for ace in found.iter().filter(|ace| !expected.contains(ace)) {
        findings.push(PipeFinding::UnexpectedAce(ace.clone()));
    }
    for ace in expected.iter().filter(|ace| !found.contains(ace)) {
        findings.push(PipeFinding::MissingAce(ace.clone()));
    }
    if findings.len() == before && expected != found {
        findings.push(PipeFinding::AcesReorderedOrRepeated {
            found: found.to_vec(),
        });
    }
}

fn check_label(
    expected: &SecurityDescriptor,
    found: &SecurityDescriptor,
    findings: &mut Vec<PipeFinding>,
) {
    let want = expected.sacl.clone().unwrap_or_default();
    let have = found.sacl.clone().unwrap_or_default();
    if have != want {
        findings.push(PipeFinding::LabelDiffers {
            expected: want,
            found: have,
        });
    }
}

/// A pipe as the host observed it. Read from the launcher's record and the pipe handle;
/// `open_mode` is what the creating call passed, since it cannot be read back.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedPipe {
    pub name: String,
    pub open_mode: u32,
    /// `PIPE_REJECT_REMOTE_CLIENTS` read back as `FILE_PIPE_REJECT_REMOTE_CLIENTS` from
    /// the pipe's local information, with the type and read mode.
    pub pipe_mode: u32,
    pub max_instances: u32,
    /// The owner, DACL and label read from the handle, as SDDL.
    pub descriptor: String,
}

/// One way an observed pipe differs from its policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum PipeFinding {
    NameDiffers {
        expected: String,
        found: String,
    },
    /// The server end is not duplex.
    NotDuplex {
        access: u32,
    },
    /// Created without `FILE_FLAG_FIRST_PIPE_INSTANCE`: another process may have held the
    /// name first and served the hypervisor.
    NotFirstInstance,
    /// `WRITE_DAC`, `ACCESS_SYSTEM_SECURITY`, write-through or any other open flag.
    UnexpectedOpenModeFlags {
        flags: u32,
    },
    /// Clients through the network redirector are accepted.
    RemoteClientsAccepted,
    NotByteStream {
        flags: u32,
    },
    NonBlocking,
    UnknownPipeModeFlags {
        flags: u32,
    },
    /// More than one instance may exist, so a second client could be served.
    InstanceLimit {
        found: u32,
    },
    DescriptorUnreadable(SddlError),
    OwnerDiffers {
        expected: Sid,
        found: Option<Sid>,
    },
    DaclMissing,
    /// A null DACL: every access is granted to everyone.
    DaclNull,
    /// Not protected, or other flags than protected.
    DaclFlagsDiffer {
        found: AclFlags,
    },
    UnexpectedAce(Ace),
    MissingAce(Ace),
    /// The same entries in another order, or one repeated.
    AcesReorderedOrRepeated {
        found: Vec<Ace>,
    },
    /// The mandatory label is not exactly low with no write up.
    LabelDiffers {
        expected: Acl,
        found: Acl,
    },
}

impl fmt::Display for PipeFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameDiffers { expected, found } => {
                write!(f, "the pipe is named {found}, not {expected}")
            }
            Self::NotDuplex { access } => {
                write!(f, "the server end's access is {access:#x}, not duplex")
            }
            Self::NotFirstInstance => f.write_str(
                "the pipe was created without FILE_FLAG_FIRST_PIPE_INSTANCE, so another \
                 process may have held the name first",
            ),
            Self::UnexpectedOpenModeFlags { flags } => {
                write!(f, "the pipe was created with open flags {flags:#x}")
            }
            Self::RemoteClientsAccepted => {
                f.write_str("the pipe accepts clients through the network redirector")
            }
            Self::NotByteStream { flags } => {
                write!(
                    f,
                    "the pipe is in message mode ({flags:#x}), not a byte stream"
                )
            }
            Self::NonBlocking => f.write_str("the pipe is in PIPE_NOWAIT mode"),
            Self::UnknownPipeModeFlags { flags } => {
                write!(f, "the pipe mode has unknown flags {flags:#x}")
            }
            Self::InstanceLimit { found } => {
                write!(f, "the pipe allows {found} instances, not 1")
            }
            Self::DescriptorUnreadable(error) => {
                write!(f, "the pipe's descriptor cannot be read: {error}")
            }
            Self::OwnerDiffers { expected, found } => match found {
                Some(found) => write!(f, "the pipe is owned by {found}, not {expected}"),
                None => write!(
                    f,
                    "the pipe's descriptor names no owner; expected {expected}"
                ),
            },
            Self::DaclMissing => f.write_str("the pipe's descriptor has no DACL"),
            Self::DaclNull => f.write_str("the pipe has a null DACL, which grants everyone"),
            Self::DaclFlagsDiffer { found } => write!(
                f,
                "the DACL flags are protected={}, auto_inherited={}, auto_inherit_required={}; \
                 only protected is expected",
                found.protected, found.auto_inherited, found.auto_inherit_required
            ),
            Self::UnexpectedAce(ace) => write!(f, "the DACL has an unexpected entry {ace}"),
            Self::MissingAce(ace) => write!(f, "the DACL lacks the entry {ace}"),
            Self::AcesReorderedOrRepeated { found } => write!(
                f,
                "the DACL holds the expected entries reordered or repeated ({} entries)",
                found.len()
            ),
            Self::LabelDiffers { found, .. } => write!(
                f,
                "the mandatory label is {} entries, not one low label with no write up",
                found.aces.len()
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;
    use crate::sandbox::link_transport::sddl::SddlErrorKind;

    const USER: &str = "S-1-5-21-1004336348-1177238915-682003330-1001";
    const CONTAINER: &str =
        "S-1-15-2-2434737943-167758768-3180539153-984336765-1107280622-3591121930-2677285773";
    const VM_ACCOUNT: &str = "S-1-5-83-1-1580447216-1312413590-2918211995-1408931012";

    fn sid(text: &str) -> Sid {
        Sid::parse(text).unwrap()
    }

    fn vm() -> VmInstanceId {
        VmInstanceId::new(digest("yougori/link/transport/test/v1", &[b"vm"]))
    }

    fn policy() -> NamedPipePolicy {
        NamedPipePolicy::new(
            vm(),
            SandboxBootGeneration::new(3),
            HostIdentity::classify(sid(USER)).unwrap(),
            HypervisorIdentity::classify(sid(CONTAINER)).unwrap(),
        )
    }

    /// The pipe as Windows would report it for the policy: the group appears when the
    /// reader asks for it, and well-known SIDs come back as aliases.
    fn observed() -> ObservedPipe {
        ObservedPipe {
            name: policy().name().to_owned(),
            open_mode: LINK_PIPE_OPEN_MODE,
            pipe_mode: LINK_PIPE_MODE,
            max_instances: 1,
            descriptor: format!(
                "O:{USER}G:{USER}D:P(A;;FA;;;{USER})(A;;0x100083;;;{CONTAINER})S:(ML;;NW;;;LW)"
            ),
        }
    }

    fn with_descriptor(descriptor: &str) -> ObservedPipe {
        ObservedPipe {
            descriptor: descriptor.to_owned(),
            ..observed()
        }
    }

    #[test]
    fn the_policy_names_one_instance_and_renders_its_descriptor() {
        let policy = policy();
        assert_eq!(
            policy.name(),
            format!(r"\\.\pipe\yougori-link-{}-3", vm().digest().to_hex())
        );
        assert_eq!(
            policy.sddl(),
            format!("O:{USER}D:P(A;;FA;;;{USER})(A;;0x100083;;;{CONTAINER})S:(ML;;NW;;;LW)")
        );
        assert_eq!(
            SecurityDescriptor::parse(&policy.sddl()),
            Ok(policy.descriptor())
        );
        assert_eq!(policy.open_mode(), 0x4008_0003);
        assert_eq!(policy.pipe_mode(), 0x8);
        assert_eq!(policy.max_instances(), 1);
        assert_eq!(policy.host().kind(), HostKind::User);
        assert_eq!(policy.hypervisor().kind(), HypervisorKind::AppContainer);
        let other_boot = NamedPipePolicy::new(
            vm(),
            SandboxBootGeneration::new(4),
            policy.host().clone(),
            policy.hypervisor().clone(),
        );
        assert_ne!(other_boot.name(), policy.name());
    }

    #[test]
    fn a_pipe_made_by_the_policy_matches_it() {
        assert_eq!(policy().check(&observed()), vec![]);
        let spelled = with_descriptor(&format!(
            "O:{USER}D:P(A;;0x1f01ff;;;{USER})(A;;0x100083;;;{CONTAINER})S:(ML;;0x1;;;S-1-16-4096)"
        ));
        assert_eq!(policy().check(&spelled), vec![]);
        let without_overlapped = ObservedPipe {
            open_mode: PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
            ..observed()
        };
        assert_eq!(policy().check(&without_overlapped), vec![]);
    }

    #[test]
    fn creation_flags_and_mode_are_each_checked() {
        let cases = [
            (
                ObservedPipe {
                    name: r"\\.\pipe\yougori-link-other".to_owned(),
                    ..observed()
                },
                PipeFinding::NameDiffers {
                    expected: policy().name().to_owned(),
                    found: r"\\.\pipe\yougori-link-other".to_owned(),
                },
            ),
            (
                ObservedPipe {
                    open_mode: 0x4008_0001,
                    ..observed()
                },
                PipeFinding::NotDuplex { access: 1 },
            ),
            (
                ObservedPipe {
                    open_mode: PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
                    ..observed()
                },
                PipeFinding::NotFirstInstance,
            ),
            (
                ObservedPipe {
                    open_mode: LINK_PIPE_OPEN_MODE | 0x0004_0000,
                    ..observed()
                },
                PipeFinding::UnexpectedOpenModeFlags { flags: 0x0004_0000 },
            ),
            (
                ObservedPipe {
                    pipe_mode: 0,
                    ..observed()
                },
                PipeFinding::RemoteClientsAccepted,
            ),
            (
                ObservedPipe {
                    pipe_mode: LINK_PIPE_MODE | PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE,
                    ..observed()
                },
                PipeFinding::NotByteStream { flags: 0x6 },
            ),
            (
                ObservedPipe {
                    pipe_mode: LINK_PIPE_MODE | PIPE_NOWAIT,
                    ..observed()
                },
                PipeFinding::NonBlocking,
            ),
            (
                ObservedPipe {
                    pipe_mode: LINK_PIPE_MODE | 0x10,
                    ..observed()
                },
                PipeFinding::UnknownPipeModeFlags { flags: 0x10 },
            ),
            (
                ObservedPipe {
                    max_instances: 255,
                    ..observed()
                },
                PipeFinding::InstanceLimit { found: 255 },
            ),
        ];
        for (pipe, finding) in cases {
            assert_eq!(policy().check(&pipe), vec![finding], "{pipe:?}");
        }
    }

    #[test]
    fn every_wider_descriptor_is_a_finding() {
        let host = format!("(A;;FA;;;{USER})");
        let hypervisor = format!("(A;;0x100083;;;{CONTAINER})");
        let label = "S:(ML;;NW;;;LW)";
        let everyone = Ace::allow(0x0012_019f, sid("WD"));
        let wide_hypervisor = Ace::allow(0x0012_019f, sid(CONTAINER));
        let expected_hypervisor = Ace::allow(HYPERVISOR_PIPE_ACCESS, sid(CONTAINER));
        let cases: Vec<(String, Vec<PipeFinding>)> = vec![
            (
                format!("O:BAD:P{host}{hypervisor}{label}"),
                vec![PipeFinding::OwnerDiffers {
                    expected: sid(USER),
                    found: Some(sid("BA")),
                }],
            ),
            (
                format!("D:P{host}{hypervisor}{label}"),
                vec![PipeFinding::OwnerDiffers {
                    expected: sid(USER),
                    found: None,
                }],
            ),
            (format!("O:{USER}{label}"), vec![PipeFinding::DaclMissing]),
            (
                format!("O:{USER}D:NO_ACCESS_CONTROL{label}"),
                vec![PipeFinding::DaclNull],
            ),
            (
                format!("O:{USER}D:{host}{hypervisor}{label}"),
                vec![PipeFinding::DaclFlagsDiffer {
                    found: AclFlags::default(),
                }],
            ),
            (
                format!("O:{USER}D:PAI{host}{hypervisor}{label}"),
                vec![PipeFinding::DaclFlagsDiffer {
                    found: AclFlags {
                        protected: true,
                        auto_inherited: true,
                        auto_inherit_required: false,
                    },
                }],
            ),
            (
                format!("O:{USER}D:P{host}{hypervisor}(A;;0x12019f;;;WD){label}"),
                vec![PipeFinding::UnexpectedAce(everyone)],
            ),
            (
                format!("O:{USER}D:P{host}(A;;0x12019f;;;{CONTAINER}){label}"),
                vec![
                    PipeFinding::UnexpectedAce(wide_hypervisor),
                    PipeFinding::MissingAce(expected_hypervisor.clone()),
                ],
            ),
            (
                format!("O:{USER}D:P{host}{label}"),
                vec![PipeFinding::MissingAce(expected_hypervisor)],
            ),
            (
                format!("O:{USER}D:P{hypervisor}{host}{label}"),
                vec![PipeFinding::AcesReorderedOrRepeated {
                    found: vec![
                        Ace::allow(HYPERVISOR_PIPE_ACCESS, sid(CONTAINER)),
                        Ace::allow(FILE_ALL_ACCESS, sid(USER)),
                    ],
                }],
            ),
            (
                format!("O:{USER}D:P{host}{hypervisor}{hypervisor}{label}"),
                vec![PipeFinding::AcesReorderedOrRepeated {
                    found: vec![
                        Ace::allow(FILE_ALL_ACCESS, sid(USER)),
                        Ace::allow(HYPERVISOR_PIPE_ACCESS, sid(CONTAINER)),
                        Ace::allow(HYPERVISOR_PIPE_ACCESS, sid(CONTAINER)),
                    ],
                }],
            ),
        ];
        for (descriptor, findings) in cases {
            assert_eq!(
                policy().check(&with_descriptor(&descriptor)),
                findings,
                "{descriptor}"
            );
        }
        let denied = policy().check(&with_descriptor(&format!(
            "O:{USER}D:P(D;;FA;;;WD){host}{hypervisor}{label}"
        )));
        assert!(matches!(&denied[..], [PipeFinding::UnexpectedAce(ace)] if ace.sid == sid("WD")));
        let inherited = policy().check(&with_descriptor(&format!(
            "O:{USER}D:P(A;ID;FA;;;{USER}){hypervisor}{label}"
        )));
        assert_eq!(inherited.len(), 2, "{inherited:?}");
    }

    #[test]
    fn the_label_must_be_low_with_no_write_up() {
        let dacl = format!("O:{USER}D:P(A;;FA;;;{USER})(A;;0x100083;;;{CONTAINER})");
        let low = Acl {
            aces: vec![Ace::label(1, sid("LW"))],
            ..Acl::default()
        };
        for (label, found) in [
            ("", Acl::default()),
            ("S:", Acl::default()),
            (
                "S:(ML;;NW;;;ME)",
                Acl {
                    aces: vec![Ace::label(1, sid("ME"))],
                    ..Acl::default()
                },
            ),
            (
                "S:(ML;;NWNR;;;LW)",
                Acl {
                    aces: vec![Ace::label(3, sid("LW"))],
                    ..Acl::default()
                },
            ),
            (
                "S:P(ML;;NW;;;LW)",
                Acl {
                    flags: AclFlags {
                        protected: true,
                        ..AclFlags::default()
                    },
                    ..low.clone()
                },
            ),
        ] {
            assert_eq!(
                policy().check(&with_descriptor(&format!("{dacl}{label}"))),
                vec![PipeFinding::LabelDiffers {
                    expected: low.clone(),
                    found
                }],
                "{label}"
            );
        }
    }

    #[test]
    fn an_unreadable_descriptor_is_a_finding_not_a_pass() {
        let findings = policy().check(&with_descriptor("O:BAD:P(AU;SA;FA;;;WD)"));
        assert_eq!(
            findings,
            vec![PipeFinding::DescriptorUnreadable(SddlError {
                offset: 8,
                kind: SddlErrorKind::UnsupportedAceType
            })]
        );
        assert!(findings[0].to_string().contains("cannot be read"));
    }

    #[test]
    fn hosts_are_accounts_and_hypervisors_are_single_instances() {
        for (text, kind) in [
            (USER, HostKind::User),
            ("S-1-12-1-1234-5678-9012-3456", HostKind::User),
            ("SY", HostKind::LocalSystem),
        ] {
            assert_eq!(HostIdentity::classify(sid(text)).unwrap().kind(), kind);
        }
        for text in ["BA", "BU", "WD", "AU", "S-1-5-5-0-12345", "LS", CONTAINER] {
            assert_eq!(
                HostIdentity::classify(sid(text)),
                Err(PipePolicyError::HostNotAnAccount { sid: sid(text) }),
                "{text}"
            );
        }
        for (text, kind) in [
            (CONTAINER, HypervisorKind::AppContainer),
            (VM_ACCOUNT, HypervisorKind::VirtualMachine),
            ("S-1-5-5-0-12345", HypervisorKind::LogonSession),
        ] {
            let identity = HypervisorIdentity::classify(sid(text)).unwrap();
            assert_eq!(identity.kind(), kind);
            assert_eq!(identity.sid(), &sid(text));
        }
        for text in [
            "AC",
            "S-1-5-83-0",
            "WD",
            "BU",
            "RC",
            "AU",
            USER,
            "SY",
            "S-1-15-2-1-2-3-4-5-6",
        ] {
            let refusal = HypervisorIdentity::classify(sid(text)).unwrap_err();
            assert_eq!(
                refusal,
                PipePolicyError::HypervisorNotPerInstance { sid: sid(text) }
            );
            assert!(refusal.to_string().contains("does not name one hypervisor"));
        }
    }

    #[test]
    fn observed_pipes_read_strictly_and_findings_serialize() {
        let text = serde_json::to_string(&observed()).unwrap();
        let back: ObservedPipe = serde_json::from_str(&text).unwrap();
        assert_eq!(back, observed());
        let mut value = serde_json::to_value(observed()).unwrap();
        value["client_process_id"] = serde_json::json!(4);
        assert!(serde_json::from_value::<ObservedPipe>(value).is_err());
        assert_eq!(
            serde_json::to_value(PipeFinding::InstanceLimit { found: 2 }).unwrap(),
            serde_json::json!({"finding": "instance_limit", "found": 2})
        );
        assert_eq!(
            serde_json::to_value(policy().hypervisor()).unwrap(),
            serde_json::json!({"kind": "app_container", "sid": CONTAINER})
        );
    }

    #[cfg(windows)]
    #[test]
    fn the_constants_are_the_windows_values() {
        use windows_sys::Win32::Storage::FileSystem as fs;
        use windows_sys::Win32::System::Pipes as pipes;
        assert_eq!(PIPE_ACCESS_DUPLEX, fs::PIPE_ACCESS_DUPLEX);
        assert_eq!(
            FILE_FLAG_FIRST_PIPE_INSTANCE,
            fs::FILE_FLAG_FIRST_PIPE_INSTANCE
        );
        assert_eq!(FILE_FLAG_OVERLAPPED, fs::FILE_FLAG_OVERLAPPED);
        assert_eq!(PIPE_NOWAIT, pipes::PIPE_NOWAIT);
        assert_eq!(PIPE_READMODE_MESSAGE, pipes::PIPE_READMODE_MESSAGE);
        assert_eq!(PIPE_TYPE_MESSAGE, pipes::PIPE_TYPE_MESSAGE);
        assert_eq!(
            PIPE_REJECT_REMOTE_CLIENTS,
            pipes::PIPE_REJECT_REMOTE_CLIENTS
        );
        assert_eq!(
            pipes::PIPE_TYPE_BYTE | pipes::PIPE_READMODE_BYTE | pipes::PIPE_WAIT,
            0
        );
        assert_eq!(FILE_ALL_ACCESS, fs::FILE_ALL_ACCESS);
        assert_eq!(
            HYPERVISOR_PIPE_ACCESS,
            fs::FILE_READ_DATA | fs::FILE_WRITE_DATA | fs::FILE_READ_ATTRIBUTES | fs::SYNCHRONIZE
        );
        assert_eq!(HYPERVISOR_PIPE_ACCESS & fs::FILE_CREATE_PIPE_INSTANCE, 0);
        assert_eq!(
            HYPERVISOR_PIPE_ACCESS & (fs::WRITE_DAC | fs::WRITE_OWNER | fs::DELETE),
            0
        );
    }
}
