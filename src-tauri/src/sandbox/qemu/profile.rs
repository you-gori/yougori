//! The typed QEMU profile and the launch plan built from a backend launch request
//! (VM-W19 row, line 2618; VM-W16 row, line 2615: no fallback may weaken required
//! properties, unsupported features are explicit; VM-W22 row, line 2621; §3.4 line 2101;
//! §7.2 line 2368: only required block, link, entropy and platform devices).
//!
//! A profile has one hardware accelerator and no TCG; `-nodefaults` and
//! `-no-user-config`; a read-only root drive; declared data volumes only; one entropy
//! device; the link channel of its platform; the link secret through fw_cfg; QMP only on
//! a socket in the host-created private directory; an explicitly requested outbound NAT
//! adapter whose every frame passes the host's network filter, or no network device; no
//! share, USB, display,
//! console or balloon device and no PCI transport (the device profile cannot declare
//! any of them today); and on Linux QEMU's seccomp sandbox.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

use super::argv::{canonical, concrete, flatten, Arg, Bindings, Item, Pair, Part, Role};
use super::linux::LinuxHostRestrictions;
use super::platform::{accelerator_name, LinkKind, PlatformProfile, PlatformRefusal, QemuPlatform};
use super::values::{
    GuestCid, GuestResources, HostPath, InstanceName, KernelArguments, PathStyle, PrivateDirectory,
};
use super::windows::WindowsHostRestrictions;
use crate::foundation::evidence::{HypervisorKind, OsKind, Satisfied};
use crate::foundation::ids::{Clock, Digest, ExecutionId, TenantId};
use crate::foundation::ledger::{
    HostResource, Ledger, ReservationId, ReservationState, ResourceKey,
};
use crate::sandbox::backend::{
    precheck, vm_handle, BackendFeatures, BackendIdentity, BackendKind, ConfinementControl,
    GuestEgressEndpoint, HostEvidence, LaunchRefusal, LaunchRequest, NetworkTarget,
};

/// The virtio-serial port name the guest agent opens for the link.
pub const LINK_PORT_NAME: &str = "org.yougori.link";
/// The fw_cfg entry that carries the link bootstrap secret (§3.2 line 2075: per-instance
/// bootstrap material through a backend-supported channel, not the arguments).
pub const LINK_SECRET_FW_CFG_NAME: &str = "opt/yougori/link-secret";

/// The fw_cfg entry that carries the guest's egress endpoint list (names, hosts and ports
/// the guest may address over the link; no secret), always present, empty when nothing is
/// declared, so the vector keeps one shape.
pub const EGRESS_ENDPOINTS_FW_CFG_NAME: &str = "opt/yougori/egress-endpoints";
pub const WORKLOAD_FW_CFG_NAME: &str = "opt/yougori/workload";
/// Most declared data volumes one profile attaches.
pub const MAX_VOLUMES: usize = 8;
pub(super) const INTERNET_BACKEND: &str = "user,id=internet,ipv6=off";
pub(super) const INTERNET_DEVICE: &str = "virtio-net-device,netdev=internet";
pub(super) const INTERNET_BOOT_MODE: &str = "name=opt/yougori/internet,string=1";

/// The canonical arguments a network card adds to a profile ([`network_args`]), as the
/// golden comparison extends an offline golden file with them.
pub(super) fn internet_arguments() -> Vec<String> {
    flatten(&canonical(&network_args(["", "", "", ""])))
}

/// The network card and the host's filter of its frames: QEMU's user network, the device and
/// the guest's boot flag, then the filter's four sockets in the private directory and the two
/// redirectors that send every frame through them: queue `rx` takes the guest's frames on
/// their way to the user network (out on socket 0, back on 1), queue `tx` the user network's
/// on their way to the guest (out on 2, back on 3). A redirector with an output keeps every
/// frame it takes, so a frame the host has not judged reaches neither side, and none passes
/// while the host's end of a socket is closed.
fn network_args(sockets: [&str; 4]) -> Vec<Arg> {
    let mut args = vec![
        Arg::plain("-netdev", Part::text(INTERNET_BACKEND)),
        Arg::plain("-device", Part::text(INTERNET_DEVICE)),
        Arg::plain("-fw_cfg", Part::text(INTERNET_BOOT_MODE)),
    ];
    for (index, socket) in (0u8..).zip(sockets) {
        args.push(Arg::items(
            "-chardev",
            vec![
                Item::implied("socket"),
                Item::pair("id", format!("net{index}")),
                Item::bound("path", Role::NetworkSocket { index }, socket),
                Item::pair("server", "on"),
                Item::pair("wait", "off"),
            ],
        ));
    }
    for (queue, out, back) in [("rx", 0, 1), ("tx", 2, 3)] {
        args.push(Arg::items(
            "-object",
            vec![
                Item::implied("filter-redirector"),
                Item::pair("id", format!("net-{queue}")),
                Item::pair("netdev", "internet"),
                Item::pair("queue", queue),
                Item::pair("outdev", format!("net{out}")),
                Item::pair("indev", format!("net{back}")),
            ],
        ));
    }
    args
}

/// The features the QEMU profile offers beyond launch and stop: none. Snapshots, a
/// display, GPU assignment, confidential VMs and a dedicated host are refused by name
/// through the backend's precheck (VM-W16 acceptance, line 2615).
pub fn qemu_features() -> BackendFeatures {
    BackendFeatures::none()
}

/// How the guest reaches the host's link endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum LinkChannel {
    /// A virtio-serial port on a socket in the private directory.
    VirtioSerial,
    /// vhost-vsock with the context id the host allocated.
    Vsock { cid: GuestCid },
}

/// Which host path a refusal is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "path", rename_all = "snake_case")]
pub enum PathRole {
    FirmwareDirectory,
    Kernel,
    Initrd,
    RootImage,
    Volume { index: usize },
    ControlDirectory,
}

impl fmt::Display for PathRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FirmwareDirectory => f.write_str("firmware directory"),
            Self::Kernel => f.write_str("kernel"),
            Self::Initrd => f.write_str("initrd"),
            Self::RootImage => f.write_str("root image"),
            Self::Volume { index } => write!(f, "data volume {index}"),
            Self::ControlDirectory => f.write_str("private control directory"),
        }
    }
}

/// What a backend reservation holds, as the profile needs it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReservedVm {
    pub execution: ExecutionId,
    pub tenant: TenantId,
    pub state: ReservationState,
    /// Host RAM the reservation holds now.
    pub ram_bytes: u64,
    /// CPU slots held by this launch; production uses one slot per guest vCPU.
    pub cpu_slots: u64,
}

/// A view of CORE-03 reservations: the launch request names only a reservation id, so
/// the profile reads the reserved host RAM here to keep the guest inside it (S3 item 2,
/// line 224: the host enforces its VM allocations). Implemented for the ledger itself.
pub trait ReservationView {
    fn reserved_vm(&self, reservation: ReservationId) -> Option<ReservedVm>;
    fn reserved_gpu_bytes(&self, _reservation: ReservationId) -> u64 { 0 }
}

impl<T: ReservationView + ?Sized> ReservationView for &T {
    fn reserved_gpu_bytes(&self, reservation: ReservationId) -> u64 { (**self).reserved_gpu_bytes(reservation) }
    fn reserved_vm(&self, reservation: ReservationId) -> Option<ReservedVm> {
        (**self).reserved_vm(reservation)
    }
}

impl<C: Clock> ReservationView for Ledger<C> {
    fn reserved_gpu_bytes(&self, reservation: ReservationId) -> u64 {
        self.reservation(reservation).map_or(0, |record| record.current().iter()
            .filter_map(|(key, bytes)| matches!(key, ResourceKey::Vram(_)).then_some(bytes))
            .fold(0, u64::saturating_add))
    }
    fn reserved_vm(&self, reservation: ReservationId) -> Option<ReservedVm> {
        let record = self.reservation(reservation)?;
        Some(ReservedVm {
            execution: record.provenance().execution.clone(),
            tenant: record.provenance().tenant.clone(),
            state: record.state(),
            ram_bytes: record.current().get(ResourceKey::Host(HostResource::Ram)),
            cpu_slots: record
                .current()
                .get(ResourceKey::Host(HostResource::CpuInitializationSlots)),
        })
    }
}

/// Why no profile was built. Every need the profile cannot meet is named; nothing is
/// dropped or substituted. Serialize only, like the backend refusal it may carry.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ProfileRefusal {
    WorkloadImage {
        detail: String,
    },
    /// The targets the VM's network card is held to are not the request's, or are named for
    /// a launch without a network card.
    NetworkTargets {
        detail: String,
    },
    /// The backend identity is not a QEMU build.
    NotQemuBackend {
        kind: BackendKind,
    },
    Platform {
        refusal: PlatformRefusal,
    },
    /// The backend build uses another hypervisor than this host's QEMU profile.
    HypervisorMismatch {
        platform: HypervisorKind,
        backend: HypervisorKind,
    },
    /// The backend's precheck refused: the request is pinned to another build, needs a
    /// feature the profile does not offer, or the CORE-01 evidence that the hardware
    /// hypervisor is available is missing, stale, unsupported or not host-probed.
    Launch {
        refusal: LaunchRefusal,
    },
    /// The request requires confinement controls this platform's profile does not apply
    /// (§3.4 line 2101: such a platform is unsupported for that profile).
    ConfinementNotProvided {
        missing: BTreeSet<ConfinementControl>,
    },
    /// A declared data volume has no host path.
    VolumeNotProvided {
        volume: Digest,
    },
    /// A host path was given for a volume the request does not declare.
    UndeclaredVolume {
        volume: Digest,
    },
    TooManyVolumes {
        count: usize,
        max: usize,
    },
    /// A host path is spelled for another OS.
    PathStyle {
        role: PathRole,
        expected: PathStyle,
        found: PathStyle,
    },
    /// A vsock platform needs the host-allocated context id.
    GuestCidRequired,
    /// A context id was given where the link is not vsock.
    GuestCidNotUsed,
    ReservationNotFound {
        reservation: ReservationId,
    },
    ReservationOfOtherExecution {
        reservation: ReservationId,
        execution: ExecutionId,
        tenant: TenantId,
    },
    /// The reservation is no longer open for a workload.
    ReservationNotUsable {
        reservation: ReservationId,
        state: ReservationState,
    },
    /// The guest memory exceeds the host RAM the reservation holds.
    MemoryExceedsReservation {
        memory_bytes: u64,
        reserved_bytes: u64,
    },
}

impl fmt::Display for ProfileRefusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WorkloadImage { detail } => write!(f, "image declaration: {detail}"),
            Self::NetworkTargets { detail } => write!(f, "network targets: {detail}"),
            Self::NotQemuBackend { kind } => write!(f, "{kind} is not a QEMU backend"),
            Self::Platform { refusal } => write!(f, "{refusal}"),
            Self::HypervisorMismatch { platform, backend } => write!(
                f,
                "this host's QEMU profile uses {platform}, but the backend build uses {backend}"
            ),
            Self::Launch { refusal } => write!(f, "{refusal}"),
            Self::ConfinementNotProvided { missing } => {
                let names: Vec<&str> = missing.iter().map(|control| control.tag()).collect();
                write!(
                    f,
                    "this platform's QEMU profile does not apply the required confinement: {}",
                    names.join(", ")
                )
            }
            Self::VolumeNotProvided { volume } => {
                write!(f, "declared data volume {volume} has no host path")
            }
            Self::UndeclaredVolume { volume } => {
                write!(f, "data volume {volume} is not declared by the request")
            }
            Self::TooManyVolumes { count, max } => {
                write!(f, "{count} data volumes is more than {max}")
            }
            Self::PathStyle {
                role,
                expected,
                found,
            } => write!(f, "the {role} is a {found} path on a {expected} host"),
            Self::GuestCidRequired => {
                f.write_str("the vsock link needs a host-allocated guest context id")
            }
            Self::GuestCidNotUsed => {
                f.write_str("a guest context id was given, but this platform's link is not vsock")
            }
            Self::ReservationNotFound { reservation } => {
                write!(f, "{reservation} is not an open reservation")
            }
            Self::ReservationOfOtherExecution {
                reservation,
                execution,
                tenant,
            } => write!(
                f,
                "{reservation} belongs to execution {execution} of tenant {tenant}, not this launch"
            ),
            Self::ReservationNotUsable { reservation, state } => {
                write!(f, "{reservation} is {state:?}, not open for a workload")
            }
            Self::MemoryExceedsReservation {
                memory_bytes,
                reserved_bytes,
            } => write!(
                f,
                "the guest's {memory_bytes} bytes of memory exceed the {reserved_bytes} bytes of \
                 host RAM reserved"
            ),
        }
    }
}

impl std::error::Error for ProfileRefusal {}

/// The values a profile is assembled from, by a build or by reading an observed vector.
pub(super) struct ProfileParts {
    pub(super) internet: bool,
    pub(super) platform: QemuPlatform,
    pub(super) name: InstanceName,
    pub(super) resources: GuestResources,
    pub(super) firmware_directory: HostPath,
    pub(super) kernel: HostPath,
    pub(super) initrd: Option<HostPath>,
    pub(super) kernel_arguments: KernelArguments,
    pub(super) root_image: HostPath,
    pub(super) volumes: Vec<HostPath>,
    pub(super) control: PrivateDirectory,
    pub(super) cid: Option<GuestCid>,
}

/// One VM's QEMU configuration: exactly what its argument vector says, nothing else.
/// Serialize only: a profile is built or read back from a vector, never hand-written.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QemuProfile {
    internet: bool,
    fixed: PlatformProfile,
    name: InstanceName,
    resources: GuestResources,
    firmware_directory: HostPath,
    kernel: HostPath,
    initrd: Option<HostPath>,
    kernel_arguments: KernelArguments,
    root_image: HostPath,
    volumes: Vec<HostPath>,
    control: PrivateDirectory,
    link: LinkChannel,
}

impl QemuProfile {
    pub(super) fn assemble(parts: ProfileParts) -> Result<Self, ProfileRefusal> {
        let fixed = parts
            .platform
            .profile()
            .map_err(|refusal| ProfileRefusal::Platform { refusal })?;
        let style = fixed.path_style;
        let mut paths = vec![
            (PathRole::FirmwareDirectory, &parts.firmware_directory),
            (PathRole::Kernel, &parts.kernel),
            (PathRole::RootImage, &parts.root_image),
            (PathRole::ControlDirectory, parts.control.path()),
        ];
        if let Some(initrd) = &parts.initrd {
            paths.push((PathRole::Initrd, initrd));
        }
        paths.extend(
            parts
                .volumes
                .iter()
                .enumerate()
                .map(|(index, path)| (PathRole::Volume { index }, path)),
        );
        if let Some((role, path)) = paths.iter().find(|(_, path)| path.style() != style) {
            return Err(ProfileRefusal::PathStyle {
                role: *role,
                expected: style,
                found: path.style(),
            });
        }
        if parts.volumes.len() > MAX_VOLUMES {
            return Err(ProfileRefusal::TooManyVolumes {
                count: parts.volumes.len(),
                max: MAX_VOLUMES,
            });
        }
        let link = match (fixed.link, parts.cid) {
            (LinkKind::Vsock, Some(cid)) => LinkChannel::Vsock { cid },
            (LinkKind::Vsock, None) => return Err(ProfileRefusal::GuestCidRequired),
            (LinkKind::VirtioSerial, None) => LinkChannel::VirtioSerial,
            (LinkKind::VirtioSerial, Some(_)) => return Err(ProfileRefusal::GuestCidNotUsed),
        };
        Ok(Self {
            internet: parts.internet,
            fixed,
            name: parts.name,
            resources: parts.resources,
            firmware_directory: parts.firmware_directory,
            kernel: parts.kernel,
            initrd: parts.initrd,
            kernel_arguments: parts.kernel_arguments,
            root_image: parts.root_image,
            volumes: parts.volumes,
            control: parts.control,
            link,
        })
    }

    pub fn internet(&self) -> bool { self.internet }

    pub fn platform(&self) -> QemuPlatform {
        self.fixed.platform
    }

    pub fn fixed(&self) -> &PlatformProfile {
        &self.fixed
    }

    /// The one hardware accelerator, never TCG (VM-CP-01, line 3151).
    pub fn hypervisor(&self) -> HypervisorKind {
        self.fixed.hypervisor
    }

    pub fn name(&self) -> &InstanceName {
        &self.name
    }

    pub fn resources(&self) -> GuestResources {
        self.resources
    }

    pub fn root_image(&self) -> &HostPath {
        &self.root_image
    }

    /// The writable data volumes, in the order of their catalog identities.
    pub fn volumes(&self) -> &[HostPath] {
        &self.volumes
    }

    pub fn control(&self) -> &PrivateDirectory {
        &self.control
    }

    pub fn link(&self) -> LinkChannel {
        self.link
    }

    pub fn kernel_arguments(&self) -> &KernelArguments {
        &self.kernel_arguments
    }

    /// The exact argument vector, without the executable: deterministic, for a process
    /// start without a shell.
    pub fn argv(&self) -> Vec<String> {
        flatten(&concrete(&self.args()))
    }

    /// The argument vector with each per-launch value replaced by its role: the form a
    /// golden file records (VM-CP-02, line 3152).
    pub fn canonical_argv(&self) -> Vec<String> {
        flatten(&canonical(&self.args()))
    }

    pub(super) fn pairs(&self) -> Vec<Pair> {
        concrete(&self.args())
    }

    pub(super) fn bindings(&self) -> Bindings {
        Bindings::of(&self.args())
    }

    pub(super) fn args(&self) -> Vec<Arg> {
        let qmp_socket = self.control.qmp_socket();
        let link_socket = self.control.link_socket();
        let link_secret = self.control.link_secret();
        let egress_endpoints = self.control.egress_endpoints();
        let workload = self.control.workload();
        let vcpus = self.resources.vcpu_count().to_string();
        let mut machine = vec![Item::implied(self.fixed.machine.tag())];
        machine.extend(
            self.fixed
                .machine_options()
                .into_iter()
                .map(|(key, value)| Item::pair(key, value)),
        );
        let mut accelerator = vec![Item::implied(accelerator_name(self.fixed.hypervisor))];
        accelerator.extend(
            self.fixed
                .accelerator_options()
                .into_iter()
                .map(|(key, value)| Item::pair(key, value)),
        );
        let mut args = vec![
            Arg::plain(
                "-name",
                Part::Bound(Role::Instance, self.name.as_str().to_owned()),
            ),
            Arg::items("-machine", machine),
            Arg::items("-accel", accelerator),
            Arg::plain("-cpu", Part::text(self.fixed.cpu_model())),
            Arg::items(
                "-smp",
                vec![
                    Item::bound("cpus", Role::VcpuCount, vcpus.clone()),
                    Item::bound("maxcpus", Role::VcpuCount, vcpus.clone()),
                    Item::pair("sockets", "1"),
                    Item::bound("cores", Role::VcpuCount, vcpus),
                    Item::pair("threads", "1"),
                ],
            ),
            Arg::plain(
                "-m",
                Part::Bound(Role::Memory, format!("{}M", self.resources.memory_mib())),
            ),
            Arg::flag("-nodefaults"),
            Arg::flag("-no-user-config"),
            Arg::items("-display", vec![Item::implied("none")]),
            Arg::plain(
                "-L",
                Part::Bound(
                    Role::FirmwareDirectory,
                    self.firmware_directory.as_str().to_owned(),
                ),
            ),
            Arg::plain(
                "-kernel",
                Part::Bound(Role::Kernel, self.kernel.as_str().to_owned()),
            ),
        ];
        if let Some(initrd) = &self.initrd {
            args.push(Arg::plain(
                "-initrd",
                Part::Bound(Role::Initrd, initrd.as_str().to_owned()),
            ));
        }
        args.push(Arg::plain(
            "-append",
            Part::Bound(Role::KernelArguments, self.kernel_arguments.command_line()),
        ));
        args.extend(drive("root", Role::RootImage, &self.root_image, true));
        for (index, volume) in self.volumes.iter().enumerate() {
            let role = Role::Volume {
                index: u16::try_from(index).unwrap_or(u16::MAX),
            };
            args.extend(drive(&format!("vol{index}"), role, volume, false));
        }
        args.push(Arg::items(
            "-device",
            vec![Item::implied("virtio-rng-device"), Item::pair("id", "rng")],
        ));
        match self.link {
            LinkChannel::VirtioSerial => {
                args.push(Arg::items(
                    "-chardev",
                    vec![
                        Item::implied("socket"),
                        Item::pair("id", "link"),
                        Item::bound("path", Role::LinkSocket, link_socket.as_str()),
                        Item::pair("server", "on"),
                        Item::pair("wait", "off"),
                    ],
                ));
                args.push(Arg::items(
                    "-device",
                    vec![
                        Item::implied("virtio-serial-device"),
                        Item::pair("id", "link-bus"),
                        // virtio-serial reserves port 0 for a console, and QEMU refuses
                        // a non-console port on a bus of one ("Out-of-range port id
                        // specified, max. allowed: 0"), so the bus has two: port 0 stays
                        // empty (no console device exists) and the link takes port 1.
                        Item::pair("max_ports", "2"),
                    ],
                ));
                args.push(Arg::items(
                    "-device",
                    vec![
                        Item::implied("virtserialport"),
                        Item::pair("id", "link-port"),
                        Item::pair("bus", "link-bus.0"),
                        Item::pair("chardev", "link"),
                        Item::pair("name", LINK_PORT_NAME),
                    ],
                ));
            }
            LinkChannel::Vsock { cid } => args.push(Arg::items(
                "-device",
                vec![
                    Item::implied("vhost-vsock-device"),
                    Item::pair("id", "link"),
                    Item::bound("guest-cid", Role::GuestCid, cid.get().to_string()),
                ],
            )),
        }
        args.push(Arg::items(
            "-fw_cfg",
            vec![
                Item::pair("name", LINK_SECRET_FW_CFG_NAME),
                Item::bound("file", Role::LinkSecret, link_secret.as_str()),
            ],
        ));
        args.push(Arg::items(
            "-fw_cfg",
            vec![
                Item::pair("name", EGRESS_ENDPOINTS_FW_CFG_NAME),
                Item::bound("file", Role::EgressEndpoints, egress_endpoints.as_str()),
            ],
        ));
        args.push(Arg::items(
            "-fw_cfg",
            vec![
                Item::pair("name", WORKLOAD_FW_CFG_NAME),
                Item::bound("file", Role::Workload, workload.as_str()),
            ],
        ));
        args.push(Arg::items(
            "-chardev",
            vec![
                Item::implied("socket"),
                Item::pair("id", "qmp"),
                Item::bound("path", Role::QmpSocket, qmp_socket.as_str()),
                Item::pair("server", "on"),
                Item::pair("wait", "off"),
            ],
        ));
        args.push(Arg::items(
            "-mon",
            vec![Item::pair("chardev", "qmp"), Item::pair("mode", "control")],
        ));
        // A guest reboot ends the process and a guest panic exits with failure, so the
        // supervisor observes both; nothing restarts inside the same process.
        args.push(Arg::items(
            "-action",
            vec![
                Item::pair("reboot", "shutdown"),
                Item::pair("panic", "exit-failure"),
            ],
        ));
        if let Some(settings) = self.fixed.seccomp_sandbox() {
            let mut items = vec![Item::implied("on")];
            items.extend(settings.iter().map(|&(key, value)| Item::pair(key, value)));
            args.push(Arg::items("-sandbox", items));
        }
        if self.internet {
            let [rx, rx_back, tx, tx_back] = self.control.network_sockets();
            args.extend(network_args([
                rx.as_str(),
                rx_back.as_str(),
                tx.as_str(),
                tx_back.as_str(),
            ]));
        }
        args
    }
}

/// A raw image as a file node, a format node and a virtio-mmio block device. The root
/// is read-only in both nodes, so the guest cannot write it whatever it mounts.
fn drive(node: &str, role: Role, path: &HostPath, read_only: bool) -> [Arg; 3] {
    let read_only = if read_only { "on" } else { "off" };
    [
        Arg::items(
            "-blockdev",
            vec![
                Item::pair("driver", "file"),
                Item::pair("node-name", format!("{node}-file")),
                Item::bound("filename", role, path.as_str()),
                Item::pair("read-only", read_only),
            ],
        ),
        Arg::items(
            "-blockdev",
            vec![
                Item::pair("driver", "raw"),
                Item::pair("node-name", node.to_owned()),
                Item::pair("file", format!("{node}-file")),
                Item::pair("read-only", read_only),
            ],
        ),
        Arg::items(
            "-device",
            vec![
                Item::implied("virtio-blk-device"),
                Item::pair("id", format!("{node}-disk")),
                Item::pair("drive", node.to_owned()),
            ],
        ),
    ]
}

/// The host-created handles and validated values of one launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLaunchInputs {
    pub platform: QemuPlatform,
    pub resources: GuestResources,
    /// The pinned QEMU data directory (firmware and option ROMs), read-only.
    pub firmware_directory: HostPath,
    pub kernel: HostPath,
    pub initrd: Option<HostPath>,
    /// From the pinned guest image's manifest.
    pub kernel_arguments: KernelArguments,
    /// The pinned guest root image, attached read-only.
    pub root_image: HostPath,
    /// A host path for each data volume the request declares, by catalog identity.
    pub volumes: BTreeMap<Digest, HostPath>,
    pub control: PrivateDirectory,
    /// The host-allocated vsock context id, on platforms whose link is vsock.
    pub vsock_cid: Option<GuestCid>,
    /// The endpoints the guest may address over the link (the launch's declaration).
    pub egress_endpoints: Vec<GuestEgressEndpoint>,
    pub workload_image: Option<crate::sandbox_contract::oci::WorkloadImage>,
    /// The only destinations the network card reaches (the launch's targets); `None` with a
    /// card is the public internet.
    pub targets: Option<Vec<NetworkTarget>>,
}

/// A launch ready to start: the profile, the CORE-01 hypervisor evidence the backend's
/// admission needs, the volumes by identity, the reserved host RAM and, on Windows, the
/// restrictions the launcher must apply. Nothing has been started.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct QemuLaunchPlan {
    profile: QemuProfile,
    evidence: Satisfied,
    volumes: BTreeMap<Digest, HostPath>,
    reserved_ram_bytes: u64,
    windows: Option<WindowsHostRestrictions>,
    linux: Option<LinuxHostRestrictions>,
    /// The endpoints the guest is told of at boot, written to the private directory's
    /// `egress-endpoints` file by the host that starts the plan (not part of the vector,
    /// which names only the file).
    egress_endpoints: Vec<GuestEgressEndpoint>,
    workload_image: Option<crate::sandbox_contract::oci::WorkloadImage>,
    /// What the host's network filter lets the card reach: these targets alone, or with
    /// `None` the public internet (never this computer or its networks). Not part of the
    /// vector: the filter the host starts beside QEMU applies it.
    targets: Option<Vec<NetworkTarget>>,
}

impl QemuLaunchPlan {
    pub fn profile(&self) -> &QemuProfile {
        &self.profile
    }

    /// The targets the network card is held to; `None` is the public internet for a profile
    /// with a card and nothing for one without.
    pub fn targets(&self) -> Option<&[NetworkTarget]> {
        self.targets.as_deref()
    }

    /// The endpoints the guest is told of at boot.
    pub fn egress_endpoints(&self) -> &[GuestEgressEndpoint] {
        &self.egress_endpoints
    }

    pub fn workload_file(&self) -> Result<Vec<u8>, String> {
        let bytes = crate::sandbox_contract::oci::workload_file(self.workload_image.as_ref())?;
        // This profile has no RTC. Give every guest the host's UTC clock through
        // protected boot data so TLS can verify certificate dates: through the outgoing
        // NAT, and through an offline VM's relayed tunnels (a harness's chosen sites).
        let seconds = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH)
            .map_err(|e| format!("the host clock is invalid: {e}"))?.as_secs();
        let mut declaration: serde_json::Value = serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
        declaration["wall_time_unix_seconds"] = seconds.into();
        serde_json::to_vec(&declaration).map_err(|e| e.to_string())
    }

    /// The hypervisor evidence for [`admit`](crate::sandbox::backend::admit).
    pub fn evidence(&self) -> &Satisfied {
        &self.evidence
    }

    pub fn volumes(&self) -> &BTreeMap<Digest, HostPath> {
        &self.volumes
    }

    pub fn reserved_ram_bytes(&self) -> u64 {
        self.reserved_ram_bytes
    }

    pub fn windows(&self) -> Option<&WindowsHostRestrictions> {
        self.windows.as_ref()
    }

    /// What the host applies to the QEMU process on Linux; `None` elsewhere.
    pub fn linux(&self) -> Option<&LinuxHostRestrictions> {
        self.linux.as_ref()
    }
}

/// Builds the launch plan of one boot, or refuses before anything is created. In order:
/// the backend is a QEMU build for this host's one hardware hypervisor; the backend's
/// precheck passes (pinned build, offered features, fresh host-probed CORE-01 evidence
/// that the hypervisor is available, so a host without it is refused and nothing retries
/// in emulation: VM-CP-01, VM-CP-33, lines 3151 and 3183); the platform applies every
/// required confinement control; every declared volume and no other has a host path; the
/// CORE-03 reservation belongs to this launch, is open and holds the guest memory; and
/// every path suits the platform.
pub fn plan_launch(
    request: &LaunchRequest,
    backend: &BackendIdentity,
    host: &dyn HostEvidence,
    reservations: &dyn ReservationView,
    inputs: QemuLaunchInputs,
) -> Result<QemuLaunchPlan, ProfileRefusal> {
    if backend.kind != BackendKind::Qemu {
        return Err(ProfileRefusal::NotQemuBackend { kind: backend.kind });
    }
    let fixed = inputs
        .platform
        .profile()
        .map_err(|refusal| ProfileRefusal::Platform { refusal })?;
    if backend.hypervisor != fixed.hypervisor {
        return Err(ProfileRefusal::HypervisorMismatch {
            platform: fixed.hypervisor,
            backend: backend.hypervisor,
        });
    }
    if inputs.workload_image != request.required.workload_image {
        return Err(ProfileRefusal::WorkloadImage {
            detail: "the layout changed the requested image".into(),
        });
    }
    if let Some(image) = &inputs.workload_image {
        image
            .validate()
            .map_err(|detail| ProfileRefusal::WorkloadImage { detail })?;
        if image.root_bytes.saturating_add(256 << 20) > inputs.resources.memory_bytes() {
            return Err(ProfileRefusal::WorkloadImage {
                detail:
                    "guest RAM must cover the image root plus 256 MiB for its agent and processes"
                        .into(),
            });
        }
    }
    let internet = request
        .required
        .network
        .channels
        .contains(&crate::sandbox::backend::NetworkChannel::Internet);
    if inputs.targets != request.required.targets {
        return Err(ProfileRefusal::NetworkTargets {
            detail: "the layout changed the requested targets".into(),
        });
    }
    if inputs.targets.is_some() && !internet {
        return Err(ProfileRefusal::NetworkTargets {
            detail: "targets were named for a launch without a network card".into(),
        });
    }
    let evidence = precheck(request, backend, &qemu_features(), host)
        .map_err(|refusal| ProfileRefusal::Launch { refusal })?;
    let missing: BTreeSet<ConfinementControl> = request
        .required
        .confinement
        .difference(&fixed.confinement_applied())
        .copied()
        .collect();
    if !missing.is_empty() {
        return Err(ProfileRefusal::ConfinementNotProvided { missing });
    }
    let declared = request.required.persistence.volumes();
    if let Some(volume) = declared
        .iter()
        .find(|volume| !inputs.volumes.contains_key(volume))
    {
        return Err(ProfileRefusal::VolumeNotProvided { volume: *volume });
    }
    if let Some(volume) = inputs
        .volumes
        .keys()
        .find(|volume| !declared.contains(volume))
    {
        return Err(ProfileRefusal::UndeclaredVolume { volume: *volume });
    }
    let reserved = reservations.reserved_vm(request.reservation).ok_or(
        ProfileRefusal::ReservationNotFound {
            reservation: request.reservation,
        },
    )?;
    if reserved.execution != request.execution || reserved.tenant != request.tenant {
        return Err(ProfileRefusal::ReservationOfOtherExecution {
            reservation: request.reservation,
            execution: reserved.execution,
            tenant: reserved.tenant,
        });
    }
    if !matches!(
        reserved.state,
        ReservationState::Granted | ReservationState::InUse
    ) {
        return Err(ProfileRefusal::ReservationNotUsable {
            reservation: request.reservation,
            state: reserved.state,
        });
    }
    if inputs.resources.memory_bytes() > reserved.ram_bytes {
        return Err(ProfileRefusal::MemoryExceedsReservation {
            memory_bytes: inputs.resources.memory_bytes(),
            reserved_bytes: reserved.ram_bytes,
        });
    }
    let name = InstanceName::of(vm_handle(
        BackendKind::Qemu,
        &request.execution,
        request.generations.boot,
    ));
    let profile = QemuProfile::assemble(ProfileParts {
        internet,
        platform: inputs.platform,
        name,
        resources: inputs.resources,
        firmware_directory: inputs.firmware_directory,
        kernel: inputs.kernel,
        initrd: inputs.initrd,
        kernel_arguments: inputs.kernel_arguments,
        root_image: inputs.root_image,
        volumes: inputs.volumes.values().cloned().collect(),
        control: inputs.control,
        cid: inputs.vsock_cid,
    })?;
    let windows = match profile.platform().os {
        OsKind::Windows => Some(WindowsHostRestrictions::for_profile(
            &profile,
            reserved.ram_bytes,
        )),
        _ => None,
    };
    let linux = match profile.platform().os {
        OsKind::Linux => Some(LinuxHostRestrictions::for_profile(
            &profile,
            reserved.ram_bytes,
        )),
        _ => None,
    };
    Ok(QemuLaunchPlan {
        profile,
        evidence,
        volumes: inputs.volumes,
        reserved_ram_bytes: reserved.ram_bytes,
        windows,
        linux,
        egress_endpoints: inputs.egress_endpoints,
        workload_image: inputs.workload_image,
        targets: inputs.targets,
    })
}
