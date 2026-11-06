//! vsock's binding of the link to one guest (M06 carry-forward: "restrict transport
//! writers"; §3.2 line 2061 and lines 2073–2074: bind the host's channel to the VM object
//! it launched; VM-R25 line 2890: restrict vsock device access; VM-R56 line 2921; VM-R64
//! line 2929: restrict host vsock endpoints).
//!
//! Two forms:
//!
//! - [`VsockPolicy::Kernel`]: `AF_VSOCK` through the host kernel (vhost-vsock, QEMU on
//!   Linux). Context ids are global to the host, so the host allocates each guest its own
//!   and the device must carry exactly that id. The host listens on
//!   (`VMADDR_CID_HOST`, port), never `VMADDR_CID_ANY`, and accepts a connection only from
//!   the bound guest's context id: the hypervisor (0), local loopback (1), the host
//!   itself (2), the wildcard and every other guest are refused. Binding the listener
//!   to the host id alone does not keep local processes out, so the peer check is the
//!   restriction.
//! - [`VsockPolicy::Hybrid`]: Firecracker's vsock. The device is the VM's own, so its
//!   context id only has to be the configured one; the guest's connections to the host
//!   arrive on the Unix socket `<uds>_<port>` the host listens on, whose ownership and
//!   peer are a [`UnixSocketPolicy`] in the jail layout.
//!
//! Allocating context ids so that no two running guests share one is the backend's part;
//! this module checks one instance's observation.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::unix_socket::{
    ObservedUnixSocket, UnixIdentity, UnixPolicyError, UnixSocketFinding, UnixSocketPolicy,
};

/// `VMADDR_CID_HYPERVISOR`.
pub const VMADDR_CID_HYPERVISOR: u32 = 0;
/// `VMADDR_CID_LOCAL`: loopback within one host or guest.
pub const VMADDR_CID_LOCAL: u32 = 1;
/// `VMADDR_CID_HOST`.
pub const VMADDR_CID_HOST: u32 = 2;
/// `VMADDR_CID_ANY`.
pub const VMADDR_CID_ANY: u32 = u32::MAX;
/// `VMADDR_PORT_ANY`.
pub const VMADDR_PORT_ANY: u32 = u32::MAX;

/// Why a vsock policy could not be made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "vsock_policy_error", rename_all = "snake_case")]
pub enum VsockPolicyError {
    /// 0, 1, 2 and `VMADDR_CID_ANY` name no guest.
    ReservedCid {
        cid: u32,
    },
    /// `VMADDR_PORT_ANY` is not one port.
    AnyPort,
    Socket(UnixPolicyError),
}

impl fmt::Display for VsockPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ReservedCid { cid } => write!(
                f,
                "vsock context id {cid} is reserved; guests use 3 to 4294967294"
            ),
            Self::AnyPort => f.write_str("the link needs one vsock port, not VMADDR_PORT_ANY"),
            Self::Socket(error) => fmt::Display::fmt(error, f),
        }
    }
}

impl std::error::Error for VsockPolicyError {}

/// The context id of one guest: 3 to `u32::MAX - 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GuestCid(u32);

impl GuestCid {
    pub fn new(cid: u32) -> Result<Self, VsockPolicyError> {
        if cid <= VMADDR_CID_HOST || cid == VMADDR_CID_ANY {
            Err(VsockPolicyError::ReservedCid { cid })
        } else {
            Ok(Self(cid))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// The port the host listens on for the guest's link connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct VsockPort(u32);

impl VsockPort {
    pub fn new(port: u32) -> Result<Self, VsockPolicyError> {
        if port == VMADDR_PORT_ANY {
            Err(VsockPolicyError::AnyPort)
        } else {
            Ok(Self(port))
        }
    }

    pub const fn get(self) -> u32 {
        self.0
    }
}

/// Which form of vsock.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VsockKind {
    Kernel,
    Hybrid,
}

/// The link's vsock binding. Computed, never read from a record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "vsock", rename_all = "snake_case")]
pub enum VsockPolicy {
    Kernel {
        guest_cid: GuestCid,
        port: VsockPort,
    },
    Hybrid {
        guest_cid: GuestCid,
        port: VsockPort,
        socket: UnixSocketPolicy,
    },
}

impl VsockPolicy {
    /// Kernel vsock with the host-allocated `guest_cid`, listening on `port`.
    pub fn kernel(guest_cid: GuestCid, port: VsockPort) -> Self {
        Self::Kernel { guest_cid, port }
    }

    /// Firecracker's vsock: the device has `guest_cid`, and the host listens on
    /// `<uds_name>_<port>` in the jail's socket directory, reachable by `jail` only.
    pub fn hybrid(
        guest_cid: GuestCid,
        port: VsockPort,
        uds_name: &str,
        host: UnixIdentity,
        jail: UnixIdentity,
    ) -> Result<Self, VsockPolicyError> {
        let socket =
            UnixSocketPolicy::shared_with_jail(host, jail, &format!("{uds_name}_{}", port.get()))
                .map_err(VsockPolicyError::Socket)?;
        Ok(Self::Hybrid {
            guest_cid,
            port,
            socket,
        })
    }

    pub const fn kind(&self) -> VsockKind {
        match self {
            Self::Kernel { .. } => VsockKind::Kernel,
            Self::Hybrid { .. } => VsockKind::Hybrid,
        }
    }

    pub const fn guest_cid(&self) -> GuestCid {
        match self {
            Self::Kernel { guest_cid, .. } | Self::Hybrid { guest_cid, .. } => *guest_cid,
        }
    }

    pub const fn port(&self) -> VsockPort {
        match self {
            Self::Kernel { port, .. } | Self::Hybrid { port, .. } => *port,
        }
    }

    /// Compares the observed device and listener with the policy; an empty list means
    /// they match.
    pub fn check(&self, observed: &ObservedVsock) -> Vec<VsockFinding> {
        let mut findings = Vec::new();
        let device_guest_cid = match (self, observed) {
            (
                Self::Kernel { port, .. },
                ObservedVsock::Kernel {
                    device_guest_cid,
                    listener_cid,
                    listener_port,
                },
            ) => {
                if *listener_cid != VMADDR_CID_HOST {
                    findings.push(VsockFinding::ListenerNotOnHostCid {
                        found: *listener_cid,
                    });
                }
                if *listener_port != port.get() {
                    findings.push(VsockFinding::ListenerPortDiffers {
                        expected: port.get(),
                        found: *listener_port,
                    });
                }
                *device_guest_cid
            }
            (
                Self::Hybrid { socket, .. },
                ObservedVsock::Hybrid {
                    device_guest_cid,
                    socket: observed_socket,
                },
            ) => {
                findings.extend(
                    socket
                        .check(observed_socket)
                        .into_iter()
                        .map(|socket| VsockFinding::Socket { socket }),
                );
                *device_guest_cid
            }
            _ => {
                return vec![VsockFinding::KindDiffers {
                    expected: self.kind(),
                    found: observed.kind(),
                }]
            }
        };
        if device_guest_cid != self.guest_cid().get() {
            findings.insert(
                0,
                VsockFinding::DeviceCidDiffers {
                    expected: self.guest_cid().get(),
                    found: device_guest_cid,
                },
            );
        }
        findings
    }

    /// Compares the peer of an accepted connection with the bound guest.
    pub fn check_peer(&self, peer: &ObservedVsockPeer) -> Vec<VsockFinding> {
        match (self, peer) {
            (Self::Kernel { guest_cid, .. }, ObservedVsockPeer::Kernel { cid, .. }) => {
                if *cid <= VMADDR_CID_HOST || *cid == VMADDR_CID_ANY {
                    vec![VsockFinding::PeerNotAGuest { found: *cid }]
                } else if *cid != guest_cid.get() {
                    vec![VsockFinding::PeerIsAnotherGuest {
                        expected: guest_cid.get(),
                        found: *cid,
                    }]
                } else {
                    Vec::new()
                }
            }
            (Self::Hybrid { socket, .. }, ObservedVsockPeer::Hybrid { uid, gid }) => socket
                .check_peer(UnixIdentity {
                    uid: *uid,
                    gid: *gid,
                })
                .into_iter()
                .map(|socket| VsockFinding::Socket { socket })
                .collect(),
            _ => vec![VsockFinding::KindDiffers {
                expected: self.kind(),
                found: peer.kind(),
            }],
        }
    }
}

/// The vsock device and the host's listener as the host observed them: the device's
/// context id from the hypervisor's configuration read back, the listener's address
/// from `getsockname`, or the hybrid listener's socket from `lstat`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "vsock", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedVsock {
    Kernel {
        device_guest_cid: u32,
        listener_cid: u32,
        listener_port: u32,
    },
    Hybrid {
        device_guest_cid: u32,
        socket: ObservedUnixSocket,
    },
}

impl ObservedVsock {
    pub const fn kind(&self) -> VsockKind {
        match self {
            Self::Kernel { .. } => VsockKind::Kernel,
            Self::Hybrid { .. } => VsockKind::Hybrid,
        }
    }
}

/// The peer of one accepted connection: its vsock address from `accept`, or the hybrid
/// socket's peer credentials.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "vsock", rename_all = "snake_case", deny_unknown_fields)]
pub enum ObservedVsockPeer {
    Kernel { cid: u32, port: u32 },
    Hybrid { uid: u32, gid: u32 },
}

impl ObservedVsockPeer {
    pub const fn kind(&self) -> VsockKind {
        match self {
            Self::Kernel { .. } => VsockKind::Kernel,
            Self::Hybrid { .. } => VsockKind::Hybrid,
        }
    }
}

/// One way an observed vsock binding differs from the policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum VsockFinding {
    KindDiffers {
        expected: VsockKind,
        found: VsockKind,
    },
    /// The device carries another context id than the host allocated.
    DeviceCidDiffers {
        expected: u32,
        found: u32,
    },
    /// The listener is bound to another address than `VMADDR_CID_HOST`, the wildcard
    /// included.
    ListenerNotOnHostCid {
        found: u32,
    },
    ListenerPortDiffers {
        expected: u32,
        found: u32,
    },
    /// The peer is the hypervisor, a local process or the host itself.
    PeerNotAGuest {
        found: u32,
    },
    PeerIsAnotherGuest {
        expected: u32,
        found: u32,
    },
    /// The hybrid listener's socket or peer differs.
    Socket {
        socket: UnixSocketFinding,
    },
}

impl fmt::Display for VsockFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::KindDiffers { expected, found } => {
                write!(f, "the vsock is {found:?}, not {expected:?}")
            }
            Self::DeviceCidDiffers { expected, found } => write!(
                f,
                "the vsock device has context id {found}, not the allocated {expected}"
            ),
            Self::ListenerNotOnHostCid { found } => write!(
                f,
                "the listener is bound to context id {found}, not the host's {VMADDR_CID_HOST}"
            ),
            Self::ListenerPortDiffers { expected, found } => {
                write!(f, "the listener is on port {found}, not {expected}")
            }
            Self::PeerNotAGuest { found } => write!(
                f,
                "the connection came from context id {found}, which is not a guest"
            ),
            Self::PeerIsAnotherGuest { expected, found } => write!(
                f,
                "the connection came from guest {found}, not the bound guest {expected}"
            ),
            Self::Socket { socket } => fmt::Display::fmt(socket, f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::link_transport::unix_socket::{NodeRole, ObservedNode, S_IFDIR, S_IFSOCK};

    const HOST: UnixIdentity = UnixIdentity {
        uid: 1_000,
        gid: 1_000,
    };
    const JAIL: UnixIdentity = UnixIdentity {
        uid: 900_001,
        gid: 900_001,
    };

    fn kernel() -> VsockPolicy {
        VsockPolicy::kernel(GuestCid::new(41).unwrap(), VsockPort::new(1_024).unwrap())
    }

    fn hybrid() -> VsockPolicy {
        VsockPolicy::hybrid(
            GuestCid::new(3).unwrap(),
            VsockPort::new(1_024).unwrap(),
            "link.sock",
            HOST,
            JAIL,
        )
        .unwrap()
    }

    fn observed_kernel() -> ObservedVsock {
        ObservedVsock::Kernel {
            device_guest_cid: 41,
            listener_cid: VMADDR_CID_HOST,
            listener_port: 1_024,
        }
    }

    fn observed_socket() -> ObservedUnixSocket {
        ObservedUnixSocket {
            socket_name: "link.sock_1024".to_owned(),
            directory: ObservedNode {
                uid: JAIL.uid,
                gid: HOST.gid,
                mode: S_IFDIR | 0o770,
            },
            socket: ObservedNode {
                uid: HOST.uid,
                gid: JAIL.gid,
                mode: S_IFSOCK | 0o660,
            },
        }
    }

    #[test]
    fn reserved_context_ids_and_the_wildcard_port_are_refused() {
        for cid in [0, 1, 2, u32::MAX] {
            assert_eq!(
                GuestCid::new(cid),
                Err(VsockPolicyError::ReservedCid { cid })
            );
        }
        assert_eq!(GuestCid::new(3).unwrap().get(), 3);
        assert_eq!(GuestCid::new(u32::MAX - 1).unwrap().get(), u32::MAX - 1);
        assert_eq!(VsockPort::new(u32::MAX), Err(VsockPolicyError::AnyPort));
        assert_eq!(VsockPort::new(0).unwrap().get(), 0);
        assert_eq!(
            VsockPolicy::hybrid(
                GuestCid::new(3).unwrap(),
                VsockPort::new(52).unwrap(),
                "link/sock",
                HOST,
                JAIL
            ),
            Err(VsockPolicyError::Socket(
                UnixPolicyError::InvalidSocketName {
                    name: "link/sock_52".to_owned()
                }
            ))
        );
    }

    #[test]
    fn the_bound_configuration_matches() {
        assert_eq!(kernel().check(&observed_kernel()), vec![]);
        let observed = ObservedVsock::Hybrid {
            device_guest_cid: 3,
            socket: observed_socket(),
        };
        assert_eq!(hybrid().check(&observed), vec![]);
        assert_eq!(hybrid().kind(), VsockKind::Hybrid);
        assert_eq!(hybrid().guest_cid().get(), 3);
        assert_eq!(kernel().port().get(), 1_024);
    }

    #[test]
    fn a_wrong_device_listener_or_kind_is_a_finding() {
        let cases = [
            (
                ObservedVsock::Kernel {
                    device_guest_cid: 42,
                    listener_cid: VMADDR_CID_HOST,
                    listener_port: 1_024,
                },
                vec![VsockFinding::DeviceCidDiffers {
                    expected: 41,
                    found: 42,
                }],
            ),
            (
                ObservedVsock::Kernel {
                    device_guest_cid: 41,
                    listener_cid: VMADDR_CID_ANY,
                    listener_port: 1_025,
                },
                vec![
                    VsockFinding::ListenerNotOnHostCid { found: u32::MAX },
                    VsockFinding::ListenerPortDiffers {
                        expected: 1_024,
                        found: 1_025,
                    },
                ],
            ),
            (
                ObservedVsock::Hybrid {
                    device_guest_cid: 41,
                    socket: observed_socket(),
                },
                vec![VsockFinding::KindDiffers {
                    expected: VsockKind::Kernel,
                    found: VsockKind::Hybrid,
                }],
            ),
        ];
        for (observed, findings) in cases {
            assert_eq!(kernel().check(&observed), findings, "{observed:?}");
        }
        let mut socket = observed_socket();
        socket.socket.mode = S_IFSOCK | 0o666;
        assert_eq!(
            hybrid().check(&ObservedVsock::Hybrid {
                device_guest_cid: 4,
                socket
            }),
            vec![
                VsockFinding::DeviceCidDiffers {
                    expected: 3,
                    found: 4
                },
                VsockFinding::Socket {
                    socket: UnixSocketFinding::ModeDiffers {
                        node: NodeRole::Socket,
                        expected: 0o660,
                        found: 0o666
                    }
                },
            ]
        );
    }

    #[test]
    fn only_the_bound_guest_may_connect() {
        assert_eq!(
            kernel().check_peer(&ObservedVsockPeer::Kernel {
                cid: 41,
                port: 50_000
            }),
            vec![]
        );
        for cid in [
            VMADDR_CID_HYPERVISOR,
            VMADDR_CID_LOCAL,
            VMADDR_CID_HOST,
            VMADDR_CID_ANY,
        ] {
            assert_eq!(
                kernel().check_peer(&ObservedVsockPeer::Kernel { cid, port: 1 }),
                vec![VsockFinding::PeerNotAGuest { found: cid }]
            );
        }
        let other = kernel().check_peer(&ObservedVsockPeer::Kernel { cid: 40, port: 1 });
        assert_eq!(
            other,
            vec![VsockFinding::PeerIsAnotherGuest {
                expected: 41,
                found: 40
            }]
        );
        assert_eq!(
            other[0].to_string(),
            "the connection came from guest 40, not the bound guest 41"
        );
        assert_eq!(
            hybrid().check_peer(&ObservedVsockPeer::Hybrid {
                uid: JAIL.uid,
                gid: JAIL.gid
            }),
            vec![]
        );
        assert_eq!(
            hybrid().check_peer(&ObservedVsockPeer::Hybrid {
                uid: 1_000,
                gid: 1_000
            }),
            vec![VsockFinding::Socket {
                socket: UnixSocketFinding::PeerDiffers {
                    expected: JAIL,
                    found: HOST
                }
            }]
        );
        assert_eq!(
            hybrid().check_peer(&ObservedVsockPeer::Kernel { cid: 3, port: 1 }),
            vec![VsockFinding::KindDiffers {
                expected: VsockKind::Hybrid,
                found: VsockKind::Kernel
            }]
        );
    }

    #[test]
    fn observations_read_strictly() {
        let value = serde_json::to_value(observed_kernel()).unwrap();
        assert_eq!(
            value,
            serde_json::json!({"vsock": "kernel", "device_guest_cid": 41, "listener_cid": 2, "listener_port": 1024})
        );
        assert_eq!(
            serde_json::from_value::<ObservedVsock>(value.clone()).unwrap(),
            observed_kernel()
        );
        let mut extra = value;
        extra["peer_cid"] = serde_json::json!(41);
        assert!(serde_json::from_value::<ObservedVsock>(extra).is_err());
        assert!(serde_json::from_value::<ObservedVsockPeer>(
            serde_json::json!({"vsock": "kernel", "cid": 41, "port": 1, "uid": 0})
        )
        .is_err());
        assert_eq!(
            serde_json::to_value(kernel()).unwrap(),
            serde_json::json!({"vsock": "kernel", "guest_cid": 41, "port": 1024})
        );
        let nested = VsockFinding::Socket {
            socket: UnixSocketFinding::PeerDiffers {
                expected: JAIL,
                found: HOST,
            },
        };
        assert_eq!(
            serde_json::to_string(&nested).unwrap(),
            r#"{"finding":"socket","socket":{"finding":"peer_differs","expected":{"uid":900001,"gid":900001},"found":{"uid":1000,"gid":1000}}}"#
        );
    }
}
