//! The Unix-domain socket of one VM's link: who owns it and its directory, their modes,
//! and who may connect (M06 carry-forward: "restrict transport writers"; §3.2 line 2061;
//! VM-R25 line 2890 and VM-R64 line 2929: least host privilege and OS permissions on host
//! endpoints; VM-P03 line 2778).
//!
//! Connecting to a Unix socket needs search permission on its directory and write
//! permission on the socket file, so the directory's and the socket's owner, group and
//! mode decide which accounts can write to the link. Two layouts are fixed here:
//!
//! - [`UnixSocketPolicy::host_private`]: the hypervisor runs as the host's own account
//!   (QEMU's virtio-serial socket where there is no vsock): directory `0700` and socket
//!   `0600`, both the host's, and the peer must be the host's account.
//! - [`UnixSocketPolicy::shared_with_jail`]: Firecracker's jail. The socket directory
//!   belongs to the jail and the host owner's group with `0770` (as
//!   `sandbox::firecracker`'s launcher creates it); the socket the host listens on for the
//!   guest's connections belongs to the host and the jail's group with `0660`; the peer
//!   must be the jail's identity.
//!
//! [`UnixSocketPolicy::check`] compares what `lstat` reported (no link is followed): each
//! node's type, owner, group and every permission bit, the set-id and sticky bits
//! included, must be exactly the policy's. [`UnixSocketPolicy::check_peer`] compares the
//! connected peer's credentials (`SO_PEERCRED`, `getpeereid`). A peer of the host's own
//! account in the private layout can be any process of that account; telling the
//! hypervisor from those needs the peer's process, which is outside this module.

use std::fmt;

use serde::{Deserialize, Serialize};

/// The file-type bits of `st_mode`.
pub const S_IFMT: u32 = 0o170_000;
pub const S_IFDIR: u32 = 0o040_000;
pub const S_IFSOCK: u32 = 0o140_000;
pub const S_IFLNK: u32 = 0o120_000;
pub const S_IFREG: u32 = 0o100_000;
pub const S_IFIFO: u32 = 0o010_000;
/// Permission, set-id and sticky bits.
pub const PERMISSION_BITS: u32 = 0o7_777;

/// The private layout's directory mode.
pub const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
/// The private layout's socket mode.
pub const PRIVATE_SOCKET_MODE: u32 = 0o600;
/// The jail layout's directory mode (the firecracker launcher's socket directory).
pub const SHARED_DIRECTORY_MODE: u32 = 0o770;
/// The jail layout's socket mode.
pub const SHARED_SOCKET_MODE: u32 = 0o660;
/// The longest socket file name.
pub const MAX_SOCKET_NAME_BYTES: usize = 64;

/// A user and primary group id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UnixIdentity {
    pub uid: u32,
    pub gid: u32,
}

/// The owner, group and permission bits one node must have.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct NodePolicy {
    pub owner_uid: u32,
    pub group_gid: u32,
    pub mode: u32,
}

/// Why a socket policy could not be made.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "unix_policy_error", rename_all = "snake_case")]
pub enum UnixPolicyError {
    /// Not 1 to 64 bytes of letters, digits, `.`, `_` and `-`, or `.` or `..`.
    InvalidSocketName { name: String },
    /// The jail runs as root or root's group.
    JailIsRoot,
    /// The jail shares the host's user or group id, so the modes cannot tell them apart.
    JailSharesHostIds,
}

impl fmt::Display for UnixPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSocketName { name } => write!(
                f,
                "{name:?} is not a socket name of 1 to {MAX_SOCKET_NAME_BYTES} letters, \
                 digits, dots, underscores and hyphens"
            ),
            Self::JailIsRoot => f.write_str("the jail may not run as root or root's group"),
            Self::JailSharesHostIds => f.write_str("the jail shares the host's user or group id"),
        }
    }
}

impl std::error::Error for UnixPolicyError {}

/// Which node a finding is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeRole {
    Directory,
    Socket,
}

impl NodeRole {
    const fn name(self) -> &'static str {
        match self {
            Self::Directory => "socket directory",
            Self::Socket => "socket",
        }
    }
}

/// A node's file type, from `st_mode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Directory,
    Socket,
    SymbolicLink,
    RegularFile,
    Fifo,
    Other,
}

impl NodeKind {
    pub const fn of(mode: u32) -> Self {
        match mode & S_IFMT {
            S_IFDIR => Self::Directory,
            S_IFSOCK => Self::Socket,
            S_IFLNK => Self::SymbolicLink,
            S_IFREG => Self::RegularFile,
            S_IFIFO => Self::Fifo,
            _ => Self::Other,
        }
    }
}

/// One node as `lstat` reported it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedNode {
    pub uid: u32,
    pub gid: u32,
    /// The whole `st_mode`, file type included.
    pub mode: u32,
}

/// The link socket and its directory as the host observed them.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedUnixSocket {
    /// The socket's file name in the directory.
    pub socket_name: String,
    pub directory: ObservedNode,
    pub socket: ObservedNode,
}

/// One way an observed socket or peer differs from the policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "finding", rename_all = "snake_case")]
pub enum UnixSocketFinding {
    SocketNameDiffers {
        expected: String,
        found: String,
    },
    /// The directory is not a directory or the socket not a socket (a symbolic link
    /// included); nothing else about that node is compared.
    WrongKind {
        node: NodeRole,
        found: NodeKind,
    },
    OwnerDiffers {
        node: NodeRole,
        expected: u32,
        found: u32,
    },
    GroupDiffers {
        node: NodeRole,
        expected: u32,
        found: u32,
    },
    ModeDiffers {
        node: NodeRole,
        expected: u32,
        found: u32,
    },
    PeerDiffers {
        expected: UnixIdentity,
        found: UnixIdentity,
    },
}

impl fmt::Display for UnixSocketFinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SocketNameDiffers { expected, found } => {
                write!(f, "the socket is named {found:?}, not {expected:?}")
            }
            Self::WrongKind { node, found } => {
                write!(f, "the {} is a {found:?}", node.name())
            }
            Self::OwnerDiffers {
                node,
                expected,
                found,
            } => write!(
                f,
                "the {} is owned by uid {found}, not {expected}",
                node.name()
            ),
            Self::GroupDiffers {
                node,
                expected,
                found,
            } => write!(f, "the {} has group {found}, not {expected}", node.name()),
            Self::ModeDiffers {
                node,
                expected,
                found,
            } => write!(
                f,
                "the {} has mode {found:o}, not {expected:o}",
                node.name()
            ),
            Self::PeerDiffers { expected, found } => write!(
                f,
                "the peer is uid {} gid {}, not uid {} gid {}",
                found.uid, found.gid, expected.uid, expected.gid
            ),
        }
    }
}

/// Who may reach the link socket: its directory, the socket itself and the peer.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UnixSocketPolicy {
    socket_name: String,
    directory: NodePolicy,
    socket: NodePolicy,
    peer: UnixIdentity,
}

impl UnixSocketPolicy {
    /// The hypervisor runs as `host`: directory `0700` and socket `0600`, both the
    /// host's; the peer must be `host`.
    pub fn host_private(host: UnixIdentity, socket_name: &str) -> Result<Self, UnixPolicyError> {
        Ok(Self {
            socket_name: checked_name(socket_name)?,
            directory: NodePolicy {
                owner_uid: host.uid,
                group_gid: host.gid,
                mode: PRIVATE_DIRECTORY_MODE,
            },
            socket: NodePolicy {
                owner_uid: host.uid,
                group_gid: host.gid,
                mode: PRIVATE_SOCKET_MODE,
            },
            peer: host,
        })
    }

    /// The hypervisor runs as `jail`, in a directory the jail owns with the host's
    /// group (`0770`); the host's socket there belongs to the host and the jail's group
    /// (`0660`); the peer must be `jail`. The jail may be neither root nor share an id
    /// with the host.
    pub fn shared_with_jail(
        host: UnixIdentity,
        jail: UnixIdentity,
        socket_name: &str,
    ) -> Result<Self, UnixPolicyError> {
        let socket_name = checked_name(socket_name)?;
        if jail.uid == 0 || jail.gid == 0 {
            return Err(UnixPolicyError::JailIsRoot);
        }
        if jail.uid == host.uid || jail.gid == host.gid {
            return Err(UnixPolicyError::JailSharesHostIds);
        }
        Ok(Self {
            socket_name,
            directory: NodePolicy {
                owner_uid: jail.uid,
                group_gid: host.gid,
                mode: SHARED_DIRECTORY_MODE,
            },
            socket: NodePolicy {
                owner_uid: host.uid,
                group_gid: jail.gid,
                mode: SHARED_SOCKET_MODE,
            },
            peer: jail,
        })
    }

    pub fn socket_name(&self) -> &str {
        &self.socket_name
    }

    pub fn directory(&self) -> NodePolicy {
        self.directory
    }

    pub fn socket(&self) -> NodePolicy {
        self.socket
    }

    pub fn peer(&self) -> UnixIdentity {
        self.peer
    }

    /// Compares the observed socket and directory with the policy; an empty list means
    /// they match.
    pub fn check(&self, observed: &ObservedUnixSocket) -> Vec<UnixSocketFinding> {
        let mut findings = Vec::new();
        if observed.socket_name != self.socket_name {
            findings.push(UnixSocketFinding::SocketNameDiffers {
                expected: self.socket_name.clone(),
                found: observed.socket_name.clone(),
            });
        }
        check_node(
            NodeRole::Directory,
            NodeKind::Directory,
            &self.directory,
            &observed.directory,
            &mut findings,
        );
        check_node(
            NodeRole::Socket,
            NodeKind::Socket,
            &self.socket,
            &observed.socket,
            &mut findings,
        );
        findings
    }

    /// Compares a connected peer's credentials with the policy's peer.
    pub fn check_peer(&self, peer: UnixIdentity) -> Vec<UnixSocketFinding> {
        if peer == self.peer {
            Vec::new()
        } else {
            vec![UnixSocketFinding::PeerDiffers {
                expected: self.peer,
                found: peer,
            }]
        }
    }
}

fn check_node(
    node: NodeRole,
    kind: NodeKind,
    policy: &NodePolicy,
    observed: &ObservedNode,
    findings: &mut Vec<UnixSocketFinding>,
) {
    let found = NodeKind::of(observed.mode);
    if found != kind {
        findings.push(UnixSocketFinding::WrongKind { node, found });
        return;
    }
    if observed.uid != policy.owner_uid {
        findings.push(UnixSocketFinding::OwnerDiffers {
            node,
            expected: policy.owner_uid,
            found: observed.uid,
        });
    }
    if observed.gid != policy.group_gid {
        findings.push(UnixSocketFinding::GroupDiffers {
            node,
            expected: policy.group_gid,
            found: observed.gid,
        });
    }
    let mode = observed.mode & PERMISSION_BITS;
    if mode != policy.mode {
        findings.push(UnixSocketFinding::ModeDiffers {
            node,
            expected: policy.mode,
            found: mode,
        });
    }
}

fn checked_name(name: &str) -> Result<String, UnixPolicyError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_SOCKET_NAME_BYTES
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'));
    if valid {
        Ok(name.to_owned())
    } else {
        Err(UnixPolicyError::InvalidSocketName {
            name: name.to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOST: UnixIdentity = UnixIdentity {
        uid: 1_000,
        gid: 1_000,
    };
    const JAIL: UnixIdentity = UnixIdentity {
        uid: 900_001,
        gid: 900_001,
    };

    fn private() -> UnixSocketPolicy {
        UnixSocketPolicy::host_private(HOST, "link.sock").unwrap()
    }

    fn jailed() -> UnixSocketPolicy {
        UnixSocketPolicy::shared_with_jail(HOST, JAIL, "link.sock_1024").unwrap()
    }

    fn observed_private() -> ObservedUnixSocket {
        ObservedUnixSocket {
            socket_name: "link.sock".to_owned(),
            directory: ObservedNode {
                uid: 1_000,
                gid: 1_000,
                mode: S_IFDIR | 0o700,
            },
            socket: ObservedNode {
                uid: 1_000,
                gid: 1_000,
                mode: S_IFSOCK | 0o600,
            },
        }
    }

    #[test]
    fn the_two_layouts_fix_owner_group_and_mode() {
        let private = private();
        assert_eq!(
            private.directory(),
            NodePolicy {
                owner_uid: 1_000,
                group_gid: 1_000,
                mode: 0o700
            }
        );
        assert_eq!(private.socket().mode, 0o600);
        assert_eq!(private.peer(), HOST);
        let jailed = jailed();
        assert_eq!(
            jailed.directory(),
            NodePolicy {
                owner_uid: JAIL.uid,
                group_gid: HOST.gid,
                mode: 0o770
            }
        );
        assert_eq!(
            jailed.socket(),
            NodePolicy {
                owner_uid: HOST.uid,
                group_gid: JAIL.gid,
                mode: 0o660
            }
        );
        assert_eq!(jailed.peer(), JAIL);
        assert_eq!(jailed.socket_name(), "link.sock_1024");
    }

    #[test]
    fn impossible_layouts_are_refused() {
        let long = "x".repeat(65);
        for name in ["", ".", "..", "a/b", "link sock", "é", long.as_str()] {
            assert_eq!(
                UnixSocketPolicy::host_private(HOST, name),
                Err(UnixPolicyError::InvalidSocketName {
                    name: name.to_owned()
                })
            );
        }
        assert!(UnixSocketPolicy::host_private(HOST, &"x".repeat(64)).is_ok());
        for (jail, error) in [
            (UnixIdentity { uid: 0, gid: 5 }, UnixPolicyError::JailIsRoot),
            (UnixIdentity { uid: 5, gid: 0 }, UnixPolicyError::JailIsRoot),
            (
                UnixIdentity {
                    uid: HOST.uid,
                    gid: 5,
                },
                UnixPolicyError::JailSharesHostIds,
            ),
            (
                UnixIdentity {
                    uid: 5,
                    gid: HOST.gid,
                },
                UnixPolicyError::JailSharesHostIds,
            ),
        ] {
            assert_eq!(
                UnixSocketPolicy::shared_with_jail(HOST, jail, "link.sock"),
                Err(error.clone())
            );
            assert!(!error.to_string().is_empty());
        }
    }

    #[test]
    fn an_exact_match_passes() {
        assert_eq!(private().check(&observed_private()), vec![]);
        let jailed = ObservedUnixSocket {
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
        };
        assert_eq!(self::jailed().check(&jailed), vec![]);
    }

    #[test]
    fn every_difference_is_a_finding() {
        let base = observed_private();
        let with_directory = |node: ObservedNode| ObservedUnixSocket {
            directory: node,
            ..base.clone()
        };
        let with_socket = |node: ObservedNode| ObservedUnixSocket {
            socket: node,
            ..base.clone()
        };
        let cases = [
            (
                ObservedUnixSocket {
                    socket_name: "other.sock".to_owned(),
                    ..base.clone()
                },
                vec![UnixSocketFinding::SocketNameDiffers {
                    expected: "link.sock".to_owned(),
                    found: "other.sock".to_owned(),
                }],
            ),
            (
                with_directory(ObservedNode {
                    mode: S_IFLNK | 0o777,
                    ..base.directory
                }),
                vec![UnixSocketFinding::WrongKind {
                    node: NodeRole::Directory,
                    found: NodeKind::SymbolicLink,
                }],
            ),
            (
                with_directory(ObservedNode {
                    mode: S_IFDIR | 0o755,
                    ..base.directory
                }),
                vec![UnixSocketFinding::ModeDiffers {
                    node: NodeRole::Directory,
                    expected: 0o700,
                    found: 0o755,
                }],
            ),
            (
                with_directory(ObservedNode {
                    mode: S_IFDIR | 0o1700,
                    ..base.directory
                }),
                vec![UnixSocketFinding::ModeDiffers {
                    node: NodeRole::Directory,
                    expected: 0o700,
                    found: 0o1700,
                }],
            ),
            (
                with_directory(ObservedNode {
                    uid: 0,
                    gid: 0,
                    ..base.directory
                }),
                vec![
                    UnixSocketFinding::OwnerDiffers {
                        node: NodeRole::Directory,
                        expected: 1_000,
                        found: 0,
                    },
                    UnixSocketFinding::GroupDiffers {
                        node: NodeRole::Directory,
                        expected: 1_000,
                        found: 0,
                    },
                ],
            ),
            (
                with_socket(ObservedNode {
                    mode: S_IFREG | 0o600,
                    ..base.socket
                }),
                vec![UnixSocketFinding::WrongKind {
                    node: NodeRole::Socket,
                    found: NodeKind::RegularFile,
                }],
            ),
            (
                with_socket(ObservedNode {
                    mode: S_IFSOCK | 0o666,
                    ..base.socket
                }),
                vec![UnixSocketFinding::ModeDiffers {
                    node: NodeRole::Socket,
                    expected: 0o600,
                    found: 0o666,
                }],
            ),
            (
                with_socket(ObservedNode {
                    mode: S_IFSOCK | 0o2600,
                    ..base.socket
                }),
                vec![UnixSocketFinding::ModeDiffers {
                    node: NodeRole::Socket,
                    expected: 0o600,
                    found: 0o2600,
                }],
            ),
            (
                with_socket(ObservedNode {
                    uid: 1_001,
                    ..base.socket
                }),
                vec![UnixSocketFinding::OwnerDiffers {
                    node: NodeRole::Socket,
                    expected: 1_000,
                    found: 1_001,
                }],
            ),
        ];
        for (observed, findings) in cases {
            assert_eq!(private().check(&observed), findings, "{observed:?}");
            for finding in &findings {
                assert!(!finding.to_string().is_empty());
            }
        }
        assert_eq!(NodeKind::of(S_IFIFO | 0o600), NodeKind::Fifo);
        assert_eq!(NodeKind::of(0o060_000), NodeKind::Other);
    }

    #[test]
    fn only_the_policy_peer_may_connect() {
        assert_eq!(private().check_peer(HOST), vec![]);
        assert_eq!(jailed().check_peer(JAIL), vec![]);
        let finding = jailed().check_peer(HOST);
        assert_eq!(
            finding,
            vec![UnixSocketFinding::PeerDiffers {
                expected: JAIL,
                found: HOST
            }]
        );
        assert_eq!(
            finding[0].to_string(),
            "the peer is uid 1000 gid 1000, not uid 900001 gid 900001"
        );
        assert_eq!(
            private()
                .check_peer(UnixIdentity {
                    uid: 1_000,
                    gid: 20
                })
                .len(),
            1
        );
    }

    #[test]
    fn observations_read_strictly() {
        let text = serde_json::to_string(&observed_private()).unwrap();
        assert_eq!(
            serde_json::from_str::<ObservedUnixSocket>(&text).unwrap(),
            observed_private()
        );
        let mut value = serde_json::to_value(observed_private()).unwrap();
        value["directory"]["inode"] = serde_json::json!(7);
        assert!(serde_json::from_value::<ObservedUnixSocket>(value).is_err());
        assert_eq!(
            serde_json::to_value(UnixSocketFinding::ModeDiffers {
                node: NodeRole::Socket,
                expected: 0o600,
                found: 0o666
            })
            .unwrap(),
            serde_json::json!({"finding": "mode_differs", "node": "socket", "expected": 384, "found": 438})
        );
    }
}
