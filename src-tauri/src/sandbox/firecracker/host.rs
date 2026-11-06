//! The host's jail settings: where the official jailer and Firecracker binaries are, the
//! chroot base, the network namespace directory, the cgroup v2 root and parent, the
//! content-addressed directory of verified artifacts, the host service identity that owns
//! the logger and metrics sinks, and the range of user and group ids reserved for jails
//! (§7.2 line 2370: the jailer drops to the selected UID/GID; VM-D15 line 3209).
//!
//! Host configuration, never a launch request, supplies these; a request names none of
//! them, so a guest or a template cannot move the jail or pick its identity.

use std::fmt;

use serde::{Deserialize, Serialize};

use super::names::{CgroupPath, HostPath, JailIdentity};

/// The substring the official jailer requires in the name of the file it executes.
pub const EXEC_FILE_MARKER: &str = "firecracker";

/// The host service identity that owns the host-created sinks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostOwner {
    pub uid: u32,
    pub gid: u32,
}

/// A range of ids reserved for jails: `first` to `first + count - 1`, used for both user
/// and group ids.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IdRange {
    pub first: u32,
    pub count: u32,
}

impl IdRange {
    /// Whether `id` lies in the range; an empty or overflowing range holds nothing.
    pub fn contains(self, id: u32) -> bool {
        id >= self.first && u64::from(id) < u64::from(self.first) + u64::from(self.count)
    }

    fn last(self) -> Option<u32> {
        self.count
            .checked_sub(1)
            .and_then(|span| self.first.checked_add(span))
    }
}

/// The host's settings for every Firecracker jail.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailHost {
    /// The official jailer binary of the pinned release.
    pub jailer: HostPath,
    /// The Firecracker binary the jailer executes.
    pub firecracker: HostPath,
    /// The jailer's `--chroot-base-dir`.
    pub chroot_base: HostPath,
    /// Where per-launch network namespaces are created, such as `/run/netns`.
    pub netns_dir: HostPath,
    /// The cgroup v2 mount, such as `/sys/fs/cgroup`.
    pub cgroup_root: HostPath,
    /// The jailer's `--parent-cgroup`, under the cgroup root.
    pub cgroup_parent: CgroupPath,
    /// The directory of verified artifacts, one file per content key.
    pub artifact_dir: HostPath,
    pub owner: HostOwner,
    pub jail_ids: IdRange,
}

/// Why host settings or a jail identity were refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum HostError {
    /// The jailer only executes a file whose name contains `firecracker`.
    ExecFileName {
        name: String,
    },
    /// The jailer and the file it executes are the same path.
    JailerIsExecFile,
    EmptyIdRange,
    /// The range reaches past the largest id or onto `u32::MAX`, which is no valid id.
    IdRangeOverflow,
    /// Root (0) can never be a jail identity.
    IdRangeIncludesRoot,
    /// The host owner's user or group id lies in the jail range, so a jail could act as
    /// the owner of the sinks.
    OwnerInJailRange {
        id: u32,
    },
    /// A jail identity outside the reserved range.
    UidOutsideRange {
        uid: u32,
    },
    GidOutsideRange {
        gid: u32,
    },
}

impl fmt::Display for HostError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExecFileName { name } => write!(
                f,
                "the jailer executes only a file whose name contains {EXEC_FILE_MARKER:?}, not \
                 {name:?}"
            ),
            Self::JailerIsExecFile => {
                f.write_str("the jailer and the Firecracker binary are the same file")
            }
            Self::EmptyIdRange => f.write_str("the jail id range is empty"),
            Self::IdRangeOverflow => f.write_str("the jail id range overflows"),
            Self::IdRangeIncludesRoot => f.write_str("the jail id range includes root"),
            Self::OwnerInJailRange { id } => {
                write!(f, "the host owner's id {id} lies in the jail id range")
            }
            Self::UidOutsideRange { uid } => {
                write!(f, "uid {uid} is outside the range reserved for jails")
            }
            Self::GidOutsideRange { gid } => {
                write!(f, "gid {gid} is outside the range reserved for jails")
            }
        }
    }
}

impl std::error::Error for HostError {}

impl JailHost {
    /// Checks the settings.
    pub fn validate(&self) -> Result<(), HostError> {
        let name = self.firecracker.file_name();
        if !name.contains(EXEC_FILE_MARKER) {
            return Err(HostError::ExecFileName {
                name: name.to_owned(),
            });
        }
        if self.jailer == self.firecracker {
            return Err(HostError::JailerIsExecFile);
        }
        let range = self.jail_ids;
        if range.count == 0 {
            return Err(HostError::EmptyIdRange);
        }
        match range.last() {
            Some(last) if last < u32::MAX => {}
            _ => return Err(HostError::IdRangeOverflow),
        }
        if range.contains(0) {
            return Err(HostError::IdRangeIncludesRoot);
        }
        for id in [self.owner.uid, self.owner.gid] {
            if range.contains(id) {
                return Err(HostError::OwnerInJailRange { id });
            }
        }
        Ok(())
    }

    /// Checks that a launch's jail identity lies in the reserved range, which also keeps
    /// it away from root and the host owner.
    pub fn check_identity(&self, identity: JailIdentity) -> Result<(), HostError> {
        if !self.jail_ids.contains(identity.uid) {
            return Err(HostError::UidOutsideRange { uid: identity.uid });
        }
        if !self.jail_ids.contains(identity.gid) {
            return Err(HostError::GidOutsideRange { gid: identity.gid });
        }
        Ok(())
    }

    /// The name of the Firecracker binary, which the jailer puts in the chroot path.
    pub fn exec_file_name(&self) -> &str {
        self.firecracker.file_name()
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures;
    use super::*;

    #[test]
    fn the_fixture_host_is_valid() {
        let host = fixtures::host();
        assert_eq!(host.validate(), Ok(()));
        assert_eq!(host.exec_file_name(), "firecracker");
        assert_eq!(host.check_identity(fixtures::identity()), Ok(()));
    }

    #[test]
    fn the_exec_file_must_be_named_for_firecracker() {
        let mut host = fixtures::host();
        host.firecracker = HostPath::new("/usr/bin/qemu-system-x86_64").unwrap();
        assert_eq!(
            host.validate(),
            Err(HostError::ExecFileName {
                name: "qemu-system-x86_64".to_owned()
            })
        );
        let mut same = fixtures::host();
        same.jailer = HostPath::new("/opt/vm/firecracker").unwrap();
        same.firecracker = same.jailer.clone();
        assert_eq!(same.validate(), Err(HostError::JailerIsExecFile));
    }

    #[test]
    fn the_jail_range_never_includes_root_the_owner_or_the_invalid_id() {
        let cases = [
            (
                IdRange {
                    first: 64000,
                    count: 0,
                },
                HostError::EmptyIdRange,
            ),
            (
                IdRange {
                    first: 0,
                    count: 10,
                },
                HostError::IdRangeIncludesRoot,
            ),
            (
                IdRange {
                    first: u32::MAX - 9,
                    count: 10,
                },
                HostError::IdRangeOverflow,
            ),
            (
                IdRange {
                    first: u32::MAX,
                    count: 2,
                },
                HostError::IdRangeOverflow,
            ),
            (
                IdRange {
                    first: 900,
                    count: 200,
                },
                HostError::OwnerInJailRange { id: 1000 },
            ),
        ];
        for (range, error) in cases {
            let mut host = fixtures::host();
            host.jail_ids = range;
            assert_eq!(host.validate(), Err(error));
        }
        let mut edge = fixtures::host();
        edge.jail_ids = IdRange {
            first: u32::MAX - 10,
            count: 10,
        };
        assert_eq!(edge.validate(), Ok(()));
    }

    #[test]
    fn a_jail_identity_must_lie_in_the_range() {
        let host = fixtures::host();
        let range = host.jail_ids;
        assert_eq!(
            host.check_identity(JailIdentity { uid: 0, gid: 0 }),
            Err(HostError::UidOutsideRange { uid: 0 })
        );
        assert_eq!(
            host.check_identity(JailIdentity {
                uid: host.owner.uid,
                gid: range.first
            }),
            Err(HostError::UidOutsideRange {
                uid: host.owner.uid
            })
        );
        assert_eq!(
            host.check_identity(JailIdentity {
                uid: range.first,
                gid: range.first + range.count
            }),
            Err(HostError::GidOutsideRange {
                gid: range.first + range.count
            })
        );
        assert_eq!(
            host.check_identity(JailIdentity {
                uid: range.first + range.count - 1,
                gid: range.first
            }),
            Ok(())
        );
    }

    #[test]
    fn host_settings_refuse_unknown_fields() {
        let json = serde_json::to_value(fixtures::host()).unwrap();
        assert_eq!(
            serde_json::from_value::<JailHost>(json.clone()).unwrap(),
            fixtures::host()
        );
        let mut extra = json;
        extra["no_seccomp"] = true.into();
        assert!(serde_json::from_value::<JailHost>(extra).is_err());
    }
}
