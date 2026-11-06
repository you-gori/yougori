//! Typed names and paths of a Firecracker launch: host paths, paths inside the jail,
//! cgroup paths, network interface names, Firecracker API identifiers, guest MAC
//! addresses, the jail id and the jail identity (§3.4 line 2101: minimize writable paths,
//! devices and management APIs; VM-P49 line 2824: a malicious path cannot cause unrelated
//! deletion).
//!
//! Every path is absolute or relative by type, made of components that start with a
//! letter or digit and use only letters, digits, '.', '_' and '-', so no path can hold
//! `..`, an empty component, a shell metacharacter or a component that reads as an
//! option in an argument vector.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::foundation::coordination::SandboxGenerations;
use crate::foundation::ids::{Digest, DigestBuilder, ExecutionId, TenantId};

/// Longest accepted path, in bytes.
pub const MAX_PATH_BYTES: usize = 1024;
/// Longest accepted path component, in bytes.
pub const MAX_COMPONENT_BYTES: usize = 128;
/// Longest Linux network interface name, in bytes (IFNAMSIZ less the terminator).
pub const MAX_INTERFACE_NAME_BYTES: usize = 15;
/// Longest Firecracker API identifier accepted here, in bytes.
pub const MAX_API_ID_BYTES: usize = 64;
/// Longest jail id the official jailer accepts, in bytes.
pub const MAX_JAIL_ID_BYTES: usize = 64;
/// Digest domain of [`JailId::derive`].
pub const JAIL_ID_DOMAIN: &str = "yougori/sandbox/firecracker/jail-id/v1";

/// What kind of name a [`NameError`] is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum NameKind {
    HostPath,
    JailPath,
    CgroupPath,
    PathComponent,
    InterfaceName,
    ApiId,
    JailId,
    MacAddress,
}

impl fmt::Display for NameKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::HostPath => "host path",
            Self::JailPath => "path inside the jail",
            Self::CgroupPath => "cgroup path",
            Self::PathComponent => "path component",
            Self::InterfaceName => "network interface name",
            Self::ApiId => "Firecracker API identifier",
            Self::JailId => "jail id",
            Self::MacAddress => "MAC address",
        })
    }
}

/// Why a name or path was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum NameError {
    Empty {
        kind: NameKind,
    },
    TooLong {
        kind: NameKind,
        max_bytes: usize,
    },
    NotAbsolute {
        kind: NameKind,
    },
    NotRelative {
        kind: NameKind,
    },
    /// An empty component, such as a doubled or trailing '/'.
    EmptyComponent {
        kind: NameKind,
    },
    InvalidCharacter {
        kind: NameKind,
        character: char,
    },
    /// The name or a component starts with something other than what its grammar
    /// allows, which also excludes `.`, `..` and leading '-'.
    InvalidStart {
        kind: NameKind,
    },
    /// The name is reserved, such as `lo` for a tap device.
    Reserved {
        kind: NameKind,
    },
    /// A guest MAC address must be six lowercase hexadecimal octets separated by ':'.
    MacFormat,
    /// A guest MAC address must be a locally administered unicast address.
    MacNotLocalUnicast,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty { kind } => write!(f, "the {kind} is empty"),
            Self::TooLong { kind, max_bytes } => {
                write!(f, "the {kind} is longer than {max_bytes} bytes")
            }
            Self::NotAbsolute { kind } => write!(f, "the {kind} must start with '/'"),
            Self::NotRelative { kind } => write!(f, "the {kind} must not start with '/'"),
            Self::EmptyComponent { kind } => write!(f, "the {kind} has an empty component"),
            Self::InvalidCharacter { kind, character } => {
                write!(f, "the {kind} contains {character:?}")
            }
            Self::InvalidStart { kind } => {
                write!(
                    f,
                    "the {kind} or one of its components starts with a disallowed character"
                )
            }
            Self::Reserved { kind } => write!(f, "the {kind} is reserved"),
            Self::MacFormat => {
                f.write_str("a MAC address is six lowercase hexadecimal octets separated by ':'")
            }
            Self::MacNotLocalUnicast => {
                f.write_str("a guest MAC address must be locally administered and unicast")
            }
        }
    }
}

impl std::error::Error for NameError {}

fn check_length(kind: NameKind, value: &str, max_bytes: usize) -> Result<(), NameError> {
    if value.is_empty() {
        return Err(NameError::Empty { kind });
    }
    if value.len() > max_bytes {
        return Err(NameError::TooLong { kind, max_bytes });
    }
    Ok(())
}

/// One path component: 1–128 letters, digits, '.', '_' or '-', starting with a letter or
/// digit.
fn check_component(kind: NameKind, component: &str) -> Result<(), NameError> {
    let first = component
        .chars()
        .next()
        .ok_or(NameError::EmptyComponent { kind })?;
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(NameError::TooLong {
            kind: NameKind::PathComponent,
            max_bytes: MAX_COMPONENT_BYTES,
        });
    }
    if let Some(character) = component.chars().find(|character| {
        !(character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-'))
    }) {
        return Err(NameError::InvalidCharacter { kind, character });
    }
    if !first.is_ascii_alphanumeric() {
        return Err(NameError::InvalidStart { kind });
    }
    Ok(())
}

fn check_absolute(kind: NameKind, value: &str) -> Result<(), NameError> {
    check_length(kind, value, MAX_PATH_BYTES)?;
    let rest = value
        .strip_prefix('/')
        .ok_or(NameError::NotAbsolute { kind })?;
    rest.split('/')
        .try_for_each(|component| check_component(kind, component))
}

fn check_relative(kind: NameKind, value: &str) -> Result<(), NameError> {
    check_length(kind, value, MAX_PATH_BYTES)?;
    if value.starts_with('/') {
        return Err(NameError::NotRelative { kind });
    }
    value
        .split('/')
        .try_for_each(|component| check_component(kind, component))
}

macro_rules! text_name {
    ($(#[$doc:meta])* $name:ident, $check:expr) => {
        $(#[$doc])*
        #[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Accepts the value only if it follows this name's grammar.
            pub fn new(value: impl Into<String>) -> Result<Self, NameError> {
                let value = value.into();
                let check: fn(&str) -> Result<(), NameError> = $check;
                check(&value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "{}({})", stringify!($name), self.0)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
            }
        }
    };
}

text_name!(
    /// An absolute path on the host, such as the jailer binary or the chroot base.
    HostPath,
    |value| check_absolute(NameKind::HostPath, value)
);

text_name!(
    /// An absolute path inside the jail's root, as Firecracker sees it after the jailer's
    /// chroot. Only the plan's fixed layout uses these.
    JailPath,
    |value| check_absolute(NameKind::JailPath, value)
);

text_name!(
    /// A cgroup path relative to the cgroup v2 root, such as the jailer's parent cgroup.
    CgroupPath,
    |value| check_relative(NameKind::CgroupPath, value)
);

text_name!(
    /// A Linux network interface name: 1–15 lowercase letters, digits, '_' or '-',
    /// starting with a letter.
    InterfaceName,
    check_interface_name
);

text_name!(
    /// A Firecracker API identifier for a drive or network interface: 1–64 lowercase
    /// letters, digits or '_', starting with a letter.
    ApiId,
    check_api_id
);

text_name!(
    /// The jail id the official jailer takes with `--id`: 1–64 letters, digits or '-',
    /// starting with a letter or digit. A plan derives it from the launch with
    /// [`JailId::derive`].
    JailId,
    check_jail_id
);

fn check_interface_name(value: &str) -> Result<(), NameError> {
    let kind = NameKind::InterfaceName;
    check_length(kind, value, MAX_INTERFACE_NAME_BYTES)?;
    if let Some(character) = value.chars().find(|character| {
        !(character.is_ascii_lowercase()
            || character.is_ascii_digit()
            || matches!(character, '_' | '-'))
    }) {
        return Err(NameError::InvalidCharacter { kind, character });
    }
    if !value.starts_with(|character: char| character.is_ascii_lowercase()) {
        return Err(NameError::InvalidStart { kind });
    }
    Ok(())
}

fn check_api_id(value: &str) -> Result<(), NameError> {
    let kind = NameKind::ApiId;
    check_length(kind, value, MAX_API_ID_BYTES)?;
    if let Some(character) = value.chars().find(|character| {
        !(character.is_ascii_lowercase() || character.is_ascii_digit() || *character == '_')
    }) {
        return Err(NameError::InvalidCharacter { kind, character });
    }
    if !value.starts_with(|character: char| character.is_ascii_lowercase()) {
        return Err(NameError::InvalidStart { kind });
    }
    Ok(())
}

fn check_jail_id(value: &str) -> Result<(), NameError> {
    let kind = NameKind::JailId;
    check_length(kind, value, MAX_JAIL_ID_BYTES)?;
    if let Some(character) = value
        .chars()
        .find(|character| !(character.is_ascii_alphanumeric() || *character == '-'))
    {
        return Err(NameError::InvalidCharacter { kind, character });
    }
    if !value.starts_with(|character: char| character.is_ascii_alphanumeric()) {
        return Err(NameError::InvalidStart { kind });
    }
    Ok(())
}

impl HostPath {
    /// This path with one more component.
    pub fn join(&self, component: &str) -> Result<Self, NameError> {
        check_component(NameKind::HostPath, component)?;
        Self::new(format!("{}/{}", self.0, component))
    }

    /// Where `path` inside a jail whose root is this path lies on the host.
    pub fn within(&self, path: &JailPath) -> Result<Self, NameError> {
        Self::new(format!("{}{}", self.0, path.0))
    }

    /// This path followed by the components of `path`.
    pub fn join_relative(&self, path: &CgroupPath) -> Result<Self, NameError> {
        Self::new(format!("{}/{}", self.0, path.0))
    }

    /// The last component.
    pub fn file_name(&self) -> &str {
        self.0.rsplit('/').next().unwrap_or_default()
    }
}

impl JailPath {
    /// A path of the plan's fixed layout; a test checks each one against [`Self::new`].
    pub(super) fn fixed(path: &'static str) -> Self {
        Self(path.to_owned())
    }

    /// The directory that holds this path; `None` for a path directly under the root.
    pub fn parent(&self) -> Option<Self> {
        match self.0.rsplit_once('/') {
            Some((parent, _)) if !parent.is_empty() => Some(Self(parent.to_owned())),
            _ => None,
        }
    }
}

impl CgroupPath {
    /// This path with one more component.
    pub fn join(&self, component: &str) -> Result<Self, NameError> {
        check_component(NameKind::CgroupPath, component)?;
        Self::new(format!("{}/{}", self.0, component))
    }
}

impl InterfaceName {
    /// The loopback interface every network namespace has.
    pub fn loopback() -> Self {
        Self("lo".to_owned())
    }

    pub fn is_loopback(&self) -> bool {
        self.0 == "lo"
    }
}

impl JailId {
    /// The jail id of one boot of one sandbox: `vm-` and 32 hexadecimal digits of a digest
    /// over the execution, tenant, machine and boot generation. Every boot gets a new
    /// generation (S3.1), so a relaunch or a restore never reuses an earlier boot's jail
    /// directory, cgroup, network namespace or sockets (§6.6 lines 2340–2347; VM-P21 line
    /// 2621).
    pub fn derive(
        execution: &ExecutionId,
        tenant: &TenantId,
        machine: &Digest,
        generations: &SandboxGenerations,
    ) -> Self {
        let hex = DigestBuilder::new(JAIL_ID_DOMAIN)
            .str(execution.as_str())
            .str(tenant.as_str())
            .digest(machine)
            .u64(generations.boot.get())
            .finish()
            .to_hex();
        Self(format!("vm-{}", hex.chars().take(32).collect::<String>()))
    }
}

/// A guest MAC address: locally administered and unicast, so it never collides with a
/// vendor-assigned address or names a multicast group.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MacAddress([u8; 6]);

impl MacAddress {
    /// Parses six lowercase hexadecimal octets separated by ':'.
    pub fn parse(text: &str) -> Result<Self, NameError> {
        let mut octets = [0u8; 6];
        let mut parts = text.split(':');
        for octet in &mut octets {
            let part = parts.next().ok_or(NameError::MacFormat)?;
            let lowercase_hex = part.len() == 2
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
            if !lowercase_hex {
                return Err(NameError::MacFormat);
            }
            *octet = u8::from_str_radix(part, 16).map_err(|_| NameError::MacFormat)?;
        }
        if parts.next().is_some() {
            return Err(NameError::MacFormat);
        }
        if octets[0] & 0x02 == 0 || octets[0] & 0x01 != 0 {
            return Err(NameError::MacNotLocalUnicast);
        }
        Ok(Self(octets))
    }

    pub const fn octets(self) -> [u8; 6] {
        self.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
    }
}

impl fmt::Debug for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MacAddress({self})")
    }
}

impl Serialize for MacAddress {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MacAddress {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Self::parse(&String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// The unprivileged user and group the jailer drops to before it executes Firecracker
/// (§7.2 line 2370; VM-CP-04 line 3154: "the launcher's unprivileged uid").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailIdentity {
    pub uid: u32,
    pub gid: u32,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    #[test]
    fn host_paths_are_absolute_and_made_of_plain_components() {
        for good in ["/srv/jailer", "/usr/lib/yougori/firecracker-v1.10", "/a"] {
            assert_eq!(HostPath::new(good).unwrap().as_str(), good);
        }
        let refused = [
            (
                "",
                NameError::Empty {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "srv/jailer",
                NameError::NotAbsolute {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/",
                NameError::EmptyComponent {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/srv//jailer",
                NameError::EmptyComponent {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/srv/jailer/",
                NameError::EmptyComponent {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/srv/../etc",
                NameError::InvalidStart {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/srv/./x",
                NameError::InvalidStart {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/srv/-rf",
                NameError::InvalidStart {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/srv/.hidden",
                NameError::InvalidStart {
                    kind: NameKind::HostPath,
                },
            ),
            (
                "/srv/a b",
                NameError::InvalidCharacter {
                    kind: NameKind::HostPath,
                    character: ' ',
                },
            ),
            (
                "/srv/$(id)",
                NameError::InvalidCharacter {
                    kind: NameKind::HostPath,
                    character: '$',
                },
            ),
            (
                "/srv/x;y",
                NameError::InvalidCharacter {
                    kind: NameKind::HostPath,
                    character: ';',
                },
            ),
        ];
        for (text, error) in refused {
            assert_eq!(HostPath::new(text), Err(error), "{text:?}");
        }
        let long_component = format!("/{}", "a".repeat(MAX_COMPONENT_BYTES + 1));
        assert!(matches!(
            HostPath::new(long_component),
            Err(NameError::TooLong { .. })
        ));
        let long_path = "/a".repeat(MAX_PATH_BYTES / 2 + 1);
        assert!(matches!(
            HostPath::new(long_path),
            Err(NameError::TooLong { .. })
        ));
        assert!(serde_json::from_str::<HostPath>("\"/srv/../etc\"").is_err());
        assert_eq!(
            serde_json::from_str::<HostPath>("\"/srv/jailer\"").unwrap(),
            HostPath::new("/srv/jailer").unwrap()
        );
    }

    #[test]
    fn host_paths_join_only_plain_components() {
        let base = HostPath::new("/srv/jailer").unwrap();
        assert_eq!(
            base.join("firecracker").unwrap().as_str(),
            "/srv/jailer/firecracker"
        );
        assert!(base.join("..").is_err());
        assert!(base.join("a/b").is_err());
        assert!(base.join("").is_err());
        let jail = JailPath::new("/run/link.sock").unwrap();
        assert_eq!(
            base.within(&jail).unwrap().as_str(),
            "/srv/jailer/run/link.sock"
        );
        let cgroup = CgroupPath::new("yougori/vm").unwrap();
        assert_eq!(
            HostPath::new("/sys/fs/cgroup")
                .unwrap()
                .join_relative(&cgroup)
                .unwrap()
                .as_str(),
            "/sys/fs/cgroup/yougori/vm"
        );
        assert_eq!(base.file_name(), "jailer");
    }

    #[test]
    fn jail_paths_know_their_parent() {
        assert_eq!(
            JailPath::new("/run/link.sock").unwrap().parent(),
            Some(JailPath::new("/run").unwrap())
        );
        assert_eq!(JailPath::new("/run").unwrap().parent(), None);
        assert!(JailPath::new("run").is_err());
    }

    #[test]
    fn cgroup_paths_are_relative() {
        assert_eq!(
            CgroupPath::new("/yougori"),
            Err(NameError::NotRelative {
                kind: NameKind::CgroupPath
            })
        );
        let parent = CgroupPath::new("yougori/firecracker").unwrap();
        assert_eq!(
            parent.join("vm-1").unwrap().as_str(),
            "yougori/firecracker/vm-1"
        );
        assert!(parent.join("..").is_err());
        assert!(CgroupPath::new("a//b").is_err());
    }

    #[test]
    fn interface_names_and_api_ids_follow_their_grammars() {
        assert!(InterfaceName::new("tap0").is_ok());
        assert!(InterfaceName::new("fc-tap_1").is_ok());
        assert!(matches!(
            InterfaceName::new("tap-name-too-long"),
            Err(NameError::TooLong { max_bytes: 15, .. })
        ));
        assert!(InterfaceName::new("Tap0").is_err());
        assert!(InterfaceName::new("0tap").is_err());
        assert!(InterfaceName::new("tap/0").is_err());
        assert!(InterfaceName::new("tap 0").is_err());
        assert!(InterfaceName::loopback().is_loopback());
        assert!(!InterfaceName::new("tap0").unwrap().is_loopback());

        assert!(ApiId::new("rootfs").is_ok());
        assert!(ApiId::new("eth_0").is_ok());
        assert!(ApiId::new("eth-0").is_err());
        assert!(ApiId::new("_eth").is_err());
        assert!(ApiId::new("x".repeat(65)).is_err());
    }

    #[test]
    fn jail_ids_follow_the_jailer_rule_and_change_with_every_boot() {
        assert!(JailId::new("vm-0123abc").is_ok());
        assert!(JailId::new("vm_1").is_err());
        assert!(JailId::new("-vm").is_err());
        assert!(JailId::new("a".repeat(65)).is_err());

        let execution = ExecutionId::new("exe-1").unwrap();
        let tenant = TenantId::new("tenant-1").unwrap();
        let machine = digest("yougori/test/machine/v1", &[b"m"]);
        let first = JailId::derive(&execution, &tenant, &machine, &SandboxGenerations::FIRST);
        assert_eq!(first.as_str().len(), 35);
        assert!(first.as_str().starts_with("vm-"));
        assert_eq!(JailId::new(first.as_str()), Ok(first.clone()));
        assert_eq!(
            JailId::derive(&execution, &tenant, &machine, &SandboxGenerations::FIRST),
            first
        );
        let mut second_boot = SandboxGenerations::FIRST;
        second_boot.boot = second_boot.boot.next().unwrap();
        assert_ne!(
            JailId::derive(&execution, &tenant, &machine, &second_boot),
            first
        );
        let other = ExecutionId::new("exe-2").unwrap();
        assert_ne!(
            JailId::derive(&other, &tenant, &machine, &SandboxGenerations::FIRST),
            first
        );
    }

    #[test]
    fn guest_macs_are_locally_administered_unicast() {
        let mac = MacAddress::parse("02:fc:00:00:00:01").unwrap();
        assert_eq!(mac.to_string(), "02:fc:00:00:00:01");
        assert_eq!(mac.octets()[1], 0xfc);
        assert_eq!(
            serde_json::to_value(mac).unwrap(),
            serde_json::Value::from("02:fc:00:00:00:01")
        );
        assert_eq!(
            serde_json::from_str::<MacAddress>("\"02:fc:00:00:00:01\"").unwrap(),
            mac
        );
        for bad in [
            "02:FC:00:00:00:01",
            "02:fc:00:00:00",
            "02:fc:00:00:00:01:02",
            "02-fc-00-00-00-01",
            "2:fc:00:00:00:01",
            "02:fc:00:00:00:0g",
        ] {
            assert_eq!(MacAddress::parse(bad), Err(NameError::MacFormat), "{bad}");
        }
        assert_eq!(
            MacAddress::parse("00:1a:2b:3c:4d:5e"),
            Err(NameError::MacNotLocalUnicast)
        );
        assert_eq!(
            MacAddress::parse("03:00:00:00:00:01"),
            Err(NameError::MacNotLocalUnicast)
        );
    }

    #[test]
    fn a_jail_identity_refuses_unknown_fields() {
        let identity: JailIdentity =
            serde_json::from_str(r#"{"uid": 64001, "gid": 64001}"#).unwrap();
        assert_eq!(identity.uid, 64001);
        assert!(serde_json::from_str::<JailIdentity>(
            r#"{"uid": 64001, "gid": 64001, "groups": [0]}"#
        )
        .is_err());
    }
}
