//! Validated values of a QEMU launch profile (VM-W19 row, line 2618; §3.4 line 2101:
//! minimize writable paths and management APIs): host paths the host created, the private
//! control directory, the instance name, the guest resources, the kernel arguments and the
//! vsock context id. Nothing here comes from the guest, and every value is checked before
//! it can reach an argument vector.

use std::fmt;

use serde::Serialize;

use crate::foundation::coordination::VmInstanceId;
use crate::foundation::evidence::OsKind;

/// Longest accepted host path, in bytes.
pub const MAX_HOST_PATH_BYTES: usize = 1024;
/// Longest Unix-domain socket path on a Unix host, in bytes: macOS's `sun_path` holds 104
/// bytes with the terminating NUL (Linux holds 108), so the stricter bound applies to both.
pub const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
/// Longest AF_UNIX socket path on Windows, in bytes (`sun_path` of 108 with the NUL).
pub const MAX_WINDOWS_SOCKET_PATH_BYTES: usize = 107;
/// The QMP socket's name inside the private control directory.
pub const QMP_SOCKET_NAME: &str = "qmp.sock";
/// The link socket's name inside the private control directory (virtio-serial link).
pub const LINK_SOCKET_NAME: &str = "link.sock";
/// The link bootstrap secret's file name inside the private control directory. The
/// secret reaches the guest through QEMU's fw_cfg from this file, never through the
/// arguments, which any host process can read from the process list (§3.2 line 2075).
pub const LINK_SECRET_NAME: &str = "link-secret";

/// The name of the guest's egress endpoint list in the private directory: the declared
/// endpoints (names, hosts, ports; no secret), handed to the guest through fw_cfg.
pub const EGRESS_ENDPOINTS_NAME: &str = "egress-endpoints";
pub const WORKLOAD_NAME: &str = "workload";
/// Most vCPUs a profile gives a guest (the bound today's launcher clamps to).
pub const MAX_VCPU_COUNT: u16 = 255;
/// One mebibyte, the granularity of guest memory.
pub const MIB_BYTES: u64 = 1024 * 1024;
/// Most guest memory a profile accepts: 1 TiB.
pub const MAX_GUEST_MEMORY_BYTES: u64 = 1024 * 1024 * MIB_BYTES;
/// Longest kernel command line, in bytes.
pub const MAX_KERNEL_COMMAND_LINE_BYTES: usize = 2048;
/// Longest kernel argument, in bytes.
pub const MAX_KERNEL_ARGUMENT_BYTES: usize = 256;
/// The prefix of every instance name.
pub const INSTANCE_NAME_PREFIX: &str = "yougori-";

/// How the host spells paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStyle {
    /// A drive-absolute Windows path such as `C:\dir\file`.
    Windows,
    /// An absolute Unix path such as `/dir/file`.
    Unix,
}

impl PathStyle {
    /// The path style of a host OS. WSL2 has none: a shared WSL kernel is never a sandbox
    /// host (§7.3 line 2386).
    pub const fn of(os: OsKind) -> Option<Self> {
        match os {
            OsKind::Windows => Some(Self::Windows),
            OsKind::Linux | OsKind::MacOs => Some(Self::Unix),
            OsKind::Wsl2 => None,
        }
    }

    pub const fn separator(self) -> char {
        match self {
            Self::Windows => '\\',
            Self::Unix => '/',
        }
    }

    const fn max_socket_path_bytes(self) -> usize {
        match self {
            Self::Windows => MAX_WINDOWS_SOCKET_PATH_BYTES,
            Self::Unix => MAX_UNIX_SOCKET_PATH_BYTES,
        }
    }
}

impl fmt::Display for PathStyle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Windows => "Windows",
            Self::Unix => "Unix",
        })
    }
}

/// Why a host path was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum PathError {
    Empty,
    TooLong {
        length_bytes: usize,
        max_bytes: usize,
    },
    NotAbsolute {
        style: PathStyle,
    },
    ControlCharacter,
    EmptyComponent,
    DotComponent {
        component: String,
    },
    ForbiddenCharacter {
        character: char,
    },
    ReservedName {
        component: String,
    },
    TrailingDotOrSpace {
        component: String,
    },
    SocketPathTooLong {
        length_bytes: usize,
        max_bytes: usize,
    },
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the path is empty"),
            Self::TooLong {
                length_bytes,
                max_bytes,
            } => write!(f, "the path is {length_bytes} bytes, more than {max_bytes}"),
            Self::NotAbsolute { style } => {
                write!(f, "the path is not an absolute {style} path")
            }
            Self::ControlCharacter => f.write_str("the path contains a control character"),
            Self::EmptyComponent => f.write_str("the path has an empty component"),
            Self::DotComponent { component } => {
                write!(f, "the path has a {component:?} component")
            }
            Self::ForbiddenCharacter { character } => {
                write!(f, "the path contains {character:?}")
            }
            Self::ReservedName { component } => {
                write!(
                    f,
                    "the path component {component:?} is a reserved device name"
                )
            }
            Self::TrailingDotOrSpace { component } => write!(
                f,
                "the path component {component:?} ends with a dot or space, which Windows strips"
            ),
            Self::SocketPathTooLong {
                length_bytes,
                max_bytes,
            } => write!(
                f,
                "the socket path is {length_bytes} bytes, more than the {max_bytes} a socket \
                 address holds"
            ),
        }
    }
}

impl std::error::Error for PathError {}

/// An absolute path on the host, which the host created or selected itself; never a
/// string the guest supplied (§3.4 line 2101). Windows paths are drive-absolute with
/// backslashes only, so UNC, device (`\\.\`) and alternate-stream (`:`) forms are refused,
/// as are reserved device names and components Windows would silently strip. Unix paths
/// are absolute without empty, `.` or `..` components. Commas are kept and doubled when
/// a path is written into a QEMU option.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct HostPath {
    style: PathStyle,
    text: String,
}

impl HostPath {
    /// Validates `text` as an absolute path of `style`.
    pub fn new(style: PathStyle, text: impl Into<String>) -> Result<Self, PathError> {
        let text = text.into();
        if text.is_empty() {
            return Err(PathError::Empty);
        }
        if text.len() > MAX_HOST_PATH_BYTES {
            return Err(PathError::TooLong {
                length_bytes: text.len(),
                max_bytes: MAX_HOST_PATH_BYTES,
            });
        }
        if text.chars().any(char::is_control) {
            return Err(PathError::ControlCharacter);
        }
        match style {
            PathStyle::Unix => {
                let rest = text
                    .strip_prefix('/')
                    .ok_or(PathError::NotAbsolute { style })?;
                for component in rest.split('/') {
                    check_component(component)?;
                }
            }
            PathStyle::Windows => {
                let bytes = text.as_bytes();
                if bytes.len() < 3
                    || !bytes[0].is_ascii_alphabetic()
                    || bytes[1] != b':'
                    || bytes[2] != b'\\'
                {
                    return Err(PathError::NotAbsolute { style });
                }
                for component in text[3..].split('\\') {
                    check_component(component)?;
                    check_windows_component(component)?;
                }
            }
        }
        Ok(Self { style, text })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    pub fn style(&self) -> PathStyle {
        self.style
    }

    /// This path with one more component, `name`.
    pub fn join(&self, name: &str) -> Result<Self, PathError> {
        Self::new(
            self.style,
            format!("{}{}{}", self.text, self.style.separator(), name),
        )
    }

    /// The directory holding this path and the last component's name.
    pub fn split_last(&self) -> Option<(Self, &str)> {
        let index = self.text.rfind(self.style.separator())?;
        let parent = match self.style {
            PathStyle::Unix if index == 0 => return None,
            PathStyle::Windows if index <= 2 => return None,
            _ => &self.text[..index],
        };
        let parent = Self::new(self.style, parent).ok()?;
        Some((parent, &self.text[index + 1..]))
    }
}

impl fmt::Display for HostPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

fn check_component(component: &str) -> Result<(), PathError> {
    match component {
        "" => Err(PathError::EmptyComponent),
        "." | ".." => Err(PathError::DotComponent {
            component: component.to_owned(),
        }),
        _ => Ok(()),
    }
}

fn check_windows_component(component: &str) -> Result<(), PathError> {
    if let Some(character) = component
        .chars()
        .find(|character| matches!(character, '<' | '>' | ':' | '"' | '/' | '|' | '?' | '*'))
    {
        return Err(PathError::ForbiddenCharacter { character });
    }
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(PathError::TrailingDotOrSpace {
            component: component.to_owned(),
        });
    }
    let base = component
        .split('.')
        .next()
        .unwrap_or(component)
        .trim_end()
        .to_ascii_uppercase();
    let reserved = matches!(base.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || ((base.starts_with("COM") || base.starts_with("LPT"))
            && base.len() == 4
            && base.as_bytes()[3].is_ascii_digit());
    if reserved {
        return Err(PathError::ReservedName {
            component: component.to_owned(),
        });
    }
    Ok(())
}

/// The private directory the host created for one VM: it holds the QMP socket, the link
/// socket and the link secret under fixed names, so the management endpoint is never
/// anywhere else (VM-CP-03, line 3153: QMP socket in a private directory). Creating it
/// owner-only (and, on Windows, labelled for the low-integrity VMM) is the launcher's
/// part; the socket paths are checked here against the socket address size.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct PrivateDirectory {
    path: HostPath,
    #[serde(skip_serializing)]
    qmp_socket: HostPath,
    #[serde(skip_serializing)]
    link_socket: HostPath,
    #[serde(skip_serializing)]
    link_secret: HostPath,
    #[serde(skip_serializing)]
    egress_endpoints: HostPath,
    #[serde(skip_serializing)]
    workload: HostPath,
}

impl PrivateDirectory {
    /// Takes the directory the host created and refuses one whose socket paths do not
    /// fit a socket address.
    pub fn new(path: HostPath) -> Result<Self, PathError> {
        let qmp_socket = path.join(QMP_SOCKET_NAME)?;
        let link_socket = path.join(LINK_SOCKET_NAME)?;
        let link_secret = path.join(LINK_SECRET_NAME)?;
        let egress_endpoints = path.join(EGRESS_ENDPOINTS_NAME)?;
        let workload = path.join(WORKLOAD_NAME)?;
        for socket in [&qmp_socket, &link_socket] {
            let max_bytes = socket.style().max_socket_path_bytes();
            if socket.as_str().len() > max_bytes {
                return Err(PathError::SocketPathTooLong {
                    length_bytes: socket.as_str().len(),
                    max_bytes,
                });
            }
        }
        Ok(Self {
            path,
            qmp_socket,
            link_socket,
            link_secret,
            egress_endpoints,
            workload,
        })
    }

    pub fn path(&self) -> &HostPath {
        &self.path
    }

    pub fn qmp_socket(&self) -> &HostPath {
        &self.qmp_socket
    }

    pub fn link_socket(&self) -> &HostPath {
        &self.link_socket
    }

    pub fn link_secret(&self) -> &HostPath {
        &self.link_secret
    }

    /// The guest's egress endpoint list, which QEMU hands the guest through fw_cfg.
    pub fn egress_endpoints(&self) -> &HostPath {
        &self.egress_endpoints
    }

    pub fn workload(&self) -> &HostPath {
        &self.workload
    }
}

/// Why an instance name was refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NameError {
    pub name: String,
}

impl fmt::Display for NameError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:?} is not an instance name: \"{INSTANCE_NAME_PREFIX}\" and 64 lowercase \
             hexadecimal digits",
            self.name
        )
    }
}

impl std::error::Error for NameError {}

/// The QEMU `-name` of one VM: a fixed prefix and the VM handle's digest (VM part §6.4:
/// a handle, never a PID or a user string).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct InstanceName(String);

impl InstanceName {
    /// The name of the VM with this handle.
    pub fn of(vm: VmInstanceId) -> Self {
        Self(format!("{INSTANCE_NAME_PREFIX}{}", vm.digest().to_hex()))
    }

    /// Reads a name back from an observed vector.
    pub fn parse(text: &str) -> Result<Self, NameError> {
        let valid = text.strip_prefix(INSTANCE_NAME_PREFIX).is_some_and(|hex| {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        });
        if valid {
            Ok(Self(text.to_owned()))
        } else {
            Err(NameError {
                name: text.to_owned(),
            })
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Why guest resources were refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum ResourceError {
    VcpuCount { vcpu_count: u16, max: u16 },
    MemoryNotWholeMebibytes { memory_bytes: u64 },
    MemoryOutOfRange { memory_bytes: u64, max_bytes: u64 },
}

impl fmt::Display for ResourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VcpuCount { vcpu_count, max } => {
                write!(f, "{vcpu_count} vCPUs is outside 1 to {max}")
            }
            Self::MemoryNotWholeMebibytes { memory_bytes } => {
                write!(
                    f,
                    "{memory_bytes} bytes of memory is not a whole number of MiB"
                )
            }
            Self::MemoryOutOfRange {
                memory_bytes,
                max_bytes,
            } => write!(
                f,
                "{memory_bytes} bytes of memory is outside 1 MiB to {max_bytes} bytes"
            ),
        }
    }
}

impl std::error::Error for ResourceError {}

/// The vCPUs and memory of one guest. The memory must fit the CORE-03 reservation the
/// launch runs inside (checked when the profile is built).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub struct GuestResources {
    vcpu_count: u16,
    memory_bytes: u64,
}

impl GuestResources {
    /// Validates the vCPU count and the memory size.
    pub fn new(vcpu_count: u16, memory_bytes: u64) -> Result<Self, ResourceError> {
        if vcpu_count == 0 || vcpu_count > MAX_VCPU_COUNT {
            return Err(ResourceError::VcpuCount {
                vcpu_count,
                max: MAX_VCPU_COUNT,
            });
        }
        if memory_bytes == 0 || memory_bytes > MAX_GUEST_MEMORY_BYTES {
            return Err(ResourceError::MemoryOutOfRange {
                memory_bytes,
                max_bytes: MAX_GUEST_MEMORY_BYTES,
            });
        }
        if memory_bytes % MIB_BYTES != 0 {
            return Err(ResourceError::MemoryNotWholeMebibytes { memory_bytes });
        }
        Ok(Self {
            vcpu_count,
            memory_bytes,
        })
    }

    pub fn vcpu_count(&self) -> u16 {
        self.vcpu_count
    }

    pub fn memory_bytes(&self) -> u64 {
        self.memory_bytes
    }

    pub fn memory_mib(&self) -> u64 {
        self.memory_bytes / MIB_BYTES
    }
}

/// Why kernel arguments were refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum KernelArgumentError {
    Empty,
    TooLong {
        length_bytes: usize,
        max_bytes: usize,
    },
    EmptyArgument,
    ArgumentTooLong {
        argument: String,
    },
    InvalidCharacter {
        argument: String,
        character: char,
    },
    InvalidStart {
        argument: String,
    },
    /// `rw`: the root drive is read-only.
    WritableRoot,
    /// `console=`, `earlycon` or `earlyprintk`: the profile has no console (VM-CP-02).
    Console {
        argument: String,
    },
}

impl fmt::Display for KernelArgumentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("the kernel command line is empty"),
            Self::TooLong {
                length_bytes,
                max_bytes,
            } => write!(
                f,
                "the kernel command line is {length_bytes} bytes, more than {max_bytes}"
            ),
            Self::EmptyArgument => f.write_str("the kernel command line has an empty argument"),
            Self::ArgumentTooLong { argument } => {
                write!(f, "the kernel argument {argument:?} is too long")
            }
            Self::InvalidCharacter {
                argument,
                character,
            } => write!(f, "the kernel argument {argument:?} contains {character:?}"),
            Self::InvalidStart { argument } => write!(
                f,
                "the kernel argument {argument:?} must start with a letter or digit"
            ),
            Self::WritableRoot => {
                f.write_str("the kernel argument \"rw\" contradicts the read-only root drive")
            }
            Self::Console { argument } => write!(
                f,
                "the kernel argument {argument:?} names a console, and the profile has none"
            ),
        }
    }
}

impl std::error::Error for KernelArgumentError {}

/// The guest kernel's command line, from the pinned guest image's manifest: host-verified
/// configuration, never guest input. Each argument is 1–256 ASCII letters, digits or
/// `. _ , : / = + - @`, starting with a letter or digit, so no quoting, spacing or shell
/// meaning is possible. The line is visible in the host's process list, so it never
/// carries a secret; the link secret goes through fw_cfg.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct KernelArguments(Vec<String>);

impl KernelArguments {
    /// Validates each argument and the whole line.
    pub fn new<S: Into<String>>(
        arguments: impl IntoIterator<Item = S>,
    ) -> Result<Self, KernelArgumentError> {
        let arguments: Vec<String> = arguments.into_iter().map(Into::into).collect();
        if arguments.is_empty() {
            return Err(KernelArgumentError::Empty);
        }
        for argument in &arguments {
            check_kernel_argument(argument)?;
        }
        let line = Self(arguments);
        let length_bytes = line.command_line().len();
        if length_bytes > MAX_KERNEL_COMMAND_LINE_BYTES {
            return Err(KernelArgumentError::TooLong {
                length_bytes,
                max_bytes: MAX_KERNEL_COMMAND_LINE_BYTES,
            });
        }
        Ok(line)
    }

    /// Reads a command line whose arguments are separated by single spaces.
    pub fn parse(command_line: &str) -> Result<Self, KernelArgumentError> {
        if command_line.is_empty() {
            return Err(KernelArgumentError::Empty);
        }
        Self::new(command_line.split(' '))
    }

    pub fn arguments(&self) -> &[String] {
        &self.0
    }

    pub fn command_line(&self) -> String {
        self.0.join(" ")
    }
}

fn check_kernel_argument(argument: &str) -> Result<(), KernelArgumentError> {
    let first = argument
        .chars()
        .next()
        .ok_or(KernelArgumentError::EmptyArgument)?;
    if argument.len() > MAX_KERNEL_ARGUMENT_BYTES {
        return Err(KernelArgumentError::ArgumentTooLong {
            argument: argument.to_owned(),
        });
    }
    if let Some(character) = argument.chars().find(|character| {
        !(character.is_ascii_alphanumeric()
            || matches!(
                character,
                '.' | '_' | ',' | ':' | '/' | '=' | '+' | '-' | '@'
            ))
    }) {
        return Err(KernelArgumentError::InvalidCharacter {
            argument: argument.to_owned(),
            character,
        });
    }
    if !first.is_ascii_alphanumeric() {
        return Err(KernelArgumentError::InvalidStart {
            argument: argument.to_owned(),
        });
    }
    if argument == "rw" {
        return Err(KernelArgumentError::WritableRoot);
    }
    let name = argument.split('=').next().unwrap_or(argument);
    if matches!(name, "console" | "earlycon" | "earlyprintk") {
        return Err(KernelArgumentError::Console {
            argument: argument.to_owned(),
        });
    }
    Ok(())
}

/// Why a vsock context id was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CidError {
    pub cid: u32,
}

impl fmt::Display for CidError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "vsock context id {} is reserved; guests use 3 to 4294967294",
            self.cid
        )
    }
}

impl std::error::Error for CidError {}

/// The vsock context id the host allocated to one guest. 0, 1 and 2 name the hypervisor,
/// the local loopback and the host, and `u32::MAX` means any, so none of them is a guest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct GuestCid(u32);

impl GuestCid {
    /// Refuses the reserved context ids.
    pub fn new(cid: u32) -> Result<Self, CidError> {
        if cid <= 2 || cid == u32::MAX {
            Err(CidError { cid })
        } else {
            Ok(Self(cid))
        }
    }

    pub fn get(self) -> u32 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::ids::digest;

    #[test]
    fn unix_paths_are_absolute_without_dot_or_empty_components() {
        let path = HostPath::new(PathStyle::Unix, "/var/lib/yougori/vm,1/root.img").unwrap();
        assert_eq!(path.as_str(), "/var/lib/yougori/vm,1/root.img");
        for (text, error) in [
            ("", PathError::Empty),
            (
                "relative/x",
                PathError::NotAbsolute {
                    style: PathStyle::Unix,
                },
            ),
            ("/", PathError::EmptyComponent),
            ("/a//b", PathError::EmptyComponent),
            ("/a/b/", PathError::EmptyComponent),
            (
                "/a/../etc",
                PathError::DotComponent {
                    component: "..".into(),
                },
            ),
            (
                "/a/./b",
                PathError::DotComponent {
                    component: ".".into(),
                },
            ),
            ("/a\nb", PathError::ControlCharacter),
            ("/a\0b", PathError::ControlCharacter),
        ] {
            assert_eq!(HostPath::new(PathStyle::Unix, text), Err(error), "{text:?}");
        }
        let long = format!("/{}", "a".repeat(MAX_HOST_PATH_BYTES));
        assert!(matches!(
            HostPath::new(PathStyle::Unix, long),
            Err(PathError::TooLong { .. })
        ));
    }

    #[test]
    fn windows_paths_refuse_unc_device_streams_and_aliases() {
        let path = HostPath::new(PathStyle::Windows, r"C:\Yougori\vm 1\root.img").unwrap();
        assert_eq!(path.style(), PathStyle::Windows);
        for (text, error) in [
            (
                r"\\server\share\x",
                PathError::NotAbsolute {
                    style: PathStyle::Windows,
                },
            ),
            (
                r"\\.\pipe\qmp",
                PathError::NotAbsolute {
                    style: PathStyle::Windows,
                },
            ),
            (
                r"C:relative",
                PathError::NotAbsolute {
                    style: PathStyle::Windows,
                },
            ),
            (
                "/unix/style",
                PathError::NotAbsolute {
                    style: PathStyle::Windows,
                },
            ),
            (
                r"C:\a\file.txt:stream",
                PathError::ForbiddenCharacter { character: ':' },
            ),
            (r"C:\a/b", PathError::ForbiddenCharacter { character: '/' }),
            (r"C:\a\*", PathError::ForbiddenCharacter { character: '*' }),
            (
                r"C:\a\NUL.txt",
                PathError::ReservedName {
                    component: "NUL.txt".into(),
                },
            ),
            (
                r"C:\a\com1",
                PathError::ReservedName {
                    component: "com1".into(),
                },
            ),
            (
                r"C:\a\b.",
                PathError::TrailingDotOrSpace {
                    component: "b.".into(),
                },
            ),
            (
                r"C:\a\b ",
                PathError::TrailingDotOrSpace {
                    component: "b ".into(),
                },
            ),
            (
                r"C:\a\..\b",
                PathError::DotComponent {
                    component: "..".into(),
                },
            ),
            (r"C:\", PathError::EmptyComponent),
        ] {
            assert_eq!(
                HostPath::new(PathStyle::Windows, text),
                Err(error),
                "{text:?}"
            );
        }
        assert!(HostPath::new(PathStyle::Windows, r"C:\a\COM10").is_ok());
        assert!(HostPath::new(PathStyle::Windows, r"C:\a\console").is_ok());
    }

    #[test]
    fn paths_join_and_split() {
        let directory = HostPath::new(PathStyle::Windows, r"C:\vm").unwrap();
        let file = directory.join("qmp.sock").unwrap();
        assert_eq!(file.as_str(), r"C:\vm\qmp.sock");
        assert_eq!(file.split_last(), Some((directory.clone(), "qmp.sock")));
        assert_eq!(directory.split_last(), None);
        assert!(directory.join("..").is_err());
        assert!(directory.join(r"a\b").is_ok());
        let unix = HostPath::new(PathStyle::Unix, "/run/vm").unwrap();
        assert_eq!(
            unix.join("link.sock").unwrap().split_last(),
            Some((unix.clone(), "link.sock"))
        );
        assert_eq!(
            HostPath::new(PathStyle::Unix, "/run").unwrap().split_last(),
            None
        );
    }

    #[test]
    fn socket_paths_must_fit_a_socket_address() {
        let fits = format!("/{}", "d".repeat(MAX_UNIX_SOCKET_PATH_BYTES - 1 - 10));
        let directory =
            PrivateDirectory::new(HostPath::new(PathStyle::Unix, fits).unwrap()).unwrap();
        assert_eq!(
            directory.link_socket().as_str().len(),
            MAX_UNIX_SOCKET_PATH_BYTES
        );
        assert!(directory.qmp_socket().as_str().ends_with("/qmp.sock"));
        let too_long = format!("/{}", "d".repeat(MAX_UNIX_SOCKET_PATH_BYTES - 10));
        assert_eq!(
            PrivateDirectory::new(HostPath::new(PathStyle::Unix, too_long).unwrap()),
            Err(PathError::SocketPathTooLong {
                length_bytes: MAX_UNIX_SOCKET_PATH_BYTES + 1,
                max_bytes: MAX_UNIX_SOCKET_PATH_BYTES,
            })
        );
        let windows = format!(r"C:\{}", "d".repeat(MAX_WINDOWS_SOCKET_PATH_BYTES - 3 - 10));
        assert!(PrivateDirectory::new(HostPath::new(PathStyle::Windows, windows).unwrap()).is_ok());
        let windows = format!(r"C:\{}", "d".repeat(MAX_WINDOWS_SOCKET_PATH_BYTES - 3 - 9));
        assert!(matches!(
            PrivateDirectory::new(HostPath::new(PathStyle::Windows, windows).unwrap()),
            Err(PathError::SocketPathTooLong { .. })
        ));
    }

    #[test]
    fn instance_names_come_from_handles() {
        let vm = VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm"]));
        let name = InstanceName::of(vm);
        assert_eq!(name.as_str().len(), INSTANCE_NAME_PREFIX.len() + 64);
        assert_eq!(InstanceName::parse(name.as_str()), Ok(name.clone()));
        for bad in [
            "yougori-",
            "other-0000000000000000000000000000000000000000000000000000000000000000",
            "yougori-000000000000000000000000000000000000000000000000000000000000000G",
            "yougori-00000000000000000000000000000000000000000000000000000000000000AA",
            "yougori-00",
        ] {
            assert!(InstanceName::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn guest_resources_are_bounded_and_whole_mebibytes() {
        let resources = GuestResources::new(2, 512 * MIB_BYTES).unwrap();
        assert_eq!(resources.memory_mib(), 512);
        assert_eq!(resources.vcpu_count(), 2);
        assert!(GuestResources::new(MAX_VCPU_COUNT, MIB_BYTES).is_ok());
        assert!(GuestResources::new(1, MAX_GUEST_MEMORY_BYTES).is_ok());
        assert_eq!(
            GuestResources::new(0, MIB_BYTES),
            Err(ResourceError::VcpuCount {
                vcpu_count: 0,
                max: MAX_VCPU_COUNT
            })
        );
        assert!(GuestResources::new(MAX_VCPU_COUNT + 1, MIB_BYTES).is_err());
        assert!(matches!(
            GuestResources::new(1, 0),
            Err(ResourceError::MemoryOutOfRange { .. })
        ));
        assert!(matches!(
            GuestResources::new(1, MAX_GUEST_MEMORY_BYTES + MIB_BYTES),
            Err(ResourceError::MemoryOutOfRange { .. })
        ));
        assert_eq!(
            GuestResources::new(1, MIB_BYTES + 1),
            Err(ResourceError::MemoryNotWholeMebibytes {
                memory_bytes: MIB_BYTES + 1
            })
        );
    }

    #[test]
    fn kernel_arguments_cannot_quote_open_a_console_or_write_the_root() {
        let line = KernelArguments::parse("root=/dev/vda ro quiet panic=-1").unwrap();
        assert_eq!(line.arguments().len(), 4);
        assert_eq!(line.command_line(), "root=/dev/vda ro quiet panic=-1");
        assert_eq!(KernelArguments::parse(""), Err(KernelArgumentError::Empty));
        assert_eq!(
            KernelArguments::new(Vec::<String>::new()),
            Err(KernelArgumentError::Empty)
        );
        assert_eq!(
            KernelArguments::parse("ro  quiet"),
            Err(KernelArgumentError::EmptyArgument)
        );
        assert_eq!(
            KernelArguments::parse("root=/dev/vda rw"),
            Err(KernelArgumentError::WritableRoot)
        );
        for console in ["console=ttyS0", "earlycon", "earlyprintk=serial"] {
            assert!(matches!(
                KernelArguments::parse(console),
                Err(KernelArgumentError::Console { .. })
            ));
        }
        assert!(matches!(
            KernelArguments::parse("a=\"b c\""),
            Err(KernelArgumentError::InvalidCharacter { character: '"', .. })
        ));
        assert!(matches!(
            KernelArguments::parse("x=$(id)"),
            Err(KernelArgumentError::InvalidCharacter { character: '$', .. })
        ));
        assert!(matches!(
            KernelArguments::parse("-x"),
            Err(KernelArgumentError::InvalidStart { .. })
        ));
        assert!(matches!(
            KernelArguments::new(["a".repeat(MAX_KERNEL_ARGUMENT_BYTES + 1)]),
            Err(KernelArgumentError::ArgumentTooLong { .. })
        ));
        let many = vec!["a".repeat(200); 11];
        assert!(matches!(
            KernelArguments::new(many),
            Err(KernelArgumentError::TooLong { .. })
        ));
    }

    #[test]
    fn guest_context_ids_exclude_reserved_values() {
        for reserved in [0, 1, 2, u32::MAX] {
            assert_eq!(GuestCid::new(reserved), Err(CidError { cid: reserved }));
        }
        assert_eq!(GuestCid::new(3).unwrap().get(), 3);
        assert!(GuestCid::new(u32::MAX - 1).is_ok());
    }

    #[test]
    fn wsl_has_no_path_style() {
        assert_eq!(PathStyle::of(OsKind::Wsl2), None);
        assert_eq!(PathStyle::of(OsKind::Windows), Some(PathStyle::Windows));
        assert_eq!(PathStyle::of(OsKind::MacOs), Some(PathStyle::Unix));
    }
}
