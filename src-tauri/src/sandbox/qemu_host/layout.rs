//! The QEMU backend's [`LaunchLayout`] over a configured runtime directory (M02;
//! docs/combined-gpu-memory-and-vm-sandbox-plan.md: VM-W16 row, line 2615; VM-W19 row,
//! line 2618: "Exact machine/device build boots under intended token/Job rules"; §7.3
//! lines 2378–2386).
//!
//! [`RuntimeLayout`] looks up, without creating anything, the host inputs of a launch:
//!
//! - in the runtime directory, the hardened build's executable
//!   `qemu-secure\qemu-system-<arch>.exe` (its directory holds the DLLs it loads) and the
//!   firmware directory `qemu\share` QEMU reads through `-L`;
//! - for the pinned guest image, by its catalog identity, the configured kernel, optional
//!   initrd, root image and kernel arguments (the image store verified them; this layout
//!   does not hash them);
//! - a host path for each data volume the request declares, the guest resources, and the
//!   path of the VM's private directory under a configured base (the host process port
//!   creates it at start).
//!
//! Every path is checked to exist as the expected kind, a regular file or a directory,
//! that is not a symbolic link, junction or any other reparse point (read without
//! following it). Each component under the runtime directory is checked, the runtime
//! directory and the private directories' base included; the directories above them are
//! not.
//!
//! On Windows the restricted QEMU passes a second access check against its restricting
//! SIDs alone (`RESTRICTED`, `Users`, the logon session's SID). So each path QEMU opens
//! must grant the access through one of them: read and execute on the executable and its
//! DLL directory, read on the firmware directory and the kernel, initrd and root image.
//! The check reads each path's DACL (`GetNamedSecurityInfoW`) and walks its ACEs with
//! `acl.rs`'s [`restricted_access`]: in order, over the set of restricting SIDs, deny ACEs
//! honoured where they come, inherited ACEs as they stand in the object's DACL and
//! inherit-only ACEs skipped. A path that does not grant it is refused with
//! [`LayoutError::AccessMissing`], naming the path, the access and the rights missing and
//! denied. Data volumes are checked for their kind only: their write access is the
//! launcher's labelling, not this lookup's. The files inside the two directories (the
//! DLLs, the firmware blobs) are not checked one by one.
//!
//! On Linux and other Unix hosts the executable has no extension, and the access check is
//! the mode bits for others: the hypervisor runs as an account of its own, neither the
//! owner nor in the group of the runtime's files, so read must be granted to others, and
//! execute on the executable and on every directory checked (a directory is read through);
//! a link is refused as on Windows.
//!
//! Every check is of the moment it runs; the host process port opens the paths later.
//! On other platforms the checks are [`LayoutError::Unsupported`].

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::Serialize;

#[cfg(not(unix))]
use super::acl::{restricted_access, right_names};
use super::acl::{LogonSid, PathAccess, Trustees};
use crate::foundation::coordination::VmInstanceId;
use crate::foundation::ids::Digest;
use crate::sandbox::backend::{Architecture, LaunchRequest};
use crate::sandbox::qemu::{
    GuestResources, HostInputs, HostPath, KernelArguments, LaunchLayout, LayoutRefusal, PathError,
    PrivateDirectory, QemuLaunchInputs, QemuPlatform, RestrictingSid,
};

/// The hardened build's directory in the runtime directory.
pub const QEMU_SECURE_DIRECTORY: &str = "qemu-secure";
/// The QEMU data directory in the runtime directory.
pub const QEMU_DATA_DIRECTORY: &str = "qemu";
/// The firmware directory in the data directory, passed to QEMU with `-L`.
pub const FIRMWARE_DIRECTORY: &str = "share";
/// How many hex digits of the VM handle name its private directory.
pub const CONTROL_NAME_HEX_DIGITS: usize = 16;

/// The QEMU executable's file name for a guest architecture, which is the host's.
#[cfg(windows)]
pub const fn executable_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "qemu-system-x86_64.exe",
        Architecture::Aarch64 => "qemu-system-aarch64.exe",
    }
}

/// The QEMU executable's file name for a guest architecture, which is the host's.
#[cfg(not(windows))]
pub const fn executable_name(architecture: Architecture) -> &'static str {
    match architecture {
        Architecture::X86_64 => "qemu-system-x86_64",
        Architecture::Aarch64 => "qemu-system-aarch64",
    }
}

/// Which path of the layout a check or refusal is about.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(tag = "path", rename_all = "snake_case")]
pub enum LayoutPath {
    RuntimeDirectory,
    ExecutableDirectory,
    Executable,
    DataDirectory,
    FirmwareDirectory,
    Kernel,
    Initrd,
    RootImage,
    Volume { index: usize },
    ControlBase,
}

impl fmt::Display for LayoutPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RuntimeDirectory => f.write_str("runtime directory"),
            Self::ExecutableDirectory => f.write_str("QEMU executable's directory"),
            Self::Executable => f.write_str("QEMU executable"),
            Self::DataDirectory => f.write_str("QEMU data directory"),
            Self::FirmwareDirectory => f.write_str("firmware directory"),
            Self::Kernel => f.write_str("kernel"),
            Self::Initrd => f.write_str("initrd"),
            Self::RootImage => f.write_str("root image"),
            Self::Volume { index } => write!(f, "data volume {index}"),
            Self::ControlBase => f.write_str("base of the private directories"),
        }
    }
}

/// The kind a path must be.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathKind {
    Directory,
    File,
}

/// Why the layout refused.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "problem", rename_all = "snake_case")]
pub enum LayoutError {
    /// The checks run on Windows only.
    Unsupported,
    /// A layout path could not be formed.
    Path {
        role: LayoutPath,
        error: PathError,
    },
    Missing {
        role: LayoutPath,
        path: HostPath,
    },
    WrongKind {
        role: LayoutPath,
        path: HostPath,
        expected: PathKind,
    },
    /// The path is a symbolic link, junction or other reparse point.
    Redirected {
        role: LayoutPath,
        path: HostPath,
    },
    /// The path's metadata could not be read.
    Unreadable {
        role: LayoutPath,
        path: HostPath,
        detail: String,
    },
    /// The path's DACL could not be read (a Win32 error code).
    SecurityUnreadable {
        role: LayoutPath,
        path: HostPath,
        code: u32,
    },
    /// The path's DACL could not be evaluated.
    Acl {
        role: LayoutPath,
        path: HostPath,
        error: super::acl::AclError,
    },
    /// The path does not grant the restricted QEMU the access through any restricting
    /// SID: the rights not granted, and those a deny ACE denied.
    AccessMissing {
        role: LayoutPath,
        path: HostPath,
        access: PathAccess,
        missing: Vec<&'static str>,
        denied: Vec<&'static str>,
    },
    /// The private directory's socket paths would not fit a socket address.
    ControlDirectory {
        error: PathError,
    },
}

impl fmt::Display for LayoutError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unsupported => f.write_str("the launch layout's checks run on Windows only"),
            Self::Path { role, error } => write!(f, "the {role}'s path: {error}"),
            Self::Missing { role, path } => write!(f, "the {role} {path} does not exist"),
            Self::WrongKind {
                role,
                path,
                expected,
            } => write!(
                f,
                "the {role} {path} is not a {}",
                match expected {
                    PathKind::Directory => "directory",
                    PathKind::File => "regular file",
                }
            ),
            Self::Redirected { role, path } => write!(
                f,
                "the {role} {path} is a link or reparse point, which is never followed"
            ),
            Self::Unreadable { role, path, detail } => {
                write!(f, "the {role} {path} could not be inspected: {detail}")
            }
            Self::SecurityUnreadable { role, path, code } => write!(
                f,
                "the {role} {path}'s DACL could not be read: Windows error {code}"
            ),
            Self::Acl { role, path, error } => write!(f, "the {role} {path}: {error}"),
            Self::AccessMissing {
                role,
                path,
                access,
                missing,
                denied,
            } => {
                write!(
                    f,
                    "the restricted QEMU cannot {access} the {role} {path}: {} not granted to \
                     RESTRICTED, Users or the logon SID",
                    missing.join(", ")
                )?;
                if !denied.is_empty() {
                    write!(f, " ({} denied by an ACE)", denied.join(", "))?;
                }
                Ok(())
            }
            Self::ControlDirectory { error } => {
                write!(f, "the VM's private directory: {error}")
            }
        }
    }
}

impl std::error::Error for LayoutError {}

/// How one path grants the restricted QEMU its access.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PathGrant {
    pub role: LayoutPath,
    pub path: HostPath,
    pub access: PathAccess,
    /// The restricting SIDs whose ACEs granted it.
    pub through: BTreeSet<RestrictingSid>,
    /// The path has no DACL, which grants everyone everything.
    pub null_dacl: bool,
}

/// The files of one guest image, as the image store verified them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuestImageFiles {
    pub kernel: HostPath,
    pub initrd: Option<HostPath>,
    pub root_image: HostPath,
    pub kernel_arguments: KernelArguments,
}

/// What a [`RuntimeLayout`] is configured with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayoutSettings {
    /// The runtime directory holding `qemu-secure` and `qemu\share`.
    pub runtime_directory: HostPath,
    pub platform: QemuPlatform,
    pub resources: GuestResources,
    /// The guest images, by catalog identity.
    pub images: BTreeMap<Digest, GuestImageFiles>,
    /// The data volumes, by catalog identity.
    pub volumes: BTreeMap<Digest, HostPath>,
    /// The existing directory the VMs' private directories are made in.
    pub control_base: HostPath,
    /// The logon session's SID, when the restricted token has it as a restricting SID.
    pub logon_sid: Option<LogonSid>,
}

/// The host layout of launches from a configured runtime directory (see the module
/// notes).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RuntimeLayout {
    settings: LayoutSettings,
    executable_directory: HostPath,
    executable: HostPath,
    data_directory: HostPath,
    firmware_directory: HostPath,
    trustees: Trustees,
}

impl RuntimeLayout {
    /// Forms the layout's paths; nothing is looked up yet.
    pub fn new(settings: LayoutSettings) -> Result<Self, LayoutError> {
        let join = |base: &HostPath, name: &str, role: LayoutPath| {
            base.join(name)
                .map_err(|error| LayoutError::Path { role, error })
        };
        let executable_directory = join(
            &settings.runtime_directory,
            QEMU_SECURE_DIRECTORY,
            LayoutPath::ExecutableDirectory,
        )?;
        let executable = join(
            &executable_directory,
            executable_name(settings.platform.architecture),
            LayoutPath::Executable,
        )?;
        let data_directory = join(
            &settings.runtime_directory,
            QEMU_DATA_DIRECTORY,
            LayoutPath::DataDirectory,
        )?;
        let firmware_directory = join(
            &data_directory,
            FIRMWARE_DIRECTORY,
            LayoutPath::FirmwareDirectory,
        )?;
        let trustees = Trustees::new(settings.logon_sid.as_ref());
        Ok(Self {
            settings,
            executable_directory,
            executable,
            data_directory,
            firmware_directory,
            trustees,
        })
    }

    /// What the layout was configured with.
    pub fn settings(&self) -> &LayoutSettings {
        &self.settings
    }

    /// The pinned QEMU executable, as the backend's settings name it.
    pub fn executable(&self) -> &HostPath {
        &self.executable
    }

    /// The firmware directory QEMU reads through `-L`.
    pub fn firmware_directory(&self) -> &HostPath {
        &self.firmware_directory
    }

    /// The path of `vm`'s private directory: the first [`CONTROL_NAME_HEX_DIGITS`] hex
    /// digits of its handle under the configured base. Nothing is created.
    pub fn control_directory(&self, vm: VmInstanceId) -> Result<PrivateDirectory, LayoutError> {
        let hex = vm.digest().to_hex();
        let name = hex.get(..CONTROL_NAME_HEX_DIGITS).unwrap_or(&hex);
        let path = self
            .settings
            .control_base
            .join(name)
            .map_err(|error| LayoutError::ControlDirectory { error })?;
        PrivateDirectory::new(path).map_err(|error| LayoutError::ControlDirectory { error })
    }

    /// Checks the runtime: the runtime and data directories, the executable and its
    /// directory (read and execute) and the firmware directory (read).
    pub fn check_runtime(&self) -> Result<Vec<PathGrant>, LayoutError> {
        check_kind(
            LayoutPath::RuntimeDirectory,
            &self.settings.runtime_directory,
            PathKind::Directory,
        )?;
        check_kind(
            LayoutPath::ExecutableDirectory,
            &self.executable_directory,
            PathKind::Directory,
        )?;
        check_kind(LayoutPath::Executable, &self.executable, PathKind::File)?;
        check_kind(
            LayoutPath::DataDirectory,
            &self.data_directory,
            PathKind::Directory,
        )?;
        check_kind(
            LayoutPath::FirmwareDirectory,
            &self.firmware_directory,
            PathKind::Directory,
        )?;
        Ok(vec![
            self.check_access(
                LayoutPath::ExecutableDirectory,
                &self.executable_directory,
                PathAccess::ReadExecute,
            )?,
            self.check_access(
                LayoutPath::Executable,
                &self.executable,
                PathAccess::ReadExecute,
            )?,
            self.check_access(
                LayoutPath::FirmwareDirectory,
                &self.firmware_directory,
                PathAccess::Read,
            )?,
        ])
    }

    /// Checks one image's kernel, initrd and root image: regular files the restricted
    /// QEMU can read.
    pub fn check_image(&self, files: &GuestImageFiles) -> Result<Vec<PathGrant>, LayoutError> {
        let mut paths = vec![(LayoutPath::Kernel, &files.kernel)];
        if let Some(initrd) = &files.initrd {
            paths.push((LayoutPath::Initrd, initrd));
        }
        paths.push((LayoutPath::RootImage, &files.root_image));
        let mut grants = Vec::with_capacity(paths.len());
        for (role, path) in paths {
            check_kind(role, path, PathKind::File)?;
            grants.push(self.check_access(role, path, PathAccess::Read)?);
        }
        Ok(grants)
    }

    /// On Unix: `path` grants `access` to others (module notes).
    #[cfg(unix)]
    fn check_access(
        &self,
        role: LayoutPath,
        path: &HostPath,
        access: PathAccess,
    ) -> Result<PathGrant, LayoutError> {
        use std::os::unix::fs::PermissionsExt;
        let metadata =
            std::fs::metadata(path.as_str()).map_err(|error| LayoutError::Unreadable {
                role,
                path: path.clone(),
                detail: error.to_string(),
            })?;
        let mode = metadata.permissions().mode();
        // A directory is read through: listing it needs read, opening what it holds execute.
        let needed = match access {
            PathAccess::Read if !metadata.is_dir() => 0o004,
            _ => 0o005,
        };
        if mode & needed != needed {
            return Err(LayoutError::AccessMissing {
                role,
                path: path.clone(),
                access,
                missing: vec![if needed == 0o004 {
                    "read for others"
                } else {
                    "read and execute for others"
                }],
                denied: Vec::new(),
            });
        }
        let _ = &self.trustees;
        Ok(PathGrant {
            role,
            path: path.clone(),
            access,
            through: BTreeSet::new(),
            null_dacl: false,
        })
    }

    /// Reads `path`'s DACL and runs the restricting-SID pass for `access`.
    #[cfg(not(unix))]
    fn check_access(
        &self,
        role: LayoutPath,
        path: &HostPath,
        access: PathAccess,
    ) -> Result<PathGrant, LayoutError> {
        let dacl = read_dacl(role, path)?;
        let outcome =
            restricted_access(dacl.as_deref(), &self.trustees, access.mask()).map_err(|error| {
                LayoutError::Acl {
                    role,
                    path: path.clone(),
                    error,
                }
            })?;
        if !outcome.allowed() {
            return Err(LayoutError::AccessMissing {
                role,
                path: path.clone(),
                access,
                missing: right_names(outcome.missing()),
                denied: right_names(outcome.denied),
            });
        }
        Ok(PathGrant {
            role,
            path: path.clone(),
            access,
            through: outcome.through,
            null_dacl: outcome.null_dacl,
        })
    }
}

fn unavailable(error: LayoutError) -> LayoutRefusal {
    LayoutRefusal::Unavailable {
        detail: error.to_string(),
    }
}

/// Host RAM kept outside the guest for QEMU and the hardware accelerator. Small
/// reservations retain the existing minimum guest size; the host Job/cgroup still
/// limits the whole process to the reservation. Image roots require their existing
/// root-plus-256-MiB minimum and are never silently shrunk to fit.
pub const GUEST_HOST_HEADROOM_BYTES: u64 = 256 << 20;

pub(crate) fn resources_in_reservation(
    minimum: GuestResources,
    reserved_bytes: u64,
    reserved_cpu_slots: u64,
) -> Result<GuestResources, LayoutRefusal> {
    let mib = 1 << 20;
    let memory = (reserved_bytes.saturating_sub(GUEST_HOST_HEADROOM_BYTES) / mib * mib)
        .max(minimum.memory_bytes());
    if memory > reserved_bytes {
        return Err(LayoutRefusal::Unavailable {
            detail: format!(
                "guest needs at least {} bytes but only {reserved_bytes} host bytes are reserved",
                minimum.memory_bytes()
            ),
        });
    }
    let cpus = u16::try_from(reserved_cpu_slots).map_err(|_| LayoutRefusal::Unavailable {
        detail: "CPU allocation exceeds the VM's supported range".into(),
    })?;
    GuestResources::new(cpus, memory).map_err(|error| LayoutRefusal::Unavailable {
        detail: format!("guest resources: {error}"),
    })
}

impl LaunchLayout for RuntimeLayout {
    fn inputs_with_reserved_resources(
        &self,
        request: &LaunchRequest,
        vm: VmInstanceId,
        reserved_bytes: u64,
        reserved_cpu_slots: u64,
    ) -> Result<HostInputs, LayoutRefusal> {
        let mut host = self.inputs(request, vm)?;
        host.inputs.resources =
            resources_in_reservation(host.inputs.resources, reserved_bytes, reserved_cpu_slots)?;
        Ok(host)
    }

    /// The inputs of `request`'s launch of `vm`: the pinned image's files and the declared
    /// volumes from the configuration (an unknown image or volume is not available), then
    /// every check of the module notes; any failed check is [`LayoutRefusal::Unavailable`]
    /// with its reason.
    fn inputs(
        &self,
        request: &LaunchRequest,
        vm: VmInstanceId,
    ) -> Result<HostInputs, LayoutRefusal> {
        let image = request.pinned.guest_image;
        let files = self
            .settings
            .images
            .get(&image)
            .ok_or(LayoutRefusal::ImageNotAvailable { image })?;
        let mut volumes = BTreeMap::new();
        for volume in request.required.persistence.volumes() {
            let path = self
                .settings
                .volumes
                .get(&volume)
                .ok_or(LayoutRefusal::VolumeNotAvailable { volume })?;
            volumes.insert(volume, path.clone());
        }
        self.check_runtime().map_err(unavailable)?;
        self.check_image(files).map_err(unavailable)?;
        for (index, path) in volumes.values().enumerate() {
            check_kind(LayoutPath::Volume { index }, path, PathKind::File).map_err(unavailable)?;
        }
        check_kind(
            LayoutPath::ControlBase,
            &self.settings.control_base,
            PathKind::Directory,
        )
        .map_err(unavailable)?;
        let control = self.control_directory(vm).map_err(unavailable)?;
        Ok(HostInputs {
            inputs: QemuLaunchInputs {
                platform: self.settings.platform,
                resources: match &request.required.workload_image {
                    Some(image) => GuestResources::new(
                        self.settings.resources.vcpu_count(),
                        image.root_bytes.saturating_add(256 << 20).div_ceil(1 << 20) * (1 << 20),
                    )
                    .map_err(|error| LayoutRefusal::Unavailable {
                        detail: format!("image memory: {error}"),
                    })?,
                    None => self.settings.resources,
                },
                firmware_directory: self.firmware_directory.clone(),
                kernel: files.kernel.clone(),
                initrd: files.initrd.clone(),
                kernel_arguments: files.kernel_arguments.clone(),
                root_image: files.root_image.clone(),
                volumes,
                control,
                vsock_cid: None,
                egress_endpoints: request.required.declared_endpoints.clone(),
                workload_image: request.required.workload_image.clone(),
            },
            guest_image: image,
        })
    }
}

/// Checks that `path` exists as `kind` and is no link or reparse point, without following
/// it.
#[cfg(windows)]
fn check_kind(role: LayoutPath, path: &HostPath, kind: PathKind) -> Result<(), LayoutError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let metadata = match std::fs::symlink_metadata(path.as_str()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LayoutError::Missing {
                role,
                path: path.clone(),
            })
        }
        Err(error) => {
            return Err(LayoutError::Unreadable {
                role,
                path: path.clone(),
                detail: error.to_string(),
            })
        }
    };
    if metadata.file_type().is_symlink()
        || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
    {
        return Err(LayoutError::Redirected {
            role,
            path: path.clone(),
        });
    }
    let fits = match kind {
        PathKind::Directory => metadata.is_dir(),
        PathKind::File => metadata.is_file(),
    };
    if !fits {
        return Err(LayoutError::WrongKind {
            role,
            path: path.clone(),
            expected: kind,
        });
    }
    Ok(())
}

/// Checks that `path` exists as `kind` and is no symbolic link, without following it.
#[cfg(unix)]
fn check_kind(role: LayoutPath, path: &HostPath, kind: PathKind) -> Result<(), LayoutError> {
    let metadata = match std::fs::symlink_metadata(path.as_str()) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(LayoutError::Missing {
                role,
                path: path.clone(),
            })
        }
        Err(error) => {
            return Err(LayoutError::Unreadable {
                role,
                path: path.clone(),
                detail: error.to_string(),
            })
        }
    };
    if metadata.file_type().is_symlink() {
        return Err(LayoutError::Redirected {
            role,
            path: path.clone(),
        });
    }
    let fits = match kind {
        PathKind::Directory => metadata.is_dir(),
        PathKind::File => metadata.is_file(),
    };
    if !fits {
        return Err(LayoutError::WrongKind {
            role,
            path: path.clone(),
            expected: kind,
        });
    }
    Ok(())
}

#[cfg(not(any(windows, unix)))]
fn check_kind(_role: LayoutPath, _path: &HostPath, _kind: PathKind) -> Result<(), LayoutError> {
    Err(LayoutError::Unsupported)
}

/// The bytes of `path`'s DACL, or `None` when it has none (a NULL DACL).
#[cfg(windows)]
fn read_dacl(role: LayoutPath, path: &HostPath) -> Result<Option<Vec<u8>>, LayoutError> {
    use std::ptr::null_mut;
    use windows_sys::Win32::Foundation::{LocalFree, ERROR_SUCCESS};
    use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{ACL, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR};

    /// Frees the security descriptor the call allocated.
    struct Descriptor(PSECURITY_DESCRIPTOR);

    impl Drop for Descriptor {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the descriptor was allocated by GetNamedSecurityInfoW for this
                // caller and is freed once, here.
                unsafe {
                    LocalFree(self.0);
                }
            }
        }
    }

    let wide: Vec<u16> = path.as_str().encode_utf16().chain(Some(0)).collect();
    let mut dacl: *mut ACL = null_mut();
    let mut descriptor = Descriptor(null_mut());
    // SAFETY: `wide` is NUL-terminated and live for the call; only the DACL is asked for,
    // and both out-pointers are live. The descriptor is freed by `Descriptor`.
    let code = unsafe {
        GetNamedSecurityInfoW(
            wide.as_ptr(),
            SE_FILE_OBJECT,
            DACL_SECURITY_INFORMATION,
            null_mut(),
            null_mut(),
            &mut dacl,
            null_mut(),
            &mut descriptor.0,
        )
    };
    if code != ERROR_SUCCESS {
        return Err(LayoutError::SecurityUnreadable {
            role,
            path: path.clone(),
            code,
        });
    }
    if dacl.is_null() {
        return Ok(None);
    }
    // SAFETY: `dacl` points to a valid ACL inside the descriptor, which stays allocated
    // until `descriptor` drops at the end of this function; `AclSize` is the ACL's whole
    // size in bytes, header included, so the slice covers only the ACL.
    let bytes = unsafe {
        let size = usize::from((*dacl).AclSize);
        std::slice::from_raw_parts(dacl.cast::<u8>(), size).to_vec()
    };
    drop(descriptor);
    Ok(Some(bytes))
}

#[cfg(not(any(windows, unix)))]
fn read_dacl(_role: LayoutPath, _path: &HostPath) -> Result<Option<Vec<u8>>, LayoutError> {
    Err(LayoutError::Unsupported)
}
