//! Launch layout tests: path formation and lookups everywhere; on Windows, kinds, links
//! and DACL decisions on files created in a temporary directory with the ACLs each test
//! sets. Every test ACL also grants Authenticated Users (not a restricting SID, so it
//! never changes a decision) full access, inherited by children, so the files stay
//! removable.

use std::collections::BTreeMap;
use std::time::Duration;

use super::acl::LogonSid;
use super::layout::*;
use crate::foundation::coordination::{SandboxGenerations, VmInstanceId};
use crate::foundation::evidence::{ConfigurationFingerprint, OsKind};
use crate::foundation::ids::{digest, Digest, ExecutionId, SandboxBootGeneration, TenantId};
use crate::sandbox::backend::{
    Architecture, DeviceExposure, DeviceProfile, LaunchRequest, Persistence, PinnedArtifacts,
    RequiredProperties,
};
use crate::sandbox::qemu::{
    GuestResources, HostPath, KernelArguments, LaunchLayout, LayoutRefusal, PathError, PathStyle,
    QemuPlatform, MIB_BYTES,
};

fn windows(text: &str) -> HostPath {
    HostPath::new(PathStyle::Windows, text).unwrap()
}

fn image() -> Digest {
    digest("yougori/test/image/v1", &[b"alpine"])
}

fn volume() -> Digest {
    digest("yougori/test/volume/v1", &[b"data"])
}

fn vm() -> VmInstanceId {
    VmInstanceId::new(digest("yougori/test/vm/v1", &[b"vm-a"]))
}

fn platform() -> QemuPlatform {
    QemuPlatform {
        os: OsKind::Windows,
        architecture: Architecture::X86_64,
    }
}

fn files(base: &str) -> GuestImageFiles {
    GuestImageFiles {
        kernel: windows(&format!(r"{base}\images\vmlinuz")),
        initrd: Some(windows(&format!(r"{base}\images\initrd"))),
        root_image: windows(&format!(r"{base}\images\root.img")),
        kernel_arguments: KernelArguments::parse("root=/dev/vda ro quiet").unwrap(),
    }
}

fn settings(base: &str, logon_sid: Option<LogonSid>) -> LayoutSettings {
    LayoutSettings {
        runtime_directory: windows(&format!(r"{base}\runtime")),
        platform: platform(),
        resources: GuestResources::new(2, 512 * MIB_BYTES).unwrap(),
        images: BTreeMap::from([(image(), files(base))]),
        volumes: BTreeMap::from([(volume(), windows(&format!(r"{base}\volumes\data.img")))]),
        control_base: windows(&format!(r"{base}\control")),
        logon_sid,
    }
}

fn request(image: Digest, volumes: &[Digest]) -> LaunchRequest {
    let mut required = RequiredProperties::strictest(Duration::from_secs(60));
    if !volumes.is_empty() {
        required.persistence = Persistence::DeclaredDataVolumes {
            volumes: volumes.iter().copied().collect(),
        };
    }
    LaunchRequest {
        execution: ExecutionId::new("exe-1").unwrap(),
        tenant: TenantId::new("tenant-1").unwrap(),
        generations: SandboxGenerations {
            boot: SandboxBootGeneration::new(1),
            ..SandboxGenerations::FIRST
        },
        machine: digest("yougori/test/machine/v1", &[b"m"]),
        configuration: ConfigurationFingerprint::from_settings([("host", "a")]).unwrap(),
        contract: digest("yougori/test/contract/v1", &[b"c1"]),
        pinned: PinnedArtifacts {
            guest_image: image,
            backend: digest("yougori/test/backend/v1", &[b"qemu"]),
        },
        device_profile: DeviceProfile {
            identity: digest("yougori/test/profile/v1", &[b"minimal"]),
            devices: DeviceExposure::cpu_only(),
        },
        required,
        reservation: serde_json::from_value(1.into()).unwrap(),
    }
}

#[test]
fn paths_are_formed_from_the_runtime_directory() {
    let layout = RuntimeLayout::new(settings(r"C:\Yougori", None)).unwrap();
    // The executable's name is the host's: with `.exe` on Windows, without elsewhere.
    let extension = if cfg!(windows) { ".exe" } else { "" };
    assert_eq!(
        layout.executable().as_str(),
        format!(r"C:\Yougori\runtime\qemu-secure\qemu-system-x86_64{extension}")
    );
    assert_eq!(
        layout.firmware_directory().as_str(),
        r"C:\Yougori\runtime\qemu\share"
    );
    assert_eq!(
        executable_name(Architecture::Aarch64),
        format!("qemu-system-aarch64{extension}")
    );
}

#[test]
fn guest_memory_uses_its_own_reservation_with_host_headroom() {
    let minimum = GuestResources::new(1, 256 * MIB_BYTES).unwrap();
    for (reserved_mib, guest_mib) in [(320, 256), (1024, 768), (2048, 1792)] {
        let sized = resources_in_reservation(minimum, reserved_mib * MIB_BYTES, 1).unwrap();
        assert_eq!(sized.memory_bytes(), guest_mib * MIB_BYTES);
        assert_eq!(sized.vcpu_count(), 1);
    }
    // Fractional MiB must round down, never exceed the host budget.
    let sized = resources_in_reservation(minimum, 1024 * MIB_BYTES + MIB_BYTES - 1, 1).unwrap();
    assert_eq!(sized.memory_bytes(), 768 * MIB_BYTES);
    assert!(resources_in_reservation(minimum, 255 * MIB_BYTES, 1).is_err());
    assert!(resources_in_reservation(minimum, 0, 1).is_err());
    assert!(resources_in_reservation(minimum, u64::MAX, 1).is_err());

    // Image minimums remain binding; a large previous launch cannot affect the next.
    let image = GuestResources::new(2, 768 * MIB_BYTES).unwrap();
    assert!(resources_in_reservation(image, 512 * MIB_BYTES, 2).is_err());
    assert_eq!(
        resources_in_reservation(image, 1024 * MIB_BYTES, 2).unwrap(),
        image
    );
    assert_eq!(
        resources_in_reservation(minimum, 320 * MIB_BYTES, 1).unwrap(),
        minimum
    );
}

#[test]
fn the_private_directory_is_named_by_the_vm_handle_and_fits_a_socket_address() {
    let layout = RuntimeLayout::new(settings(r"C:\Yougori", None)).unwrap();
    let control = layout.control_directory(vm()).unwrap();
    let short = &vm().digest().to_hex()[..CONTROL_NAME_HEX_DIGITS];
    assert_eq!(
        control.path().as_str(),
        format!(r"C:\Yougori\control\{short}")
    );
    assert!(control.qmp_socket().as_str().ends_with(r"\qmp.sock"));
    let mut long = settings(r"C:\Yougori", None);
    long.control_base = windows(&format!(r"C:\{}", "d".repeat(90)));
    let layout = RuntimeLayout::new(long).unwrap();
    assert!(matches!(
        layout.control_directory(vm()),
        Err(LayoutError::ControlDirectory {
            error: PathError::SocketPathTooLong { .. }
        })
    ));
}

#[test]
fn an_unknown_image_or_volume_is_not_available_before_anything_is_read() {
    let layout = RuntimeLayout::new(settings(r"C:\Yougori\absent", None)).unwrap();
    let other = digest("yougori/test/image/v1", &[b"other"]);
    assert_eq!(
        layout.inputs(&request(other, &[]), vm()).err(),
        Some(LayoutRefusal::ImageNotAvailable { image: other })
    );
    let undeclared = digest("yougori/test/volume/v1", &[b"other"]);
    assert_eq!(
        layout.inputs(&request(image(), &[undeclared]), vm()).err(),
        Some(LayoutRefusal::VolumeNotAvailable { volume: undeclared })
    );
}

#[cfg(not(any(windows, unix)))]
#[test]
fn the_checks_are_unsupported_off_windows_and_unix() {
    let layout = RuntimeLayout::new(settings(r"C:\Yougori", None)).unwrap();
    assert_eq!(layout.check_runtime().err(), Some(LayoutError::Unsupported));
}

/// PROVES on Unix the runtime's paths are checked for their kind without following a link
/// and for the access others hold, since QEMU runs as an account of its own: a runtime
/// readable and executable by others passes; a missing executable, a link in its place,
/// a directory without others' execute and a firmware directory without others' read are
/// each refused, naming the path.
#[cfg(unix)]
#[test]
fn on_unix_the_runtime_is_checked_for_kind_and_others_access() {
    use std::os::unix::fs::PermissionsExt;
    let base = std::env::temp_dir().join(format!("yg-layout-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&base);
    let runtime = base.join("runtime");
    let secure = runtime.join("qemu-secure");
    let share = runtime.join("qemu").join("share");
    std::fs::create_dir_all(&secure).unwrap();
    std::fs::create_dir_all(&share).unwrap();
    let executable = secure.join(executable_name(Architecture::X86_64));
    std::fs::write(&executable, b"qemu").unwrap();
    let mode = |path: &std::path::Path, mode: u32| {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    };
    mode(&executable, 0o755);
    let unix = |path: &std::path::Path| {
        HostPath::new(
            crate::sandbox::qemu::PathStyle::Unix,
            path.to_str().unwrap(),
        )
        .unwrap()
    };
    let mut unix_settings = settings(r"C:\Yougori", None);
    unix_settings.runtime_directory = unix(&runtime);
    unix_settings.control_base = unix(&base.join("control"));
    let layout = RuntimeLayout::new(unix_settings).unwrap();
    let grants = layout.check_runtime().unwrap();
    assert_eq!(grants.len(), 3);

    mode(&secure, 0o750);
    assert!(matches!(
        layout.check_runtime(),
        Err(LayoutError::AccessMissing {
            role: LayoutPath::ExecutableDirectory,
            ..
        })
    ));
    mode(&secure, 0o755);
    mode(&share, 0o754);
    assert!(matches!(
        layout.check_runtime(),
        Err(LayoutError::AccessMissing {
            role: LayoutPath::FirmwareDirectory,
            ..
        })
    ));
    mode(&share, 0o755);
    std::fs::remove_file(&executable).unwrap();
    assert!(matches!(
        layout.check_runtime(),
        Err(LayoutError::Missing {
            role: LayoutPath::Executable,
            ..
        })
    ));
    std::os::unix::fs::symlink("/bin/sh", &executable).unwrap();
    assert!(matches!(
        layout.check_runtime(),
        Err(LayoutError::Redirected {
            role: LayoutPath::Executable,
            ..
        })
    ));
    std::fs::remove_dir_all(&base).unwrap();
}

#[cfg(windows)]
mod host_files {
    use std::collections::BTreeSet;
    use std::os::windows::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::ptr::{null, null_mut};

    use windows_sys::Win32::Security::Authorization::{SetNamedSecurityInfoW, SE_FILE_OBJECT};
    use windows_sys::Win32::Security::{
        ACL, DACL_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION,
    };

    use super::super::acl::{
        acl_bytes, restricted_sid, users_sid, LogonSid, PathAccess, ACCESS_ALLOWED_ACE_TYPE,
        ACCESS_DENIED_ACE_TYPE, CONTAINER_INHERIT_ACE, FILE_ALL_ACCESS, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, INHERIT_ONLY_ACE, OBJECT_INHERIT_ACE, READ_DATA,
    };
    use super::*;
    use crate::sandbox::qemu::RestrictingSid;

    const ALLOW: u8 = ACCESS_ALLOWED_ACE_TYPE;
    const DENY: u8 = ACCESS_DENIED_ACE_TYPE;
    const READ: u32 = FILE_GENERIC_READ;
    const READ_EXECUTE: u32 = FILE_GENERIC_READ | FILE_GENERIC_EXECUTE;
    const INHERIT: u8 = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

    fn sid(authority: u8, sub_authorities: &[u32]) -> Vec<u8> {
        let mut bytes = vec![
            1,
            u8::try_from(sub_authorities.len()).unwrap(),
            0,
            0,
            0,
            0,
            0,
            authority,
        ];
        for sub_authority in sub_authorities {
            bytes.extend_from_slice(&sub_authority.to_le_bytes());
        }
        bytes
    }

    fn authenticated_users() -> Vec<u8> {
        sid(5, &[11])
    }

    fn everyone() -> Vec<u8> {
        sid(1, &[0])
    }

    fn logon() -> LogonSid {
        LogonSid::parse("S-1-5-5-0-12345").unwrap()
    }

    /// A Windows host path for a temporary path, with backslashes.
    pub fn host(path: &Path) -> HostPath {
        windows(&path.to_str().unwrap().replace('/', "\\"))
    }

    /// Replaces `path`'s DACL with `aces` and the keeper ACE, protected from inheritance.
    fn protect(path: &Path, aces: &[(u8, u8, u32, &[u8])]) {
        let keeper = authenticated_users();
        let keeper_flags = if path.is_dir() { INHERIT } else { 0 };
        let mut all = aces.to_vec();
        all.push((ALLOW, keeper_flags, FILE_ALL_ACCESS, &keeper));
        let bytes = acl_bytes(&all);
        // An ACL is DWORD-aligned.
        let mut storage = vec![0u32; bytes.len().div_ceil(4)];
        for (index, byte) in bytes.iter().enumerate() {
            storage[index / 4] |= u32::from(*byte) << (8 * (index % 4));
        }
        let wide: Vec<u16> = path.as_os_str().encode_wide().chain(Some(0)).collect();
        // SAFETY: `wide` is NUL-terminated and `storage` holds a valid ACL; both outlive
        // the call, which copies the ACL into the file's security descriptor.
        let code = unsafe {
            SetNamedSecurityInfoW(
                wide.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                null_mut(),
                null_mut(),
                storage.as_ptr().cast::<ACL>(),
                null(),
            )
        };
        assert_eq!(code, 0, "SetNamedSecurityInfoW on {path:?}");
    }

    /// A runtime tree, an image and a volume in a temporary directory, each checked path
    /// readable through a restricting SID.
    pub struct Fixture {
        directory: tempfile::TempDir,
    }

    impl Fixture {
        pub fn new() -> Self {
            let fixture = Self {
                directory: tempfile::tempdir().unwrap(),
            };
            for directory in [
                r"runtime\qemu-secure",
                r"runtime\qemu\share",
                "images",
                "volumes",
                "control",
            ] {
                std::fs::create_dir_all(fixture.path(directory)).unwrap();
            }
            for file in [
                r"runtime\qemu-secure\qemu-system-x86_64.exe",
                r"runtime\qemu\share\bios-microvm.bin",
                r"images\vmlinuz",
                r"images\initrd",
                r"images\root.img",
                r"volumes\data.img",
            ] {
                std::fs::write(fixture.path(file), b"x").unwrap();
            }
            let restricted = restricted_sid();
            let users = users_sid();
            fixture.set(
                r"runtime\qemu-secure\qemu-system-x86_64.exe",
                &[(ALLOW, 0, READ_EXECUTE, &restricted)],
            );
            fixture.set(r"images\vmlinuz", &[(ALLOW, 0, READ, &users)]);
            fixture.set(r"images\initrd", &[(ALLOW, 0, READ, &restricted)]);
            fixture.set(r"images\root.img", &[(ALLOW, 0, READ, &restricted)]);
            fixture.set(
                r"runtime\qemu-secure",
                &[(ALLOW, 0, READ_EXECUTE, &restricted)],
            );
            fixture.set(r"runtime\qemu\share", &[(ALLOW, 0, READ, &users)]);
            fixture
        }

        pub fn path(&self, relative: &str) -> PathBuf {
            self.directory.path().join(relative)
        }

        pub fn set(&self, relative: &str, aces: &[(u8, u8, u32, &[u8])]) {
            protect(&self.path(relative), aces);
        }

        pub fn base(&self) -> String {
            host(self.directory.path()).as_str().to_owned()
        }

        pub fn layout(&self, logon_sid: Option<LogonSid>) -> RuntimeLayout {
            RuntimeLayout::new(settings(&self.base(), logon_sid)).unwrap()
        }
    }

    fn access_missing(
        error: LayoutError,
    ) -> (LayoutPath, PathAccess, Vec<&'static str>, Vec<&'static str>) {
        match error {
            LayoutError::AccessMissing {
                role,
                access,
                missing,
                denied,
                ..
            } => (role, access, missing, denied),
            other => panic!("expected missing access, got {other:?}"),
        }
    }

    #[test]
    fn paths_readable_through_restricting_sids_give_the_launch_inputs() {
        let fixture = Fixture::new();
        let layout = fixture.layout(None);
        let grants = layout.check_runtime().unwrap();
        let through: Vec<(LayoutPath, BTreeSet<RestrictingSid>)> = grants
            .iter()
            .map(|grant| (grant.role, grant.through.clone()))
            .collect();
        assert_eq!(
            through,
            vec![
                (
                    LayoutPath::ExecutableDirectory,
                    BTreeSet::from([RestrictingSid::Restricted])
                ),
                (
                    LayoutPath::Executable,
                    BTreeSet::from([RestrictingSid::Restricted])
                ),
                (
                    LayoutPath::FirmwareDirectory,
                    BTreeSet::from([RestrictingSid::Users])
                ),
            ]
        );
        assert!(grants.iter().all(|grant| !grant.null_dacl));
        let inputs = layout.inputs(&request(image(), &[volume()]), vm()).unwrap();
        assert_eq!(inputs.guest_image, image());
        let inputs = inputs.inputs;
        let base = fixture.base();
        assert_eq!(
            inputs.firmware_directory.as_str(),
            format!(r"{base}\runtime\qemu\share")
        );
        assert_eq!(inputs.kernel.as_str(), format!(r"{base}\images\vmlinuz"));
        assert_eq!(
            inputs.initrd.as_ref().map(HostPath::as_str),
            Some(format!(r"{base}\images\initrd").as_str())
        );
        assert_eq!(
            inputs.root_image.as_str(),
            format!(r"{base}\images\root.img")
        );
        assert_eq!(
            inputs.volumes.get(&volume()).map(HostPath::as_str),
            Some(format!(r"{base}\volumes\data.img").as_str())
        );
        let short = &vm().digest().to_hex()[..CONTROL_NAME_HEX_DIGITS];
        assert_eq!(
            inputs.control.path().as_str(),
            format!(r"{base}\control\{short}")
        );
        assert!(!fixture.path(&format!(r"control\{short}")).exists());
        assert_eq!(inputs.vsock_cid, None);
        assert_eq!(inputs.platform, platform());
    }

    #[test]
    fn a_deny_for_users_before_an_allow_for_restricted_refuses() {
        let fixture = Fixture::new();
        let users = users_sid();
        let restricted = restricted_sid();
        fixture.set(
            r"images\vmlinuz",
            &[(DENY, 0, READ_DATA, &users), (ALLOW, 0, READ, &restricted)],
        );
        let error = fixture
            .layout(None)
            .check_image(&files(&fixture.base()))
            .unwrap_err();
        assert!(error.to_string().contains("vmlinuz"), "{error}");
        assert_eq!(
            access_missing(error),
            (
                LayoutPath::Kernel,
                PathAccess::Read,
                vec!["READ_DATA"],
                vec!["READ_DATA"]
            )
        );
        // The same ACEs the other way round grant it.
        fixture.set(
            r"images\vmlinuz",
            &[(ALLOW, 0, READ, &restricted), (DENY, 0, READ_DATA, &users)],
        );
        assert!(fixture
            .layout(None)
            .check_image(&files(&fixture.base()))
            .is_ok());
    }

    #[test]
    fn read_without_execute_refuses_the_executable_and_its_directory() {
        let fixture = Fixture::new();
        let restricted = restricted_sid();
        fixture.set(
            r"runtime\qemu-secure\qemu-system-x86_64.exe",
            &[(ALLOW, 0, READ, &restricted)],
        );
        assert_eq!(
            access_missing(fixture.layout(None).check_runtime().unwrap_err()),
            (
                LayoutPath::Executable,
                PathAccess::ReadExecute,
                vec!["EXECUTE"],
                vec![]
            )
        );
        fixture.set(r"runtime\qemu-secure", &[(ALLOW, 0, READ, &restricted)]);
        assert_eq!(
            access_missing(fixture.layout(None).check_runtime().unwrap_err()).0,
            LayoutPath::ExecutableDirectory
        );
    }

    #[test]
    fn grants_to_other_sids_do_not_count() {
        let fixture = Fixture::new();
        let everyone = everyone();
        fixture.set(
            r"runtime\qemu\share",
            &[(ALLOW, 0, FILE_ALL_ACCESS, &everyone)],
        );
        let layout = fixture.layout(None);
        let (role, access, missing, denied) = access_missing(layout.check_runtime().unwrap_err());
        assert_eq!(
            (role, access),
            (LayoutPath::FirmwareDirectory, PathAccess::Read)
        );
        assert_eq!(
            missing,
            vec![
                "READ_DATA",
                "READ_EA",
                "READ_ATTRIBUTES",
                "READ_CONTROL",
                "SYNCHRONIZE"
            ]
        );
        assert!(denied.is_empty());
        match layout.inputs(&request(image(), &[]), vm()) {
            Err(LayoutRefusal::Unavailable { detail }) => {
                assert!(detail.contains(r"runtime\qemu\share"), "{detail}");
                assert!(
                    detail.contains("RESTRICTED, Users or the logon SID"),
                    "{detail}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_logon_sid_grant_counts_only_when_the_logon_sid_is_given() {
        let fixture = Fixture::new();
        let logon_sid = logon();
        fixture.set(
            r"images\root.img",
            &[(ALLOW, 0, READ, logon_sid.as_bytes())],
        );
        let without = fixture.layout(None).check_image(&files(&fixture.base()));
        assert_eq!(
            access_missing(without.unwrap_err()).0,
            LayoutPath::RootImage
        );
        let grants = fixture
            .layout(Some(logon()))
            .check_image(&files(&fixture.base()))
            .unwrap();
        let root = grants
            .iter()
            .find(|grant| grant.role == LayoutPath::RootImage)
            .unwrap();
        assert_eq!(root.through, BTreeSet::from([RestrictingSid::LogonSession]));
    }

    #[test]
    fn inherited_aces_count_and_inherit_only_aces_do_not() {
        let fixture = Fixture::new();
        let restricted = restricted_sid();
        let users = users_sid();
        fixture.set(
            "images",
            &[(ALLOW, INHERIT | INHERIT_ONLY_ACE, READ, &restricted)],
        );
        std::fs::write(fixture.path(r"images\fresh-kernel"), b"x").unwrap();
        let mut fresh = files(&fixture.base());
        fresh.kernel = windows(&format!(r"{}\images\fresh-kernel", fixture.base()));
        let grants = fixture.layout(None).check_image(&fresh).unwrap();
        assert_eq!(grants[0].role, LayoutPath::Kernel);
        assert_eq!(
            grants[0].through,
            BTreeSet::from([RestrictingSid::Restricted])
        );
        fixture.set(
            r"runtime\qemu\share",
            &[(ALLOW, INHERIT | INHERIT_ONLY_ACE, READ, &users)],
        );
        assert_eq!(
            access_missing(fixture.layout(None).check_runtime().unwrap_err()).0,
            LayoutPath::FirmwareDirectory
        );
    }

    #[test]
    fn missing_paths_wrong_kinds_and_links_are_refused() {
        let fixture = Fixture::new();
        let base = fixture.base();
        std::fs::remove_file(fixture.path(r"images\initrd")).unwrap();
        assert!(matches!(
            fixture.layout(None).check_image(&files(&base)),
            Err(LayoutError::Missing {
                role: LayoutPath::Initrd,
                ..
            })
        ));
        let mut directory_as_kernel = files(&base);
        directory_as_kernel.kernel = windows(&format!(r"{base}\volumes"));
        assert!(matches!(
            fixture.layout(None).check_image(&directory_as_kernel),
            Err(LayoutError::WrongKind {
                role: LayoutPath::Kernel,
                expected: PathKind::File,
                ..
            })
        ));
        std::fs::remove_dir_all(fixture.path(r"runtime\qemu\share")).unwrap();
        std::fs::create_dir(fixture.path("share-elsewhere")).unwrap();
        let junction = std::process::Command::new("cmd")
            .args(["/C", "mklink", "/J"])
            .arg(host(&fixture.path(r"runtime\qemu\share")).as_str())
            .arg(host(&fixture.path("share-elsewhere")).as_str())
            .output()
            .unwrap();
        assert!(junction.status.success(), "{junction:?}");
        assert!(matches!(
            fixture.layout(None).check_runtime(),
            Err(LayoutError::Redirected {
                role: LayoutPath::FirmwareDirectory,
                ..
            })
        ));
        std::fs::remove_dir_all(fixture.path(r"runtime\qemu")).unwrap();
        assert!(matches!(
            fixture.layout(None).check_runtime(),
            Err(LayoutError::Missing {
                role: LayoutPath::DataDirectory,
                ..
            })
        ));
    }
}

#[test]
fn guest_cpu_allocation_is_taken_from_this_launch_reservation() {
    let minimum = GuestResources::new(1, 256 * MIB_BYTES).unwrap();
    assert_eq!(
        resources_in_reservation(minimum, 1024 * MIB_BYTES, 4)
            .unwrap()
            .vcpu_count(),
        4
    );
    assert_eq!(
        resources_in_reservation(minimum, 1024 * MIB_BYTES, 1)
            .unwrap()
            .vcpu_count(),
        1
    );
    for count in [0, 256, u64::MAX] {
        assert!(resources_in_reservation(minimum, 1024 * MIB_BYTES, count).is_err());
    }
}
