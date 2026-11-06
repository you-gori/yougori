//! Host probes of the restricted VM path (module docs in `mod.rs`; CORE-01: evidence is
//! produced by probe adapters that observe and never change host state; S01's carry-forward
//! "`HypervisorAvailable` ... is produced here", with M08 owning the controlled checks).
//!
//! - [`WhpxProbe`]: `Capability::HypervisorAvailable` for the Windows Hypervisor Platform
//!   on this machine, from the platform's own capability report
//!   (`WHvGetCapability(WHvCapabilityCodeHypervisorPresent)` in `WinHvPlatform.dll`, loaded
//!   from the system directory alone). Present is supported with the WHPX detail; absent
//!   is unsupported (`HypervisorUnavailable`); a platform library the host does not have is
//!   the same refusal (the optional feature is not installed); a call that fails is unknown.
//!   This is the hypervisor's availability as the host reports it, which the backend's
//!   precheck requires fresh before a plan exists. It is not the VM-CP-01 controlled check
//!   (a launch whose record names the accelerator, a forced failure refused), which the
//!   doctor's check runner owns (M08) and which the launch records this path seals feed.
//! - [`KvmProbe`]: the same capability for KVM on Linux, from the kernel's own answer:
//!   `/dev/kvm` opened read-write and asked its API version (`KVM_GET_API_VERSION`, 12).
//!   A device that is not there is unsupported (`HypervisorUnavailable`: no KVM module, or
//!   no hardware virtualization); one that cannot be opened is unsupported too; another API
//!   version is unknown.
//! - [`PinnedRuntimeProbe`]: `Capability::RuntimeCategory` for the one runtime this path
//!   offers, the pinned QEMU build on this machine, by hashing the executable now and
//!   comparing it with the build's artifact identity. The same bytes are the VM sandbox
//!   runtime the profile confines; different bytes are a different category
//!   (`DifferentCategory`), not this runtime. It observes only its own subject.
//!
//! Both stamp the host's configuration fingerprint from `host_evidence`'s inventory, so a
//! changed host configuration invalidates them as it invalidates every other host fact.

use std::path::PathBuf;
use std::time::Duration;

use crate::foundation::evidence::{
    Capability, ConfigurationFingerprint, HostChange, HypervisorKind, Observation, ProbeAdapter,
    SourceClass, Subject, SupportDetail, UnknownReason, UnsupportedReason,
};
use crate::foundation::ids::{Digest, ExecutionCategory};

use super::artifacts::sha256_file;

/// How long each probe's observation stays fresh: ten minutes, as the backend's own
/// observations.
pub const FRESH_FOR: Duration = Duration::from_secs(600);

/// The registry has one adapter per capability/source. Dispatch disjoint runtime
/// subjects inside that adapter instead of replacing the CPU probe with GPU's.
#[cfg(windows)]
pub struct Alternatives(pub Box<dyn ProbeAdapter>, pub Box<dyn ProbeAdapter>);
#[cfg(windows)]
impl ProbeAdapter for Alternatives {
    fn capability(&self) -> Capability { self.0.capability() }
    fn source(&self) -> SourceClass { self.0.source() }
    fn host_changes(&self) -> Vec<HostChange> { self.0.host_changes().into_iter().chain(self.1.host_changes()).collect() }
    fn observes(&self, subject: &Subject) -> bool { self.0.observes(subject) != self.1.observes(subject) }
    fn observe(&self, subject: &Subject) -> Observation {
        if self.1.observes(subject) && !self.0.observes(subject) { self.1.observe(subject) }
        else { self.0.observe(subject) }
    }
}

/// What the platform reports about the hypervisor: the Windows Hypervisor Platform, or KVM
/// on Linux (each platform makes only its own variants).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum PlatformReport {
    Present,
    Absent,
    /// `WinHvPlatform.dll` is not in the system directory: the optional feature is off.
    LibraryMissing,
    /// The capability call failed with this HRESULT.
    CallFailed {
        hresult: i32,
    },
    /// Linux: `/dev/kvm` does not exist (no KVM module, or no hardware virtualization).
    DeviceMissing,
    /// Linux: `/dev/kvm` could not be opened read-write (this OS error).
    DeviceUnusable {
        os_error: i32,
    },
    /// Linux: KVM answered another API version than 12.
    UnexpectedApi {
        version: i32,
    },
}

impl PlatformReport {
    /// What the report says, as a person reads it, and whether it reports a hypervisor.
    pub fn describe(self) -> (Option<bool>, String) {
        match self {
            Self::Present => (Some(true), "the platform reports a hypervisor".to_owned()),
            Self::Absent => (Some(false), "the platform reports no hypervisor".to_owned()),
            Self::LibraryMissing => (
                Some(false),
                "WinHvPlatform.dll is not installed (the Windows Hypervisor Platform feature is off)"
                    .to_owned(),
            ),
            Self::CallFailed { hresult } => (
                None,
                format!("WHvGetCapability failed with HRESULT {hresult:#x}"),
            ),
            Self::DeviceMissing => (
                Some(false),
                "/dev/kvm does not exist (no KVM module, or no hardware virtualization)".to_owned(),
            ),
            Self::DeviceUnusable { os_error } => (
                Some(false),
                format!(
                    "/dev/kvm could not be opened read-write: {}",
                    std::io::Error::from_raw_os_error(os_error)
                ),
            ),
            Self::UnexpectedApi { version } => (
                None,
                format!("KVM answered API version {version}, not 12"),
            ),
        }
    }
}

#[cfg(windows)]
mod sys {
    use std::ptr::null_mut;

    use windows_sys::Win32::Foundation::FreeLibrary;
    use windows_sys::Win32::System::LibraryLoader::{
        GetProcAddress, LoadLibraryExW, LOAD_LIBRARY_SEARCH_SYSTEM32,
    };

    use super::PlatformReport;

    /// `WHvCapabilityCodeHypervisorPresent` (WinHvPlatformDefs.h).
    const HYPERVISOR_PRESENT: u32 = 0;

    type GetCapability = unsafe extern "system" fn(
        capability_code: u32,
        buffer: *mut core::ffi::c_void,
        buffer_size: u32,
        written: *mut u32,
    ) -> i32;

    /// Asks the platform whether a hypervisor is present (module notes).
    pub(super) fn hypervisor_present() -> PlatformReport {
        let name: Vec<u16> = "WinHvPlatform.dll".encode_utf16().chain([0]).collect();
        // SAFETY: the name is NUL-terminated; the library is searched in the system
        // directory only.
        let library =
            unsafe { LoadLibraryExW(name.as_ptr(), null_mut(), LOAD_LIBRARY_SEARCH_SYSTEM32) };
        if library.is_null() {
            return PlatformReport::LibraryMissing;
        }
        // SAFETY: the library handle is valid; the name is NUL-terminated.
        let address = unsafe { GetProcAddress(library, c"WHvGetCapability".as_ptr().cast()) };
        let report = match address {
            None => PlatformReport::CallFailed { hresult: 0 },
            Some(address) => {
                // SAFETY: the function has the documented signature; the output buffer is
                // a live u32 (the platform writes a BOOL) of the size given.
                let get_capability: GetCapability = unsafe { std::mem::transmute(address) };
                let mut present: u32 = 0;
                let mut written: u32 = 0;
                let hresult = unsafe {
                    get_capability(
                        HYPERVISOR_PRESENT,
                        (&mut present as *mut u32).cast(),
                        u32::try_from(std::mem::size_of::<u32>()).unwrap_or(4),
                        &mut written,
                    )
                };
                if hresult < 0 {
                    PlatformReport::CallFailed { hresult }
                } else if present != 0 {
                    PlatformReport::Present
                } else {
                    PlatformReport::Absent
                }
            }
        };
        // SAFETY: the handle came from LoadLibraryExW and is freed once.
        unsafe { FreeLibrary(library) };
        report
    }
}

#[cfg(target_os = "linux")]
mod sys {
    use std::os::fd::AsRawFd;

    use super::PlatformReport;

    /// `KVM_GET_API_VERSION` (`_IO(0xAE, 0x00)`), and the version every KVM since Linux
    /// 2.6.22 answers.
    const KVM_GET_API_VERSION: u32 = 0xAE00;
    const KVM_API_VERSION: i32 = 12;

    /// Opens `/dev/kvm` read-write and asks its API version (module notes).
    pub(super) fn hypervisor_present() -> PlatformReport {
        let device = match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/kvm")
        {
            Ok(device) => device,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return PlatformReport::DeviceMissing
            }
            Err(error) => {
                return PlatformReport::DeviceUnusable {
                    os_error: error.raw_os_error().unwrap_or(0),
                }
            }
        };
        // SAFETY: an open KVM device and an ioctl that takes no argument.
        let version = unsafe { libc::ioctl(device.as_raw_fd(), KVM_GET_API_VERSION as _, 0) };
        if version == KVM_API_VERSION {
            PlatformReport::Present
        } else {
            PlatformReport::UnexpectedApi { version }
        }
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod sys {
    use super::PlatformReport;

    pub(super) fn hypervisor_present() -> PlatformReport {
        PlatformReport::LibraryMissing
    }
}

/// The platform's report now.
pub fn platform_report() -> PlatformReport {
    sys::hypervisor_present()
}

/// The observation a platform report makes for `hypervisor` (module notes).
fn report_observation(
    report: PlatformReport,
    hypervisor: HypervisorKind,
    configuration: ConfigurationFingerprint,
) -> Observation {
    match report {
        PlatformReport::Present => Observation::supported(
            configuration,
            FRESH_FOR,
            SupportDetail::Hypervisor { hypervisor },
        ),
        PlatformReport::Absent
        | PlatformReport::LibraryMissing
        | PlatformReport::DeviceMissing
        | PlatformReport::DeviceUnusable { .. } => Observation::unsupported(
            configuration,
            FRESH_FOR,
            UnsupportedReason::HypervisorUnavailable,
        ),
        PlatformReport::CallFailed { .. } | PlatformReport::UnexpectedApi { .. } => {
            Observation::unknown(configuration, FRESH_FOR, UnknownReason::Inconclusive)
        }
    }
}

/// `HypervisorAvailable` for KVM on one Linux machine (module notes).
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub struct KvmProbe {
    pub machine: Digest,
    pub configuration: ConfigurationFingerprint,
}

impl ProbeAdapter for KvmProbe {
    fn capability(&self) -> Capability {
        Capability::HypervisorAvailable
    }

    fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    fn observes(&self, subject: &Subject) -> bool {
        matches!(subject, Subject::Hypervisor(target) if target.machine == self.machine
            && target.hypervisor == HypervisorKind::Kvm)
    }

    fn observe(&self, subject: &Subject) -> Observation {
        if !self.observes(subject) {
            return Observation::unknown(
                self.configuration,
                FRESH_FOR,
                UnknownReason::InconsistentReport,
            );
        }
        report_observation(platform_report(), HypervisorKind::Kvm, self.configuration)
    }
}

/// `HypervisorAvailable` for WHPX on one machine (module notes).
#[cfg_attr(not(windows), allow(dead_code))]
pub struct WhpxProbe {
    pub machine: Digest,
    pub configuration: ConfigurationFingerprint,
}

/// Hardware availability for the native HCS route. Permission is obtained by the
/// per-VM helper at launch; this probe does not claim the caller is elevated.
#[cfg(windows)]
pub struct HcsProbe { pub machine: Digest, pub configuration: ConfigurationFingerprint }
#[cfg(windows)]
impl ProbeAdapter for HcsProbe {
    fn capability(&self) -> Capability { Capability::HypervisorAvailable }
    fn source(&self) -> SourceClass { SourceClass::HostProbe }
    fn host_changes(&self) -> Vec<HostChange> { Vec::new() }
    fn observes(&self, subject: &Subject) -> bool { matches!(subject, Subject::Hypervisor(target) if target.machine == self.machine && target.hypervisor == HypervisorKind::Hcs) }
    fn observe(&self, subject: &Subject) -> Observation {
        if !self.observes(subject) { return Observation::unknown(self.configuration, FRESH_FOR, UnknownReason::InconsistentReport); }
        let system = std::env::var_os("SystemRoot").map(PathBuf::from).unwrap_or_default();
        let report = if system.join("System32/computecore.dll").is_file() { platform_report() } else { PlatformReport::LibraryMissing };
        report_observation(report, HypervisorKind::Hcs, self.configuration)
    }
}

impl ProbeAdapter for WhpxProbe {
    fn capability(&self) -> Capability {
        Capability::HypervisorAvailable
    }

    fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    fn observes(&self, subject: &Subject) -> bool {
        matches!(subject, Subject::Hypervisor(target) if target.machine == self.machine
            && target.hypervisor == HypervisorKind::Whpx)
    }

    fn observe(&self, subject: &Subject) -> Observation {
        if !self.observes(subject) {
            return Observation::unknown(
                self.configuration,
                FRESH_FOR,
                UnknownReason::InconsistentReport,
            );
        }
        report_observation(platform_report(), HypervisorKind::Whpx, self.configuration)
    }
}

/// `RuntimeCategory` for the pinned QEMU build this path runs (module notes).
pub struct PinnedRuntimeProbe {
    /// The runtime subject's instance digest.
    pub instance: Digest,
    /// The build's artifact identity: the executable's SHA-256.
    pub artifact: Digest,
    pub executable: PathBuf,
    pub configuration: ConfigurationFingerprint,
}

impl ProbeAdapter for PinnedRuntimeProbe {
    fn capability(&self) -> Capability {
        Capability::RuntimeCategory
    }

    fn source(&self) -> SourceClass {
        SourceClass::HostProbe
    }

    fn host_changes(&self) -> Vec<HostChange> {
        Vec::new()
    }

    fn observes(&self, subject: &Subject) -> bool {
        matches!(subject, Subject::Runtime(runtime) if runtime.instance == self.instance)
    }

    fn observe(&self, subject: &Subject) -> Observation {
        let Subject::Runtime(runtime) = subject else {
            return Observation::unknown(
                self.configuration,
                FRESH_FOR,
                UnknownReason::InconsistentReport,
            );
        };
        if runtime.instance != self.instance {
            return Observation::unknown(
                self.configuration,
                FRESH_FOR,
                UnknownReason::InconsistentReport,
            );
        }
        match sha256_file(&self.executable) {
            Ok(digest) if digest == self.artifact => Observation::supported(
                self.configuration,
                FRESH_FOR,
                SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox,
                },
            ),
            Ok(_) => Observation::unsupported(
                self.configuration,
                FRESH_FOR,
                UnsupportedReason::DifferentCategory,
            ),
            Err(_) => {
                Observation::unknown(self.configuration, FRESH_FOR, UnknownReason::Unreachable)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::foundation::evidence::{HypervisorSubject, ObservationResult};

    fn configuration() -> ConfigurationFingerprint {
        ConfigurationFingerprint::from_settings([("host", "test")]).unwrap()
    }

    /// PROVES the KVM probe observes only its machine's KVM, and reports what the kernel
    /// answers: a present device with API 12 is supported, a missing one unsupported.
    #[test]
    fn the_kvm_probe_observes_only_its_machines_kvm() {
        let machine = crate::foundation::ids::digest("yougori/test/machine/v1", &[b"m"]);
        let probe = KvmProbe {
            machine,
            configuration: configuration(),
        };
        let kvm = Subject::Hypervisor(HypervisorSubject {
            machine,
            hypervisor: HypervisorKind::Kvm,
        });
        assert!(probe.observes(&kvm));
        assert!(!probe.observes(&Subject::Hypervisor(HypervisorSubject {
            machine,
            hypervisor: HypervisorKind::Whpx,
        })));
        let observation = probe.observe(&kvm);
        eprintln!("KVM: {:?} -> {observation:?}", platform_report());
        assert_eq!(observation.configuration, configuration());
        assert!(matches!(
            report_observation(PlatformReport::Present, HypervisorKind::Kvm, configuration()).result,
            ObservationResult::Supported {
                detail: SupportDetail::Hypervisor {
                    hypervisor: HypervisorKind::Kvm
                }
            }
        ));
        assert!(matches!(
            report_observation(PlatformReport::DeviceMissing, HypervisorKind::Kvm, configuration())
                .result,
            ObservationResult::Unsupported {
                reason: UnsupportedReason::HypervisorUnavailable
            }
        ));
        assert!(matches!(
            report_observation(
                PlatformReport::UnexpectedApi { version: 11 },
                HypervisorKind::Kvm,
                configuration()
            )
            .result,
            ObservationResult::Unknown { .. }
        ));
    }

    #[test]
    fn the_whpx_probe_observes_only_its_machines_whpx() {
        let machine = crate::foundation::ids::digest("yougori/test/machine/v1", &[b"m"]);
        let probe = WhpxProbe {
            machine,
            configuration: configuration(),
        };
        assert!(probe.observes(&Subject::Hypervisor(HypervisorSubject {
            machine,
            hypervisor: HypervisorKind::Whpx,
        })));
        assert!(!probe.observes(&Subject::Hypervisor(HypervisorSubject {
            machine,
            hypervisor: HypervisorKind::Kvm,
        })));
        let other = crate::foundation::ids::digest("yougori/test/machine/v1", &[b"other"]);
        assert!(!probe.observes(&Subject::Hypervisor(HypervisorSubject {
            machine: other,
            hypervisor: HypervisorKind::Whpx,
        })));
        // On this host the platform answers; the answer is whatever the platform says, and
        // it is never a guess.
        let observation = probe.observe(&Subject::Hypervisor(HypervisorSubject {
            machine,
            hypervisor: HypervisorKind::Whpx,
        }));
        eprintln!("WHPX: {:?} -> {observation:?}", platform_report());
        assert_eq!(observation.configuration, configuration());
    }

    #[test]
    fn the_pinned_runtime_probe_judges_the_executables_bytes() {
        let directory = tempfile::tempdir().unwrap();
        let executable = directory.path().join("qemu.exe");
        std::fs::write(&executable, b"the pinned build").unwrap();
        let artifact = sha256_file(&executable).unwrap();
        let instance = crate::foundation::ids::digest("yougori/test/instance/v1", &[b"i"]);
        let probe = PinnedRuntimeProbe {
            instance,
            artifact,
            executable: executable.clone(),
            configuration: configuration(),
        };
        let subject = Subject::Runtime(crate::foundation::evidence::RuntimeSubject {
            category: ExecutionCategory::VmSandbox,
            release: crate::foundation::evidence::BackendRelease::new(
                crate::foundation::evidence::Backend::Qemu,
                "11.1.0",
            )
            .unwrap(),
            instance,
        });
        assert!(probe.observes(&subject));
        assert!(matches!(
            probe.observe(&subject).result,
            ObservationResult::Supported {
                detail: SupportDetail::RuntimeCategory {
                    category: ExecutionCategory::VmSandbox
                }
            }
        ));
        std::fs::write(&executable, b"another build").unwrap();
        assert!(matches!(
            probe.observe(&subject).result,
            ObservationResult::Unsupported {
                reason: UnsupportedReason::DifferentCategory
            }
        ));
        std::fs::remove_file(&executable).unwrap();
        assert!(matches!(
            probe.observe(&subject).result,
            ObservationResult::Unknown { .. }
        ));
    }
}
