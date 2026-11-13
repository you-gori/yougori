//! The pinned inputs of the restricted VM path, verified before anything boots (module
//! docs in `mod.rs`; M01's "boot the selected image rather than accepting an arbitrary
//! declared image"; VM-CP-02's golden file; VM-CP-17's pinned kernel):
//!
//! - the guest artifacts record `runtime/sandbox-guest/artifacts.json`, written by
//!   `scripts/build-guest.sh` (`yougori-guest-artifacts/v1`), read strictly; the initrd
//!   and root image beside it and the pinned appliance kernel are hashed and must be the
//!   record's; the root image's SHA-256 is the guest image identity every launch pins, and
//!   the record's link protocol must be the host's;
//! - the pinned QEMU executable, hashed and compared with `runtime/qemu-secure/SHA256SUMS`;
//!   the digest is the backend's artifact identity (`qemu-system-x86_64.exe` on Windows,
//!   `qemu-system-x86_64` on Linux, whose `qemu-secure` also holds the libraries it loads);
//! - the release's golden file of this platform's x86-64 profile,
//!   `runtime/sandbox-guest/qemu-windows-x86_64.golden.json` (or `qemu-linux-...`), read
//!   strictly; its digest is checked by the backend before every launch.
//!
//! A record that is not exactly what was built, a file whose bytes differ from the record,
//! a kernel that is not the pinned one or a golden file for another build refuses the
//! whole service: there is no "declared" image here, only verified bytes. The signed
//! feature manifest and the catalog's storage of these artifacts (M01 with S02/S08) stay
//! open; this verification is the host's own hash of each file against a record that is
//! itself part of the pinned, checksummed runtime.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use sha2::{Digest as _, Sha256};

use crate::foundation::ids::Digest;
use crate::sandbox::link::PROTOCOL_VERSION;
use crate::sandbox::qemu::{GoldenFile, KernelArguments};
use crate::sandbox_contract::confinement::{KernelOption, OptionState};

/// The directory under the runtime that holds the guest artifacts and the golden file.
pub const GUEST_DIRECTORY: &str = "sandbox-guest";
/// The guest artifacts record the build writes.
pub const RECORD_NAME: &str = "artifacts.json";
/// The record format this module reads.
pub const RECORD_FORMAT: &str = "yougori-guest-artifacts/v1";
/// The golden file of this platform's x86-64 profile.
#[cfg(windows)]
pub const GOLDEN_NAME: &str = "qemu-windows-x86_64.golden.json";
#[cfg(not(windows))]
pub const GOLDEN_NAME: &str = "qemu-linux-x86_64.golden.json";
/// The guest directory's checksum list (`sha256sum` output over every shipped file).
pub const GUEST_SUMS: &str = "SHA256SUMS";
/// The pinned kernel, shared with the appliance.
pub const KERNEL_PATH: &str = "appliance/vmlinuz-virt";
/// The pinned QEMU executable, its name in the checksum list, and the list.
#[cfg(windows)]
pub const EXECUTABLE_PATH: &str = "qemu-secure/qemu-system-x86_64.exe";
#[cfg(windows)]
const EXECUTABLE_NAME: &str = "qemu-system-x86_64.exe";
#[cfg(not(windows))]
pub const EXECUTABLE_PATH: &str = "qemu-secure/qemu-system-x86_64";
#[cfg(not(windows))]
const EXECUTABLE_NAME: &str = "qemu-system-x86_64";
pub const EXECUTABLE_SUMS: &str = "qemu-secure/SHA256SUMS";
/// The most bytes read of any record or checksum list.
const MAX_RECORD_BYTES: u64 = 1 << 20;

/// One built artifact as the record names it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactEntry {
    pub name: String,
    pub role: String,
    pub sha256: String,
    pub content_key: String,
    pub bytes: u64,
    pub version: String,
    /// Provenance the build records (read by people and the evidence, not the launch).
    #[allow(dead_code)]
    pub source: String,
}

/// One kernel module in the initrd: provenance the strict record carries; the launch
/// verifies the initrd that contains it as a whole.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct ModuleEntry {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

/// One pinned input of the build: provenance the strict record carries.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct InputEntry {
    pub path: String,
    pub sha256: String,
    /// A file's length; absent for a source tree, whose digest covers its files.
    #[serde(default)]
    pub bytes: Option<u64>,
    /// How many files a source tree's digest covers; absent for one file.
    #[serde(default)]
    pub files: Option<u64>,
    pub note: String,
}

/// The guest artifacts record, exactly as `guest/guest_build.py` writes it.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(dead_code)]
pub struct GuestArtifactsRecord {
    pub format: String,
    pub profile: String,
    pub source_date_epoch: u64,
    pub kernel_release: String,
    pub kernel_version: String,
    pub kernel_arguments: Vec<String>,
    pub init: String,
    /// The content key of the agent executable, which the guest's hello carries as its
    /// agent build.
    pub agent_build: String,
    pub link_protocol: u8,
    pub artifacts: Vec<ArtifactEntry>,
    pub modules: Vec<ModuleEntry>,
    pub inputs: Vec<InputEntry>,
    pub toolchain: Vec<String>,
    pub commands: Vec<String>,
}

/// The guest a launch boots, every file verified against the record.
#[derive(Clone, Debug)]
pub struct VerifiedGuest {
    pub kernel: PathBuf,
    pub initrd: PathBuf,
    pub root_image: PathBuf,
    pub kernel_arguments: KernelArguments,
    /// The root image's SHA-256: the guest image identity a launch pins.
    pub guest_image: Digest,
    pub kernel_digest: Digest,
    pub initrd_digest: Digest,
    /// The agent build the guest's hello should carry.
    pub agent_build: Digest,
    /// The record file's own SHA-256.
    pub record_digest: Digest,
    pub kernel_release: String,
    pub profile: String,
    /// The kernel configuration the record names (role `kernel_configuration`), hashed and
    /// compared with the record: its SHA-256, and the state of every confinement-relevant
    /// option it states (VM-CP-05's host corroboration: build facts of the booted kernel,
    /// never the guest's word). An option the file does not state is left out.
    pub kernel_configuration_digest: Digest,
    pub kernel_options: Vec<(KernelOption, OptionState)>,
}

/// The state of every [`KernelOption`] a kernel configuration file states: `=y`, `=m` or
/// `# ... is not set`. An option the file does not mention is left out, never guessed.
pub fn kernel_options_of(configuration: &str) -> Vec<(KernelOption, OptionState)> {
    KernelOption::ALL
        .into_iter()
        .filter_map(|option| {
            let name = option.config_name();
            let unset = format!("# {name} is not set");
            configuration
                .lines()
                .map(str::trim)
                .find_map(|line| {
                    if line == unset {
                        return Some(OptionState::NotSet);
                    }
                    match line.strip_prefix(name)?.strip_prefix('=')? {
                        "y" => Some(OptionState::BuiltIn),
                        "m" => Some(OptionState::Module),
                        _ => None,
                    }
                })
                .map(|state| (option, state))
        })
        .collect()
}

/// Why the pinned inputs were refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactRefusal {
    pub detail: String,
}

impl std::fmt::Display for ArtifactRefusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.detail)
    }
}

impl std::error::Error for ArtifactRefusal {}

fn refuse(detail: impl Into<String>) -> ArtifactRefusal {
    ArtifactRefusal {
        detail: detail.into(),
    }
}

/// The SHA-256 of the file at `path`, read in bounded chunks; the file must be a regular
/// file reached without following a link.
pub fn sha256_file(path: &Path) -> Result<Digest, ArtifactRefusal> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        refuse(format!(
            "{} could not be inspected: {error}",
            path.display()
        ))
    })?;
    if !metadata.is_file() {
        return Err(refuse(format!(
            "{} is not a regular file (links are never followed)",
            path.display()
        )));
    }
    let mut file = fs::File::open(path)
        .map_err(|error| refuse(format!("{} could not be read: {error}", path.display())))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| refuse(format!("{} could not be read: {error}", path.display())))?;
        if read == 0 {
            break;
        }
        hasher.update(buffer.get(..read).unwrap_or_default());
    }
    Ok(Digest::from_bytes(hasher.finalize().into()))
}

fn parse_digest(text: &str, what: &str) -> Result<Digest, ArtifactRefusal> {
    Digest::from_hex(text.trim())
        .map_err(|error| refuse(format!("{what} is not a digest: {error}")))
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, ArtifactRefusal> {
    let file = fs::File::open(path)
        .map_err(|error| refuse(format!("{} could not be read: {error}", path.display())))?;
    let mut bytes = Vec::new();
    file.take(MAX_RECORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| refuse(format!("{} could not be read: {error}", path.display())))?;
    if bytes.len() as u64 > MAX_RECORD_BYTES {
        return Err(refuse(format!(
            "{} is larger than {MAX_RECORD_BYTES} bytes",
            path.display()
        )));
    }
    Ok(bytes)
}

/// Reads the record and verifies every file it names that a launch uses.
pub fn verify_guest(runtime: &Path) -> Result<VerifiedGuest, ArtifactRefusal> {
    let directory = runtime.join(GUEST_DIRECTORY);
    let record_path = directory.join(RECORD_NAME);
    let record_bytes = read_bounded(&record_path)?;
    let record_digest = Digest::from_bytes(Sha256::digest(&record_bytes).into());
    let record_pinned = guest_pin(runtime, RECORD_NAME)?;
    if record_digest != record_pinned {
        return Err(refuse(format!(
            "the guest artifacts record {} is not the pinned one (its SHA-256 is {}, the checksum list says {})",
            record_path.display(),
            record_digest.to_hex(),
            record_pinned.to_hex()
        )));
    }
    let record: GuestArtifactsRecord = serde_json::from_slice(&record_bytes).map_err(|error| {
        refuse(format!(
            "{} is not a guest artifacts record: {error}",
            record_path.display()
        ))
    })?;
    if record.format != RECORD_FORMAT {
        return Err(refuse(format!(
            "the guest artifacts record is {}, not {RECORD_FORMAT}",
            record.format
        )));
    }
    if record.link_protocol != PROTOCOL_VERSION {
        return Err(refuse(format!(
            "the guest speaks link protocol {}; this host speaks {PROTOCOL_VERSION}",
            record.link_protocol
        )));
    }
    let entry = |role: &str| -> Result<&ArtifactEntry, ArtifactRefusal> {
        record
            .artifacts
            .iter()
            .find(|artifact| artifact.role == role)
            .ok_or_else(|| refuse(format!("the guest artifacts record names no {role}")))
    };
    let kernel_entry = entry("kernel")?;
    if kernel_entry.version != record.kernel_release {
        return Err(refuse(format!(
            "the record's kernel is {}, but the record was built for {}",
            kernel_entry.version, record.kernel_release
        )));
    }
    let initrd_entry = entry("initrd")?;
    let root_entry = entry("root_image")?;
    let agent_entry = entry("agent")?;
    let kernel = runtime.join(KERNEL_PATH);
    let initrd = directory.join(&initrd_entry.name);
    let root_image = directory.join(&root_entry.name);
    for name in [&initrd_entry.name, &root_entry.name] {
        if name.is_empty() || name.contains(['/', '\\']) || name.starts_with('.') {
            return Err(refuse(format!(
                "the record names an artifact as {name:?}, not a plain file name"
            )));
        }
    }
    let mut checked = Vec::new();
    for (what, path, entry) in [
        ("kernel", &kernel, kernel_entry),
        ("initrd", &initrd, initrd_entry),
        ("root image", &root_image, root_entry),
    ] {
        let expected = parse_digest(&entry.sha256, &format!("the record's {what} digest"))?;
        let actual = sha256_file(path)?;
        if actual != expected {
            return Err(refuse(format!(
                "the {what} {} is not the one the record names (its SHA-256 is {}, the record says {})",
                path.display(),
                actual.to_hex(),
                expected.to_hex()
            )));
        }
        let length = fs::metadata(path)
            .map(|metadata| metadata.len())
            .unwrap_or(0);
        if length != entry.bytes {
            return Err(refuse(format!(
                "the {what} {} is {length} bytes; the record says {}",
                path.display(),
                entry.bytes
            )));
        }
        checked.push(actual);
    }
    let kernel_arguments =
        KernelArguments::parse(&record.kernel_arguments.join(" ")).map_err(|error| {
            refuse(format!(
                "the record's kernel arguments were refused: {error}"
            ))
        })?;
    // The kernel configuration: the build facts the host corroborates a guest's
    // confinement report with.
    let configuration_entry = entry("kernel_configuration")?;
    let configuration_name = &configuration_entry.name;
    if configuration_name.is_empty()
        || configuration_name.contains(['/', '\\'])
        || configuration_name.starts_with('.')
    {
        return Err(refuse(format!(
            "the record names the kernel configuration as {configuration_name:?}, not a plain file name"
        )));
    }
    let configuration_path = directory.join(configuration_name);
    let configuration_bytes = read_bounded(&configuration_path)?;
    let kernel_configuration_digest =
        Digest::from_bytes(Sha256::digest(&configuration_bytes).into());
    let configuration_expected = parse_digest(
        &configuration_entry.sha256,
        "the record's kernel configuration digest",
    )?;
    if kernel_configuration_digest != configuration_expected
        || configuration_bytes.len() as u64 != configuration_entry.bytes
    {
        return Err(refuse(format!(
            "the kernel configuration {} is not the one the record names",
            configuration_path.display()
        )));
    }
    let kernel_options = kernel_options_of(&String::from_utf8_lossy(&configuration_bytes));
    let agent_build = parse_digest(&record.agent_build, "the record's agent build")?;
    if agent_build != parse_digest(&agent_entry.content_key, "the agent's content key")? {
        return Err(refuse(
            "the record's agent build is not the agent artifact's content key",
        ));
    }
    Ok(VerifiedGuest {
        kernel,
        initrd,
        root_image,
        kernel_arguments,
        guest_image: checked[2],
        kernel_digest: checked[0],
        initrd_digest: checked[1],
        agent_build,
        record_digest,
        kernel_release: record.kernel_release,
        profile: record.profile,
        kernel_configuration_digest,
        kernel_options,
    })
}

/// The digest a checksum list (`sha256sum` output) pins for one file name.
fn pinned_in(sums_path: &Path, name: &str) -> Result<Digest, ArtifactRefusal> {
    let sums = read_bounded(sums_path)?;
    let sums = std::str::from_utf8(&sums)
        .map_err(|error| refuse(format!("{} is not UTF-8: {error}", sums_path.display())))?;
    let pinned = sums
        .lines()
        .filter_map(|line| line.split_once(char::is_whitespace))
        .find(|(_, listed)| listed.trim().trim_start_matches('*') == name)
        .map(|(digest, _)| digest)
        .ok_or_else(|| refuse(format!("{} does not pin {name}", sums_path.display())))?;
    parse_digest(pinned, &format!("the pinned digest of {name}"))
}

/// The guest directory's own checksum list, which pins the record and the golden file.
fn guest_pin(runtime: &Path, name: &str) -> Result<Digest, ArtifactRefusal> {
    pinned_in(&runtime.join(GUEST_DIRECTORY).join(GUEST_SUMS), name)
}

/// Whether the pinned QEMU build and the guest's record are installed under `runtime`, without
/// hashing anything: what the setup catalogue asks. A launch verifies every file.
pub fn installed(runtime: &Path) -> bool {
    runtime.join(EXECUTABLE_PATH).is_file()
        && runtime.join(EXECUTABLE_SUMS).is_file()
        && runtime.join(GUEST_DIRECTORY).join(RECORD_NAME).is_file()
        && runtime.join(GUEST_DIRECTORY).join(GUEST_SUMS).is_file()
}

/// The pinned QEMU executable: its path, and its SHA-256 as hashed now, which must be the
/// one its checksum list records.
pub fn pinned_executable(runtime: &Path) -> Result<(PathBuf, Digest), ArtifactRefusal> {
    let executable = runtime.join(EXECUTABLE_PATH);
    let pinned = pinned_in(&runtime.join(EXECUTABLE_SUMS), EXECUTABLE_NAME)?;
    let actual = sha256_file(&executable)?;
    if actual != pinned {
        return Err(refuse(format!(
            "the QEMU executable {} is not the pinned build (its SHA-256 is {}, the checksum list says {})",
            executable.display(),
            actual.to_hex(),
            pinned.to_hex()
        )));
    }
    Ok((executable, actual))
}

/// The release's golden file of this platform's x86-64 profile.
pub fn load_golden(runtime: &Path) -> Result<GoldenFile, ArtifactRefusal> {
    let path = runtime.join(GUEST_DIRECTORY).join(GOLDEN_NAME);
    let bytes = read_bounded(&path)?;
    let actual = Digest::from_bytes(Sha256::digest(&bytes).into());
    let pinned = guest_pin(runtime, GOLDEN_NAME)?;
    if actual != pinned {
        return Err(refuse(format!(
            "the golden file {} is not the pinned one (its SHA-256 is {}, the checksum list says {})",
            path.display(),
            actual.to_hex(),
            pinned.to_hex()
        )));
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| refuse(format!("{} is not a golden file: {error}", path.display())))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PROVES the kernel configuration's options are read exactly as stated: built in,
    /// module, not set, and an option the file does not mention left out; a longer name
    /// that starts with an option's name is not taken for it.
    #[test]
    fn kernel_options_are_read_as_the_configuration_states_them() {
        let options = kernel_options_of(
            "CONFIG_IO_URING=y\nCONFIG_KEXEC_FILE=y\n# CONFIG_KEXEC is not set\nCONFIG_VSOCKETS=m\nCONFIG_MODULES=y\n",
        );
        assert_eq!(
            options,
            vec![
                (KernelOption::IoUring, OptionState::BuiltIn),
                (KernelOption::Kexec, OptionState::NotSet),
                (KernelOption::KexecFile, OptionState::BuiltIn),
                (KernelOption::Modules, OptionState::BuiltIn),
                (KernelOption::Vsockets, OptionState::Module),
            ]
        );
    }

    /// The source checkout's runtime directory, with the shipped artifacts (the Windows
    /// runtime: the checkout ships no Linux QEMU, so the tests of shipped files are
    /// Windows's).
    fn runtime() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("resources/runtime")
    }

    /// The golden file of this platform's profile for the pinned build: its canonical vector,
    /// in which every value a launch fills in is a placeholder, from a plan made over the
    /// launch fixture's evidence (`qemu_host::launch_fixture`) with stand-in paths, under the
    /// version the engine pins for this platform.
    fn golden_of_this_platform() -> GoldenFile {
        use super::super::engine::{GUEST_MEMORY_BYTES, GUEST_VCPUS, HOST_OS, QEMU_VERSION};
        use crate::foundation::ids::digest;
        use crate::sandbox::backend::{Architecture, Persistence};
        use crate::sandbox::qemu::{
            plan_launch, GuestResources, HostPath, PathStyle, PrivateDirectory, QemuLaunchInputs,
            QemuPlatform,
        };
        use crate::sandbox::qemu_host::launch_fixture::{launch, LaunchValues, GIB};
        let launch = launch(LaunchValues {
            os: HOST_OS,
            execution: "exe-golden",
            guest_image: digest("yougori/golden/image/v1", &[b"guest"]),
            artifact: digest("yougori/golden/backend/v1", &[b"qemu"]),
            version: QEMU_VERSION,
            reserved_ram_bytes: GIB,
            persistence: Persistence::EphemeralTask,
        });
        let path = |name: &str| {
            if cfg!(windows) {
                HostPath::new(PathStyle::Windows, format!(r"C:\golden\{name}")).unwrap()
            } else {
                HostPath::new(PathStyle::Unix, format!("/golden/{name}")).unwrap()
            }
        };
        let inputs = QemuLaunchInputs {
            platform: QemuPlatform {
                os: HOST_OS,
                architecture: Architecture::X86_64,
            },
            resources: GuestResources::new(GUEST_VCPUS, GUEST_MEMORY_BYTES).unwrap(),
            firmware_directory: path("share"),
            kernel: path("vmlinuz"),
            initrd: Some(path("initrd")),
            kernel_arguments: KernelArguments::parse("panic=-1 quiet").unwrap(),
            root_image: path("root.img"),
            volumes: std::collections::BTreeMap::new(),
            control: PrivateDirectory::new(path("vm")).unwrap(),
            vsock_cid: None,
            egress_endpoints: Vec::new(),
            workload_image: None,
            targets: None,
        };
        let plan = plan_launch(
            &launch.request,
            &launch.backend,
            &launch.registry,
            &launch.ledger,
            inputs,
        )
        .unwrap();
        GoldenFile::of(plan.profile(), &launch.backend).unwrap()
    }

    #[cfg(windows)]
    #[test]
    fn the_shipped_guest_artifacts_are_the_ones_their_record_names() {
        let guest = verify_guest(&runtime()).unwrap();
        assert_eq!(guest.kernel_release, "6.18.58-0-virt");
        assert_eq!(guest.profile, "sandbox-minimal");
        assert_eq!(
            guest.kernel_digest.to_hex(),
            "17fbd3efd16f2e7cb1b945f06423b37399ba7d5ac8cdd3665e7f13f363500e85"
        );
        assert!(guest.initrd.ends_with("initrd"));
        assert!(guest.root_image.ends_with("root.img"));
        assert_eq!(guest.kernel_arguments.command_line(), "panic=-1 quiet");
    }

    #[cfg(windows)]
    #[test]
    fn the_pinned_executable_is_the_one_its_checksum_list_names() {
        let (path, digest) = pinned_executable(&runtime()).unwrap();
        assert!(path.ends_with("qemu-system-x86_64.exe"));
        assert_eq!(
            digest.to_hex(),
            "16cd6270a3784d0c21415499d25faf75e1585a1fc81990e13ece6b9bee7f8dac"
        );
    }

    /// Writes the release's golden file of this platform's x86-64 profile for the pinned
    /// build, when asked: the golden file of a plan of the same profile, which is the same
    /// for every launch (the canonical vector replaces each per-launch value), under the
    /// backend version the pinned QEMU reports. `YOUGORI_WRITE_GOLDEN=1` writes the source
    /// checkout's runtime; any other value is the runtime directory to write (a staged Linux
    /// runtime). The guest directory's checksum list is written anew to pin it.
    #[test]
    #[ignore = "writes a runtime's sandbox-guest; run with YOUGORI_WRITE_GOLDEN=1 (or a runtime path) --ignored"]
    fn write_the_production_golden_file() {
        let Some(asked) = std::env::var_os("YOUGORI_WRITE_GOLDEN") else {
            return;
        };
        let runtime = if asked == "1" {
            runtime()
        } else {
            PathBuf::from(asked)
        };
        let golden = golden_of_this_platform();
        let path = runtime.join(GUEST_DIRECTORY).join(GOLDEN_NAME);
        let mut text = serde_json::to_string_pretty(&golden).unwrap();
        text.push('\n');
        fs::write(&path, text).unwrap();
        // The checksum list pins every shipped file, the golden file included.
        let directory = runtime.join(GUEST_DIRECTORY);
        let mut names: Vec<String> = fs::read_dir(&directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .filter(|name| name != GUEST_SUMS)
            .collect();
        names.sort();
        let mut sums = String::new();
        for name in names {
            let digest = sha256_file(&directory.join(&name)).unwrap();
            sums.push_str(&format!("{} *{name}\n", digest.to_hex()));
        }
        fs::write(directory.join(GUEST_SUMS), sums).unwrap();
        assert_eq!(load_golden(&runtime).unwrap(), golden);
    }

    #[cfg(windows)]
    #[test]
    fn the_shipped_golden_file_is_the_one_this_builds_profile_makes() {
        let shipped = load_golden(&runtime()).unwrap();
        assert_eq!(
            shipped,
            golden_of_this_platform(),
            "regenerate with YOUGORI_WRITE_GOLDEN=1"
        );
        // The service's test harness plans with the same file.
        let clock = std::sync::Arc::new(crate::foundation::ids::ManualClock::new(
            crate::foundation::ids::MonotonicTime::ZERO,
        ));
        assert_eq!(shipped, crate::sandbox::vm_service::fakes::golden(&clock));
    }

    /// PROVES this platform's golden file is the platform's own: its OS, the version the
    /// engine pins and the hypervisor's accelerator, and that it reads back as written.
    #[test]
    fn this_platforms_golden_file_names_its_platform() {
        let golden = golden_of_this_platform();
        assert_eq!(golden.os, super::super::engine::HOST_OS);
        assert_eq!(
            golden.backend_version.as_str(),
            super::super::engine::QEMU_VERSION
        );
        let accelerator = if cfg!(windows) { "whpx" } else { "kvm" };
        assert!(golden
            .arguments
            .windows(2)
            .any(|pair| pair[0] == "-accel" && pair[1].starts_with(accelerator)));
        golden.verify().unwrap();
        let text = serde_json::to_string(&golden).unwrap();
        assert_eq!(serde_json::from_str::<GoldenFile>(&text).unwrap(), golden);
    }

    #[cfg(windows)]
    #[test]
    fn the_shipped_golden_file_reads_strictly() {
        let golden = load_golden(&runtime()).unwrap();
        assert_eq!(golden.backend_version.as_str(), "11.1.0");
        assert!(!golden.arguments.is_empty());
    }

    #[cfg(windows)]
    #[test]
    fn a_changed_file_or_record_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path();
        fs::create_dir_all(runtime.join(GUEST_DIRECTORY)).unwrap();
        fs::create_dir_all(runtime.join("appliance")).unwrap();
        let source = super::super::artifacts::tests::runtime();
        // Every pinned file of the guest directory: the images, the record, the golden file,
        // the checksum list and the kernel configuration.
        for entry in fs::read_dir(source.join(GUEST_DIRECTORY)).unwrap() {
            let entry = entry.unwrap();
            fs::copy(
                entry.path(),
                runtime.join(GUEST_DIRECTORY).join(entry.file_name()),
            )
            .unwrap();
        }
        fs::copy(source.join(KERNEL_PATH), runtime.join(KERNEL_PATH)).unwrap();
        let verified = verify_guest(runtime).unwrap();
        // The shipped kernel's build facts as its configuration states them.
        assert!(verified
            .kernel_options
            .contains(&(KernelOption::IoUring, OptionState::BuiltIn)));
        assert!(verified
            .kernel_options
            .contains(&(KernelOption::Userfaultfd, OptionState::NotSet)));
        // The kernel configuration is part of the pinned guest: a changed one is refused.
        let configuration = fs::read_dir(runtime.join(GUEST_DIRECTORY))
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .find(|path| {
                path.file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("config-"))
            })
            .unwrap();
        let original = fs::read(&configuration).unwrap();
        let mut changed = original.clone();
        changed.extend_from_slice(
            b"# CONFIG_IO_URING is not set
",
        );
        fs::write(&configuration, &changed).unwrap();
        let refused = verify_guest(runtime).unwrap_err();
        assert!(refused.detail.contains("kernel configuration"), "{refused}");
        fs::write(&configuration, &original).unwrap();
        assert!(verify_guest(runtime).is_ok());
        // One byte of the root image.
        let root = runtime.join(GUEST_DIRECTORY).join("root.img");
        // fs::copy preserves the packaged image's read-only Windows attribute.
        // Make only this disposable copy writable for the corruption probe.
        let mut permissions = fs::metadata(&root).unwrap().permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&root, permissions).unwrap();
        let mut bytes = fs::read(&root).unwrap();
        bytes[100] ^= 1;
        fs::write(&root, &bytes).unwrap();
        let refused = verify_guest(runtime).unwrap_err();
        assert!(refused.detail.contains("root image"), "{refused}");
        bytes[100] ^= 1;
        fs::write(&root, &bytes).unwrap();
        assert!(verify_guest(runtime).is_ok());
        // A record with an unknown field.
        let record_path = runtime.join(GUEST_DIRECTORY).join(RECORD_NAME);
        let mut record: serde_json::Value =
            serde_json::from_slice(&fs::read(&record_path).unwrap()).unwrap();
        record["extra"] = serde_json::json!(1);
        let original = fs::read(&record_path).unwrap();
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        let refused = verify_guest(runtime).unwrap_err();
        assert!(refused.detail.contains("not the pinned one"), "{refused}");
        fs::write(&record_path, &original).unwrap();
        assert!(verify_guest(runtime).is_ok());
        // A golden file whose bytes changed, and a checksum list that no longer pins it.
        let golden_path = runtime.join(GUEST_DIRECTORY).join(GOLDEN_NAME);
        assert!(load_golden(runtime).is_ok());
        let mut golden = fs::read(&golden_path).unwrap();
        golden.push(b' ');
        fs::write(&golden_path, &golden).unwrap();
        let refused = load_golden(runtime).unwrap_err();
        assert!(refused.detail.contains("golden file"), "{refused}");
        let sums_path = runtime.join(GUEST_DIRECTORY).join(GUEST_SUMS);
        fs::write(&sums_path, "").unwrap();
        let refused = verify_guest(runtime).unwrap_err();
        assert!(refused.detail.contains("does not pin"), "{refused}");
    }
}
