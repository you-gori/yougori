//! From what the host read about a running jail to the facts admission judges (VM-CP-01
//! line 3151: the actual accelerator; VM-CP-02 line 3152: the configuration against the
//! golden file; VM-CP-04 line 3154: the jailed process against the expected state; §8.1:
//! host-observed facts only).
//!
//! - The accelerator is KVM only when the host sees the Firecracker process hold a KVM
//!   VM descriptor (`anon_inode:kvm-vm` among the targets of `/proc/<pid>/fd`). Firecracker
//!   has no emulator, so anything else is "not observed", never emulation.
//! - VM-CP-04's typed observed state comes from the strict status parser, one cgroup v2
//!   line, the interfaces of the process's network namespace, the cgroup's files and the
//!   number of descriptors. The chroot is observed apart, from `/proc/<pid>/root`, and is
//!   what shows filesystem limits, which VM-CP-04 does not.
//! - VM-CP-02's observed side is the API calls as the port wrote them, Firecracker's
//!   arguments as the launcher executed them, and the version the running Firecracker
//!   reports. Once it matches the golden file, admission takes the comparison as the
//!   digests of the golden file and of the running configuration with the device flags
//!   from the check's forbidden items, and VM-CP-03's listing of the API socket in the
//!   jail's socket directory (line 3153; `sandbox::backend`'s configuration facts).
//! - The remaining facets follow from what the backend observed and what Firecracker can
//!   express: a configuration that matches the golden file has no metadata service,
//!   shared filesystem, display or assigned device and only the read-only root drive, so
//!   no credentials, an ephemeral task, a CPU-only inventory and no confidentiality claim.
//!   Without a declared interface, VM-CP-04 shows only `lo`, so the VM is offline; with
//!   one, which channels the host enforces is the perimeter's to show, so the network is
//!   not observed here.

use std::collections::BTreeSet;
use std::time::Duration;

use super::api::ApiCall;
use super::golden::{ForbiddenItem, GoldenCheck, GoldenFile};
use super::layout;
use super::linux_state::ObservedLinuxState;
use super::names::JailPath;
use super::ports::{HostState, InstanceInfo, ProcessObservation};
use super::refusal::FirecrackerRefusal;
use super::status::{parse_status, MAX_STATUS_BYTES};
use crate::foundation::evidence::{
    ClockReading, ConfigurationFingerprint, HypervisorKind, UnknownReason,
};
use crate::foundation::ids::Digest;
use crate::foundation::process::ProcessIdentity;
use crate::sandbox::backend::{
    Accelerator, ConfigurationComparison, ConfigurationFacts, ConfinementControl,
    CredentialExposure, DeviceInventory, GuestAssertions, HostFact, HostInterfaceListing,
    HostObserved, IsolationObservation, LaunchFacts, NetworkAuthority, ObservedProperties,
    OperatorConfidentiality, Persistence, PhysicalHost,
};
use crate::sandbox::trust::ComponentVersion;

/// The descriptor target of a KVM VM, as `/proc/<pid>/fd` shows it.
pub const KVM_VM_DESCRIPTOR: &str = "anon_inode:kvm-vm";
/// The state Firecracker reports once the instance started.
pub const RUNNING_STATE: &str = "Running";
/// Firecracker's argument naming the Unix socket it serves its API on.
const API_SOCKET_FLAG: &str = "--api-sock";

/// Whether the descriptors include a KVM VM.
pub fn holds_kvm_vm(descriptors: &[String]) -> bool {
    descriptors.iter().any(|target| target == KVM_VM_DESCRIPTOR)
}

/// The cgroup v2 path of a `/proc/<pid>/cgroup` text: exactly one line `0::<path>`, the
/// path absolute and without control characters, ending with a newline.
pub fn cgroup_path(text: &str) -> Result<&str, FirecrackerRefusal> {
    let refused = || FirecrackerRefusal::CgroupUnreadable {
        text: text.to_owned(),
    };
    if text.len() > MAX_STATUS_BYTES {
        return Err(refused());
    }
    let path = text
        .strip_suffix('\n')
        .and_then(|line| line.strip_prefix("0::"))
        .ok_or_else(refused)?;
    if !path.starts_with('/') || path.chars().any(char::is_control) {
        return Err(refused());
    }
    Ok(path)
}

/// VM-CP-04's observed state of `process`, from what the host read. The status must
/// parse strictly and name the process's own PID.
pub(super) fn linux_state(
    observation: &ProcessObservation,
    process: &ProcessIdentity,
) -> Result<ObservedLinuxState, FirecrackerRefusal> {
    let status = parse_status(&observation.status)
        .map_err(|error| FirecrackerRefusal::StatusUnreadable { error })?;
    if status.pid != process.pid {
        return Err(FirecrackerRefusal::StatusOfAnotherProcess {
            process: *process,
            pid: status.pid,
        });
    }
    let cgroup = cgroup_path(&observation.cgroup)?.to_owned();
    Ok(ObservedLinuxState {
        status,
        network_interfaces: observation.network_interfaces.clone(),
        cgroup,
        cgroup_files: observation.cgroup_files.clone(),
        open_descriptors: observation.descriptors.len() as u64,
    })
}

/// VM-CP-02's observed configuration: the calls as sent and Firecracker's arguments, under
/// the version the running Firecracker reports. Refused when Firecracker describes itself
/// as another instance, as not running, or with a version that is not an exact version.
pub(super) fn running_configuration(
    expected_id: &str,
    info: &InstanceInfo,
    sent: &[ApiCall],
    firecracker_args: &[String],
) -> Option<GoldenFile> {
    if info.id != expected_id || info.state != RUNNING_STATE {
        return None;
    }
    let version = ComponentVersion::new(info.vmm_version.clone()).ok()?;
    Some(GoldenFile::from_calls(&version, sent, firecracker_args))
}

/// VM-CP-02's comparison as admission takes it (line 3152): the digests of the approved
/// golden file and of the running configuration, equal exactly when the running
/// configuration is the golden file's, and the devices the row names, from `check`'s
/// forbidden items: a network interface the profile does not declare, a console, a balloon
/// and the PCI transport. `check` is [`GoldenCheck::run`] of `golden` and `running`.
pub(super) fn configuration_comparison(
    golden: &GoldenFile,
    running: &GoldenFile,
    check: &GoldenCheck,
) -> ConfigurationComparison {
    let found = |item: fn(&ForbiddenItem) -> bool| check.forbidden.iter().any(item);
    ConfigurationComparison {
        golden: golden.digest(),
        observed: running.digest(),
        network_device: found(|item| {
            matches!(item, ForbiddenItem::UndeclaredNetworkInterface { .. })
        }),
        console: found(|item| *item == ForbiddenItem::Console),
        balloon: found(|item| *item == ForbiddenItem::Balloon),
        undeclared_pci_transport: found(|item| *item == ForbiddenItem::PciTransport),
    }
}

/// The socket Firecracker's arguments name for its API: the value after the one
/// `--api-sock`; `None` without exactly one, or without a value after it.
fn api_socket<'a>(args: &[&'a str]) -> Option<&'a str> {
    let mut flags = args
        .iter()
        .enumerate()
        .filter(|(_, arg)| **arg == API_SOCKET_FLAG);
    let (Some((index, _)), None) = (flags.next(), flags.next()) else {
        return None;
    };
    args.get(index + 1).copied()
}

/// VM-CP-03's listing of Firecracker's host interfaces (line 3153), from its running
/// configuration and the jail's layout:
///
/// - the API socket is private when Firecracker's arguments name exactly one and it lies
///   in the jail's socket directory ([`layout::SOCKET_DIRECTORY`]), which the launcher
///   creates for the jail and the host owner's group only;
/// - Firecracker has no host filesystem share device (no 9p, virtiofs or HGFS
///   equivalent), serves its API on that Unix socket and on no network listener, and
///   forwards no host port (a declared interface is a tap device in the jail's own
///   network namespace), so the listing shows none of them.
pub(super) fn interface_listing(running: &GoldenFile) -> HostInterfaceListing {
    let socket_directory = layout::path(layout::SOCKET_DIRECTORY);
    let private = running
        .firecracker_args()
        .and_then(|args| api_socket(&args).and_then(|socket| JailPath::new(socket).ok()))
        .and_then(|socket| socket.parent())
        == Some(socket_directory);
    HostInterfaceListing {
        share_device: false,
        management_listener: false,
        monitor_socket_private: private,
        old_agent_port_forward: false,
    }
}

/// The configuration facts of an observed jail, stamped now under the configuration the
/// host reports: VM-CP-02's [`configuration_comparison`] and VM-CP-03's
/// [`interface_listing`], and no GPU order, since Firecracker assigns no device.
pub(super) fn configuration_facts(
    golden: &GoldenFile,
    running: &GoldenFile,
    check: &GoldenCheck,
    host: &HostState,
    now: ClockReading,
    fresh_for: Duration,
) -> ConfigurationFacts {
    let configuration = host.configuration;
    ConfigurationFacts {
        comparison: Some(HostObserved::stamp(
            configuration_comparison(golden, running, check),
            now,
            fresh_for,
            configuration,
        )),
        listing: Some(HostObserved::stamp(
            interface_listing(running),
            now,
            fresh_for,
            configuration,
        )),
        gpu_assignments: Vec::new(),
    }
}

/// What the backend observed about a running jail, for admission.
pub(super) struct JailObservation<'a> {
    pub(super) host: &'a HostState,
    /// Whether the process holds a KVM VM descriptor.
    pub(super) kvm: bool,
    /// The confinement controls the passing VM-CP-04 checks and the chroot show.
    pub(super) controls: BTreeSet<ConfinementControl>,
    /// The root image's content key as the launcher verified the staged copy; `None` when
    /// the host does not observe the process holding it.
    pub(super) guest_image: Option<Digest>,
    /// Whether the profile declares a network interface.
    pub(super) declares_network: bool,
}

/// A host fact observed now, under `configuration`, fresh for `fresh_for`.
fn stamp<T>(
    value: T,
    now: ClockReading,
    fresh_for: Duration,
    configuration: ConfigurationFingerprint,
) -> HostFact<T> {
    HostFact::observed(HostObserved::stamp(value, now, fresh_for, configuration))
}

/// The launch facts of an observed jail, stamped now under the configuration the host
/// reports.
pub(super) fn launch_facts(
    observed: &JailObservation<'_>,
    now: ClockReading,
    fresh_for: Duration,
) -> LaunchFacts {
    let configuration = observed.host.configuration;
    let not_seen = UnknownReason::Inconclusive;
    let accelerator = if observed.kvm {
        stamp(
            Accelerator::Hardware {
                hypervisor: HypervisorKind::Kvm,
            },
            now,
            fresh_for,
            configuration,
        )
    } else {
        HostFact::unavailable(not_seen)
    };
    let isolation = if observed.kvm {
        stamp(
            IsolationObservation {
                own_guest_kernel: true,
                physical_host: PhysicalHost::Shared,
            },
            now,
            fresh_for,
            configuration,
        )
    } else {
        HostFact::unavailable(not_seen)
    };
    let network = if observed.declares_network {
        HostFact::unavailable(UnknownReason::NotTested)
    } else {
        stamp(NetworkAuthority::offline(), now, fresh_for, configuration)
    };
    LaunchFacts {
        accelerator,
        observed: ObservedProperties {
            host: stamp(observed.host.build.clone(), now, fresh_for, configuration),
            guest_image: match observed.guest_image {
                Some(image) => stamp(image, now, fresh_for, configuration),
                None => HostFact::unavailable(not_seen),
            },
            isolation,
            confinement: stamp(observed.controls.clone(), now, fresh_for, configuration),
            network,
            credentials: stamp(CredentialExposure::none(), now, fresh_for, configuration),
            persistence: stamp(Persistence::EphemeralTask, now, fresh_for, configuration),
            devices: stamp(DeviceInventory::cpu_only(), now, fresh_for, configuration),
            confidentiality: stamp(OperatorConfidentiality::None, now, fresh_for, configuration),
        },
        guest: GuestAssertions::none(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::fixtures;
    use super::*;
    use serde_json::{json, Value};

    /// The golden file of the strict fixture plan with `entries` added or replaced.
    fn with(golden: &GoldenFile, entries: &[(&str, Value)]) -> GoldenFile {
        let mut map = golden.entries().clone();
        for (key, value) in entries {
            map.insert((*key).to_owned(), value.clone());
        }
        GoldenFile::from_entries(golden.firecracker_version().clone(), map).unwrap()
    }

    #[test]
    fn the_comparison_carries_both_digests_and_the_rows_devices_from_the_forbidden_items() {
        let profile = fixtures::profile();
        let golden = GoldenFile::from_plan(&fixtures::plan());
        let matching = configuration_comparison(
            &golden,
            &golden,
            &GoldenCheck::run(&golden, &golden, &profile),
        );
        assert_eq!(
            matching,
            ConfigurationComparison {
                golden: golden.digest(),
                observed: golden.digest(),
                network_device: false,
                console: false,
                balloon: false,
                undeclared_pci_transport: false,
            }
        );
        assert!(matching.approved());

        // Each device the row names sets its own flag; other forbidden configuration sets
        // none, and every difference shows in the observed digest.
        let flags = |comparison: &ConfigurationComparison| {
            [
                comparison.network_device,
                comparison.console,
                comparison.balloon,
                comparison.undeclared_pci_transport,
            ]
        };
        for (key, value, expected) in [
            (
                "PUT /network-interfaces/eth0 /iface_id",
                json!("eth0"),
                [true, false, false, false],
            ),
            (
                "PUT /boot-source /boot_args",
                json!("console=ttyS0 reboot=k panic=1 pci=off"),
                [false, true, false, false],
            ),
            (
                "PUT /serial /serial_out_path",
                json!("/run/serial"),
                [false, true, false, false],
            ),
            (
                "PUT /balloon /amount_mib",
                json!(0),
                [false, false, true, false],
            ),
            (
                "firecracker.args /2",
                json!("--enable-pci"),
                [false, false, false, true],
            ),
            ("PUT /mmds/config /version", json!("V2"), [false; 4]),
            ("PUT /machine-config /smt", json!(true), [false; 4]),
        ] {
            let running = with(&golden, &[(key, value)]);
            let check = GoldenCheck::run(&golden, &running, &profile);
            let comparison = configuration_comparison(&golden, &running, &check);
            assert_eq!(comparison.golden, golden.digest(), "{key}");
            assert_eq!(comparison.observed, running.digest(), "{key}");
            assert!(!comparison.matches() && !comparison.approved(), "{key}");
            assert_eq!(flags(&comparison), expected, "{key}");
        }

        // A declared interface is no finding; the same interface undeclared is.
        let network = GoldenFile::from_plan(&fixtures::network_plan());
        for (profile, declared) in [(fixtures::network_profile(), true), (profile, false)] {
            let check = GoldenCheck::run(&network, &network, &profile);
            let comparison = configuration_comparison(&network, &network, &check);
            assert_eq!(comparison.network_device, !declared);
            assert_eq!(comparison.approved(), declared);
        }
    }

    #[test]
    fn the_listing_shows_the_api_socket_private_only_in_the_jails_socket_directory() {
        let golden = GoldenFile::from_plan(&fixtures::plan());
        assert_eq!(interface_listing(&golden), HostInterfaceListing::clean());
        assert!(interface_listing(&golden).approved());

        let version = golden.firecracker_version().clone();
        let api = fixtures::plan().api().clone();
        let running = |args: &[&str]| {
            let args: Vec<String> = args.iter().map(|arg| (*arg).to_owned()).collect();
            GoldenFile::from_parts(&version, &api, &args)
        };
        let private = running(&["--api-sock", "/run/api.sock"]);
        assert!(interface_listing(&private).monitor_socket_private);
        let outside = HostInterfaceListing {
            monitor_socket_private: false,
            ..HostInterfaceListing::clean()
        };
        for args in [
            &["--api-sock", "/tmp/firecracker.socket"][..],
            &["--api-sock", "/run/api/firecracker.socket"],
            &["--api-sock", "/run/../firecracker.socket"],
            &["--api-sock", "/run"],
            &["--api-sock", "run/firecracker.socket"],
            &["--api-sock"],
            &[],
            &["--api-sock=/run/firecracker.socket"],
            &[
                "--api-sock",
                "/run/firecracker.socket",
                "--api-sock",
                "/run/other.socket",
            ],
        ] {
            let listing = interface_listing(&running(args));
            assert_eq!(listing, outside, "{args:?}");
            assert!(!listing.approved(), "{args:?}");
        }
        // Arguments that do not read back as Firecracker's are no private socket either.
        let unreadable = with(&golden, &[("firecracker.args /2", json!(2))]);
        assert_eq!(interface_listing(&unreadable), outside);
    }

    #[test]
    fn a_cgroup_text_is_exactly_one_cgroup_v2_line() {
        assert_eq!(
            cgroup_path("0::/yougori/firecracker/vm-1\n"),
            Ok("/yougori/firecracker/vm-1")
        );
        assert_eq!(cgroup_path("0::/\n"), Ok("/"));
        for refused in [
            "",
            "0::/a",
            "0::a\n",
            "1:cpu:/a\n",
            "0::/a\n0::/b\n",
            "0::/a\n\n",
            "0::/a\tb\n",
            " 0::/a\n",
        ] {
            assert_eq!(
                cgroup_path(refused),
                Err(FirecrackerRefusal::CgroupUnreadable {
                    text: refused.to_owned()
                }),
                "{refused:?}"
            );
        }
        let long = format!("0::/{}\n", "a".repeat(MAX_STATUS_BYTES));
        assert!(cgroup_path(&long).is_err());
    }

    #[test]
    fn only_a_kvm_vm_descriptor_shows_kvm() {
        let targets = |items: &[&str]| -> Vec<String> {
            items.iter().map(|item| (*item).to_owned()).collect()
        };
        assert!(holds_kvm_vm(&targets(&["/dev/null", "anon_inode:kvm-vm"])));
        for without in [
            targets(&[]),
            targets(&["/dev/kvm"]),
            targets(&["anon_inode:kvm-vcpu:0", "/dev/kvm"]),
            targets(&["anon_inode:kvm-vm (deleted)", "/tmp/anon_inode:kvm-vm"]),
        ] {
            assert!(!holds_kvm_vm(&without), "{without:?}");
        }
    }

    #[test]
    fn the_running_configuration_needs_the_instance_running_at_an_exact_version() {
        let info = |id: &str, state: &str, version: &str| InstanceInfo {
            id: id.to_owned(),
            state: state.to_owned(),
            vmm_version: version.to_owned(),
        };
        let args = vec![
            "--api-sock".to_owned(),
            "/run/firecracker.socket".to_owned(),
        ];
        let golden =
            running_configuration("vm-1", &info("vm-1", "Running", "1.10.1"), &[], &args).unwrap();
        assert_eq!(golden.firecracker_version().as_str(), "1.10.1");
        assert_eq!(golden.entries().len(), 3);
        for refused in [
            info("vm-2", "Running", "1.10.1"),
            info("vm-1", "Not started", "1.10.1"),
            info("vm-1", "Running", "1.10 .1"),
            info("vm-1", "Running", ""),
        ] {
            assert!(
                running_configuration("vm-1", &refused, &[], &args).is_none(),
                "{refused:?}"
            );
        }
    }
}
